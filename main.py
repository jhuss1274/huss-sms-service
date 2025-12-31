import os
import re
import urllib.parse
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel, Field
from twilio.rest import Client

app = FastAPI(title="Huss SMS Service", version="12.5.0")

APP_VERSION = "12.5.0-auth-debug"

# === ONE SECRET RULE: everything uses WEBHOOK_SECRET ===
WEBHOOK_SECRET = (os.getenv("WEBHOOK_SECRET", "") or "").strip()

# Airtable
AIRTABLE_PAT = (os.getenv("AIRTABLE_PAT", "") or "").strip()
AIRTABLE_BASE_ID = (os.getenv("AIRTABLE_BASE_ID", "") or "").strip()
AIRTABLE_TABLE_ID = (os.getenv("AIRTABLE_TABLE_ID", "") or "").strip()  # table name or id

# Twilio
TWILIO_ACCOUNT_SID = (os.getenv("TWILIO_ACCOUNT_SID", "") or "").strip()
TWILIO_AUTH_TOKEN = (os.getenv("TWILIO_AUTH_TOKEN", "") or "").strip()
TWILIO_MESSAGING_SERVICE_SID = (os.getenv("TWILIO_MESSAGING_SERVICE_SID", "") or "").strip()

_client: Optional[Client] = None
E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")


# -------------------- Models --------------------

class SendSmsRequest(BaseModel):
    phone_e164: str = Field(..., description="Recipient phone number in E.164 format")
    message: str = Field(..., min_length=1, max_length=1000)
    secret: str = Field(..., min_length=8)
    event_id: Optional[str] = None


class SendSmsResponse(BaseModel):
    twilio_sid: str
    event_id: Optional[str] = None


# -------------------- Helpers --------------------

def _check_secret(body_secret: Optional[str], header_secret: Optional[str]) -> None:
    """
    Accept secret via header OR body.
    Header name Zapier uses: X-Huss-Secret
    """
    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Server misconfigured (missing WEBHOOK_SECRET).")

    hs = (header_secret or "").strip()
    bs = (body_secret or "").strip()

    if hs == WEBHOOK_SECRET or bs == WEBHOOK_SECRET:
        return

    raise HTTPException(status_code=401, detail="Unauthorized.")


def get_client() -> Client:
    global _client
    if _client is None:
        if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN):
            raise RuntimeError("Missing Twilio credentials.")
        _client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    return _client


def _require_airtable_env() -> None:
    if not AIRTABLE_PAT:
        raise HTTPException(status_code=500, detail="Server misconfigured (missing AIRTABLE_PAT).")
    if not AIRTABLE_BASE_ID:
        raise HTTPException(status_code=500, detail="Server misconfigured (missing AIRTABLE_BASE_ID).")
    if not AIRTABLE_TABLE_ID:
        raise HTTPException(status_code=500, detail="Server misconfigured (missing AIRTABLE_TABLE_ID).")


def _airtable_table_path(table: str) -> str:
    return urllib.parse.quote(table, safe="")


def _airtable_record_url(record_id: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{_airtable_table_path(AIRTABLE_TABLE_ID)}/{record_id}"


def _airtable_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {AIRTABLE_PAT}", "Content-Type": "application/json"}


async def airtable_patch_record(record_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """
    PATCH Airtable record and return a debug dict with status_code + body.
    """
    _require_airtable_env()

    url = _airtable_record_url(record_id)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.patch(url, headers=_airtable_headers(), json={"fields": fields})

        content_type = (r.headers.get("content-type", "") or "").lower()
        body = r.json() if "application/json" in content_type else r.text

        return {"attempted_url": url, "status_code": r.status_code, "body": body}

    except Exception as e:
        return {"attempted_url": url, "status_code": 0, "error": "AIRTABLE_HTTP_ERROR", "exception": repr(e)}


# -------------------- Endpoints --------------------

@app.get("/health")
def health():
    return {"ok": True, "service": "huss-sms-service", "version": APP_VERSION}


@app.get("/version")
def version():
    return {"ok": True, "service": "huss-sms-service", "version": APP_VERSION}


@app.get("/airtable_auth_check")
async def airtable_auth_check(x_huss_secret: Optional[str] = Header(default=None)):
    _check_secret(None, x_huss_secret)
    _require_airtable_env()

    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{_airtable_table_path(AIRTABLE_TABLE_ID)}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(url, headers={"Authorization": f"Bearer {AIRTABLE_PAT}"}, params={"maxRecords": 1})
        return {
            "ok": True,
            "status_code": r.status_code,
            "body": r.json() if r.status_code == 200 else r.text,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/send-intake-sms", response_model=SendSmsResponse)
def send_intake_sms(payload: SendSmsRequest, x_huss_secret: Optional[str] = Header(default=None)):
    _check_secret(payload.secret, x_huss_secret)

    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_MESSAGING_SERVICE_SID):
        raise HTTPException(status_code=500, detail="Server misconfigured (Twilio vars missing).")

    if not E164_RE.match(payload.phone_e164):
        raise HTTPException(status_code=400, detail="Invalid phone format.")

    try:
        client = get_client()
        msg = client.messages.create(
            to=payload.phone_e164,
            messaging_service_sid=TWILIO_MESSAGING_SERVICE_SID,
            body=payload.message,
        )
        return {"twilio_sid": msg.sid, "event_id": payload.event_id}
    except Exception:
        raise HTTPException(status_code=502, detail="Twilio send failed.")


@app.post("/intake_process")
async def intake_process(payload: dict, request: Request, x_huss_secret: Optional[str] = Header(default=None)):
    # Secret check: header OR body
    _check_secret(payload.get("secret", ""), x_huss_secret)

    # Record id: accept all common keys
    record_id = (
        (payload.get("airtable_record_id") or "")
        or (payload.get("record_id") or "")
        or (payload.get("airtableRecordId") or "")
    ).strip()

    if not record_id:
        raise HTTPException(status_code=400, detail="missing airtable_record_id")

    raw_intake_text = (payload.get("raw_intake_text") or "").strip()
    lower = raw_intake_text.lower()

    # Minimal deterministic processor
    urgency = "Medium"
    if any(k in lower for k in ["jail", "custody", "arrest", "warrant", "court tomorrow", "today", "tonight"]):
        urgency = "High"
    if raw_intake_text in ("", "NO_TRANSCRIPT_AVAILABLE_YET"):
        urgency = "Low"

    category = "Lead"

    missing: List[str] = []
    if raw_intake_text in ("", "NO_TRANSCRIPT_AVAILABLE_YET"):
        missing.append("voicemail transcript / reason for call")
    if "court" not in lower:
        missing.append("court date (if any)")
    if not any(city in lower for city in ["phoenix", "tempe", "mesa", "scottsdale", "chandler", "gilbert"]):
        missing.append("incident location (city/state)")

    summary = raw_intake_text if raw_intake_text else "No transcript available."
    recommended_route = "Jeremy"

    # Patch Airtable — THIS is the Zap 3 ledger write
    patch_result = await airtable_patch_record(
        record_id,
        {
            "SMS Status": "Processed",
            "Notes": f"V12.5_Zap3 OK | zap_run_id={(payload.get('zap_run_id') or '')}",
        },
    )

    airtable_patch_status = patch_result.get("status_code", 0)
    airtable_patch_ok = airtable_patch_status in (200, 204)
    airtable_patch_error = patch_result.get("error") or None

    return {
        "summary": summary,
        "category": category,
        "urgency": urgency,
        "missing_info_list": missing,
        "recommended_route": recommended_route,
        "airtable_record_id_used": record_id,
        "airtable_patch_ok": airtable_patch_ok,
        "airtable_patch_status": airtable_patch_status,
        "airtable_patch_error": airtable_patch_error,
    }


@app.get("/intake_process")
async def intake_process_get():
    return {"ok": False, "error": "METHOD_NOT_ALLOWED", "message": "Use POST to /intake_process"}


@app.post("/intake_process/")
async def intake_process_slash(payload: dict, request: Request, x_huss_secret: Optional[str] = Header(default=None)):
    return await intake_process(payload, request, x_huss_secret)
