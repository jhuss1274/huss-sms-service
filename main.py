impoimport traceback
rt os, json, urllib.request, urllib.error, httpx, urllib.parse
import re
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from twilio.rest import Client
app = FastAPI(title="Huss SMS Service", version="1.0.0")

APP_VERSION = "auth-debug-v1"

AIRTABLE_PAT = os.getenv("AIRTABLE_PAT", "")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "")
AIRTABLE_TABLE_ID = os.getenv("AIRTABLE_TABLE_ID", "")
HUSS_SECRET = os.getenv("HUSS_SECRET", "")

# Airtable helper functions
def airtable_table_path(table: str) -> str:
    return urllib.parse.quote(table, safe="")

def airtable_record_url(record_id: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{airtable_table_path(AIRTABLE_TABLE_ID)}/{record_id}"

def airtable_headers() -> dict:
    return {"Authorization": f"Bearer {AIRTABLE_PAT}", "Content-Type": "application/json"}

async def airtable_patch_record(record_id: str, fields: dict) -> dict:
    url = airtable_record_url(record_id)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.patch(
                url,
                headers=airtable_headers(),
                json={"fields": fields},
            )

        # Return raw detail for debugging (until Zap 3 is done)
        content_type = r.headers.get("content-type", "")
        body = r.json() if "application/json" in content_type else r.text

        return {
            "attempted_url": url,
            "status_code": r.status_code,
            "body": body,
        }

    except Exception as e:
        # Keep this simple and NEVER indent weirdly
        return {
            "attempted_url": url,
            "status_code": 0,
            "error": "AIRTABLE_HTTP_ERROR",
            "exception": repr(e),
        }
def _check_secret(body_secret: str, header_secret: str, request_headers: dict):
    expected = (HUSS_SECRET or "").strip()

    # Collect possible provided secrets from multiple header spellings + body
    candidates = []

    if body_secret:
        candidates.append(("body.secret", str(body_secret)))

    if header_secret:
        candidates.append(("header.X-Huss-Secret(param)", str(header_secret)))

    # raw headers (case-insensitive in Starlette, but we normalize)
    for k in ["x-huss-secret", "X-Huss-Secret", "X_HUSS_SECRET", "x_huss_secret"]:
        v = request_headers.get(k)
        if v:
            candidates.append((f"header.{k}", str(v)))

    # choose first non-empty candidate
    provided_src = None
    provided_val = ""
    for src, val in candidates:
        if (val or "").strip():
            provided_src = src
            provided_val = val.strip()
            break

    if not expected:
        # If expected is empty, allow (shouldn't happen, but prevents lockout)
        return

    if provided_val != expected:
        # Return safe debug info (no secret leak)
        exp_len = len(expected)
        got_len = len(provided_val)
        got_preview = (provided_val[:3] + "..." + provided_val[-3:]) if got_len >= 7 else "(too_short_or_empty)"
        raise HTTPException(
            status_code=401,
            detail={
                "error": "unauthorized",
                "expected_len": exp_len,
                "got_len": got_len,
                "got_preview": got_preview,
                "got_from": provided_src,
                "headers_seen": sorted(list(request_headers.keys()))[:25],
            },
        )


TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_MESSAGING_SERVICE_SID = os.getenv("TWILIO_MESSAGING_SERVICE_SID", "").strip()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
_client: Optional[Client] = None
E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")

class SendSmsRequest(BaseModel):
    phone_e164: str = Field(..., description="Recipient phone number in E.164 format")
    message: str = Field(..., min_length=1, max_length=1000)
    secret: str = Field(..., min_length=8)
    event_id: Optional[str] = None

class SendSmsResponse(BaseModel):
    twilio_sid: str
    event_id: Optional[str] = None

def get_client() -> Client:
    global _client
    if _client is None:
        if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN):
            raise RuntimeError("Missing Twilio credentials.")
        _client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    return _client

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/version")
async def version():
    return {"version": APP_VERSION}

@app.get("/airtable_auth_check")
async def airtable_auth_check():
    import httpx
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_ID}"
    headers = {"Authorization": f"Bearer {AIRTABLE_PAT}"}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params={"maxRecords": 1})
            return {
                "status_code": response.status_code,
                "response_body": response.json() if response.status_code == 200 else response.text,
                "headers_sent": {"Authorization": f"Bearer {AIRTABLE_PAT[:8]}..."}
            }
    except Exception as e:
        return {"error": str(e)}

@app.post("/send-intake-sms", response_model=SendSmsResponse)
def send_intake_sms(payload: SendSmsRequest):
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_MESSAGING_SERVICE_SID and WEBHOOK_SECRET):
        raise HTTPException(status_code=500, detail="Server misconfigured.")
    if payload.secret != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized.")
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
    except Exception as e:
        raise HTTPException(status_code=502, detail="Twilio send failed.")

@app.post("/intake_process")
async def intake_process(payload: dict, request: Request, x_huss_secret: str = Header(default="")):
    # Check for secret in header or body
    _check_secret(payload.get("secret", ""), x_huss_secret, dict(request.headers))
    
    record_id = (payload.get("airtable_record_id") or "").strip()
    if not record_id:
        raise HTTPException(status_code=400, detail="missing airtable_record_id")
    
    # Extract fields
    airtable_record_id = payload.get("airtable_record_id", "")
    caller_phone_e164 = payload.get("caller_phone_e164", "")
    raw_intake_text = (payload.get("raw_intake_text") or "").strip()
    timestamp_phx = payload.get("timestamp_phx", "")
    source = payload.get("source", "")
    
    # Minimal deterministic processor
    lower = raw_intake_text.lower()
    urgency = "Medium"
    if any(k in lower for k in ["jail", "custody", "arrest", "warrant", "court tomorrow", "today"]):
        urgency = "High"
    if raw_intake_text == "" or raw_intake_text == "NO_TRANSCRIPT_AVAILABLE_YET":
        urgency = "Low"
    
    category = "Lead"
    missing = []
    if raw_intake_text == "" or raw_intake_text == "NO_TRANSCRIPT_AVAILABLE_YET":
        missing.append("voicemail transcript / reason for call")
    if "court" not in lower:
        missing.append("court date (if any)")
    if not any(city in lower for city in ["phoenix", "tempe", "mesa", "scottsdale", "chandler", "gilbert"]):
        missing.append("incident location (city/state)")
    
    summary = raw_intake_text if raw_intake_text else "No transcript available."
    recommended_route = "Jeremy" 
    notes_blob = (
        "V12.5_Zap3\n"
        f"Summary: {summary}\n"
        f"Category: {category}\n"
        f"Urgency: {urgency}\n"
        f"Missing: {', '.join(missing) if isinstance(missing, list) else str(missing)}\n"
        f"Route: {recommended_route}\n"
    )
    
    fields_to_write = {
        "Status": "Processed",
        "Notes": notes_blob,
    }
        recotry:
        patch_result = await airtable_patch_record(
            record_id,
            {
                "SMS Status": "Processed",
                "Notes": f"V12.5_Zap3 OK | zap_run_id={payload.get('zap_run_id') or ''}",
            },
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "AIRTABLE_PATCH_CRASH",
                "exception": repr(e),
                "traceback": traceback.format_exc(),
                "airtable_record_id": payload.get("airtable_record_id"),
                "zap_run_id": payload.get("zap_run_id"),
            },
        )
    return {
        "summary": summary,
        "category": category,
        "urgency": urgency,
        "missing_info_list": missing,
        "recommended_route": recommended_route,
        "patch_result": patch_result,

@app.get("/intake_process")
async def intake_process_get():
    return {"ok": False, "error": "METHOD_NOT_ALLOWED", "message": "Use POST to /intake_process"}
@app.post("/intake_process/")
async def intake_process_slash(payload: dict, request: Request, x_huss_secret: str = Header(default="")):
    return await intake_process(payload, request, x_huss_secret)
