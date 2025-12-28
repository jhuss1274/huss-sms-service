import os, json, urllib.request, urllib.error
import re
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from twilio.rest import Client

app = FastAPI(title="Huss SMS Service", version="1.0.0")

AIRTABLE_PAT = os.getenv("AIRTABLE_PAT", "")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "")
AIRTABLE_TABLE_ID = os.getenv("AIRTABLE_TABLE_ID", "")
HUSS_SECRET = os.getenv("HUSS_SECRET", "")

def _check_secret(body_secret: str, header_secret: str):
    expected = (HUSS_SECRET or "").strip()
    provided = (body_secret or "").strip() or (header_secret or "").strip()
    if expected and provided != expected:
        raise HTTPException(status_code=401, detail="unauthorized")

def _airtable_patch(record_id: str, fields: dict):
    if not AIRTABLE_PAT or not AIRTABLE_BASE_ID or not AIRTABLE_TABLE_ID:
        raise HTTPException(status_code=500, detail="Missing Airtable env vars")
    
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_ID}/{record_id}"
    body = json.dumps({"fields": fields}).encode("utf-8")
    
    # Safe PAT debugging
    pat = (AIRTABLE_PAT or "")
    pat_len = len(pat)
    pat_preview = pat[:3] + "..." + pat[-3:] if pat_len >= 7 else "(too_short)"
    
    req = urllib.request.Request(
        url,
        data=body,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {(AIRTABLE_PAT or '').strip()}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            result["_debug_pat_len"] = pat_len
            result["_debug_pat_preview"] = pat_preview
            return result
    except urllib.error.HTTPError as e:
        raise HTTPException(
                        status_code=502,
                        detail={
                                            "error": "AIRTABLE_HTTP_ERROR",
                                            "airtable_status": e.code,
                                            "airtable_body": e.read().decode("utf-8"),
                                            "pat_len": pat_len,
                                            "pat_preview": pat_preview,
                                        },
                    )
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
async def intake_process(payload: dict, x_huss_secret: str = Header(default="")):  # Check for secret in header or body
    _check_secret(payload.get("secret", ""), x_huss_secret)
    
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
    airtable_result = _airtable_patch(record_id, fields_to_write)
    return {
        "summary": summary,
        "category": category,
        "urgency": urgency,
        "missing_info_list": missing,
        "recommended_route": recommended_route
    }
