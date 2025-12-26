import os
import re
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from twilio.rest import Client

app = FastAPI(title="Huss SMS Service", version="1.0.0")

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
