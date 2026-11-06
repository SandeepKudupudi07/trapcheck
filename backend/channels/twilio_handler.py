"""
TrapCheck — Twilio WhatsApp & SMS Handler
==========================================
Receives scam messages forwarded by users on WhatsApp or SMS,
runs them through the RAG engine, and replies with threat analysis.

HOW IT WORKS:
  1. User saves TrapCheck's Twilio number as a contact
  2. User forwards a suspicious WhatsApp/SMS message to TrapCheck
  3. Twilio receives it and POSTs to our /webhook/whatsapp or /webhook/sms
  4. We analyze with RAG engine
  5. We reply back via Twilio with the threat report

SETUP STEPS (one time):
  1. Create free Twilio account at twilio.com
  2. Get a Twilio phone number (free trial gives you one)
  3. Enable WhatsApp sandbox in Twilio console
  4. Set webhook URL to: https://your-domain.com/webhook/whatsapp
  5. Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE to .env
"""

import os
import re
from fastapi import APIRouter, Depends, Form, Response, Request, HTTPException
from starlette.concurrency import run_in_threadpool
from twilio.request_validator import RequestValidator
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
from dotenv import load_dotenv

load_dotenv()

async def verify_twilio(request: Request):
    token = os.getenv("TWILIO_AUTH_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="Twilio is not configured")
    base_url = os.getenv("TWILIO_WEBHOOK_BASE_URL", "").rstrip("/")
    url = base_url + request.url.path if base_url else str(request.url)
    if base_url and request.url.query:
        url += "?" + request.url.query
    params = await request.form()
    signature = request.headers.get("X-Twilio-Signature", "")
    if not RequestValidator(token).validate(url, params, signature):
        raise HTTPException(status_code=403, detail="Invalid webhook signature")


router = APIRouter(prefix="/webhook", tags=["Twilio Webhooks"], dependencies=[Depends(verify_twilio)])

# ── Twilio client ─────────────────────────────────────────────────────────────
# Initialized lazily so server starts even without Twilio credentials
_twilio_client = None

def get_twilio_client():
    global _twilio_client
    if _twilio_client is None:
        sid   = os.getenv("TWILIO_ACCOUNT_SID")
        token = os.getenv("TWILIO_AUTH_TOKEN")
        if not sid or not token:
            raise ValueError("TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN not set in .env")
        _twilio_client = Client(sid, token)
    return _twilio_client


# ── Format RAG result as WhatsApp-friendly message ────────────────────────────
def format_whatsapp_reply(result: dict, language: str = "en") -> str:
    """
    Convert JSON analysis result to a readable WhatsApp message.
    WhatsApp supports bold (*text*) and newlines.
    Keeps it concise — WhatsApp messages should be short.
    """
    threat   = result.get("threat_level", "UNKNOWN")
    emoji    = result.get("threat_emoji", "🟡")
    summary  = result.get("summary", "")
    action   = result.get("action", "")
    flags    = result.get("red_flags", [])
    scam_type = result.get("matched_scam_type", "")
    confidence = result.get("confidence", "MEDIUM")

    # Build message
    lines = [
        f"🛡️ *TrapCheck Analysis*",
        f"",
        f"{emoji} *{threat}*" + (f" — {scam_type}" if scam_type else ""),
        f"",
        f"{summary}",
    ]

    if flags:
        lines.append(f"")
        lines.append(f"⚠️ *Red Flags:*")
        for flag in flags[:3]:   # max 3 flags for WhatsApp readability
            lines.append(f"  • {flag}")

    lines += [
        f"",
        f"✅ *What to do:*",
        f"{action}",
        f"",
        f"_Confidence: {confidence} | Powered by TrapCheck_"
    ]

    return "\n".join(lines)


def format_sms_reply(result: dict) -> str:
    """
    SMS version — much shorter (160 char limit per SMS segment).
    """
    threat  = result.get("threat_level", "UNKNOWN")
    emoji   = result.get("threat_emoji", "🟡")
    action  = result.get("action", "Be cautious")

    # Keep under 160 chars for single SMS
    msg = f"TrapCheck: {emoji} {threat}. {action[:100]}. Reply HELP for more info."
    return msg[:320]  # max 2 SMS segments


# ── WhatsApp Webhook ──────────────────────────────────────────────────────────
@router.post("/whatsapp")
async def whatsapp_webhook(
    Body: str = Form(...),           # the message text
    From: str = Form(...),           # sender's WhatsApp number (e.g. whatsapp:+919876543210)
    NumMedia: int = Form(0),         # number of media attachments
):
    """
    Twilio calls this endpoint when someone messages TrapCheck on WhatsApp.
    
    This is a webhook — Twilio POSTs here, we reply with TwiML XML.
    TwiML tells Twilio what message to send back to the user.
    
    PRIVACY: We never store the sender's WhatsApp number.
    We only use it to send the reply, then discard it.
    """
    from main import vectorstore, llm    # import here to avoid circular import
    from security import sanitize_message, is_safe_to_process
    from rag_engine import analyze_with_rag

    # Build TwiML response object
    twiml = MessagingResponse()

    # Handle media messages (images, documents) — not supported yet
    if NumMedia > 0:
        twiml.message("TrapCheck only analyzes text messages for now. Please forward the text of the suspicious message.")
        return Response(content=str(twiml), media_type="application/xml")

    message_text = Body.strip()

    # Handle help command
    if message_text.lower() in ["help", "hi", "hello", "start", "/start"]:
        help_msg = (
            "👋 *Welcome to TrapCheck!*\n\n"
            "Forward any suspicious SMS, WhatsApp message, or URL to me.\n"
            "I'll tell you if it's a scam — in Telugu, Hindi, or English!\n\n"
            "Just paste or forward the suspicious message here 👇"
        )
        twiml.message(help_msg)
        return Response(content=str(twiml), media_type="application/xml")

    # Validate message
    is_safe, reason = is_safe_to_process(message_text)
    if not is_safe:
        twiml.message(f"⚠️ {reason}\n\nPlease forward the full suspicious message text.")
        return Response(content=str(twiml), media_type="application/xml")

    # Sanitize
    sanitization = sanitize_message(message_text)
    sanitized    = sanitization.sanitized_message

    # Analyze
    try:
        result = await run_in_threadpool(analyze_with_rag,
            user_message=sanitized,
            channel="WhatsApp",
            vectorstore=vectorstore,
            llm=llm
        )
        reply = format_whatsapp_reply(result)
    except Exception as e:
        reply = "⚠️ Analysis failed. Please try again in a moment."

    twiml.message(reply)
    return Response(content=str(twiml), media_type="application/xml")


# ── SMS Webhook ───────────────────────────────────────────────────────────────
@router.post("/sms")
async def sms_webhook(
    Body: str = Form(...),
    From: str = Form(...),
):
    """
    Twilio calls this when someone sends an SMS to TrapCheck's number.
    Reply is formatted for SMS (shorter, no markdown).
    """
    from main import vectorstore, llm
    from security import sanitize_message, is_safe_to_process
    from rag_engine import analyze_with_rag

    twiml = MessagingResponse()

    message_text = Body.strip()

    is_safe, reason = is_safe_to_process(message_text)
    if not is_safe:
        twiml.message(f"TrapCheck: {reason}. Send the full suspicious message.")
        return Response(content=str(twiml), media_type="application/xml")

    sanitization = sanitize_message(message_text)
    sanitized    = sanitization.sanitized_message

    try:
        result = await run_in_threadpool(analyze_with_rag,
            user_message=sanitized,
            channel="SMS",
            vectorstore=vectorstore,
            llm=llm
        )
        reply = format_sms_reply(result)
    except Exception:
        reply = "TrapCheck: Analysis failed. Try again shortly."

    twiml.message(reply)
    return Response(content=str(twiml), media_type="application/xml")


# ── Send proactive alert (optional) ──────────────────────────────────────────
def send_whatsapp_alert(to_number: str, message: str):
    """
    Send a proactive WhatsApp message to a user.
    Example use: notify user when a new scam targeting their region is detected.
    
    to_number format: "+919876543210" (with country code)
    """
    client = get_twilio_client()
    from_number = f"whatsapp:{os.getenv('TWILIO_PHONE')}"
    to_whatsapp = f"whatsapp:{to_number}"

    client.messages.create(
        body=message,
        from_=from_number,
        to=to_whatsapp
    )
