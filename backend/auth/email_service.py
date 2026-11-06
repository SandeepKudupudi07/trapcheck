"""
TrapCheck — Email Service
==========================
Sends password reset emails via Gmail SMTP.
Uses Python's built-in smtplib — no extra packages needed.
"""

import hmac
import logging
import os
import smtplib
import secrets
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

SMTP_EMAIL    = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM     = os.getenv("SMTP_FROM_NAME", "TrapCheck")

logger = logging.getLogger(__name__)

# For multi-server: move to Redis or DB
_reset_tokens: dict = {}


# ── Token management ──────────────────────────────────────────────────────────
def generate_reset_token(email: str) -> str:
    """Generate a secure 6-digit OTP reset token valid for 15 minutes."""
    # Remove any existing token for this email
    _reset_tokens.pop(email, None)

    # Generate secure 6-digit OTP
    token = str(secrets.randbelow(900000) + 100000)   # 100000–999999

    _reset_tokens[email] = {
        "token": token,
        "expires_at": datetime.utcnow() + timedelta(minutes=15),
        "attempts": 0,
    }
    return token


def verify_reset_token(email: str, token: str) -> bool:
    """Verify OTP token for email. Returns True if valid and not expired."""
    record = _reset_tokens.get(email)
    if not record:
        return False
    if datetime.utcnow() >= record["expires_at"] or record["attempts"] >= 5:
        _reset_tokens.pop(email, None)
        return False
    if not hmac.compare_digest(record["token"].encode("utf-8"), token.encode("utf-8")):
        record["attempts"] += 1
        if record["attempts"] >= 5:
            _reset_tokens.pop(email, None)
        return False
    return True


def consume_reset_token(email: str):
    """Delete token after successful password reset."""
    _reset_tokens.pop(email, None)


# ── Email sender ──────────────────────────────────────────────────────────────
def is_smtp_configured() -> bool:
    return bool(SMTP_EMAIL and SMTP_EMAIL.strip() and SMTP_PASSWORD and SMTP_PASSWORD.strip())


def send_reset_email(to_email: str, token: str) -> bool:
    """
    Send password reset OTP email.
    Returns True if sent successfully, False if failed.
    """
    if not is_smtp_configured():
        logger.error("Password reset email unavailable: SMTP is not configured")
        return False

    subject = "🛡️ TrapCheck — Your Password Reset OTP"

    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:'Courier New',monospace;">
  <div style="max-width:480px;margin:0 auto;padding:2rem;">

    <!-- Header -->
    <div style="text-align:center;margin-bottom:2rem;">
      <div style="display:inline-block;background:linear-gradient(135deg,#00e576,#00b8d4);width:60px;height:60px;border-radius:16px;line-height:60px;font-size:28px;margin-bottom:1rem;">🛡️</div>
      <h1 style="color:#fff;margin:0;font-size:1.8rem;letter-spacing:-1px;">TrapCheck</h1>
      <p style="color:#444;font-size:0.75rem;letter-spacing:3px;margin:0.3rem 0 0;">SCAM PROTECTION</p>
    </div>

    <!-- Card -->
    <div style="background:#111;border:1px solid rgba(0,229,118,0.15);border-radius:16px;padding:2rem;text-align:center;">
      <p style="color:#888;font-size:0.9rem;margin:0 0 1.5rem;line-height:1.6;">
        We received a request to reset your TrapCheck password.<br>
        Use this OTP to reset your password:
      </p>

      <!-- OTP -->
      <div style="background:rgba(0,229,118,0.06);border:1px solid rgba(0,229,118,0.2);border-radius:12px;padding:1.5rem;margin:1.5rem 0;">
        <div style="font-size:2.8rem;font-weight:900;letter-spacing:8px;color:#00e576;">{token}</div>
        <div style="color:#444;font-size:0.72rem;margin-top:0.5rem;letter-spacing:2px;">VALID FOR 15 MINUTES</div>
      </div>

      <p style="color:#555;font-size:0.78rem;line-height:1.6;margin:0;">
        If you didn't request this, ignore this email.<br>
        Your password will not change.
      </p>
    </div>

    <!-- Footer -->
    <div style="text-align:center;margin-top:1.5rem;">
      <p style="color:#2a2a2a;font-size:0.68rem;">
        TrapCheck · AI-Powered Scam Detector · India<br>
        This is an automated message, do not reply.
      </p>
    </div>

  </div>
</body>
</html>
"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{SMTP_FROM} <{SMTP_EMAIL}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())

        return True

    except Exception:
        logger.error("Password reset email delivery failed")
        return False