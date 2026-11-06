"""
TrapCheck — Security Layer 1: Zero-Log Policy
===============================================
PURPOSE:
  By default FastAPI logs EVERYTHING — URLs, request bodies, IP addresses.
  This means user's private scam messages get written to log files on disk.
  This module disables all sensitive logging.

WHAT IT DOES:
  - Strips message content from all logs
  - Replaces sensitive data with [REDACTED] in any log output
  - Only logs: timestamp, endpoint, response code, response time
  - Never logs: message content, IP address, user input

EXAMPLE:
  Without this:  LOG: POST /analyze {"message": "మీ KYC expire...పేరు: రాజు, phone: 9876543210"}
  With this:     LOG: POST /analyze [CONTENT REDACTED] 200 OK 0.3s
"""

import logging
import re
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import time


# ── Silence all default uvicorn/FastAPI loggers ───────────────────────────────
# These loggers would otherwise dump full request details to console/files
logging.getLogger("uvicorn.access").handlers = []       # access logs
logging.getLogger("uvicorn.access").propagate = False   # stop propagation
logging.getLogger("uvicorn.error").setLevel(logging.WARNING)  # only warnings+


# ── Safe logger — only logs what we explicitly allow ─────────────────────────
safe_logger = logging.getLogger("trapcheck.safe")
safe_logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
))
safe_logger.addHandler(handler)


# ── Zero-Log Middleware ───────────────────────────────────────────────────────
class ZeroLogMiddleware(BaseHTTPMiddleware):
    """
    Intercepts every request BEFORE it hits any endpoint.
    Logs only: method, endpoint, status code, response time.
    NEVER logs: request body, user message, IP address, headers.
    """

    # Endpoints that contain sensitive user data — never log their bodies
    SENSITIVE_ENDPOINTS = {"/analyze", "/report"}

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()

        # Process request normally
        response = await call_next(request)

        duration = round((time.time() - start_time) * 1000, 1)
        endpoint = request.url.path

        # Log ONLY safe metadata — never the content
        if endpoint in self.SENSITIVE_ENDPOINTS:
            safe_logger.info(
                f"{request.method} {endpoint} | "
                f"status={response.status_code} | "
                f"time={duration}ms | "
                f"content=[REDACTED FOR PRIVACY]"
            )
        else:
            safe_logger.info(
                f"{request.method} {endpoint} | "
                f"status={response.status_code} | "
                f"time={duration}ms"
            )

        return response


# ── Log sanitizer — cleans any accidental log output ─────────────────────────
class SanitizingFilter(logging.Filter):
    """
    Safety net: even if some code accidentally logs sensitive data,
    this filter strips it before it hits any handler.
    
    Patterns it removes:
    - Phone numbers (Indian format)
    - Aadhaar numbers (12 digits)
    - OTPs (4-6 digit codes)
    - UPI IDs (xxx@yyy format)
    - Email addresses
    """

    SENSITIVE_PATTERNS = [
        (r'\b[6-9]\d{9}\b',           '[PHONE REDACTED]'),      # Indian phone numbers
        (r'\b\d{4}\s?\d{4}\s?\d{4}\b','[AADHAAR REDACTED]'),    # Aadhaar numbers
        (r'\b\d{4,6}\b',              '[OTP REDACTED]'),         # OTPs
        (r'\b[\w.]+@[\w]+\b',         '[UPI REDACTED]'),         # UPI IDs
        (r'\b[\w.]+@[\w.]+\.\w+\b',   '[EMAIL REDACTED]'),       # Email addresses
        (r'\b\d{16}\b',               '[CARD REDACTED]'),        # Card numbers
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        # Sanitize the log message
        message = record.getMessage()
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            message = re.sub(pattern, replacement, message)
        record.msg = message
        record.args = ()
        return True


# Apply sanitizing filter to root logger — catches everything
logging.getLogger().addFilter(SanitizingFilter())
safe_logger.addFilter(SanitizingFilter())
