"""
TrapCheck — Auth Routes
========================
All authentication and user account endpoints.

Routes:
  POST /auth/register   → create new account
  POST /auth/login      → login, get JWT token
  GET  /auth/me         → get current user info
  GET  /auth/history    → get scan history
  DELETE /auth/account  → delete account + all data (GDPR right to erasure)
"""

import json
from datetime import datetime
from auth.email_service import (
    generate_reset_token, verify_reset_token, consume_reset_token,
    send_reset_email, is_smtp_configured,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, Field, field_validator
from rate_limit import limiter

from auth.database import get_db, ScanHistory
from auth.auth import (
    create_user,
    authenticate_user,
    create_access_token,
    get_current_user,
    get_user_by_email,
    hash_password,
    validate_password,
)
from auth.database import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Request models ────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        return validate_password(value)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(RegisterRequest):
    otp: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    email:        str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
    """
    Create a new TrapCheck account.
    
    Validations:
    - Email must be unique
    - Password minimum 8 characters
    - Password never stored plain (bcrypt hashed)
    """
    # Check email not already registered
    existing = get_user_by_email(db, body.email)
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # Create user (password is hashed inside create_user)
    try:
        user = create_user(db, body.email, body.password)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already registered") from None

    return {
        "message":  "Account created successfully!",
        "email":    user.email,
        "tip":      "Use POST /auth/login to get your access token"
    }


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Login with email + password. Returns JWT access token.
    
    Use the token in all protected requests:
    Header: Authorization: Bearer <your_token>
    
    Token expires after 24 hours.
    """
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user.email, user.hashed_password)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        email=user.email
    )


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current logged-in user's profile."""
    return {
        "email":      current_user.email,
        "member_since": current_user.created_at.strftime("%B %Y"),
        "is_active":  current_user.is_active,
    }


@router.get("/history")
async def get_history(
    limit:        int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    """
    Get current user's scan history.
    Returns last 20 scans by default (pass ?limit=50 for more).
    """
    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.scanned_at.desc())
        .limit(limit)
        .all()
    )

    return {
        "email":       current_user.email,
        "total_scans": db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id).count(),
        "scans": [
            {
                "id":              s.id,
                "message_preview": s.message_preview,
                "channel":         s.channel,
                "threat_level":    s.threat_level,
                "threat_emoji":    s.threat_emoji,
                "scam_type":       s.scam_type,
                "confidence":      s.confidence,
                "scanned_at":      s.scanned_at.strftime("%d %b %Y, %I:%M %p"),
            }
            for s in scans
        ]
    }


@router.get("/stats")
async def get_user_stats(
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    """Personal stats — how many scams caught, by type, etc."""
    all_scans = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id).all()

    # Count by threat level
    dangerous   = sum(1 for s in all_scans if s.threat_level == "DANGEROUS")
    suspicious  = sum(1 for s in all_scans if s.threat_level == "SUSPICIOUS")
    safe        = sum(1 for s in all_scans if s.threat_level == "SAFE")

    # Count by scam type
    scam_types = {}
    for s in all_scans:
        if s.scam_type:
            scam_types[s.scam_type] = scam_types.get(s.scam_type, 0) + 1

    # Count by channel
    channels = {}
    for s in all_scans:
        channels[s.channel] = channels.get(s.channel, 0) + 1

    return {
        "email":            current_user.email,
        "total_scans":      len(all_scans),
        "scams_caught":     dangerous + suspicious,
        "by_threat_level":  {"dangerous": dangerous, "suspicious": suspicious, "safe": safe},
        "top_scam_types":   dict(sorted(scam_types.items(), key=lambda x: x[1], reverse=True)[:5]),
        "by_channel":       channels,
        "member_since":     current_user.created_at.strftime("%B %Y"),
    }


@router.delete("/account")
async def delete_account(
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    """
    GDPR right to erasure — permanently delete account + all scan history.
    This cannot be undone.
    """
    # Delete user (cascade deletes scan_history too)
    db.delete(current_user)
    db.commit()

    return {
        "message": "Account and all associated data permanently deleted.",
        "email":   current_user.email,
        "deleted_at": datetime.utcnow().isoformat()
    }



@router.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Accept reset requests without disclosing whether an account exists."""
    if not is_smtp_configured():
        raise HTTPException(status_code=503, detail="Password reset is temporarily unavailable")

    user = get_user_by_email(db, body.email)
    if user:
        token = generate_reset_token(body.email)
        if not send_reset_email(body.email, token):
            consume_reset_token(body.email)

    return {
        "message": "Request accepted. If the account is eligible, check your email for reset instructions.",
        "expires_in": "15 minutes"
    }


@router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(request: Request, body: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset a password and invalidate tokens bound to its previous hash."""
    if not verify_reset_token(body.email, body.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP. Please request a new one.")

    user = get_user_by_email(db, body.email)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP. Please request a new one.")

    # Update password
    user.hashed_password = hash_password(body.password)
    db.commit()

    # Consume token so it can't be reused
    consume_reset_token(body.email)

    return { "message": "Password reset successful! Please login with your new password." }


# ── Helper: save scan to history (called from main.py after analysis) ─────────
def save_scan_to_history(
    db:           Session,
    user:         User,
    sanitized_msg: str,
    channel:      str,
    result:       dict
):
    """
    Save a completed analysis to user's scan history.
    Called internally after /analyze completes for logged-in users.
    
    Stores SANITIZED message preview only — never full original message.
    """
    scan = ScanHistory(
        user_id         = user.id,
        message_preview = sanitized_msg[:100],           # first 100 chars only
        channel         = channel,
        threat_level    = result.get("threat_level", "UNKNOWN"),
        threat_emoji    = result.get("threat_emoji", "🟡"),
        scam_type       = result.get("matched_scam_type"),
        confidence      = result.get("confidence", "MEDIUM"),
        full_result     = json.dumps({                   # store sanitized result
            k: v for k, v in result.items()
            if k != "retrieved_patterns"                 # skip raw DB patterns
        })
    )
    db.add(scan)
    db.commit()