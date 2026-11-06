"""
TrapCheck — Auth Logic
========================
Handles:
  1. Password hashing (bcrypt) — never store plain passwords
  2. JWT token creation — issued on login, verified on every request
  3. User creation and lookup

HOW JWT WORKS IN TRAPCHECK:
  1. User logs in with email + password
  2. We verify password against bcrypt hash
  3. We issue a JWT token: { "sub": "user@email.com", "exp": <24hrs> }
  4. User sends this token in every request header: Authorization: Bearer <token>
  5. We verify token signature + expiry on every protected endpoint
  6. No session stored server-side — token IS the proof of identity

WHY BCRYPT:
  - Bcrypt is slow BY DESIGN — makes brute force attacks extremely hard
  - Even if database is stolen, passwords can't be recovered
  - Each hash is salted — same password gives different hash each time
"""

import hashlib
import hmac
import os
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from auth.database import User, get_db

# ── Config ────────────────────────────────────────────────────────────────────
def _load_secret_key() -> str:
    secret = os.getenv("JWT_SECRET_KEY", "").strip()
    normalized = secret.lower().replace("_", "-")
    placeholders = (
        "change-this", "change-me", "changeme", "replace-me", "replace-with",
        "your-secret", "your-jwt", "placeholder",
    )
    if len(secret) < 32 or any(marker in normalized for marker in placeholders):
        raise RuntimeError(
            "JWT_SECRET_KEY must be configured with a non-placeholder random secret "
            "of at least 32 characters."
        )
    return secret


SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
TOKEN_EXPIRY = int(os.getenv("JWT_EXPIRY_HOURS", 24))   # token valid for 24 hours

# ── OAuth2 token scheme ───────────────────────────────────────────────────────
# Tells FastAPI where to expect the token (Authorization: Bearer <token>)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


# ── Password functions ────────────────────────────────────────────────────────
def validate_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must be at most 72 UTF-8 bytes")
    return password


def hash_password(plain_password: str) -> str:
    """
    Hash a plain password using bcrypt.
    
    Example:
      Input:  "mypassword123"
      Output: "$2b$12$EixZaYVK1fsbw1ZfbX3OXe.PmR3/Xm3mI3AiVRNJK..." (60 chars)
    
    This hash is what gets stored in the database — never the plain password.
    """
    validate_password(plain_password)
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        password_bytes = plain_password.encode("utf-8")
        if len(password_bytes) > 72:
            return False
        return bcrypt.checkpw(password_bytes, hashed_password.encode("ascii"))
    except (ValueError, UnicodeError):
        return False


# ── JWT token functions ───────────────────────────────────────────────────────
def _password_fingerprint(password_hash: str) -> str:
    return hmac.new(
        SECRET_KEY.encode("utf-8"),
        b"password-version:" + password_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_access_token(email: str, password_hash: str) -> str:
    """
    Create a signed JWT token for a logged-in user.
    
    Token payload:
      sub: user's email (the "subject")
      exp: expiry timestamp (24 hours from now)
    
    Token is signed with SECRET_KEY — can't be forged without it.
    """
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY)
    payload = {
        "sub": email,
        "exp": expire,
        "pwd": _password_fingerprint(password_hash),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Return signed token claims, or None for invalid or expired tokens."""
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require_exp": True, "require_sub": True},
        )
        if not isinstance(payload.get("sub"), str) or not payload["sub"]:
            return None
        fingerprint = payload.get("pwd")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64 or not fingerprint.isascii():
            return None
        return payload
    except (JWTError, ValueError, TypeError):
        return None


# ── User CRUD ─────────────────────────────────────────────────────────────────
def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Fetch user from database by email."""
    return db.query(User).filter(User.email == email).first()


def create_user(db: Session, email: str, plain_password: str) -> User:
    hashed = hash_password(plain_password)
    user = User(email=email, hashed_password=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """
    Verify email + password combination.
    Returns User object if valid, None if invalid.
    """
    user = get_user_by_email(db, email)
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


# ── FastAPI dependency: get current logged-in user ────────────────────────────
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency that:
    1. Extracts JWT token from request header
    2. Verifies token is valid and not expired
    3. Returns the User object for the logged-in user

    Usage in protected endpoints:
        @app.get("/history")
        async def history(current_user: User = Depends(get_current_user)):
            # current_user is the logged-in user
            ...
    
    Raises 401 if token is missing, invalid, or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if not payload:
        raise credentials_exception

    user = get_user_by_email(db, payload["sub"])
    if not user or not user.is_active:
        raise credentials_exception
    if not hmac.compare_digest(
        payload["pwd"].encode("utf-8"),
        _password_fingerprint(user.hashed_password).encode("ascii"),
    ):
        raise credentials_exception

    return user


# ── Optional auth: works with or without token ────────────────────────────────
async def get_optional_user(
    request: Request,
    token: Optional[str] = Depends(optional_oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Like get_current_user but doesn't raise error if not logged in.
    Used for /analyze — works for both logged-in and anonymous users.
    Logged-in users get their scan saved to history.
    Anonymous users still get analysis, just not saved.
    """
    if token is None and "Authorization" not in request.headers:
        return None
    return await get_current_user(token or "", db)
