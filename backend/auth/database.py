"""
TrapCheck — User Accounts: Database Models
============================================
Uses SQLite (local) via SQLAlchemy ORM.
Same code works on cloud (swap SQLite URL for PostgreSQL URL).

Tables:
  users         → email, hashed password, created_at
  scan_history  → user's past analyses, linked to users table

SECURITY:
  - Passwords NEVER stored plain — always bcrypt hashed
  - JWT tokens used for auth — no sessions stored server-side
  - User email is the only PII stored
  - Scan messages are sanitized before storage (via sanitizer.py)
"""

import os
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String,
    DateTime, Text, ForeignKey, Boolean
)
from pathlib import Path
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from dotenv import load_dotenv

load_dotenv()

# ── Database setup ────────────────────────────────────────────────────────────
# Local: SQLite file on disk
# Cloud: swap to PostgreSQL by changing DATABASE_URL in .env
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/trapcheck.db")

# Auto-create the data/ folder if it doesn't exist
# This fixes: "sqlite3.OperationalError: unable to open database file"
database_url = make_url(DATABASE_URL)
if database_url.get_backend_name() == "sqlite" and database_url.database not in (None, "", ":memory:"):
    db_path = Path(database_url.database)
    if not db_path.is_absolute():
        db_path = Path(__file__).resolve().parents[1] / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = database_url.set(database=str(db_path))

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if database_url.get_backend_name() == "sqlite" else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── TABLE 1: Users ────────────────────────────────────────────────────────────
class User(Base):
    """
    Stores registered user accounts.
    
    What we store:    email, hashed_password, created_at, is_active
    What we NEVER store: plain password, IP address, phone number
    """
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    email           = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)   # bcrypt hash, never plain
    is_active       = Column(Boolean, default=True)
    created_at      = Column(DateTime, default=datetime.utcnow)

    # One user → many scan history entries
    scan_history = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.email}>"


# ── TABLE 2: Scan History ─────────────────────────────────────────────────────
class ScanHistory(Base):
    """
    Stores a user's past scam analyses.
    
    What we store:    sanitized message, channel, threat level, result, timestamp
    What we NEVER store: original unsanitized message, IP address
    
    NOTE: message_preview stores only first 100 chars of SANITIZED message
    so users can identify which scan was which, without storing full content.
    """
    __tablename__ = "scan_history"

    id              = Column(Integer, primary_key=True, index=True)
    user_id         = Column(Integer, ForeignKey("users.id"), nullable=False)
    message_preview = Column(String(100), nullable=False)   # first 100 chars, sanitized
    channel         = Column(String(20), default="SMS")     # SMS | Email | WhatsApp | URL
    threat_level    = Column(String(20), nullable=False)    # SAFE | SUSPICIOUS | DANGEROUS
    threat_emoji    = Column(String(5), default="🟡")
    scam_type       = Column(String(100), nullable=True)    # KYC Fraud, UPI Scam, etc.
    confidence      = Column(String(10), default="MEDIUM")  # HIGH | MEDIUM | LOW
    full_result     = Column(Text, nullable=True)           # full JSON result (sanitized)
    scanned_at      = Column(DateTime, default=datetime.utcnow)

    # Link back to user
    user = relationship("User", back_populates="scan_history")

    def __repr__(self):
        return f"<Scan {self.threat_level} @ {self.scanned_at}>"


# ── TABLE 3: Reported Scams (community reports, pending admin review) ─────────
class ReportedScam(Base):
    """
    Community-reported scams waiting for admin review.

    Flow:
      User clicks "Report" → saved here with status='pending'
      Admin approves       → status='approved', added to ChromaDB
      Admin rejects        → status='rejected', not added to DB
    """
    __tablename__ = "reported_scams"

    id           = Column(Integer, primary_key=True, index=True)
    scam_text    = Column(Text, nullable=False)          # the reported message
    category     = Column(String(100), nullable=True)    # scam type
    language     = Column(String(10), default="en")      # te | hi | en | ta
    threat_level = Column(String(20), default="UNKNOWN") # filled on approve
    status       = Column(String(20), default="pending") # pending | approved | rejected
    reported_at  = Column(DateTime, default=datetime.utcnow)
    reviewed_at  = Column(DateTime, nullable=True)
    admin_note   = Column(String(200), nullable=True)    # optional note from admin

    def __repr__(self):
        return f"<Report {self.status} @ {self.reported_at}>"


# ── Database helpers ──────────────────────────────────────────────────────────
def create_tables():
    """Create all tables if they don't exist. Safe to call multiple times."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """
    FastAPI dependency — provides a database session per request.
    Automatically closes session when request is done.
    
    Usage in endpoints:
        @app.post("/analyze")
        async def analyze(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()