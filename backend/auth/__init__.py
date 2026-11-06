# TrapCheck Auth Package
from auth.database import create_tables, get_db, User, ScanHistory, ReportedScam
from auth.auth import get_current_user, get_optional_user, create_access_token
from auth.routes import router as auth_router, save_scan_to_history

__all__ = [
    "create_tables",
    "get_db",
    "User",
    "ScanHistory",
    "ReportedScam",
    "get_current_user",
    "get_optional_user",
    "auth_router",
    "save_scan_to_history",
]