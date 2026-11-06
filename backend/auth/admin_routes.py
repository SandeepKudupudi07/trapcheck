"""
TrapCheck — Admin Routes
=========================
Protected admin endpoints for reviewing reported scams and exporting data.

Routes:
  GET  /admin/reports          → list all pending reports
  POST /admin/reports/{id}/approve → approve + add to ChromaDB
  POST /admin/reports/{id}/reject  → reject with optional note
  GET  /admin/export           → download all approved scams as CSV
  GET  /admin/stats            → admin dashboard stats

Security:
  All routes require ADMIN_SECRET from .env
  Set ADMIN_SECRET=your-secret-key in .env
"""

import os
import csv
import io
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, Literal

from auth.database import get_db, ReportedScam, ScanHistory, User

router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")


# ── Admin auth check ──────────────────────────────────────────────────────────
def verify_admin(x_admin_key: str = Header(None)):
    """Simple header-based admin auth. Pass X-Admin-Key: your-secret in headers."""
    from secrets import compare_digest
    if len(ADMIN_SECRET) < 32 or "change-this" in ADMIN_SECRET or not x_admin_key or not compare_digest(x_admin_key, ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Invalid admin key")
    return True


# ── Request models ────────────────────────────────────────────────────────────
class ReviewRequest(BaseModel):
    note: Optional[str] = Field(default=None, max_length=200)
    threat_level: Literal["SAFE", "SUSPICIOUS", "DANGEROUS"] = "DANGEROUS"


# ── GET /admin/reports ────────────────────────────────────────────────────────
@router.get("/reports")
async def list_reports(
    status: str = "pending",   # pending | approved | rejected | all
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin)
):
    """List all community reported scams filtered by status."""
    query = db.query(ReportedScam)
    if status != "all":
        query = query.filter(ReportedScam.status == status)

    reports = query.order_by(ReportedScam.reported_at.desc()).all()

    return {
        "total":   len(reports),
        "status":  status,
        "reports": [
            {
                "id":          r.id,
                "scam_text":   r.scam_text[:200] + "..." if len(r.scam_text) > 200 else r.scam_text,
                "category":    r.category,
                "language":    r.language,
                "threat_level":r.threat_level,
                "status":      r.status,
                "reported_at": r.reported_at.strftime("%Y-%m-%d %H:%M") if r.reported_at else None,
                "reviewed_at": r.reviewed_at.strftime("%Y-%m-%d %H:%M") if r.reviewed_at else None,
                "admin_note":  r.admin_note,
            }
            for r in reports
        ]
    }


# ── POST /admin/reports/{id}/approve ─────────────────────────────────────────
@router.post("/reports/{report_id}/approve")
async def approve_report(
    report_id: int,
    body: ReviewRequest,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin)
):
    """
    Approve a reported scam.
    Updates status to 'approved' in DB.
    The vectorstore addition is handled in main.py via /admin/approve endpoint.
    """
    report = db.query(ReportedScam).filter(ReportedScam.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "pending":
        raise HTTPException(status_code=400, detail=f"Report is already {report.status}")

    report.status      = "approved"
    report.threat_level= body.threat_level or "DANGEROUS"
    report.reviewed_at = datetime.utcnow()
    report.admin_note  = body.note
    db.commit()

    return {
        "message":     f"Report #{report_id} approved ✅",
        "scam_text":   report.scam_text,
        "category":    report.category,
        "threat_level":report.threat_level,
        "note":        "Approved for review; use add-to-db to update the protection database"
    }


# ── POST /admin/reports/{id}/reject ──────────────────────────────────────────
@router.post("/reports/{report_id}/reject")
async def reject_report(
    report_id: int,
    body: ReviewRequest,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin)
):
    """Reject a reported scam — it will NOT be added to the protection database."""
    report = db.query(ReportedScam).filter(ReportedScam.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "pending":
        raise HTTPException(status_code=400, detail=f"Report is already {report.status}")

    report.status      = "rejected"
    report.reviewed_at = datetime.utcnow()
    report.admin_note  = body.note or "Rejected by admin"
    db.commit()

    return {"message": f"Report #{report_id} rejected ❌", "reason": body.note}


# ── GET /admin/export ─────────────────────────────────────────────────────────
@router.get("/export")
async def export_dataset(
    format:  str = "csv",   # csv | json
    include: str = "approved",  # approved | all
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin)
):
    """
    Export scam dataset as CSV or JSON for AI training.
    
    CSV columns: id, scam_text, category, language, threat_level, reported_at
    
    Usage:
      GET /admin/export               → approved scams as CSV
      GET /admin/export?format=json   → approved scams as JSON
      GET /admin/export?include=all   → all scams including pending/rejected
    """
    query = db.query(ReportedScam)
    if include == "approved":
        query = query.filter(ReportedScam.status == "approved")

    reports = query.order_by(ReportedScam.reported_at.desc()).all()

    if not reports:
        raise HTTPException(status_code=404, detail="No scams found to export")

    if format == "json":
        import json
        data = [
            {
                "id":          r.id,
                "scam_text":   r.scam_text,
                "category":    r.category,
                "language":    r.language,
                "threat_level":r.threat_level,
                "status":      r.status,
                "reported_at": r.reported_at.isoformat() if r.reported_at else None,
            }
            for r in reports
        ]
        json_bytes = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        return StreamingResponse(
            io.BytesIO(json_bytes),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=trapcheck_scams_{datetime.now().strftime('%Y%m%d')}.json"}
        )

    # Default: CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "scam_text", "category", "language", "threat_level", "status", "reported_at"])
    for r in reports:
        values = [r.id, r.scam_text, r.category or "", r.language or "en", r.threat_level or "UNKNOWN", r.status,
                  r.reported_at.strftime("%Y-%m-%d %H:%M") if r.reported_at else ""]
        writer.writerow([
            "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else value
            for value in values
        ])

    csv_bytes = output.getvalue().encode("utf-8-sig")  # utf-8-sig for Excel compatibility
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=trapcheck_scams_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


# ── GET /admin/stats ──────────────────────────────────────────────────────────
@router.get("/stats")
async def admin_stats(
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin)
):
    """Admin dashboard — overall platform statistics."""
    total_users    = db.query(User).count()
    total_scans    = db.query(ScanHistory).count()
    total_reports  = db.query(ReportedScam).count()
    pending        = db.query(ReportedScam).filter(ReportedScam.status=="pending").count()
    approved       = db.query(ReportedScam).filter(ReportedScam.status=="approved").count()
    rejected       = db.query(ReportedScam).filter(ReportedScam.status=="rejected").count()

    # Top reported categories
    from sqlalchemy import func
    top_cats = (
        db.query(ReportedScam.category, func.count(ReportedScam.id).label("count"))
        .filter(ReportedScam.category != None)
        .group_by(ReportedScam.category)
        .order_by(func.count(ReportedScam.id).desc())
        .limit(5)
        .all()
    )

    return {
        "platform": {
            "total_users":   total_users,
            "total_scans":   total_scans,
            "total_reports": total_reports,
        },
        "reports": {
            "pending":  pending,
            "approved": approved,
            "rejected": rejected,
        },
        "top_reported_categories": {cat: count for cat, count in top_cats},
        "export_url": "/admin/export  (add X-Admin-Key header)"
    }