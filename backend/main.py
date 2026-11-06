"""
TrapCheck FastAPI Backend — Full Edition v4.0
===============================================
✅ Security Layer 1-4
✅ User accounts + JWT auth
✅ Twilio WhatsApp/SMS
✅ Daily PhishTank refresh
✅ Rate limiting (Feature 2)
"""

import os
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from rate_limit import limiter

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from security import (
    ZeroLogMiddleware, safe_logger,
    sanitize_message, is_safe_to_process,
    ephemeral_processing, processing_guarantee,
    prepare_anonymous_report,
)
from auth import (
    create_tables, get_db,
    get_current_user, auth_router,
    save_scan_to_history, User,
)
from auth.database import ReportedScam
from auth.admin_routes import router as admin_router, verify_admin
from security.sanitizer import sanitize_for_storage
from channels.twilio_handler import router as twilio_router
from scheduler.refresh import setup_scheduler, stop_scheduler, daily_refresh_job, scheduler
from rag_engine import (
    get_embeddings_model, get_aya_llm,
    load_knowledge_base, load_existing_vectorstore,
    analyze_with_rag, InvalidAnalysisError,
)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="TrapCheck API",
    description="Multilingual RAG scam detector",
    version="4.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(ZeroLogMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-Key"],
)

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(twilio_router)

embeddings        = None
vectorstore       = None
llm               = None
scam_fingerprints = set()


@app.on_event("startup")
async def startup_event():
    global embeddings, vectorstore, llm, scam_fingerprints
    safe_logger.info("🚀 TrapCheck v4.0 starting...")
    create_tables()
    safe_logger.info("✅ Database tables ready")
    try:
        llm = await run_in_threadpool(get_aya_llm)
        embeddings = await run_in_threadpool(get_embeddings_model)
        db_path = os.environ["CHROMA_DB_PATH"]
        loader = load_existing_vectorstore if os.path.exists(db_path) and os.listdir(db_path) else load_knowledge_base
        vectorstore = await run_in_threadpool(loader, embeddings)
        if vectorstore._collection.count() == 0:
            vectorstore = await run_in_threadpool(load_knowledge_base, embeddings)
        results = vectorstore._collection.get()
        scam_fingerprints = {meta["fingerprint"] for meta in results.get("metadatas", []) if meta and "fingerprint" in meta}
        setup_scheduler(vectorstore)
    except Exception:
        embeddings, vectorstore, llm = None, None, None
        safe_logger.error("AI initialization failed; check Ollama, model files, and database compatibility")


@app.on_event("shutdown")
async def shutdown_event():
    stop_scheduler()
    safe_logger.info("TrapCheck shutdown complete")


class AnalyzeRequest(BaseModel):
    message: str = Field(min_length=10, max_length=5000)
    channel: Literal["SMS", "WhatsApp", "Email", "URL"] = "SMS"
    language: Literal["en", "te", "hi", "ta"] = "en"

class ReportRequest(BaseModel):
    scam_text: str = Field(min_length=10, max_length=5000)
    category: str = Field(min_length=1, max_length=100)
    language: Literal["en", "te", "hi", "ta"] = "en"


@app.get("/")
async def root():
    return {"name": "TrapCheck API v4.0", "status": "running", "docs": "/docs"}


@app.get("/health")
async def health_check():
    ready = all(component is not None for component in (embeddings, vectorstore, llm))
    return JSONResponse(status_code=200 if ready else 503, content={
        "status": "ready" if ready else "unavailable",
        "components": {
            "embeddings": embeddings is not None,
            "vector_db": vectorstore is not None,
            "llm": llm is not None,
            "scheduler": scheduler.running,
        },
        "message": "AI initialized" if ready else "Start Ollama, install the configured models, and restart the backend.",
    })


@app.get("/privacy")
async def privacy():
    return {"title": "TrapCheck Privacy Guarantee", **processing_guarantee()}


@app.post("/analyze")
@limiter.limit("20/minute")   # max 20 scans per minute per IP
def analyze_message(
    request:      Request,
    body:         AnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    if not all([embeddings, vectorstore, llm]):
        raise HTTPException(status_code=503, detail="Models still loading, try in a moment")

    is_safe, reason = is_safe_to_process(body.message)
    if not is_safe:
        raise HTTPException(status_code=400, detail=reason)

    sanitization  = sanitize_message(body.message)
    sanitized_msg = sanitization.sanitized_message

    try:
        with ephemeral_processing("user_message") as ctx:
            ctx["data"] = sanitized_msg
            result = analyze_with_rag(
                user_message=ctx["data"],
                channel=body.channel,
                vectorstore=vectorstore,
                llm=llm,
                language=body.language
            )

    except InvalidAnalysisError:
        raise HTTPException(status_code=502, detail="The AI returned an invalid analysis. Please try again.") from None
    except Exception:
        safe_logger.error("Analysis could not complete")
        raise HTTPException(status_code=503, detail="AI service unavailable. Please try again later.") from None

    try:
        save_scan_to_history(db, current_user, sanitized_msg, body.channel, result)
        result["saved_to_history"] = True
    except Exception:
        db.rollback()
        safe_logger.error("Scan history could not be saved")
        result["saved_to_history"] = False
        result["history_notice"] = "Analysis completed, but could not be saved to history."
    if sanitization.items_removed:
        result["privacy_notice"] = {
            "message": "Detected personal data was removed before analysis",
            "removed": sanitization.items_removed,
        }
    return result


@app.post("/report")
@limiter.limit("10/minute")
def report_scam(request: Request, body: ReportRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    is_safe, reason = is_safe_to_process(body.scam_text)
    if not is_safe:
        raise HTTPException(status_code=400, detail=reason)
    sanitized_text, _ = sanitize_for_storage(body.scam_text)
    category = sanitize_message(body.category).sanitized_message
    new_report = ReportedScam(scam_text=sanitized_text, category=category, language=body.language, status="pending")
    db.add(new_report)
    try:
        db.commit()
        db.refresh(new_report)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="Report could not be saved. Please retry.") from None

    return {
        "status":  "received",
        "message": "Thank you! Your report is under review and will protect others soon.",
        "report_id": new_report.id,
        "reporter_stored": False,
    }


@app.post("/admin/reports/{report_id}/add-to-db")
def add_approved_to_vectorstore(
    report_id: int,
    db: Session = Depends(get_db),
    admin: bool = Depends(verify_admin),
):
    if vectorstore is None:
        raise HTTPException(status_code=503, detail="AI database unavailable")

    report = db.query(ReportedScam).filter(ReportedScam.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "approved":
        raise HTTPException(status_code=400, detail="Approve the report first via /admin/reports/{id}/approve")

    doc, result = prepare_anonymous_report(
        scam_text=report.scam_text,
        category=report.category,
        language=report.language,
        existing_fingerprints=scam_fingerprints
    )

    if doc is None:
        if result["duplicate"]:
            return {"status": "skipped", "reason": result["reason"]}
        raise HTTPException(status_code=400, detail=result["reason"])

    try:
        vectorstore.add_documents([doc], ids=[doc.metadata["id"]])
    except Exception:
        raise HTTPException(status_code=503, detail="Could not update the knowledge base") from None
    scam_fingerprints.add(result["fingerprint"])

    return {
        "status": "added",
        "message": f"Report #{report_id} added to protection database ✅",
        "total_patterns": vectorstore._collection.count()
    }


@app.post("/refresh")
@limiter.limit("1/hour")
async def manual_refresh(request: Request, admin: bool = Depends(verify_admin)):
    if not vectorstore:
        raise HTTPException(status_code=503, detail="Database not ready")
    return await daily_refresh_job(vectorstore)


@app.get("/stats")
async def get_stats():
    return {
        "total_scam_patterns": vectorstore._collection.count() if vectorstore else 0,
        "languages": ["Telugu", "Hindi", "Tamil", "English"],
        "channels":  ["SMS", "Email", "WhatsApp", "URL"],
        "status": "active" if vectorstore is not None and llm is not None else "unavailable"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)), access_log=False)