"""
TrapCheck — Daily PhishTank Auto-Refresh
==========================================
Automatically updates the scam database every day at midnight.
Uses APScheduler — runs inside FastAPI, no separate process needed.

WHAT IT DOES DAILY:
  1. Fetches latest verified phishing URLs from PhishTank
  2. Fetches latest CERT-In advisories
  3. Adds new patterns to ChromaDB
  4. Removes patterns older than 90 days (keeps DB fresh)
  5. Logs a summary of what changed

WHY THIS MATTERS:
  New scams emerge daily — especially UPI and KYC scams targeting
  Indian users. Without daily refresh, TrapCheck's database goes stale.
  With it, TrapCheck automatically knows about scams reported today.
"""

import os
import asyncio
import hashlib
import requests
import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from langchain_core.documents import Document

logger = logging.getLogger("trapcheck.safe")

# Global scheduler instance
scheduler = AsyncIOScheduler()


# ── PhishTank fetcher ─────────────────────────────────────────────────────────
async def fetch_and_update_phishtank(vectorstore):
    """
    Fetch latest phishing URLs from PhishTank and add to ChromaDB.
    
    PhishTank is a free community-maintained database of phishing URLs.
    Updated hourly with community-verified reports.
    We fetch once daily to stay current without hammering their API.
    """
    logger.info("🔄 Daily PhishTank refresh starting...")

    api_key = os.getenv("PHISHTANK_API_KEY", "")
    url = (
        f"https://data.phishtank.com/data/{api_key}/online-valid.json"
        if api_key else
        "https://data.phishtank.com/data/online-valid.json"
    )

    try:
        response = await asyncio.to_thread(requests.get, url, timeout=60)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        logger.warning("PhishTank fetch failed")
        return {"status": "failed", "reason": "Threat feed unavailable"}

    # Filter India-relevant phishing only
    india_keywords = [
        "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "googlepay",
        "upi", "aadhaar", "irctc", "uidai", "npci", "bhim", "neft", "imps",
        "yono", "kotak", "pnb", "canara", "union", "indian.bank"
    ]

    new_docs   = []
    seen_urls  = set()

    for entry in data:
        entry_url   = entry.get("url", "").lower()
        entry_target = entry.get("target", "").lower()

        # Skip non-India entries
        if not any(kw in entry_url or kw in entry_target for kw in india_keywords):
            continue

        # Skip duplicates in this batch
        if entry_url in seen_urls:
            continue
        seen_urls.add(entry_url)

        doc = Document(
            page_content=(
                f"Verified phishing URL: {entry.get('url')} "
                f"Targets: {entry.get('target', 'Unknown Indian bank/service')} "
                f"Verified by PhishTank community"
            ),
            metadata={
                "id":        f"pt_{entry.get('phish_id', '')}",
                "category":  "Verified Phishing URL",
                "language":  "en",
                "red_flags": "verified phishing, community confirmed",
                "source":    "PhishTank Daily Feed",
                "url":       entry.get("url", ""),
                "added_on":  datetime.utcnow().isoformat(),
            }
        )
        new_docs.append(doc)

    if new_docs:
        ids = ["pt_" + hashlib.sha256(doc.metadata["url"].encode()).hexdigest() for doc in new_docs]
        for start in range(0, len(new_docs), 100):
            await asyncio.to_thread(vectorstore.add_documents, new_docs[start:start + 100], ids=ids[start:start + 100])
        logger.info(f"✅ PhishTank refresh: added {len(new_docs)} new India-relevant URLs")
    else:
        logger.info("PhishTank refresh: no new India-relevant URLs found")

    return {
        "status":    "success",
        "new_added": len(new_docs),
        "timestamp": datetime.utcnow().isoformat()
    }


# ── CERT-In advisory fetcher ──────────────────────────────────────────────────
async def fetch_cert_in_advisories(vectorstore):
    """
    Fetch latest CERT-In (India's cybersecurity agency) advisories.
    CERT-In posts advisories about active threats targeting Indian users.
    
    In production: scrape https://www.cert-in.org.in
    Here: uses curated recent advisories as a starting point.
    """
    logger.info("🔄 Fetching CERT-In advisories...")

    # In production, scrape CERT-In website
    # For now, add any new manually curated advisories
    new_advisories = [
        {
            "text": "CERT-In Alert 2025: Fake Aadhaar update links circulating on WhatsApp and SMS. Links lead to phishing pages that steal banking credentials. Verify Aadhaar only at uidai.gov.in",
            "category": "Aadhaar Phishing",
            "language": "en",
            "source": "CERT-In Advisory 2025-001"
        },
        {
            "text": "CERT-In Warning 2025: Fraudulent electricity bill payment apps on Play Store. Apps mimic BESCOM, TSSPDCL, APSPDCL. Steal UPI credentials. Only pay through official utility websites.",
            "category": "Fake Utility App",
            "language": "en",
            "source": "CERT-In Advisory 2025-002"
        },
        {
            "text": "CERT-In 2025 హెచ్చరిక: WhatsApp లో fake job offers పంపబడుతున్నాయి. రోజుకు Rs.5000 అని చెప్పి registration fee తీసుకుంటున్నారు. ఇవి scams.",
            "category": "Fake Job Scam (Telugu)",
            "language": "te",
            "source": "CERT-In Advisory 2025-003"
        }
    ]

    docs = []
    for advisory in new_advisories:
        doc = Document(
            page_content=advisory["text"],
            metadata={
                "id":       f"certin_{datetime.utcnow().strftime('%Y%m%d')}_{advisory['source'][-3:]}",
                "category": advisory["category"],
                "language": advisory["language"],
                "red_flags": "official government advisory",
                "source":   advisory["source"],
                "added_on": datetime.utcnow().isoformat(),
            }
        )
        docs.append(doc)

    if docs:
        vectorstore.add_documents(docs)
        logger.info(f"✅ CERT-In: added {len(docs)} advisories")

    return {"status": "success", "added": len(docs)}


# ── Cleanup old entries ───────────────────────────────────────────────────────
async def cleanup_old_entries(vectorstore):
    """
    Remove phishing URL entries older than 90 days.
    
    WHY: PhishTank URLs get taken down. Old URLs in our DB waste space
    and could cause false positives on legitimate domains that were
    previously compromised but are now clean.
    
    We keep: scam patterns (timeless), CERT-In advisories
    We remove: PhishTank URLs older than 90 days
    """
    logger.info("🧹 Cleaning up old PhishTank entries...")

    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        collection = vectorstore._collection

        # Get all PhishTank entries
        results = collection.get(
            where={"source": "PhishTank Daily Feed"}
        )

        old_ids = []
        for i, meta in enumerate(results.get("metadatas", [])):
            if meta and meta.get("added_on", "9999") < cutoff:
                old_ids.append(results["ids"][i])

        if old_ids:
            collection.delete(ids=old_ids)
            logger.info(f"🧹 Removed {len(old_ids)} outdated PhishTank entries")
        else:
            logger.info("🧹 No outdated entries to remove")

        return {"removed": len(old_ids)}

    except Exception as e:
        logger.warning(f"Cleanup failed: {e}")
        return {"removed": 0, "error": str(e)}


# ── Full daily refresh job ────────────────────────────────────────────────────
async def daily_refresh_job(vectorstore):
    """
    Master daily job that runs all refresh tasks.
    Scheduled to run at midnight every day.
    """
    logger.info("=" * 40)
    logger.info("🌙 Daily TrapCheck database refresh starting")
    logger.info("=" * 40)

    results = {}

    # 1. Fetch new PhishTank URLs
    results["phishtank"] = await fetch_and_update_phishtank(vectorstore)

    results["cert_in"] = {"status": "disabled", "reason": "No verified live advisory source configured"}

    # 3. Clean up old entries
    results["cleanup"] = await cleanup_old_entries(vectorstore)

    # 4. Log summary
    total = vectorstore._collection.count()
    logger.info(f"✅ Daily refresh complete. Database now has {total} patterns.")
    logger.info("=" * 40)

    return results


# ── Scheduler setup ───────────────────────────────────────────────────────────
def setup_scheduler(vectorstore):
    """
    Set up APScheduler to run daily_refresh_job every day at midnight.
    Called once during FastAPI startup.
    
    APScheduler runs INSIDE FastAPI — no separate process or cron needed.
    """

    # Schedule daily refresh at midnight
    scheduler.add_job(
        daily_refresh_job,
        trigger=CronTrigger(hour=0, minute=0),   # midnight every day
        args=[vectorstore],
        id="daily_refresh",
        name="Daily PhishTank + CERT-In Refresh",
        replace_existing=True,
        misfire_grace_time=3600    # if server was down at midnight, run within 1 hour
    )

    # Also schedule cleanup weekly (Sunday 1am)
    scheduler.add_job(
        cleanup_old_entries,
        trigger=CronTrigger(day_of_week="sun", hour=1),
        args=[vectorstore],
        id="weekly_cleanup",
        name="Weekly Old Entry Cleanup",
        replace_existing=True,
    )

    scheduler.start()
    logger.info("✅ Scheduler started — daily refresh at midnight, weekly cleanup Sundays")

    return scheduler


def stop_scheduler():
    """Stop scheduler gracefully on server shutdown."""
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
