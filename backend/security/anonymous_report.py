"""
TrapCheck — Security Layer 4: Anonymized Reporting
=====================================================
PURPOSE:
  When users report new scams via /report, we want to save the SCAM PATTERN
  to ChromaDB — not any personal information about who reported it or 
  what personal data was in the message.
  
  This module ensures every report is anonymized before storage.

WHAT IT DOES:
  1. Strips all personal data from reported scam text (uses sanitizer.py)
  2. Never stores who reported the scam (no user ID, no IP, no timestamp)
  3. Extracts only the "scam fingerprint" — the pattern that makes it a scam
  4. Validates the report is actually a scam pattern (not personal data)
  5. Deduplicates — don't store same scam twice

WHAT GETS STORED IN CHROMADB:
  ✅ The scam pattern text (sanitized)
  ✅ Category (UPI Fraud, KYC Scam, etc.)
  ✅ Language (te, hi, en, ta)
  ✅ Source: "TrapCheck Community"
  
  ❌ Who reported it
  ❌ When it was reported  
  ❌ IP address of reporter
  ❌ Any personal data from the message
"""

import re
import hashlib
from typing import Tuple, Optional
from langchain_core.documents import Document

from security.sanitizer import sanitize_for_storage, is_safe_to_process


# ── Scam pattern validator ────────────────────────────────────────────────────
# These keywords suggest a message is actually a scam pattern worth storing
SCAM_INDICATORS = {
    "en": [
        "click", "verify", "urgent", "expire", "block", "suspended",
        "otp", "kyc", "upi", "account", "prize", "won", "free",
        "whatsapp", "call now", "limited time", "claim", "reward"
    ],
    "te": [
        "క్లిక్", "verify", "expire", "block", "suspended", "otp",
        "kyc", "upi", "account", "బహుమతి", "గెలిచారు", "free",
        "ఇప్పుడే", "వెంటనే", "అత్యవసర"
    ],
    "hi": [
        "क्लिक", "verify", "expire", "block", "suspended", "otp",
        "kyc", "upi", "account", "इनाम", "जीता", "free",
        "अभी", "तुरंत", "जरूरी"
    ],
    "ta": [
        "click", "verify", "expire", "block", "suspended", "otp",
        "kyc", "upi", "account", "பரிசு", "வென்றீர்கள்", "free",
        "இப்போதே", "உடனே", "அவசரம்"
    ]
}


def validate_is_scam_pattern(text: str, language: str = "en") -> Tuple[bool, str]:
    """
    Check if the reported text actually looks like a scam pattern.
    Reject reports that are just personal data or gibberish.
    
    Returns: (is_valid, reason)
    """
    # Basic length check
    is_safe, reason = is_safe_to_process(text)
    if not is_safe:
        return False, reason

    # Must contain at least one scam indicator
    text_lower = text.lower()
    indicators = SCAM_INDICATORS.get(language, SCAM_INDICATORS["en"])
    
    found_indicators = [ind for ind in indicators if ind.lower() in text_lower]
    
    if not found_indicators:
        # Also check English indicators for non-English text (many scams mix languages)
        found_indicators = [ind for ind in SCAM_INDICATORS["en"] if ind.lower() in text_lower]

    if not found_indicators:
        return False, "Text doesn't appear to contain scam patterns"

    return True, f"Valid scam pattern (indicators: {', '.join(found_indicators[:3])})"


def generate_scam_fingerprint(text: str) -> str:
    """
    Generate a unique fingerprint for a scam pattern.
    Used to detect duplicates — don't store the same scam twice.
    
    HOW IT WORKS:
    1. Normalize the text (lowercase, remove extra spaces)
    2. Remove all personal data placeholders (they vary per instance)
    3. Hash the normalized text
    
    Example:
      "Your KYC expires [PHONE]" and "Your KYC expires [PHONE] today"
      → Different hashes (different patterns)
      
      "Your KYC expires [PHONE]" reported twice
      → Same hash → duplicate detected → not stored again
    """
    # Normalize
    normalized = text.lower().strip()
    normalized = re.sub(r'\s+', ' ', normalized)  # collapse whitespace
    
    # Remove placeholder variations (they come from sanitizer)
    for placeholder in ["[PHONE]", "[AADHAAR]", "[OTP]", "[EMAIL]", "[UPI_ID]", "[NAME]", "[NUMBER]"]:
        normalized = normalized.replace(placeholder.lower(), "")
    
    # Generate SHA256 fingerprint (first 16 chars)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def prepare_anonymous_report(
    scam_text: str,
    category: str,
    language: str,
    existing_fingerprints: set
) -> Tuple[Optional[Document], dict]:
    """
    Full anonymization pipeline for a user-reported scam.
    
    Steps:
    1. Validate it's actually a scam pattern
    2. Sanitize all personal data
    3. Check for duplicates
    4. Create anonymous ChromaDB Document (no reporter info)
    
    Returns:
        (Document to store, report of what happened)
        Document is None if report was rejected
    """
    report = {
        "accepted": False,
        "reason": "",
        "items_sanitized": {},
        "duplicate": False
    }

    # ── Step 1: Validate ─────────────────────────────────────────────────────
    is_valid, reason = validate_is_scam_pattern(scam_text, language)
    if not is_valid:
        report["reason"] = f"Rejected: {reason}"
        return None, report

    # ── Step 2: Sanitize ─────────────────────────────────────────────────────
    sanitized_text, sanitization_info = sanitize_for_storage(scam_text)
    report["items_sanitized"] = sanitization_info.get("items_sanitized", {})

    # ── Step 3: Check for duplicates ─────────────────────────────────────────
    fingerprint = generate_scam_fingerprint(sanitized_text)
    if fingerprint in existing_fingerprints:
        report["duplicate"] = True
        report["reason"] = "Duplicate pattern already in database"
        return None, report

    # ── Step 4: Create anonymous Document ────────────────────────────────────
    # Notice: NO reporter info, NO timestamp, NO IP
    doc = Document(
        page_content=sanitized_text,
        metadata={
            "id":          f"community_{fingerprint}",
            "category":    category,
            "language":    language,
            "red_flags":   "community-reported",
            "source":      "TrapCheck Community",
            "fingerprint": fingerprint,
            # Deliberately NOT storing: reporter IP, time, user ID
        }
    )

    report["accepted"] = True
    report["reason"] = f"Accepted and anonymized. Removed: {report['items_sanitized']}"
    report["fingerprint"] = fingerprint

    return doc, report
