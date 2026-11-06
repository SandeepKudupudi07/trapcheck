"""
TrapCheck — Security Layer 2: Message Sanitizer
=================================================
PURPOSE:
  Users often paste real scam messages that contain THEIR OWN personal info.
  Example: A scam SMS might include the victim's name, phone, or partial account.
  Before we process anything, we strip all personal identifiers.

WHAT IT DOES:
  1. Detects and removes Indian phone numbers
  2. Detects and removes Aadhaar numbers
  3. Detects and removes OTPs
  4. Detects and removes account numbers
  5. Detects and removes real names (basic heuristic)
  6. Keeps the scam indicators intact (URLs, keywords, patterns)

EXAMPLE:
  Input:  "Dear Raju, your SBI account 9876543210 KYC expires. 
           Call 9123456789 or click sbi-kyc.xyz. OTP: 847291"
           
  Output: "Dear [NAME], your SBI account [PHONE] KYC expires.
           Call [PHONE] or click sbi-kyc.xyz. OTP: [OTP]"

  → Scam indicators preserved (sbi-kyc.xyz, KYC expires)
  → Personal data removed (phone, OTP)
"""

import re
from dataclasses import dataclass
from typing import Tuple


@dataclass
class SanitizationReport:
    """What was found and removed during sanitization."""
    original_length:   int
    sanitized_length:  int
    items_removed:     dict   # { "phone_numbers": 2, "otps": 1, ... }
    sanitized_message: str


# ── Regex patterns for Indian personal data ───────────────────────────────────
PATTERNS = {

    # Indian mobile numbers: starts with 6-9, 10 digits
    # Matches: 9876543210 | +919876543210 | 91-9876543210 | +91 98765 43210
    "phone_numbers": [
        r'\+91[-\s]?[6-9]\d{9}',
        r'\b91[6-9]\d{9}\b',
        r'\b[6-9]\d{9}\b',
        r'\b[6-9]\d{4}[-\s]\d{5}\b',
    ],

    # Aadhaar: 12 digits, sometimes space/dash separated
    # Matches: 1234 5678 9012 | 1234-5678-9012 | 123456789012
    "aadhaar_numbers": [
        r'\b\d{4}[-\s]\d{4}[-\s]\d{4}\b',
        r'\b\d{12}\b',
    ],

    # OTPs: 4-8 digit codes, often labeled
    # Matches: OTP: 847291 | OTP is 1234 | verification code: 567890
    "otps": [
        r'\b(?:OTP|otp|one.?time.?password|verification.?code)\s*[:\-is]*\s*\d{4,8}\b',
        r'\bcode\s*[:\-]\s*\d{4,8}\b',
    ],

    # Bank account numbers: 9-18 digits
    "account_numbers": [
        r'\baccount\s*(?:no|number|#)?\s*[:\-]?\s*\d{9,18}\b',
        r'\b\d{9,18}\b(?=\s*(?:is|account|bank))',
    ],

    # UPI IDs: word@word format
    "upi_ids": [
        r'\b[\w.\-]+@(?:okaxis|oksbi|okicici|okhdfcbank|ybl|upi|paytm|gpay)\b',
        r'\b[\w.\-]{3,}@[\w]{3,}\b',
    ],

    # Email addresses
    "email_addresses": [
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
    ],

    # IFSC codes: 4 letters + 0 + 6 alphanumeric
    "ifsc_codes": [
        r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
    ],

    # PAN numbers: 5 letters + 4 digits + 1 letter
    "pan_numbers": [
        r'\b[A-Z]{5}\d{4}[A-Z]\b',
    ],

    # Debit/Credit card numbers: 16 digits, may have spaces/dashes
    "card_numbers": [
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    ],
}

# Replacement labels for each pattern type
REPLACEMENTS = {
    "phone_numbers":    "[PHONE]",
    "aadhaar_numbers":  "[AADHAAR]",
    "otps":             "[OTP]",
    "account_numbers":  "[ACCOUNT]",
    "upi_ids":          "[UPI_ID]",
    "email_addresses":  "[EMAIL]",
    "ifsc_codes":       "[IFSC]",
    "pan_numbers":      "[PAN]",
    "card_numbers":     "[CARD]",
}


def sanitize_message(message: str) -> SanitizationReport:
    """
    Main sanitization function.
    
    Strips all personal identifiers from a message while preserving
    the scam indicators (suspicious URLs, keywords, patterns).
    
    Args:
        message: Raw user message that may contain personal data
        
    Returns:
        SanitizationReport with sanitized message and what was removed
    """
    sanitized = message
    items_removed = {}

    ordered_categories = ["email_addresses", "card_numbers", "aadhaar_numbers"]
    ordered_categories += [category for category in PATTERNS if category not in ordered_categories]
    for category in ordered_categories:
        patterns = PATTERNS[category]
        count = 0
        replacement = REPLACEMENTS[category]

        for pattern in patterns:
            matches = re.findall(pattern, sanitized, re.IGNORECASE)
            count += len(matches)
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        if count > 0:
            items_removed[category] = count

    return SanitizationReport(
        original_length=len(message),
        sanitized_length=len(sanitized),
        items_removed=items_removed,
        sanitized_message=sanitized
    )


def sanitize_for_storage(scam_text: str) -> Tuple[str, dict]:
    """
    Extra-strict sanitization for text being saved to ChromaDB.
    Used when users report new scams via /report endpoint.
    
    We save scam PATTERNS not personal data — so this strips
    even more aggressively before anything touches the database.
    
    Returns:
        (sanitized_text, report_dict)
    """
    report = sanitize_message(scam_text)
    sanitized = report.sanitized_message

    # Additional cleanup for storage — remove anything that looks like
    # it could identify the reporter or victim
    
    # Remove potential names (capitalized words that aren't at start of sentence)
    sanitized = re.sub(r'(?<=[,\s])([A-Z][a-z]{2,15})(?=[\s,.])', '[NAME]', sanitized)

    # Remove any remaining long digit sequences
    sanitized = re.sub(r'\b\d{6,}\b', '[NUMBER]', sanitized)

    return sanitized, {
        "items_sanitized": report.items_removed,
        "length_before": report.original_length,
        "length_after": len(sanitized)
    }


def is_safe_to_process(message: str) -> Tuple[bool, str]:
    """
    Quick safety check before processing.
    Rejects messages that are clearly not scam reports
    (e.g. someone accidentally pasting their own credentials).
    
    Returns:
        (is_safe, reason)
    """
    # Reject if message is just a phone number or Aadhaar
    if re.fullmatch(r'[\d\s\-+]{10,15}', message.strip()):
        return False, "Message appears to be just a phone number"

    if re.fullmatch(r'[\d\s\-]{12,14}', message.strip()):
        return False, "Message appears to be just an Aadhaar number"

    # Reject very short messages (less than 10 chars)
    if len(message.strip()) < 10:
        return False, "Message too short to analyze"

    # Reject very long messages (over 5000 chars — likely a paste error)
    if len(message.strip()) > 5000:
        return False, "Message too long — please paste just the suspicious part"

    return True, "OK"
