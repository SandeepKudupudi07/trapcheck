"""
TrapCheck - PhishTank Data Loader
===================================
Fetches real phishing URLs from PhishTank API
and loads them into ChromaDB for RAG retrieval.

Run this script once a day (via cron job) to keep
the database fresh with latest phishing URLs.

Usage:
    python scripts/load_phishtank.py
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

# Add parent to path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.rag_engine import get_embeddings_model, load_existing_vectorstore
from langchain_core.documents import Document


def fetch_phishtank_data(limit: int = 500):
    """
    Fetch verified phishing URLs from PhishTank API.
    PhishTank is free and updated hourly with community-verified phishing URLs.
    
    Returns list of phishing entries with URL, target, and submission date.
    """
    print("🌐 Fetching PhishTank data...")
    
    api_key = os.getenv("PHISHTANK_API_KEY")
    
    # PhishTank provides a JSON feed of verified phishing URLs
    url = "https://data.phishtank.com/data/online-valid.json"
    if api_key:
        url = f"https://data.phishtank.com/data/{api_key}/online-valid.json"
    
    try:
        response = requests.get(url, timeout=30)
        data = response.json()
        
        # Filter for India-relevant phishing (UPI, banking, government)
        india_keywords = [
            "sbi", "hdfc", "icici", "axis", "paytm", "phonepe",
            "upi", "aadhaar", "irctc", "uidai", "npci", "bhim"
        ]
        
        india_phishing = []
        for entry in data[:limit]:
            url_lower = entry.get("url", "").lower()
            target = entry.get("target", "").lower()
            
            if any(kw in url_lower or kw in target for kw in india_keywords):
                india_phishing.append(entry)
        
        print(f"✅ Found {len(india_phishing)} India-relevant phishing URLs")
        return india_phishing
        
    except Exception as e:
        print(f"❌ PhishTank fetch failed: {e}")
        return []


def load_phishtank_into_chromadb(vectorstore):
    """
    Load PhishTank URLs into ChromaDB as searchable documents.
    """
    phishing_data = fetch_phishtank_data()
    
    if not phishing_data:
        print("No data to load.")
        return
    
    documents = []
    for entry in phishing_data:
        # Create descriptive text for each phishing URL
        # This text is what gets embedded and searched
        text = f"Phishing URL: {entry.get('url', '')} Target: {entry.get('target', 'Unknown')} Verified: {entry.get('verification_time', '')}"
        
        doc = Document(
            page_content=text,
            metadata={
                "id":       f"phishtank_{entry.get('phish_id', '')}",
                "category": "Verified Phishing URL",
                "language": "en",
                "red_flags": "verified phishing URL, community confirmed",
                "source":   "PhishTank Database",
                "url":      entry.get("url", ""),
                "target":   entry.get("target", "")
            }
        )
        documents.append(doc)
    
    # Add to existing ChromaDB
    vectorstore.add_documents(documents)
    print(f"✅ Added {len(documents)} PhishTank URLs to ChromaDB!")


def load_cert_in_advisories(vectorstore):
    """
    Load CERT-In (India's cybersecurity agency) advisories.
    
    In production: scrape https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01
    For now: manually curated recent advisories
    """
    cert_in_advisories = [
        {
            "text": "CERT-In Advisory: Fake investment apps promising high returns via WhatsApp groups. Apps collect personal and banking data. Common targets: Telugu and Hindi speaking users in Andhra Pradesh, Telangana, Maharashtra.",
            "category": "Fake Investment App",
            "source": "CERT-In Advisory CI-24-001"
        },
        {
            "text": "CERT-In Warning: SMS phishing (smishing) campaign impersonating TRAI (Telecom Regulatory Authority). Messages claim mobile number will be blocked. Asks users to call a fraudulent number.",
            "category": "TRAI Impersonation Scam",
            "source": "CERT-In Advisory CI-24-002"
        },
        {
            "text": "CERT-In Alert: Fake electricity bill payment links circulating via WhatsApp. Links redirect to fake BESCOM/APSEB/TSECL portals. Steal banking credentials.",
            "category": "Fake Utility Bill Scam",
            "source": "CERT-In Advisory CI-24-003"
        },
        {
            "text": "విద్యుత్ బిల్లు payment కోసం fake WhatsApp links వస్తున్నాయి. CERT-In హెచ్చరిక: ఇవి మీ bank details దొంగిలించే scam links.",
            "category": "Fake Utility Bill Scam (Telugu)",
            "source": "CERT-In Advisory CI-24-003"
        }
    ]
    
    documents = []
    for i, advisory in enumerate(cert_in_advisories):
        doc = Document(
            page_content=advisory["text"],
            metadata={
                "id":       f"certin_{i:03d}",
                "category": advisory["category"],
                "language": "te" if "విద్యుత్" in advisory["text"] else "en",
                "red_flags": "official government advisory",
                "source":   advisory["source"]
            }
        )
        documents.append(doc)
    
    vectorstore.add_documents(documents)
    print(f"✅ Added {len(documents)} CERT-In advisories to ChromaDB!")


if __name__ == "__main__":
    print("🚀 TrapCheck Data Loader Starting...")
    
    embeddings = get_embeddings_model()
    vectorstore = load_existing_vectorstore(embeddings)
    
    # Load PhishTank URLs
    load_phishtank_into_chromadb(vectorstore)
    
    # Load CERT-In advisories
    load_cert_in_advisories(vectorstore)
    
    print("✅ All data loaded! TrapCheck database is up to date.")
