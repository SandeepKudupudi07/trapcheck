# TrapCheck Scam Knowledge Base
# This data gets loaded into ChromaDB as vectors
# Each entry = one scam pattern the RAG will retrieve from

scam_patterns = [

    # ── UPI / PAYMENT SCAMS ──────────────────────────────────────────
    {
        "id": "upi_001",
        "text": "Your UPI ID has been blocked. Click here to reactivate immediately or your account will be permanently suspended. Reactivate now: bit.ly/upi-reactivate",
        "category": "UPI Fraud",
        "language": "en",
        "red_flags": ["urgency", "suspicious URL", "account threat", "bit.ly shortener"],
        "source": "CERT-In Advisory 2024"
    },
    {
        "id": "upi_002",
        "text": "మీ UPI ID బ్లాక్ అయింది. వెంటనే ఇక్కడ క్లిక్ చేయండి లేకపోతే మీ account శాశ్వతంగా మూసివేయబడుతుంది",
        "category": "UPI Fraud",
        "language": "te",
        "red_flags": ["urgency", "account threat", "Telugu phishing"],
        "source": "RBI Fraud Alert 2024"
    },
    {
        "id": "upi_003",
        "text": "Congratulations! You have received Rs.50,000 in your UPI account. To claim, share your UPI PIN and OTP with our agent.",
        "category": "UPI Reward Scam",
        "language": "en",
        "red_flags": ["fake reward", "asking for PIN", "asking for OTP", "too good to be true"],
        "source": "PhishTank Database"
    },

    # ── KYC SCAMS ────────────────────────────────────────────────────
    {
        "id": "kyc_001",
        "text": "Your SBI KYC verification is pending. Your account will be blocked in 24 hours. Update KYC: sbi-kyc-update.xyz/verify",
        "category": "KYC Fraud",
        "language": "en",
        "red_flags": ["fake bank domain", "24 hour urgency", "account block threat", "non-official domain"],
        "source": "CERT-In Advisory 2024"
    },
    {
        "id": "kyc_002",
        "text": "మీ Aadhaar KYC గడువు తీరిపోతుంది. 24 గంటల్లో update చేయకపోతే మీ bank account block అవుతుంది. ఇప్పుడే చేయండి",
        "category": "KYC Fraud",
        "language": "te",
        "red_flags": ["Aadhaar impersonation", "urgency", "bank block threat", "Telugu phishing"],
        "source": "RBI Fraud Alert 2024"
    },
    {
        "id": "kyc_003",
        "text": "आपका KYC अपडेट नहीं है। आपका बैंक अकाउंट 48 घंटे में बंद हो जाएगा। अभी अपडेट करें।",
        "category": "KYC Fraud",
        "language": "hi",
        "red_flags": ["Hindi phishing", "urgency", "account block threat"],
        "source": "RBI Fraud Alert 2024"
    },

    # ── OTP SCAMS ────────────────────────────────────────────────────
    {
        "id": "otp_001",
        "text": "This is SBI customer care. We are updating your account security. Please share the OTP you just received to complete verification.",
        "category": "OTP Theft",
        "language": "en",
        "red_flags": ["asking for OTP", "bank impersonation", "fake customer care"],
        "source": "SBI Security Advisory"
    },
    {
        "id": "otp_002",
        "text": "మీ phone number verify చేయడానికి మీకు వచ్చిన OTP చెప్పండి. ఇది SBI customer care నుండి",
        "category": "OTP Theft",
        "language": "te",
        "red_flags": ["OTP request", "bank impersonation", "Telugu social engineering"],
        "source": "RBI Fraud Alert 2024"
    },

    # ── FAKE JOB SCAMS ───────────────────────────────────────────────
    {
        "id": "job_001",
        "text": "Work from home job offer! Earn Rs.5000 per day just by liking YouTube videos. No experience needed. Registration fee: Rs.500 only. WhatsApp: +91-9XXXXXXXXX",
        "category": "Fake Job Scam",
        "language": "en",
        "red_flags": ["unrealistic earnings", "registration fee", "WhatsApp job offer", "no experience claim"],
        "source": "Consumer Forum Reports 2024"
    },
    {
        "id": "job_002",
        "text": "గృహిణులకు మరియు విద్యార్థులకు అద్భుతమైన అవకాశం! రోజుకు Rs.3000 సంపాదించండి. Registration fee కేవలం Rs.299",
        "category": "Fake Job Scam",
        "language": "te",
        "red_flags": ["Telugu fake job", "unrealistic earnings", "registration fee"],
        "source": "Consumer Forum Reports 2024"
    },

    # ── GOVERNMENT SCHEME SCAMS ──────────────────────────────────────
    {
        "id": "gov_001",
        "text": "PM Awas Yojana: You are selected for free house scheme. Claim your Rs.2,50,000 benefit. Click: pmawas-apply.in/claim?id=12345",
        "category": "Fake Government Scheme",
        "language": "en",
        "red_flags": ["government impersonation", "fake domain", "unsolicited selection", "suspicious URL"],
        "source": "PIB Fact Check"
    },
    {
        "id": "gov_002",
        "text": "మీరు PM Kisan Yojana కింద ఎంపికయ్యారు. Rs.6000 పొందడానికి మీ Aadhaar మరియు bank details enter చేయండి",
        "category": "Fake Government Scheme",
        "language": "te",
        "red_flags": ["government impersonation", "asking for Aadhaar", "bank details request", "Telugu phishing"],
        "source": "PIB Fact Check"
    },

    # ── LOTTERY / PRIZE SCAMS ────────────────────────────────────────
    {
        "id": "lottery_001",
        "text": "You have won Rs.25 Lakh in KBC lottery! To claim your prize, pay processing fee of Rs.2500 to this account and send your Aadhaar copy.",
        "category": "Lottery Scam",
        "language": "en",
        "red_flags": ["fake lottery", "advance fee fraud", "KBC impersonation", "Aadhaar request"],
        "source": "PhishTank Database"
    },

    # ── PHISHING URLS ────────────────────────────────────────────────
    {
        "id": "url_001",
        "text": "sbi-kyc-update.xyz",
        "category": "Phishing URL",
        "language": "en",
        "red_flags": ["fake SBI domain", "non-official TLD", "kyc keyword"],
        "source": "PhishTank Database"
    },
    {
        "id": "url_002",
        "text": "pmawas-apply.in",
        "category": "Phishing URL",
        "language": "en",
        "red_flags": ["fake government domain", "impersonates PM Awas Yojana"],
        "source": "CERT-In URL Blacklist"
    },
    {
        "id": "url_003",
        "text": "upi-reactivate.net upi-block.com paytm-kyc.xyz phonepe-verify.in",
        "category": "Phishing URL",
        "language": "en",
        "red_flags": ["fake UPI domains", "impersonates payment apps"],
        "source": "PhishTank Database"
    },
]
