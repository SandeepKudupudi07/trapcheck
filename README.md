# 🛡️ TrapCheck — Multilingual AI Scam Detector

> AI-powered scam detection chatbot for Telugu, Hindi, Tamil & English users.
> Built with LangChain + ChromaDB + Ollama (gemma:2b) + FastAPI + React.
> Messages reach the configured backend. Ollama inference can run locally; SMTP, Twilio and threat-feed integrations use the network.

## Repair status and current setup

Use Python 3.11 and the isolated project `.venv`. Old global Python packages conflict; do not use them to launch the backend. Requirements now use the modular LangChain integrations.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` only for a new installation; never overwrite an existing configuration. Generate separate random JWT and admin secrets of at least 32 characters. `JWT_SECRET_KEY` is mandatory; admin routes fail closed without a strong `ADMIN_SECRET`. Existing environment files and database records were not intentionally changed by the repairs.

Install/start Ollama and install the configured model (`gemma:2b` by default). The embedding model downloads on first successful initialization and requires network access and sufficient disk/RAM. Backend startup checks the Ollama model before loading embeddings. Relative database paths are resolved against `backend`, regardless of the shell directory. Back up an existing Chroma directory before opening it with the upgraded dependencies; old database migration has not been verified.

```powershell
ollama pull gemma:2b
.\.venv\Scripts\python.exe backend\main.py
```

In a separate terminal:

```powershell
$env:VITE_API_BASE = "http://127.0.0.1:8000"
npm --prefix frontend/trapcheck-frontend run dev -- --host 127.0.0.1
```

On this machine, the npm shim on PATH is broken. Use `D:\nodejs\node.exe D:\nodejs\node_modules\npm\bin\npm-cli.js` in place of `npm`, without changing global installations. Add the actual frontend origin to `CORS_ORIGINS` when hosting elsewhere. For Twilio behind a tunnel, set `TWILIO_WEBHOOK_BASE_URL` to the public origin configured at Twilio; unsigned webhooks are rejected.

`/health` returns HTTP 503 when AI initialization is unavailable, rather than pretending the detector is ready. Authentication and sanitized report submission can still operate. Restart the backend after repairing model configuration. Analysis and reporting require login. Admin approval and adding a report to the knowledge base are separate operations. Unverified hard-coded CERT-In advisories are not imported by the scheduled refresh.

### Verification commands

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -v
npm --prefix frontend/trapcheck-frontend test
npm --prefix frontend/trapcheck-frontend run lint
npm --prefix frontend/trapcheck-frontend run build
```

Automated API tests use isolated databases and mocked model/email boundaries, not real scam-detection accuracy. Real Ollama inference, old Chroma migration, browser interaction, SMTP delivery, and Twilio delivery require separate verification. At repair time Ollama/model files were absent and the Browser Connector was disconnected. Do not present automated tests as proof of a bug-free or production-ready system.

### Project explanation and demo preparation

- **30-second pitch:** TrapCheck helps users assess suspicious text in English, Telugu, Hindi and Tamil. It retrieves related scam patterns and asks a locally hosted language model for a structured risk assessment and recommended action.
- **Data flow:** React submits an authenticated message to FastAPI; validation and heuristic PII sanitization run first; multilingual embeddings retrieve Chroma patterns; Ollama analyzes the context; strict response validation rejects malformed output; a sanitized preview and result are saved to SQLite history.
- **RAG versus training:** Retrieval supplies reference patterns at inference time; reporting does not train or fine-tune the model. Admin-approved patterns can update the retrieval database.
- **Security:** bcrypt password hashing, signed expiring JWTs, password-reset token revocation, limited OTP attempts, request rate limits, restricted CORS, admin keys, and Twilio signature checks. Application code excludes raw model output and reset codes from logs.
- **Privacy limitations:** Sanitization is heuristic, not guaranteed anonymization. Authenticated history and sanitized reports persist. Python cannot guarantee memory erasure; a remote backend still receives submitted messages.
- **Accuracy limitations:** SAFE is not a guarantee. Model confidence is self-reported, not a calibrated probability. Multilingual UI does not establish equal accuracy in every language; measure with labeled benign/scam samples before making accuracy claims.
- **Demo sequence:** Show language selection, register/login, analyze synthetic scam and benign examples, inspect history, submit a report, and show an invalid-input or unavailable-model error. Never use real credentials, OTPs, or personal financial data in a demo.
- **Likely questions:** Why RAG rather than keywords? Why Chroma and SQLite? How are expired tokens handled? What prevents malicious reports from entering retrieval? What happens when the model fails? How would you measure false positives and false negatives?

### Git publication gate

Only the nested frontend currently has Git metadata; publishing it alone omits the backend. The configured Git remote contained an embedded token and the old sample configuration contained credential-like values. Revoke/rotate exposed credentials, authenticate GitHub locally, exclude databases/environment files, and review a full-project repository layout before publishing a new branch. No publication is authorized by a passing unit test alone.

**Live App:** https://SandeepKudupudi07.github.io/trapcheck  
**Backend API:** https://lilyana-unthanking-earnestly.ngrok-free.dev  
**API Docs:** https://lilyana-unthanking-earnestly.ngrok-free.dev/docs

---

## 🏗️ Architecture

```
User (Browser)
     │
     ▼
┌─────────────────────────────────┐
│  React Frontend (GitHub Pages)  │
│  TrapCheck.jsx + History.jsx    │
└──────────────┬──────────────────┘
               │ HTTPS via ngrok
               ▼
┌─────────────────────────────────┐
│  FastAPI Backend (localhost:8000)│
│  ├── Auth (JWT)                 │
│  ├── Rate Limiting (slowapi)    │
│  ├── Security Layers (1-4)      │
│  └── RAG Engine                 │
│       ├── multilingual-e5-large │
│       ├── ChromaDB              │
│       └── gemma:2b via Ollama   │
└─────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  SQLite Database                │
│  ├── users                      │
│  ├── scan_history               │
│  └── reported_scams             │
└─────────────────────────────────┘
```

---

## ✅ Features

### Core
- 🧠 RAG-powered scam detection
- 🌐 4 languages: Telugu, Hindi, Tamil, English
- 📱 4 channels: SMS, WhatsApp, Email, URL
- 🤖 Local LLM (gemma:2b via Ollama) — no API costs
- 🔍 multilingual-e5-large embeddings

### User Accounts
- 📝 Register / Login / Logout
- 🔑 JWT authentication
- 📧 Password reset via email OTP
- 📊 Scan history + stats dashboard
- 🗑️ GDPR right to erasure

### Security (4 Layers)
- Layer 1: Zero logging middleware
- Layer 2: Message sanitization (removes PII)
- Layer 3: Ephemeral processing
- Layer 4: Anonymous reporting

### Community
- 🚩 Report scam button on every analysis
- 👨‍💼 Admin review panel (approve/reject)
- 📥 Export scams as CSV/JSON for AI training
- 🔄 Daily PhishTank auto-refresh

### UI/UX
- 🌍 Full native language UI (తెలుగు/हिंदी/தமிழ்/English)
- 📈 History page with threat breakdown
- ⚡ Live loading steps during analysis
- 🔐 Login-required flow

### Infrastructure
- ⚡ Rate limiting (20/min analyze, 5/min login)
- 📱 Twilio WhatsApp/SMS webhooks
- 🌐 GitHub Pages frontend
- 🔗 ngrok static domain

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| FastAPI | REST API backend |
| LangChain | RAG pipeline |
| ChromaDB 0.4.24 | Vector database |
| multilingual-e5-large | Multilingual embeddings |
| gemma:2b (Ollama) | Local LLM |
| SQLite + SQLAlchemy | User database |
| JWT + bcrypt | Authentication |
| slowapi | Rate limiting |
| React + Vite | Frontend |
| GitHub Pages | Frontend hosting |
| ngrok | Backend tunnel |

---

## 📁 Project Structure

```
trapcheck/
├── backend/
│   ├── main.py                    ← FastAPI server
│   ├── rag_engine.py              ← RAG pipeline
│   ├── auth/
│   │   ├── database.py            ← SQLite models
│   │   ├── auth.py                ← bcrypt + JWT
│   │   ├── routes.py              ← /auth/* endpoints
│   │   ├── admin_routes.py        ← /admin/* endpoints
│   │   └── email_service.py       ← Gmail SMTP reset
│   ├── security/
│   │   ├── zero_log.py
│   │   ├── sanitizer.py
│   │   ├── ephemeral.py
│   │   └── anonymous_report.py
│   ├── channels/
│   │   └── twilio_handler.py
│   └── scheduler/
│       └── refresh.py
├── data/
│   ├── scam_patterns.py
│   └── chromadb/
├── frontend/
│   ├── src/
│   │   ├── TrapCheck.jsx
│   │   └── History.jsx
│   ├── package.json
│   └── vite.config.js
├── scripts/
│   └── load_phishtank.py
├── start_backend.bat
├── start_ngrok.bat
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🚀 Daily Usage (Windows)

### Start the app
```
1. Double-click start_backend.bat
2. Double-click start_ngrok.bat
3. Share: https://SandeepKudupudi07.github.io/trapcheck
```

### Redeploy frontend after changes
```powershell
cd E:\trapcheck\trapcheck\frontend\trapcheck-frontend
npm run build
npm run deploy
```

---

## ⚙️ Environment Variables (.env)

```env
OLLAMA_MODEL=gemma:2b
OLLAMA_BASE_URL=http://localhost:11434
EMBEDDINGS_MODEL=intfloat/multilingual-e5-large
CHROMA_DB_PATH=./data/chromadb
DATABASE_URL=sqlite:///./data/trapcheck.db
JWT_SECRET_KEY=your-secret-key
JWT_EXPIRY_HOURS=24
SMTP_EMAIL=your-gmail@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_NAME=TrapCheck
ADMIN_SECRET=your-admin-secret
HOST=0.0.0.0
PORT=8000
```

---

## 📡 API Endpoints

### Public
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /analyze | Analyze message |
| POST | /report | Report a scam |
| GET | /health | Health check |
| GET | /stats | DB stats |
| GET | /privacy | Privacy info |

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | Create account |
| POST | /auth/login | Login |
| GET | /auth/me | Current user |
| GET | /auth/history | Scan history |
| GET | /auth/stats | Personal stats |
| POST | /auth/forgot-password | Send OTP |
| POST | /auth/reset-password | Reset password |
| DELETE | /auth/account | Delete account |

### Admin (X-Admin-Key header required)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /admin/reports | List reports |
| POST | /admin/reports/{id}/approve | Approve |
| POST | /admin/reports/{id}/reject | Reject |
| POST | /admin/reports/{id}/add-to-db | Add to ChromaDB |
| GET | /admin/export | Download CSV/JSON |
| GET | /admin/stats | Platform stats |

### Webhooks
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /webhook/whatsapp | Twilio WhatsApp |
| POST | /webhook/sms | Twilio SMS |

---

## 🌐 Deployment Info

| Component | Platform | URL |
|-----------|----------|-----|
| Frontend | GitHub Pages | https://SandeepKudupudi07.github.io/trapcheck |
| Backend | Local + ngrok | https://lilyana-unthanking-earnestly.ngrok-free.dev |
| Database | Local SQLite | backend/data/trapcheck.db |
| LLM | Local Ollama | localhost:11434 |

---

## ⚠️ Known Limitations

- PC must stay ON for backend to work
- ngrok free = 1 tunnel at a time
- gemma:2b responses: 10-30 seconds (local LLM)
- SQLite: suitable for small-medium usage

---

## 🔮 Future Plans

- [ ] Kannada, Malayalam, Bengali support
- [ ] Mobile app (React Native)
- [ ] PostgreSQL for scale
- [ ] Cloud GPU for faster responses
- [ ] Community scam leaderboard
- [ ] Browser extension

---

## 👨‍💻 Built By

**Sandeep (SandeepKudupudi07)** — built from scratch.  
Protecting Telugu-speaking and Indian users from scams. 🇮🇳