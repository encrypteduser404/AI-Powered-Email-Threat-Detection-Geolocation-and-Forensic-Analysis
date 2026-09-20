# ECHO — Email Threat Intelligence & Forensic Analysis

> Smart India Hackathon 2026 | Cybersecurity | Team The Phoenix

ECHO is a cybersecurity platform designed to analyze suspicious email
messages and present explainable threat evidence through a security
investigation workspace.

The platform focuses on extracting email evidence, analyzing multiple
security signals, identifying suspicious patterns, and presenting the
results in a structured forensic workflow.

---

## Problem Statement

**SIH26106 — AI Powered Email Threat Detection, Geolocation and Forensic Analysis**

ECHO is being developed as a working prototype for the Smart India
Hackathon 2026 cybersecurity problem statement.

The system is designed around the following workflow:

```text
Email Input
    ↓
Email Parsing
    ↓
Header / Authentication / URL / Attachment / Content Analysis
    ↓
Threat Assessment
    ↓
Infrastructure & Geolocation Enrichment
    ↓
Forensic Investigation
    ↓
Actionable Report

Current Implementation

The current prototype already supports real .eml analysis.

Frontend
React
TypeScript
Vite
Tailwind CSS
React Router
Framer Motion
Recharts
Lucide React
Backend
Python
FastAPI
Uvicorn
Pydantic
Email Analysis

The backend currently extracts and analyzes:

sender and recipient metadata
Reply-To and Return-Path
Message-ID and Date
Received headers
authentication evidence
plain-text and HTML bodies
URLs
attachments
SHA-256 attachment hashes
Deterministic Threat Analysis

The current analysis engine includes:

header mismatch detection
SPF / DKIM / DMARC evidence interpretation
URL structural analysis
suspicious attachment metadata detection
credential-related language detection
urgency indicators
financial/social-engineering indicators
explainable findings
deterministic risk scoring
threat classification
IOC generation
forensic timeline
analyst recommendations

The engine does not currently claim live DNS verification, cryptographic
DKIM verification, malware execution/scanning, or attacker identification.

Investigation Workspace

ECHO provides a structured investigation interface containing:

Threat assessment
Risk score
Findings and evidence
Email metadata
Authentication results
URL evidence
Attachment evidence
Observed infrastructure
Indicators of compromise
Forensic timeline
Recommended response actions
Analyst notes

The interface is designed around three questions:

What happened?
Why was it flagged?
What evidence supports the assessment?
Architecture
                    ECHO
                     │
        ┌────────────┴────────────┐
        │                         │
     React                     FastAPI
        │                         │
        │                   POST /api/analyze
        │                         │
        │                         ▼
        │                   Email Parser
        │                         │
        │                         ▼
        │                  EmailData
        │                         │
        │        ┌────────────────┼────────────────┐
        │        │                │                │
        │        ▼                ▼                ▼
        │    Headers          URLs          Attachments
        │        │                │                │
        │        └────────────────┼────────────────┘
        │                         ▼
        │                  Threat Engine
        │                         │
        │                         ▼
        └────────────────── AnalysisResult
                                   │
                                   ▼
                         Investigation UI
Project Structure
echo/
├── src/
│   ├── components/
│   ├── pages/
│   ├── services/
│   ├── types/
│   └── data/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── schemas/
│   │   └── services/
│   ├── tests/
│   └── requirements.txt
│
├── public/
├── package.json
├── vite.config.ts
└── README.md
Running Locally
Frontend

From the project root:

npm.cmd install
npm.cmd run dev

Frontend:

http://localhost:5173
Backend

Open a second terminal:

cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

Backend:

http://127.0.0.1:8000

Swagger documentation:

http://127.0.0.1:8000/docs

Health endpoint:

http://127.0.0.1:8000/api/health
API
Health
GET /api/health
Analyze Email
POST /api/analyze
Content-Type: multipart/form-data

Field:

file=<email.eml>

The endpoint returns a structured analysis result containing the
extracted email evidence and deterministic threat assessment.

Demo Cases

The frontend includes built-in demonstration scenarios for:

Credential Phishing
Invoice Fraud
Malicious Attachment
Spoofed Sender
Benign Message

Uploaded .eml files are processed through the real FastAPI backend.

Security Boundaries

The current prototype intentionally does not:

execute email attachments
download URLs
execute JavaScript from HTML emails
perform arbitrary outbound requests
claim that an observed IP is an attacker IP
claim IP geolocation proves physical attacker location
perform malware sandboxing
perform cryptographic DKIM verification
perform live SPF/DMARC DNS validation

These capabilities may be evaluated as future extensions.

Roadmap
Implemented
 ECHO frontend shell
 Email analysis workflow
 Investigation workspace
 .eml parsing
 Header analysis
 Authentication evidence analysis
 URL analysis
 Attachment analysis
 Content heuristics
 Deterministic threat engine
 IOC generation
 Frontend / backend integration
Planned
 IP infrastructure enrichment
 Geolocation visualization
 Investigation report export
 Real dashboard aggregation
 Additional threat intelligence enrichment
 Optional machine-learning signal
 Deployment
Team

Team: The Phoenix

Project: ECHO

Smart India Hackathon 2026

References
NIST Cybersecurity Resources
RFC 7208 — SPF
RFC 6376 — DKIM
RFC 7489 — DMARC
MITRE ATT&CK — Phishing / T1566