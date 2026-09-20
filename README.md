# ECHO — Email Threat Intelligence & Forensic Analysis

> **Smart India Hackathon 2026** · Cybersecurity · Team The Phoenix

ECHO is a cybersecurity platform for analyzing suspicious email messages and presenting explainable threat evidence in a structured investigation workspace.

The platform extracts email evidence, evaluates multiple security signals, identifies suspicious patterns, and produces a deterministic threat assessment with supporting indicators and recommendations.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Workflow](#workflow)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [API](#api)
- [Demo Cases](#demo-cases)
- [Security Boundaries](#security-boundaries)
- [Roadmap](#roadmap)
- [Team](#team)
- [References](#references)

## Overview

**Problem statement:** **SIH26106 — AI Powered Email Threat Detection, Geolocation and Forensic Analysis**

ECHO is being developed as a working prototype for the Smart India Hackathon 2026 cybersecurity problem statement. It is designed to help an analyst answer three questions:

1. **What happened?**
2. **Why was the message flagged?**
3. **What evidence supports the assessment?**

The current prototype supports analysis of real `.eml` files through the FastAPI backend.

## Features

### Email evidence extraction

- Sender and recipient metadata
- `Reply-To`, `Return-Path`, `Message-ID`, and `Date` headers
- `Received` header hops
- Authentication evidence
- Plain-text and HTML message bodies
- URLs
- Attachments and SHA-256 attachment hashes

### Deterministic threat analysis

- Header mismatch detection
- SPF, DKIM, and DMARC evidence interpretation
- URL structure analysis
- Suspicious attachment metadata detection
- Credential-related language detection
- Urgency indicators
- Financial and social-engineering indicators
- Explainable findings
- Deterministic risk scoring
- Threat classification
- Indicator-of-compromise (IOC) generation
- Forensic timeline
- Analyst recommendations

### Investigation workspace

The interface presents:

- Threat assessment and risk score
- Findings and supporting evidence
- Email metadata
- Authentication results
- URL evidence
- Attachment evidence
- Observed infrastructure
- Indicators of compromise
- Forensic timeline
- Recommended response actions
- Analyst notes

## Workflow

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
```

## Technology Stack

| Layer | Technologies |
| --- | --- |
| Frontend | React, TypeScript, Vite, Tailwind CSS, React Router |
| UI and visualization | Framer Motion, Recharts, Lucide React |
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Email analysis | Python standard-library `email` package |

## Architecture

```text
                              ECHO
                               │
                ┌──────────────┴──────────────┐
                │                             │
             React                         FastAPI
                │                             │
                │                    POST /api/analyze
                │                             │
                │                             ▼
                │                       Email Parser
                │                             │
                │                             ▼
                │                          EmailData
                │                             │
                │              ┌──────────────┼──────────────┐
                │              │              │              │
                │              ▼              ▼              ▼
                │          Headers          URLs       Attachments
                │              │              │              │
                │              └──────────────┼──────────────┘
                │                             ▼
                │                      Threat Engine
                │                             │
                │                             ▼
                └──────────────────── AnalysisResult
                                              │
                                              ▼
                                    Investigation UI
```

## Project Structure

```text
.
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
```

## Getting Started

### Prerequisites

- Node.js and npm
- Python 3.10 or later
- A supported `.eml` file for analysis

### 1. Start the frontend

From the project root:

```bash
npm install
npm run dev
```

The frontend is available at <http://localhost:5173>.

> On Windows, `npm.cmd install` and `npm.cmd run dev` can be used if required by your shell.

### 2. Start the backend

Open a second terminal:

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment and install dependencies:

**Windows PowerShell**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**macOS/Linux**

```bash
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend is available at <http://127.0.0.1:8000>.

Interactive API documentation is available at <http://127.0.0.1:8000/docs>.

## API

### Health check

```http
GET /api/health
```

### Analyze an email

```http
POST /api/analyze
Content-Type: multipart/form-data
```

Form field:

```text
file=<email.eml>
```

Example with cURL:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -F "file=@sample.eml"
```

The endpoint returns a structured analysis result containing extracted email evidence and the deterministic threat assessment.

## Demo Cases

The frontend includes demonstration scenarios for:

- Credential phishing
- Invoice fraud
- Malicious attachment
- Spoofed sender
- Benign message

Uploaded `.eml` files are processed through the FastAPI backend.

## Security Boundaries

The current prototype intentionally does **not**:

- Execute email attachments
- Download URLs
- Execute JavaScript from HTML emails
- Perform arbitrary outbound requests
- Claim that an observed IP is an attacker IP
- Claim that IP geolocation proves the physical location of an attacker
- Perform malware sandboxing
- Perform cryptographic DKIM verification
- Perform live SPF/DMARC DNS validation

These capabilities may be evaluated as future extensions. Findings should be treated as decision support and reviewed by a qualified analyst.

## Roadmap

### Implemented

- [x] ECHO frontend shell
- [x] Email analysis workflow
- [x] Investigation workspace
- [x] `.eml` parsing
- [x] Header analysis
- [x] Authentication evidence analysis
- [x] URL analysis
- [x] Attachment analysis
- [x] Content heuristics
- [x] Deterministic threat engine
- [x] IOC generation
- [x] Frontend/backend integration

### Planned

- [ ] IP infrastructure enrichment
- [ ] Geolocation visualization
- [ ] Investigation report export
- [ ] Real dashboard aggregation
- [ ] Additional threat-intelligence enrichment
- [ ] Optional machine-learning signals

## Team

- **Team:** The Phoenix
- **Project:** ECHO
- **Event:** Smart India Hackathon 2026

## References

- [NIST Cybersecurity Resources](https://www.nist.gov/cybersecurity)
- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 6376 — DomainKeys Identified Mail (DKIM)](https://www.rfc-editor.org/rfc/rfc6376)
- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489)
- [MITRE ATT&CK — Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)
