# MailForensics — Email Threat Investigation & Phishing Analysis Platform

> **Tagline:** *"Analyze. Investigate. Explain."*

MailForensics is a professional defensive cybersecurity platform designed for Security Operations Center (SOC) analysts, Digital Forensics and Incident Response (DFIR) teams, and email security engineers. It allows analysts to safely ingest, parse, investigate, and score suspicious emails and email artifacts (.eml files, raw RFC messages, headers, attachments, and URLs).

---

## Table of Contents
1. [What MailForensics Does](#what-mailforensics-does)
2. [Why MailForensics Exists](#why-mailforensics-exists)
3. [System Architecture](#system-architecture)
4. [Email Analysis Workflow](#email-analysis-workflow)
5. [Authentication Analysis (SPF, DKIM, DMARC)](#authentication-analysis)
6. [URL Analysis Engine](#url-analysis-engine)
7. [Safe Attachment Analysis](#safe-attachment-analysis)
8. [Threat Intelligence Integration](#threat-intelligence-integration)
9. [Explainable Risk Engine](#explainable-risk-engine)
10. [Case Management & Incident Response](#case-management)
11. [Demo Workflow & Seed Samples](#demo-workflow)
12. [Defensive Security Model](#defensive-security-model)
13. [Platform Limitations](#platform-limitations)
14. [Testing & Verification](#testing--verification)
15. [Quick Start & Setup](#quick-start--setup)

---

## 1. What MailForensics Does
MailForensics automates the complex, multi-stage triage process required when investigating suspicious emails:
- **RFC Email Ingestion**: Accepts `.eml` uploads, raw message text, and header strings.
- **Header Inconsistency Detection**: Detects spoofing indicators such as `From` vs `Reply-To` mismatches, `From` vs `Return-Path` mismatches, and `Message-ID` anomalies.
- **Received Chain Reconstruction**: Parses `Received` headers into ordered transit hops with delay timing and private IP anomaly detection.
- **Authentication Protocol Evaluation**: Verifies SPF, DKIM, and DMARC alignment.
- **Domain & Typosquatting Analysis**: Calculates Levenshtein edit distance against target brand domains to flag lookalike domains, punycode (`xn--`), and subdomain depth.
- **Isolated URL Extraction**: Normalizes URLs, flagging IP-based hosts, unencrypted HTTP, suspicious TLDs, and credential-harvesting keywords without visiting URLs.
- **Safe Static Attachment Inspection**: Computes SHA-256/SHA-1/MD5 hashes and inspects archive bomb limits safely without executing payloads or macros.
- **Explainable Risk Scoring**: Produces an evidence-weighted 0–100 risk score with clear contributing factors.
- **SOC Case Management & Reports**: Binds email samples to incident cases, supports analyst notes, and exports executive PDF and JSON reports.

---

## 2. Why MailForensics Exists
In high-velocity SOC environments, phishing remains the primary initial access vector. Analysts must rapidly distinguish benign communications from targeted social engineering attacks. MailForensics provides an evidence-based, explainable investigation workbench that prioritizes analyst control and eliminates black-box guesswork.

---

## 3. System Architecture
- **Backend**: Python 3.10+, FastAPI, SQLAlchemy, Pydantic, Pytest, WebSockets, ReportLab.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts.
- **Database**: SQLite (default for local/testing) / PostgreSQL (production compatible), 23 UUID-keyed relational models.
- **Real-Time Engine**: FastAPI WebSockets delivering real backend events step-by-step to the UI.

---

## 4. Email Analysis Workflow
```
   Ingest .eml / Raw RFC
             ↓
        Safe Parsing
             ↓
      Header Analysis
             ↓
   Received Chain Ordering
             ↓
    SPF / DKIM / DMARC
             ↓
   Sender & Domain Analysis
             ↓
       URL Extraction
             ↓
    Attachment Analysis
             ↓
  Phishing Rules Consolidation
             ↓
     Threat Intel Status
             ↓
   Explainable Risk Score
             ↓
    Analyst Verdict & PDF
```

---

## 5. Authentication Analysis
MailForensics evaluates email authentication protocols against header evidence:
- **SPF**: Verifies IP authorization against domain policies (`PASS`, `FAIL`, `SOFTFAIL`, `NONE`).
- **DKIM**: Inspects `DKIM-Signature` headers, signing domains, selectors, alignment, and cryptographic signatures.
- **DMARC**: Evaluates SPF and DKIM alignment against the header `From` domain to detect identity spoofing.

---

## 6. URL Analysis Engine
Extracted URLs are parsed strictly in-memory using URL string utilities.
- **Zero Browser Visiting**: Extracted URLs are **NEVER** automatically visited in a real browser.
- **Indicators Detected**: IP-based hosts (`http://192.168.1.50/...`), suspicious TLDs (`.top`, `.xyz`, `.click`), unencrypted HTTP, and credential keywords (`login`, `verify`, `password`).

---

## 7. Safe Attachment Analysis
- **Zero Execution Policy**: Uploaded attachments are stored in isolated storage with UUID-prefixed filenames. Payload execution, VBA macros, and active content rendering are strictly disabled.
- **Archive Safety Protections**: Safe archive inspection checking decompression limits (`MAX_ARCHIVE_SIZE`, `MAX_EXTRACTED_SIZE`, `MAX_NESTING_DEPTH`, `MAX_FILE_COUNT`) to prevent zip bomb attacks.
- **Static Metadata**: Calculates SHA-256, SHA-1, and MD5 hashes.

---

## 8. Threat Intelligence Integration
Supports optional lookup adapters for VirusTotal, AlienVault OTX, and AbuseIPDB.
- **Explicit Provider Status**: If no API keys are provided in `.env`, status displays `NOT_CONFIGURED`. No synthetic or fake threat intelligence statistics are generated.

---

## 9. Explainable Risk Engine
Calculates a 0–100 evidence-based risk score mapped to risk categories:
- `0–19`: **LOW**
- `20–39`: **GUARDED**
- `40–59`: **SUSPICIOUS**
- `60–79`: **HIGH**
- `80–100`: **CRITICAL**

Automated risk is kept separate from the Analyst Verdict (`BENIGN`, `SUSPICIOUS`, `PHISHING`, `MALICIOUS_ATTACHMENT`, `SPAM`, `UNRESOLVED`).

---

## 10. Case Management
Allows analysts to bundle related email samples, URLs, and attachments into incident cases, record analyst notes, transition case statuses (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`), and maintain append-only audit trails.

---

## 11. Demo Workflow
To immediately test the platform with controlled defensive lab samples:
1. Navigate to the **Dashboard**.
2. Click **Seed Controlled Lab Demo Samples**.
3. Observe real database telemetry updating in real-time across the KPI metrics cards.

---

## 12. Defensive Security Model
- **Filename Sanitization**: Prevents path traversal attacks (`../../../etc/passwd`).
- **Append-Only Audit Logs**: Logs all user operations while auto-redacting passwords, tokens, and API keys.
- **RBAC**: Enforces role permissions (`ADMIN`, `ANALYST`, `VIEWER`) at the FastAPI endpoint level.

---

## 13. Operational Reality & Service Status Declarations

| Category | Component | Status | Details |
|---|---|---|---|
| **WHAT IS REAL** | RFC .eml Parser | **ACTIVE / REAL** | Standard library MIME parsing, body extraction, safe handling |
| **WHAT IS REAL** | Native YARA Engine | **ACTIVE / REAL** | Native `yara-python` C-extension v4.5.4 compiled and active |
| **WHAT IS REAL** | Risk Engine | **ACTIVE / REAL** | Transparent evidence-based additive scoring (0-100) |
| **WHAT IS REAL** | STIX 2.1 Bundles | **ACTIVE / REAL** | Valid OASIS STIX 2.1 JSON export for emails, hashes, URLs |
| **WHAT IS REAL** | WebSockets | **ACTIVE / REAL** | Real FastAPI event dispatching step-by-step to the UI |
| **WHAT IS REAL** | Safe Static Analysis | **ACTIVE / REAL** | PE header inspection (MZ), PDF streams, archive limits |
| **WHAT IS LOCAL** | Default DB Mode | **ACTIVE / LOCAL** | SQLite (`sqlite:///./mailforensics.db`) for lightweight local dev/testing |
| **WHAT IS LOCAL** | Processing Mode | **ACTIVE / LOCAL** | Synchronous FastAPI BackgroundTasks when `PROCESSING_MODE=local` |
| **REQUIRES KEYS** | Threat Intelligence | **STANDBY / NOT_CONFIGURED** | VirusTotal, AlienVault OTX, AbuseIPDB require API keys in `.env` |
| **REQUIRES DOCKER** | Production Stack | **STANDBY / READY** | Multi-container Docker Compose (PostgreSQL, Redis, Celery worker) |
| **CONTROLLED DATA** | Demo Samples | **ISOLATED / LAB** | Explicitly tagged `CONTROLLED_TEST` and filterable in UI |
| **NOT IMPLEMENTED** | Malware Detonation | **BY DESIGN / DISABLED** | No dynamic VM execution, payload triggering, or evasion |

---

## 14. Testing & Verification

MailForensics includes a verified test suite covering unit, API, database, Celery, DNS, health, YARA, and STIX export:
```bash
cd backend
.\venv\Scripts\python.exe -m pytest tests/ -v
```
**Test Results**: **39 passed out of 39 tests** (100% pass rate).

Frontend Build Verification:
```bash
cd frontend
npm run build
```
**Build Result**: Clean TypeScript compilation (`tsc`) and Vite production bundle (`dist/`).

---

## 15. Quick Start & Setup

### Local Mode (Default / Development):
```bash
# Backend
cd backend
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
.\venv\Scripts\uvicorn app.main:app --reload --port 8000

# Frontend
cd ../frontend
npm install
npm run dev
```

### Production Mode (Docker Compose):
```bash
docker compose build
docker compose up -d
```
The Docker stack spins up PostgreSQL, Redis, Celery Worker, FastAPI backend (with auto-applied Alembic migrations), and Nginx-served React frontend on isolated network `mailforensics-net`.
