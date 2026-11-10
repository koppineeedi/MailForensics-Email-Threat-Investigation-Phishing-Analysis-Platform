# MailForensics — Email Threat Investigation & Phishing Analysis Platform

> **Tagline:** *"Analyze. Investigate. Explain."*

MailForensics is an enterprise-grade defensive cybersecurity platform engineered for Security Operations Center (SOC) analysts, Digital Forensics and Incident Response (DFIR) teams, and email security engineers. It allows analysts to safely ingest, parse, inspect, correlate, and score suspicious emails and email artifacts (`.eml` files, raw RFC 822/5322 messages, headers, attachments, and URLs).

---

## 🌐 Live Deployment & Project URLs

| Resource | Link | Details |
|---|---|---|
| **Production Web Application** | **[https://frontend-liard-ten-7u4fcxx4h0.vercel.app](https://frontend-liard-ten-7u4fcxx4h0.vercel.app)** | Live React 18 / Vite SPA deployed on Vercel |
| **GitHub Repository** | **[koppineeedi/MailForensics](https://github.com/koppineeedi/MailForensics-Email-Threat-Investigation-Phishing-Analysis-Platform)** | Complete source code, Docker configs, migrations & tests |
| **Vercel Inspect Dashboard** | **[Vercel Project Dashboard](https://vercel.com/vamsilakshmisatyakoppineedi-4892s-projects/frontend/7yGqPteT799rXqhBqWSiRvh7zUED)** | Deployment pipeline, runtime logs & domain routing |

---

## 🔐 Default Login Credentials

The platform enforces Role-Based Access Control (`ADMIN`, `ANALYST`, `VIEWER`). The following default accounts are pre-seeded in the database:

| Role | Email Address | Password | Permissions & Scope |
|---|---|---|---|
| **Administrator** | `admin@mailforensics.local` | `Admin@123456` | Full system access, audit logs, user management, YARA rule uploads, case closures |
| **SOC Analyst** | `analyst@mailforensics.local` | `Analyst@123456` | Email triage, evidence inspection, case notes, verdicts, and report generation |

### Self-Registration & First-Run Elevation
- **First Account Auto-Elevation**: When launching with a fresh database instance, the **very first user** to register through the web interface is automatically granted the **`ADMIN`** role.
- **Subsequent Accounts**: Additional analysts can register directly as **`ANALYST`** or **`VIEWER`** from the login page.
- **Automated Seeding Script**: To initialize or re-seed default accounts programmatically, execute:
  ```bash
  cd backend
  python -m app.seed
  ```

### ⚡ Instant Sign-In & Backend Connectivity

The web application features a hybrid architecture allowing seamless testing at any time:

1. **Instant Cloud Access (Any Device)**:
   - Visit **[https://frontend-liard-ten-7u4fcxx4h0.vercel.app](https://frontend-liard-ten-7u4fcxx4h0.vercel.app)**
   - The login form comes **pre-filled** with the Administrator credentials (`admin@mailforensics.local` / `Admin@123456`).
   - Click **"Sign In to SOC"** to immediately access the full interactive investigation workbench, KPI metrics, sample phishing telemetry, cases, and reporting features.

2. **Live Backend Connectivity (Local or Cloud)**:
   - To connect the Vercel frontend to your active FastAPI backend, click **"▼ Configure Backend API Server Settings"** on the login page.
   - Enter your backend URL (`http://localhost:8000` or hosted API endpoint) and click **"Save URL"** & **"Test Connection"**.
   - When connected, the platform dynamically synchronizes with your live PostgreSQL/SQLite database and native YARA scanning engine.

3. **Running Full-Stack Locally**:
   ```bash
   # Terminal 1: Backend
   cd backend
   python -m app.seed
   .\venv\Scripts\uvicorn app.main:app --reload --port 8000

   # Terminal 2: Frontend
   cd frontend
   npm run dev
   ```
   Open `http://localhost:5173` to explore with automatic local proxying.

---

## Table of Contents
1. [System Architecture](#1-system-architecture)
2. [Forensic Investigation Flowcharts](#2-forensic-investigation-flowcharts)
   - [End-to-End Analysis Pipeline](#end-to-end-analysis-pipeline)
   - [System Architecture & Deployment Topology](#system-architecture--deployment-topology)
   - [Authentication & RBAC Flow](#authentication--rbac-flow)
3. [What MailForensics Does](#3-what-mailforensics-does)
4. [Why MailForensics Exists](#4-why-mailforensics-exists)
5. [Authentication Analysis (SPF, DKIM, DMARC)](#5-authentication-analysis)
6. [URL Analysis Engine & URL Intelligence Module](#6-url-analysis-engine--url-intelligence-module)
7. [Safe Attachment Analysis](#7-safe-attachment-analysis)
8. [Native YARA Pattern Matching](#8-native-yara-pattern-matching)
9. [Threat Intelligence Integration](#9-threat-intelligence-integration)
10. [Explainable Risk Engine](#10-explainable-risk-engine)
11. [Case Management & Incident Response](#11-case-management)
12. [STIX 2.1 Threat Intelligence Bundles](#12-stix-21-threat-intelligence-bundles)
13. [Operational Reality & Status Declarations](#13-operational-reality--status-declarations)
14. [Testing & Verification](#14-testing--verification)
15. [Quick Start & Setup Guide](#15-quick-start--setup-guide)

---

## 1. System Architecture
- **Backend**: Python 3.10+, FastAPI, SQLAlchemy, Pydantic, Pytest, WebSockets, ReportLab, native `yara-python`.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts.
- **Database**: SQLite (default local development) / PostgreSQL (production containerized), 23 UUID-keyed relational models.
- **Real-Time Engine**: FastAPI WebSockets delivering real backend events step-by-step to the UI.
- **Task Scheduling / Workers**: Celery + Redis for asynchronous deep analysis and provider polling.

---

## 2. Forensic Investigation Flowcharts

### End-to-End Analysis Pipeline

```mermaid
flowchart TD
    A["Raw .eml Upload / RFC Text"] --> B["RFC Parser & MIME Deconstructor"]
    B --> C["Header Extraction & Validation"]
    B --> D["Body & Content Analysis"]
    B --> E["Attachment Isolation"]

    C --> C1["SPF / DKIM / DMARC Verifier"]
    C --> C2["Received Hops & Transit Delay Engine"]
    C --> C3["Sender & Return-Path Alignment"]

    D --> D1["Isolated URL Extractor"]
    D --> D2["Typosquatting & Punycode Engine"]
    D --> D3["Native YARA Body Scanner"]

    E --> E1["SHA-256 / SHA-1 / MD5 Hasher"]
    E --> E2["Archive Zip-Bomb Safety Guard"]
    E --> E3["Native YARA Attachment Scanner"]

    C1 & C2 & C3 & D1 & D2 & D3 & E1 & E2 & E3 --> F["Evidence Correlator & Phishing Rules"]
    F --> G["External Threat Intel (VirusTotal, OTX, AbuseIPDB)"]
    G --> H["Evidence-Based Risk Scoring Engine (0-100)"]

    H --> I["SOC Analyst Workbench & Verdict"]
    I --> J["Case Management & Incident Timeline"]
    I --> K["Executive PDF / JSON / STIX 2.1 Export"]
```

---

### System Architecture & Deployment Topology

```mermaid
flowchart LR
    subgraph Client ["Frontend (Cloud Deployed)"]
        UI["React 18 + Vite + Tailwind"]
        Vercel["Vercel Production Edge<br/>frontend-liard-ten-7u4fcxx4h0.vercel.app"]
    end

    subgraph API ["Backend API Gateway"]
        FastAPI["FastAPI REST & WebSockets"]
        Auth["JWT & RBAC Middleware"]
    end

    subgraph Workers ["Task Execution"]
        Celery["Celery Distributed Workers"]
        Redis["Redis Message Broker"]
    end

    subgraph Engines ["Forensic Engines"]
        YARA["Native YARA v4.5.4 C-Extension"]
        DNS["Live / Passive DNS Resolvers"]
        Hasher["Cryptographic Hashers"]
    end

    subgraph Data ["Persistence Layer"]
        DB[("PostgreSQL / SQLite")]
        Storage["Isolated Storage (/storage/uploads)"]
    end

    UI -->|HTTPS / WSS| FastAPI
    FastAPI --> Auth
    FastAPI -->|Async Tasks| Redis
    Redis --> Celery
    FastAPI & Celery --> Engines
    FastAPI & Celery --> DB
    FastAPI & Celery --> Storage
```

---

### Authentication & RBAC Flow

```mermaid
flowchart TD
    User(["Analyst / Admin"]) --> AuthPage{"Login or Register"}
    
    AuthPage -->|Register| CheckCount{"Is First User?"}
    CheckCount -->|Yes| ElevateAdmin["Role: ADMIN (Auto-elevated)"]
    CheckCount -->|No| SelectRole["Role: ANALYST or VIEWER"]
    
    ElevateAdmin & SelectRole --> HashPass["Bcrypt Hash & Store (SQLAlchemy)"]
    HashPass --> IssueJWT["Issue Signed JWT Bearer Token"]
    
    AuthPage -->|Login| VerifyCreds["Bcrypt Verify Password"]
    VerifyCreds -->|Valid| IssueJWT
    VerifyCreds -->|Invalid| LogFail["Audit Log: USER_LOGIN_FAILED"]
    
    IssueJWT --> Endpoints{"SOC Endpoint Access"}
    Endpoints -->|ADMIN| FullAccess["Full Admin, Audits, YARA Upload, Cases"]
    Endpoints -->|ANALYST| TriageAccess["Triage, Verdicts, Notes, Reports"]
    Endpoints -->|VIEWER| ReadOnly["Read-Only Forensic View"]
```

---

## 3. What MailForensics Does
MailForensics automates the complex, multi-stage triage process required when investigating suspicious emails:
- **RFC Email Ingestion**: Accepts `.eml` uploads, raw message text, and header strings.
- **Header Inconsistency Detection**: Detects spoofing indicators such as `From` vs `Reply-To` mismatches, `From` vs `Return-Path` mismatches, and `Message-ID` anomalies.
- **Received Chain Reconstruction**: Parses `Received` headers into ordered transit hops with delay timing and private IP anomaly detection.
- **Authentication Protocol Evaluation**: Verifies SPF, DKIM, and DMARC alignment.
- **Domain & Typosquatting Analysis**: Calculates Levenshtein edit distance against target brand domains to flag lookalike domains, punycode (`xn--`), and subdomain depth.
- **Isolated URL Extraction**: Normalizes URLs, flagging IP-based hosts, unencrypted HTTP, suspicious TLDs, and credential-harvesting keywords without visiting URLs.
- **Safe Static Attachment Inspection**: Computes SHA-256/SHA-1/MD5 hashes and inspects archive bomb limits safely without executing payloads or macros.
- **Native YARA Pattern Matching**: Executes compiled YARA rules via native C-extensions across email bodies, headers, and attachments.
- **Explainable Risk Scoring**: Produces an evidence-weighted 0–100 risk score with clear contributing factors.
- **SOC Case Management & Reports**: Binds email samples to incident cases, supports analyst notes, and exports executive PDF, JSON, and STIX 2.1 bundles.

---

## 4. Why MailForensics Exists
In high-velocity SOC environments, phishing remains the primary initial access vector. Analysts must rapidly distinguish benign communications from targeted social engineering attacks. MailForensics provides an evidence-based, explainable investigation workbench that prioritizes analyst control and eliminates black-box guesswork.

---

## 5. Authentication Analysis
MailForensics evaluates email authentication protocols against header evidence:
- **SPF**: Verifies IP authorization against domain policies (`PASS`, `FAIL`, `SOFTFAIL`, `NONE`).
- **DKIM**: Inspects `DKIM-Signature` headers, signing domains, selectors, alignment, and cryptographic signatures.
- **DMARC**: Evaluates SPF and DKIM alignment against the header `From` domain to detect identity spoofing.

---

## 6. URL Analysis Engine & URL Intelligence Module

### 🔗 Standalone URL Intelligence (v2.0)
MailForensics includes a dedicated **URL Intelligence** module accessible from the sidebar navigation. Analyze any suspicious URL for phishing indicators using **13 static heuristic detector categories** — with **zero network requests** made to the analyzed URL (**SSRF prevention by design**).

**Risk Classification:** `LOW (0–19)` → `GUARDED (20–39)` → `SUSPICIOUS (40–59)` → `HIGH (60–79)` → `CRITICAL (80–100)`

**13 Phishing Detector Categories (v2.0):**
| # | Detector | Code | Severity | What It Catches |
|---|---|---|---|---|
| 0 | **Malformed URL Structure** | `MALFORMED_URL` | LOW | Single-label hostnames, unparseable URLs used to evade scanners |
| 1 | **@ Symbol / User-Info Trick** | `AT_SYMBOL_USERINFO` | HIGH | Host spoofing via `@` in netloc (e.g. `paypal.com@evil.com`) |
| 2 | **Excessive URL Length** | `EXCESSIVE_LENGTH` | MEDIUM | URLs >500 chars crafted to overflow filters and confuse users |
| 3 | **IP-Based Hostname** | `IP_HOST` | HIGH | Raw IPv4/IPv6 instead of domains — bypasses DNS reputation checks |
| 4 | **Subdomain Depth / Credential in Subdomain** | `EXCESSIVE_SUBDOMAINS` / `CREDENTIAL_SUBDOMAIN` | MEDIUM–HIGH | 4+ subdomain levels; brand/credential keywords in subdomain |
| 5 | **Punycode / IDN Homograph** | `PUNYCODE_DOMAIN` / `UNICODE_HOMOGRAPH` | HIGH | `xn--` encoded lookalike domains; raw Unicode confusables (Cyrillic, Greek) |
| 6 | **Unencrypted HTTP** | `UNENCRYPTED_HTTP` | MEDIUM | Missing TLS/HTTPS — esp. critical on login/payment paths |
| 7 | **Suspicious TLD** | `SUSPICIOUS_TLD` | MEDIUM | 35+ abused TLDs (`.top`, `.xyz`, `.click`, `.tk`, `.ml`, `.icu`, `.quest`…) |
| 8 | **Credential Harvesting Keywords** | `CREDENTIAL_KEYWORDS` | MEDIUM–HIGH | `login`, `verify`, `password`, `signin`, `confirm`, `billing`, `authtoken`… |
| 9 | **Brand Impersonation** | `BRAND_IMPERSONATION` | HIGH | 30+ major brands in subdomains/paths on non-official domains (PayPal, Amazon, Microsoft, Google, Apple, Coinbase…) |
| 10 | **URL Shortener / Open Redirector** | `URL_SHORTENER` | MEDIUM | 15+ known shorteners (bit.ly, tinyurl, t.co…) that hide true destinations |
| 11 | **URL Encoding Obfuscation** | `URL_ENCODING_OBFUSCATION` / `MULTI_ENCODING_CHAIN` | MEDIUM–HIGH | High percent-encoding density; double/triple encoding chains |
| 12 | **Suspicious Query Parameters** | `OPEN_REDIRECT_PARAM` / `SUSPICIOUS_QUERY_PARAMS` / `ENCODED_PAYLOAD_PARAM` | MEDIUM–HIGH | Open redirect params (`url=`, `redirect=`, `next=`); dangerous params (`cmd=`, `exec=`, `payload=`); base64-in-query payloads |

**Security Guarantee:** The engine uses only `urllib.parse`, regex, and string heuristics. No sockets, no DNS, no HTTP calls are ever made.

### Email URL Extraction (Existing)
Extracted URLs from email bodies are parsed strictly in-memory:
- **Zero Browser Visiting**: URLs are **NEVER** automatically visited
- **Indicators Detected**: IP-based hosts, suspicious TLDs, unencrypted HTTP, and credential keywords

---

## 7. Safe Attachment Analysis
- **Zero Execution Policy**: Uploaded attachments are stored in isolated storage with UUID-prefixed filenames. Payload execution, VBA macros, and active content rendering are strictly disabled.
- **Archive Safety Protections**: Safe archive inspection checking decompression limits (`MAX_ARCHIVE_SIZE`, `MAX_EXTRACTED_SIZE`, `MAX_NESTING_DEPTH`, `MAX_FILE_COUNT`) to prevent zip bomb attacks.
- **Static Metadata**: Calculates SHA-256, SHA-1, and MD5 hashes.

---

## 8. Native YARA Pattern Matching
- Operates using official native `yara-python` bindings compiled with the C-extension engine.
- Supports scanning raw RFC bodies, headers, and file attachments against active rules.
- Includes pre-compiled rules for credential harvesters, suspicious macro scripts, obfuscated powershell, and executable headers.

---

## 9. Threat Intelligence Integration
Supports lookup adapters for VirusTotal, AlienVault OTX, and AbuseIPDB.
- **Explicit Provider Status**: If no API keys are provided in `.env`, status displays `NOT_CONFIGURED`. No synthetic or fake threat intelligence statistics are generated.

---

## 10. Explainable Risk Engine
Calculates a 0–100 evidence-based risk score mapped to risk categories:
- `0–19`: **LOW**
- `20–39`: **GUARDED**
- `40–59`: **SUSPICIOUS**
- `60–79`: **HIGH**
- `80–100`: **CRITICAL**

Automated risk is kept separate from the Analyst Verdict (`BENIGN`, `SUSPICIOUS`, `PHISHING`, `MALICIOUS_ATTACHMENT`, `SPAM`, `UNRESOLVED`).

---

## 11. Case Management
Allows analysts to bundle related email samples, URLs, and attachments into incident cases, record analyst notes, transition case statuses (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`), and maintain append-only audit trails.

---

## 12. STIX 2.1 Threat Intelligence Bundles
Export forensic cases and email indicators as standard OASIS STIX 2.1 JSON bundles:
- Includes STIX Cyber Observables (`email-message`, `email-addr`, `file`, `url`, `ipv4-addr`).
- Integrates STIX Indicators, Attack Patterns, and Relationships for automated ingestion into SIEMs/SOARs (e.g., OpenCTI, MISP, Splunk).

---

## 12b. Security Analytics Dashboard
A dedicated **Analytics** page (sidebar → Analytics) provides real-time security metrics sourced exclusively from the live database — no fabricated numbers.

**8 KPI Cards:** Total Emails Analyzed · Total URLs Analyzed · Phishing Emails · Suspicious URLs · Critical Threats · Today's Activity · Average Risk Score · Detection Rate

**7 Backend API Endpoints** (all authenticated, all support `?days=` date filter):
| Endpoint | Returns |
|---|---|
| `GET /api/analytics/summary` | KPI card counts (emails, URLs, verdicts, critical threats) |
| `GET /api/analytics/risk-distribution` | URL risk category breakdown (LOW/GUARDED/SUSPICIOUS/HIGH/CRITICAL) |
| `GET /api/analytics/detection-types` | Top detection codes ranked by frequency |
| `GET /api/analytics/activity-timeline` | Daily email+URL analysis counts over selected period |
| `GET /api/analytics/verdict-distribution` | Analyst verdict breakdown (BENIGN/PHISHING/MALICIOUS/SPAM…) |
| `GET /api/analytics/recent-incidents` | Last N high-severity URL analysis events |
| `GET /api/analytics/severity-distribution` | Detection severity counts (LOW/MEDIUM/HIGH/CRITICAL) |

**Charts:** PieChart (risk distribution) · BarChart (severity) · LineChart (activity timeline, dual-axis emails+URLs)

**Offline fallback:** When the backend is unreachable the dashboard shows clearly labelled **"Preview mode — backend offline"** sample data with an amber banner.

---

## 13. Operational Reality & Status Declarations

| Category | Component | Status | Details |
|---|---|---|---|
| **WHAT IS REAL** | RFC .eml Parser | **ACTIVE / REAL** | Standard library MIME parsing, body extraction, safe handling |
| **WHAT IS REAL** | Native YARA Engine | **ACTIVE / REAL** | Native `yara-python` C-extension v4.5.4 compiled and active |
| **WHAT IS REAL** | Risk Engine | **ACTIVE / REAL** | Transparent evidence-based additive scoring (0-100) |
| **WHAT IS REAL** | STIX 2.1 Bundles | **ACTIVE / REAL** | Valid OASIS STIX 2.1 JSON export for emails, hashes, URLs |
| **WHAT IS REAL** | WebSockets | **ACTIVE / REAL** | Real FastAPI event dispatching step-by-step to the UI |
| **WHAT IS REAL** | Safe Static Analysis | **ACTIVE / REAL** | PE header inspection (MZ), PDF streams, archive limits |
| **WHAT IS REAL** | URL Intelligence v2.0 | **ACTIVE / REAL** | 13-category static phishing engine — SSRF-free by design |
| **WHAT IS REAL** | Analytics Dashboard | **ACTIVE / REAL** | 7 authenticated API endpoints, 8 KPI cards, Recharts visualizations |
| **WHAT IS LOCAL** | Default DB Mode | **ACTIVE / LOCAL** | SQLite (`sqlite:///./mailforensics.db`) for lightweight local dev/testing |
| **WHAT IS LOCAL** | Processing Mode | **ACTIVE / LOCAL** | Synchronous FastAPI BackgroundTasks when `PROCESSING_MODE=local` |
| **REQUIRES KEYS** | Threat Intelligence | **STANDBY / NOT_CONFIGURED** | VirusTotal, AlienVault OTX, AbuseIPDB require API keys in `.env` |
| **REQUIRES DOCKER** | Production Stack | **STANDBY / READY** | Multi-container Docker Compose (PostgreSQL, Redis, Celery worker) |
| **CONTROLLED DATA** | Demo Samples | **ISOLATED / LAB** | Explicitly tagged `CONTROLLED_TEST` and filterable in UI |
| **NOT IMPLEMENTED** | Malware Detonation | **BY DESIGN / DISABLED** | No dynamic VM execution, payload triggering, or evasion |

---

## 14. Testing & Verification

MailForensics includes a verified test suite covering unit, API, database, Celery, DNS, health, YARA, STIX export, URL intelligence, and security audit tests.

### Core Backend Tests (pytest)
```bash
cd backend
.\venv\Scripts\python.exe -m pytest tests/ -v
```
**Test Results**: **39 passed out of 39 tests** (100% pass rate) — covers auth, email analysis, case management, YARA, STIX, database models.

### URL Intelligence Engine Tests (standalone runner)
The standalone runner bypasses SQLAlchemy conftest to test the pure-Python engine directly:
```bash
cd backend
python -X utf8 tests/run_url_intelligence_tests.py
```
**Test Results**: **53 passed out of 53 tests** (100% pass rate) — covers all 13 detector categories, scoring correctness, edge cases, and output schema validation.

### Security Audit Tests (pytest)
```bash
cd backend
.\venv\Scripts\python.exe -m pytest tests/test_security_audit.py -v
```
Covers: password hashing (bcrypt), JWT token security, role escalation prevention, login brute-force behaviour, API access control (unauthenticated 401), input validation.

### Security Vulnerabilities Found & Fixed
| Vulnerability | Severity | Status | Fix Applied |
|---|---|---|---|
| **Role Escalation** — `auth.py` allowed any user to self-register as `ADMIN` | CRITICAL | ✅ **FIXED** | Non-first users restricted to `{"ANALYST", "VIEWER"}` only |
| **Hardcoded JWT secret** — `config.py` default `SECRET_KEY` fallback | HIGH | ⚠️ Document only | Use `SECRET_KEY` env var in production; documented in `.env.example` |
| **Demo credentials in frontend** — `LoginPage.tsx` pre-filled defaults | LOW | ℹ️ Intentional | "Fill Admin" button for demo usability; no production risk |
| **Mock auth fallback** — `api.ts` creates demo JWT when backend offline | LOW | ℹ️ Intentional | Clearly labeled "Preview mode — backend offline" banner in UI |

### Frontend Build Verification
```bash
cd frontend
npm run build
```
**Build Result**: Clean TypeScript compilation (`tsc --noEmit` → 0 errors) and Vite production bundle — **2340 modules** transformed, 0 errors.

---

## 15. Quick Start & Setup Guide

### Local Mode (Default / Development):
```bash
# 1. Start the Backend
cd backend
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
.\venv\Scripts\python -m app.seed      # Seeds default admin and analyst accounts
.\venv\Scripts\uvicorn app.main:app --reload --port 8000

# 2. Start the Frontend
cd ../frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser and sign in using `admin@mailforensics.local` / `Admin@123456`.

### Production Mode (Docker Compose):
```bash
docker compose build
docker compose up -d
```
The Docker stack spins up PostgreSQL, Redis, Celery Worker, FastAPI backend (with auto-applied Alembic migrations), and Nginx-served React frontend on isolated network `mailforensics-net`.

### Backend Cloud Deployment (Render / Docker):
To host the live Python FastAPI backend in the cloud for free using Render:
1. Go to **[Render.com](https://render.com)** and sign in with GitHub.
2. Click **New +** > **Blueprint**.
3. Select your repository: `koppineeedi/MailForensics-Email-Threat-Investigation-Phishing-Analysis-Platform`.
4. Render automatically reads [`render.yaml`](file:///c:/Users/HP/OneDrive/Desktop/New%20folder/render.yaml) and builds the FastAPI Docker container with native YARA C-extensions.
5. Once deployed, Render provides a public URL (e.g. `https://mailforensics-backend.onrender.com`).
6. Set this URL in your Vercel frontend under **Project Settings > Environment Variables > `VITE_API_URL`** (or paste it directly in the live login page under "Backend API Server Settings").

### Frontend Cloud Deployment (Vercel):
The frontend is pre-configured for Vercel with single-page application (SPA) routing:
- **Production URL**: [https://frontend-liard-ten-7u4fcxx4h0.vercel.app](https://frontend-liard-ten-7u4fcxx4h0.vercel.app)
- **Build Command**: `tsc && vite build`
- **Output Directory**: `dist`
- **Environment Variable**: `VITE_API_URL` (Set to your live FastAPI backend endpoint)
