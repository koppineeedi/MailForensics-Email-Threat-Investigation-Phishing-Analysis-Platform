# MailForensics — Real Environment Status

**Audit & Assessment Date:** 2026-09-29  
**Host Platform:** Windows 11 (AMD64 / win32)  
**Execution Context:** Local Workstation / DFIR Lab  

---

## 1. Host Software Status Matrix

| SOFTWARE | REQUIRED | INSTALLED | VERSION | RUNNING | VERIFIED |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Python** | YES | **YES** | `3.14.3` | **YES** | Verified via `python --version` and active venv |
| **pip** | YES | **YES** | `25.3` | **YES** | Verified via `pip --version` |
| **Node.js** | YES | **YES** | `v25.2.1` | **YES** | Verified via `node --version` |
| **npm** | YES | **YES** | `11.7.0` | **YES** | Verified via `npm --version` |
| **SQLite** | YES (Dev/Test) | **YES** | `3.x` (Built-in) | **YES** | Verified via `mailforensics.db` (23 tables active) |
| **PostgreSQL** | OPTIONAL (Prod) | **NO** (Host) | N/A | **NO** | Port 5432 idle; drivers configured for prod |
| **Redis** | OPTIONAL (Prod) | **NO** (Host) | N/A | **NO** | Port 6379 idle; client configured for prod |
| **Celery** | OPTIONAL (Prod) | **YES** (Python) | Configured | **STANDBY** | Dual-mode: Local (sync) or Celery worker |
| **Docker** | OPTIONAL (Prod) | **NO** (Host) | N/A | **NO** | Docker CLI not on host PATH |
| **Docker Compose** | OPTIONAL (Prod) | **NO** (Host) | N/A | **NO** | Configs created for containerized deployment |
| **YARA (Native C)** | YES | **YES** | `4.5.4` | **YES** | Verified via native compilation & match test |

---

## 2. Database Configuration

- **Current Active Database Engine:** SQLite 3
- **Current Connection String:** `sqlite:///./mailforensics.db` (Dev), `sqlite:///./test_mailforensics.db` (Test)
- **Database Tables Active:** 23 relational tables
- **PostgreSQL Readiness:** Supported via `psycopg` / `asyncpg` with connection pooling, startup connectivity checks, and Alembic migrations.

---

## 3. Threat Intelligence Provider Status

- **VirusTotal:** `NOT_CONFIGURED` (Defensive fallback; no API key committed in `.env`)
- **AlienVault OTX:** `NOT_CONFIGURED` (Defensive fallback; no API key committed in `.env`)
- **AbuseIPDB:** `NOT_CONFIGURED` (Defensive fallback; no API key committed in `.env`)

*Rule strictly enforced: Absence of API credentials gracefully returns `NOT_CONFIGURED` status rather than fake results.*
