# MailForensics — Database Architecture & Operations

## 1. Overview & Dual-Engine Strategy

MailForensics supports two primary relational database configurations:

1. **SQLite (Development / Testing / Air-Gapped Workstations):**
   - Zero-dependency local setup.
   - Preserves SQLite foreign key enforcement via runtime `PRAGMA foreign_keys=ON`.
   - File-based persistence under `backend/mailforensics.db`.
   - Test databases dynamically isolated (`test_mailforensics.db`).

2. **PostgreSQL (Production / Multi-Analyst SOC Deployments):**
   - High-concurrency relational backend supporting multi-worker Celery task pipelines.
   - Enterprise connection pooling via SQLAlchemy `QueuePool` with:
     - `pool_size`: 10 (configurable)
     - `max_overflow`: 20
     - `pool_pre_ping`: True (verifies liveness before checkout)
     - `pool_recycle`: 1800 seconds (prevents stale TCP connections)
   - Connection driver: `psycopg` (v3) with native C/binary optimizations.

---

## 2. Configuration & Connection Strings

The database connection is set via the environment variable `DATABASE_URL`:

### SQLite Development Mode:
```bash
DATABASE_URL=sqlite:///./mailforensics.db
```

### PostgreSQL Production Mode:
```bash
# Standard PostgreSQL connection using psycopg 3 driver
DATABASE_URL=postgresql+psycopg://postgres:your_secure_password@postgres:5432/mailforensics
```

*Security Warning:* Never commit database passwords to source control. Set `DATABASE_URL` via `.env` or container environment secrets.

---

## 3. Schema & Table Structure

The platform manages 23 relational tables:

| Table Category | Tables Included |
| :--- | :--- |
| **Identity & Access** | `users` |
| **Forensic Email Core** | `email_samples`, `email_headers`, `email_addresses`, `email_domains`, `received_hops`, `email_events` |
| **Authentication Records** | `authentication_results` |
| **Artifacts & Files** | `attachments`, `attachment_findings`, `urls` |
| **Static Threat Detection** | `yara_rules`, `phishing_findings`, `threat_intel_results` |
| **SOC Case Management** | `email_cases`, `case_emails`, `case_notes`, `case_findings`, `case_urls`, `case_attachments`, `analyst_verdicts` |
| **Compliance & Reporting** | `reports`, `audit_logs` |

---

## 4. Database Migrations (Alembic)

Database schema evolution is managed via **Alembic**:

```bash
# Apply migrations to the current database
cd backend
alembic upgrade head

# Check current revision status
alembic current

# Create a new revision after updating models
alembic revision --autogenerate -m "Add new forensic fields"
```

In Docker production deployments, the backend container automatically runs `alembic upgrade head` on startup before launching FastAPI.

---

## 5. Startup Validation & Health Checks

`app.database.check_db_connection()` executes an active verification query (`SELECT 1`) at application startup and exposes health status via `GET /health` and `GET /health/ready`.

If the database is unreachable, the system gracefully handles the failure by reporting component status `UNAVAILABLE` or `ERROR` without crashing worker processes.

---

## 6. Backup & Recovery Considerations

- **SQLite:** Safely backup `mailforensics.db` using SQLite online backup API or file copy when idle:
  ```bash
  sqlite3 mailforensics.db ".backup mailforensics_backup_$(date +%Y%m%d).db"
  ```
- **PostgreSQL:** Execute standard `pg_dump`:
  ```bash
  pg_dump -U postgres -d mailforensics -F c -b -v -f /backups/mailforensics_$(date +%Y%m%d).dump
  ```
