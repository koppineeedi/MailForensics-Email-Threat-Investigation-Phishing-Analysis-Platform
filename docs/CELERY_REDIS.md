# MailForensics — Celery Worker & Redis Broker Architecture

## 1. Overview & Dual Processing Modes

MailForensics supports two distinct execution architectures:

1. **Local Mode (`PROCESSING_MODE=local`):**
   - Default for local development, CLI tests, and air-gapped forensic laptops.
   - Executes the email parsing, YARA, heuristic rules, and risk evaluation asynchronously within the FastAPI application event loop using `fastapi.BackgroundTasks`.
   - Requires zero external services or daemon processes.

2. **Celery Distributed Mode (`PROCESSING_MODE=celery`):**
   - Designed for high-volume enterprise SOC deployments and Docker clusters.
   - Decouples file upload from heavy CPU-intensive parsing and static file analysis.
   - Background tasks run in dedicated worker containers, scaling horizontally across nodes.
   - Task broker and result backend: **Redis** (`redis://redis:6379/0`).

---

## 2. Forensic Analysis Pipeline Flow

When an email is ingested, the pipeline transitions through the following stages:

```
[REST / UPLOAD]
      ↓
[FILE VALIDATION & STORAGE] (UUID path, SHA-256 / SHA-1 / MD5)
      ↓
[PROCESSING MODE DECISION]
      ├── local  → FastAPI BackgroundTasks
      └── celery → Celery analyze_email_task.delay(email_id)
            ↓
      [STAGE 1: RFC Email Structure Parsing] (Headers, Body Plain, Body HTML)
            ↓
      [STAGE 2: Multi-Hop Received Chain Traversal] (Hop delays, IP extraction, TLS verification)
            ↓
      [STAGE 3: Header Inconsistency Analysis] (From vs Reply-To, Display Name Spoofing)
            ↓
      [STAGE 4: Authentication Verification] (SPF, DKIM cryptographic check, DMARC alignment)
            ↓
      [STAGE 5: Sender Domain & Lookalike Analysis] (Levenshtein distance, entropy, punycode)
            ↓
      [STAGE 6: Safe URL Extraction & Normalization] (No automated outbound requests)
            ↓
      [STAGE 7: Attachment Static Analysis] (Hashes, MIME, Archive Bomb check)
            ↓
      [STAGE 8: Native YARA Scanning] (PE Headers, VBA Macros, Shell scripts)
            ↓
      [STAGE 9: Threat Intelligence Enrichment] (If API keys configured)
            ↓
      [STAGE 10: Explainable Risk Engine] (0-100 score + evidence breakdown)
            ↓
      [STAGE 11: Real-Time WebSocket Broadcast] (Live event streamed to analyst UI)
```

---

## 3. Running Celery Worker Manually

To launch a standalone Celery worker against Redis:

```bash
cd backend
celery -A app.celery_app.celery_app worker --loglevel=info --concurrency=4
```

In the Docker deployment, the `celery-worker` container automatically runs this command.

---

## 4. Health Checks & Observability

- **Redis Health:** Verified via `app.celery_app.check_redis_connection()`.
- **Worker Health:** Verified via `app.celery_app.check_celery_status()`, querying active workers via Celery `inspect().ping()`.
- Results are reported under `GET /health` and displayed on the Frontend System Status page.
