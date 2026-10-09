# MailForensics — Production Architecture & Design Document

## System Overview
MailForensics is a defensive Security Operations Center (SOC) investigation platform for analyzing suspicious email samples (.eml, raw RFC 822/5322 messages, headers, attachments, and URLs).

```
+-----------------------------------------------------------------------------------+
|                                  React Frontend                                   |
|       (TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts, WebSocket Client)  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                HTTP / WebSockets (8000)
                                          |
+-----------------------------------------v-----------------------------------------+
|                                 FastAPI Backend                                   |
|                                                                                   |
|  +--------------------+  +--------------------+  +-----------------------------+  |
|  |   Auth & RBAC      |  | Audit Logger       |  | WS Event Manager            |  |
|  +--------------------+  +--------------------+  +-----------------------------+  |
|  | Health & Probes    |  | Dual Mode Dispatch |  | STIX 2.1 Export Generator   |  |
|  | (/health/ready)    |  | (local vs celery)  |  | (OASIS Compliant JSON)      |  |
|  +--------------------+  +--------------------+  +-----------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                          Email Forensic Pipeline                            |  |
|  |                                                                             |  |
|  | RFC Parser -> Header Analyzer -> Received Chain -> Auth (SPF/DKIM/DMARC)    |  |
|  | -> DNS Verifier -> Sender/Domain -> URL Extractor -> Safe Static Attachment |  |
|  | Analyzer (PE/PDF) -> Native YARA C-Engine -> Threat Intel -> Risk Engine    |  |
|  +-----------------------------------------------------------------------------+  |
+-------------------+---------------------------------------+-----------------------+
                    |                                       |
          SQLAlchemy ORM (Pool)                       Celery / Redis
                    |                                       |
+-------------------v-------------------+   +---------------v-----------------------+
|        PostgreSQL / SQLite            |   |              Redis                    |
|  - SQLite (Local dev/testing)         |   |  - Message Broker                     |
|  - PostgreSQL + Alembic (Production)  |   |  - Result Backend                     |
+---------------------------------------+   +---------------+-----------------------+
                                                            |
                                            +---------------v-----------------------+
                                            |           Celery Worker               |
                                            |  - Distributed background processing  |
                                            |  - Same forensic engine & models      |
                                            +---------------------------------------+
```

## Processing Modes Architecture
The platform implements an explicit dual processing model configured via `PROCESSING_MODE`:
1. **`local` Mode (Default for Development and Automated Testing)**:
   - Analysis executes synchronously within FastAPI's `BackgroundTasks`.
   - SQLite is utilized (`sqlite:///./mailforensics.db`).
   - Requires zero external services (no Redis, no Celery, no Docker daemon required).
   - Allows all unit and API tests to execute cleanly and reliably.
2. **`celery` Mode (Production Deployment)**:
   - Uploaded sample is written to storage, recorded in the database, and queued to Redis.
   - Celery worker picks up `analyze_email_task(email_id)`.
   - Real-time event notifications stream to WebSockets across all worker stages.

## Defensive Safety Controls Architecture
1. **Isolated Attachment Parsing**: Attachments are stored as UUID-named binary files in a dedicated storage directory. No attachment, macro, executable, or script is ever executed.
2. **Safe Static PE & PDF Inspection**:
   - PE files: COFF header inspected directly for architecture (`IMAGE_FILE_MACHINE_I386` / `AMD64`), section counts, entropy, and MZ signatures.
   - PDF files: Scanned statically for embedded streams, `/JavaScript`, `/EmbeddedFiles`, and `/OpenAction`.
3. **URL Isolation**: Extracted URLs are parsed using URL string utilities without visiting or firing HTTP requests.
4. **Zip Bomb Protection**: Archives are inspected safely for nested depths, total file counts, and decompression limits.
5. **Native YARA C-Engine**: Attachment bytes are scanned using `yara-python` 4.5.4 compiled C-library matching against defensive rules without execution.
6. **Live DNS Verification**: Queries SPF and DMARC TXT records directly via `dnspython`, distinguishing `HEADER_REPORTED` from `DNS_VERIFIED`.
7. **Threat Intelligence Isolation**: External API calls (VirusTotal, OTX, AbuseIPDB) strictly return `NOT_CONFIGURED` when API keys are absent. No mock results or false scores are generated.

## Component Breakdown
- `app/services/email_parser.py`: RFC email parser extracting MIME structure, headers, body, and attachments.
- `app/services/header_analyzer.py`: Detects header inconsistencies, spoofing indicators, and From/Reply-To/Return-Path mismatches.
- `app/services/received_chain.py`: Parses Received headers into ordered chronological transit hops with delay & IP anomaly detection.
- `app/services/spf_analyzer.py`, `dkim_analyzer.py`, `dmarc_analyzer.py`: Authentication protocol verification engines.
- `app/services/dns_verifier.py`: Independent live DNS verification for SPF, DMARC, and DKIM selector keys.
- `app/services/sender_domain_analyzer.py`: Typosquatting, punycode, lookalike domain, and entropy detector.
- `app/services/url_extractor.py`: Extracts and normalizes URLs, flagging IP-hosts, suspicious TLDs, and credential keywords.
- `app/services/attachment_analyzer.py`: Safe static file analysis, SHA-256 calculation, PE header parsing, and static metadata extraction.
- `app/services/yara_service.py`: Native C-extension YARA scanner with defensive rule compilation and verification.
- `app/services/phishing_detector.py`: Defensive rule engine producing evidence-backed findings.
- `app/services/risk_engine.py`: 0–100 evidence-weighted risk score calculator.
- `app/services/threat_intel_service.py`: Provider abstraction (VirusTotal, OTX, AbuseIPDB) returning `NOT_CONFIGURED` when unconfigured.
- `app/services/stix_generator.py`: Generates standardized OASIS STIX 2.1 JSON bundles with observables and relationships.
- `app/services/report_generator.py`: ReportLab PDF and JSON forensic investigation report builder.
- `app/celery_app.py` & `app/tasks.py`: Celery distributed queue application and analysis task.
- `app/database.py` & `alembic/`: Database engine with connection pooling and schema migrations.
