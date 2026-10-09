# MailForensics — REST API Reference

## Authentication
- `POST /api/auth/register` — Register a new analyst account.
- `POST /api/auth/login` — Authenticate and receive a JWT access token.
- `GET /api/auth/me` — Return current authenticated user profile.

## Email Ingestion & Analysis
- `POST /api/emails` — Upload a `.eml` file or submit raw RFC content.
- `GET /api/emails` — List analyzed email samples with summary risk scores.
- `GET /api/emails/{id}` — Fetch detailed email artifact record with all nested findings.
- `POST /api/emails/{id}/analyze` — Trigger/re-run full backend analysis pipeline.
- `POST /api/emails/{id}/verdict` — Set analyst verdict (`BENIGN`, `SUSPICIOUS`, `PHISHING`, etc.).
- `POST /api/emails/compare` — Compare two email artifacts side by side.
- `DELETE /api/emails/{id}` — Delete an email sample and purge raw storage.

## Headers & Received Chain
- `GET /api/emails/{id}/headers` — Fetch raw preserved RFC headers.
- `GET /api/emails/{id}/received-chain` — Fetch ordered transit hops.
- `GET /api/emails/{id}/authentication` — Fetch SPF, DKIM, and DMARC results.

## Cases, Graph & Reports
- `POST /api/cases` — Create an incident case.
- `GET /api/cases` — List investigation cases.
- `GET /api/relationships` — Fetch global evidence relationship graph nodes and edges.
- `POST /api/emails/{id}/report` — Generate PDF or JSON forensic report.
- `GET /api/audit` — Query append-only audit logs.

## WebSockets
- `WS /ws/email/{email_id}` — Subscribe to real-time analysis pipeline events.
- `WS /ws/audit` — Subscribe to live audit log stream.
