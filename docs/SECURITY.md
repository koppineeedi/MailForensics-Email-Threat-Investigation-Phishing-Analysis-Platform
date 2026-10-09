# MailForensics — Security Hardening & Defensive Compliance Architecture

## 1. Threat Model & Defensive Mandate

MailForensics is designed for analyzing untrusted, weaponized, and malicious email artifacts. The platform adheres to **Zero Dynamic Execution** and **Defensive Containment** principles:

| Threat Vector | Mitigation Strategy | Implemented Mechanism |
| :--- | :--- | :--- |
| **Malicious Code Execution** | Complete isolation of uploaded attachments. | Zero dynamic sandbox detonation. Files are inspected purely via static hash analysis, PE COFF header inspection, and YARA pattern compilation. |
| **Tracking Beacons & Phishing URLs** | Zero outbound HTTP/HTTPS requests from server or browser. | URLs are extracted, normalized, and displayed as plain text in the UI. No automated scraping; URLs are not rendered as active hyperlinks. |
| **Archive Bomb / Zip Bomb** | Safety limits enforced prior to any archive parsing. | Capped at 50 max files and 100 MB max uncompressed size. Traversal paths (`..`) inside zip headers are blocked and flagged. |
| **Path Traversal Attacks** | Strict file storage boundary validation. | `validate_storage_path()` asserts all file writes resolve within configured storage directories. Original filenames are aggressively sanitized. |
| **Stored Cross-Site Scripting (XSS)** | Safe email body rendering. | Raw HTML email bodies are presented strictly inside `<pre>` code blocks as text. `dangerouslySetInnerHTML` is prohibited. |
| **SQL Injection (SQLi)** | Parameterized queries via ORM. | All queries execute through SQLAlchemy ORM parameter binding. Zero raw SQL string concatenation. |
| **Credential Theft & Brute Force** | Cryptographic authentication. | Passwords hashed using `bcrypt` (work factor 12). API access protected by short-lived signed JWTs (HS256). |
| **Unauthorized Action Execution** | Role-Based Access Control (RBAC). | Roles (`ADMIN`, `ANALYST`, `VIEWER`) enforced across sensitive routes using FastAPI dependencies. |
| **Audit Compliance & Chain of Custody** | Non-repudiation audit logging. | Crucial analyst decisions (verdict submission, report generation, data export) logged to the `audit_logs` database table. |

---

## 2. Network Security & Air-Gap Compliance

- **No Public DNS Leakage:** `ENABLE_LIVE_DNS_LOOKUPS` is set to `False` by default to prevent honeypot beaconing or active information leakage during sensitive DFIR investigations.
- **Strict CORS Policy:** Whitelist restricted to authorized frontend origins.
- **Secret Redaction:** Threat intelligence keys, database passwords, and JWT secrets are never rendered in responses, logs, or reports.
