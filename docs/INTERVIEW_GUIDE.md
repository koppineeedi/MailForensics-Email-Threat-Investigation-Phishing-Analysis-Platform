# MailForensics — Technical Interview Guide & Core Concepts

## Key Concepts to Discuss with Interviewers

### 1. How Email Authentication Works
- **SPF (Sender Policy Framework)**: Specifies which IP addresses are authorized to send email on behalf of a DNS domain via `v=spf1` TXT records.
- **DKIM (DomainKeys Identified Mail)**: Adds a cryptographic RSA/Ed25519 signature header (`DKIM-Signature`) to verify that the message body and headers were not tampered with during transit.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Mandates alignment between the header `From` domain and the SPF/DKIM authenticated domains.

### 2. Defensive Security Principles
- **Why active content is never executed**: Attachments and URLs are malicious payloads in real-world SOC scenarios. MailForensics isolates parsing to static RFC header decoding, string regex normalization, and cryptographic hashing.
- **Explainable Risk Scoring vs Machine Learning Black Boxes**: In SOC operations, analysts require evidence-backed risk explanations (e.g. `+25 for DMARC Failure`, `+20 for IP-host URL`) rather than arbitrary predictions.

### 3. Architecture Highlights
- **FastAPI & Async WebSockets**: Real-time event streaming (`/ws/email/{id}`) notifies the React UI as each pipeline stage completes.
- **Clean Relational Schema**: 23 SQLAlchemy models enforcing foreign key constraints, indexing, and append-only audit logging.
