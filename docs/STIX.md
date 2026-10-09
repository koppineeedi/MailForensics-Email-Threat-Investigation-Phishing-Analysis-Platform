# MailForensics — STIX 2.1 Threat Intelligence Export

## 1. Specification & Standards

MailForensics supports threat intelligence sharing via the **OASIS STIX™ Version 2.1 (Structured Threat Information Expression)** specification.

Endpoint:
```http
GET /api/emails/{id}/stix
GET /api/reports/{id}/stix
```

All objects are encapsulated in a standard STIX 2.1 `bundle`:
```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "spec_version": "2.1",
  "objects": [...]
}
```

---

## 2. Evidence-Based Object Mapping

To prevent the dissemination of false intelligence, STIX objects are **only emitted when backed by direct forensic observations**:

| Observed Forensic Evidence | Generated STIX 2.1 Cyber Observable / Domain Object |
| :--- | :--- |
| **Sender Email Address** | `email-addr` (normalized value) |
| **RFC Email Message Header/Body** | `email-message` (subject, date, message_id, from_ref) |
| **Extracted Normalized URLs** | `url` (normalized URL string) |
| **Suspicious IP-Based / Phishing URLs** | `indicator` (pattern: `[url:value = '...']`) |
| **Quarantined Attachments** | `file` (name, size, SHA-256, SHA-1, MD5 hashes, mime_type) |
| **Executable/Macro Attachments** | `indicator` (pattern: `[file:hashes.'SHA-256' = '...']`) |
| **High/Critical Phishing Rules** | `indicator` (pattern: `[email-message:subject = '...']`) |
| **Investigating Platform Identity** | `identity` (MailForensics Defensive Platform) |

---

## 3. Strict Limitations & Evidentiary Boundaries

1. **No Speculative Threat Actors:** MailForensics will **never** generate speculative `threat-actor`, `campaign`, or `intrusion-set` objects unless confirmed by verified external threat intelligence feeds with valid API keys.
2. **Deterministic Patterns:** All STIX indicator patterns use standardized STIX Patterning language (e.g. `[file:hashes.'SHA-256' = '...']`).
3. **No Dynamic Execution Artifacts:** Because attachments are never executed, STIX exports do not include process trees or registry modifications.
