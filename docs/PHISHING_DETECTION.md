# MailForensics — Phishing Detection & Explainable Risk Model

## Detection Finding Codes

| Finding Code | Category | Severity | Description |
| :--- | :--- | :--- | :--- |
| `REPLY_TO_MISMATCH` | HEADER_ANALYSIS | SUSPICIOUS | Reply-To domain differs from header From domain |
| `RETURN_PATH_MISMATCH` | HEADER_ANALYSIS | GUARDED | Envelope Return-Path differs from header From domain |
| `SPF_FAILURE` | EMAIL_AUTHENTICATION | HIGH | SPF evaluation returned FAIL |
| `DKIM_FAILURE` | EMAIL_AUTHENTICATION | HIGH | DKIM evaluation returned FAIL |
| `DMARC_FAILURE` | EMAIL_AUTHENTICATION | HIGH | DMARC alignment evaluation failed |
| `LOOKALIKE_DOMAIN` | DOMAIN_ANALYSIS | HIGH | Domain is visually similar to brand domain (typosquatting) |
| `PUNYCODE_DOMAIN` | DOMAIN_ANALYSIS | SUSPICIOUS | Domain uses Punycode (`xn--`) encoding |
| `IP_BASED_URL` | URL_ANALYSIS | HIGH | Extracted URL uses raw IP address instead of domain name |
| `SUSPICIOUS_ATTACHMENT` | ATTACHMENT_ANALYSIS | HIGH | Attachment has executable or script extension (.exe, .scr, .vbs) |
| `URGENT_LANGUAGE_INDICATOR` | CONTENT_HEURISTICS | GUARDED | Message body contains urgent social engineering keywords |
| `CREDENTIAL_REQUEST_INDICATOR` | CONTENT_HEURISTICS | SUSPICIOUS | Message body requests password or credential confirmation |

## Explainable Risk Score Bounds
- `0–19`: **LOW**
- `20–39`: **GUARDED**
- `40–59`: **SUSPICIOUS**
- `60–79`: **HIGH**
- `80–100`: **CRITICAL**

Automated risk scores are kept completely separate from the Analyst Verdict (`BENIGN`, `SUSPICIOUS`, `PHISHING`, `MALICIOUS_ATTACHMENT`, `SPAM`, `UNRESOLVED`).
