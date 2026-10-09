# MailForensics — Threat Model Document

## Assets
1. Local Forensic Database (Email samples, findings, cases, audit logs).
2. Threat Intelligence API Keys (VirusTotal, OTX, AbuseIPDB).
3. JWT Secret Keys and User Credentials.

## Adversary Capabilities & Defensive Mitigations

| Threat Vector | Potential Impact | Defensive Mitigation in MailForensics |
| :--- | :--- | :--- |
| Malicious Attachment Execution | Arbitrary Code Execution on SOC workstation | Zero-execution static analysis. Files stored in isolated storage directory with UUID filenames. |
| Malicious URL Auto-Fetch / Drive-by Download | Infrastructure compromise or payload download | Extracted URLs are parsed strictly using `urllib.parse`. No HTTP GET requests are fired. |
| Path Traversal in Uploaded Filenames | File overwrite on SOC server | Filename sanitization via `os.path.basename` and `validate_storage_path` enforcing strict parent directory bounds. |
| Zip Bomb Archive Upload | Denial of Service (Disk Exhaustion) | Safe archive inspection checking uncompressed size, total file count, and nesting depth limits before extraction. |
| Credential Leaks in Audit Logs | Exposure of API keys / Passwords | Automatic key redactor in `log_audit_event` redacting sensitive field keys. |
