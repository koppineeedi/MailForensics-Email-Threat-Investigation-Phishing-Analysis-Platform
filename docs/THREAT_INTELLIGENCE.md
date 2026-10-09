# MailForensics — Threat Intelligence Architecture & Standards

## 1. Defensive Philosophy & No-Fabrication Mandate

MailForensics adheres to strict SOC evidentiary standards:
- **Zero Synthetic Intelligence:** If an external API key is not configured, the platform explicitly reports `NOT_CONFIGURED`. It **never** converts an absence of credentials or a network timeout into a fake "Clean" verdict.
- **Provider State Transparency:** The platform exposes exact provider states:
  - `NOT_CONFIGURED`: API key is missing from environment.
  - `CONFIGURED`: Key is set, ready for query.
  - `LIVE_PROVIDER_VERIFIED`: Real API response received from provider.
  - `PROVIDER_ERROR`: External provider returned an HTTP error code (e.g. 500, 503).
  - `RATE_LIMITED`: Provider returned HTTP 429 quota exhaustion.
  - `TIMEOUT`: Provider did not respond within configured timeout (8.0s).
  - `INVALID_CREDENTIALS`: Provider returned HTTP 401/403 unauthorized.

---

## 2. Integrated Providers & Configuration

Threat intelligence keys are configured via environment variables or `.env`:

```bash
# VirusTotal API v3 (File Hashes, Domains, URLs)
VT_API_KEY=your_virustotal_api_key_here
# Or alternatively:
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AlienVault OTX Direct API (Pulses & File Hashes)
OTX_API_KEY=your_otx_api_key_here
# Or alternatively:
ALIENVAULT_OTX_API_KEY=your_otx_api_key_here

# AbuseIPDB API v2 (IP Reputation & Abuse Reports)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

*Defensive Default:* Keys are optional. In air-gapped environments or local testing, the platform runs with full static and heuristic analysis without requiring external API keys.

---

## 3. Data Schema & Evidence Preservation

Every threat intelligence observation records:

| Field | Description |
| :--- | :--- |
| `provider` | Provider name (`VirusTotal`, `AlienVault_OTX`, `AbuseIPDB`) |
| `indicator` | The exact queried string (SHA-256 hash, IPv4 address, domain) |
| `indicator_type` | `FILE_HASH_SHA256`, `IPV4_ADDRESS`, `DOMAIN` |
| `lookup_time` | ISO-8601 UTC timestamp of execution |
| `status` | Explicit provider status code |
| `source` | `LIVE_EXTERNAL_PROVIDER` or `NOT_CONFIGURED` |
| `evidence` | Structured JSON containing raw telemetry, hit counts, or pulse IDs |
| `error` | Human-readable explanation if unconfigured or errored |
