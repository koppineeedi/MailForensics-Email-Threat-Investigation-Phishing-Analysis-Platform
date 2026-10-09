# MailForensics — Email Analysis & Header Investigation Workflow

## Forensic Pipeline Overview
MailForensics executes a deterministic 10-stage forensic pipeline upon email ingestion:

1. **RFC Parsing**: Extracts headers, MIME boundaries, plain text body, HTML source, and raw attachments using Python's standard `email` library.
2. **Header Analysis**: Inspects `From`, `Reply-To`, `Return-Path`, `Sender`, and `Message-ID` for domain mismatches and spoofing indicators.
3. **Received Chain Analysis**: Parses all `Received` headers into chronological transit hops, calculating inter-hop delays and detecting private IP anomalies.
4. **SPF Verification**: Evaluates `Authentication-Results` and `Received-SPF` headers.
5. **DKIM Verification**: Inspects signature headers, signing domains, selectors, and verifies cryptographic signatures where compatible.
6. **DMARC Evaluation**: Evaluates SPF alignment and DKIM alignment against the header `From` domain.
7. **Sender & Domain Analysis**: Performs Levenshtein edit distance analysis against target brand domains to detect typosquatting and punycode (`xn--`) attacks.
8. **URL Extraction**: Extracts and normalizes URLs from text and HTML sources, flagging IP-hosts, suspicious TLDs, and credential harvesting keywords.
9. **Attachment Analysis**: Computes SHA-256/SHA-1/MD5 hashes and inspects archive limits safely.
10. **Explainable Risk Scoring**: Consolidates evidence into a 0–100 risk score and evidence factors list.
