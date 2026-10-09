import re
from urllib.parse import urlparse, unquote
from typing import List, Dict, Any, Tuple

# Suspicious TLDs often abused in phishing
SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".club", ".work", ".click", ".country", ".kim", ".science",
    ".gq", ".ml", ".cf", ".ga", ".tk", ".fit", ".rest", ".racing", ".zip", ".mov"
]

# Heuristic keywords associated with phishing credential harvesting
CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "bank", "password",
    "security", "credential", "confirm", "wallet", "invoice", "authorize", "token"
]

def extract_urls(
    body_plain: str,
    body_html: str,
    headers: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Safely extract and normalize URLs from plain text body, HTML body, and headers.
    Does NOT make any network requests or open URLs.
    """
    raw_url_entries = []

    # Regex pattern for matching URLs
    url_pattern = re.compile(
        r'https?://(?:[a-zA-Z0-9\.\-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s"<>]*)?',
        re.IGNORECASE
    )

    # 1. Plain text URLs
    if body_plain:
        for match in url_pattern.findall(body_plain):
            raw_url_entries.append((match, "BODY_TEXT"))

    # 2. HTML body URLs (href attributes + raw text)
    if body_html:
        href_matches = re.findall(r'href=["\'](https?://[^"\']+)["\']', body_html, re.IGNORECASE)
        for href in href_matches:
            raw_url_entries.append((href, "BODY_HTML"))
        for match in url_pattern.findall(body_html):
            raw_url_entries.append((match, "BODY_HTML"))

    parsed_urls = []
    findings = []
    seen_normalized = set()

    for orig_url, source_loc in raw_url_entries:
        # Clean trailing punctuation
        clean_url = orig_url.rstrip('.,;)"]\'')
        
        try:
            parsed = urlparse(clean_url)
        except Exception:
            continue

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        if not hostname:
            continue

        port = parsed.port
        path = parsed.path
        query = parsed.query

        # Normalize URL
        normalized_url = f"{scheme}://{hostname}{f':{port}' if port else ''}{path}{f'?{query}' if query else ''}"

        if normalized_url in seen_normalized:
            continue
        seen_normalized.add(normalized_url)

        # Check indicators
        is_http = (scheme == "http")
        is_ip_based = bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname))
        is_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
        contains_credentials = any(kw in clean_url.lower() for kw in CREDENTIAL_KEYWORDS)
        is_punycode = "xn--" in hostname

        url_record = {
            "original_url": orig_url,
            "normalized_url": normalized_url,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": path,
            "query": query,
            "domain": hostname,
            "ip_address": hostname if is_ip_based else None,
            "source_location": source_loc,
            "is_http": is_http,
            "is_ip_based": is_ip_based,
            "is_suspicious_tld": is_suspicious_tld,
            "contains_credentials": contains_credentials,
            "is_punycode": is_punycode,
            "is_lookalike": False
        }
        parsed_urls.append(url_record)

        # Generate Findings
        if is_ip_based:
            findings.append({
                "finding_code": "IP_BASED_URL",
                "category": "URL_ANALYSIS",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": f"URL: '{normalized_url}'",
                "explanation": "URL uses an raw IP address host instead of a domain name, hiding domain identity.",
                "source": "URL_EXTRACTOR"
            })

        if is_suspicious_tld:
            findings.append({
                "finding_code": "SUSPICIOUS_TLD_URL",
                "category": "URL_ANALYSIS",
                "severity": "SUSPICIOUS",
                "confidence": 0.85,
                "evidence": f"Host: '{hostname}'",
                "explanation": f"URL host uses a Top-Level Domain frequently associated with spam or phishing campaigns.",
                "source": "URL_EXTRACTOR"
            })

        if is_http:
            findings.append({
                "finding_code": "UNENCRYPTED_HTTP_URL",
                "category": "URL_ANALYSIS",
                "severity": "GUARDED",
                "confidence": 0.80,
                "evidence": f"URL: '{normalized_url}'",
                "explanation": "URL uses plain HTTP without TLS encryption.",
                "source": "URL_EXTRACTOR"
            })

        if contains_credentials:
            findings.append({
                "finding_code": "CREDENTIAL_KEYWORD_URL",
                "category": "URL_ANALYSIS",
                "severity": "SUSPICIOUS",
                "confidence": 0.75,
                "evidence": f"URL: '{normalized_url}'",
                "explanation": "[HEURISTIC INDICATOR] URL path/query contains credential or account harvesting keywords.",
                "source": "URL_EXTRACTOR"
            })

    return parsed_urls, findings
