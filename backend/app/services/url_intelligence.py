"""
URL Intelligence Service — Static phishing URL analysis engine.
ZERO network requests are made to the submitted URL (SSRF prevention by design).
All analysis is purely string/regex/heuristic based.
"""
import re
import math
from urllib.parse import urlparse, unquote
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


SUSPICIOUS_TLDS = {
    '.top', '.xyz', '.click', '.tk', '.ml', '.ga', '.cf', '.pw',
    '.ru', '.cn', '.info', '.biz', '.win', '.loan', '.work',
    '.date', '.review', '.stream', '.download', '.gq', '.icu',
    '.buzz', '.surf', '.monster', '.rest', '.life', '.live'
}

CREDENTIAL_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'password',
    'passwd', 'credential', 'account', 'secure', 'update',
    'confirm', 'validate', 'activate', 'unlock', 'recover',
    'restore', 'suspend', 'expire', 'billing', 'payment'
]

BRAND_TARGETS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'twitter', 'instagram', 'netflix', 'bankofamerica', 'chase',
    'wellsfargo', 'citibank', 'outlook', 'office365', 'dropbox',
    'linkedin', 'docusign', 'fedex', 'ups', 'dhl', 'irs', 'ssa'
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'rebrand.ly',
    'cutt.ly', 'short.link', 'clck.ru', 'bl.ink', 'rb.gy'
}

RISK_CATEGORIES = [
    (0,  20,  'LOW'),
    (20, 40,  'GUARDED'),
    (40, 60,  'SUSPICIOUS'),
    (60, 80,  'HIGH'),
    (80, 101, 'CRITICAL'),
]


@dataclass
class Detection:
    code: str
    weight: int
    title: str
    description: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL


def categorize_score(score: int) -> str:
    for lo, hi, cat in RISK_CATEGORIES:
        if lo <= score < hi:
            return cat
    return 'CRITICAL'


def _safe_parse(url: str) -> Optional[Any]:
    """Safely parse a URL, handling malformed inputs."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            parsed = urlparse('https://' + url)
        return parsed
    except Exception:
        return None


def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Main analysis entry point. Returns full analysis result dict.
    NO network requests are made. All analysis is static/heuristic.
    """
    raw_url = (raw_url or '').strip()
    detections: List[Detection] = []

    if not raw_url:
        return {
            'url': raw_url,
            'risk_score': 0,
            'risk_category': 'LOW',
            'detections': [],
            'summary': 'No URL provided.',
            'is_safe_to_display': True,
            'parsed': None,
        }

    parsed = _safe_parse(raw_url)

    if not parsed or not parsed.netloc:
        return {
            'url': raw_url,
            'risk_score': 10,
            'risk_category': 'LOW',
            'detections': [{
                'code': 'MALFORMED_URL',
                'weight': 10,
                'title': 'Malformed URL Structure',
                'description': (
                    'The URL cannot be parsed into a valid structure. '
                    'Malformed URLs are sometimes used to evade URL scanners.'
                ),
                'severity': 'LOW',
            }],
            'summary': 'URL appears malformed or unparseable.',
            'is_safe_to_display': True,
            'parsed': None,
        }

    scheme  = parsed.scheme.lower()
    netloc  = parsed.netloc.lower()
    path    = parsed.path.lower()
    query   = (parsed.query or '').lower()
    full_lower = raw_url.lower()

    # --- DETECTOR 1: @ symbol trick ---
    if '@' in netloc:
        detections.append(Detection(
            code='AT_SYMBOL_USERINFO',
            weight=25,
            title='@ Symbol User-Info Trick',
            description=(
                'The URL contains an @ symbol in the host portion. Browsers render everything '
                'before @ as user credentials, so the real destination is after the @. '
                'Example: http://legit-bank.com@evil.com/phish — real host is evil.com. '
                'This is a classic phishing obfuscation technique.'
            ),
            severity='HIGH',
        ))

    # --- DETECTOR 2: Excessive URL length ---
    url_len = len(raw_url)
    if url_len > 500:
        detections.append(Detection(
            code='EXCESSIVE_LENGTH',
            weight=20,
            title='Excessive URL Length',
            description=(
                f'URL is {url_len} characters long (threshold: 500). Attackers use excessively '
                'long URLs to hide the real destination, confuse users, and bypass simple filters.'
            ),
            severity='MEDIUM',
        ))
    elif url_len > 200:
        detections.append(Detection(
            code='LONG_URL',
            weight=10,
            title='Unusually Long URL',
            description=(
                f'URL is {url_len} characters long. While not conclusive, unusually long URLs '
                'are common in phishing campaigns to obscure the real destination.'
            ),
            severity='LOW',
        ))

    # --- DETECTOR 3: IP-based hostname ---
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
        r'|'
        r'^\[?[0-9a-fA-F:]+\]?$'
    )
    hostname = netloc.split(':')[0].lstrip('[').rstrip(']')
    if ip_pattern.match(hostname):
        detections.append(Detection(
            code='IP_HOST',
            weight=30,
            title='IP Address Used as Hostname',
            description=(
                f'The URL uses a raw IP address ({hostname}) instead of a domain name. '
                'Legitimate services rarely use IP addresses in URLs shown to users. '
                'This technique bypasses DNS reputation checks and hides the true owner.'
            ),
            severity='HIGH',
        ))

    # --- DETECTOR 4: Excessive subdomain depth ---
    domain_parts = hostname.split('.')
    subdomain_depth = max(0, len(domain_parts) - 2)
    if subdomain_depth >= 4:
        detections.append(Detection(
            code='EXCESSIVE_SUBDOMAINS',
            weight=20,
            title='Excessive Subdomain Depth',
            description=(
                f'The URL has {subdomain_depth} subdomain levels (e.g. a.b.c.d.evil.com). '
                'Phishing sites use deep subdomain nesting to place legitimate-looking brand '
                'names early (e.g. paypal.secure.update.evil.com) to trick users.'
            ),
            severity='HIGH',
        ))
    elif subdomain_depth >= 2:
        detections.append(Detection(
            code='DEEP_SUBDOMAINS',
            weight=10,
            title='Multiple Subdomain Levels',
            description=(
                f'URL has {subdomain_depth} subdomain levels. Moderate depth may be used to '
                'impersonate trusted brands by prepending them as subdomains.'
            ),
            severity='LOW',
        ))

    # --- DETECTOR 5: Punycode / IDN homograph ---
    if 'xn--' in netloc:
        detections.append(Detection(
            code='PUNYCODE_DOMAIN',
            weight=25,
            title='Punycode / IDN Homograph Domain',
            description=(
                'The URL contains a Punycode-encoded internationalized domain (xn-- prefix). '
                'IDN homograph attacks use Unicode characters that visually resemble ASCII letters '
                '(e.g., Cyrillic "а" looks like Latin "a") to spoof trusted domains.'
            ),
            severity='HIGH',
        ))

    # --- DETECTOR 6: HTTP instead of HTTPS ---
    if scheme == 'http':
        detections.append(Detection(
            code='UNENCRYPTED_HTTP',
            weight=15,
            title='Unencrypted HTTP Protocol',
            description=(
                'URL uses plain HTTP instead of HTTPS. While not conclusive alone, '
                'phishing pages often skip TLS certificates due to cost or detection risk. '
                'Legitimate login and payment pages always use HTTPS.'
            ),
            severity='MEDIUM',
        ))

    # --- DETECTOR 7: Suspicious TLD ---
    tld = '.' + domain_parts[-1] if domain_parts else ''
    if tld in SUSPICIOUS_TLDS:
        detections.append(Detection(
            code='SUSPICIOUS_TLD',
            weight=20,
            title=f'High-Risk Top-Level Domain ({tld})',
            description=(
                f'The domain uses the "{tld}" TLD, which appears frequently in phishing campaigns '
                'and malicious infrastructure. These TLDs are often cheap, freely registered, '
                'or have minimal abuse enforcement.'
            ),
            severity='MEDIUM',
        ))

    # --- DETECTOR 8: Credential/phishing keywords in URL ---
    found_cred_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in full_lower]
    if found_cred_keywords:
        weight = 25 if len(found_cred_keywords) > 1 else 15
        severity = 'HIGH' if len(found_cred_keywords) > 1 else 'MEDIUM'
        detections.append(Detection(
            code='CREDENTIAL_KEYWORDS',
            weight=weight,
            title='Credential Harvesting Keywords Detected',
            description=(
                f'URL contains keywords associated with credential harvesting or phishing: '
                f'{", ".join(found_cred_keywords[:5])}. '
                'Attackers embed these keywords to create convincing login/verify pages.'
            ),
            severity=severity,
        ))

    # --- DETECTOR 9: Brand impersonation ---
    found_brands = [brand for brand in BRAND_TARGETS if brand in full_lower]
    for brand in found_brands[:3]:
        brand_in_registered = any(
            part == brand or part.startswith(brand)
            for part in domain_parts[-3:]
        )
        if not brand_in_registered:
            detections.append(Detection(
                code=f'BRAND_IMPERSONATION_{brand.upper()}',
                weight=25,
                title=f'Brand Impersonation: {brand.capitalize()}',
                description=(
                    f'URL references "{brand}" but the registered domain does not appear to '
                    f'be the official {brand.capitalize()} domain. Attackers embed brand '
                    'names in subdomains or paths to deceive users (e.g., amazon.evil.com/login).'
                ),
                severity='HIGH',
            ))
            break  # only flag first brand match

    # --- DETECTOR 10: URL shortener ---
    if hostname in URL_SHORTENERS:
        detections.append(Detection(
            code='URL_SHORTENER',
            weight=20,
            title='URL Shortener / Redirector Detected',
            description=(
                f'URL uses the shortening service "{hostname}". URL shorteners hide the true '
                'destination from the user. While many are legitimate, they are frequently '
                'abused in phishing campaigns to bypass email filters and obscure malicious destinations.'
            ),
            severity='MEDIUM',
        ))

    # --- DETECTOR 11: Double encoding / obfuscation ---
    decoded_url = unquote(raw_url)
    if decoded_url != raw_url and ('%' in raw_url):
        pct_count = raw_url.count('%')
        if pct_count >= 3:
            detections.append(Detection(
                code='URL_ENCODING_OBFUSCATION',
                weight=20,
                title='URL Encoding Obfuscation',
                description=(
                    f'URL contains {pct_count} percent-encoded characters. Attackers use URL '
                    'encoding to hide malicious keywords from filters and confuse parsing tools. '
                    'High encoding density often indicates deliberate obfuscation.'
                ),
                severity='MEDIUM',
            ))

    # --- DETECTOR 12: High-entropy / random subdomain ---
    if subdomain_depth >= 1 and len(domain_parts) > 2:
        subdomain = '.'.join(domain_parts[:-2])
        if subdomain and len(subdomain) > 10:
            char_counts: Dict[str, int] = {}
            for c in subdomain:
                char_counts[c] = char_counts.get(c, 0) + 1
            entropy = -sum(
                (v / len(subdomain)) * math.log2(v / len(subdomain))
                for v in char_counts.values()
            )
            if entropy > 3.8:
                detections.append(Detection(
                    code='HIGH_ENTROPY_SUBDOMAIN',
                    weight=15,
                    title='High-Entropy / Random-Appearing Subdomain',
                    description=(
                        f'The subdomain "{subdomain[:30]}" has high character entropy '
                        f'({entropy:.2f} bits), suggesting it may be algorithmically generated '
                        '(DGA) or randomly assigned. DGA domains are common in malware C2 infrastructure.'
                    ),
                    severity='MEDIUM',
                ))

    # Deduplicate by code
    seen_codes: set = set()
    unique_detections: List[Detection] = []
    for d in detections:
        if d.code not in seen_codes:
            seen_codes.add(d.code)
            unique_detections.append(d)

    total_score = min(100, sum(d.weight for d in unique_detections))
    risk_category = categorize_score(total_score)

    # Build summary
    n = len(unique_detections)
    if n == 0:
        summary = (
            'No significant phishing indicators detected in static URL analysis. '
            'Exercise normal caution when visiting unknown URLs.'
        )
    elif total_score < 40:
        summary = f'Minor indicators detected. URL shows {n} low-risk signal(s). Exercise caution.'
    elif total_score < 70:
        summary = (
            f'Moderate phishing risk. {n} suspicious indicator(s) found. '
            'Avoid clicking without verification.'
        )
    else:
        summary = f'HIGH PHISHING RISK. {n} critical indicator(s) found. Do not visit this URL.'

    return {
        'url': raw_url,
        'risk_score': total_score,
        'risk_category': risk_category,
        'detections': [
            {
                'code': d.code,
                'weight': d.weight,
                'title': d.title,
                'description': d.description,
                'severity': d.severity,
            }
            for d in unique_detections
        ],
        'summary': summary,
        'is_safe_to_display': True,
        'parsed': {
            'scheme': scheme,
            'hostname': hostname,
            'tld': tld,
            'subdomain_depth': subdomain_depth,
            'url_length': url_len,
        },
    }
