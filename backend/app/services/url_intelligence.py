"""
URL Intelligence Service — Advanced static phishing URL analysis engine v2.0
===========================================================================
ZERO network requests are made to the submitted URL (SSRF prevention by design).
All analysis is purely string/regex/heuristic based.

12 detector categories, each with sub-checks:
1.  @ Symbol / User-info trick
2.  Excessive URL length
3.  IP-based hostname (IPv4 + IPv6)
4.  Subdomain depth & suspicious subdomain patterns
5.  Punycode / IDN homograph
6.  HTTP (no TLS)
7.  Suspicious TLD
8.  Credential harvesting keywords
9.  Brand impersonation heuristics
10. URL shortener / open redirector
11. URL encoding obfuscation (percent, hex, mixed)
12. Suspicious query parameters (redirect, tracking, encoded payloads)
"""

import re
import math
import unicodedata
from urllib.parse import urlparse, unquote, parse_qs
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Static reference data
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: Set[str] = {
    '.top', '.xyz', '.click', '.tk', '.ml', '.ga', '.cf', '.pw',
    '.ru', '.cn', '.info', '.biz', '.win', '.loan', '.work',
    '.date', '.review', '.stream', '.download', '.gq', '.icu',
    '.buzz', '.surf', '.monster', '.rest', '.life', '.live',
    '.shop', '.online', '.website', '.site', '.space', '.fun',
    '.club', '.vip', '.link', '.wtf', '.quest',
}

# Keywords that appear in phishing credential-capture URLs
CREDENTIAL_KEYWORDS: List[str] = [
    'login', 'signin', 'sign-in', 'sign_in', 'verify', 'verification',
    'password', 'passwd', 'credential', 'credentials', 'account',
    'secure', 'security', 'update', 'confirm', 'confirmation',
    'validate', 'activate', 'activation', 'unlock', 'recover',
    'recovery', 'restore', 'suspend', 'expire', 'expired',
    'billing', 'payment', 'checkout', 'invoice', 'wallet',
    'webscr', 'cmd=_login', 'authtoken', 'access_token',
]

# Redirect / open-redirect parameter names
REDIRECT_PARAMS: Set[str] = {
    'url', 'redirect', 'redirect_uri', 'redirect_url', 'return',
    'returnurl', 'return_url', 'next', 'continue', 'destination',
    'target', 'dest', 'goto', 'forward', 'redir', 'r', 'u', 'link',
    'out', 'jump', 'location', 'ref', 'referer', 'referrer',
}

# Suspicious query parameter names (tracking / payload delivery)
SUSPICIOUS_PARAMS: Set[str] = {
    'cmd', 'exec', 'execute', 'payload', 'base64', 'encoded',
    'script', 'eval', 'token', 'authtoken', 'access_token',
    'session', 'sid', 'uid', 'user_id', 'email', 'username',
    'pass', 'password', 'pwd', 'secret', 'key', 'apikey', 'api_key',
}

BRAND_TARGETS: List[str] = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'twitter', 'instagram', 'netflix', 'bankofamerica', 'chase',
    'wellsfargo', 'citibank', 'outlook', 'office365', 'dropbox',
    'linkedin', 'docusign', 'fedex', 'ups', 'dhl', 'irs', 'ssa',
    'steam', 'ebay', 'alibaba', 'coinbase', 'binance', 'metamask',
    'discord', 'whatsapp', 'telegram', 'adobe', 'zoom', 'dropbox',
]

# Exact official registrable domains for the brands above
BRAND_OFFICIAL_DOMAINS: Set[str] = {
    'paypal.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'netflix.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    'citibank.com', 'outlook.com', 'office.com', 'office365.com',
    'dropbox.com', 'linkedin.com', 'docusign.com', 'fedex.com',
    'ups.com', 'dhl.com', 'irs.gov', 'ssa.gov', 'steampowered.com',
    'ebay.com', 'alibaba.com', 'coinbase.com', 'binance.com',
    'discord.com', 'whatsapp.com', 'telegram.org', 'adobe.com',
    'zoom.us', 'google.co.uk', 'amazon.co.uk', 'amazon.co.in',
}

URL_SHORTENERS: Set[str] = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'rebrand.ly',
    'cutt.ly', 'short.link', 'clck.ru', 'bl.ink', 'rb.gy',
    'shorte.st', 'za.gl', 'v.gd', 'qlink.me', 'rotf.lol',
    'shrtco.de', 'tr.im', 't2m.io', 'shorturl.at',
}

# Homograph confusable characters (a sample set; real deployments use Unicode confusables DB)
HOMOGRAPH_PATTERNS = [
    # Cyrillic lookalikes
    (re.compile(r'[а-яА-ЯёЁ]'), 'Cyrillic'),
    # Greek lookalikes
    (re.compile(r'[α-ωΑ-Ω]'), 'Greek'),
    # Mixed-script detection
    (re.compile(r'[\u0400-\u04FF]'), 'Cyrillic-block'),
    (re.compile(r'[\u0370-\u03FF]'), 'Greek-block'),
    (re.compile(r'[\u4E00-\u9FFF]'), 'CJK'),
]

RISK_CATEGORIES = [
    (0,  20,  'LOW'),
    (20, 40,  'GUARDED'),
    (40, 60,  'SUSPICIOUS'),
    (60, 80,  'HIGH'),
    (80, 101, 'CRITICAL'),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    code: str
    weight: int
    title: str
    description: str
    severity: str   # INFO | LOW | MEDIUM | HIGH | CRITICAL
    evidence: str = ''


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _categorize(score: int) -> str:
    for lo, hi, cat in RISK_CATEGORIES:
        if lo <= score < hi:
            return cat
    return 'CRITICAL'


def _safe_parse(raw: str):
    """Parse URL safely; prepend https:// if scheme is missing."""
    try:
        p = urlparse(raw)
        if not p.scheme:
            p = urlparse('https://' + raw)
        return p
    except Exception:
        return None


def _registrable_domain(hostname: str) -> str:
    """Return best-effort registrable domain (last 2 parts of hostname)."""
    parts = hostname.lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname.lower()


def _subdomain_string(hostname: str) -> str:
    parts = hostname.lower().split('.')
    if len(parts) > 2:
        return '.'.join(parts[:-2])
    return ''


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in counts.values())


def _has_non_ascii(s: str) -> bool:
    return any(ord(c) > 127 for c in s)


def _detect_homograph_script(netloc: str) -> Optional[str]:
    """Return script name if non-ASCII confusables detected, else None."""
    for pattern, script_name in HOMOGRAPH_PATTERNS:
        if pattern.search(netloc):
            return script_name
    return None


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Analyze a URL for phishing indicators using static heuristics only.
    NO network requests are ever made (SSRF prevention by design).
    Returns a structured dict with risk_score, risk_category, detections, summary.
    """
    raw_url = (raw_url or '').strip()
    detections: List[Detection] = []

    # ── Empty URL ──────────────────────────────────────────────────────────
    if not raw_url:
        return _build_result(raw_url, [], None)

    # ── Parse ──────────────────────────────────────────────────────────────
    parsed = _safe_parse(raw_url)
    if not parsed or not parsed.netloc:
        detections.append(Detection(
            code='MALFORMED_URL', weight=10,
            title='Malformed URL Structure',
            description=(
                'The URL cannot be parsed into a valid structure. '
                'Malformed URLs are sometimes crafted to evade URL scanners '
                'or confuse browser parsers.'
            ),
            severity='LOW', evidence=raw_url[:120],
        ))
        return _build_result(raw_url, detections, None)

    scheme     = parsed.scheme.lower()
    netloc     = parsed.netloc.lower()
    path       = parsed.path
    query_str  = parsed.query or ''
    full_lower = raw_url.lower()
    hostname   = netloc.split(':')[0].lstrip('[').rstrip(']')
    domain_parts = hostname.split('.')
    tld = ('.' + domain_parts[-1]) if domain_parts else ''
    registrable = _registrable_domain(hostname)
    subdomain_str = _subdomain_string(hostname)
    subdomain_depth = max(0, len(domain_parts) - 2)
    url_len = len(raw_url)

    # ── DETECTOR 0: Single-label hostname (no dot = no real TLD) ───────────
    # urlparse("https://notaurl") succeeds but netloc has no dot, meaning it
    # cannot be a real public domain.  Flag it as MALFORMED before continuing.
    _ipv4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    if '.' not in hostname and not _ipv4.match(hostname) and not hostname.startswith('['):
        detections.append(Detection(
            code='MALFORMED_URL', weight=10,
            title='Malformed URL Structure',
            description=(
                'The URL hostname has no dot separator and therefore no recognisable TLD. '
                'Single-label hostnames are not valid public internet domains. '
                'Malformed URLs may be crafted to evade URL scanners or confuse browser parsers.'
            ),
            severity='LOW', evidence=hostname,
        ))
        return _build_result(raw_url, detections, parsed)

    # ── DETECTOR 1: @ symbol / user-info trick ─────────────────────────────
    if '@' in netloc:
        real_host = netloc.split('@')[-1].split(':')[0]
        fake_host = netloc.split('@')[0]
        detections.append(Detection(
            code='AT_SYMBOL_USERINFO', weight=30,
            title='@ Symbol User-Info Host Spoofing',
            description=(
                'The URL contains an @ symbol in the authority component. '
                'RFC 3986 specifies that everything before the last @ is treated as user '
                'credentials by browsers, so the REAL destination is the hostname '
                f'after the @: "{real_host}". The "{fake_host}" part before @ '
                'is merely display text — a classic phishing obfuscation trick.'
            ),
            severity='HIGH', evidence=f'netloc: {netloc}',
        ))

    # ── DETECTOR 2: Excessive URL length ──────────────────────────────────
    if url_len > 500:
        detections.append(Detection(
            code='EXCESSIVE_LENGTH', weight=20,
            title='Excessive URL Length (>500 chars)',
            description=(
                f'URL is {url_len} characters long. Legitimate URLs are rarely this '
                'long. Phishing kits use very long URLs to: (1) hide the real '
                'domain in visual truncation, (2) overflow URL display areas, '
                '(3) confuse filter regular expressions with excessive query parameters.'
            ),
            severity='MEDIUM', evidence=f'{url_len} chars',
        ))
    elif url_len > 200:
        detections.append(Detection(
            code='LONG_URL', weight=8,
            title='Unusually Long URL (>200 chars)',
            description=(
                f'URL is {url_len} characters long. While not conclusive alone, '
                'URLs above 200 characters are atypical for legitimate services '
                'and commonly used in phishing campaigns to hide the destination.'
            ),
            severity='LOW', evidence=f'{url_len} chars',
        ))

    # ── DETECTOR 3: IP-based hostname ─────────────────────────────────────
    _ipv4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    _ipv6 = re.compile(r'^\[?[0-9a-fA-F:]+\]?$')
    if _ipv4.match(hostname) or _ipv6.match(hostname):
        # Validate it's actually a valid-ish IP
        detections.append(Detection(
            code='IP_HOST', weight=30,
            title='Raw IP Address Used as Hostname',
            description=(
                f'The URL uses a raw IP address ("{hostname}") instead of a registered '
                'domain name. Legitimate public-facing services virtually never use '
                'bare IP addresses in user-facing URLs. This technique: '
                '(1) bypasses domain-reputation blacklists, '
                '(2) conceals the true operator identity, '
                '(3) prevents browser certificate name validation.'
            ),
            severity='HIGH', evidence=hostname,
        ))
    else:
        # ── DETECTOR 4: Subdomain depth & suspicious subdomain patterns ────
        if subdomain_depth >= 4:
            detections.append(Detection(
                code='EXCESSIVE_SUBDOMAINS', weight=20,
                title='Excessive Subdomain Depth (≥4 levels)',
                description=(
                    f'The URL has {subdomain_depth} subdomain levels '
                    f'(e.g. a.b.c.d.example.com). Phishing sites use deep subdomain '
                    'nesting to place legitimate-looking brand names in the early '
                    'sub-labels (e.g. paypal.secure.update.evil.com) to trick users '
                    'who only read the beginning of the URL.'
                ),
                severity='HIGH', evidence=hostname,
            ))
        elif subdomain_depth >= 2:
            detections.append(Detection(
                code='DEEP_SUBDOMAINS', weight=10,
                title='Multiple Subdomain Levels (≥2)',
                description=(
                    f'URL has {subdomain_depth} subdomain levels. '
                    'Moderate depth can be used to impersonate trusted brands '
                    'by prepending them as subdomains: "paypal.evil.com".'
                ),
                severity='LOW', evidence=hostname,
            ))

        # Suspicious subdomain keywords
        if subdomain_str:
            sub_lower = subdomain_str.lower()
            sub_cred_hits = [kw for kw in CREDENTIAL_KEYWORDS if kw in sub_lower]
            if sub_cred_hits:
                detections.append(Detection(
                    code='CREDENTIAL_KEYWORDS_IN_SUBDOMAIN', weight=20,
                    title='Credential Keywords in Subdomain',
                    description=(
                        f'The subdomain portion "{subdomain_str}" contains credential-related '
                        f'keywords: {", ".join(sub_cred_hits[:4])}. Phishing sites frequently '
                        'embed "secure", "login", "verify" etc. in subdomains to appear '
                        'legitimate (e.g. secure-login.evil.com).'
                    ),
                    severity='HIGH', evidence=subdomain_str,
                ))

    # ── DETECTOR 5: Punycode / IDN homograph ──────────────────────────────
    if 'xn--' in netloc:
        detections.append(Detection(
            code='PUNYCODE_DOMAIN', weight=25,
            title='Punycode / IDN Homograph Domain',
            description=(
                'The URL contains a Punycode-encoded internationalized domain name '
                '(indicated by the "xn--" prefix). IDN homograph attacks use Unicode '
                'characters that are visually indistinguishable from ASCII letters '
                '(e.g. Cyrillic "а" looks identical to Latin "a") to spoof trusted '
                'domains. Example: "xn--pple-43d.com" renders as "аpple.com".'
            ),
            severity='HIGH', evidence=netloc,
        ))

    # ── DETECTOR 5b: Unicode / homograph without xn-- (raw Unicode netloc) ─
    if _has_non_ascii(netloc):
        script = _detect_homograph_script(netloc)
        detections.append(Detection(
            code='UNICODE_HOMOGRAPH', weight=25,
            title='Unicode Homograph / Non-ASCII Domain Characters',
            description=(
                f'The URL contains non-ASCII characters in the domain '
                f'(detected script: {script or "unknown"}). '
                'Attackers use visually similar Unicode characters from other scripts '
                '(Cyrillic, Greek, Armenian, etc.) to create domains that look '
                'identical to legitimate ones in most fonts.'
            ),
            severity='HIGH', evidence=netloc,
        ))

    # ── DETECTOR 6: HTTP (no TLS) ─────────────────────────────────────────
    if scheme == 'http':
        detections.append(Detection(
            code='UNENCRYPTED_HTTP', weight=15,
            title='Unencrypted HTTP Protocol (No TLS)',
            description=(
                'The URL uses plain HTTP instead of HTTPS. While HTTP is not conclusive '
                'by itself, every legitimate login page, payment page, and credential form '
                'today requires HTTPS. Phishing pages sometimes use HTTP to: '
                '(1) avoid certificate authority scrutiny, '
                '(2) run on cheap infrastructure, '
                '(3) intercept credentials over public Wi-Fi.'
            ),
            severity='MEDIUM', evidence=scheme,
        ))

    # ── DETECTOR 7: Suspicious TLD ────────────────────────────────────────
    if tld.lower() in SUSPICIOUS_TLDS:
        detections.append(Detection(
            code='SUSPICIOUS_TLD', weight=18,
            title=f'High-Risk Top-Level Domain ({tld})',
            description=(
                f'The domain uses "{tld}", a TLD that appears disproportionately '
                'in phishing and malware campaigns. These TLDs are typically '
                'cheap or free to register, have minimal abuse enforcement, '
                'and are rarely used by legitimate enterprises.'
            ),
            severity='MEDIUM', evidence=tld,
        ))

    # ── DETECTOR 8: Credential harvesting keywords ────────────────────────
    # Check path + query (not just the full URL to avoid false positives from hostname)
    path_query = (path + '?' + query_str).lower()
    found_cred = [kw for kw in CREDENTIAL_KEYWORDS if kw in path_query]
    if found_cred:
        w = 25 if len(found_cred) > 1 else 15
        detections.append(Detection(
            code='CREDENTIAL_KEYWORDS', weight=w,
            title='Credential Harvesting Keywords in URL Path/Query',
            description=(
                f'The URL path or query string contains keywords strongly associated '
                f'with credential capture: {", ".join(found_cred[:6])}. '
                'Phishing kits embed these in URLs to route victims to fake '
                'login forms while appearing to reference legitimate processes.'
            ),
            severity='HIGH' if len(found_cred) > 1 else 'MEDIUM',
            evidence=', '.join(found_cred[:6]),
        ))

    # ── DETECTOR 9: Brand impersonation heuristics ────────────────────────
    for brand in BRAND_TARGETS:
        if brand in full_lower:
            # Check if the registrable domain actually belongs to the brand
            is_official = any(
                registrable == od or registrable.endswith('.' + od)
                for od in BRAND_OFFICIAL_DOMAINS
                if brand in od
            )
            if not is_official:
                detections.append(Detection(
                    code=f'BRAND_IMPERSONATION',
                    weight=28,
                    title=f'Brand Impersonation: {brand.capitalize()}',
                    description=(
                        f'The URL references "{brand}" but the registrable domain '
                        f'"{registrable}" does not match any known official '
                        f'{brand.capitalize()} domain. Attackers embed brand names in '
                        'subdomains or paths to deceive users: '
                        f'"paypal.{registrable}/login" or "{registrable}/paypal/verify".'
                    ),
                    severity='HIGH', evidence=f'brand="{brand}", domain="{registrable}"',
                ))
                break  # Only flag the first matching brand per URL

    # ── DETECTOR 10: URL shortener / open redirector ──────────────────────
    if hostname in URL_SHORTENERS:
        detections.append(Detection(
            code='URL_SHORTENER', weight=20,
            title='URL Shortener / Redirector Service',
            description=(
                f'The URL uses "{hostname}", a known URL shortening service. '
                'URL shorteners are frequently abused in phishing campaigns because: '
                '(1) they completely hide the destination from the user and email filters, '
                '(2) they can bypass link-reputation systems, '
                '(3) the short link can be re-targeted after delivery.'
            ),
            severity='MEDIUM', evidence=hostname,
        ))

    # Open redirect parameter check
    if query_str:
        try:
            params = parse_qs(query_str, keep_blank_values=True)
            redir_hits = [k for k in params if k.lower() in REDIRECT_PARAMS]
            if redir_hits:
                param_values = [params[k][0][:80] for k in redir_hits[:3]]
                detections.append(Detection(
                    code='OPEN_REDIRECT_PARAM', weight=18,
                    title='Suspicious Redirect Parameter(s) Detected',
                    description=(
                        f'The URL contains query parameters commonly used in open redirect '
                        f'attacks: {", ".join(redir_hits)}. Attackers use these to chain '
                        'a trusted domain with a malicious destination: '
                        '"trusted-site.com/login?redirect=evil.com/phish".'
                    ),
                    severity='MEDIUM',
                    evidence=f'params={redir_hits}, values≈{param_values}',
                ))

            # Suspicious param names
            sus_params = [k for k in params if k.lower() in SUSPICIOUS_PARAMS]
            if sus_params:
                detections.append(Detection(
                    code='SUSPICIOUS_QUERY_PARAMS', weight=12,
                    title='Suspicious Query Parameter Names',
                    description=(
                        f'URL contains query parameters that are unusual for normal '
                        f'web browsing: {", ".join(sus_params[:5])}. These may indicate '
                        'credential exfiltration, session hijacking, or payload delivery.'
                    ),
                    severity='LOW', evidence=', '.join(sus_params[:5]),
                ))

            # Base64-looking values in query params
            for k, vals in params.items():
                for v in vals:
                    if len(v) > 20 and re.match(r'^[A-Za-z0-9+/=_-]{20,}$', v):
                        detections.append(Detection(
                            code='ENCODED_PAYLOAD_IN_PARAM', weight=15,
                            title='Potentially Encoded Payload in Query Parameter',
                            description=(
                                f'Query parameter "{k}" contains a long alphanumeric value '
                                f'("{v[:40]}...") that resembles a Base64 or URL-safe '
                                'encoded string. Phishing kits use encoded parameters to: '
                                '(1) pass tracking tokens, '
                                '(2) encode victim email addresses, '
                                '(3) deliver obfuscated payloads.'
                            ),
                            severity='LOW', evidence=f'{k}={v[:40]}',
                        ))
                        break  # One per URL is enough
                else:
                    continue
                break
        except Exception:
            pass

    # ── DETECTOR 11: URL encoding obfuscation ─────────────────────────────
    pct_count = raw_url.count('%')
    decoded = unquote(raw_url)
    if pct_count >= 5:
        detections.append(Detection(
            code='URL_ENCODING_OBFUSCATION', weight=22,
            title='Heavy URL Percent-Encoding Obfuscation',
            description=(
                f'URL contains {pct_count} percent-encoded characters (%%xx sequences). '
                'High encoding density strongly indicates deliberate obfuscation to: '
                '(1) hide malicious keywords from string-based scanners, '
                '(2) confuse URL parsers with double-encoding, '
                '(3) disguise the true path or query parameters.'
            ),
            severity='HIGH', evidence=f'{pct_count} %xx sequences',
        ))
    elif pct_count >= 3:
        detections.append(Detection(
            code='URL_ENCODING_MODERATE', weight=10,
            title='Moderate URL Encoding Detected',
            description=(
                f'URL contains {pct_count} percent-encoded characters. '
                'While some encoding is normal (spaces, special chars), '
                '{pct_count} encoded sequences in a suspicious URL context '
                'may indicate filter evasion.'
            ),
            severity='LOW', evidence=f'{pct_count} %xx sequences',
        ))

    # Hex encoding detection (\\x sequences or &#x; HTML entities in URL)
    if re.search(r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}', raw_url):
        detections.append(Detection(
            code='MULTI_ENCODING_CHAIN', weight=20,
            title='Multi-Level Encoding Chain Detected',
            description=(
                'URL contains sequences of consecutive percent-encoded characters '
                '(triple-encoding). This is virtually never seen in legitimate URLs '
                'and strongly indicates deliberate scanner evasion.'
            ),
            severity='HIGH', evidence='consecutive %xx%xx%xx sequences',
        ))

    # ── DETECTOR 12: High-entropy / DGA subdomain ─────────────────────────
    if subdomain_str and len(subdomain_str) > 8 and not hostname in URL_SHORTENERS:
        entropy = _shannon_entropy(subdomain_str)
        if entropy > 3.9:
            detections.append(Detection(
                code='HIGH_ENTROPY_SUBDOMAIN', weight=15,
                title='High-Entropy / DGA-Like Subdomain',
                description=(
                    f'The subdomain "{subdomain_str[:35]}" has Shannon entropy of '
                    f'{entropy:.2f} bits, suggesting it is algorithmically generated '
                    '(DGA — Domain Generation Algorithm). DGA domains are characteristic '
                    'of malware command-and-control infrastructure and some phishing kits '
                    'that rotate domains automatically.'
                ),
                severity='MEDIUM', evidence=f'entropy={entropy:.2f}',
            ))

    # ── Deduplicate by code ────────────────────────────────────────────────
    seen: Set[str] = set()
    unique: List[Detection] = []
    for d in detections:
        if d.code not in seen:
            seen.add(d.code)
            unique.append(d)

    return _build_result(raw_url, unique, {
        'scheme': scheme,
        'hostname': hostname,
        'registrable_domain': registrable,
        'tld': tld,
        'subdomain_depth': subdomain_depth,
        'url_length': url_len,
        'has_query': bool(query_str),
        'query_param_count': len(parse_qs(query_str)) if query_str else 0,
    })


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def _build_result(url: str, detections: List[Detection], parsed_info: Optional[Dict]) -> Dict[str, Any]:
    score = min(100, sum(d.weight for d in detections))
    category = _categorize(score)
    n = len(detections)

    if n == 0:
        summary = (
            'No significant phishing indicators detected in this URL. '
            'Static analysis found no suspicious patterns. '
            'Exercise normal caution when visiting any unknown link.'
        )
    elif score < 20:
        summary = f'Very low risk. {n} minor signal(s) detected — likely benign.'
    elif score < 40:
        summary = f'Low-to-moderate risk. {n} signal(s) detected. Verify before clicking.'
    elif score < 60:
        summary = (
            f'Moderate phishing risk — {n} indicator(s) found. '
            'Treat with caution; do not enter credentials.'
        )
    elif score < 80:
        summary = (
            f'High phishing risk — {n} indicator(s) found. '
            'Strong evidence of malicious intent. Do not visit.'
        )
    else:
        summary = (
            f'CRITICAL — {n} indicator(s). Multiple strong phishing signals. '
            'This URL exhibits hallmarks of an active phishing or malware campaign.'
        )

    return {
        'url': url,
        'risk_score': score,
        'risk_category': category,
        'detections': [
            {
                'code': d.code,
                'weight': d.weight,
                'title': d.title,
                'description': d.description,
                'severity': d.severity,
                'evidence': d.evidence,
            }
            for d in detections
        ],
        'summary': summary,
        'is_safe_to_display': True,
        'parsed': parsed_info,
        'detector_version': '2.0',
    }
