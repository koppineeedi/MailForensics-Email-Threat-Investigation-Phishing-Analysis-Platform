"""
Standalone test runner for URL Intelligence engine.
Runs WITHOUT SQLAlchemy/FastAPI (pure Python only) to avoid DLL issues.
Execute: python tests/run_url_intelligence_tests.py
"""
import sys
import os
# Force UTF-8 output on Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.url_intelligence import analyze_url

PASS = "[PASS]"
FAIL = "[FAIL]"

results = []

def test(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append(condition)
    print(f"  [{status}] {name}" + (f" â€” {detail}" if detail else ""))
    return condition

def get_codes(r):
    return [d["code"] for d in r["detections"]]

print("\n=== URL Intelligence Engine v2.0 â€” Test Suite ===\n")

# â”€â”€ 1. Edge cases â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("1. Edge Cases")
r = analyze_url("")
test("Empty URL â†’ score=0, no detections", r["risk_score"] == 0 and r["detections"] == [])

r = analyze_url("   ")
test("Whitespace-only URL â†’ score=0", r["risk_score"] == 0)

r = analyze_url("notaurl")
test("No-TLD URL â†’ MALFORMED_URL flagged", "MALFORMED_URL" in get_codes(r))

r = analyze_url("https://www.google.com/search?q=test")
codes = get_codes(r)
test("Clean Google URL â†’ no IP/punycode/shortener flags",
     "IP_HOST" not in codes and "PUNYCODE_DOMAIN" not in codes and "URL_SHORTENER" not in codes)
test("Clean Google URL â†’ score < 40", r["risk_score"] < 40)

# â”€â”€ 2. @ symbol â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n2. @ Symbol / User-Info")
r = analyze_url("http://paypal.com@evil.com/phish")
test("@ in netloc â†’ AT_SYMBOL_USERINFO", "AT_SYMBOL_USERINFO" in get_codes(r))
test("@ attack â†’ score â‰¥ 30", r["risk_score"] >= 30)

r = analyze_url("https://example.com/api?email=user@domain.com")
test("@ in query string (email param) â†’ no AT flag", "AT_SYMBOL_USERINFO" not in get_codes(r))

# â”€â”€ 3. IP-based hostname â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n3. IP-Based Hostname")
r = analyze_url("http://192.168.1.100/login")
test("IPv4 host â†’ IP_HOST flagged", "IP_HOST" in get_codes(r))
test("IPv4 â†’ score â‰¥ 30", r["risk_score"] >= 30)

r = analyze_url("https://203.0.113.5/verify")
test("Public IPv4 â†’ IP_HOST flagged", "IP_HOST" in get_codes(r))

r = analyze_url("https://example.com/page")
test("Domain URL â†’ not flagged as IP", "IP_HOST" not in get_codes(r))

r = analyze_url("http://198.51.100.25/login/verify?password=reset")
test("IP + HTTP + credential keywords â†’ score â‰¥ 60", r["risk_score"] >= 60)

# â”€â”€ 4. Subdomain depth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n4. Subdomain Depth")
r = analyze_url("https://paypal.secure.update.accounts.evil.com/login")
codes = get_codes(r)
test("4-level subdomain â†’ EXCESSIVE or DEEP flag",
     "EXCESSIVE_SUBDOMAINS" in codes or "DEEP_SUBDOMAINS" in codes)

r = analyze_url("https://www.example.com/page")
test("www.example.com â†’ no excessive subdomain", "EXCESSIVE_SUBDOMAINS" not in get_codes(r))

r = analyze_url("https://secure-login.evil.com/account")
codes = get_codes(r)
test("Credential keyword in subdomain flagged",
     "CREDENTIAL_KEYWORDS_IN_SUBDOMAIN" in codes or "CREDENTIAL_KEYWORDS" in codes)

# â”€â”€ 5. Punycode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n5. Punycode / IDN Homograph")
r = analyze_url("https://xn--pple-43d.com/login")
test("Punycode domain â†’ PUNYCODE_DOMAIN", "PUNYCODE_DOMAIN" in get_codes(r))
test("Punycode â†’ score â‰¥ 25", r["risk_score"] >= 25)

r = analyze_url("http://xn--pypl-poad.com/verify?password=reset")
test("Punycode + HTTP + credential â†’ score â‰¥ 50", r["risk_score"] >= 50)

r = analyze_url("https://paypal.com/pay")
test("Legitimate paypal.com â†’ no punycode flag", "PUNYCODE_DOMAIN" not in get_codes(r))

# â”€â”€ 6. HTTP detector â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n6. HTTP (No TLS)")
r = analyze_url("http://example.com/page")
test("HTTP URL â†’ UNENCRYPTED_HTTP flagged", "UNENCRYPTED_HTTP" in get_codes(r))

r = analyze_url("https://example.com/page")
test("HTTPS URL â†’ no HTTP flag", "UNENCRYPTED_HTTP" not in get_codes(r))

# â”€â”€ 7. Suspicious TLD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n7. Suspicious TLD")
r = analyze_url("https://phishing-site.top/verify")
test(".top TLD â†’ SUSPICIOUS_TLD", "SUSPICIOUS_TLD" in get_codes(r))

r = analyze_url("https://malware-payload.xyz/download")
test(".xyz TLD â†’ SUSPICIOUS_TLD", "SUSPICIOUS_TLD" in get_codes(r))

r = analyze_url("https://example.com/page")
test(".com â†’ not flagged", "SUSPICIOUS_TLD" not in get_codes(r))

r = analyze_url("https://nonprofitorg.org/donate")
test(".org â†’ not flagged", "SUSPICIOUS_TLD" not in get_codes(r))

# â”€â”€ 8. Credential keywords â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n8. Credential Harvesting Keywords")
r = analyze_url("https://evil.com/login/verify")
test("login+verify in path â†’ CREDENTIAL_KEYWORDS", "CREDENTIAL_KEYWORDS" in get_codes(r))

r1 = analyze_url("https://evil.com/login")
r2 = analyze_url("https://evil.com/login/verify/password")
test("More keywords â†’ higher score", r2["risk_score"] >= r1["risk_score"])

r = analyze_url("https://example.com/products/shoes")
test("Clean path â†’ no credential flag", "CREDENTIAL_KEYWORDS" not in get_codes(r))

# â”€â”€ 9. Brand impersonation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n9. Brand Impersonation")
r = analyze_url("https://paypal.secure-verify.com/account/login")
test("paypal in subdomain of non-paypal.com â†’ flagged", "BRAND_IMPERSONATION" in get_codes(r))

r = analyze_url("https://evil.com/amazon/login")
test("amazon in path of evil.com â†’ flagged", "BRAND_IMPERSONATION" in get_codes(r))

r = analyze_url("https://www.paypal.com/signin")
test("Official paypal.com â†’ not flagged", "BRAND_IMPERSONATION" not in get_codes(r))

r = analyze_url("https://accounts.google.com/signin")
test("Official google.com â†’ not flagged", "BRAND_IMPERSONATION" not in get_codes(r))

# â”€â”€ 10. URL shorteners â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n10. URL Shorteners")
r = analyze_url("https://bit.ly/3xAbc12")
test("bit.ly â†’ URL_SHORTENER", "URL_SHORTENER" in get_codes(r))

r = analyze_url("https://tinyurl.com/phishing")
test("tinyurl.com â†’ URL_SHORTENER", "URL_SHORTENER" in get_codes(r))

r = analyze_url("https://www.example.com/long/path")
test("Full domain â†’ no shortener flag", "URL_SHORTENER" not in get_codes(r))

# â”€â”€ 11. URL encoding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n11. URL Encoding Obfuscation")
r = analyze_url("http://evil.com/%6C%6F%67%69%6E/%76%65%72%69%66%79")
codes = get_codes(r)
test("Heavy %xx encoding â†’ obfuscation flag",
     "URL_ENCODING_OBFUSCATION" in codes or "URL_ENCODING_MODERATE" in codes)

r = analyze_url("https://example.com/search?q=hello%20world")
test("Single %20 â†’ no heavy encoding flag", "URL_ENCODING_OBFUSCATION" not in get_codes(r))

# â”€â”€ 12. Redirect / query params â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n12. Redirect & Query Parameters")
r = analyze_url("https://example.com/login?redirect=http://evil.com")
test("?redirect= param â†’ OPEN_REDIRECT_PARAM", "OPEN_REDIRECT_PARAM" in get_codes(r))

r = analyze_url("https://trusted.com/auth?next=//evil.com/phish")
test("?next= param â†’ OPEN_REDIRECT_PARAM", "OPEN_REDIRECT_PARAM" in get_codes(r))

r = analyze_url("https://example.com/search?q=shoes&page=2")
test("Normal params â†’ no redirect flag", "OPEN_REDIRECT_PARAM" not in get_codes(r))

r = analyze_url("https://example.com/api?cmd=exec&payload=base64data")
codes = get_codes(r)
test("?cmd=exec&payload= â†’ SUSPICIOUS_QUERY_PARAMS", "SUSPICIOUS_QUERY_PARAMS" in codes)

# â”€â”€ 13. Scoring correctness â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n13. Risk Scoring")
r = analyze_url("http://xn--pple-43d.top/paypal/login/verify?redirect=http://evil.com&password=abc" + "a"*300)
test("Score always â‰¤ 100", r["risk_score"] <= 100)

r_low  = analyze_url("https://example.com/page")
r_high = analyze_url("http://paypal.secure.evil.top/login/verify")
test("More signals â†’ higher score", r_high["risk_score"] > r_low["risk_score"])

r = analyze_url("https://example.com")
test("Clean URL â†’ LOW category", r["risk_category"] == "LOW")

r = analyze_url("http://192.168.0.1/paypal/login/verify/password/confirm")
test("IP+HTTP+brand+credentials â†’ HIGH or CRITICAL",
     r["risk_category"] in ("HIGH", "CRITICAL"))

r = analyze_url("https://example.com")
for field in ("url","risk_score","risk_category","detections","summary","is_safe_to_display"):
    test(f"Result has '{field}' field", field in r)

r = analyze_url("https://example.com")
test("detector_version == '2.0'", r.get("detector_version") == "2.0")

# â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
passed = sum(results)
total  = len(results)
failed = total - passed

print(f"\n{'='*50}")
print(f"Results: {passed}/{total} passed", end="")
if failed:
    print(f"  ({failed} FAILED)", end="")
print()

if failed:
    sys.exit(1)

