"""
Tests for URL Intelligence Engine v2.0
Covers all 12 detector categories with positive and negative cases.
"""
import pytest
from app.services.url_intelligence import analyze_url


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def get_codes(result: dict) -> list:
    return [d["code"] for d in result["detections"]]


def get_score(result: dict) -> int:
    return result["risk_score"]


def get_cat(result: dict) -> str:
    return result["risk_category"]


# ---------------------------------------------------------------------------
# 1. Empty / malformed URLs
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_url_returns_zero_score(self):
        r = analyze_url("")
        assert r["risk_score"] == 0
        assert r["risk_category"] == "LOW"
        assert r["detections"] == []

    def test_whitespace_only_url(self):
        r = analyze_url("   ")
        assert r["risk_score"] == 0

    def test_malformed_no_tld(self):
        r = analyze_url("notaurl")
        assert "MALFORMED_URL" in get_codes(r)

    def test_safe_https_domain(self):
        r = analyze_url("https://www.google.com/search?q=test")
        # Should not be flagged for IP, punycode, shortener, etc.
        codes = get_codes(r)
        assert "IP_HOST" not in codes
        assert "PUNYCODE_DOMAIN" not in codes
        assert "URL_SHORTENER" not in codes
        assert get_score(r) < 40


# ---------------------------------------------------------------------------
# 2. @ symbol / user-info
# ---------------------------------------------------------------------------

class TestAtSymbolDetector:
    def test_at_symbol_in_host_flagged(self):
        r = analyze_url("http://paypal.com@evil.com/phish")
        assert "AT_SYMBOL_USERINFO" in get_codes(r)
        assert get_score(r) >= 30

    def test_at_in_path_not_flagged(self):
        # @ in path/query is legitimate (email addresses)
        r = analyze_url("https://example.com/api?email=user@domain.com")
        assert "AT_SYMBOL_USERINFO" not in get_codes(r)


# ---------------------------------------------------------------------------
# 3. IP-based hostname
# ---------------------------------------------------------------------------

class TestIPHostDetector:
    def test_ipv4_flagged(self):
        r = analyze_url("http://192.168.1.100/login")
        assert "IP_HOST" in get_codes(r)
        assert get_score(r) >= 30

    def test_public_ipv4_flagged(self):
        r = analyze_url("https://203.0.113.5/verify")
        assert "IP_HOST" in get_codes(r)

    def test_valid_domain_not_flagged_as_ip(self):
        r = analyze_url("https://example.com/page")
        assert "IP_HOST" not in get_codes(r)

    def test_ip_with_credentials_is_critical(self):
        r = analyze_url("http://198.51.100.25/login/verify?password=reset")
        assert "IP_HOST" in get_codes(r)
        assert get_score(r) >= 60  # IP + HTTP + credential keywords


# ---------------------------------------------------------------------------
# 4. Subdomain depth
# ---------------------------------------------------------------------------

class TestSubdomainDetector:
    def test_excessive_depth_flagged(self):
        r = analyze_url("https://paypal.secure.update.accounts.evil.com/login")
        assert "EXCESSIVE_SUBDOMAINS" in get_codes(r) or "DEEP_SUBDOMAINS" in get_codes(r)

    def test_normal_subdomain_not_excessive(self):
        r = analyze_url("https://www.example.com/page")
        assert "EXCESSIVE_SUBDOMAINS" not in get_codes(r)

    def test_credential_keyword_in_subdomain_flagged(self):
        r = analyze_url("https://secure-login.evil.com/account")
        codes = get_codes(r)
        assert "CREDENTIAL_KEYWORDS_IN_SUBDOMAIN" in codes or "CREDENTIAL_KEYWORDS" in codes


# ---------------------------------------------------------------------------
# 5. Punycode / IDN homograph
# ---------------------------------------------------------------------------

class TestPunycodeDetector:
    def test_punycode_domain_flagged(self):
        r = analyze_url("https://xn--pple-43d.com/login")
        assert "PUNYCODE_DOMAIN" in get_codes(r)
        assert get_score(r) >= 25

    def test_punycode_with_credentials_high_risk(self):
        r = analyze_url("http://xn--pypl-poad.com/verify?password=reset")
        assert "PUNYCODE_DOMAIN" in get_codes(r)
        assert get_score(r) >= 50

    def test_clean_domain_no_punycode(self):
        r = analyze_url("https://paypal.com/pay")
        assert "PUNYCODE_DOMAIN" not in get_codes(r)


# ---------------------------------------------------------------------------
# 6. HTTP (no TLS)
# ---------------------------------------------------------------------------

class TestHTTPDetector:
    def test_http_flagged(self):
        r = analyze_url("http://example.com/page")
        assert "UNENCRYPTED_HTTP" in get_codes(r)

    def test_https_not_flagged(self):
        r = analyze_url("https://example.com/page")
        assert "UNENCRYPTED_HTTP" not in get_codes(r)


# ---------------------------------------------------------------------------
# 7. Suspicious TLD
# ---------------------------------------------------------------------------

class TestSuspiciousTLDDetector:
    def test_top_tld_flagged(self):
        r = analyze_url("https://phishing-site.top/verify")
        assert "SUSPICIOUS_TLD" in get_codes(r)

    def test_xyz_tld_flagged(self):
        r = analyze_url("https://malware-payload.xyz/download")
        assert "SUSPICIOUS_TLD" in get_codes(r)

    def test_com_not_flagged(self):
        r = analyze_url("https://example.com/page")
        assert "SUSPICIOUS_TLD" not in get_codes(r)

    def test_org_not_flagged(self):
        r = analyze_url("https://nonprofitorg.org/donate")
        assert "SUSPICIOUS_TLD" not in get_codes(r)


# ---------------------------------------------------------------------------
# 8. Credential harvesting keywords
# ---------------------------------------------------------------------------

class TestCredentialKeywords:
    def test_login_in_path(self):
        r = analyze_url("https://evil.com/login/verify")
        assert "CREDENTIAL_KEYWORDS" in get_codes(r)

    def test_multiple_keywords_higher_weight(self):
        r1 = analyze_url("https://evil.com/login")
        r2 = analyze_url("https://evil.com/login/verify/password")
        assert get_score(r2) >= get_score(r1)

    def test_clean_path_no_credential_flag(self):
        r = analyze_url("https://example.com/products/shoes")
        assert "CREDENTIAL_KEYWORDS" not in get_codes(r)


# ---------------------------------------------------------------------------
# 9. Brand impersonation
# ---------------------------------------------------------------------------

class TestBrandImpersonation:
    def test_paypal_in_subdomain_flagged(self):
        r = analyze_url("https://paypal.secure-verify.com/account/login")
        assert "BRAND_IMPERSONATION" in get_codes(r)

    def test_amazon_in_path_non_official_domain(self):
        r = analyze_url("https://evil.com/amazon/login")
        assert "BRAND_IMPERSONATION" in get_codes(r)

    def test_official_paypal_not_flagged(self):
        r = analyze_url("https://www.paypal.com/signin")
        assert "BRAND_IMPERSONATION" not in get_codes(r)

    def test_official_google_not_flagged(self):
        r = analyze_url("https://accounts.google.com/signin")
        assert "BRAND_IMPERSONATION" not in get_codes(r)


# ---------------------------------------------------------------------------
# 10. URL shorteners
# ---------------------------------------------------------------------------

class TestURLShorteners:
    def test_bitly_flagged(self):
        r = analyze_url("https://bit.ly/3xAbc12")
        assert "URL_SHORTENER" in get_codes(r)

    def test_tinyurl_flagged(self):
        r = analyze_url("https://tinyurl.com/phishing")
        assert "URL_SHORTENER" in get_codes(r)

    def test_full_domain_not_flagged(self):
        r = analyze_url("https://www.example.com/long/path")
        assert "URL_SHORTENER" not in get_codes(r)


# ---------------------------------------------------------------------------
# 11. URL encoding obfuscation
# ---------------------------------------------------------------------------

class TestURLEncoding:
    def test_heavy_encoding_flagged(self):
        r = analyze_url("http://evil.com/%6C%6F%67%69%6E/%76%65%72%69%66%79")
        assert "URL_ENCODING_OBFUSCATION" in get_codes(r) or "URL_ENCODING_MODERATE" in get_codes(r)

    def test_triple_encoding_flagged(self):
        r = analyze_url("https://evil.com/%25%36%43%25%36%46%25%36%37%25%36%39%25%36%45")
        codes = get_codes(r)
        assert "MULTI_ENCODING_CHAIN" in codes or "URL_ENCODING_OBFUSCATION" in codes

    def test_normal_encoding_not_flagged_harshly(self):
        # Single space encoding (%20) is totally normal
        r = analyze_url("https://example.com/search?q=hello%20world")
        # Should not hit heavy encoding threshold
        assert "URL_ENCODING_OBFUSCATION" not in get_codes(r)


# ---------------------------------------------------------------------------
# 12. Redirect / query parameter detection
# ---------------------------------------------------------------------------

class TestQueryParameters:
    def test_redirect_param_flagged(self):
        r = analyze_url("https://example.com/login?redirect=http://evil.com")
        assert "OPEN_REDIRECT_PARAM" in get_codes(r)

    def test_next_param_flagged(self):
        r = analyze_url("https://trusted.com/auth?next=//evil.com/phish")
        assert "OPEN_REDIRECT_PARAM" in get_codes(r)

    def test_no_redirect_param_not_flagged(self):
        r = analyze_url("https://example.com/search?q=shoes&page=2")
        assert "OPEN_REDIRECT_PARAM" not in get_codes(r)

    def test_suspicious_param_names(self):
        r = analyze_url("https://example.com/api?cmd=exec&payload=base64data")
        codes = get_codes(r)
        assert "SUSPICIOUS_QUERY_PARAMS" in codes


# ---------------------------------------------------------------------------
# 13. Risk scoring correctness
# ---------------------------------------------------------------------------

class TestRiskScoring:
    def test_score_capped_at_100(self):
        # Pile on every indicator
        r = analyze_url(
            "http://xn--pple-43d.top/paypal/login/verify?"
            "redirect=http://evil.com&password=abc"
            "&" + "a" * 300
        )
        assert r["risk_score"] <= 100

    def test_score_increases_with_more_indicators(self):
        r_low  = analyze_url("https://example.com/page")
        r_high = analyze_url("http://paypal.secure.evil.top/login/verify")
        assert get_score(r_high) > get_score(r_low)

    def test_low_risk_category_mapping(self):
        r = analyze_url("https://example.com")
        assert get_cat(r) == "LOW"

    def test_critical_category_for_multiple_signals(self):
        r = analyze_url(
            "http://192.168.0.1/paypal/login/verify/password/confirm"
        )
        # IP + HTTP + brand + credential keywords → should be HIGH or CRITICAL
        assert get_cat(r) in ("HIGH", "CRITICAL")

    def test_result_has_required_fields(self):
        r = analyze_url("https://example.com")
        for field in ("url", "risk_score", "risk_category", "detections", "summary", "is_safe_to_display"):
            assert field in r

    def test_detector_version_present(self):
        r = analyze_url("https://example.com")
        assert r.get("detector_version") == "2.0"
