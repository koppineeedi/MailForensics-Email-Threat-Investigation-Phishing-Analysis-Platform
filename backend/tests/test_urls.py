from app.services.url_extractor import extract_urls

def test_url_extraction_and_indicators():
    plain_text = "Please check http://192.168.1.50/login/verify or https://malicious-site.top/verify_account"
    html_text = '<a href="http://10.0.0.1/auth">Click here to confirm password</a>'

    urls, findings = extract_urls(plain_text, html_text, [])
    assert len(urls) >= 2

    codes = [f["finding_code"] for f in findings]
    assert "IP_BASED_URL" in codes
    assert "SUSPICIOUS_TLD_URL" in codes
    assert "UNENCRYPTED_HTTP_URL" in codes
    assert "CREDENTIAL_KEYWORD_URL" in codes
