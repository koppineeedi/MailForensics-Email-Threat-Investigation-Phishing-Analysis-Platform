from app.services.header_analyzer import analyze_headers

def test_header_analyzer_mismatches():
    from_p = [{"domain": "legitimate.com", "normalized_address": "user@legitimate.com", "display_name": "User", "raw_address": "user@legitimate.com"}]
    reply_p = [{"domain": "attacker.com", "normalized_address": "collector@attacker.com", "display_name": "Collector", "raw_address": "collector@attacker.com"}]
    return_p = [{"domain": "relay.com", "normalized_address": "bounce@relay.com", "display_name": None, "raw_address": "bounce@relay.com"}]

    headers = [
        {"header_name": "From", "header_value": "user@legitimate.com"},
        {"header_name": "Reply-To", "header_value": "collector@attacker.com"}
    ]

    findings = analyze_headers(headers, from_p, reply_p, return_p, "<msg123@legitimate.com>")
    codes = [f["finding_code"] for f in findings]

    assert "REPLY_TO_MISMATCH" in codes
    assert "RETURN_PATH_MISMATCH" in codes
