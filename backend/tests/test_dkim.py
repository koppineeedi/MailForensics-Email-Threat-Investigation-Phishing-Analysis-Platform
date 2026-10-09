from app.services.dkim_analyzer import parse_dkim

def test_dkim_auth_results_parsing():
    headers = [
        {"header_name": "DKIM-Signature", "header_value": "v=1; a=rsa-sha256; d=example.com; s=s1;"},
        {"header_name": "Authentication-Results", "header_value": "mx.google.com; dkim=pass header.i=@example.com"}
    ]
    res, findings = parse_dkim(headers, None, "example.com")
    assert res["dkim_result"] == "PASS"
    assert res["dkim_domain"] == "example.com"
    assert res["dkim_selector"] == "s1"
    assert res["dkim_alignment"] is True
