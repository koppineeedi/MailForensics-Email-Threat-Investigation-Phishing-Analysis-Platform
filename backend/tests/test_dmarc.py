from app.services.dmarc_analyzer import parse_dmarc

def test_dmarc_pass():
    headers = [
        {"header_name": "Authentication-Results", "header_value": "mx.google.com; dmarc=pass action=none header.from=target.com"}
    ]
    res, findings = parse_dmarc(headers, "target.com", "PASS", "target.com", "PASS", True)
    assert res["dmarc_result"] == "PASS"
    assert len(findings) == 0

def test_dmarc_fail():
    headers = [
        {"header_name": "Authentication-Results", "header_value": "mx.google.com; dmarc=fail action=quarantine header.from=target.com"}
    ]
    res, findings = parse_dmarc(headers, "target.com", "FAIL", "other.com", "FAIL", False)
    assert res["dmarc_result"] == "FAIL"
    assert len(findings) == 1
    assert findings[0]["finding_code"] == "DMARC_FAILURE"
