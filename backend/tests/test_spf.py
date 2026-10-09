from app.services.spf_analyzer import parse_spf

def test_spf_pass_parsing():
    headers = [
        {"header_name": "Received-SPF", "header_value": "pass (domain of test.lab designates 192.168.1.1 as permitted sender)"}
    ]
    res, findings = parse_spf(headers, "test.lab")
    assert res["spf_result"] == "PASS"
    assert res["spf_domain"] == "test.lab"
    assert len(findings) == 0

def test_spf_fail_parsing():
    headers = [
        {"header_name": "Received-SPF", "header_value": "fail (domain of test.lab does not designate 192.168.1.1)"}
    ]
    res, findings = parse_spf(headers, "test.lab")
    assert res["spf_result"] == "FAIL"
    assert len(findings) == 1
    assert findings[0]["finding_code"] == "SPF_FAILURE"
