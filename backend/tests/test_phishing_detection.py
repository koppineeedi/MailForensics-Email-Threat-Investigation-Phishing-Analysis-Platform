from app.services.phishing_detector import run_phishing_detection_rules

def test_phishing_rules_consolidation():
    h_find = [{"finding_code": "REPLY_TO_MISMATCH", "category": "HEADER_ANALYSIS", "severity": "SUSPICIOUS", "confidence": 0.9, "evidence": "e", "explanation": "x", "source": "s"}]
    body_p = "URGENT: Please verify your password and confirm your account within 24 hours!"
    
    findings = run_phishing_detection_rules(h_find, [], [], [], [], [], [], [], body_p, "")
    codes = [f["finding_code"] for f in findings]
    assert "REPLY_TO_MISMATCH" in codes
    assert "URGENT_LANGUAGE_INDICATOR" in codes
    assert "CREDENTIAL_REQUEST_INDICATOR" in codes
