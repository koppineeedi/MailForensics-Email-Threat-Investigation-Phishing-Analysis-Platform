from app.services.risk_engine import calculate_risk_score

def test_risk_score_calculation():
    findings = [
        {"finding_code": "DMARC_FAILURE", "evidence": "DMARC fail", "confidence": 1.0},
        {"finding_code": "SPF_FAILURE", "evidence": "SPF fail", "confidence": 1.0},
        {"finding_code": "SUSPICIOUS_ATTACHMENT", "evidence": ".exe file", "confidence": 1.0}
    ]

    score, category, factors = calculate_risk_score(findings)
    # DMARC_FAILURE (25) + SPF_FAILURE (20) + SUSPICIOUS_ATTACHMENT (30) = 75
    assert score == 75.0
    assert category == "HIGH"
    assert len(factors) == 3
