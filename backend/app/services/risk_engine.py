from typing import List, Dict, Any, Tuple

WEIGHT_TABLE = {
    "DMARC_FAILURE": {"weight": 25.0, "factor": "DMARC Authentication Failure"},
    "SPF_FAILURE": {"weight": 20.0, "factor": "SPF Authentication Failure"},
    "DKIM_FAILURE": {"weight": 20.0, "factor": "DKIM Authentication Failure"},
    "LOOKALIKE_DOMAIN": {"weight": 25.0, "factor": "Spoofed/Lookalike Domain Detected"},
    "PUNYCODE_DOMAIN": {"weight": 15.0, "factor": "Punycode Domain Indicator"},
    "REPLY_TO_MISMATCH": {"weight": 15.0, "factor": "From vs Reply-To Address Mismatch"},
    "RETURN_PATH_MISMATCH": {"weight": 10.0, "factor": "From vs Return-Path Mismatch"},
    "IP_BASED_URL": {"weight": 20.0, "factor": "Raw IP Address Host URL"},
    "SUSPICIOUS_ATTACHMENT": {"weight": 30.0, "factor": "Executable Attachment Payload"},
    "ARCHIVE_BOMB_INDICATOR": {"weight": 40.0, "factor": "Archive Bomb / Compression Anomaly"},
    "SUSPICIOUS_TLD_URL": {"weight": 10.0, "factor": "Suspicious TLD Host URL"},
    "CREDENTIAL_REQUEST_INDICATOR": {"weight": 10.0, "factor": "Credential Request Text Heuristic"},
    "URGENT_LANGUAGE_INDICATOR": {"weight": 5.0, "factor": "Urgent Language Text Heuristic"},
    "SUSPICIOUS_RECEIVED_CHAIN": {"weight": 10.0, "factor": "Received Chain Anomaly"},
    "MISSING_AUTHENTICATION_HEADERS": {"weight": 15.0, "factor": "Missing Authentication Headers"}
}

def calculate_risk_score(findings: List[Dict[str, Any]]) -> Tuple[float, str, List[Dict[str, Any]]]:
    """
    Explainable Risk Engine producing 0-100 score and explicit breakdown of evidence factors.
    """
    total_score = 0.0
    factors = []
    seen_codes = set()

    for f in findings:
        code = f.get("finding_code")
        if not code or code in seen_codes:
            continue
        seen_codes.add(code)

        rule = WEIGHT_TABLE.get(code)
        if rule:
            weight = rule["weight"]
            evidence = f.get("evidence", "Observed finding")
            confidence = f.get("confidence", 1.0)
            contribution = round(weight * confidence, 1)
            total_score += contribution
            factors.append({
                "factor": rule["factor"],
                "evidence": evidence,
                "weight": weight,
                "contribution": contribution
            })

    # Clamp total score to 0 - 100
    risk_score = min(100.0, round(total_score, 1))

    # Category Mapping
    if risk_score <= 19.0:
        category = "LOW"
    elif risk_score <= 39.0:
        category = "GUARDED"
    elif risk_score <= 59.0:
        category = "SUSPICIOUS"
    elif risk_score <= 79.0:
        category = "HIGH"
    else:
        category = "CRITICAL"

    return risk_score, category, factors
