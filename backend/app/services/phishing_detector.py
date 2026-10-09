import re
from typing import List, Dict, Any

URGENT_KEYWORDS = [
    "urgent", "action required", "immediate action", "account suspended",
    "unauthorized login", "security breach", "final notice", "wire transfer",
    "expire today", "within 24 hours"
]

CREDENTIAL_REQUEST_KEYWORDS = [
    "verify your password", "confirm your account", "update billing information",
    "enter your credentials", "re-authenticate", "login to restore access"
]

def run_phishing_detection_rules(
    header_findings: List[Dict[str, Any]],
    domain_findings: List[Dict[str, Any]],
    url_findings: List[Dict[str, Any]],
    attachment_findings: List[Dict[str, Any]],
    received_findings: List[Dict[str, Any]],
    spf_findings: List[Dict[str, Any]],
    dkim_findings: List[Dict[str, Any]],
    dmarc_findings: List[Dict[str, Any]],
    body_plain: str,
    body_html: str
) -> List[Dict[str, Any]]:
    """
    Rule-based defensive phishing indicator detection engine.
    Aggregates findings from sub-analyzers and evaluates body text heuristics.
    """
    all_findings = []

    # Combine sub-analyzer findings
    all_findings.extend(header_findings)
    all_findings.extend(domain_findings)
    all_findings.extend(url_findings)
    all_findings.extend(attachment_findings)
    all_findings.extend(received_findings)
    all_findings.extend(spf_findings)
    all_findings.extend(dkim_findings)
    all_findings.extend(dmarc_findings)

    # Content Heuristics (Urgency & Credential Requests)
    full_text = (body_plain + " " + body_html).lower()

    # 1. Urgent Language Heuristic
    found_urgent = [kw for kw in URGENT_KEYWORDS if kw in full_text]
    if found_urgent:
        all_findings.append({
            "finding_code": "URGENT_LANGUAGE_INDICATOR",
            "category": "CONTENT_HEURISTICS",
            "severity": "GUARDED",
            "confidence": 0.70,
            "evidence": f"Matched urgency keywords: {', '.join(found_urgent[:3])}",
            "explanation": "[HEURISTIC INDICATOR] Message contains high-urgency or coercive language commonly observed in social engineering. Does not prove malicious intent.",
            "source": "PHISHING_DETECTOR"
        })

    # 2. Credential Request Heuristic
    found_cred_req = [kw for kw in CREDENTIAL_REQUEST_KEYWORDS if kw in full_text]
    if found_cred_req:
        all_findings.append({
            "finding_code": "CREDENTIAL_REQUEST_INDICATOR",
            "category": "CONTENT_HEURISTICS",
            "severity": "SUSPICIOUS",
            "confidence": 0.75,
            "evidence": f"Matched credential request phrases: {', '.join(found_cred_req[:3])}",
            "explanation": "[HEURISTIC INDICATOR] Message explicitly requests identity verification or credential entry. Does not prove malicious intent.",
            "source": "PHISHING_DETECTOR"
        })

    return all_findings
