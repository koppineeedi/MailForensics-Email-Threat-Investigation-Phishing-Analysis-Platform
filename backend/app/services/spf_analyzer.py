import re
from typing import Dict, Any, List, Tuple, Optional

def parse_spf(headers: List[Dict[str, Any]], from_domain: Optional[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    SPF Analysis Engine.
    Parses Received-SPF or Authentication-Results headers.
    """
    spf_result = "NONE"
    spf_domain = from_domain
    explanation = "No explicit SPF authentication header observed in raw email headers."
    raw_auth_header = ""

    findings = []

    # Look for Received-SPF header first
    for h in headers:
        name_lower = h["header_name"].lower()
        if name_lower == "received-spf":
            raw_val = h["header_value"]
            raw_auth_header = raw_val
            match = re.match(r'^(pass|fail|softfail|neutral|none|temperror|permerror)', raw_val, re.IGNORECASE)
            if match:
                spf_result = match.group(1).upper()
                domain_match = re.search(r'domain of\s+([^\s;]+)', raw_val, re.IGNORECASE)
                if domain_match:
                    spf_domain = domain_match.group(1).strip()
                explanation = f"SPF header result '{spf_result}' evaluated for domain '{spf_domain}'."
                break

    # If Received-SPF not present, check Authentication-Results header
    if spf_result == "NONE":
        for h in headers:
            if h["header_name"].lower() == "authentication-results":
                raw_val = h["header_value"]
                if "spf=" in raw_val.lower():
                    raw_auth_header = raw_val
                    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', raw_val, re.IGNORECASE)
                    if spf_match:
                        spf_result = spf_match.group(1).upper()
                        # Extract domain if present (smtp.mailfrom=domain.com or header.from=domain.com)
                        mailfrom_match = re.search(r'smtp\.mailfrom=([^\s;]+)', raw_val, re.IGNORECASE)
                        if mailfrom_match:
                            spf_domain = mailfrom_match.group(1).strip()
                        explanation = f"Authentication-Results header indicates SPF {spf_result} for domain '{spf_domain}'."
                        break

    if spf_result == "FAIL":
        findings.append({
            "finding_code": "SPF_FAILURE",
            "category": "EMAIL_AUTHENTICATION",
            "severity": "HIGH",
            "confidence": 0.95,
            "evidence": f"Header: {raw_auth_header if raw_auth_header else 'SPF status: FAIL'}",
            "explanation": f"SPF authentication failed for domain '{spf_domain}'. The sending server IP is not authorized to send email for this domain according to DNS policy.",
            "source": "SPF_ANALYZER"
        })
    elif spf_result == "SOFTFAIL":
        findings.append({
            "finding_code": "SPF_SOFTFAIL",
            "category": "EMAIL_AUTHENTICATION",
            "severity": "SUSPICIOUS",
            "confidence": 0.85,
            "evidence": f"Header: {raw_auth_header}",
            "explanation": f"SPF evaluation returned SOFTFAIL for domain '{spf_domain}'. Sending host is probably not authorized.",
            "source": "SPF_ANALYZER"
        })
    elif spf_result in ["NONE", "NEUTRAL"]:
        findings.append({
            "finding_code": "SPF_NEUTRAL_OR_NONE",
            "category": "EMAIL_AUTHENTICATION",
            "severity": "LOW",
            "confidence": 0.70,
            "evidence": f"SPF status: {spf_result}",
            "explanation": f"No definitive SPF pass policy was asserted for domain '{spf_domain}'.",
            "source": "SPF_ANALYZER"
        })

    result_dict = {
        "spf_result": spf_result,
        "spf_domain": spf_domain,
        "spf_explanation": explanation
    }

    return result_dict, findings
