import re
from typing import Dict, Any, List, Tuple, Optional

def parse_dkim(
    headers: List[Dict[str, Any]],
    raw_bytes: Optional[bytes],
    from_domain: Optional[str]
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    DKIM Analysis Engine.
    Parses DKIM-Signature headers and Authentication-Results headers.
    Optionally performs cryptographic verification if dkimpy is available.
    """
    dkim_result = "NOT_CHECKED"
    dkim_domain = None
    dkim_selector = None
    dkim_alignment = False
    explanation = "DKIM validation status unconfirmed."

    findings = []

    # 1. Parse DKIM-Signature header if present for d and s parameters
    for h in headers:
        if h["header_name"].lower() == "dkim-signature":
            raw_val = h["header_value"]
            d_match = re.search(r'd=([^\s;]+)', raw_val)
            if d_match:
                dkim_domain = d_match.group(1).strip()
            s_match = re.search(r's=([^\s;]+)', raw_val)
            if s_match:
                dkim_selector = s_match.group(1).strip()

    # 2. Check Authentication-Results for header DKIM status
    raw_auth_results = ""
    for h in headers:
        if h["header_name"].lower() == "authentication-results":
            raw_val = h["header_value"]
            if "dkim=" in raw_val.lower():
                raw_auth_results = raw_val
                match = re.search(r'dkim=(pass|fail|none|neutral|temperror|permerror)', raw_val, re.IGNORECASE)
                if match:
                    dkim_result = match.group(1).upper()
                    explanation = f"Authentication-Results header recorded DKIM status: '{dkim_result}'."

                    # Parse header.i or header.d from Authentication-Results if not already set
                    d_auth = re.search(r'header\.(?:i|d)=([^\s;@]+)', raw_val, re.IGNORECASE)
                    if d_auth and not dkim_domain:
                        dkim_domain = d_auth.group(1).strip()
                    break

    # 3. Perform cryptographic verification if raw_bytes available & dkimpy installed
    if raw_bytes:
        try:
            import dkim
            res = dkim.verify(raw_bytes)
            if res:
                dkim_result = "PASS"
                explanation = "Cryptographic DKIM signature verified successfully using dkimpy engine."
            elif dkim_result == "NOT_CHECKED":
                dkim_result = "FAIL"
                explanation = "DKIM cryptographic signature verification failed."
        except Exception:
            # Fallback to header result if cryptographic verification throws exception or isn't compatible
            pass

    # Check alignment against From domain
    if from_domain and dkim_domain:
        from_dom_clean = from_domain.lower()
        dkim_dom_clean = dkim_domain.lower()
        if from_dom_clean == dkim_dom_clean or dkim_dom_clean.endswith("." + from_dom_clean) or from_dom_clean.endswith("." + dkim_dom_clean):
            dkim_alignment = True

    if dkim_result == "FAIL":
        findings.append({
            "finding_code": "DKIM_FAILURE",
            "category": "EMAIL_AUTHENTICATION",
            "severity": "HIGH",
            "confidence": 0.95,
            "evidence": f"DKIM result: FAIL, Signing Domain: {dkim_domain or 'Unknown'}",
            "explanation": f"DKIM verification failed for signing domain '{dkim_domain}'. The email body or headers may have been altered in transit, or the signature is invalid.",
            "source": "DKIM_ANALYZER"
        })
    elif dkim_result == "PASS" and not dkim_alignment:
        findings.append({
            "finding_code": "DKIM_UNALIGNED",
            "category": "EMAIL_AUTHENTICATION",
            "severity": "SUSPICIOUS",
            "confidence": 0.85,
            "evidence": f"From domain: '{from_domain}', DKIM signing domain: '{dkim_domain}'",
            "explanation": f"DKIM signature passed, but signing domain '{dkim_domain}' is not aligned with header From domain '{from_domain}'.",
            "source": "DKIM_ANALYZER"
        })

    result_dict = {
        "dkim_result": dkim_result,
        "dkim_domain": dkim_domain,
        "dkim_selector": dkim_selector,
        "dkim_alignment": dkim_alignment,
        "dkim_explanation": explanation
    }

    return result_dict, findings
