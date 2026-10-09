import re
from typing import Dict, Any, List, Tuple, Optional

def parse_dmarc(
    headers: List[Dict[str, Any]],
    from_domain: Optional[str],
    spf_result: str,
    spf_domain: Optional[str],
    dkim_result: str,
    dkim_alignment: bool
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    DMARC Analysis Engine.
    Evaluates SPF alignment + DKIM alignment against the header From domain.
    Reads Authentication-Results DMARC status if present.
    """
    dmarc_result = "NOT_CHECKED"
    dmarc_policy = None
    explanation = "DMARC evaluation unconfirmed."
    raw_auth_header = ""

    findings = []

    # Check SPF alignment
    spf_align = False
    if from_domain and spf_domain and spf_result == "PASS":
        f_dom = from_domain.lower()
        s_dom = spf_domain.lower()
        if f_dom == s_dom or s_dom.endswith("." + f_dom) or f_dom.endswith("." + s_dom):
            spf_align = True

    dkim_align = dkim_alignment and dkim_result == "PASS"

    # 1. Search for DMARC header in Authentication-Results
    for h in headers:
        if h["header_name"].lower() == "authentication-results":
            raw_val = h["header_value"]
            if "dmarc=" in raw_val.lower():
                raw_auth_header = raw_val
                match = re.search(r'dmarc=(pass|fail|none)', raw_val, re.IGNORECASE)
                if match:
                    dmarc_result = match.group(1).upper()
                    pol_match = re.search(r'action=([^\s;]+)', raw_val, re.IGNORECASE)
                    if pol_match:
                        dmarc_policy = pol_match.group(1).lower()
                    explanation = f"Authentication-Results header recorded DMARC status: '{dmarc_result}'."
                    break

    # 2. If Authentication-Results lacks DMARC status, compute DMARC status logically based on alignment
    if dmarc_result == "NOT_CHECKED":
        if spf_align or dkim_align:
            dmarc_result = "PASS"
            explanation = f"DMARC passed based on alignment evaluation (SPF Align: {spf_align}, DKIM Align: {dkim_align})."
        elif spf_result in ["FAIL", "SOFTFAIL"] or dkim_result == "FAIL":
            dmarc_result = "FAIL"
            explanation = f"DMARC failed due to lack of aligned passing SPF or DKIM signature for domain '{from_domain}'."
        else:
            dmarc_result = "NONE"
            explanation = "DMARC policy cannot be verified without authoritative SPF/DKIM alignment."

    if dmarc_result == "FAIL":
        findings.append({
            "finding_code": "DMARC_FAILURE",
            "category": "EMAIL_AUTHENTICATION",
            "severity": "HIGH",
            "confidence": 0.95,
            "evidence": f"From domain: '{from_domain}', SPF Align: {spf_align}, DKIM Align: {dkim_align}",
            "explanation": f"DMARC validation failed for From domain '{from_domain}'. Neither SPF nor DKIM provided aligned authentication.",
            "source": "DMARC_ANALYZER"
        })

    result_dict = {
        "dmarc_result": dmarc_result,
        "dmarc_domain": from_domain,
        "dmarc_policy": dmarc_policy or "quarantine",
        "dmarc_spf_align": spf_align,
        "dmarc_dkim_align": dkim_align,
        "dmarc_explanation": explanation,
        "raw_auth_results_header": raw_auth_header
    }

    return result_dict, findings
