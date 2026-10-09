from typing import List, Dict, Any

def analyze_headers(
    headers: List[Dict[str, Any]],
    from_parsed: List[Dict[str, str]],
    reply_to_parsed: List[Dict[str, str]],
    return_path_parsed: List[Dict[str, str]],
    message_id: str
) -> List[Dict[str, Any]]:
    """
    Header Analysis Engine detecting header inconsistencies, spoofing indicators, and missing security controls.
    """
    findings = []

    from_domain = from_parsed[0]["domain"].lower() if from_parsed and from_parsed[0].get("domain") else ""
    reply_to_domain = reply_to_parsed[0]["domain"].lower() if reply_to_parsed and reply_to_parsed[0].get("domain") else ""
    return_path_domain = return_path_parsed[0]["domain"].lower() if return_path_parsed and return_path_parsed[0].get("domain") else ""

    # 1. From vs Reply-To Mismatch
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        findings.append({
            "finding_code": "REPLY_TO_MISMATCH",
            "category": "HEADER_ANALYSIS",
            "severity": "SUSPICIOUS",
            "confidence": 0.90,
            "evidence": f"From domain: '{from_domain}', Reply-To domain: '{reply_to_domain}'",
            "explanation": f"The Reply-To header domain ({reply_to_domain}) differs from the display From header domain ({from_domain}). Replies will be directed to a different organization.",
            "source": "HEADER_ANALYZER"
        })

    # 2. From vs Return-Path Mismatch
    if from_domain and return_path_domain and from_domain != return_path_domain:
        findings.append({
            "finding_code": "RETURN_PATH_MISMATCH",
            "category": "HEADER_ANALYSIS",
            "severity": "GUARDED",
            "confidence": 0.85,
            "evidence": f"From domain: '{from_domain}', Return-Path domain: '{return_path_domain}'",
            "explanation": f"The envelope Return-Path domain ({return_path_domain}) does not match the header From domain ({from_domain}). Common in email spoofing or third-party mailing list services.",
            "source": "HEADER_ANALYZER"
        })

    # 3. Message-ID Domain Inconsistency
    if message_id and "@" in message_id:
        msg_id_domain = message_id.split("@")[-1].lower().strip("> ")
        if from_domain and msg_id_domain and not (msg_id_domain.endswith(from_domain) or from_domain.endswith(msg_id_domain)):
            # Ignore generic cloud provider domains like google.com, outlook.com if relaying
            if not any(provider in msg_id_domain for provider in ["google.com", "outlook.com", "sendgrid.net", "mailgun.org", "amazonses.com"]):
                findings.append({
                    "finding_code": "SUSPICIOUS_MESSAGE_ID_DOMAIN",
                    "category": "HEADER_ANALYSIS",
                    "severity": "GUARDED",
                    "confidence": 0.75,
                    "evidence": f"Message-ID: '{message_id}', From domain: '{from_domain}'",
                    "explanation": f"The domain in the Message-ID ({msg_id_domain}) is inconsistent with the From header domain ({from_domain}).",
                    "source": "HEADER_ANALYZER"
                })

    # 4. Check for X-Originating-IP or suspicious originating IP
    header_names = [h["header_name"].lower() for h in headers]
    originating_ip = None
    for h in headers:
        if h["header_name"].lower() in ["x-originating-ip", "x-sender-ip", "x-client-ip"]:
            originating_ip = h["header_value"].strip("[] ")
            break

    if originating_ip:
        findings.append({
            "finding_code": "ORIGINATING_IP_DISCOVERED",
            "category": "HEADER_ANALYSIS",
            "severity": "LOW",
            "confidence": 1.0,
            "evidence": f"Originating IP header found: {originating_ip}",
            "explanation": f"Message contains explicit sender client IP metadata ({originating_ip}).",
            "source": "HEADER_ANALYZER"
        })

    # 5. Missing Expected Authentication Headers
    has_auth_results = any(h in header_names for h in ["authentication-results", "received-spf"])
    if not has_auth_results:
        findings.append({
            "finding_code": "MISSING_AUTHENTICATION_HEADERS",
            "category": "HEADER_ANALYSIS",
            "severity": "SUSPICIOUS",
            "confidence": 0.95,
            "evidence": "No 'Authentication-Results' or 'Received-SPF' header found in raw message.",
            "explanation": "The email sample lacks standard email authentication verification headers, making identity verification unconfirmed.",
            "source": "HEADER_ANALYZER"
        })

    return findings
