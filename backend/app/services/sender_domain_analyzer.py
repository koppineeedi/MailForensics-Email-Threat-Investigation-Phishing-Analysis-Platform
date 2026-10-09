import re
import math
from typing import List, Dict, Any, Tuple, Optional

# Popular target brand domains for typosquatting / lookalike detection
TARGET_BRANDS = [
    "microsoft.com", "office365.com", "outlook.com", "google.com", "gmail.com",
    "apple.com", "icloud.com", "amazon.com", "paypal.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "docusign.com", "dropbox.com", "adobe.com"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p, 2) for p in prob])

def analyze_sender_and_domains(
    from_parsed: List[Dict[str, str]],
    reply_to_parsed: List[Dict[str, str]],
    return_path_parsed: List[Dict[str, str]],
    to_parsed: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Sender & Domain Analysis Engine.
    Distinguishes OBSERVED FACTS from HEURISTIC INDICATORS.
    """
    domain_records = []
    findings = []

    # Collect recipient domains to check against
    recipient_domains = [t["domain"].lower() for t in to_parsed if t.get("domain")]

    observed_domains = set()

    def check_domain(domain_str: str, dom_type: str):
        if not domain_str or domain_str in observed_domains:
            return
        observed_domains.add(domain_str)
        
        dom_clean = domain_str.lower().strip()
        is_punycode = dom_clean.startswith("xn--") or ".xn--" in dom_clean
        entropy = calculate_entropy(dom_clean)
        subdomain_depth = max(0, len(dom_clean.split('.')) - 2)

        is_lookalike = False
        matched_target = None

        # Lookalike detection (check edit distance 1 or 2 against target brands and recipient domains)
        targets_to_check = set(TARGET_BRANDS + recipient_domains)
        for target in targets_to_check:
            if target == dom_clean:
                continue
            dist = levenshtein_distance(dom_clean, target)
            if 0 < dist <= 2 and abs(len(dom_clean) - len(target)) <= 3:
                is_lookalike = True
                matched_target = target
                break

        domain_records.append({
            "domain": dom_clean,
            "domain_type": dom_type,
            "is_lookalike": is_lookalike,
            "is_punycode": is_punycode,
            "entropy": round(entropy, 2),
            "subdomain_depth": subdomain_depth
        })

        # Findings generation
        if is_punycode:
            findings.append({
                "finding_code": "PUNYCODE_DOMAIN",
                "category": "DOMAIN_ANALYSIS",
                "severity": "SUSPICIOUS",
                "confidence": 0.90,
                "evidence": f"Domain '{dom_clean}' uses Internationalized Domain Name (Punycode) encoding.",
                "explanation": f"[HEURISTIC INDICATOR] Punycode domain '{dom_clean}' may be used for homograph attacks.",
                "source": "SENDER_DOMAIN_ANALYZER"
            })

        if is_lookalike and matched_target:
            findings.append({
                "finding_code": "LOOKALIKE_DOMAIN",
                "category": "DOMAIN_ANALYSIS",
                "severity": "HIGH",
                "confidence": 0.90,
                "evidence": f"Observed Domain: '{dom_clean}', Target Brand: '{matched_target}'",
                "explanation": f"[HEURISTIC INDICATOR] Domain '{dom_clean}' is visually similar to legitimate target brand '{matched_target}' (typosquatting indicator).",
                "source": "SENDER_DOMAIN_ANALYZER"
            })

        if subdomain_depth > 3:
            findings.append({
                "finding_code": "EXCESSIVE_SUBDOMAIN_DEPTH",
                "category": "DOMAIN_ANALYSIS",
                "severity": "GUARDED",
                "confidence": 0.75,
                "evidence": f"Domain: '{dom_clean}' (Subdomain Depth: {subdomain_depth})",
                "explanation": f"[HEURISTIC INDICATOR] Domain '{dom_clean}' has an unusually deep subdomain hierarchy.",
                "source": "SENDER_DOMAIN_ANALYZER"
            })

    if from_parsed and from_parsed[0].get("domain"):
        check_domain(from_parsed[0]["domain"], "FROM")

    if reply_to_parsed and reply_to_parsed[0].get("domain"):
        check_domain(reply_to_parsed[0]["domain"], "REPLY_TO")

    if return_path_parsed and return_path_parsed[0].get("domain"):
        check_domain(return_path_parsed[0]["domain"], "RETURN_PATH")

    return domain_records, findings
