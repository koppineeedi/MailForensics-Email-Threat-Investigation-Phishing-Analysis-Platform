import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any

def parse_received_headers(headers: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse RFC 'Received' headers into an ordered chain of mail transfer hops.
    Hops are ordered chronologically from origin (Hop 1) to final recipient mailbox.
    """
    raw_received_headers = [h["header_value"] for h in headers if h["header_name"].lower() == "received"]
    
    # In raw email headers, top Received header is the final recipient hop, bottom is original sender hop.
    # Reverse list so Hop 1 = original sender/first relay hop.
    raw_received_headers.reverse()

    hops = []
    anomalies = []

    prev_timestamp = None

    for idx, raw_val in enumerate(raw_received_headers, start=1):
        # Extract IP addresses: e.g. [192.168.1.1] or (10.0.0.1)
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_val)
        from_ip = ips[0] if len(ips) > 0 else None
        by_ip = ips[1] if len(ips) > 1 else None

        # Extract "from" domain/host
        from_match = re.search(r'from\s+([^\s;]+)', raw_val, re.IGNORECASE)
        from_host = from_match.group(1).strip("()") if from_match else None

        # Extract "by" domain/host
        by_match = re.search(r'by\s+([^\s;]+)', raw_val, re.IGNORECASE)
        by_host = by_match.group(1).strip("()") if by_match else None

        # Extract HELO/EHLO
        helo_match = re.search(r'helo=([^\s;)]+)', raw_val, re.IGNORECASE)
        helo_domain = helo_match.group(1) if helo_match else None

        # Extract TLS / Protocol
        tls_version = None
        cipher = None
        if "using TLS" in raw_val or "with TLS" in raw_val or "version=TLS" in raw_val:
            tls_match = re.search(r'(TLSv[0-9\.]+)', raw_val)
            tls_version = tls_match.group(1) if tls_match else "TLS"
            cipher_match = re.search(r'cipher=([^\s;]+)', raw_val, re.IGNORECASE)
            cipher = cipher_match.group(1) if cipher_match else None

        protocol_match = re.search(r'with\s+([A-Z0-9]+)', raw_val, re.IGNORECASE)
        protocol = protocol_match.group(1) if protocol_match else "ESMTP"

        # Extract Timestamp
        timestamp = None
        if ";" in raw_val:
            date_part = raw_val.split(";")[-1].strip()
            try:
                timestamp = parsedate_to_datetime(date_part)
            except Exception:
                timestamp = None

        delay_seconds = None
        anomaly_detected = False
        anomaly_details = []

        if timestamp and prev_timestamp:
            try:
                diff = (timestamp - prev_timestamp).total_seconds()
                delay_seconds = max(0.0, diff)
                if diff < -10:
                    anomaly_detected = True
                    anomaly_details.append(f"Negative time delay ({diff}s) between hop {idx-1} and hop {idx}, indicating clock skew or timestamp manipulation.")
                elif diff > 3600:
                    anomaly_detected = True
                    anomaly_details.append(f"Unusually long delay ({diff/3600:.1f} hours) between relay hops.")
            except Exception:
                pass

        prev_timestamp = timestamp or prev_timestamp

        # Check for IP anomalies
        if from_ip and from_ip.startswith("10.") or (from_ip and from_ip.startswith("192.168.")):
            if idx > 1: # Internal private hops are normal inside network, but flagged for visibility
                anomaly_details.append(f"Private IP address ({from_ip}) in transit hop.")

        hop_dict = {
            "hop_order": idx,
            "from_host": from_host,
            "from_ip": from_ip,
            "by_host": by_host,
            "by_ip": by_ip,
            "timestamp": timestamp,
            "protocol": protocol,
            "tls_version": tls_version,
            "cipher": cipher,
            "helo_domain": helo_domain,
            "delay_seconds": delay_seconds,
            "reverse_dns": None,
            "anomaly_detected": len(anomaly_details) > 0,
            "anomaly_details": "; ".join(anomaly_details) if anomaly_details else None
        }
        hops.append(hop_dict)

        if len(anomaly_details) > 0:
            anomalies.append({
                "finding_code": "SUSPICIOUS_RECEIVED_CHAIN",
                "category": "RECEIVED_CHAIN",
                "severity": "GUARDED",
                "confidence": 0.80,
                "evidence": f"Hop {idx}: {hop_dict['anomaly_details']}",
                "explanation": f"Anomaly detected in Received hop #{idx}.",
                "source": "RECEIVED_CHAIN_ANALYZER"
            })

    return hops, anomalies
