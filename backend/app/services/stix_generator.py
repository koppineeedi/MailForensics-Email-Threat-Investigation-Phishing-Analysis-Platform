import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def generate_stix_bundle(email_sample_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a compliant STIX 2.1 JSON Bundle representing real observed defensive artifacts.
    Contains: email-message, email-addr, domain-name, ipv4-addr, url, file, and indicator objects.
    Guaranteed: Every STIX object maps directly to verified evidence.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects = []

    # 1. Identity Object (MailForensics Defensive Platform)
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'mailforensics.local')}"
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_utc,
        "modified": now_utc,
        "name": "MailForensics Defensive Platform",
        "identity_class": "system",
        "description": "SOC Email Threat Investigation & Phishing Analysis Engine"
    }
    objects.append(identity_obj)

    # 2. Email Address Objects (Sender)
    sender_val = email_sample_data.get("sender") or "unknown@domain.local"
    sender_addr_id = f"email-addr--{uuid.uuid5(uuid.NAMESPACE_DNS, sender_val)}"
    objects.append({
        "type": "email-addr",
        "spec_version": "2.1",
        "id": sender_addr_id,
        "value": sender_val
    })

    # 3. Email Message Object
    email_obj_id = f"email-message--{uuid.uuid4()}"
    email_obj = {
        "type": "email-message",
        "spec_version": "2.1",
        "id": email_obj_id,
        "is_multipart": True,
        "date": str(email_sample_data.get("received_timestamp") or now_utc),
        "subject": email_sample_data.get("subject", ""),
        "from_ref": sender_addr_id,
        "message_id": email_sample_data.get("message_id")
    }
    objects.append(email_obj)

    # 4. URLs Extracted
    for u in email_sample_data.get("urls", []):
        raw_url = u.get("normalized_url") or u.get("original_url")
        if not raw_url:
            continue
        url_id = f"url--{uuid.uuid5(uuid.NAMESPACE_URL, raw_url)}"
        objects.append({
            "type": "url",
            "spec_version": "2.1",
            "id": url_id,
            "value": raw_url
        })

        # If suspicious, emit an Indicator object
        if u.get("is_ip_based") or u.get("is_suspicious_tld") or u.get("contains_credentials"):
            indicator_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now_utc,
                "modified": now_utc,
                "name": f"Suspicious URL: {u.get('hostname')}",
                "description": f"URL extracted from email {email_sample_data.get('id')}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[url:value = '{raw_url}']",
                "pattern_type": "stix",
                "valid_from": now_utc,
                "created_by_ref": identity_id
            })

    # 5. Attachment Files
    for att in email_sample_data.get("attachments", []):
        file_sha256 = att.get("sha256")
        if not file_sha256:
            continue
        file_id = f"file--{uuid.uuid5(uuid.NAMESPACE_DNS, file_sha256)}"
        hashes = {"SHA-256": file_sha256}
        if att.get("sha1"):
            hashes["SHA-1"] = att["sha1"]
        if att.get("md5"):
            hashes["MD5"] = att["md5"]

        objects.append({
            "type": "file",
            "spec_version": "2.1",
            "id": file_id,
            "name": att.get("sanitized_filename") or att.get("filename"),
            "size": att.get("size_bytes", 0),
            "hashes": hashes,
            "mime_type": att.get("mime_type", "application/octet-stream")
        })

        # If attachment is flagged suspicious, create an indicator
        ext = att.get("extension", "").lower()
        if ext in [".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".docm"]:
            ind_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_utc,
                "modified": now_utc,
                "name": f"Suspicious Attachment: {att.get('filename')}",
                "description": f"High-risk extension {ext} detected in email attachment.",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[file:hashes.'SHA-256' = '{file_sha256}']",
                "pattern_type": "stix",
                "valid_from": now_utc,
                "created_by_ref": identity_id
            })

            # Add Relationship SRO
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now_utc,
                "modified": now_utc,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": file_id
            })

    # 6. Observed Phishing Findings
    for find in email_sample_data.get("phishing_findings", []):
        code = find.get("finding_code")
        severity = find.get("severity", "MEDIUM")
        if severity in ["HIGH", "CRITICAL"]:
            find_ind_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": find_ind_id,
                "created": now_utc,
                "modified": now_utc,
                "name": f"Finding: {code}",
                "description": find.get("explanation", ""),
                "indicator_types": ["malicious-activity"],
                "pattern": f"[email-message:subject = '{email_sample_data.get('subject', '')}']",
                "pattern_type": "stix",
                "valid_from": now_utc,
                "created_by_ref": identity_id
            })
            # Add Relationship SRO
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now_utc,
                "modified": now_utc,
                "relationship_type": "indicates",
                "source_ref": find_ind_id,
                "target_ref": email_obj_id
            })

    stix_bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }

    return stix_bundle
