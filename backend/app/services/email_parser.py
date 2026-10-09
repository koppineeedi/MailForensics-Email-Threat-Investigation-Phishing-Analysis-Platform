import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses, parsedate_to_datetime
import re
from typing import Dict, Any, List, Tuple, Optional

def parse_address(raw_header_val: Optional[str]) -> List[Dict[str, str]]:
    """Parse raw address header into structured list of display_name, address, domain."""
    if not raw_header_val:
        return []
    
    results = []
    addresses = getaddresses([raw_header_val])
    for display_name, addr in addresses:
        if not addr:
            continue
        addr_clean = addr.strip().lower()
        domain = addr_clean.split('@')[-1] if '@' in addr_clean else ""
        results.append({
            "raw_address": addr,
            "normalized_address": addr_clean,
            "display_name": display_name.strip() if display_name else None,
            "domain": domain
        })
    return results

def parse_raw_email(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Safely parse RFC 822/5322 email bytes into metadata, headers, body text, body HTML, and attachments.
    Does NOT execute any content or scripts.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    
    # Metadata
    message_id = msg.get("Message-ID", "")
    if message_id:
        message_id = message_id.strip("<> ")
        
    subject = msg.get("Subject", "(No Subject)")
    date_str = msg.get("Date", None)
    received_timestamp = None
    if date_str:
        try:
            received_timestamp = parsedate_to_datetime(date_str)
        except Exception:
            received_timestamp = None

    from_raw = msg.get("From", "")
    to_raw = msg.get("To", "")
    cc_raw = msg.get("Cc", "")
    bcc_raw = msg.get("Bcc", "")
    reply_to_raw = msg.get("Reply-To", "")
    return_path_raw = msg.get("Return-Path", "")
    sender_raw = msg.get("Sender", "")

    # Parse address structures
    from_parsed = parse_address(from_raw)
    to_parsed = parse_address(to_raw)
    cc_parsed = parse_address(cc_raw)
    bcc_parsed = parse_address(bcc_raw)
    reply_to_parsed = parse_address(reply_to_raw)
    return_path_parsed = parse_address(return_path_raw)
    sender_parsed = parse_address(sender_raw)

    sender_address = from_parsed[0]["normalized_address"] if from_parsed else (sender_parsed[0]["normalized_address"] if sender_parsed else None)

    # Extract all headers preserving original order and values
    all_headers = []
    hop_counter = 0
    for name, value in msg.items():
        name_str = str(name)
        val_str = str(value)
        is_auth = any(auth_kw in name_str.lower() for auth_kw in ["authentication-results", "received-spf", "dkim-signature", "arc-"])
        
        hop_idx = None
        if name_str.lower() == "received":
            hop_idx = hop_counter
            hop_counter += 1

        all_headers.append({
            "header_name": name_str,
            "header_value": val_str,
            "is_auth_header": is_auth,
            "hop_index": hop_idx
        })

    # Extract Body Parts & Attachments
    body_plain = ""
    body_html = ""
    raw_attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Attachment identification
            is_attachment = "attachment" in content_disposition or part.get_filename() is not None

            if is_attachment:
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                raw_attachments.append({
                    "filename": filename,
                    "mime_type": content_type,
                    "payload": payload,
                    "size": len(payload)
                })
            else:
                if content_type == "text/plain" and not body_plain:
                    try:
                        body_plain = part.get_content()
                    except Exception:
                        body_plain = str(part.get_payload(decode=True) or "", errors="replace")
                elif content_type == "text/html" and not body_html:
                    try:
                        body_html = part.get_content()
                    except Exception:
                        body_html = str(part.get_payload(decode=True) or "", errors="replace")
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = str(msg.get_payload(decode=True) or "", errors="replace")
            
        if content_type == "text/html":
            body_html = content
        else:
            body_plain = content

    return {
        "message_id": message_id,
        "subject": subject,
        "sender": sender_address,
        "sender_raw": from_raw,
        "from_parsed": from_parsed,
        "to_parsed": to_parsed,
        "cc_parsed": cc_parsed,
        "bcc_parsed": bcc_parsed,
        "reply_to_parsed": reply_to_parsed,
        "return_path_parsed": return_path_parsed,
        "sender_parsed": sender_parsed,
        "received_timestamp": received_timestamp,
        "headers": all_headers,
        "body_plain": body_plain,
        "body_html": body_html,
        "raw_attachments": raw_attachments
    }
