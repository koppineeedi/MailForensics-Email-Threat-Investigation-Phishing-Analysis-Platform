import os
import struct
import math
from typing import List, Dict, Any, Tuple
from app.core.file_storage import save_uploaded_file, inspect_archive_safely, sanitize_filename

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".pif",
    ".jar", ".wsf", ".cpl", ".iso", ".img", ".lnk", ".docm", ".xlsm"
]

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    occ = [0] * 256
    for b in data:
        occ[b] += 1
    total = len(data)
    entropy = 0.0
    for count in occ:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 2)

def parse_static_pe_metadata(payload: bytes) -> Dict[str, Any]:
    """
    Safely inspect Portable Executable (PE) headers without executing code.
    Extracts architecture, section count, and timestamp if valid.
    """
    result = {"is_pe": False, "machine": None, "sections_count": 0, "entropy": calculate_entropy(payload)}
    if len(payload) < 64 or not payload.startswith(b"MZ"):
        return result

    try:
        # e_lfanew is at offset 0x3C (4 bytes, little-endian)
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        if pe_offset + 24 <= len(payload) and payload[pe_offset:pe_offset+4] == b"PE\x00\x00":
            result["is_pe"] = True
            # Read COFF File Header: Machine (2 bytes at pe_offset + 4), NumberOfSections (2 bytes at pe_offset + 6)
            machine, num_sections = struct.unpack_from("<HH", payload, pe_offset + 4)
            machine_map = {0x014c: "IMAGE_FILE_MACHINE_I386 (32-bit)", 0x8664: "IMAGE_FILE_MACHINE_AMD64 (64-bit)"}
            result["machine"] = machine_map.get(machine, f"0x{machine:04x}")
            result["sections_count"] = num_sections
    except Exception:
        pass
    return result

def inspect_pdf_safely(payload: bytes) -> Dict[str, Any]:
    """Safe static inspection of PDF stream keywords without parsing JavaScript."""
    result = {"is_pdf": False, "has_javascript": False, "has_embedded_files": False}
    if payload.startswith(b"%PDF-"):
        result["is_pdf"] = True
        result["has_javascript"] = (b"/JavaScript" in payload or b"/JS" in payload)
        result["has_embedded_files"] = (b"/EmbeddedFiles" in payload or b"/Launch" in payload)
    return result

def analyze_raw_attachments(
    raw_attachments: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Safe static attachment analysis engine.
    Computes cryptographic hashes and extracts safe metadata.
    NEVER executes attachments, macros, or scripts.
    """
    attachment_records = []
    findings = []

    for raw in raw_attachments:
        filename = raw.get("filename", "unnamed_attachment")
        sanitized = sanitize_filename(filename)
        payload = raw.get("payload", b"")
        mime_type = raw.get("mime_type", "application/octet-stream")

        storage_path, sanitized_fn, sha256, sha1, md5, size_bytes = save_uploaded_file(payload, filename)
        ext = os.path.splitext(sanitized)[1].lower()

        # 1. Archive Safety Inspection
        archive_info = inspect_archive_safely(storage_path)
        is_archive = archive_info["is_archive"]

        # 2. PE Static Inspection
        pe_info = parse_static_pe_metadata(payload)

        # 3. PDF Static Inspection
        pdf_info = inspect_pdf_safely(payload)

        # 4. Extension Mismatch Detection
        extension_mismatch = False
        if (pe_info["is_pe"] or payload.startswith(b"MZ")) and ext not in [".exe", ".dll", ".sys", ".scr"]:
            extension_mismatch = True

        # Extract safe static metadata (without executing code)
        meta_data = {
            "archive_info": archive_info if is_archive else None,
            "pe_metadata": pe_info if pe_info["is_pe"] else None,
            "pdf_metadata": pdf_info if pdf_info["is_pdf"] else None,
            "entropy": pe_info["entropy"],
            "has_macro_extension": ext in [".docm", ".xlsm", ".pptm"],
            "extension_mismatch": extension_mismatch
        }

        is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS
        att_dict = {
            "filename": filename,
            "sanitized_filename": sanitized_fn,
            "extension": ext,
            "mime_type": mime_type,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "is_archive": is_archive,
            "nested_level": 0,
            "storage_path": storage_path,
            "metadata_json": meta_data,
            "attachment_findings": []
        }

        att_findings = []

        if is_suspicious_ext:
            att_findings.append({
                "finding_type": "SUSPICIOUS_ATTACHMENT_EXTENSION",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": f"Filename: '{filename}', Extension: '{ext}'",
                "description": f"Attachment has executable or script extension ({ext}) commonly used to deliver malware payloads."
            })
            findings.append({
                "finding_code": "SUSPICIOUS_ATTACHMENT",
                "category": "ATTACHMENT_ANALYSIS",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": f"Attachment '{filename}' (SHA256: {sha256}) has executable extension '{ext}'",
                "explanation": f"High-risk attachment format ({ext}) attached to email sample.",
                "source": "LOCAL_STATIC_ANALYSIS"
            })

        if extension_mismatch:
            att_findings.append({
                "finding_type": "EXTENSION_MISMATCH_DISGUISE",
                "severity": "CRITICAL",
                "confidence": 0.98,
                "evidence": f"File '{filename}' has extension '{ext}' but contains PE executable MZ headers.",
                "description": "Potential executable masquerading under non-executable document extension."
            })
            findings.append({
                "finding_code": "SUSPICIOUS_ATTACHMENT",
                "category": "ATTACHMENT_ANALYSIS",
                "severity": "CRITICAL",
                "confidence": 0.98,
                "evidence": f"Executable header hidden in '{filename}'",
                "explanation": "File disguise detected: PE executable bytes present in non-executable file type.",
                "source": "LOCAL_STATIC_ANALYSIS"
            })

        if is_archive and not archive_info.get("is_safe", True):
            warnings = "; ".join(archive_info.get("warnings", []))
            att_findings.append({
                "finding_type": "ARCHIVE_BOMB_INDICATOR",
                "severity": "CRITICAL",
                "confidence": 0.90,
                "evidence": f"Archive Warning: {warnings}",
                "description": "Archive file exceeds uncompressed safety limits or contains zip bomb characteristics."
            })
            findings.append({
                "finding_code": "ARCHIVE_BOMB_INDICATOR",
                "category": "ATTACHMENT_ANALYSIS",
                "severity": "CRITICAL",
                "confidence": 0.90,
                "evidence": warnings,
                "explanation": "Attached archive exhibits potential zip bomb or excessive compression ratios.",
                "source": "LOCAL_STATIC_ANALYSIS"
            })

        if meta_data["has_macro_extension"]:
            att_findings.append({
                "finding_type": "MACRO_ENABLED_DOCUMENT",
                "severity": "SUSPICIOUS",
                "confidence": 0.90,
                "evidence": f"Extension: '{ext}'",
                "description": "Office document supports VBA macro execution."
            })

        if pdf_info.get("has_javascript"):
            att_findings.append({
                "finding_type": "PDF_EMBEDDED_JAVASCRIPT",
                "severity": "HIGH",
                "confidence": 0.90,
                "evidence": f"PDF '{filename}' contains embedded /JavaScript or /JS actions.",
                "description": "PDF contains active embedded scripting."
            })

        att_dict["attachment_findings"] = att_findings
        attachment_records.append(att_dict)

    return attachment_records, findings
