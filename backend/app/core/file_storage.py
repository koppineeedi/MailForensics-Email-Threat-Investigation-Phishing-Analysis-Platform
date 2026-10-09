import os
import re
import uuid
import hashlib
import zipfile
import tarfile
from typing import Tuple, Dict, Any, List
from fastapi import HTTPException, status
from app.config import settings

def sanitize_filename(filename: str) -> str:
    """Sanitize original filename against path traversal and dangerous characters."""
    if not filename:
        return "unnamed_artifact.eml"
    # Extract basename only
    clean = os.path.basename(filename)
    # Remove control characters and path symbols
    clean = re.sub(r'[^\w\.\-]', '_', clean)
    # Avoid leading dots / empty filenames
    if not clean or clean.startswith('.'):
        clean = f"artifact_{clean.lstrip('.')}"
    return clean[:255]

def calculate_hashes(content: bytes) -> Tuple[str, str, str]:
    """Calculate SHA-256, SHA-1, and MD5 hashes safely."""
    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    return sha256, sha1, md5

def validate_storage_path(target_path: str, allowed_parent_dir: str) -> str:
    """Enforce strict path traversal prevention."""
    abs_target = os.path.abspath(target_path)
    abs_parent = os.path.abspath(allowed_parent_dir)
    if not abs_target.startswith(abs_parent):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security error: Path traversal attempt detected."
        )
    return abs_target

def save_uploaded_file(file_content: bytes, original_filename: str, directory: str = settings.UPLOAD_DIR) -> Tuple[str, str, str, str, str, int]:
    """
    Safely store an uploaded file using a UUID target filename.
    Returns (storage_path, sanitized_filename, sha256, sha1, md5, size_bytes).
    """
    size_bytes = len(file_content)
    if size_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Upload size ({size_bytes} bytes) exceeds maximum limit of {settings.MAX_UPLOAD_SIZE_BYTES} bytes."
        )

    sanitized = sanitize_filename(original_filename)
    sha256, sha1, md5 = calculate_hashes(file_content)
    
    unique_name = f"{uuid.uuid4().hex}_{sanitized}"
    target_path = os.path.join(directory, unique_name)
    validated_path = validate_storage_path(target_path, directory)
    
    with open(validated_path, "wb") as f:
        f.write(file_content)

    return validated_path, sanitized, sha256, sha1, md5, size_bytes

def inspect_archive_safely(file_path: str, max_depth: int = settings.MAX_NESTING_DEPTH) -> Dict[str, Any]:
    """
    Safely inspect zip/tar archive metadata without executing or uncompressing unsafe amounts of data.
    Implements archive bomb protections.
    """
    result = {
        "is_archive": False,
        "is_safe": True,
        "file_count": 0,
        "total_uncompressed_size": 0,
        "nested_archives": [],
        "file_list": [],
        "warnings": []
    }

    if not zipfile.is_zipfile(file_path):
        return result

    result["is_archive"] = True

    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            infolist = zf.infolist()
            result["file_count"] = len(infolist)
            
            if len(infolist) > settings.MAX_FILE_COUNT:
                result["is_safe"] = False
                result["warnings"].append(f"Archive exceeds maximum file count limit ({len(infolist)} > {settings.MAX_FILE_COUNT}).")

            for info in infolist:
                # Path traversal in archive inspection check
                if ".." in info.filename or info.filename.startswith("/") or "\\" in info.filename:
                    result["warnings"].append(f"Suspicious path in archive entry: {info.filename}")

                result["total_uncompressed_size"] += info.file_size
                result["file_list"].append({
                    "filename": sanitize_filename(info.filename),
                    "file_size": info.file_size,
                    "compress_size": info.compress_size
                })

                # Nested archive indicator
                ext = os.path.splitext(info.filename)[1].lower()
                if ext in ['.zip', '.tar', '.gz', '.7z', '.rar']:
                    result["nested_archives"].append(info.filename)

            if result["total_uncompressed_size"] > settings.MAX_EXTRACTED_SIZE_BYTES:
                result["is_safe"] = False
                result["warnings"].append(f"Archive uncompressed size ({result['total_uncompressed_size']} bytes) exceeds safety limit ({settings.MAX_EXTRACTED_SIZE_BYTES} bytes). Potential zip bomb.")

    except Exception as e:
        result["is_safe"] = False
        result["warnings"].append(f"Error inspecting archive safely: {str(e)}")

    return result
