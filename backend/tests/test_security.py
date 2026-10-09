import pytest
from fastapi import HTTPException
from app.core.file_storage import sanitize_filename, validate_storage_path, inspect_archive_safely

def test_filename_sanitization():
    raw = "../../../etc/passwd"
    clean = sanitize_filename(raw)
    assert ".." not in clean
    assert clean == "passwd"

def test_path_traversal_prevention():
    with pytest.raises(HTTPException) as exc_info:
        validate_storage_path("/var/uploads/../../etc/shadow", "/var/uploads")
    assert exc_info.value.status_code == 400

def test_unauthenticated_access(client):
    resp = client.get("/api/emails")
    assert resp.status_code == 401
