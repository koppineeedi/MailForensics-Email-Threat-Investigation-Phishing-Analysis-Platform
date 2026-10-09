import pytest
from app.services.stix_generator import generate_stix_bundle

def test_stix_bundle_structure_direct():
    email_data = {
        "id": "test-sample-1234",
        "subject": "Urgent Security Alert: Account Suspended",
        "sender": "security@attacker-domain.com",
        "recipients": "victim@enterprise.local",
        "message_id": "<msg-1234@attacker.com>",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "risk_score": 85,
        "risk_category": "CRITICAL",
        "data_source": "CONTROLLED_TEST",
        "urls": [
            {
                "id": "url-1",
                "email_id": "test-sample-1234",
                "raw_url": "http://attacker-phish.net/login.php",
                "normalized_url": "http://attacker-phish.net/login.php",
                "domain": "attacker-phish.net"
            }
        ],
        "attachments": [
            {
                "id": "att-1",
                "email_id": "test-sample-1234",
                "filename": "invoice.exe",
                "sanitized_filename": "invoice.exe",
                "mime_type": "application/x-dosexec",
                "size_bytes": 45056,
                "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "sha1": "1234567890abcdef1234567890abcdef12345678",
                "md5": "1234567890abcdef1234567890abcdef"
            }
        ],
        "phishing_findings": [
            {
                "id": "finding-1",
                "email_id": "test-sample-1234",
                "finding_code": "CRITICAL_MALICIOUS_ATTACHMENT",
                "category": "ATTACHMENT",
                "severity": "CRITICAL",
                "confidence": 95,
                "evidence": "YARA signature match: Ransomware payload",
                "explanation": "High-risk malicious executable detected.",
                "source": "LOCAL_STATIC_ANALYSIS"
            }
        ],
        "addresses": [],
        "domains": []
    }

    bundle = generate_stix_bundle(email_data)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert "objects" in bundle
    assert len(bundle["objects"]) >= 4

    types = {obj["type"] for obj in bundle["objects"]}
    assert "identity" in types
    assert "email-message" in types
    assert "url" in types
    assert "file" in types
    assert "indicator" in types
    assert "relationship" in types

    # Validate STIX spec adherence
    for obj in bundle["objects"]:
        assert "id" in obj
        assert "type" in obj
        assert obj["id"].startswith(f"{obj['type']}--")
        if obj["type"] in ["identity", "indicator", "relationship"]:
            assert "created" in obj
        assert "spec_version" in obj or obj["type"] in ["email-message", "url", "file", "ipv4-addr", "domain-name", "email-addr"]


def test_stix_export_api_endpoints(client, auth_headers):
    # First seed demo or upload an email to get an ID
    res = client.get("/api/emails/seed-demo", headers=auth_headers)
    assert res.status_code == 200
    samples = res.json()
    assert len(samples) > 0
    sample_id = samples[0]["id"]

    # Test /api/emails/{id}/stix
    stix_res = client.get(f"/api/emails/{sample_id}/stix", headers=auth_headers)
    assert stix_res.status_code == 200
    bundle = stix_res.json()
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) > 0

    # Test /api/reports/{id}/stix
    stix_rep_res = client.get(f"/api/reports/{sample_id}/stix", headers=auth_headers)
    assert stix_rep_res.status_code == 200
    bundle2 = stix_rep_res.json()
    assert bundle2["type"] == "bundle"
