from app.services.attachment_analyzer import analyze_raw_attachments

def test_attachment_safe_analysis():
    raw_att = [{
        "filename": "Invoice_Notice.pdf.exe",
        "mime_type": "application/octet-stream",
        "payload": b"MZ_SIMULATED_TEST_PAYLOAD"
    }]

    att_records, findings = analyze_raw_attachments(raw_att)
    assert len(att_records) == 1
    assert att_records[0]["extension"] == ".exe"
    assert len(att_records[0]["sha256"]) == 64
    assert len(findings) == 1
    assert findings[0]["finding_code"] == "SUSPICIOUS_ATTACHMENT"
