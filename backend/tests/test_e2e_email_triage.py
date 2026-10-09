from app.services.demo_data_service import MULTI_INDICATOR_PHISHING_EMAIL

def test_full_end_to_end_email_triage_workflow(client):
    """
    REQUIRED END-TO-END ACCEPTANCE TEST:
    LOGIN -> UPLOAD -> HASH -> PARSE -> HEADER ANALYSIS -> RECEIVED CHAIN -> SPF -> DKIM -> DMARC
    -> URL EXTRACTION -> ATTACHMENT ANALYSIS -> PHISHING FINDINGS -> THREAT INTEL -> RISK -> TIMELINE
    -> CREATE CASE -> ADD NOTE -> ANALYST VERDICT -> GENERATE PDF -> AUDIT LOG.
    """
    # 1. LOGIN
    reg_resp = client.post("/api/auth/register", json={
        "email": "e2e_analyst@mailforensics.test",
        "password": "SecurePassword123!",
        "full_name": "E2E Lead Analyst",
        "role": "ANALYST"
    })
    assert reg_resp.status_code in [201, 400]

    login_resp = client.post("/api/auth/login", json={
        "email": "e2e_analyst@mailforensics.test",
        "password": "SecurePassword123!"
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. UPLOAD CONTROLLED EMAIL
    up_resp = client.post(
        "/api/emails",
        files={"file": ("phishing_multi_indicator.eml", MULTI_INDICATOR_PHISHING_EMAIL, "message/rfc822")},
        headers=headers
    )
    assert up_resp.status_code == 201
    sample_data = up_resp.json()
    email_id = sample_data["id"]

    # 3. HASH & METADATA VERIFICATION
    assert len(sample_data["sha256"]) == 64
    assert sample_data["size_bytes"] > 0

    # Trigger full backend analysis pipeline
    an_resp = client.post(f"/api/emails/{email_id}/analyze", headers=headers)
    assert an_resp.status_code == 200

    # Fetch full detail
    detail_resp = client.get(f"/api/emails/{email_id}", headers=headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()

    # 4. PARSE VERIFICATION
    assert detail["subject"] == "CONTROLLED LAB DEMO: URGENT: Account Suspended - Action Required"
    assert detail["sender"] == "security-update@paypa1-verify-account.lab"
    assert len(detail["headers"]) > 0

    # 5. HEADER ANALYSIS VERIFICATION
    # Check From vs Reply-To mismatch findings
    pf_codes = [f["finding_code"] for f in detail["phishing_findings"]]
    assert "REPLY_TO_MISMATCH" in pf_codes or "RETURN_PATH_MISMATCH" in pf_codes

    # 6. RECEIVED CHAIN VERIFICATION
    rc_resp = client.get(f"/api/emails/{email_id}/received-chain", headers=headers)
    assert rc_resp.status_code == 200

    # 7. 8. 9. SPF, DKIM, DMARC VERIFICATION
    auth_resp = client.get(f"/api/emails/{email_id}/authentication", headers=headers)
    assert auth_resp.status_code == 200
    auth_data = auth_resp.json()
    assert auth_data["spf_result"] == "FAIL"
    assert auth_data["dkim_result"] in ["FAIL", "NOT_CHECKED"]
    assert auth_data["dmarc_result"] == "FAIL"

    # 10. URL EXTRACTION VERIFICATION
    urls_resp = client.get(f"/api/emails/{email_id}/urls", headers=headers)
    assert urls_resp.status_code == 200
    url_list = urls_resp.json()
    assert len(url_list) > 0
    assert any(u["is_ip_based"] for u in url_list)

    # 11. ATTACHMENT ANALYSIS VERIFICATION
    att_resp = client.get(f"/api/emails/{email_id}/attachments", headers=headers)
    assert att_resp.status_code == 200
    att_list = att_resp.json()
    assert len(att_list) > 0
    assert att_list[0]["filename"] == "Account_Verification_Form.xlsm"
    assert len(att_list[0]["sha256"]) == 64

    # 12. PHISHING FINDINGS VERIFICATION
    findings = detail["phishing_findings"]
    assert len(findings) > 0

    # 13. THREAT INTEL STATUS VERIFICATION
    ti_resp = client.get("/api/threat-intel/status", headers=headers)
    assert ti_resp.status_code == 200
    assert "VirusTotal" in ti_resp.json()

    # 14. RISK VERIFICATION
    assert detail["risk_score"] > 40.0
    assert detail["risk_category"] in ["HIGH", "CRITICAL", "SUSPICIOUS"]

    # 15. TIMELINE EVENTS VERIFICATION
    assert len(detail["events"]) > 0

    # 16. CREATE CASE
    case_resp = client.post("/api/cases", json={
        "title": "E2E Investigation: Multi-Indicator Phishing",
        "description": "PayPal brand impersonation campaign",
        "priority": "HIGH",
        "severity": "CRITICAL",
        "email_ids": [email_id]
    }, headers=headers)
    assert case_resp.status_code == 201
    case_id = case_resp.json()["id"]

    # 17. ADD CASE NOTE
    note_resp = client.post(f"/api/cases/{case_id}/notes", json={
        "content": "Analyst verified malicious payload & lookalike domain."
    }, headers=headers)
    assert note_resp.status_code == 200

    # 18. ANALYST VERDICT
    verd_resp = client.post(f"/api/emails/{email_id}/verdict", json={
        "verdict": "PHISHING",
        "notes": "Confirmed phishing attack with lookalike domain and IP-based credential harvesting link."
    }, headers=headers)
    assert verd_resp.status_code == 200
    assert verd_resp.json()["verdict"] == "PHISHING"

    # 19. GENERATE PDF REPORT & DOWNLOAD
    rep_resp = client.post(f"/api/emails/{email_id}/report?report_type=PDF", headers=headers)
    assert rep_resp.status_code == 200
    pdf_url = rep_resp.json()["pdf_url"]

    dl_resp = client.get(pdf_url)
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/pdf"

    # 20. AUDIT LOG VERIFICATION
    audit_resp = client.get("/api/audit", headers=headers)
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    actions = [l["action"] for l in logs]
    assert "EMAIL_UPLOAD" in actions
    assert "ANALYST_VERDICT_CHANGE" in actions
    assert "REPORT_GENERATE_PDF" in actions
