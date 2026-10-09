from app.services.demo_data_service import BENIGN_EMAIL

def test_report_generation(client, auth_headers):
    up_resp = client.post("/api/emails", files={"file": ("report_test.eml", BENIGN_EMAIL, "message/rfc822")}, headers=auth_headers)
    email_id = up_resp.json()["id"]

    # Trigger analysis first
    client.post(f"/api/emails/{email_id}/analyze", headers=auth_headers)

    # Generate JSON Report
    json_resp = client.post(f"/api/emails/{email_id}/report?report_type=JSON", headers=auth_headers)
    assert json_resp.status_code == 200
    assert "report_metadata" in json_resp.json()

    # Generate PDF Report
    pdf_resp = client.post(f"/api/emails/{email_id}/report?report_type=PDF", headers=auth_headers)
    assert pdf_resp.status_code == 200
    pdf_data = pdf_resp.json()
    assert "pdf_url" in pdf_data

    # Download PDF
    dl_resp = client.get(pdf_data["pdf_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/pdf"
