from app.services.demo_data_service import BENIGN_EMAIL, SPF_FAILURE_EMAIL

def test_email_comparison(client, auth_headers):
    # Upload sample A
    resp_a = client.post("/api/emails", files={"file": ("sample_a.eml", BENIGN_EMAIL, "message/rfc822")}, headers=auth_headers)
    assert resp_a.status_code == 201
    id_a = resp_a.json()["id"]

    # Upload sample B
    resp_b = client.post("/api/emails", files={"file": ("sample_b.eml", SPF_FAILURE_EMAIL, "message/rfc822")}, headers=auth_headers)
    assert resp_b.status_code == 201
    id_b = resp_b.json()["id"]

    # Compare
    comp_resp = client.post("/api/emails/compare", data={"email_a_id": id_a, "email_b_id": id_b}, headers=auth_headers)
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()
    assert "sender_comparison" in comp_data
    assert "risk_comparison" in comp_data
