def test_audit_logs_query(client, auth_headers):
    resp = client.get("/api/audit", headers=auth_headers)
    assert resp.status_code == 200
    logs = resp.json()
    assert isinstance(logs, list)
