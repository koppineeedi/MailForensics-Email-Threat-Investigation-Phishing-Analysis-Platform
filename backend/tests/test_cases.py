def test_case_management_flow(client, auth_headers):
    # Create Case
    create_resp = client.post("/api/cases", json={
        "title": "Investigating Suspicious Invoice Campaign",
        "description": "Cluster of emails targeting finance dept",
        "priority": "HIGH",
        "severity": "SUSPICIOUS"
    }, headers=auth_headers)
    assert create_resp.status_code == 201
    case_data = create_resp.json()
    case_id = case_data["id"]
    assert case_data["case_number"].startswith("CASE-")

    # Add Note
    note_resp = client.post(f"/api/cases/{case_id}/notes", json={
        "content": "Analyst performed initial investigation. Header spoofing confirmed."
    }, headers=auth_headers)
    assert note_resp.status_code == 200
    assert note_resp.json()["content"] == "Analyst performed initial investigation. Header spoofing confirmed."

    # Update Case status
    patch_resp = client.patch(f"/api/cases/{case_id}", json={
        "status": "INVESTIGATING"
    }, headers=auth_headers)
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "INVESTIGATING"
