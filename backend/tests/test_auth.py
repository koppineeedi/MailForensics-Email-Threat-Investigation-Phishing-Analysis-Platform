def test_user_registration_and_login(client):
    reg_resp = client.post("/api/auth/register", json={
        "email": "new_analyst@mailforensics.test",
        "password": "Password123!",
        "full_name": "New Analyst",
        "role": "ANALYST"
    })
    assert reg_resp.status_code == 201
    data = reg_resp.json()
    assert data["email"] == "new_analyst@mailforensics.test"

    login_resp = client.post("/api/auth/login", json={
        "email": "new_analyst@mailforensics.test",
        "password": "Password123!"
    })
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "new_analyst@mailforensics.test"
