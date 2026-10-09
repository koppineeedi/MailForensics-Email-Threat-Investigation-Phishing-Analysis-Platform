def test_relationship_graph_endpoint(client, auth_headers):
    resp = client.get("/api/relationships", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
