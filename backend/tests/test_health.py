import pytest

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "app_name" in data

def test_health_live_endpoint(client):
    res = client.get("/health/live")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"

def test_health_ready_endpoint(client):
    res = client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert "overall_status" in data
    assert "components" in data
    assert data["overall_status"] in ["READY", "DEGRADED"]

def test_system_status_endpoint(client, auth_headers):
    res = client.get("/api/system/status", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "overall_status" in data
    assert "processing_mode" in data
    assert "components" in data

    components = data["components"]
    assert "database" in components
    assert "redis" in components
    assert "celery" in components
    assert "yara" in components
    assert "dns" in components
    assert "storage" in components
    assert "threat_intelligence" in components

    # Verify real attributes
    assert components["database"]["status"] in ["HEALTHY", "DEGRADED", "ERROR"]
    assert components["yara"]["engine"] == "NATIVE"
    assert components["yara"]["rule_compilation_verified"] is True
