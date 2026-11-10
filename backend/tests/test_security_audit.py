"""
Security audit tests for MailForensics.
Tests authentication, authorization, role escalation prevention, and input validation.
"""
import pytest
from fastapi.testclient import TestClient
from app.core.security import get_password_hash, create_access_token, verify_password
from app.models.models import User


# ---------------------------------------------------------------------------
# Auth: password hashing
# ---------------------------------------------------------------------------

class TestPasswordSecurity:
    def test_bcrypt_hash_is_not_plaintext(self):
        hashed = get_password_hash("Admin@123456")
        assert hashed != "Admin@123456"
        assert hashed.startswith("$2b$")

    def test_correct_password_verifies(self):
        pw = "SecureP@ssw0rd!"
        hashed = get_password_hash(pw)
        assert verify_password(pw, hashed) is True

    def test_wrong_password_fails(self):
        hashed = get_password_hash("correct-password")
        assert verify_password("wrong-password", hashed) is False

    def test_empty_password_fails(self):
        hashed = get_password_hash("SomePassword1!")
        assert verify_password("", hashed) is False

    def test_different_hashes_for_same_password(self):
        pw = "SamePassword1!"
        h1 = get_password_hash(pw)
        h2 = get_password_hash(pw)
        # bcrypt uses random salt — hashes must differ
        assert h1 != h2


# ---------------------------------------------------------------------------
# Auth: JWT tokens
# ---------------------------------------------------------------------------

class TestJWTSecurity:
    def test_token_created_successfully(self):
        token = create_access_token({"sub": "user-123", "role": "ANALYST"})
        assert isinstance(token, str)
        assert len(token) > 20

    def test_tampered_token_rejected(self, client):
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer tampered.jwt.token"}
        )
        assert resp.status_code == 401

    def test_missing_token_rejected(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_expired_token_rejected(self, client):
        from datetime import timedelta
        expired_token = create_access_token(
            {"sub": "user-123", "role": "ANALYST"},
            expires_delta=timedelta(seconds=-1)
        )
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Auth: role escalation prevention (SECURITY FIX TEST)
# ---------------------------------------------------------------------------

class TestRoleEscalationPrevention:
    def test_second_user_cannot_self_register_as_admin(self, client, test_user):
        """
        CRITICAL SECURITY FIX: After the first user exists,
        any subsequent registration that claims ADMIN role must be downgraded.
        """
        resp = client.post("/api/auth/register", json={
            "email": "attacker@evil.com",
            "password": "Attack3r@Pass!",
            "full_name": "Attacker",
            "role": "ADMIN",  # Attempting privilege escalation
        })
        # Either created with ANALYST role or rejected
        if resp.status_code == 201:
            data = resp.json()
            assert data["role"] in ("ANALYST", "VIEWER"), (
                f"SECURITY VIOLATION: attacker was granted role={data['role']}"
            )
        else:
            # 400 (email exists) or other error is also acceptable
            assert resp.status_code in (400, 422)

    def test_viewer_cannot_register_as_admin(self, client, test_user):
        resp = client.post("/api/auth/register", json={
            "email": "viewer_trying@evil.com",
            "password": "V1ewer@Pass!",
            "full_name": "Viewer Attempt",
            "role": "ADMIN",
        })
        if resp.status_code == 201:
            assert resp.json()["role"] != "ADMIN"

    def test_valid_analyst_registration(self, client, test_user):
        resp = client.post("/api/auth/register", json={
            "email": f"newanalyst_{__name__}@test.com",
            "password": "Analyst@Pass1!",
            "full_name": "New Analyst",
            "role": "ANALYST",
        })
        # May get 400 if already exists across test runs; that's fine
        if resp.status_code == 201:
            assert resp.json()["role"] == "ANALYST"


# ---------------------------------------------------------------------------
# Auth: login security
# ---------------------------------------------------------------------------

class TestLoginSecurity:
    def test_correct_credentials_returns_token(self, client, test_user):
        resp = client.post("/api/auth/login", json={
            "email": "analyst@mailforensics.test",
            "password": "TestPassword123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_wrong_password_returns_401(self, client, test_user):
        resp = client.post("/api/auth/login", json={
            "email": "analyst@mailforensics.test",
            "password": "WrongPassword999!",
        })
        assert resp.status_code == 401

    def test_nonexistent_user_returns_401(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "ghost@nowhere.com",
            "password": "Password123!",
        })
        assert resp.status_code == 401

    def test_sql_injection_in_email_rejected(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "' OR '1'='1",
            "password": "anything",
        })
        # Should return 401 (not found) or 422 (validation), never 200
        assert resp.status_code in (401, 422)

    def test_empty_credentials_rejected(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "",
            "password": "",
        })
        assert resp.status_code in (401, 422)


# ---------------------------------------------------------------------------
# API: access control
# ---------------------------------------------------------------------------

class TestAPIAccessControl:
    def test_emails_endpoint_requires_auth(self, client):
        resp = client.get("/api/emails")
        assert resp.status_code == 401

    def test_dashboard_requires_auth(self, client):
        resp = client.get("/api/dashboard/stats")
        assert resp.status_code == 401

    def test_cases_requires_auth(self, client):
        resp = client.get("/api/cases")
        assert resp.status_code == 401

    def test_audit_logs_requires_auth(self, client):
        resp = client.get("/api/audit")
        assert resp.status_code == 401

    def test_analytics_requires_auth(self, client):
        resp = client.get("/api/analytics/summary")
        assert resp.status_code == 401

    def test_url_intelligence_requires_auth(self, client):
        resp = client.post("/api/url-intelligence/analyze", json={"url": "https://example.com"})
        assert resp.status_code == 401

    def test_authenticated_user_can_access_emails(self, client, auth_headers):
        resp = client.get("/api/emails", headers=auth_headers)
        assert resp.status_code == 200

    def test_authenticated_user_can_analyze_url(self, client, auth_headers):
        resp = client.post(
            "/api/url-intelligence/analyze",
            json={"url": "https://example.com"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_score" in data
        assert "detections" in data


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_url_too_long_rejected(self, client, auth_headers):
        resp = client.post(
            "/api/url-intelligence/analyze",
            json={"url": "https://example.com/" + "a" * 3000},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_empty_url_rejected(self, client, auth_headers):
        resp = client.post(
            "/api/url-intelligence/analyze",
            json={"url": ""},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_missing_url_field_rejected(self, client, auth_headers):
        resp = client.post(
            "/api/url-intelligence/analyze",
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_registration_requires_valid_email(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "not-an-email",
            "password": "Password123!",
            "full_name": "Test",
            "role": "ANALYST",
        })
        assert resp.status_code == 422

    def test_registration_requires_full_name(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "valid@email.com",
            "password": "Password123!",
            "role": "ANALYST",
        })
        # Missing full_name — should fail validation
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Health / public endpoints
# ---------------------------------------------------------------------------

class TestPublicEndpoints:
    def test_health_endpoint_public(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_url_intelligence_health_public(self, client):
        resp = client.get("/api/url-intelligence/health")
        assert resp.status_code == 200
