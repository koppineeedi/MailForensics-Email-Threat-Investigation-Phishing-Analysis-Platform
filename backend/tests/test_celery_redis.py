import pytest
from unittest.mock import patch, MagicMock
from app.celery_app import celery_app, check_redis_connection, check_celery_status
from app.tasks import analyze_email_task
from app.config import settings

def test_celery_app_configuration():
    assert celery_app is not None
    assert celery_app.main == "mailforensics"
    # Check that analyze_email_task is registered
    assert "app.tasks.analyze_email_task" in celery_app.tasks or "mailforensics.analyze_email" in celery_app.tasks or analyze_email_task.name in celery_app.tasks

def test_check_redis_connection_when_offline():
    # In test environment, Redis may or may not be running. Probing should be safe and return dict
    res = check_redis_connection()
    assert isinstance(res, dict)
    assert "status" in res
    assert res["status"] in ["HEALTHY", "UNAVAILABLE"]

def test_check_redis_connection_mocked():
    with patch("redis.Redis.from_url") as mock_redis:
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis.return_value = mock_client

        res = check_redis_connection()
        assert res["status"] == "HEALTHY"
        assert "responsive" in res["detail"]

def test_check_celery_status():
    status = check_celery_status()
    assert "status" in status
    assert "mode" in status
    assert "active_workers" in status
    assert status["mode"] in ["local", "celery"]
