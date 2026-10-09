import os
import logging
from celery import Celery
from app.config import settings

logger = logging.getLogger(__name__)

broker_url = settings.CELERY_BROKER_URL or settings.REDIS_URL
backend_url = settings.CELERY_RESULT_BACKEND or settings.REDIS_URL

celery_app = Celery(
    "mailforensics",
    broker=broker_url,
    backend=backend_url,
    include=["app.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300, # 5 minutes hard cap
    task_soft_time_limit=240,
    worker_prefetch_multiplier=1
)

def check_redis_connection() -> dict:
    """
    Check connection to Redis broker/cache.
    Guaranteed not to throw an unhandled exception.
    """
    status_info = {
        "status": "UNAVAILABLE",
        "url": broker_url.split("@")[-1] if "@" in broker_url else broker_url,
        "detail": None
    }
    try:
        import redis
        client = redis.Redis.from_url(broker_url, socket_timeout=2.0)
        client.ping()
        status_info["status"] = "HEALTHY"
        status_info["detail"] = "Redis broker connection responsive"
    except Exception as e:
        status_info["status"] = "UNAVAILABLE"
        status_info["detail"] = f"Redis unreachable: {str(e)}"
    return status_info

def check_celery_status() -> dict:
    """
    Check if Celery worker is active.
    """
    status_info = {
        "mode": settings.PROCESSING_MODE,
        "status": "STANDBY" if settings.PROCESSING_MODE == "local" else "UNAVAILABLE",
        "active_workers": 0,
        "detail": "Local synchronous processing mode enabled" if settings.PROCESSING_MODE == "local" else None
    }
    if settings.PROCESSING_MODE == "celery":
        try:
            inspector = celery_app.control.inspect(timeout=1.0)
            ping_res = inspector.ping() if inspector else None
            if ping_res:
                status_info["status"] = "HEALTHY"
                status_info["active_workers"] = len(ping_res)
                status_info["detail"] = f"Connected to {len(ping_res)} Celery worker(s)"
            else:
                status_info["status"] = "UNAVAILABLE"
                status_info["detail"] = "No active Celery workers responding on broker"
        except Exception as e:
            status_info["status"] = "UNAVAILABLE"
            status_info["detail"] = str(e)
    return status_info
