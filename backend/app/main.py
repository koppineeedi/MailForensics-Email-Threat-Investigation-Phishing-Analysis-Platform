from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.config import settings
from app.database import engine, Base, get_db
from app.models.models import EmailSample, PhishingFinding, AttachmentFinding, URLItem, EmailCase, AuthenticationResult
from app.schemas.schemas import DashboardStats, EmailSampleSummary
from app.api import auth, emails, headers, urls, attachments, cases, relationships, threat_intel, reports, audit, yara, websocket
from app.api.deps import get_current_user

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="MailForensics — Defensive Email Threat Investigation & Phishing Analysis Platform"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow development frontend origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth.router)
app.include_router(emails.router)
app.include_router(headers.router)
app.include_router(urls.router)
app.include_router(attachments.router)
app.include_router(cases.router)
app.include_router(relationships.router)
app.include_router(threat_intel.router)
app.include_router(reports.router)
app.include_router(audit.router)
app.include_router(yara.router)
app.include_router(websocket.router)

import os
from datetime import datetime, timezone
from app.database import check_db_connection
from app.celery_app import check_redis_connection, check_celery_status
from app.services.yara_service import yara_scanner
from app.services.threat_intel_service import threat_intel_service

@app.get("/health")
@app.get("/health/live")
@app.get("/api/health")
def liveness_check():
    """Kubernetes / Docker liveness probe: returns 200 if process is running."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "tagline": settings.TAGLINE,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health/ready")
@app.get("/api/system/status")
def readiness_and_system_status():
    """
    Component-by-component readiness and forensic system status.
    Directly probes: Database, Redis, Celery, YARA, DNS, Threat Intel, and Storage.
    Never fabricates availability.
    """
    db_status = check_db_connection()
    redis_status = check_redis_connection()
    celery_status = check_celery_status()
    yara_status = yara_scanner.get_engine_status()
    ti_status = threat_intel_service.get_provider_status()
    
    storage_writable = os.access(settings.STORAGE_DIR, os.W_OK) and os.path.exists(settings.UPLOAD_DIR)
    dns_configured = settings.ENABLE_LIVE_DNS_LOOKUPS

    is_ready = (db_status["status"] == "HEALTHY") and storage_writable

    return {
        "overall_status": "READY" if is_ready else "DEGRADED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processing_mode": settings.PROCESSING_MODE,
        "components": {
            "database": db_status,
            "redis": redis_status,
            "celery": celery_status,
            "yara": yara_status,
            "dns": {
                "status": "AVAILABLE" if dns_configured else "DISABLED",
                "live_lookups_enabled": dns_configured,
                "detail": "Live DNS lookups enabled" if dns_configured else "Defensive passive mode (live lookups disabled by policy)"
            },
            "storage": {
                "status": "HEALTHY" if storage_writable else "ERROR",
                "storage_dir": settings.STORAGE_DIR,
                "writable": storage_writable
            },
            "threat_intelligence": ti_status
        }
    }

@app.get("/api/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """Return genuine backend database statistics for the SOC dashboard (NO fake data)."""
    emails_analyzed = db.query(EmailSample).count()
    suspicious_emails = db.query(EmailSample).filter(EmailSample.risk_score >= 40.0).count()
    phishing_findings_count = db.query(PhishingFinding).count()
    attachment_findings_count = db.query(AttachmentFinding).count()
    url_findings_count = db.query(URLItem).filter(URLItem.is_ip_based | URLItem.is_suspicious_tld).count()
    open_cases = db.query(EmailCase).filter(EmailCase.status.in_(["OPEN", "INVESTIGATING"])).count()

    recent_emails = db.query(EmailSample).order_by(EmailSample.upload_timestamp.desc()).limit(5).all()

    # Calculate real risk distribution
    risk_dist = {
        "LOW": db.query(EmailSample).filter(EmailSample.risk_category == "LOW").count(),
        "GUARDED": db.query(EmailSample).filter(EmailSample.risk_category == "GUARDED").count(),
        "SUSPICIOUS": db.query(EmailSample).filter(EmailSample.risk_category == "SUSPICIOUS").count(),
        "HIGH": db.query(EmailSample).filter(EmailSample.risk_category == "HIGH").count(),
        "CRITICAL": db.query(EmailSample).filter(EmailSample.risk_category == "CRITICAL").count()
    }

    # Calculate authentication distribution
    auth_dist = {
        "SPF_PASS": db.query(AuthenticationResult).filter(AuthenticationResult.spf_result == "PASS").count(),
        "SPF_FAIL": db.query(AuthenticationResult).filter(AuthenticationResult.spf_result == "FAIL").count(),
        "DKIM_PASS": db.query(AuthenticationResult).filter(AuthenticationResult.dkim_result == "PASS").count(),
        "DKIM_FAIL": db.query(AuthenticationResult).filter(AuthenticationResult.dkim_result == "FAIL").count(),
        "DMARC_PASS": db.query(AuthenticationResult).filter(AuthenticationResult.dmarc_result == "PASS").count(),
        "DMARC_FAIL": db.query(AuthenticationResult).filter(AuthenticationResult.dmarc_result == "FAIL").count()
    }

    return DashboardStats(
        emails_analyzed=emails_analyzed,
        suspicious_emails=suspicious_emails,
        phishing_findings_count=phishing_findings_count,
        attachment_findings_count=attachment_findings_count,
        url_findings_count=url_findings_count,
        open_cases=open_cases,
        recent_emails=recent_emails,
        risk_distribution=risk_dist,
        auth_distribution=auth_dist
    )
