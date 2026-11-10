"""
Analytics API — Real database metrics for the SOC dashboard.
All numbers come from actual database queries; no fabricated data.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, and_
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..database import get_db
from ..models.models import (
    EmailSample, URLItem, PhishingFinding, AttachmentFinding,
    AnalystVerdict, AuditLog, EmailCase, User
)
from .deps import get_current_user
from ..models.models import User as UserModel

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _date_filter(model_col, days: Optional[int]):
    if days:
        cutoff = _utc_now() - timedelta(days=days)
        return model_col >= cutoff
    return None


@router.get("/summary")
def get_analytics_summary(
    days: Optional[int] = Query(None, ge=1, le=365, description="Filter to last N days"),
    db: Session = Depends(get_db),
    _user: UserModel = Depends(get_current_user),
):
    """
    Top-level SOC metrics.  Returns real counts from the database.
    """
    df = _date_filter(EmailSample.upload_timestamp, days)

    base_q = db.query(EmailSample)
    if df is not None:
        base_q = base_q.filter(df)

    total_emails = base_q.count()

    phishing_emails = base_q.filter(
        EmailSample.risk_category.in_(["HIGH", "CRITICAL"])
    ).count()

    suspicious_emails = base_q.filter(
        EmailSample.risk_category.in_(["SUSPICIOUS", "HIGH", "CRITICAL"])
    ).count()

    critical_emails = base_q.filter(EmailSample.risk_category == "CRITICAL").count()

    # URL stats
    url_q = db.query(URLItem)
    if days:
        url_q = url_q.join(EmailSample).filter(df)
    total_urls = url_q.count()
    suspicious_urls = url_q.filter(
        (URLItem.is_ip_based == True)
        | (URLItem.is_suspicious_tld == True)
        | (URLItem.contains_credentials == True)
        | (URLItem.is_punycode == True)
    ).count()

    # Open cases
    open_cases = db.query(EmailCase).filter(
        EmailCase.status.in_(["OPEN", "INVESTIGATING"])
    ).count()

    # Safe vs suspicious (email level)
    safe_emails = base_q.filter(
        EmailSample.risk_category.in_(["LOW", "GUARDED"])
    ).count()

    return {
        "total_emails_analyzed": total_emails,
        "total_urls_analyzed": total_urls,
        "phishing_emails_detected": phishing_emails,
        "suspicious_emails": suspicious_emails,
        "suspicious_urls_detected": suspicious_urls,
        "critical_threats": critical_emails,
        "open_cases": open_cases,
        "safe_emails": safe_emails,
        "period_days": days,
    }


@router.get("/risk-distribution")
def get_risk_distribution(
    days: Optional[int] = Query(None, ge=1, le=365),
    db: Session = Depends(get_db),
    _user: UserModel = Depends(get_current_user),
):
    """Email count by risk category."""
    df = _date_filter(EmailSample.upload_timestamp, days)
    q = db.query(EmailSample.risk_category, func.count(EmailSample.id).label("count"))
    if df is not None:
        q = q.filter(df)
    rows = q.group_by(EmailSample.risk_category).all()

    order = ["LOW", "GUARDED", "SUSPICIOUS", "HIGH", "CRITICAL"]
    dist = {cat: 0 for cat in order}
    for row in rows:
        if row.risk_category in dist:
            dist[row.risk_category] = row.count

    return {
        "distribution": [
            {"category": k, "count": v, "color": _risk_color(k)}
            for k, v in dist.items()
        ],
        "period_days": days,
    }


@router.get("/detection-types")
def get_top_detection_types(
    days: Optional[int] = Query(None, ge=1, le=365),
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    _user: UserModel = Depends(get_current_user),
):
    """Most common phishing finding types from the database."""
    q = db.query(
        PhishingFinding.finding_code,
        PhishingFinding.category,
        func.count(PhishingFinding.id).label("count"),
    )
    if days:
        cutoff = _utc_now() - timedelta(days=days)
        q = q.filter(PhishingFinding.created_at >= cutoff)
    rows = q.group_by(
        PhishingFinding.finding_code, PhishingFinding.category
    ).order_by(func.count(PhishingFinding.id).desc()).limit(limit).all()

    return {
        "top_detections": [
            {"code": r.finding_code, "category": r.category, "count": r.count}
            for r in rows
        ],
        "period_days": days,
    }


@router.get("/activity-timeline")
def get_activity_timeline(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _user: UserModel = Depends(get_current_user),
):
    """Daily email analysis counts for the given period."""
    cutoff = _utc_now() - timedelta(days=days)

    rows = db.query(
        func.date(EmailSample.upload_timestamp).label("date"),
        func.count(EmailSample.id).label("total"),
        func.sum(
            case((EmailSample.risk_category.in_(["HIGH", "CRITICAL"]), 1), else_=0)
        ).label("high_risk"),
    ).filter(
        EmailSample.upload_timestamp >= cutoff
    ).group_by(
        func.date(EmailSample.upload_timestamp)
    ).order_by(
        func.date(EmailSample.upload_timestamp)
    ).all()

    return {
        "timeline": [
            {
                "date": str(r.date),
                "total": r.total,
                "high_risk": int(r.high_risk or 0),
            }
            for r in rows
        ],
        "period_days": days,
    }


@router.get("/verdict-distribution")
def get_verdict_distribution(
    days: Optional[int] = Query(None, ge=1, le=365),
    db: Session = Depends(get_db),
    _user: UserModel = Depends(get_current_user),
):
    """Analyst verdict breakdown."""
    q = db.query(
        AnalystVerdict.verdict,
        func.count(AnalystVerdict.id).label("count"),
    )
    if days:
        cutoff = _utc_now() - timedelta(days=days)
        q = q.filter(AnalystVerdict.created_at >= cutoff)
    rows = q.group_by(AnalystVerdict.verdict).all()
    return {
        "verdicts": [{"verdict": r.verdict, "count": r.count} for r in rows],
        "period_days": days,
    }


@router.get("/recent-incidents")
def get_recent_incidents(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    _user: UserModel = Depends(get_current_user),
):
    """Most recent high/critical emails as security incidents."""
    rows = db.query(EmailSample).filter(
        EmailSample.risk_category.in_(["HIGH", "CRITICAL"])
    ).order_by(EmailSample.upload_timestamp.desc()).limit(limit).all()

    return {
        "incidents": [
            {
                "id": r.id,
                "subject": (r.subject or r.original_filename or "")[:80],
                "sender": r.sender or "unknown",
                "risk_score": r.risk_score,
                "risk_category": r.risk_category,
                "upload_timestamp": r.upload_timestamp.isoformat() if r.upload_timestamp else None,
                "data_source": r.data_source,
            }
            for r in rows
        ]
    }


@router.get("/severity-distribution")
def get_severity_distribution(
    days: Optional[int] = Query(None, ge=1, le=365),
    db: Session = Depends(get_db),
    _user: UserModel = Depends(get_current_user),
):
    """Finding severity breakdown across all phishing findings."""
    q = db.query(
        PhishingFinding.severity,
        func.count(PhishingFinding.id).label("count"),
    )
    if days:
        cutoff = _utc_now() - timedelta(days=days)
        q = q.filter(PhishingFinding.created_at >= cutoff)
    rows = q.group_by(PhishingFinding.severity).all()
    return {
        "severity_distribution": [
            {"severity": r.severity, "count": r.count, "color": _sev_color(r.severity)}
            for r in rows
        ],
        "period_days": days,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _risk_color(cat: str) -> str:
    return {
        "LOW": "#10B981",
        "GUARDED": "#EAB308",
        "SUSPICIOUS": "#F59E0B",
        "HIGH": "#F97316",
        "CRITICAL": "#F43F5E",
    }.get(cat, "#64748B")


def _sev_color(sev: str) -> str:
    return {
        "LOW": "#38BDF8",
        "MEDIUM": "#FBBF24",
        "HIGH": "#FB923C",
        "CRITICAL": "#F43F5E",
    }.get(sev, "#64748B")
