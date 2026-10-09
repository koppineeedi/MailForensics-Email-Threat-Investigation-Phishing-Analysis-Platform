from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import AuditLog
from app.schemas.schemas import AuditLogSchema
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/audit", tags=["Audit Logging"])

@router.get("", response_model=List[AuditLogSchema])
def list_audit_logs(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List append-only audit logs.
    Restricted access for security auditing.
    """
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
