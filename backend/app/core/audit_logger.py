from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.models import AuditLog, User

def log_audit_event(
    db: Session,
    action: str,
    resource: str,
    resource_id: Optional[str] = None,
    user: Optional[User] = None,
    outcome: str = "SUCCESS",
    metadata: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """
    Append-only audit logger.
    Sanitizes any secret fields from metadata to prevent leaking passwords, tokens, or API keys.
    """
    sanitized_metadata = {}
    if metadata:
        for k, v in metadata.items():
            key_lower = str(k).lower()
            if any(secret_term in key_lower for secret_term in ["password", "token", "secret", "key", "authorization", "cred"]):
                sanitized_metadata[k] = "[REDACTED_SECRET]"
            else:
                sanitized_metadata[k] = v

    audit_entry = AuditLog(
        user_id=user.id if user else None,
        user_email=user.email if user else "SYSTEM",
        action=action,
        resource=resource,
        resource_id=resource_id,
        outcome=outcome,
        metadata_json=sanitized_metadata
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry
