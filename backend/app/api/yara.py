from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from app.database import get_db
from app.models.models import YaraRule, User
from app.schemas.schemas import YaraRuleCreate, YaraRuleSchema
from app.services.yara_service import yara_scanner, DEFAULT_DEFENSIVE_YARA_RULES
from app.api.deps import get_current_user
from app.core.audit_logger import log_audit_event

router = APIRouter(prefix="/api/yara", tags=["YARA Lab"])

@router.get("/status")
def get_yara_status():
    return yara_scanner.get_engine_status()

@router.get("/rules", response_model=List[YaraRuleSchema])
def list_yara_rules(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    rules = db.query(YaraRule).all()
    if not rules:
        # Seed default rules
        for r in DEFAULT_DEFENSIVE_YARA_RULES:
            rule_obj = YaraRule(
                rule_name=r["rule_name"],
                category=r["category"],
                severity=r["severity"],
                description=r["description"],
                rule_content=r["rule_content"],
                is_enabled=r["is_enabled"]
            )
            db.add(rule_obj)
        db.commit()
        rules = db.query(YaraRule).all()
    return rules

@router.post("/rules", response_model=YaraRuleSchema, status_code=status.HTTP_201_CREATED)
def create_yara_rule(
    rule_in: YaraRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing = db.query(YaraRule).filter(YaraRule.rule_name == rule_in.rule_name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Rule name already exists.")

    rule_obj = YaraRule(
        rule_name=rule_in.rule_name,
        category=rule_in.category,
        severity=rule_in.severity,
        description=rule_in.description,
        rule_content=rule_in.rule_content
    )
    db.add(rule_obj)
    db.commit()
    db.refresh(rule_obj)

    log_audit_event(db, action="YARA_RULE_CREATE", resource="YARA_RULE", resource_id=rule_obj.id, user=current_user)
    return rule_obj
