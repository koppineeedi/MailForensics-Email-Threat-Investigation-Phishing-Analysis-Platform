import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import EmailCase, CaseEmail, CaseNote, EmailSample, User
from app.schemas.schemas import CaseCreate, CaseUpdate, CaseSchema, CaseNoteCreate, CaseNoteSchema
from app.api.deps import get_current_user
from app.core.audit_logger import log_audit_event

router = APIRouter(prefix="/api/cases", tags=["Case Management"])

def generate_case_number(db: Session) -> str:
    count = db.query(EmailCase).count() + 1
    return f"CASE-{datetime.utcnow().strftime('%Y%m')}-{count:04d}"

@router.post("", response_model=CaseSchema, status_code=status.HTTP_201_CREATED)
def create_case(
    case_in: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    case_num = generate_case_number(db)
    case_obj = EmailCase(
        case_number=case_num,
        title=case_in.title,
        description=case_in.description,
        priority=case_in.priority,
        severity=case_in.severity,
        status="OPEN",
        created_by_id=current_user.id,
        assigned_analyst_id=current_user.id
    )
    db.add(case_obj)
    db.commit()
    db.refresh(case_obj)

    if case_in.email_ids:
        for email_id in case_in.email_ids:
            assoc = CaseEmail(case_id=case_obj.id, email_id=email_id)
            db.add(assoc)
        db.commit()

    log_audit_event(db, action="CASE_CREATE", resource="CASE", resource_id=case_obj.id, user=current_user)
    return case_obj

@router.get("", response_model=List[CaseSchema])
def list_cases(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(EmailCase).order_by(EmailCase.created_at.desc()).all()

@router.get("/{id}", response_model=CaseSchema)
def get_case_detail(id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    c = db.query(EmailCase).filter(EmailCase.id == id).first()
    if not c:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return c

@router.patch("/{id}", response_model=CaseSchema)
def update_case(
    id: str,
    case_in: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    c = db.query(EmailCase).filter(EmailCase.id == id).first()
    if not c:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    
    if case_in.title is not None:
        c.title = case_in.title
    if case_in.description is not None:
        c.description = case_in.description
    if case_in.priority is not None:
        c.priority = case_in.priority
    if case_in.severity is not None:
        c.severity = case_in.severity
    if case_in.assigned_analyst_id is not None:
        c.assigned_analyst_id = case_in.assigned_analyst_id
    if case_in.status is not None:
        c.status = case_in.status
        if case_in.status in ["RESOLVED", "CLOSED"] and not c.closed_at:
            c.closed_at = datetime.utcnow()

    db.commit()
    db.refresh(c)
    log_audit_event(db, action="CASE_UPDATE", resource="CASE", resource_id=c.id, user=current_user)
    return c

@router.post("/{id}/emails", response_model=CaseSchema)
def link_email_to_case(
    id: str,
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    c = db.query(EmailCase).filter(EmailCase.id == id).first()
    email_sample = db.query(EmailSample).filter(EmailSample.id == email_id).first()
    if not c or not email_sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case or Email sample not found.")
    
    existing = db.query(CaseEmail).filter(CaseEmail.case_id == id, CaseEmail.email_id == email_id).first()
    if not existing:
        assoc = CaseEmail(case_id=id, email_id=email_id)
        db.add(assoc)
        db.commit()

    db.refresh(c)
    log_audit_event(db, action="CASE_LINK_EMAIL", resource="CASE", resource_id=id, user=current_user, metadata={"email_id": email_id})
    return c

@router.post("/{id}/notes", response_model=CaseNoteSchema)
def add_note_to_case(
    id: str,
    note_in: CaseNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    c = db.query(EmailCase).filter(EmailCase.id == id).first()
    if not c:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    
    note = CaseNote(
        case_id=id,
        author_id=current_user.id,
        content=note_in.content
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    log_audit_event(db, action="CASE_ADD_NOTE", resource="CASE", resource_id=id, user=current_user)
    return note
