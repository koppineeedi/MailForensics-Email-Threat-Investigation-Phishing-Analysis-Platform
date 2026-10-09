from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import EmailSample, Attachment
from app.schemas.schemas import AttachmentSchema
from app.api.deps import get_current_user

router = APIRouter(prefix="/api", tags=["Attachments"])

@router.get("/emails/{id}/attachments", response_model=List[AttachmentSchema])
def get_attachments_for_email(id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    return sample.attachments

@router.get("/attachments/{attachment_id}", response_model=AttachmentSchema)
def get_attachment_detail(attachment_id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    att = db.query(Attachment).filter(Attachment.id == attachment_id).first()
    if not att:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment not found.")
    return att
