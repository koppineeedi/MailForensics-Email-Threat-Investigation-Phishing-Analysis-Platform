from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import EmailSample, EmailHeader, ReceivedHop, AuthenticationResult
from app.schemas.schemas import EmailHeaderSchema, ReceivedHopSchema, AuthenticationResultSchema
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/emails/{id}", tags=["Headers & Authentication"])

@router.get("/headers", response_model=List[EmailHeaderSchema])
def get_email_headers(id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    return sample.headers

@router.get("/received-chain", response_model=List[ReceivedHopSchema])
def get_email_received_chain(id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    return db.query(ReceivedHop).filter(ReceivedHop.email_id == id).order_by(ReceivedHop.hop_order.asc()).all()

@router.get("/authentication", response_model=AuthenticationResultSchema)
def get_email_authentication_results(id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    auth = db.query(AuthenticationResult).filter(AuthenticationResult.email_id == id).first()
    if not auth:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authentication results not found.")
    return auth
