from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import EmailSample, URLItem
from app.schemas.schemas import URLItemSchema
from app.api.deps import get_current_user

router = APIRouter(prefix="/api", tags=["Extracted URLs"])

@router.get("/emails/{id}/urls", response_model=List[URLItemSchema])
def get_urls_for_email(id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    return sample.urls

@router.get("/urls/{url_id}", response_model=URLItemSchema)
def get_url_detail(url_id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    url_item = db.query(URLItem).filter(URLItem.id == url_id).first()
    if not url_item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL item not found.")
    return url_item
