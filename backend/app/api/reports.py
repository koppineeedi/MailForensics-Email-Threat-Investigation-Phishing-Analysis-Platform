import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import EmailSample, Report, User, EmailCase
from app.schemas.schemas import EmailSampleDetail, CaseSchema
from app.services.report_generator import generate_json_report, generate_pdf_report
from app.api.deps import get_current_user
from app.core.audit_logger import log_audit_event

router = APIRouter(prefix="/api", tags=["Reports"])

@router.post("/emails/{id}/report")
def create_email_report(
    id: str,
    report_type: str = "PDF", # JSON or PDF
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    
    # Serialize sample data
    sample_detail = EmailSampleDetail.model_validate(sample).model_dump(mode="json")

    case_data = None
    if sample.case_associations:
        case_obj = sample.case_associations[0].case
        if case_obj:
            case_data = {
                "case_number": case_obj.case_number,
                "title": case_obj.title,
                "status": case_obj.status,
                "priority": case_obj.priority
            }

    if report_type.upper() == "PDF":
        pdf_path = generate_pdf_report(sample_detail, case_data)
        rep = Report(
            email_id=id,
            case_id=case_obj.id if sample.case_associations and sample.case_associations[0].case else None,
            report_type="PDF",
            pdf_file_path=pdf_path,
            generated_by_id=current_user.id
        )
        db.add(rep)
        db.commit()
        db.refresh(rep)
        log_audit_event(db, action="REPORT_GENERATE_PDF", resource="REPORT", resource_id=rep.id, user=current_user)
        return {"report_id": rep.id, "report_type": "PDF", "pdf_url": f"/api/reports/{rep.id}/download"}

    else:
        json_data = generate_json_report(sample_detail, case_data)
        rep = Report(
            email_id=id,
            case_id=case_obj.id if sample.case_associations and sample.case_associations[0].case else None,
            report_type="JSON",
            report_data_json=json_data,
            generated_by_id=current_user.id
        )
        db.add(rep)
        db.commit()
        db.refresh(rep)
        log_audit_event(db, action="REPORT_GENERATE_JSON", resource="REPORT", resource_id=rep.id, user=current_user)
        return json_data

from app.services.stix_generator import generate_stix_bundle

@router.get("/reports/{id}/download")
def download_pdf_report(id: str, db: Session = Depends(get_db)):
    rep = db.query(Report).filter(Report.id == id).first()
    if not rep or not rep.pdf_file_path or not os.path.exists(rep.pdf_file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PDF report file not found.")
    
    return FileResponse(
        path=rep.pdf_file_path,
        filename=os.path.basename(rep.pdf_file_path),
        media_type="application/pdf"
    )

@router.get("/emails/{id}/stix")
@router.get("/reports/{id}/stix")
def export_stix_report(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Export observable forensic indicators and email artifacts as a STIX 2.1 JSON Bundle.
    """
    # Try finding email by email_id directly, or by report_id
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        rep = db.query(Report).filter(Report.id == id).first()
        if rep and rep.email_id:
            sample = db.query(EmailSample).filter(EmailSample.id == rep.email_id).first()

    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic sample not found for STIX export.")

    sample_detail = EmailSampleDetail.model_validate(sample).model_dump(mode="json")
    stix_bundle = generate_stix_bundle(sample_detail)
    log_audit_event(db, action="EXPORT_STIX_BUNDLE", resource="EMAIL_SAMPLE", resource_id=sample.id, user=current_user)
    return stix_bundle

