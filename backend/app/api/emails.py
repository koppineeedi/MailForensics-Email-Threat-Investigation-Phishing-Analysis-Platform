import os
import asyncio
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, BackgroundTasks
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import (
    EmailSample, EmailHeader, ReceivedHop, AuthenticationResult, EmailAddress,
    EmailDomain, URLItem, Attachment, AttachmentFinding, PhishingFinding,
    ThreatIntelResult, EmailEvent, AnalystVerdict, User
)
from app.schemas.schemas import (
    EmailSampleSummary, EmailSampleDetail, AnalystVerdictCreate, AnalystVerdictSchema,
    EmailComparisonResult, ComparisonSection
)
from app.api.deps import get_current_user
from app.core.rbac import require_role, ROLE_ANALYST, ROLE_VIEWER, ROLE_ADMIN
from app.core.file_storage import save_uploaded_file, sanitize_filename
from app.core.audit_logger import log_audit_event
from datetime import datetime, timezone
import logging
from app.config import settings
from app.services.email_parser import parse_raw_email
from app.services.header_analyzer import analyze_headers
from app.services.received_chain import parse_received_headers
from app.services.spf_analyzer import parse_spf
from app.services.dkim_analyzer import parse_dkim
from app.services.dmarc_analyzer import parse_dmarc
from app.services.sender_domain_analyzer import analyze_sender_and_domains
from app.services.url_extractor import extract_urls
from app.services.attachment_analyzer import analyze_raw_attachments
from app.services.yara_service import yara_scanner, DEFAULT_DEFENSIVE_YARA_RULES
from app.services.dns_verifier import dns_verifier
from app.services.phishing_detector import run_phishing_detection_rules
from app.services.risk_engine import calculate_risk_score
from app.services.threat_intel_service import threat_intel_service
from app.services.demo_data_service import DEMO_SAMPLES
from app.websockets.manager import manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["Email Samples"])

async def publish_event(
    db: Session,
    email_id: str,
    event_type: str,
    title: str,
    description: str = None,
    metadata: dict = None,
    status: str = "COMPLETED",
    error: str = None
):
    """Persist event to database and broadcast standardized payload to WebSockets."""
    event = EmailEvent(
        email_id=email_id,
        event_type=event_type,
        title=title,
        description=description,
        event_metadata=metadata
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    
    event_payload = {
        "event_id": str(event.id),
        "email_id": email_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "status": status,
        "title": title,
        "description": description,
        "evidence": metadata,
        "error": error
    }
    await manager.broadcast_email_event(email_id, event_payload)

async def execute_email_analysis_pipeline(email_id: str, db: Session):
    """
    Execute backend email analysis pipeline.
    Emits real-time WebSocket events at each stage.
    """
    sample = db.query(EmailSample).filter(EmailSample.id == email_id).first()
    if not sample or not os.path.exists(sample.raw_storage_path):
        return

    sample.status = "ANALYZING"
    db.commit()

    try:
        with open(sample.raw_storage_path, "rb") as f:
            raw_bytes = f.read()

        # 1. Parse raw email
        parsed_data = parse_raw_email(raw_bytes)
        sample.message_id = parsed_data.get("message_id")
        sample.subject = parsed_data.get("subject")
        sample.sender = parsed_data.get("sender")
        sample.received_timestamp = parsed_data.get("received_timestamp")
        sample.body_plain = parsed_data.get("body_plain")
        sample.body_html = parsed_data.get("body_html")
        db.commit()

        # Store raw headers
        for h in parsed_data.get("headers", []):
            header_obj = EmailHeader(
                email_id=email_id,
                header_name=h["header_name"],
                header_value=h["header_value"],
                is_auth_header=h["is_auth_header"],
                hop_index=h["hop_index"]
            )
            db.add(header_obj)
        db.commit()

        await publish_event(
            db, email_id, "EMAIL_PARSED", "Email Parsed Successfully",
            f"Extracted structure, subject, sender, and {len(parsed_data.get('headers', []))} headers.",
            metadata={"subject": sample.subject, "headers_count": len(parsed_data.get("headers", []))}
        )

        # 2. Received Chain Analysis
        hops, received_anomalies = parse_received_headers(parsed_data.get("headers", []))
        for hop in hops:
            hop_obj = ReceivedHop(
                email_id=email_id,
                hop_order=hop["hop_order"],
                from_host=hop["from_host"],
                from_ip=hop["from_ip"],
                by_host=hop["by_host"],
                by_ip=hop["by_ip"],
                timestamp=hop["timestamp"],
                protocol=hop["protocol"],
                tls_version=hop["tls_version"],
                cipher=hop["cipher"],
                helo_domain=hop["helo_domain"],
                delay_seconds=hop["delay_seconds"],
                anomaly_detected=hop["anomaly_detected"],
                anomaly_details=hop["anomaly_details"]
            )
            db.add(hop_obj)
        db.commit()

        # 3. Header Analysis
        header_findings = analyze_headers(
            parsed_data.get("headers", []),
            parsed_data.get("from_parsed", []),
            parsed_data.get("reply_to_parsed", []),
            parsed_data.get("return_path_parsed", []),
            parsed_data.get("message_id", "")
        )

        await publish_event(
            db, email_id, "HEADERS_ANALYZED", "Header Analysis Complete",
            f"Analyzed {len(hops)} transit hops and evaluated spoofing indicators.",
            metadata={"hops_count": len(hops), "findings_count": len(header_findings)}
        )

        # 4. Authentication Analysis (SPF / DKIM / DMARC) + Live DNS
        from_domain = parsed_data.get("from_parsed", [{}])[0].get("domain") if parsed_data.get("from_parsed") else None

        spf_res, spf_findings = parse_spf(parsed_data.get("headers", []), from_domain)
        dkim_res, dkim_findings = parse_dkim(parsed_data.get("headers", []), raw_bytes, from_domain)
        dmarc_res, dmarc_findings = parse_dmarc(
            parsed_data.get("headers", []),
            from_domain,
            spf_res["spf_result"],
            spf_res["spf_domain"],
            dkim_res["dkim_result"],
            dkim_res["dkim_alignment"]
        )

        # Query live DNS if enabled
        dns_spf = dns_verifier.lookup_spf(from_domain)
        dns_dmarc = dns_verifier.lookup_dmarc(from_domain)

        auth_record = AuthenticationResult(
            email_id=email_id,
            spf_result=spf_res["spf_result"],
            spf_domain=spf_res["spf_domain"],
            spf_explanation=spf_res["spf_explanation"],
            dkim_result=dkim_res["dkim_result"],
            dkim_domain=dkim_res["dkim_domain"],
            dkim_selector=dkim_res["dkim_selector"],
            dkim_alignment=dkim_res["dkim_alignment"],
            dkim_explanation=dkim_res["dkim_explanation"],
            dmarc_result=dmarc_res["dmarc_result"],
            dmarc_domain=dmarc_res["dmarc_domain"],
            dmarc_policy=dmarc_res["dmarc_policy"],
            dmarc_spf_align=dmarc_res["dmarc_spf_align"],
            dmarc_dkim_align=dmarc_res["dmarc_dkim_align"],
            dmarc_explanation=dmarc_res["dmarc_explanation"],
            raw_auth_results_header=dmarc_res.get("raw_auth_results_header")
        )
        db.add(auth_record)
        db.commit()

        await publish_event(
            db, email_id, "AUTH_ANALYSIS_COMPLETE", "Email Authentication Complete",
            f"SPF={spf_res['spf_result']}, DKIM={dkim_res['dkim_result']}, DMARC={dmarc_res['dmarc_result']}",
            metadata={
                "spf": spf_res["spf_result"],
                "dkim": dkim_res["dkim_result"],
                "dmarc": dmarc_res["dmarc_result"],
                "dns_spf_status": dns_spf["status"],
                "dns_dmarc_status": dns_dmarc["status"]
            }
        )

        # 5. Sender & Domain Analysis
        domain_records, domain_findings = analyze_sender_and_domains(
            parsed_data.get("from_parsed", []),
            parsed_data.get("reply_to_parsed", []),
            parsed_data.get("return_path_parsed", []),
            parsed_data.get("to_parsed", [])
        )
        for dom in domain_records:
            dom_obj = EmailDomain(
                email_id=email_id,
                domain=dom["domain"],
                domain_type=dom["domain_type"],
                is_lookalike=dom["is_lookalike"],
                is_punycode=dom["is_punycode"],
                entropy=dom["entropy"],
                subdomain_depth=dom["subdomain_depth"]
            )
            db.add(dom_obj)
        db.commit()

        # Store Addresses
        for addr_type, addr_list in [
            ("FROM", parsed_data.get("from_parsed", [])),
            ("TO", parsed_data.get("to_parsed", [])),
            ("CC", parsed_data.get("cc_parsed", [])),
            ("BCC", parsed_data.get("bcc_parsed", [])),
            ("REPLY_TO", parsed_data.get("reply_to_parsed", [])),
            ("RETURN_PATH", parsed_data.get("return_path_parsed", []))
        ]:
            for item in addr_list:
                addr_obj = EmailAddress(
                    email_id=email_id,
                    address_type=addr_type,
                    raw_address=item["raw_address"],
                    normalized_address=item["normalized_address"],
                    display_name=item["display_name"],
                    domain=item["domain"]
                )
                db.add(addr_obj)
        db.commit()

        # 6. URL Extraction
        urls_extracted, url_findings = extract_urls(
            parsed_data.get("body_plain", ""),
            parsed_data.get("body_html", ""),
            parsed_data.get("headers", [])
        )
        for u in urls_extracted:
            url_obj = URLItem(
                email_id=email_id,
                original_url=u["original_url"],
                normalized_url=u["normalized_url"],
                scheme=u["scheme"],
                hostname=u["hostname"],
                port=u["port"],
                path=u["path"],
                query=u["query"],
                domain=u["domain"],
                ip_address=u["ip_address"],
                source_location=u["source_location"],
                is_http=u["is_http"],
                is_ip_based=u["is_ip_based"],
                is_suspicious_tld=u["is_suspicious_tld"],
                contains_credentials=u["contains_credentials"],
                is_punycode=u["is_punycode"],
                is_lookalike=u["is_lookalike"]
            )
            db.add(url_obj)
        db.commit()

        await publish_event(
            db, email_id, "URL_ANALYSIS_COMPLETE", f"Extracted {len(urls_extracted)} URLs",
            f"Normalized {len(urls_extracted)} URLs from body and headers (zero automated HTTP calls).",
            metadata={"urls_count": len(urls_extracted)}
        )

        # 7. Attachment Analysis
        att_records, att_findings = analyze_raw_attachments(parsed_data.get("raw_attachments", []))
        for att in att_records:
            att_obj = Attachment(
                email_id=email_id,
                filename=att["filename"],
                sanitized_filename=att["sanitized_filename"],
                extension=att["extension"],
                mime_type=att["mime_type"],
                size_bytes=att["size_bytes"],
                sha256=att["sha256"],
                sha1=att["sha1"],
                md5=att["md5"],
                is_archive=att["is_archive"],
                nested_level=att["nested_level"],
                storage_path=att["storage_path"],
                metadata_json=att["metadata_json"]
            )
            db.add(att_obj)
            db.commit()
            db.refresh(att_obj)

            for af in att["attachment_findings"]:
                af_obj = AttachmentFinding(
                    attachment_id=att_obj.id,
                    finding_type=af["finding_type"],
                    severity=af["severity"],
                    confidence=af["confidence"],
                    evidence=af["evidence"],
                    description=af["description"]
                )
                db.add(af_obj)
            db.commit()

        await publish_event(
            db, email_id, "ATTACHMENT_ANALYSIS_COMPLETE", f"Processed {len(att_records)} Attachments",
            f"Extracted metadata, cryptographic hashes, and static structure safely.",
            metadata={"attachments_count": len(att_records)}
        )

        # 8. YARA Rules Scan on Attachments
        yara_rules_content = [r["rule_content"] for r in DEFAULT_DEFENSIVE_YARA_RULES if r.get("is_enabled")]
        yara_findings = []
        for att in att_records:
            yara_matches = yara_scanner.scan_file(att["storage_path"], yara_rules_content)
            for m in yara_matches:
                yara_findings.append({
                    "finding_code": "SUSPICIOUS_ATTACHMENT",
                    "category": "ATTACHMENT_ANALYSIS",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "evidence": f"YARA rule '{m['rule_name']}' matched in '{att['filename']}'",
                    "explanation": f"Pattern detection identified malicious or suspicious signature '{m['rule_name']}'",
                    "source": "LOCAL_STATIC_ANALYSIS"
                })

        await publish_event(
            db, email_id, "YARA_COMPLETE", "YARA Rule Scan Complete",
            f"Scanned attachments using native YARA C-engine ({len(yara_findings)} matches).",
            metadata={"yara_engine": yara_scanner.engine_mode, "matches_count": len(yara_findings)}
        )

        # 9. Phishing Findings Consolidation
        all_findings = run_phishing_detection_rules(
            header_findings, domain_findings, url_findings, att_findings + yara_findings,
            received_anomalies, spf_findings, dkim_findings, dmarc_findings,
            parsed_data.get("body_plain", ""), parsed_data.get("body_html", "")
        )

        for f in all_findings:
            find_obj = PhishingFinding(
                email_id=email_id,
                finding_code=f["finding_code"],
                category=f["category"],
                severity=f["severity"],
                confidence=f["confidence"],
                evidence=f["evidence"],
                explanation=f["explanation"],
                source=f["source"]
            )
            db.add(find_obj)
        db.commit()

        # 10. Threat Intelligence Enrichment
        await publish_event(db, email_id, "TI_LOOKUP_STARTED", "Threat Intelligence Check Started", "Checking hash reputation with configured external providers.")
        intel_results = await threat_intel_service.lookup_hash(sample.sha256)
        for prov_name, prov_res in intel_results.items():
            ti_obj = ThreatIntelResult(
                email_id=email_id,
                ioc_type="HASH",
                ioc_value=sample.sha256,
                provider_name=prov_name,
                status=prov_res.get("status", "NOT_CONFIGURED"),
                threat_score=prov_res.get("malicious_count"),
                details_json=prov_res
            )
            db.add(ti_obj)
        db.commit()

        await publish_event(
            db, email_id, "TI_LOOKUP_COMPLETE", "Threat Intelligence Completed",
            "Recorded provider responses (NOT_CONFIGURED if API keys absent).",
            metadata={"providers": list(intel_results.keys())}
        )

        # 11. Risk Engine Calculation
        risk_score, risk_cat, factors = calculate_risk_score(all_findings)
        sample.risk_score = risk_score
        sample.risk_category = risk_cat
        sample.status = "COMPLETED"
        db.commit()

        await publish_event(
            db, email_id, "RISK_CALCULATED", f"Risk Score: {risk_score}/100 ({risk_cat})",
            f"Calculated automated risk category: {risk_cat}",
            metadata={"risk_score": risk_score, "risk_category": risk_cat, "factors_count": len(factors)}
        )
        await publish_event(
            db, email_id, "ANALYSIS_COMPLETE", "Email Analysis Completed",
            "Full defensive investigation pipeline completed successfully.",
            metadata={"status": "COMPLETED"}
        )

    except Exception as e:
        logger.error(f"Error executing email analysis pipeline for {email_id}: {e}", exc_info=True)
        sample.status = "FAILED"
        db.commit()
        await publish_event(
            db, email_id, "ANALYSIS_FAILED", "Email Analysis Failed",
            f"Pipeline encountered error: {str(e)}",
            status="FAILED",
            error=str(e)
        )

@router.post("", response_model=EmailSampleSummary, status_code=status.HTTP_201_CREATED)
async def upload_email_sample(
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not file and not raw_content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must provide either an uploaded .eml file or raw RFC email content.")

    if file:
        content = await file.read()
        filename = file.filename or "uploaded_sample.eml"
    else:
        content = raw_content.encode("utf-8")
        filename = "raw_sample.eml"

    storage_path, sanitized_fn, sha256, sha1, md5, size_bytes = save_uploaded_file(content, filename)

    # Check for duplicate sha256
    existing = db.query(EmailSample).filter(EmailSample.sha256 == sha256).first()
    if existing:
        return existing

    sample = EmailSample(
        original_filename=sanitized_fn,
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        size_bytes=size_bytes,
        mime_type="message/rfc822",
        raw_storage_path=storage_path,
        uploader_id=current_user.id,
        status="UPLOADED",
        data_source="REAL_EMAIL_ARTIFACT"
    )
    db.add(sample)
    db.commit()
    db.refresh(sample)

    await publish_event(
        db, sample.id, "UPLOAD_RECEIVED", "Email Upload Received",
        f"Saved artifact '{sanitized_fn}' safely to quarantine storage.",
        metadata={"filename": sanitized_fn, "size_bytes": size_bytes}
    )
    await publish_event(
        db, sample.id, "VALIDATION_COMPLETE", "Integrity & Size Validated",
        f"Cryptographic hashes calculated: SHA-256={sha256[:16]}...",
        metadata={"sha256": sha256, "sha1": sha1, "md5": md5}
    )

    log_audit_event(db, action="EMAIL_UPLOAD", resource="EMAIL_SAMPLE", resource_id=sample.id, user=current_user)

    # Trigger analysis pipeline based on configured processing mode
    if settings.PROCESSING_MODE == "celery":
        try:
            from app.tasks import analyze_email_task
            sample.status = "QUEUED"
            db.commit()
            analyze_email_task.delay(sample.id)
            logger.info(f"Queued email analysis task in Celery for: {sample.id}")
        except Exception as e:
            logger.warning(f"Celery queue error: {e}. Falling back to local execution.")
            background_tasks.add_task(execute_email_analysis_pipeline, sample.id, db)
    else:
        background_tasks.add_task(execute_email_analysis_pipeline, sample.id, db)

    return sample

@router.get("", response_model=List[EmailSampleSummary])
def list_email_samples(
    filter_source: Optional[str] = None, # ALL, REAL, DEMO, CONTROLLED_TEST, LIVE_TI
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(EmailSample)
    if filter_source and filter_source.upper() != "ALL":
        fs = filter_source.upper()
        if fs in ["REAL", "REAL_EMAIL_ARTIFACT"]:
            query = query.filter(EmailSample.data_source == "REAL_EMAIL_ARTIFACT")
        elif fs in ["DEMO", "CONTROLLED_TEST", "SYNTHETIC_LAB"]:
            query = query.filter(EmailSample.data_source.in_(["CONTROLLED_TEST", "DEMO_DATA", "SYNTHETIC_LAB"]))
        elif fs == "LIVE_TI":
            query = query.join(ThreatIntelResult).filter(ThreatIntelResult.status == "LIVE_PROVIDER_VERIFIED")
    return query.order_by(EmailSample.upload_timestamp.desc()).all()

@router.get("/seed-demo", response_model=List[EmailSampleSummary])
async def seed_demo_samples(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Seed controlled defensive lab demo samples into database."""
    created_samples = []
    for name, raw_bytes in DEMO_SAMPLES.items():
        filename = f"{name.lower()}.eml"
        storage_path, sanitized_fn, sha256, sha1, md5, size_bytes = save_uploaded_file(raw_bytes, filename)
        
        existing = db.query(EmailSample).filter(EmailSample.sha256 == sha256).first()
        if existing:
            created_samples.append(existing)
            continue

        sample = EmailSample(
            original_filename=sanitized_fn,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            size_bytes=size_bytes,
            mime_type="message/rfc822",
            raw_storage_path=storage_path,
            uploader_id=current_user.id,
            status="UPLOADED",
            data_source="CONTROLLED_TEST"
        )
        db.add(sample)
        db.commit()
        db.refresh(sample)

        await execute_email_analysis_pipeline(sample.id, db)
        created_samples.append(sample)

    return created_samples

@router.get("/{id}", response_model=EmailSampleDetail)
def get_email_sample_detail(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    return sample

@router.post("/{id}/analyze", response_model=EmailSampleSummary)
async def trigger_email_analysis(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    
    await execute_email_analysis_pipeline(sample.id, db)
    db.refresh(sample)
    return sample

@router.post("/{id}/verdict", response_model=AnalystVerdictSchema)
def set_analyst_verdict(
    id: str,
    verdict_in: AnalystVerdictCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    
    existing = db.query(AnalystVerdict).filter(AnalystVerdict.email_id == id).first()
    if existing:
        existing.verdict = verdict_in.verdict
        existing.notes = verdict_in.notes
        existing.analyst_id = current_user.id
        db.commit()
        db.refresh(existing)
        verdict_obj = existing
    else:
        verdict_obj = AnalystVerdict(
            email_id=id,
            analyst_id=current_user.id,
            verdict=verdict_in.verdict,
            notes=verdict_in.notes
        )
        db.add(verdict_obj)
        db.commit()
        db.refresh(verdict_obj)

    log_audit_event(db, action="ANALYST_VERDICT_CHANGE", resource="EMAIL_SAMPLE", resource_id=id, user=current_user, metadata={"verdict": verdict_in.verdict})
    return verdict_obj

@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_email_sample(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sample = db.query(EmailSample).filter(EmailSample.id == id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email sample not found.")
    
    # Remove raw file safely
    if os.path.exists(sample.raw_storage_path):
        try:
            os.remove(sample.raw_storage_path)
        except Exception:
            pass

    db.delete(sample)
    db.commit()
    log_audit_event(db, action="EMAIL_DELETE", resource="EMAIL_SAMPLE", resource_id=id, user=current_user)

@router.post("/compare", response_model=EmailComparisonResult)
def compare_two_emails(
    email_a_id: str = Form(...),
    email_b_id: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    a = db.query(EmailSample).filter(EmailSample.id == email_a_id).first()
    b = db.query(EmailSample).filter(EmailSample.id == email_b_id).first()
    if not a or not b:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both email samples not found.")

    def make_sec(list_a, list_b, key_fn=str):
        set_a = {key_fn(x) for x in list_a}
        set_b = {key_fn(x) for x in list_b}
        common = list(set_a.intersection(set_b))
        only_a = list(set_a.difference(set_b))
        only_b = list(set_b.difference(set_a))
        return ComparisonSection(common=common, only_a=only_a, only_b=only_b)

    sender_comp = make_sec([a.sender] if a.sender else [], [b.sender] if b.sender else [])
    dom_comp = make_sec([d.domain for d in a.domains], [d.domain for d in b.domains])
    head_comp = make_sec([f"{h.header_name}: {h.header_value}" for h in a.headers], [f"{h.header_name}: {h.header_value}" for h in b.headers])
    url_comp = make_sec([u.normalized_url for u in a.urls], [u.normalized_url for u in b.urls])
    att_comp = make_sec([att.sha256 for att in a.attachments], [att.sha256 for att in b.attachments])
    find_comp = make_sec([f.finding_code for f in a.phishing_findings], [f.finding_code for f in b.phishing_findings])

    risk_comp = {
        "email_a": {"score": a.risk_score, "category": a.risk_category},
        "email_b": {"score": b.risk_score, "category": b.risk_category}
    }

    return EmailComparisonResult(
        email_a_id=email_a_id,
        email_b_id=email_b_id,
        sender_comparison=sender_comp,
        domain_comparison=dom_comp,
        header_comparison=head_comp,
        url_comparison=url_comp,
        attachment_comparison=att_comp,
        finding_comparison=find_comp,
        risk_comparison=risk_comp
    )
