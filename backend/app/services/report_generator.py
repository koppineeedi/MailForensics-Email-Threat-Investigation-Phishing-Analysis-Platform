import os
import json
from datetime import datetime
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from app.config import settings

def generate_json_report(email_sample_data: Dict[str, Any], case_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate structured JSON forensic report."""
    report = {
        "report_metadata": {
            "platform": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "generated_at": datetime.utcnow().isoformat(),
            "disclaimer": "CONFIDENTIAL SOC INVESTIGATION REPORT. DEFENSIVE USE ONLY."
        },
        "case_information": case_data,
        "email_metadata": {
            "id": email_sample_data.get("id"),
            "filename": email_sample_data.get("original_filename"),
            "sha256": email_sample_data.get("sha256"),
            "sha1": email_sample_data.get("sha1"),
            "md5": email_sample_data.get("md5"),
            "size_bytes": email_sample_data.get("size_bytes"),
            "message_id": email_sample_data.get("message_id"),
            "subject": email_sample_data.get("subject"),
            "sender": email_sample_data.get("sender"),
            "recipients": email_sample_data.get("recipients"),
            "upload_timestamp": str(email_sample_data.get("upload_timestamp"))
        },
        "automated_analysis": {
            "risk_score": email_sample_data.get("risk_score"),
            "risk_category": email_sample_data.get("risk_category"),
            "authentication": email_sample_data.get("auth_results"),
            "received_chain_hops": len(email_sample_data.get("received_hops", [])),
            "phishing_findings": email_sample_data.get("phishing_findings", []),
            "urls_extracted": email_sample_data.get("urls", []),
            "attachments_analyzed": email_sample_data.get("attachments", [])
        },
        "external_threat_intelligence": email_sample_data.get("threat_intel_results", []),
        "analyst_analysis": {
            "verdict": email_sample_data.get("verdict")
        },
        "limitations": [
            "Automated risk scores represent statistical heuristics and evidence weights.",
            "External threat intelligence is subject to provider rate limits and subscription configuration.",
            "Verification of cryptographic signatures depends on public DNS key availability at time of evaluation."
        ]
    }
    return report

def generate_pdf_report(email_sample_data: Dict[str, Any], case_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate professional PDF forensic report using ReportLab.
    Returns the file path of the generated PDF.
    """
    email_id = email_sample_data.get("id", "sample")
    pdf_filename = f"report_{email_id}_{int(datetime.utcnow().timestamp())}.pdf"
    pdf_path = os.path.join(settings.REPORTS_DIR, pdf_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom SOC Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor('#334155'),
        spaceAfter=4
    )

    badge_style = ParagraphStyle(
        'Badge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        textColor=colors.white
    )

    elements = []

    # Title & Header
    elements.append(Paragraph("MAILFORENSICS — EMAIL THREAT INVESTIGATION REPORT", title_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Defensive SOC Platform v{settings.APP_VERSION}", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0EA5E9'), spaceAfter=15))

    # Executive Overview Table
    risk_score = email_sample_data.get("risk_score", 0.0)
    risk_cat = email_sample_data.get("risk_category", "LOW")
    verdict_obj = email_sample_data.get("verdict")
    verdict_val = verdict_obj.get("verdict", "UNRESOLVED") if verdict_obj else "UNRESOLVED"

    overview_data = [
        [Paragraph("<b>Sample Filename:</b>", body_style), Paragraph(str(email_sample_data.get("original_filename")), body_style)],
        [Paragraph("<b>SHA-256 Hash:</b>", body_style), Paragraph(str(email_sample_data.get("sha256")), body_style)],
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(email_sample_data.get("subject")), body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(str(email_sample_data.get("sender")), body_style)],
        [Paragraph("<b>AUTOMATED RISK SCORE:</b>", body_style), Paragraph(f"<b>{risk_score}/100 ({risk_cat})</b>", body_style)],
        [Paragraph("<b>ANALYST VERDICT:</b>", body_style), Paragraph(f"<b>{verdict_val}</b>", body_style)]
    ]

    t_overview = Table(overview_data, colWidths=[140, 380])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0'))
    ]))
    elements.append(t_overview)
    elements.append(Spacer(1, 15))

    # Section 1: Authentication Analysis
    elements.append(Paragraph("[AUTOMATED ANALYSIS] Email Authentication Analysis", h2_style))
    auth = email_sample_data.get("auth_results") or {}
    auth_data = [
        ["Mechanism", "Result", "Domain / Selector", "Explanation"],
        ["SPF", auth.get("spf_result", "NONE"), str(auth.get("spf_domain", "-")), Paragraph(str(auth.get("spf_explanation", "-")), body_style)],
        ["DKIM", auth.get("dkim_result", "NOT_CHECKED"), str(auth.get("dkim_domain", "-")), Paragraph(str(auth.get("dkim_explanation", "-")), body_style)],
        ["DMARC", auth.get("dmarc_result", "NOT_CHECKED"), str(auth.get("dmarc_domain", "-")), Paragraph(str(auth.get("dmarc_explanation", "-")), body_style)]
    ]
    t_auth = Table(auth_data, colWidths=[80, 80, 140, 220])
    t_auth.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1'))
    ]))
    elements.append(t_auth)
    elements.append(Spacer(1, 15))

    # Section 2: Phishing Findings
    elements.append(Paragraph("[AUTOMATED ANALYSIS] Phishing Findings & Indicators", h2_style))
    findings = email_sample_data.get("phishing_findings", [])
    if not findings:
        elements.append(Paragraph("No automated phishing findings recorded.", body_style))
    else:
        finding_rows = [["Code", "Severity", "Evidence", "Explanation"]]
        for f in findings:
            finding_rows.append([
                f.get("finding_code", ""),
                f.get("severity", ""),
                Paragraph(str(f.get("evidence", "")), body_style),
                Paragraph(str(f.get("explanation", "")), body_style)
            ])
        t_find = Table(finding_rows, colWidths=[120, 70, 150, 180])
        t_find.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1'))
        ]))
        elements.append(t_find)

    elements.append(Spacer(1, 15))

    # Section 3: Analyst Verdict & Notes
    elements.append(Paragraph("[ANALYST ANALYSIS] Final Verdict & Case Investigation Notes", h2_style))
    verdict_notes = verdict_obj.get("notes", "No notes recorded.") if verdict_obj else "No analyst notes provided."
    elements.append(Paragraph(f"<b>Verdict:</b> {verdict_val}", body_style))
    elements.append(Paragraph(f"<b>Analyst Investigation Notes:</b> {verdict_notes}", body_style))
    elements.append(Spacer(1, 15))

    # Section 4: Limitations
    elements.append(Paragraph("Platform Limitations & Forensic Methodology", h2_style))
    lim_text = "This defensive investigation report was generated using static email RFC parsing, header analysis, and evidence-based risk scoring. Extracted URLs and attachments are isolated and were NOT automatically visited or executed."
    elements.append(Paragraph(lim_text, body_style))

    doc.build(elements)
    return pdf_path
