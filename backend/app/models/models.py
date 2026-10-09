import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index, JSON
from sqlalchemy.orm import relationship
from app.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="ANALYST")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    uploaded_emails = relationship("EmailSample", back_populates="uploader")
    audit_logs = relationship("AuditLog", back_populates="user")
    verdicts = relationship("AnalystVerdict", back_populates="analyst")
    case_notes = relationship("CaseNote", back_populates="author")

class EmailSample(Base):
    __tablename__ = "email_samples"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    original_filename = Column(String(255), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha1 = Column(String(40), nullable=True)
    md5 = Column(String(32), nullable=True)
    size_bytes = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False, default="message/rfc822")
    message_id = Column(String(255), nullable=True, index=True)
    subject = Column(Text, nullable=True)
    sender = Column(String(255), nullable=True, index=True)
    recipients = Column(Text, nullable=True)
    reply_to = Column(String(255), nullable=True)
    return_path = Column(String(255), nullable=True)
    received_timestamp = Column(DateTime, nullable=True)
    upload_timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    uploader_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    status = Column(String(50), nullable=False, default="UPLOADED", index=True)
    is_quarantined = Column(Boolean, default=False)
    raw_storage_path = Column(String(512), nullable=False)
    body_plain = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    
    risk_score = Column(Float, default=0.0)
    risk_category = Column(String(50), default="LOW")
    data_source = Column(String(50), nullable=False, default="REAL_EMAIL_ARTIFACT", index=True)

    uploader = relationship("User", back_populates="uploaded_emails")
    headers = relationship("EmailHeader", back_populates="email_sample", cascade="all, delete-orphan")
    received_hops = relationship("ReceivedHop", back_populates="email_sample", cascade="all, delete-orphan")
    auth_results = relationship("AuthenticationResult", back_populates="email_sample", uselist=False, cascade="all, delete-orphan")
    addresses = relationship("EmailAddress", back_populates="email_sample", cascade="all, delete-orphan")
    domains = relationship("EmailDomain", back_populates="email_sample", cascade="all, delete-orphan")
    urls = relationship("URLItem", back_populates="email_sample", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="email_sample", cascade="all, delete-orphan")
    phishing_findings = relationship("PhishingFinding", back_populates="email_sample", cascade="all, delete-orphan")
    threat_intel_results = relationship("ThreatIntelResult", back_populates="email_sample", cascade="all, delete-orphan")
    events = relationship("EmailEvent", back_populates="email_sample", cascade="all, delete-orphan")
    verdict = relationship("AnalystVerdict", back_populates="email_sample", uselist=False, cascade="all, delete-orphan")
    case_associations = relationship("CaseEmail", back_populates="email_sample", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="email_sample", cascade="all, delete-orphan")

class EmailHeader(Base):
    __tablename__ = "email_headers"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    header_name = Column(String(255), nullable=False, index=True)
    header_value = Column(Text, nullable=False)
    is_auth_header = Column(Boolean, default=False)
    hop_index = Column(Integer, nullable=True)

    email_sample = relationship("EmailSample", back_populates="headers")

class ReceivedHop(Base):
    __tablename__ = "received_hops"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    hop_order = Column(Integer, nullable=False)
    from_host = Column(String(255), nullable=True)
    from_ip = Column(String(100), nullable=True, index=True)
    by_host = Column(String(255), nullable=True)
    by_ip = Column(String(100), nullable=True)
    timestamp = Column(DateTime, nullable=True)
    protocol = Column(String(100), nullable=True)
    tls_version = Column(String(100), nullable=True)
    cipher = Column(String(100), nullable=True)
    helo_domain = Column(String(255), nullable=True)
    delay_seconds = Column(Float, nullable=True)
    reverse_dns = Column(String(255), nullable=True)
    anomaly_detected = Column(Boolean, default=False)
    anomaly_details = Column(Text, nullable=True)

    email_sample = relationship("EmailSample", back_populates="received_hops")

class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    
    spf_result = Column(String(50), default="NONE")
    spf_domain = Column(String(255), nullable=True)
    spf_explanation = Column(Text, nullable=True)
    
    dkim_result = Column(String(50), default="NOT_CHECKED")
    dkim_domain = Column(String(255), nullable=True)
    dkim_selector = Column(String(255), nullable=True)
    dkim_alignment = Column(Boolean, default=False)
    dkim_explanation = Column(Text, nullable=True)
    
    dmarc_result = Column(String(50), default="NOT_CHECKED")
    dmarc_domain = Column(String(255), nullable=True)
    dmarc_policy = Column(String(50), nullable=True)
    dmarc_spf_align = Column(Boolean, default=False)
    dmarc_dkim_align = Column(Boolean, default=False)
    dmarc_explanation = Column(Text, nullable=True)

    raw_auth_results_header = Column(Text, nullable=True)

    email_sample = relationship("EmailSample", back_populates="auth_results")

class EmailAddress(Base):
    __tablename__ = "email_addresses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    address_type = Column(String(50), nullable=False)
    raw_address = Column(String(512), nullable=False)
    normalized_address = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True, index=True)

    email_sample = relationship("EmailSample", back_populates="addresses")

class EmailDomain(Base):
    __tablename__ = "email_domains"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    domain_type = Column(String(50), nullable=False)
    is_lookalike = Column(Boolean, default=False)
    is_punycode = Column(Boolean, default=False)
    entropy = Column(Float, nullable=True)
    subdomain_depth = Column(Integer, default=0)

    email_sample = relationship("EmailSample", back_populates="domains")

class URLItem(Base):
    __tablename__ = "urls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    original_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False)
    scheme = Column(String(20), nullable=True)
    hostname = Column(String(255), nullable=True, index=True)
    port = Column(Integer, nullable=True)
    path = Column(Text, nullable=True)
    query = Column(Text, nullable=True)
    fragment = Column(Text, nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    ip_address = Column(String(100), nullable=True, index=True)
    source_location = Column(String(50), nullable=False, default="BODY_TEXT")
    is_http = Column(Boolean, default=False)
    is_ip_based = Column(Boolean, default=False)
    is_suspicious_tld = Column(Boolean, default=False)
    contains_credentials = Column(Boolean, default=False)
    is_punycode = Column(Boolean, default=False)
    is_lookalike = Column(Boolean, default=False)

    email_sample = relationship("EmailSample", back_populates="urls")

class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    sanitized_filename = Column(String(255), nullable=False)
    extension = Column(String(50), nullable=True, index=True)
    mime_type = Column(String(100), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha1 = Column(String(40), nullable=True)
    md5 = Column(String(32), nullable=True)
    is_archive = Column(Boolean, default=False)
    nested_level = Column(Integer, default=0)
    parent_attachment_id = Column(String(36), ForeignKey("attachments.id", ondelete="SET NULL"), nullable=True)
    storage_path = Column(String(512), nullable=False)
    metadata_json = Column(JSON, nullable=True)

    email_sample = relationship("EmailSample", back_populates="attachments")
    findings = relationship("AttachmentFinding", back_populates="attachment", cascade="all, delete-orphan")

class AttachmentFinding(Base):
    __tablename__ = "attachment_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    attachment_id = Column(String(36), ForeignKey("attachments.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)
    evidence = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    yara_rule_matched = Column(String(255), nullable=True)

    attachment = relationship("Attachment", back_populates="findings")

class PhishingFinding(Base):
    __tablename__ = "phishing_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_code = Column(String(100), nullable=False, index=True)
    category = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)
    evidence = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    source = Column(String(100), nullable=False, default="DEFENSIVE_ENGINE")
    created_at = Column(DateTime, default=datetime.utcnow)

    email_sample = relationship("EmailSample", back_populates="phishing_findings")

class ThreatIntelResult(Base):
    __tablename__ = "threat_intel_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(50), nullable=False)
    ioc_value = Column(String(512), nullable=False, index=True)
    provider_name = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False, default="NOT_CONFIGURED")
    threat_score = Column(Float, nullable=True)
    details_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    email_sample = relationship("EmailSample", back_populates="threat_intel_results")

class EmailEvent(Base):
    __tablename__ = "email_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    event_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    email_sample = relationship("EmailSample", back_populates="events")

class EmailCase(Base):
    __tablename__ = "email_cases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_number = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="OPEN", index=True)
    priority = Column(String(50), nullable=False, default="MEDIUM")
    severity = Column(String(50), nullable=False, default="SUSPICIOUS")
    assigned_analyst_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)

    assigned_analyst = relationship("User", foreign_keys=[assigned_analyst_id])
    created_by = relationship("User", foreign_keys=[created_by_id])
    emails = relationship("CaseEmail", back_populates="case", cascade="all, delete-orphan")
    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")
    case_urls = relationship("CaseURL", back_populates="case", cascade="all, delete-orphan")
    case_attachments = relationship("CaseAttachment", back_populates="case", cascade="all, delete-orphan")
    case_findings = relationship("CaseFinding", back_populates="case", cascade="all, delete-orphan")

    @property
    def email_samples(self):
        return [ce.email_sample for ce in self.emails if ce.email_sample]

class CaseEmail(Base):
    __tablename__ = "case_emails"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("EmailCase", back_populates="emails")
    email_sample = relationship("EmailSample", back_populates="case_associations")

class CaseFinding(Base):
    __tablename__ = "case_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("phishing_findings.id", ondelete="CASCADE"), nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("EmailCase", back_populates="case_findings")

class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    case = relationship("EmailCase", back_populates="notes")
    author = relationship("User", back_populates="case_notes")

class CaseURL(Base):
    __tablename__ = "case_urls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    url_id = Column(String(36), ForeignKey("urls.id", ondelete="CASCADE"), nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("EmailCase", back_populates="case_urls")

class CaseAttachment(Base):
    __tablename__ = "case_attachments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    attachment_id = Column(String(36), ForeignKey("attachments.id", ondelete="CASCADE"), nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("EmailCase", back_populates="case_attachments")

class AnalystVerdict(Base):
    __tablename__ = "analyst_verdicts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    analyst_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    verdict = Column(String(50), nullable=False, default="UNRESOLVED")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    email_sample = relationship("EmailSample", back_populates="verdict")
    analyst = relationship("User", back_populates="verdicts")

class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("email_samples.id", ondelete="CASCADE"), nullable=True, index=True)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=True, index=True)
    report_type = Column(String(20), nullable=False, default="JSON")
    report_data_json = Column(JSON, nullable=True)
    pdf_file_path = Column(String(512), nullable=True)
    generated_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow)

    email_sample = relationship("EmailSample", back_populates="reports")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    user_email = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=True)
    outcome = Column(String(50), nullable=False, default="SUCCESS")
    metadata_json = Column(JSON, nullable=True)

    user = relationship("User", back_populates="audit_logs")

class YaraRule(Base):
    __tablename__ = "yara_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_name = Column(String(255), unique=True, nullable=False, index=True)
    category = Column(String(100), nullable=False, default="ATTACHMENT_ANALYSIS")
    severity = Column(String(50), nullable=False, default="HIGH")
    description = Column(Text, nullable=True)
    rule_content = Column(Text, nullable=False)
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
