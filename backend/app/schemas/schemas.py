from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import re

def validate_email_format(v: str) -> str:
    if not v or "@" not in v or "." not in v.split("@")[-1]:
        raise ValueError("Invalid email address format")
    return v.lower().strip()

# --- Auth & User Schemas ---
class UserBase(BaseModel):
    email: str
    full_name: str
    role: str = "ANALYST" # ADMIN, ANALYST, VIEWER

    @field_validator('email')
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_format(v)

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserLogin(BaseModel):
    email: str
    password: str

    @field_validator('email')
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_format(v)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# --- Header & Auth Schemas ---
class EmailHeaderSchema(BaseModel):
    id: str
    header_name: str
    header_value: str
    is_auth_header: bool
    hop_index: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

class ReceivedHopSchema(BaseModel):
    id: str
    hop_order: int
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    by_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    protocol: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    helo_domain: Optional[str] = None
    delay_seconds: Optional[float] = None
    reverse_dns: Optional[str] = None
    anomaly_detected: bool = False
    anomaly_details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class AuthenticationResultSchema(BaseModel):
    id: str
    spf_result: str
    spf_domain: Optional[str] = None
    spf_explanation: Optional[str] = None
    dkim_result: str
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dkim_alignment: bool = False
    dkim_explanation: Optional[str] = None
    dmarc_result: str
    dmarc_domain: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_spf_align: bool = False
    dmarc_dkim_align: bool = False
    dmarc_explanation: Optional[str] = None
    raw_auth_results_header: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Address & Domain Schemas ---
class EmailAddressSchema(BaseModel):
    id: str
    address_type: str
    raw_address: str
    normalized_address: str
    display_name: Optional[str] = None
    domain: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class EmailDomainSchema(BaseModel):
    id: str
    domain: str
    domain_type: str
    is_lookalike: bool
    is_punycode: bool
    entropy: Optional[float] = None
    subdomain_depth: int

    model_config = ConfigDict(from_attributes=True)

# --- URL Schemas ---
class URLItemSchema(BaseModel):
    id: str
    original_url: str
    normalized_url: str
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    query: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    source_location: str
    is_http: bool
    is_ip_based: bool
    is_suspicious_tld: bool
    contains_credentials: bool
    is_punycode: bool
    is_lookalike: bool

    model_config = ConfigDict(from_attributes=True)

# --- Attachment Schemas ---
class AttachmentFindingSchema(BaseModel):
    id: str
    finding_type: str
    severity: str
    confidence: float
    evidence: str
    description: str
    yara_rule_matched: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class AttachmentSchema(BaseModel):
    id: str
    filename: str
    sanitized_filename: str
    extension: Optional[str] = None
    mime_type: str
    size_bytes: int
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    is_archive: bool
    nested_level: int
    metadata_json: Optional[Dict[str, Any]] = None
    findings: List[AttachmentFindingSchema] = []

    model_config = ConfigDict(from_attributes=True)

# --- Phishing Finding Schemas ---
class PhishingFindingSchema(BaseModel):
    id: str
    email_id: str
    finding_code: str
    category: str
    severity: str
    confidence: float
    evidence: str
    explanation: str
    source: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Threat Intel Schemas ---
class ThreatIntelResultSchema(BaseModel):
    id: str
    ioc_type: str
    ioc_value: str
    provider_name: str
    status: str
    threat_score: Optional[float] = None
    details_json: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ThreatIntelLookupRequest(BaseModel):
    ioc_type: str
    ioc_value: str

# --- Email Event / Timeline Schemas ---
class EmailEventSchema(BaseModel):
    id: str
    email_id: str
    event_type: str
    title: str
    description: Optional[str] = None
    event_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Analyst Verdict Schemas ---
class AnalystVerdictCreate(BaseModel):
    verdict: str
    notes: Optional[str] = None

class AnalystVerdictSchema(BaseModel):
    id: str
    email_id: str
    analyst_id: str
    verdict: str
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Email Sample Schemas ---
class EmailSampleSummary(BaseModel):
    id: str
    original_filename: str
    sha256: str
    size_bytes: int
    mime_type: str
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipients: Optional[str] = None
    upload_timestamp: datetime
    status: str
    is_quarantined: bool
    risk_score: float
    risk_category: str
    data_source: str = "REAL_EMAIL_ARTIFACT"
    verdict: Optional[AnalystVerdictSchema] = None

    model_config = ConfigDict(from_attributes=True)

class EmailSampleDetail(EmailSampleSummary):
    sha1: Optional[str] = None
    md5: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    received_timestamp: Optional[datetime] = None
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    headers: List[EmailHeaderSchema] = []
    received_hops: List[ReceivedHopSchema] = []
    auth_results: Optional[AuthenticationResultSchema] = None
    addresses: List[EmailAddressSchema] = []
    domains: List[EmailDomainSchema] = []
    urls: List[URLItemSchema] = []
    attachments: List[AttachmentSchema] = []
    phishing_findings: List[PhishingFindingSchema] = []
    threat_intel_results: List[ThreatIntelResultSchema] = []
    events: List[EmailEventSchema] = []

    model_config = ConfigDict(from_attributes=True)

# --- Risk Detail Schema ---
class RiskFactorSchema(BaseModel):
    factor: str
    evidence: str
    weight: float
    contribution: float

class RiskScoreDetail(BaseModel):
    risk_score: float
    risk_category: str
    factors: List[RiskFactorSchema]

# --- Case Management Schemas ---
class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "MEDIUM"
    severity: str = "SUSPICIOUS"
    email_ids: Optional[List[str]] = []

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    severity: Optional[str] = None
    assigned_analyst_id: Optional[str] = None

class CaseNoteCreate(BaseModel):
    content: str

class CaseNoteSchema(BaseModel):
    id: str
    case_id: str
    author_id: str
    author_name: Optional[str] = "Analyst"
    content: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class CaseSchema(BaseModel):
    id: str
    case_number: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    severity: str
    assigned_analyst_id: Optional[str] = None
    created_by_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    emails: List[EmailSampleSummary] = Field(default=[], validation_alias="email_samples")
    notes: List[CaseNoteSchema] = []

    model_config = ConfigDict(from_attributes=True)

# --- Email Comparison Schema ---
class ComparisonSection(BaseModel):
    common: List[Any]
    only_a: List[Any]
    only_b: List[Any]

class EmailComparisonResult(BaseModel):
    email_a_id: str
    email_b_id: str
    sender_comparison: ComparisonSection
    domain_comparison: ComparisonSection
    header_comparison: ComparisonSection
    url_comparison: ComparisonSection
    attachment_comparison: ComparisonSection
    finding_comparison: ComparisonSection
    risk_comparison: Dict[str, Any]

# --- Relationship Graph Schemas ---
class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    properties: Dict[str, Any] = {}

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    evidence: Optional[str] = None

class RelationshipGraph(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]

# --- Audit Log Schema ---
class AuditLogSchema(BaseModel):
    id: str
    timestamp: datetime
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    resource: str
    resource_id: Optional[str] = None
    outcome: str
    metadata_json: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)

# --- YARA Rule Schemas ---
class YaraRuleCreate(BaseModel):
    rule_name: str
    category: str = "ATTACHMENT_ANALYSIS"
    severity: str = "HIGH"
    description: Optional[str] = None
    rule_content: str

class YaraRuleSchema(BaseModel):
    id: str
    rule_name: str
    category: str
    severity: str
    description: Optional[str] = None
    rule_content: str
    is_enabled: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Dashboard Stats Schema ---
class DashboardStats(BaseModel):
    emails_analyzed: int
    suspicious_emails: int
    phishing_findings_count: int
    attachment_findings_count: int
    url_findings_count: int
    open_cases: int
    recent_emails: List[EmailSampleSummary]
    risk_distribution: Dict[str, int]
    auth_distribution: Dict[str, int]
