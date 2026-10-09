export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'ADMIN' | 'ANALYST' | 'VIEWER';
  is_active: boolean;
  created_at: string;
}

export interface AnalystVerdict {
  id: string;
  email_id: string;
  analyst_id: string;
  verdict: 'BENIGN' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS_ATTACHMENT' | 'SPAM' | 'UNRESOLVED';
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface EmailSampleSummary {
  id: string;
  original_filename: string;
  sha256: string;
  size_bytes: number;
  mime_type: string;
  message_id?: string;
  subject?: string;
  sender?: string;
  recipients?: string;
  upload_timestamp: string;
  status: 'UPLOADED' | 'QUEUED' | 'ANALYZING' | 'COMPLETED' | 'FAILED' | 'QUARANTINED';
  is_quarantined: boolean;
  risk_score: number;
  risk_category: 'LOW' | 'GUARDED' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  data_source?: string;
  verdict?: AnalystVerdict;
}

export interface SystemComponentStatus {
  status: string;
  detail?: string;
  [key: string]: any;
}

export interface SystemStatus {
  overall_status: string;
  timestamp: string;
  processing_mode: string;
  components: {
    database: SystemComponentStatus;
    redis: SystemComponentStatus;
    celery: SystemComponentStatus;
    yara: SystemComponentStatus;
    dns: SystemComponentStatus;
    storage: SystemComponentStatus;
    threat_intelligence: Record<string, string>;
  };
}

export interface EmailHeader {
  id: string;
  header_name: string;
  header_value: string;
  is_auth_header: boolean;
  hop_index?: number;
}

export interface ReceivedHop {
  id: string;
  hop_order: number;
  from_host?: string;
  from_ip?: string;
  by_host?: string;
  by_ip?: string;
  timestamp?: string;
  protocol?: string;
  tls_version?: string;
  cipher?: string;
  helo_domain?: string;
  delay_seconds?: number;
  reverse_dns?: string;
  anomaly_detected: boolean;
  anomaly_details?: string;
}

export interface AuthenticationResult {
  id: string;
  spf_result: string;
  spf_domain?: string;
  spf_explanation?: string;
  dkim_result: string;
  dkim_domain?: string;
  dkim_selector?: string;
  dkim_alignment: boolean;
  dkim_explanation?: string;
  dmarc_result: string;
  dmarc_domain?: string;
  dmarc_policy?: string;
  dmarc_spf_align: boolean;
  dmarc_dkim_align: boolean;
  dmarc_explanation?: string;
  raw_auth_results_header?: string;
}

export interface EmailAddress {
  id: string;
  address_type: string;
  raw_address: string;
  normalized_address: string;
  display_name?: string;
  domain?: string;
}

export interface EmailDomain {
  id: string;
  domain: string;
  domain_type: string;
  is_lookalike: boolean;
  is_punycode: boolean;
  entropy?: number;
  subdomain_depth: number;
}

export interface URLItem {
  id: string;
  original_url: string;
  normalized_url: string;
  scheme?: string;
  hostname?: string;
  port?: number;
  path?: string;
  query?: string;
  domain?: string;
  ip_address?: string;
  source_location: string;
  is_http: boolean;
  is_ip_based: boolean;
  is_suspicious_tld: boolean;
  contains_credentials: boolean;
  is_punycode: boolean;
  is_lookalike: boolean;
}

export interface AttachmentFinding {
  id: string;
  finding_type: string;
  severity: string;
  confidence: number;
  evidence: string;
  description: string;
  yara_rule_matched?: string;
}

export interface Attachment {
  id: string;
  filename: string;
  sanitized_filename: string;
  extension?: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  sha1?: string;
  md5?: string;
  is_archive: boolean;
  nested_level: number;
  metadata_json?: Record<string, any>;
  findings: AttachmentFinding[];
}

export interface PhishingFinding {
  id: string;
  email_id: string;
  finding_code: string;
  category: string;
  severity: 'LOW' | 'GUARDED' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  confidence: number;
  evidence: string;
  explanation: string;
  source: string;
  created_at: string;
}

export interface ThreatIntelResult {
  id: string;
  ioc_type: string;
  ioc_value: string;
  provider_name: string;
  status: 'CONFIGURED' | 'NOT_CONFIGURED' | 'RATE_LIMITED' | 'ERROR' | 'AVAILABLE';
  threat_score?: number;
  details_json?: Record<string, any>;
  created_at: string;
}

export interface EmailEvent {
  id: string;
  email_id: string;
  event_type: string;
  title: string;
  description?: string;
  event_metadata?: Record<string, any>;
  created_at: string;
}

export interface EmailSampleDetail extends EmailSampleSummary {
  sha1?: string;
  md5?: string;
  reply_to?: string;
  return_path?: string;
  received_timestamp?: string;
  body_plain?: string;
  body_html?: string;
  headers: EmailHeader[];
  received_hops: ReceivedHop[];
  auth_results?: AuthenticationResult;
  addresses: EmailAddress[];
  domains: EmailDomain[];
  urls: URLItem[];
  attachments: Attachment[];
  phishing_findings: PhishingFinding[];
  threat_intel_results: ThreatIntelResult[];
  events: EmailEvent[];
}

export interface CaseNote {
  id: string;
  case_id: string;
  author_id: string;
  author_name?: string;
  content: string;
  created_at: string;
}

export interface EmailCase {
  id: string;
  case_number: string;
  title: string;
  description?: string;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
  severity: string;
  assigned_analyst_id?: string;
  created_by_id?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  emails: EmailSampleSummary[];
  notes: CaseNote[];
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user_id?: string;
  user_email?: string;
  action: string;
  resource: string;
  resource_id?: string;
  outcome: string;
  metadata_json?: Record<string, any>;
}

export interface YaraRule {
  id: string;
  rule_name: string;
  category: string;
  severity: string;
  description?: string;
  rule_content: string;
  is_enabled: boolean;
  created_at: string;
}

export interface DashboardStats {
  emails_analyzed: number;
  suspicious_emails: number;
  phishing_findings_count: number;
  attachment_findings_count: number;
  url_findings_count: number;
  open_cases: number;
  recent_emails: EmailSampleSummary[];
  risk_distribution: Record<string, number>;
  auth_distribution: Record<string, number>;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'EMAIL' | 'SENDER' | 'RECIPIENT' | 'DOMAIN' | 'IP' | 'URL' | 'ATTACHMENT' | 'HASH' | 'CASE' | 'FINDING';
  properties: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  evidence?: string;
}

export interface RelationshipGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ComparisonSection {
  common: any[];
  only_a: any[];
  only_b: any[];
}

export interface EmailComparisonResult {
  email_a_id: string;
  email_b_id: string;
  sender_comparison: ComparisonSection;
  domain_comparison: ComparisonSection;
  header_comparison: ComparisonSection;
  url_comparison: ComparisonSection;
  attachment_comparison: ComparisonSection;
  finding_comparison: ComparisonSection;
  risk_comparison: Record<string, any>;
}
