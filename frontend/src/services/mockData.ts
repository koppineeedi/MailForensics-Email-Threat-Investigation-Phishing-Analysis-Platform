import {
  User, EmailSampleSummary, EmailSampleDetail, EmailCase,
  DashboardStats, RelationshipGraph, YaraRule, SystemStatus
} from '../types';

export const MOCK_ADMIN_USER: User = {
  id: 'usr-admin-001',
  email: 'admin@mailforensics.local',
  full_name: 'SOC Administrator',
  role: 'ADMIN',
  is_active: true,
  created_at: '2026-09-28T10:00:00Z'
};

export const MOCK_ANALYST_USER: User = {
  id: 'usr-analyst-002',
  email: 'analyst@mailforensics.local',
  full_name: 'Tier-2 SOC Analyst',
  role: 'ANALYST',
  is_active: true,
  created_at: '2026-09-28T10:05:00Z'
};

export const MOCK_EMAILS: EmailSampleSummary[] = [
  {
    id: 'eml-paypal-spoof',
    original_filename: 'paypal_security_alert.eml',
    sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
    size_bytes: 4210,
    mime_type: 'message/rfc822',
    message_id: '<alert-89218@service-paypal-verify.top>',
    subject: 'Urgent: Account Access Limited - Action Required',
    sender: 'support@service-paypal-verify.top',
    recipients: 'user@corp.internal',
    upload_timestamp: '2026-10-09T18:30:00Z',
    status: 'COMPLETED',
    is_quarantined: false,
    risk_score: 88,
    risk_category: 'CRITICAL',
    data_source: 'CONTROLLED_TEST',
    verdict: {
      id: 'vrd-001',
      email_id: 'eml-paypal-spoof',
      analyst_id: 'usr-analyst-002',
      verdict: 'PHISHING',
      notes: 'Brand impersonation targeting PayPal credentials via suspicious .top TLD domain.',
      created_at: '2026-10-09T18:35:00Z',
      updated_at: '2026-10-09T18:35:00Z'
    }
  },
  {
    id: 'eml-invoice-malware',
    original_filename: 'overdue_invoice_inv9821.eml',
    sha256: 'b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a',
    size_bytes: 125400,
    mime_type: 'message/rfc822',
    message_id: '<billing-491@billing-account-services.com>',
    subject: 'OVERDUE: Invoice #INV-9821 payment notification',
    sender: 'finance@billing-account-services.com',
    recipients: 'accounting@corp.internal',
    upload_timestamp: '2026-10-09T17:15:00Z',
    status: 'COMPLETED',
    is_quarantined: true,
    risk_score: 95,
    risk_category: 'CRITICAL',
    data_source: 'CONTROLLED_TEST',
    verdict: {
      id: 'vrd-002',
      email_id: 'eml-invoice-malware',
      analyst_id: 'usr-admin-001',
      verdict: 'MALICIOUS_ATTACHMENT',
      notes: 'Attachment contains embedded executable with suspicious PE header.',
      created_at: '2026-10-09T17:20:00Z',
      updated_at: '2026-10-09T17:20:00Z'
    }
  },
  {
    id: 'eml-ceo-fraud',
    original_filename: 'urgent_wire_instructions.eml',
    sha256: 'c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b',
    size_bytes: 3180,
    mime_type: 'message/rfc822',
    message_id: '<ceo-direct-msg@corp-executive-office.com>',
    subject: 'Urgent Wire Transfer Request - Confidential Acquisition',
    sender: 'ceo.office@corp-executive-office.com',
    recipients: 'cfo@corp.internal',
    upload_timestamp: '2026-10-09T16:00:00Z',
    status: 'COMPLETED',
    is_quarantined: false,
    risk_score: 65,
    risk_category: 'HIGH',
    data_source: 'CONTROLLED_TEST',
    verdict: {
      id: 'vrd-003',
      email_id: 'eml-ceo-fraud',
      analyst_id: 'usr-analyst-002',
      verdict: 'SUSPICIOUS',
      notes: 'Executive impersonation detected with display-name spoofing and lookalike domain.',
      created_at: '2026-10-09T16:10:00Z',
      updated_at: '2026-10-09T16:10:00Z'
    }
  },
  {
    id: 'eml-clean-newsletter',
    original_filename: 'weekly_tech_radar_digest.eml',
    sha256: 'd4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b3c',
    size_bytes: 18450,
    mime_type: 'message/rfc822',
    message_id: '<digest-2026@newsletter.thoughtworks.com>',
    subject: 'Technology Radar Volume 30: AI Security Engineering',
    sender: 'news@thoughtworks.com',
    recipients: 'analyst@corp.internal',
    upload_timestamp: '2026-10-09T14:20:00Z',
    status: 'COMPLETED',
    is_quarantined: false,
    risk_score: 5,
    risk_category: 'LOW',
    data_source: 'CONTROLLED_TEST',
    verdict: {
      id: 'vrd-004',
      email_id: 'eml-clean-newsletter',
      analyst_id: 'usr-analyst-002',
      verdict: 'BENIGN',
      notes: 'Legitimate newsletter. SPF, DKIM, and DMARC passes. Clean sender reputation.',
      created_at: '2026-10-09T14:25:00Z',
      updated_at: '2026-10-09T14:25:00Z'
    }
  }
];

export const MOCK_DASHBOARD_STATS: DashboardStats = {
  emails_analyzed: 14,
  suspicious_emails: 6,
  phishing_findings_count: 22,
  attachment_findings_count: 4,
  url_findings_count: 9,
  open_cases: 3,
  recent_emails: MOCK_EMAILS,
  risk_distribution: {
    LOW: 4,
    GUARDED: 4,
    SUSPICIOUS: 3,
    HIGH: 2,
    CRITICAL: 1
  },
  auth_distribution: {
    SPF_PASS: 8,
    SPF_FAIL: 6,
    DKIM_PASS: 7,
    DKIM_FAIL: 7,
    DMARC_PASS: 6,
    DMARC_FAIL: 8
  }
};

export const MOCK_EMAIL_DETAIL: EmailSampleDetail = {
  id: 'eml-paypal-spoof',
  original_filename: 'paypal_security_alert.eml',
  sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
  sha1: '1234567890abcdef1234567890abcdef12345678',
  md5: '1234567890abcdef1234567890abcdef',
  size_bytes: 4210,
  mime_type: 'message/rfc822',
  message_id: '<alert-89218@service-paypal-verify.top>',
  subject: 'Urgent: Account Access Limited - Action Required',
  sender: 'support@service-paypal-verify.top',
  recipients: 'user@corp.internal',
  reply_to: 'collector@192.168.1.50',
  return_path: 'bounces@service-paypal-verify.top',
  received_timestamp: '2026-10-09T18:29:55Z',
  upload_timestamp: '2026-10-09T18:30:00Z',
  status: 'COMPLETED',
  is_quarantined: false,
  risk_score: 88,
  risk_category: 'CRITICAL',
  body_plain: 'Dear Customer,\n\nYour account has been temporarily restricted due to suspicious login attempts. Please confirm your identity immediately: http://service-paypal-verify.top/login.php\n\nSecurity Operations Team',
  body_html: '<p>Dear Customer,</p><p>Your account has been temporarily restricted. <a href="http://service-paypal-verify.top/login.php">Click here to restore access</a></p>',
  data_source: 'CONTROLLED_TEST',
  verdict: MOCK_EMAILS[0].verdict,
  headers: [
    { id: 'h1', header_name: 'From', header_value: 'PayPal Support <support@service-paypal-verify.top>', is_auth_header: false },
    { id: 'h2', header_name: 'To', header_value: 'user@corp.internal', is_auth_header: false },
    { id: 'h3', header_name: 'Subject', header_value: 'Urgent: Account Access Limited - Action Required', is_auth_header: false },
    { id: 'h4', header_name: 'Reply-To', header_value: 'collector@192.168.1.50', is_auth_header: false },
    { id: 'h5', header_name: 'Authentication-Results', header_value: 'spf=fail (sender IP 198.51.100.25 is not authorized) dkim=fail dmarc=fail', is_auth_header: true }
  ],
  received_hops: [
    {
      id: 'hop-1',
      hop_order: 1,
      from_host: 'mail-out.suspicious-relay.net',
      from_ip: '198.51.100.25',
      by_host: 'mx1.corp.internal',
      by_ip: '10.0.1.15',
      timestamp: '2026-10-09T18:29:58Z',
      delay_seconds: 3,
      anomaly_detected: true,
      anomaly_details: 'Unregistered relay outside SPF authorized CIDR block'
    }
  ],
  auth_results: {
    id: 'auth-01',
    spf_result: 'FAIL',
    spf_domain: 'service-paypal-verify.top',
    spf_explanation: 'IP 198.51.100.25 is not in SPF record for service-paypal-verify.top',
    dkim_result: 'FAIL',
    dkim_domain: 'service-paypal-verify.top',
    dkim_selector: 'default',
    dkim_alignment: false,
    dkim_explanation: 'Signature verification failed',
    dmarc_result: 'FAIL',
    dmarc_domain: 'service-paypal-verify.top',
    dmarc_policy: 'REJECT',
    dmarc_spf_align: false,
    dmarc_dkim_align: false
  },
  addresses: [
    { id: 'addr-1', address_type: 'FROM', raw_address: 'support@service-paypal-verify.top', normalized_address: 'support@service-paypal-verify.top', domain: 'service-paypal-verify.top' }
  ],
  domains: [
    {
      id: 'dom-1',
      domain: 'service-paypal-verify.top',
      domain_type: 'FROM',
      is_lookalike: true,
      is_punycode: false,
      subdomain_depth: 3
    }
  ],
  urls: [
    {
      id: 'url-1',
      original_url: 'http://service-paypal-verify.top/login.php',
      normalized_url: 'http://service-paypal-verify.top/login.php',
      scheme: 'http',
      hostname: 'service-paypal-verify.top',
      domain: 'service-paypal-verify.top',
      source_location: 'BODY_HTML',
      is_http: true,
      is_ip_based: false,
      is_suspicious_tld: true,
      contains_credentials: true,
      is_punycode: false,
      is_lookalike: true
    }
  ],
  attachments: [],
  phishing_findings: [
    {
      id: 'f-1',
      email_id: 'eml-paypal-spoof',
      finding_code: 'AUTH_SPF_FAIL',
      category: 'AUTHENTICATION',
      severity: 'HIGH',
      confidence: 1.0,
      evidence: 'SPF failed for sending IP 198.51.100.25',
      explanation: 'Sender IP is not authorized to deliver mail on behalf of the domain.',
      source: 'AUTH_EVALUATOR',
      created_at: '2026-10-09T18:30:02Z'
    },
    {
      id: 'f-2',
      email_id: 'eml-paypal-spoof',
      finding_code: 'URL_CREDENTIAL_HARVESTER',
      category: 'URL_ANALYSIS',
      severity: 'CRITICAL',
      confidence: 0.95,
      evidence: 'Target URL contains unencrypted HTTP with credential keyword "login.php" under .top TLD',
      explanation: 'High probability phishing link designed to steal user credentials.',
      source: 'URL_ENGINE',
      created_at: '2026-10-09T18:30:02Z'
    },
    {
      id: 'f-3',
      email_id: 'eml-paypal-spoof',
      finding_code: 'HEADER_REPLY_TO_MISMATCH',
      category: 'HEADER_ANALYSIS',
      severity: 'HIGH',
      confidence: 0.9,
      evidence: 'From address does not match Reply-To address (collector@192.168.1.50)',
      explanation: 'Replies are directed to an IP address host, typical of spearphishing campaigns.',
      source: 'HEADER_ANALYZER',
      created_at: '2026-10-09T18:30:02Z'
    }
  ],
  threat_intel_results: [],
  events: []
};

export const MOCK_CASES: EmailCase[] = [
  {
    id: 'case-001',
    case_number: 'CASE-2026-001',
    title: 'Credential Harvesting Campaign - PayPal Brand Spoofing',
    status: 'INVESTIGATING',
    priority: 'HIGH',
    severity: 'CRITICAL',
    description: 'Active phishing wave targeting finance staff with PayPal credential harvester links.',
    created_at: '2026-10-09T18:35:00Z',
    updated_at: '2026-10-09T18:40:00Z',
    emails: [MOCK_EMAILS[0]],
    notes: [
      {
        id: 'cn-1',
        case_id: 'case-001',
        author_id: 'usr-analyst-002',
        content: 'Reported domain service-paypal-verify.top to domain registrar abuse desk.',
        created_at: '2026-10-09T18:40:00Z'
      }
    ]
  },
  {
    id: 'case-002',
    case_number: 'CASE-2026-002',
    title: 'Trojanized Invoice Attachment via Overdue Invoice Email',
    status: 'CONTAINED',
    priority: 'HIGH',
    severity: 'HIGH',
    description: 'Finance mailbox received malicious executable masquerading as a PDF invoice.',
    created_at: '2026-10-09T17:25:00Z',
    updated_at: '2026-10-09T17:35:00Z',
    emails: [MOCK_EMAILS[1]],
    notes: []
  },
  {
    id: 'case-003',
    case_number: 'CASE-2026-003',
    title: 'Executive Wire Transfer Display Name Spoofing',
    status: 'OPEN',
    priority: 'MEDIUM',
    severity: 'MEDIUM',
    description: 'Attempted business email compromise targeting CFO with urgent transfer instructions.',
    created_at: '2026-10-09T16:15:00Z',
    updated_at: '2026-10-09T16:15:00Z',
    emails: [MOCK_EMAILS[2]],
    notes: []
  }
];

export const MOCK_YARA_RULES: YaraRule[] = [
  {
    id: 'yara-01',
    rule_name: 'SUSP_Phishing_Credential_Keywords',
    category: 'PHISHING',
    severity: 'HIGH',
    rule_content: 'rule SUSP_Phishing_Credential_Keywords {\n  strings:\n    $a = "verify your password"\n    $b = "confirm your account"\n  condition:\n    any of them\n}',
    is_enabled: true,
    description: 'Detects high-frequency credential harvesting phrases in email bodies',
    created_at: '2026-09-28T10:00:00Z'
  },
  {
    id: 'yara-02',
    rule_name: 'MALW_PE_Executable_Header',
    category: 'MALWARE',
    severity: 'CRITICAL',
    rule_content: 'rule MALW_PE_Executable_Header {\n  strings:\n    $mz = "MZ"\n  condition:\n    $mz at 0\n}',
    is_enabled: true,
    description: 'Detects raw portable executable (MZ) binaries in non-executable files',
    created_at: '2026-09-28T10:00:00Z'
  }
];

export const MOCK_GRAPH: RelationshipGraph = {
  nodes: [
    { id: 'eml-paypal-spoof', label: 'paypal_security_alert.eml', type: 'EMAIL', properties: { risk: 'CRITICAL' } },
    { id: 'dom-1', label: 'service-paypal-verify.top', type: 'DOMAIN', properties: { lookalike: true } },
    { id: 'url-1', label: 'http://service-paypal-verify.top/login.php', type: 'URL', properties: { credential: true } },
    { id: 'ip-1', label: '198.51.100.25', type: 'IP', properties: { unauthorized: true } }
  ],
  edges: [
    { id: 'e1', source: 'eml-paypal-spoof', target: 'dom-1', label: 'USES_DOMAIN' },
    { id: 'e2', source: 'eml-paypal-spoof', target: 'url-1', label: 'CONTAINS_URL' },
    { id: 'e3', source: 'eml-paypal-spoof', target: 'ip-1', label: 'SENT_FROM' }
  ]
};

export const MOCK_SYSTEM_STATUS: SystemStatus = {
  overall_status: 'READY',
  timestamp: new Date().toISOString(),
  processing_mode: 'local_preview',
  components: {
    database: { status: 'HEALTHY', detail: 'Local Session Storage / SQLite Compatible' },
    redis: { status: 'STANDBY', detail: 'Preview queue active' },
    celery: { status: 'STANDBY', detail: 'Local async runner active' },
    yara: { status: 'HEALTHY', detail: 'Compiled pattern engine active' },
    dns: { status: 'AVAILABLE', detail: 'Defensive passive inspection active' },
    storage: { status: 'HEALTHY', detail: 'Secure in-memory storage' },
    threat_intelligence: {
      virustotal: 'STANDBY / NOT_CONFIGURED',
      alienvault_otx: 'STANDBY / NOT_CONFIGURED',
      abuseipdb: 'STANDBY / NOT_CONFIGURED'
    }
  }
};
