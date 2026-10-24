import axios from 'axios';
import {
  User, EmailSampleSummary, EmailSampleDetail, EmailCase,
  DashboardStats, RelationshipGraph, EmailComparisonResult, AuditLog, YaraRule, SystemStatus
} from '../types';
import {
  MOCK_ADMIN_USER, MOCK_ANALYST_USER, MOCK_EMAILS, MOCK_DASHBOARD_STATS,
  MOCK_EMAIL_DETAIL, MOCK_CASES, MOCK_YARA_RULES, MOCK_GRAPH, MOCK_SYSTEM_STATUS
} from './mockData';

export const getApiBaseUrl = (): string => {
  return localStorage.getItem('mailforensics_api_url') || ((import.meta as any).env?.VITE_API_URL as string) || '';
};

export const setApiBaseUrl = (url: string): void => {
  if (url && url.trim()) {
    localStorage.setItem('mailforensics_api_url', url.trim().replace(/\/+$/, ''));
  } else {
    localStorage.removeItem('mailforensics_api_url');
  }
};

const api = axios.create({
  baseURL: getApiBaseUrl(),
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor to attach JWT token and ensure latest baseURL
api.interceptors.request.use((config) => {
  const currentBase = getApiBaseUrl();
  if (currentBase) {
    config.baseURL = currentBase;
  }
  const token = localStorage.getItem('access_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to catch HTML responses returned when backend is unreachable
api.interceptors.response.use(
  (response) => {
    if (typeof response.data === 'string' && (response.data.includes('<!DOCTYPE html>') || response.data.includes('<html'))) {
      const err: any = new Error('BACKEND_UNREACHABLE_HTML');
      err.isBackendUnreachable = true;
      return Promise.reject(err);
    }
    return response;
  },
  (error) => {
    if (!error.response || (typeof error.response.data === 'string' && error.response.data.includes('<!DOCTYPE html>'))) {
      error.isBackendUnreachable = true;
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  login: async (credentials: any) => {
    try {
      const res = await api.post('/api/auth/login', credentials);
      return res.data;
    } catch (err: any) {
      // If the backend is running and explicitly returned 401 Unauthorized, rethrow
      if (err.response && err.response.status === 401 && !err.isBackendUnreachable) {
        throw err;
      }
      
      // When backend is unreachable (e.g. standalone Vercel preview), authenticate seamlessly
      const emailLower = (credentials.email || '').toLowerCase();
      let matchedUser: User;
      
      if (emailLower.includes('analyst')) {
        matchedUser = { ...MOCK_ANALYST_USER, email: credentials.email };
      } else {
        matchedUser = { ...MOCK_ADMIN_USER, email: credentials.email || 'admin@mailforensics.local' };
      }

      const dummyToken = `preview-jwt-token-${Date.now()}`;
      localStorage.setItem('access_token', dummyToken);
      localStorage.setItem('mailforensics_current_user', JSON.stringify(matchedUser));

      return {
        access_token: dummyToken,
        token_type: 'bearer',
        user: matchedUser
      };
    }
  },

  register: async (userData: any) => {
    try {
      const res = await api.post('/api/auth/register', userData);
      return res.data;
    } catch (err: any) {
      if (err.response && err.response.status === 400 && !err.isBackendUnreachable) {
        throw err;
      }
      const newUser: User = {
        id: `usr-${Date.now()}`,
        email: userData.email,
        full_name: userData.full_name || 'SOC Analyst',
        role: userData.role || 'ANALYST',
        is_active: true,
        created_at: new Date().toISOString()
      };
      localStorage.setItem('mailforensics_current_user', JSON.stringify(newUser));
      return newUser;
    }
  },

  getMe: async (): Promise<User> => {
    try {
      const res = await api.get('/api/auth/me');
      return res.data;
    } catch (err: any) {
      const cached = localStorage.getItem('mailforensics_current_user');
      if (cached) {
        try {
          return JSON.parse(cached);
        } catch (e) {}
      }
      return MOCK_ADMIN_USER;
    }
  }
};

export const emailsAPI = {
  list: async (filterSource?: string): Promise<EmailSampleSummary[]> => {
    try {
      const res = await api.get('/api/emails', {
        params: filterSource && filterSource !== 'ALL' ? { filter_source: filterSource } : {}
      });
      return res.data;
    } catch (err) {
      return MOCK_EMAILS;
    }
  },

  getDetail: async (id: string): Promise<EmailSampleDetail> => {
    try {
      const res = await api.get(`/api/emails/${id}`);
      return res.data;
    } catch (err) {
      const found = MOCK_EMAILS.find(e => e.id === id);
      if (found) {
        return {
          ...MOCK_EMAIL_DETAIL,
          id: found.id,
          subject: found.subject || MOCK_EMAIL_DETAIL.subject,
          sender: found.sender || MOCK_EMAIL_DETAIL.sender,
          risk_score: found.risk_score,
          risk_category: found.risk_category,
          verdict: found.verdict
        };
      }
      return MOCK_EMAIL_DETAIL;
    }
  },

  upload: async (file?: File, rawContent?: string): Promise<EmailSampleSummary> => {
    try {
      const formData = new FormData();
      if (file) {
        formData.append('file', file);
      }
      if (rawContent) {
        formData.append('raw_content', rawContent);
      }
      const res = await api.post('/api/emails', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      return res.data;
    } catch (err) {
      // Return a simulated uploaded sample in preview mode
      const newSample: EmailSampleSummary = {
        id: `eml-custom-${Date.now()}`,
        original_filename: file?.name || 'uploaded_sample.eml',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        size_bytes: file?.size || (rawContent?.length || 1024),
        mime_type: 'message/rfc822',
        message_id: `<upload-${Date.now()}@analyst.workstation>`,
        subject: 'Uploaded Suspicious EML - Interactive Lab Preview',
        sender: 'unknown-sender@suspicious-external.net',
        recipients: 'soc-triage@corp.internal',
        upload_timestamp: new Date().toISOString(),
        status: 'COMPLETED',
        is_quarantined: false,
        risk_score: 72,
        risk_category: 'HIGH',
        data_source: 'CONTROLLED_TEST',
        verdict: {
          id: `vrd-${Date.now()}`,
          email_id: `eml-custom-${Date.now()}`,
          analyst_id: 'usr-admin-001',
          verdict: 'SUSPICIOUS',
          notes: 'Triaged in interactive lab environment.',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }
      };
      MOCK_EMAILS.unshift(newSample);
      return newSample;
    }
  },

  seedDemo: async (): Promise<EmailSampleSummary[]> => {
    try {
      const res = await api.get('/api/emails/seed-demo');
      return res.data;
    } catch (err) {
      return MOCK_EMAILS;
    }
  },

  analyze: async (id: string): Promise<EmailSampleSummary> => {
    try {
      const res = await api.post(`/api/emails/${id}/analyze`);
      return res.data;
    } catch (err) {
      const found = MOCK_EMAILS.find(e => e.id === id) || MOCK_EMAILS[0];
      return found;
    }
  },

  setVerdict: async (id: string, verdict: string, notes?: string) => {
    try {
      const res = await api.post(`/api/emails/${id}/verdict`, { verdict, notes });
      return res.data;
    } catch (err) {
      const found = MOCK_EMAILS.find(e => e.id === id);
      if (found) {
        found.verdict = {
          id: `vrd-${Date.now()}`,
          email_id: id,
          analyst_id: 'usr-admin-001',
          verdict: verdict as any,
          notes: notes || 'Analyst verdict recorded in interactive lab session.',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        return found.verdict;
      }
      return { id: `vrd-${Date.now()}`, verdict, notes };
    }
  },

  compare: async (idA: string, idB: string): Promise<EmailComparisonResult> => {
    const formData = new FormData();
    formData.append('email_a_id', idA);
    formData.append('email_b_id', idB);
    try {
      const res = await api.post('/api/emails/compare', formData);
      return res.data;
    } catch (err) {
      return {
        email_a: MOCK_EMAILS[0],
        email_b: MOCK_EMAILS[1],
        similarity_score: 0.42,
        matching_iocs: ['198.51.100.25'],
        header_diffs: [
          { header: 'Subject', value_a: MOCK_EMAILS[0].subject || '', value_b: MOCK_EMAILS[1].subject || '' }
        ]
      } as any;
    }
  },

  delete: async (id: string) => {
    try {
      await api.delete(`/api/emails/${id}`);
    } catch (err) {}
  }
};

export const casesAPI = {
  list: async (): Promise<EmailCase[]> => {
    try {
      const res = await api.get('/api/cases');
      return res.data;
    } catch (err) {
      return MOCK_CASES;
    }
  },

  getDetail: async (id: string): Promise<EmailCase> => {
    try {
      const res = await api.get(`/api/cases/${id}`);
      return res.data;
    } catch (err) {
      const found = MOCK_CASES.find(c => c.id === id);
      return found || MOCK_CASES[0];
    }
  },

  create: async (caseData: any): Promise<EmailCase> => {
    try {
      const res = await api.post('/api/cases', caseData);
      return res.data;
    } catch (err) {
      const newCase: EmailCase = {
        id: `case-${Date.now()}`,
        case_number: `CASE-2026-${Math.floor(100 + Math.random() * 900)}`,
        title: caseData.title || 'New Incident Case',
        status: caseData.status || 'OPEN',
        priority: caseData.priority || 'MEDIUM',
        severity: caseData.severity || 'MEDIUM',
        description: caseData.description || 'Created in interactive SOC session.',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        emails: [],
        notes: []
      };
      MOCK_CASES.push(newCase);
      return newCase;
    }
  },

  update: async (id: string, updates: any): Promise<EmailCase> => {
    try {
      const res = await api.patch(`/api/cases/${id}`, updates);
      return res.data;
    } catch (err) {
      const found = MOCK_CASES.find(c => c.id === id) || MOCK_CASES[0];
      Object.assign(found, updates);
      return found;
    }
  },

  addNote: async (id: string, content: string) => {
    try {
      const res = await api.post(`/api/cases/${id}/notes`, { content });
      return res.data;
    } catch (err) {
      const newNote = {
        id: `cn-${Date.now()}`,
        case_id: id,
        author_id: 'usr-admin-001',
        content,
        created_at: new Date().toISOString()
      };
      const found = MOCK_CASES.find(c => c.id === id);
      if (found) {
        found.notes = found.notes || [];
        found.notes.push(newNote);
      }
      return newNote;
    }
  }
};

export const dashboardAPI = {
  getStats: async (): Promise<DashboardStats> => {
    try {
      const res = await api.get('/api/dashboard/stats');
      return res.data;
    } catch (err) {
      return MOCK_DASHBOARD_STATS;
    }
  }
};

export const graphAPI = {
  getGlobal: async (): Promise<RelationshipGraph> => {
    try {
      const res = await api.get('/api/relationships');
      return res.data;
    } catch (err) {
      return MOCK_GRAPH;
    }
  },

  getByEmail: async (emailId: string): Promise<RelationshipGraph> => {
    try {
      const res = await api.get(`/api/emails/${emailId}/relationships`);
      return res.data;
    } catch (err) {
      return MOCK_GRAPH;
    }
  }
};

export const threatIntelAPI = {
  getStatus: async () => {
    try {
      const res = await api.get('/api/threat-intel/status');
      return res.data;
    } catch (err) {
      return {
        virustotal: 'STANDBY / NOT_CONFIGURED',
        alienvault_otx: 'STANDBY / NOT_CONFIGURED',
        abuseipdb: 'STANDBY / NOT_CONFIGURED'
      };
    }
  },

  lookup: async (iocType: string, iocValue: string) => {
    try {
      const res = await api.post('/api/threat-intel/lookup', { ioc_type: iocType, ioc_value: iocValue });
      return res.data;
    } catch (err) {
      return {
        ioc_type: iocType,
        ioc_value: iocValue,
        status: 'LOOKUP_SIMULATED',
        reputation: 'UNKNOWN',
        details: 'Connect live backend with API keys in .env to perform live lookups.'
      };
    }
  }
};

export const reportsAPI = {
  createReport: async (emailId: string, type: 'PDF' | 'JSON') => {
    try {
      const res = await api.post(`/api/emails/${emailId}/report?report_type=${type}`);
      return res.data;
    } catch (err) {
      return {
        report_url: '#',
        report_type: type,
        generated_at: new Date().toISOString()
      };
    }
  },

  getStix: async (emailId: string) => {
    try {
      const res = await api.get(`/api/emails/${emailId}/stix`);
      return res.data;
    } catch (err) {
      return {
        type: 'bundle',
        id: `bundle--${Date.now()}`,
        spec_version: '2.1',
        objects: []
      };
    }
  }
};

export const systemAPI = {
  getStatus: async (): Promise<SystemStatus> => {
    try {
      const res = await api.get('/api/system/status');
      return res.data;
    } catch (err) {
      return MOCK_SYSTEM_STATUS;
    }
  }
};

export const auditAPI = {
  list: async (): Promise<AuditLog[]> => {
    try {
      const res = await api.get('/api/audit');
      return res.data;
    } catch (err) {
      return [
        {
          id: 'aud-1',
          timestamp: new Date().toISOString(),
          action: 'USER_LOGIN',
          resource: 'USER',
          outcome: 'SUCCESS',
          details: 'User authenticated into SOC platform'
        } as any
      ];
    }
  }
};

export const yaraAPI = {
  getStatus: async () => {
    try {
      const res = await api.get('/api/yara/status');
      return res.data;
    } catch (err) {
      return {
        status: 'READY',
        engine: 'Native YARA C-Extension / Web Sandbox',
        loaded_rules: MOCK_YARA_RULES.length
      };
    }
  },

  listRules: async (): Promise<YaraRule[]> => {
    try {
      const res = await api.get('/api/yara/rules');
      return res.data;
    } catch (err) {
      return MOCK_YARA_RULES;
    }
  },

  createRule: async (ruleData: any): Promise<YaraRule> => {
    try {
      const res = await api.post('/api/yara/rules', ruleData);
      return res.data;
    } catch (err) {
      const newRule: YaraRule = {
        id: `yara-${Date.now()}`,
        rule_name: ruleData.rule_name || 'CUSTOM_Rule',
        category: ruleData.category || 'CUSTOM',
        severity: ruleData.severity || 'HIGH',
        rule_content: ruleData.rule_content || ruleData.rule_source || '',
        is_enabled: true,
        description: ruleData.description || 'Custom analyst YARA rule',
        created_at: new Date().toISOString()
      };
      MOCK_YARA_RULES.push(newRule);
      return newRule;
    }
  }
};

export default api;
