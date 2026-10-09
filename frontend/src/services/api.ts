import axios from 'axios';
import {
  User, EmailSampleSummary, EmailSampleDetail, EmailCase,
  DashboardStats, RelationshipGraph, EmailComparisonResult, AuditLog, YaraRule, SystemStatus
} from '../types';

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
    const res = await api.post('/api/auth/login', credentials);
    return res.data;
  },
  register: async (userData: any) => {
    const res = await api.post('/api/auth/register', userData);
    return res.data;
  },
  getMe: async (): Promise<User> => {
    const res = await api.get('/api/auth/me');
    return res.data;
  }
};

export const emailsAPI = {
  list: async (filterSource?: string): Promise<EmailSampleSummary[]> => {
    const res = await api.get('/api/emails', {
      params: filterSource && filterSource !== 'ALL' ? { filter_source: filterSource } : {}
    });
    return res.data;
  },
  getDetail: async (id: string): Promise<EmailSampleDetail> => {
    const res = await api.get(`/api/emails/${id}`);
    return res.data;
  },
  upload: async (file?: File, rawContent?: string): Promise<EmailSampleSummary> => {
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
  },
  seedDemo: async (): Promise<EmailSampleSummary[]> => {
    const res = await api.get('/api/emails/seed-demo');
    return res.data;
  },
  analyze: async (id: string): Promise<EmailSampleSummary> => {
    const res = await api.post(`/api/emails/${id}/analyze`);
    return res.data;
  },
  setVerdict: async (id: string, verdict: string, notes?: string) => {
    const res = await api.post(`/api/emails/${id}/verdict`, { verdict, notes });
    return res.data;
  },
  compare: async (idA: string, idB: string): Promise<EmailComparisonResult> => {
    const formData = new FormData();
    formData.append('email_a_id', idA);
    formData.append('email_b_id', idB);
    const res = await api.post('/api/emails/compare', formData);
    return res.data;
  },
  delete: async (id: string) => {
    await api.delete(`/api/emails/${id}`);
  }
};

export const casesAPI = {
  list: async (): Promise<EmailCase[]> => {
    const res = await api.get('/api/cases');
    return res.data;
  },
  getDetail: async (id: string): Promise<EmailCase> => {
    const res = await api.get(`/api/cases/${id}`);
    return res.data;
  },
  create: async (caseData: any): Promise<EmailCase> => {
    const res = await api.post('/api/cases', caseData);
    return res.data;
  },
  update: async (id: string, updates: any): Promise<EmailCase> => {
    const res = await api.patch(`/api/cases/${id}`, updates);
    return res.data;
  },
  addNote: async (id: string, content: string) => {
    const res = await api.post(`/api/cases/${id}/notes`, { content });
    return res.data;
  }
};

export const dashboardAPI = {
  getStats: async (): Promise<DashboardStats> => {
    const res = await api.get('/api/dashboard/stats');
    return res.data;
  }
};

export const graphAPI = {
  getGlobal: async (): Promise<RelationshipGraph> => {
    const res = await api.get('/api/relationships');
    return res.data;
  },
  getByEmail: async (emailId: string): Promise<RelationshipGraph> => {
    const res = await api.get(`/api/emails/${emailId}/relationships`);
    return res.data;
  }
};

export const threatIntelAPI = {
  getStatus: async () => {
    const res = await api.get('/api/threat-intel/status');
    return res.data;
  },
  lookup: async (iocType: string, iocValue: string) => {
    const res = await api.post('/api/threat-intel/lookup', { ioc_type: iocType, ioc_value: iocValue });
    return res.data;
  }
};

export const reportsAPI = {
  createReport: async (emailId: string, type: 'PDF' | 'JSON') => {
    const res = await api.post(`/api/emails/${emailId}/report?report_type=${type}`);
    return res.data;
  },
  getStix: async (emailId: string) => {
    const res = await api.get(`/api/emails/${emailId}/stix`);
    return res.data;
  }
};

export const systemAPI = {
  getStatus: async (): Promise<SystemStatus> => {
    const res = await api.get('/api/system/status');
    return res.data;
  }
};

export const auditAPI = {
  list: async (): Promise<AuditLog[]> => {
    const res = await api.get('/api/audit');
    return res.data;
  }
};

export const yaraAPI = {
  getStatus: async () => {
    const res = await api.get('/api/yara/status');
    return res.data;
  },
  listRules: async (): Promise<YaraRule[]> => {
    const res = await api.get('/api/yara/rules');
    return res.data;
  },
  createRule: async (ruleData: any): Promise<YaraRule> => {
    const res = await api.post('/api/yara/rules', ruleData);
    return res.data;
  }
};

export default api;
