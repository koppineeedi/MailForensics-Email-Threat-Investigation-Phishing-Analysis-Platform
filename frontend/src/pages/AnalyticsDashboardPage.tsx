import React, { useEffect, useState, useCallback } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, LineChart, Line, CartesianGrid,
} from 'recharts';
import {
  BarChart3, Shield, AlertTriangle, CheckCircle2, XCircle,
  Link2, Briefcase, RefreshCw, Calendar, TrendingUp, AlertCircle,
  Clock,
} from 'lucide-react';
import api from '../services/api';
import { RiskBadge } from '../components/common/RiskBadge';

// ── Types ──────────────────────────────────────────────────────────────────

interface AnalyticsSummary {
  total_emails_analyzed: number;
  total_urls_analyzed: number;
  phishing_emails_detected: number;
  suspicious_emails: number;
  suspicious_urls_detected: number;
  critical_threats: number;
  open_cases: number;
  safe_emails: number;
  period_days: number | null;
}

interface RiskDistItem { category: string; count: number; color: string }
interface DetectionItem { code: string; category: string; count: number }
interface TimelineItem  { date: string; total: number; high_risk: number }
interface IncidentItem  {
  id: string; subject: string; sender: string;
  risk_score: number; risk_category: string;
  upload_timestamp: string | null; data_source: string;
}
interface SeverityItem { severity: string; count: number; color: string }
interface VerdictItem  { verdict: string; count: number }

// ── Mock fallback data (shown when backend is offline) ─────────────────────

const MOCK_SUMMARY: AnalyticsSummary = {
  total_emails_analyzed: 142,
  total_urls_analyzed: 318,
  phishing_emails_detected: 27,
  suspicious_emails: 41,
  suspicious_urls_detected: 68,
  critical_threats: 9,
  open_cases: 5,
  safe_emails: 101,
  period_days: null,
};

const MOCK_RISK_DIST: RiskDistItem[] = [
  { category: 'LOW',        count: 68,  color: '#10B981' },
  { category: 'GUARDED',    count: 33,  color: '#EAB308' },
  { category: 'SUSPICIOUS', count: 14,  color: '#F59E0B' },
  { category: 'HIGH',       count: 18,  color: '#F97316' },
  { category: 'CRITICAL',   count: 9,   color: '#F43F5E' },
];

const MOCK_DETECTIONS: DetectionItem[] = [
  { code: 'DMARC_FAILURE',               category: 'Email Auth',   count: 24 },
  { code: 'LOOKALIKE_DOMAIN',            category: 'Domain',       count: 19 },
  { code: 'CREDENTIAL_REQUEST_INDICATOR',category: 'Content',      count: 17 },
  { code: 'IP_BASED_URL',               category: 'URL',          count: 14 },
  { code: 'SPF_FAILURE',                 category: 'Email Auth',   count: 13 },
  { code: 'SUSPICIOUS_TLD_URL',          category: 'URL',          count: 11 },
  { code: 'SUSPICIOUS_ATTACHMENT',       category: 'Attachment',   count: 8  },
  { code: 'PUNYCODE_DOMAIN',             category: 'Domain',       count: 6  },
];

const MOCK_TIMELINE: TimelineItem[] = Array.from({ length: 14 }, (_, i) => {
  const d = new Date();
  d.setDate(d.getDate() - (13 - i));
  return {
    date: d.toISOString().slice(0, 10),
    total: 4 + Math.floor(Math.random() * 18),
    high_risk: Math.floor(Math.random() * 5),
  };
});

const MOCK_INCIDENTS: IncidentItem[] = [
  { id: 'e1', subject: 'Urgent: PayPal Account Suspended', sender: 'support@service-paypal-verify.top', risk_score: 88, risk_category: 'CRITICAL', upload_timestamp: new Date().toISOString(), data_source: 'CONTROLLED_TEST' },
  { id: 'e2', subject: 'OVERDUE Invoice #INV-9821 payment', sender: 'finance@billing-account-services.com', risk_score: 76, risk_category: 'HIGH', upload_timestamp: new Date().toISOString(), data_source: 'CONTROLLED_TEST' },
  { id: 'e3', subject: 'Your Microsoft account security alert', sender: 'noreply@m1crosoft-secure.xyz', risk_score: 82, risk_category: 'CRITICAL', upload_timestamp: new Date().toISOString(), data_source: 'CONTROLLED_TEST' },
];

const MOCK_SEVERITY: SeverityItem[] = [
  { severity: 'LOW',      count: 48, color: '#38BDF8' },
  { severity: 'MEDIUM',   count: 61, color: '#FBBF24' },
  { severity: 'HIGH',     count: 29, color: '#FB923C' },
  { severity: 'CRITICAL', count: 15, color: '#F43F5E' },
];

// ── Helpers ────────────────────────────────────────────────────────────────

const PERIOD_OPTIONS = [
  { label: 'All Time', value: null },
  { label: 'Last 7 Days', value: 7 },
  { label: 'Last 30 Days', value: 30 },
  { label: 'Last 90 Days', value: 90 },
];

async function fetchJSON(path: string, days?: number | null) {
  const url = days ? `${path}?days=${days}` : path;
  const res = await api.get(url);
  return res.data;
}

// ── Stat Card ──────────────────────────────────────────────────────────────

const StatCard: React.FC<{
  label: string; value: number | string;
  icon: React.FC<{ className?: string }>;
  color: string; sub?: string;
}> = ({ label, value, icon: Icon, color, sub }) => (
  <div className="bg-soc-card border border-soc-border rounded-xl p-4 flex flex-col gap-2">
    <div className="flex items-center justify-between">
      <span className="text-xs font-mono text-slate-400 uppercase tracking-wide">{label}</span>
      <Icon className={`w-4 h-4 ${color}`} />
    </div>
    <div className={`text-2xl font-mono font-bold ${color}`}>{value}</div>
    {sub && <div className="text-[11px] text-slate-500 font-mono">{sub}</div>}
  </div>
);

// ── Custom Tooltip ─────────────────────────────────────────────────────────

const ChartTooltip: React.FC<any> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-soc-card border border-soc-border rounded-lg p-2 text-xs font-mono shadow-xl">
      <div className="text-slate-300 mb-1">{label}</div>
      {payload.map((p: any) => (
        <div key={p.dataKey} style={{ color: p.color }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  );
};

// ── Main Page ──────────────────────────────────────────────────────────────

export const AnalyticsDashboardPage: React.FC = () => {
  const [period, setPeriod] = useState<number | null>(30);
  const [loading, setLoading] = useState(true);
  const [isMock, setIsMock] = useState(false);

  const [summary, setSummary]       = useState<AnalyticsSummary>(MOCK_SUMMARY);
  const [riskDist, setRiskDist]     = useState<RiskDistItem[]>(MOCK_RISK_DIST);
  const [detections, setDetections] = useState<DetectionItem[]>(MOCK_DETECTIONS);
  const [timeline, setTimeline]     = useState<TimelineItem[]>(MOCK_TIMELINE);
  const [incidents, setIncidents]   = useState<IncidentItem[]>(MOCK_INCIDENTS);
  const [severity, setSeverity]     = useState<SeverityItem[]>(MOCK_SEVERITY);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [sum, rd, det, tl, inc, sev] = await Promise.all([
        fetchJSON('/api/analytics/summary', period),
        fetchJSON('/api/analytics/risk-distribution', period),
        fetchJSON('/api/analytics/detection-types', period),
        fetchJSON('/api/analytics/activity-timeline', period || 30),
        fetchJSON('/api/analytics/recent-incidents'),
        fetchJSON('/api/analytics/severity-distribution', period),
      ]);
      setSummary(sum);
      setRiskDist(rd.distribution || []);
      setDetections(det.top_detections || []);
      setTimeline(tl.timeline || []);
      setIncidents(inc.incidents || []);
      setSeverity(sev.severity_distribution || []);
      setIsMock(false);
    } catch {
      // Backend offline — keep mock data
      setIsMock(true);
    } finally {
      setLoading(false);
    }
  }, [period]);

  useEffect(() => { loadAll(); }, [loadAll]);

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-xl">
            <BarChart3 className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100 tracking-wide">SECURITY ANALYTICS</h1>
            <p className="text-xs text-slate-400 font-mono mt-0.5">Real-time threat intelligence from backend database</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Period filter */}
          <div className="flex items-center gap-1 bg-soc-card border border-soc-border rounded-lg p-1">
            {PERIOD_OPTIONS.map(opt => (
              <button
                key={String(opt.value)}
                onClick={() => setPeriod(opt.value)}
                className={`px-3 py-1 text-xs rounded font-mono transition-colors ${
                  period === opt.value
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <button
            onClick={loadAll}
            disabled={loading}
            className="p-2 bg-soc-card border border-soc-border rounded-lg text-slate-400 hover:text-slate-200 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ── Mock banner ── */}
      {isMock && (
        <div className="flex items-center gap-2 p-3 bg-amber-950/40 border border-amber-700/40 rounded-xl text-xs text-amber-300 font-mono">
          <AlertCircle className="w-4 h-4 shrink-0" />
          Preview mode — backend offline. Showing labelled demo data.
          Connect backend in Login → Backend API Server Settings.
        </div>
      )}

      {/* ── KPI Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Emails Analyzed"      value={summary.total_emails_analyzed} icon={Shield}        color="text-sky-400"     sub="total samples ingested" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="URLs Analyzed"         value={summary.total_urls_analyzed}   icon={Link2}         color="text-purple-400"  sub="extracted from emails" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Phishing Detected"     value={summary.phishing_emails_detected} icon={AlertTriangle} color="text-orange-400" sub="HIGH + CRITICAL emails" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Critical Threats"      value={summary.critical_threats}      icon={XCircle}       color="text-rose-400"    sub="score 80–100" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Suspicious URLs"       value={summary.suspicious_urls_detected} icon={Link2}      color="text-amber-400"   sub="IP/TLD/credential hits" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Safe Emails"            value={summary.safe_emails}           icon={CheckCircle2}  color="text-emerald-400" sub="LOW + GUARDED" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Suspicious Emails"     value={summary.suspicious_emails}     icon={AlertCircle}   color="text-yellow-400"  sub="SUSPICIOUS + above" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Open Cases"            value={summary.open_cases}            icon={Briefcase}     color="text-blue-400"    sub="OPEN + INVESTIGATING" />
        </div>
      </div>

      {/* ── Charts Row 1 ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Pie */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5">
          <h2 className="text-sm font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-400" />
            RISK CATEGORY DISTRIBUTION
          </h2>
          {riskDist.length === 0 ? (
            <EmptyChart />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={riskDist}
                  dataKey="count"
                  nameKey="category"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  innerRadius={40}
                  label={({ category, count }) => count > 0 ? `${category}: ${count}` : ''}
                  labelLine={false}
                >
                  {riskDist.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
                <Legend
                  iconSize={10}
                  formatter={(value) => <span className="text-xs font-mono text-slate-300">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Severity Distribution Bar */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5">
          <h2 className="text-sm font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            FINDING SEVERITY DISTRIBUTION
          </h2>
          {severity.length === 0 ? (
            <EmptyChart />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severity} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="severity" tick={{ fill: '#64748B', fontSize: 11, fontFamily: 'monospace' }} />
                <YAxis tick={{ fill: '#64748B', fontSize: 11 }} />
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="count" name="Count" radius={[4, 4, 0, 0]}>
                  {severity.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── Activity Timeline ── */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-5">
        <h2 className="text-sm font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-sky-400" />
          ANALYSIS ACTIVITY OVER TIME
          <span className="text-xs text-slate-500 font-normal ml-2">
            (last {period || 'all'} days)
          </span>
        </h2>
        {timeline.length === 0 ? (
          <EmptyChart />
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timeline} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
              <XAxis
                dataKey="date"
                tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
                tickFormatter={d => d.slice(5)}
              />
              <YAxis tick={{ fill: '#64748B', fontSize: 11 }} allowDecimals={false} />
              <Tooltip content={<ChartTooltip />} />
              <Line type="monotone" dataKey="total"     name="Total Analyzed" stroke="#38BDF8" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="high_risk" name="High/Critical"  stroke="#F43F5E" strokeWidth={2} dot={false} strokeDasharray="4 2" />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* ── Charts Row 2 ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Detection Types */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5">
          <h2 className="text-sm font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-purple-400" />
            TOP DETECTION TYPES
          </h2>
          {detections.length === 0 ? (
            <EmptyChart />
          ) : (
            <div className="space-y-2">
              {detections.slice(0, 8).map((d, i) => {
                const max = detections[0]?.count || 1;
                const pct = (d.count / max) * 100;
                return (
                  <div key={d.code} className="flex items-center gap-3 text-xs font-mono">
                    <span className="w-5 text-slate-500 text-right shrink-0">{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-slate-300 truncate">{d.code.replace(/_/g, ' ')}</div>
                      <div className="mt-0.5 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-indigo-500 rounded-full transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                    <span className="text-slate-400 shrink-0">{d.count}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Recent Incidents */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5">
          <h2 className="text-sm font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
            <Clock className="w-4 h-4 text-rose-400" />
            RECENT HIGH-RISK INCIDENTS
          </h2>
          {incidents.length === 0 ? (
            <EmptyChart label="No high-risk incidents found" />
          ) : (
            <div className="space-y-2">
              {incidents.map(inc => (
                <div
                  key={inc.id}
                  className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg"
                >
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <span className="text-xs text-slate-200 font-medium truncate">{inc.subject}</span>
                    <RiskBadge category={inc.risk_category} score={inc.risk_score} />
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono truncate">{inc.sender}</div>
                  {inc.upload_timestamp && (
                    <div className="text-[10px] text-slate-600 mt-1">
                      {new Date(inc.upload_timestamp).toLocaleString()}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ── Empty Chart placeholder ────────────────────────────────────────────────

const EmptyChart: React.FC<{ label?: string }> = ({ label = 'No data for this period' }) => (
  <div className="h-32 flex items-center justify-center border border-dashed border-slate-800 rounded-lg">
    <span className="text-xs font-mono text-slate-500">{label}</span>
  </div>
);
