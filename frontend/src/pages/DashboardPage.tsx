import React, { useEffect, useState } from 'react';
import { dashboardAPI, emailsAPI } from '../services/api';
import { DashboardStats } from '../types';
import { RiskBadge } from '../components/common/RiskBadge';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { Mail, ShieldAlert, Paperclip, Link, Briefcase, RefreshCw, AlertTriangle } from 'lucide-react';
import { Link as RouterLink } from 'react-router-dom';

export const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const data = await dashboardAPI.getStats();
      setStats(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleSeedDemo = async () => {
    setSeeding(true);
    try {
      await emailsAPI.seedDemo();
      await fetchStats();
    } catch (e) {
      console.error(e);
    } finally {
      setSeeding(false);
    }
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 font-mono text-sm">
        Loading SOC metrics from backend database...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-wide">SOC DEFENSIVE DASHBOARD</h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">Real-time Backend Database Metrics & Investigation Telemetry</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleSeedDemo}
            disabled={seeding}
            className="px-3 py-1.5 bg-sky-600/20 hover:bg-sky-600/30 border border-sky-500/40 text-sky-300 text-xs font-mono rounded-lg transition-colors flex items-center gap-2"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${seeding ? 'animate-spin' : ''}`} />
            <span>{seeding ? 'Seeding Demo Samples...' : 'Seed Controlled Lab Demo Samples'}</span>
          </button>
          <button
            onClick={fetchStats}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
            title="Refresh Metrics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Primary KPI Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-soc-card border border-soc-border rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">EMLS ANALYZED</span>
            <Mail className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-slate-100">{stats?.emails_analyzed || 0}</div>
        </div>

        <div className="bg-soc-card border border-soc-border rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">SUSPICIOUS EMLS</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-amber-400">{stats?.suspicious_emails || 0}</div>
        </div>

        <div className="bg-soc-card border border-soc-border rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">PHISHING FINDINGS</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-rose-400">{stats?.phishing_findings_count || 0}</div>
        </div>

        <div className="bg-soc-card border border-soc-border rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">ATTACHMENT FINDINGS</span>
            <Paperclip className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-purple-400">{stats?.attachment_findings_count || 0}</div>
        </div>

        <div className="bg-soc-card border border-soc-border rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">SUSPICIOUS URLS</span>
            <Link className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-400">{stats?.url_findings_count || 0}</div>
        </div>

        <div className="bg-soc-card border border-soc-border rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">OPEN CASES</span>
            <Briefcase className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-blue-400">{stats?.open_cases || 0}</div>
        </div>
      </div>

      {/* Distribution Grids */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Risk Category Distribution */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5">
          <h2 className="text-sm font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-sky-400" />
            AUTOMATED RISK CATEGORY DISTRIBUTION
          </h2>
          <div className="space-y-3 font-mono text-xs">
            {Object.entries(stats?.risk_distribution || {}).map(([cat, count]) => (
              <div key={cat} className="flex items-center justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
                <RiskBadge category={cat} />
                <span className="font-bold text-slate-200">{count} samples</span>
              </div>
            ))}
          </div>
        </div>

        {/* Authentication Distribution */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-5">
          <h2 className="text-sm font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
            <Mail className="w-4 h-4 text-emerald-400" />
            EMAIL AUTHENTICATION RESULT TELEMETRY
          </h2>
          <div className="grid grid-cols-2 gap-3 font-mono text-xs">
            {Object.entries(stats?.auth_distribution || {}).map(([key, count]) => {
              const isPass = key.endsWith('_PASS');
              return (
                <div key={key} className={`p-3 rounded-lg border flex flex-col justify-between ${
                  isPass ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300' : 'bg-rose-950/20 border-rose-800/40 text-rose-300'
                }`}>
                  <span className="text-[11px] text-slate-400">{key.replace('_', ' ')}</span>
                  <span className="text-xl font-bold mt-1">{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Email Investigations Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-bold text-slate-200 font-mono">RECENT EMAIL SAMPLE TRIAGE</h2>
          <RouterLink to="/emails" className="text-xs text-sky-400 hover:text-sky-300 font-mono">View All Samples →</RouterLink>
        </div>

        {!stats?.recent_emails.length ? (
          <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
            No email samples analyzed yet. Click "Seed Controlled Lab Demo Samples" above to ingest lab email artifacts.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-soc-border uppercase text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Subject / Filename</th>
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">SHA-256</th>
                  <th className="py-2.5 px-3">Risk Category</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {stats.recent_emails.map((sample) => (
                  <tr key={sample.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-100 max-w-xs truncate">{sample.subject || sample.original_filename}</div>
                      <div className="text-[10px] text-slate-500">{sample.original_filename}</div>
                    </td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate">{sample.sender || '—'}</td>
                    <td className="py-3 px-3 text-slate-500 text-[10px]">{sample.sha256.substring(0, 16)}...</td>
                    <td className="py-3 px-3">
                      <RiskBadge category={sample.risk_category} score={sample.risk_score} />
                    </td>
                    <td className="py-3 px-3">
                      <VerdictBadge verdict={sample.verdict?.verdict} />
                    </td>
                    <td className="py-3 px-3">
                      <RouterLink
                        to={`/emails/${sample.id}`}
                        className="px-2.5 py-1 bg-sky-600/20 hover:bg-sky-600/40 text-sky-300 border border-sky-500/30 rounded text-[11px] transition-colors"
                      >
                        Investigate
                      </RouterLink>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
