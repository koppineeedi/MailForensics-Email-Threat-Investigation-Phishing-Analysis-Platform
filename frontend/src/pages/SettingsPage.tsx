import React, { useEffect, useState } from 'react';
import { yaraAPI, systemAPI } from '../services/api';
import { YaraRule, SystemStatus } from '../types';
import { Settings, Shield, Plus, CheckCircle, AlertTriangle, Server, Database, Cpu, Radio, Globe, Folder, Key, RefreshCw } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [yaraStatus, setYaraStatus] = useState<any | null>(null);
  const [rules, setRules] = useState<YaraRule[]>([]);
  const [loading, setLoading] = useState(true);

  // New Rule Form
  const [showModal, setShowModal] = useState(false);
  const [ruleName, setRuleName] = useState('');
  const [description, setDescription] = useState('');
  const [ruleContent, setRuleContent] = useState('');
  const [saving, setSaving] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [sysRes, yaraRes, rulesRes] = await Promise.all([
        systemAPI.getStatus().catch(() => null),
        yaraAPI.getStatus().catch(() => null),
        yaraAPI.listRules().catch(() => [])
      ]);
      setSystemStatus(sysRes);
      setYaraStatus(yaraRes);
      setRules(rulesRes);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await yaraAPI.createRule({ rule_name: ruleName, description, rule_content: ruleContent });
      setShowModal(false);
      setRuleName('');
      setDescription('');
      setRuleContent('');
      await fetchData();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create YARA rule.');
    } finally {
      setSaving(false);
    }
  };

  const getStatusBadge = (status?: string) => {
    const s = (status || 'UNKNOWN').toUpperCase();
    if (s === 'HEALTHY' || s === 'AVAILABLE' || s === 'LIVE_PROVIDER_VERIFIED' || s === 'VERIFIED') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800">{s}</span>;
    }
    if (s === 'STANDBY' || s === 'NOT_CONFIGURED' || s === 'CONFIGURED') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800">{s}</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 text-rose-400 border border-rose-800">{s}</span>;
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
            <Settings className="w-5 h-5 text-sky-400" />
            SYSTEM STATUS & DEFENSIVE CONFIGURATION
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">Real Infrastructure Health, Processing Queues & YARA Detection Rules</p>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded-lg transition-colors flex items-center gap-2 border border-slate-700 w-fit"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* System Infrastructure Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-bold text-slate-300 font-mono flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            REAL INFRASTRUCTURE & BACKEND HEALTH
          </h2>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-500">MODE:</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-950/80 text-sky-400 border border-sky-800">
              {systemStatus?.processing_mode || 'LOCAL'}
            </span>
            <span className="text-slate-500 ml-2">OVERALL:</span>
            {getStatusBadge(systemStatus?.overall_status || 'UNKNOWN')}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
          {/* Database */}
          <div className="p-4 bg-soc-card border border-soc-border rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-200 font-bold flex items-center gap-2">
                <Database className="w-4 h-4 text-sky-400" />
                Database Engine
              </span>
              {getStatusBadge(systemStatus?.components.database.status)}
            </div>
            <div className="text-[11px] text-slate-400 space-y-1 pt-1">
              <div><b>Dialect:</b> {systemStatus?.components.database.dialect || 'SQLite'}</div>
              <div><b>Engine:</b> {systemStatus?.components.database.engine || 'sqlite'}</div>
              {systemStatus?.components.database.pool_size !== undefined && (
                <div><b>Pool Size:</b> {systemStatus.components.database.pool_size} (Overflow: {systemStatus.components.database.max_overflow})</div>
              )}
            </div>
          </div>

          {/* Celery Worker */}
          <div className="p-4 bg-soc-card border border-soc-border rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-200 font-bold flex items-center gap-2">
                <Cpu className="w-4 h-4 text-amber-400" />
                Celery Distributed Queue
              </span>
              {getStatusBadge(systemStatus?.components.celery.status)}
            </div>
            <div className="text-[11px] text-slate-400 space-y-1 pt-1">
              <div><b>Mode:</b> {systemStatus?.components.celery.mode || 'local (synchronous)'}</div>
              <div><b>Active Workers:</b> {systemStatus?.components.celery.active_workers ?? 0}</div>
              <div className="text-[10px] text-slate-500 truncate">{systemStatus?.components.celery.detail || 'Synchronous execution fallback'}</div>
            </div>
          </div>

          {/* Redis Broker */}
          <div className="p-4 bg-soc-card border border-soc-border rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-200 font-bold flex items-center gap-2">
                <Radio className="w-4 h-4 text-rose-400" />
                Redis Message Broker
              </span>
              {getStatusBadge(systemStatus?.components.redis.status)}
            </div>
            <div className="text-[11px] text-slate-400 space-y-1 pt-1">
              <div><b>Connected:</b> {systemStatus?.components.redis.connected ? 'True' : 'False'}</div>
              <div className="text-[10px] text-slate-500 truncate">{systemStatus?.components.redis.detail || 'Broker standby'}</div>
            </div>
          </div>

          {/* YARA Engine */}
          <div className="p-4 bg-soc-card border border-soc-border rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-200 font-bold flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                YARA Static Engine
              </span>
              {getStatusBadge(systemStatus?.components.yara.status)}
            </div>
            <div className="text-[11px] text-slate-400 space-y-1 pt-1">
              <div><b>Engine:</b> {systemStatus?.components.yara.engine || 'NATIVE'}</div>
              <div><b>Version:</b> {systemStatus?.components.yara.version || '4.5.4'}</div>
              <div><b>Compiled Rules:</b> {systemStatus?.components.yara.rules_loaded ?? rules.length}</div>
            </div>
          </div>

          {/* DNS Verifier */}
          <div className="p-4 bg-soc-card border border-soc-border rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-200 font-bold flex items-center gap-2">
                <Globe className="w-4 h-4 text-indigo-400" />
                Live DNS Resolver
              </span>
              {getStatusBadge(systemStatus?.components.dns.status)}
            </div>
            <div className="text-[11px] text-slate-400 space-y-1 pt-1">
              <div><b>Resolver:</b> {systemStatus?.components.dns.resolver_configured ? 'dnspython (system/8.8.8.8)' : 'None'}</div>
              <div className="text-[10px] text-slate-500">SPF / DKIM / DMARC verification</div>
            </div>
          </div>

          {/* Storage */}
          <div className="p-4 bg-soc-card border border-soc-border rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-200 font-bold flex items-center gap-2">
                <Folder className="w-4 h-4 text-teal-400" />
                Artifact Storage
              </span>
              {getStatusBadge(systemStatus?.components.storage.status)}
            </div>
            <div className="text-[11px] text-slate-400 space-y-1 pt-1">
              <div className="truncate"><b>Path:</b> {systemStatus?.components.storage.path || './uploads'}</div>
              <div><b>Writable:</b> {systemStatus?.components.storage.writable ? 'Yes' : 'No'}</div>
            </div>
          </div>
        </div>

        {/* Threat Intelligence Providers Status */}
        <div className="p-4 bg-soc-card border border-soc-border rounded-xl space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-soc-border pb-2">
            <span className="text-slate-200 font-bold flex items-center gap-2">
              <Key className="w-4 h-4 text-amber-400" />
              LIVE THREAT INTELLIGENCE PROVIDER INTEGRATIONS
            </span>
            <span className="text-[10px] text-slate-500">No Mock Data — Live APIs Require Configured Keys</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-1">
            {systemStatus?.components.threat_intelligence && Object.entries(systemStatus.components.threat_intelligence).map(([prov, st]) => (
              <div key={prov} className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[11px] font-bold text-slate-300 uppercase truncate">{prov.replace('_', ' ')}</div>
                <div>{getStatusBadge(st)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* YARA Rules Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-bold text-slate-200 font-mono text-xs">DEFENSIVE YARA RULES ({rules.length})</h3>
          <button
            onClick={() => setShowModal(true)}
            className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono rounded-lg transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            <span>Create YARA Rule</span>
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-400 font-mono text-xs">Loading YARA rules...</div>
        ) : (
          <div className="space-y-4 font-mono text-xs">
            {rules.map((r) => (
              <div key={r.id} className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sky-400 text-sm">{r.rule_name}</span>
                  <span className="text-[10px] text-slate-400">{r.category} ({r.severity})</span>
                </div>
                <p className="text-slate-300">{r.description || 'No description provided.'}</p>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded text-[11px] text-slate-400 overflow-x-auto">
                  {r.rule_content}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Rule Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <h2 className="text-sm font-bold text-slate-100">CREATE DEFENSIVE YARA RULE</h2>
              <button onClick={() => setShowModal(false)} className="text-slate-400">✕</button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-4">
              <div>
                <label className="block text-slate-400 mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  placeholder="e.g. Detect_Powershell_Encoded_Payload"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Purpose of detection rule..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">YARA Rule Syntax</label>
                <textarea
                  rows={6}
                  required
                  value={ruleContent}
                  onChange={(e) => setRuleContent(e.target.value)}
                  placeholder="rule RuleName { strings: $a = 'test' condition: $a }"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-slate-200 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 bg-sky-600 text-white rounded-lg font-medium"
                >
                  {saving ? 'Creating Rule...' : 'Save Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
