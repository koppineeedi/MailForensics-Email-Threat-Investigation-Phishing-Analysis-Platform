import React, { useEffect, useState } from 'react';
import { emailsAPI } from '../services/api';
import { EmailSampleSummary } from '../types';
import { RiskBadge } from '../components/common/RiskBadge';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { Upload, Mail, Search, RefreshCw, Trash2, Shield, Plus, FileText } from 'lucide-react';
import { Link as RouterLink } from 'react-router-dom';

export const EmailListPage: React.FC = () => {
  const [emails, setEmails] = useState<EmailSampleSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [dataSourceFilter, setDataSourceFilter] = useState('ALL');

  // Upload modal state
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadMode, setUploadMode] = useState<'FILE' | 'RAW'>('FILE');
  const [file, setFile] = useState<File | null>(null);
  const [rawContent, setRawContent] = useState('');
  const [uploading, setUploading] = useState(false);

  const fetchEmails = async (sourceFilter = dataSourceFilter) => {
    setLoading(true);
    try {
      const data = await emailsAPI.list(sourceFilter);
      setEmails(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmails();
  }, []);

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setUploading(true);
    try {
      if (uploadMode === 'FILE' && file) {
        await emailsAPI.upload(file);
      } else if (uploadMode === 'RAW' && rawContent) {
        await emailsAPI.upload(undefined, rawContent);
      }
      setShowUploadModal(false);
      setFile(null);
      setRawContent('');
      await fetchEmails();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to upload email sample.');
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this email sample?')) {
      try {
        await emailsAPI.delete(id);
        await fetchEmails();
      } catch (e) {
        console.error(e);
      }
    }
  };

  const filteredEmails = emails.filter((e) => {
    const matchesSearch =
      !search ||
      (e.subject && e.subject.toLowerCase().includes(search.toLowerCase())) ||
      (e.sender && e.sender.toLowerCase().includes(search.toLowerCase())) ||
      e.sha256.toLowerCase().includes(search.toLowerCase()) ||
      e.original_filename.toLowerCase().includes(search.toLowerCase());

    const matchesRisk = riskFilter === 'ALL' || e.risk_category === riskFilter;

    return matchesSearch && matchesRisk;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-wide">EMAIL THREAT INGESTION & TRIAGE</h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">Safely Ingest, Parse, and Analyze Suspicious RFC Artifacts</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowUploadModal(true)}
            className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium rounded-lg transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            <span>Submit Email Artifact</span>
          </button>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-soc-card border border-soc-border p-4 rounded-xl">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search Subject, Sender, SHA256..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto font-mono text-xs">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Source:</span>
            <select
              value={dataSourceFilter}
              onChange={(e) => {
                setDataSourceFilter(e.target.value);
                fetchEmails(e.target.value);
              }}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">ALL SOURCES</option>
              <option value="REAL">REAL (REAL_EMAIL_ARTIFACT)</option>
              <option value="DEMO">DEMO / CONTROLLED (CONTROLLED_TEST)</option>
              <option value="LIVE_TI">LIVE TI ARTIFACTS</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">ALL RISK LEVELS</option>
              <option value="LOW">LOW</option>
              <option value="GUARDED">GUARDED</option>
              <option value="SUSPICIOUS">SUSPICIOUS</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>
        </div>
      </div>

      {/* Email List Table */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-5">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">Loading email repository...</div>
        ) : !filteredEmails.length ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
            No email samples match your search criteria. Click "Submit Email Artifact" to upload an .eml sample.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-soc-border uppercase text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Subject / Filename</th>
                  <th className="py-2.5 px-3">Source</th>
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">SHA-256</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {filteredEmails.map((sample) => (
                  <tr key={sample.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-100 max-w-sm truncate">{sample.subject || sample.original_filename}</div>
                      <div className="text-[10px] text-slate-500">{sample.original_filename} ({Math.round(sample.size_bytes / 1024)} KB)</div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        sample.data_source === 'REAL_EMAIL_ARTIFACT'
                          ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800'
                          : sample.data_source === 'CONTROLLED_TEST'
                          ? 'bg-amber-950/80 text-amber-400 border-amber-800'
                          : sample.data_source === 'LIVE_EXTERNAL_PROVIDER'
                          ? 'bg-sky-950/80 text-sky-400 border-sky-800'
                          : 'bg-purple-950/80 text-purple-400 border-purple-800'
                      }`}>
                        {sample.data_source === 'CONTROLLED_TEST' ? 'DEMO / CONTROLLED' : (sample.data_source || 'REAL')}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate">{sample.sender || '—'}</td>
                    <td className="py-3 px-3 text-slate-500 text-[10px]">{sample.sha256.substring(0, 16)}...</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] border border-slate-700 bg-slate-800/80 text-slate-300">
                        {sample.status}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <RiskBadge category={sample.risk_category} score={sample.risk_score} />
                    </td>
                    <td className="py-3 px-3">
                      <VerdictBadge verdict={sample.verdict?.verdict} />
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <RouterLink
                          to={`/emails/${sample.id}`}
                          className="px-2.5 py-1 bg-sky-600/20 hover:bg-sky-600/40 text-sky-300 border border-sky-500/30 rounded text-[11px] transition-colors"
                        >
                          Investigate
                        </RouterLink>
                        <button
                          onClick={() => handleDelete(sample.id)}
                          className="p-1 text-slate-500 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                          title="Delete Sample"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <h2 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
                <Upload className="w-4 h-4 text-sky-400" />
                SUBMIT SUSPICIOUS EMAIL ARTIFACT
              </h2>
              <button onClick={() => setShowUploadModal(false)} className="text-slate-400 hover:text-slate-200 text-xs">✕</button>
            </div>

            <div className="flex border-b border-slate-800 text-xs font-mono">
              <button
                onClick={() => setUploadMode('FILE')}
                className={`py-2 px-4 border-b-2 font-medium transition-colors ${
                  uploadMode === 'FILE' ? 'border-sky-400 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Upload .eml File
              </button>
              <button
                onClick={() => setUploadMode('RAW')}
                className={`py-2 px-4 border-b-2 font-medium transition-colors ${
                  uploadMode === 'RAW' ? 'border-sky-400 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Paste Raw RFC Headers/Body
              </button>
            </div>

            <form onSubmit={handleUploadSubmit} className="space-y-4">
              {uploadMode === 'FILE' ? (
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-2">Select .eml / RFC message file</label>
                  <input
                    type="file"
                    accept=".eml,.msg,.txt"
                    required
                    onChange={(e) => setFile(e.target.files?.[0] || null)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-sky-600 file:text-white hover:file:bg-sky-500"
                  />
                </div>
              ) : (
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-2">Raw RFC 822/5322 Content</label>
                  <textarea
                    rows={8}
                    required
                    value={rawContent}
                    onChange={(e) => setRawContent(e.target.value)}
                    placeholder="From: sender@domain.com&#10;To: victim@corp.com&#10;Subject: Urgent...&#10;&#10;Raw email body..."
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                  />
                </div>
              )}

              <div className="bg-slate-900/60 border border-slate-800 p-3 rounded-lg text-[11px] text-slate-400 space-y-1">
                <div className="font-semibold text-slate-300">DEFENSIVE SAFETY GUARANTEES:</div>
                <div>• Attachments will be parsed statically & isolated without execution.</div>
                <div>• Extracted URLs will NOT be automatically opened or visited.</div>
                <div>• Archive bomb protection limits are strictly enforced.</div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 text-xs rounded-lg hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading}
                  className="px-4 py-2 bg-sky-600 text-white text-xs rounded-lg hover:bg-sky-500 font-medium"
                >
                  {uploading ? 'Ingesting & Analyzing...' : 'Submit & Analyze'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
