import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import { emailsAPI, reportsAPI, casesAPI } from '../services/api';
import { EmailSampleDetail } from '../types';
import { RiskBadge } from '../components/common/RiskBadge';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { useWebSocket } from '../context/WebSocketContext';
import {
  ShieldAlert, Mail, ShieldCheck, Link, Paperclip, AlertTriangle,
  FileText, Clock, Network, Briefcase, RefreshCw, Download, CheckCircle, XCircle
} from 'lucide-react';

export const EmailDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [email, setEmail] = useState<EmailSampleDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  // Verdict Modal / Form
  const [verdictInput, setVerdictInput] = useState('UNRESOLVED');
  const [verdictNotes, setVerdictNotes] = useState('');
  const [savingVerdict, setSavingVerdict] = useState(false);

  // Case Linking
  const [creatingCase, setCreatingCase] = useState(false);

  const { subscribeEmail, unsubscribeEmail, lastEvent } = useWebSocket();

  const fetchDetail = async () => {
    if (!id) return;
    try {
      const data = await emailsAPI.getDetail(id);
      setEmail(data);
      if (data.verdict) {
        setVerdictInput(data.verdict.verdict);
        setVerdictNotes(data.verdict.notes || '');
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchDetail();
      subscribeEmail(id);
    }
    return () => {
      if (id) unsubscribeEmail(id);
    };
  }, [id]);

  useEffect(() => {
    if (lastEvent && lastEvent.email_id === id) {
      fetchDetail();
    }
  }, [lastEvent]);

  const handleSaveVerdict = async () => {
    if (!id) return;
    setSavingVerdict(true);
    try {
      await emailsAPI.setVerdict(id, verdictInput, verdictNotes);
      await fetchDetail();
    } catch (e) {
      console.error(e);
    } finally {
      setSavingVerdict(false);
    }
  };

  const handleGenerateReport = async (type: 'PDF' | 'JSON') => {
    if (!id) return;
    try {
      const res = await reportsAPI.createReport(id, type);
      if (type === 'PDF' && res.pdf_url) {
        window.open(res.pdf_url, '_blank');
      } else {
        const jsonStr = JSON.stringify(res, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report_${id}.json`;
        a.click();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleDownloadSTIX = async () => {
    if (!id) return;
    try {
      const res = await reportsAPI.getStix(id);
      const jsonStr = JSON.stringify(res, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `stix_bundle_${id}.json`;
      a.click();
    } catch (e) {
      console.error(e);
    }
  };

  const handleCreateCaseForEmail = async () => {
    if (!email) return;
    setCreatingCase(true);
    try {
      const c = await casesAPI.create({
        title: `Investigation: ${email.subject || email.original_filename}`,
        description: `Case automatically created for email sample ${email.id}`,
        severity: email.risk_category,
        email_ids: [email.id]
      });
      navigate(`/cases/${c.id}`);
    } catch (e) {
      console.error(e);
    } finally {
      setCreatingCase(false);
    }
  };

  if (loading || !email) {
    return <div className="p-12 text-center text-slate-400 font-mono text-xs">Loading email forensic sample #{id}...</div>;
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Mail },
    { id: 'headers', label: 'Headers', icon: FileText },
    { id: 'auth', label: 'Authentication', icon: ShieldCheck },
    { id: 'received', label: 'Received Chain', icon: Clock },
    { id: 'body', label: 'Body Content', icon: FileText },
    { id: 'urls', label: `URLs (${email.urls.length})`, icon: Link },
    { id: 'attachments', label: `Attachments (${email.attachments.length})`, icon: Paperclip },
    { id: 'findings', label: `Findings (${email.phishing_findings.length})`, icon: AlertTriangle },
    { id: 'threat_intel', label: 'Threat Intel', icon: ShieldAlert },
    { id: 'risk', label: 'Risk Model', icon: ShieldAlert },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'relationships', label: 'Graph', icon: Network },
    { id: 'case', label: 'Case Management', icon: Briefcase },
    { id: 'report', label: 'Export Report', icon: Download },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-soc-border pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-bold text-slate-100">{email.subject || '(No Subject)'}</h1>
              <RiskBadge category={email.risk_category} score={email.risk_score} />
              <VerdictBadge verdict={email.verdict?.verdict} />
            </div>
            <div className="text-xs text-slate-400 font-mono flex flex-wrap gap-4 pt-1">
              <span><b>SHA-256:</b> {email.sha256}</span>
              <span><b>Filename:</b> {email.original_filename}</span>
              <span><b>Uploaded:</b> {new Date(email.upload_timestamp).toLocaleString()}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => handleGenerateReport('PDF')}
              className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono rounded-lg transition-colors flex items-center gap-2"
            >
              <Download className="w-3.5 h-3.5" />
              <span>PDF Report</span>
            </button>
            <button
              onClick={handleDownloadSTIX}
              className="px-3 py-1.5 bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-800 text-emerald-400 text-xs font-mono rounded-lg transition-colors flex items-center gap-2"
            >
              <Download className="w-3.5 h-3.5" />
              <span>STIX 2.1</span>
            </button>
            <button
              onClick={handleCreateCaseForEmail}
              disabled={creatingCase}
              className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 text-xs font-mono rounded-lg transition-colors flex items-center gap-2"
            >
              <Briefcase className="w-3.5 h-3.5" />
              <span>Create Case</span>
            </button>
          </div>
        </div>

        {/* Key Attributes Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <div className="text-[10px] text-slate-500">DISPLAY SENDER</div>
            <div className="text-slate-200 truncate mt-0.5">{email.sender || '—'}</div>
          </div>
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <div className="text-[10px] text-slate-500">REPLY-TO ADDRESS</div>
            <div className="text-slate-200 truncate mt-0.5">{email.reply_to || '—'}</div>
          </div>
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <div className="text-[10px] text-slate-500">ENVELOPE RETURN-PATH</div>
            <div className="text-slate-200 truncate mt-0.5">{email.return_path || '—'}</div>
          </div>
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <div className="text-[10px] text-slate-500">MESSAGE-ID</div>
            <div className="text-slate-200 truncate mt-0.5">{email.message_id || '—'}</div>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-soc-border overflow-x-auto text-xs font-mono scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 py-2.5 px-4 border-b-2 font-medium whitespace-nowrap transition-colors ${
                isActive
                  ? 'border-sky-400 text-sky-400 bg-sky-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Content Panels */}
      <div className="space-y-6">
        {/* TAB 1: OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              {/* Authentication Summary Card */}
              <div className="bg-soc-card border border-soc-border rounded-xl p-5">
                <h3 className="text-xs font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  AUTHENTICATION PROTOCOL SUMMARY
                </h3>
                <div className="grid grid-cols-3 gap-4 font-mono text-xs">
                  <div className="p-3 rounded-lg border bg-slate-900/80 border-slate-800">
                    <div className="text-[10px] text-slate-400 mb-1">SPF STATUS</div>
                    <div className={`text-base font-bold ${email.auth_results?.spf_result === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {email.auth_results?.spf_result || 'NONE'}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1 truncate">{email.auth_results?.spf_domain || '—'}</div>
                  </div>

                  <div className="p-3 rounded-lg border bg-slate-900/80 border-slate-800">
                    <div className="text-[10px] text-slate-400 mb-1">DKIM STATUS</div>
                    <div className={`text-base font-bold ${email.auth_results?.dkim_result === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {email.auth_results?.dkim_result || 'NOT CHECKED'}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1 truncate">{email.auth_results?.dkim_domain || '—'}</div>
                  </div>

                  <div className="p-3 rounded-lg border bg-slate-900/80 border-slate-800">
                    <div className="text-[10px] text-slate-400 mb-1">DMARC STATUS</div>
                    <div className={`text-base font-bold ${email.auth_results?.dmarc_result === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {email.auth_results?.dmarc_result || 'NOT CHECKED'}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1 truncate">{email.auth_results?.dmarc_domain || '—'}</div>
                  </div>
                </div>
              </div>

              {/* Phishing Findings Summary */}
              <div className="bg-soc-card border border-soc-border rounded-xl p-5">
                <h3 className="text-xs font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  EVIDENCE-BASED PHISHING INDICATORS ({email.phishing_findings.length})
                </h3>
                {!email.phishing_findings.length ? (
                  <div className="text-xs font-mono text-slate-500 p-4 border border-dashed border-slate-800 rounded">
                    No automated phishing findings generated.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {email.phishing_findings.map((f) => (
                      <div key={f.id} className="p-3 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-sky-400">{f.finding_code}</span>
                          <span className="text-[10px] font-mono text-slate-400">{f.severity} (Confidence: {f.confidence * 100}%)</span>
                        </div>
                        <div className="text-xs text-slate-300 font-sans">{f.explanation}</div>
                        <div className="text-[11px] font-mono text-slate-400 bg-slate-950 p-2 rounded border border-slate-800/80 mt-1">
                          <b>Evidence:</b> {f.evidence}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Sidebar: Analyst Verdict Form */}
            <div className="space-y-6">
              <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
                <h3 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
                  <FileText className="w-4 h-4 text-sky-400" />
                  ANALYST VERDICT CONTROL
                </h3>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Select Final Verdict</label>
                  <select
                    value={verdictInput}
                    onChange={(e) => setVerdictInput(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                  >
                    <option value="UNRESOLVED">UNRESOLVED</option>
                    <option value="BENIGN">BENIGN (Legitimate)</option>
                    <option value="SUSPICIOUS">SUSPICIOUS (Guarded)</option>
                    <option value="PHISHING">PHISHING (Social Engineering)</option>
                    <option value="MALICIOUS_ATTACHMENT">MALICIOUS ATTACHMENT</option>
                    <option value="SPAM">SPAM (Unsolicited)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Analyst Investigation Notes</label>
                  <textarea
                    rows={4}
                    value={verdictNotes}
                    onChange={(e) => setVerdictNotes(e.target.value)}
                    placeholder="Document forensic findings, SPF/DKIM verification details, or campaign indicators..."
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                  />
                </div>

                <button
                  onClick={handleSaveVerdict}
                  disabled={savingVerdict}
                  className="w-full bg-sky-600 hover:bg-sky-500 text-white font-medium py-2 rounded-lg text-xs transition-colors"
                >
                  {savingVerdict ? 'Saving Verdict...' : 'Save Analyst Verdict'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: HEADERS */}
        {activeTab === 'headers' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">PRESERVED RAW RFC HEADERS</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-900/80 text-slate-400 border-b border-soc-border uppercase text-[11px]">
                  <tr>
                    <th className="py-2 px-3">Header Name</th>
                    <th className="py-2 px-3">Raw Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {email.headers.map((h) => (
                    <tr key={h.id} className={h.is_auth_header ? 'bg-sky-950/20' : ''}>
                      <td className="py-2 px-3 font-semibold text-slate-300 whitespace-nowrap">{h.header_name}</td>
                      <td className="py-2 px-3 text-slate-400 break-all">{h.header_value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 3: AUTHENTICATION */}
        {activeTab === 'auth' && (
          <div className="space-y-6">
            <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
              <h3 className="text-xs font-bold text-slate-200 font-mono">SPF (Sender Policy Framework) EVALUATION</h3>
              <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-2 font-mono text-xs">
                <div><b>SPF Result:</b> <span className="text-emerald-400 font-bold">{email.auth_results?.spf_result}</span></div>
                <div><b>Evaluated Domain:</b> {email.auth_results?.spf_domain || '—'}</div>
                <div><b>Explanation:</b> {email.auth_results?.spf_explanation}</div>
              </div>
            </div>

            <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
              <h3 className="text-xs font-bold text-slate-200 font-mono">DKIM (DomainKeys Identified Mail) EVALUATION</h3>
              <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-2 font-mono text-xs">
                <div><b>DKIM Result:</b> <span className="text-emerald-400 font-bold">{email.auth_results?.dkim_result}</span></div>
                <div><b>Signing Domain:</b> {email.auth_results?.dkim_domain || '—'}</div>
                <div><b>Selector:</b> {email.auth_results?.dkim_selector || '—'}</div>
                <div><b>Alignment:</b> {email.auth_results?.dkim_alignment ? 'ALIGNED' : 'NOT ALIGNED'}</div>
                <div><b>Explanation:</b> {email.auth_results?.dkim_explanation}</div>
              </div>
            </div>

            <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
              <h3 className="text-xs font-bold text-slate-200 font-mono">DMARC EVALUATION & ALIGNMENT</h3>
              <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-2 font-mono text-xs">
                <div><b>DMARC Result:</b> <span className="text-emerald-400 font-bold">{email.auth_results?.dmarc_result}</span></div>
                <div><b>From Domain:</b> {email.auth_results?.dmarc_domain || '—'}</div>
                <div><b>SPF Alignment:</b> {email.auth_results?.dmarc_spf_align ? 'PASS' : 'FAIL'}</div>
                <div><b>DKIM Alignment:</b> {email.auth_results?.dmarc_dkim_align ? 'PASS' : 'FAIL'}</div>
                <div><b>Explanation:</b> {email.auth_results?.dmarc_explanation}</div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: RECEIVED CHAIN */}
        {activeTab === 'received' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">ORDERED TRANSIT HOPS TIMELINE</h3>
            <div className="space-y-4 font-mono text-xs">
              {email.received_hops.map((hop) => (
                <div key={hop.id} className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sky-400">Hop #{hop.hop_order}</span>
                    <span className="text-[10px] text-slate-400">{hop.timestamp ? new Date(hop.timestamp).toUTCString() : 'No timestamp'}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-slate-300">
                    <div><b>From Host:</b> {hop.from_host || '—'}</div>
                    <div><b>From IP:</b> {hop.from_ip || '—'}</div>
                    <div><b>By Host:</b> {hop.by_host || '—'}</div>
                    <div><b>Protocol / TLS:</b> {hop.protocol || 'ESMTP'} ({hop.tls_version || 'No TLS'})</div>
                  </div>
                  {hop.anomaly_detected && (
                    <div className="p-2 bg-amber-950/60 border border-amber-800 text-amber-300 text-[11px] rounded">
                      <b>Hop Anomaly:</b> {hop.anomaly_details}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 5: BODY */}
        {activeTab === 'body' && (
          <div className="space-y-6">
            <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-2">
              <h3 className="text-xs font-bold text-slate-200 font-mono">PLAIN TEXT BODY CONTENT</h3>
              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-96 overflow-y-auto">
                {email.body_plain || '(No plain text body content)'}
              </pre>
            </div>

            <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-2">
              <h3 className="text-xs font-bold text-slate-200 font-mono">HTML BODY SOURCE (DEFENSIVE TEXT ONLY — NO ACTIVE JS RENDER)</h3>
              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-400 whitespace-pre-wrap max-h-96 overflow-y-auto">
                {email.body_html || '(No HTML body content)'}
              </pre>
            </div>
          </div>
        )}

        {/* TAB 6: URLS */}
        {activeTab === 'urls' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">EXTRACTED & NORMALIZED URLS ({email.urls.length})</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-900/80 text-slate-400 border-b border-soc-border uppercase text-[11px]">
                  <tr>
                    <th className="py-2 px-3">Normalized URL</th>
                    <th className="py-2 px-3">Host / Domain</th>
                    <th className="py-2 px-3">Location</th>
                    <th className="py-2 px-3">Indicators</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {email.urls.map((u) => (
                    <tr key={u.id}>
                      <td className="py-2 px-3 font-mono text-sky-400 break-all max-w-md">{u.normalized_url}</td>
                      <td className="py-2 px-3 text-slate-300">{u.hostname}</td>
                      <td className="py-2 px-3 text-slate-400">{u.source_location}</td>
                      <td className="py-2 px-3 space-x-1">
                        {u.is_ip_based && <span className="px-1.5 py-0.5 bg-rose-950 text-rose-400 border border-rose-800 text-[10px] rounded">IP-HOST</span>}
                        {u.is_http && <span className="px-1.5 py-0.5 bg-amber-950 text-amber-400 border border-amber-800 text-[10px] rounded">HTTP</span>}
                        {u.is_suspicious_tld && <span className="px-1.5 py-0.5 bg-purple-950 text-purple-400 border border-purple-800 text-[10px] rounded">SUSPICIOUS-TLD</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 7: ATTACHMENTS */}
        {activeTab === 'attachments' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">ATTACHMENT METADATA & HASHES</h3>
            <div className="space-y-4 font-mono text-xs">
              {email.attachments.map((att) => (
                <div key={att.id} className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-100">{att.filename}</span>
                    <span className="text-[10px] text-slate-400">{Math.round(att.size_bytes / 1024)} KB</span>
                  </div>
                  <div className="text-slate-400 text-[11px] space-y-1">
                    <div><b>MIME Type:</b> {att.mime_type}</div>
                    <div><b>SHA-256:</b> {att.sha256}</div>
                    <div><b>SHA-1:</b> {att.sha1 || '—'}</div>
                    <div><b>MD5:</b> {att.md5 || '—'}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 8: FINDINGS */}
        {activeTab === 'findings' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">ALL PHISHING FINDINGS</h3>
            <div className="space-y-3 font-mono text-xs">
              {email.phishing_findings.map((f) => (
                <div key={f.id} className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sky-400">{f.finding_code}</span>
                    <span className="text-[10px] text-slate-400">{f.severity}</span>
                  </div>
                  <div className="text-slate-300">{f.explanation}</div>
                  <div className="text-[10px] text-slate-500">Evidence: {f.evidence}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 9: THREAT INTEL */}
        {activeTab === 'threat_intel' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">EXTERNAL THREAT INTELLIGENCE RESULTS</h3>
            <div className="space-y-3 font-mono text-xs">
              {email.threat_intel_results.map((ti) => (
                <div key={ti.id} className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{ti.provider_name} ({ti.ioc_type}: {ti.ioc_value.substring(0, 16)}...)</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded border ${
                      ti.status === 'AVAILABLE' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}>{ti.status}</span>
                  </div>
                  <pre className="text-[10px] text-slate-400 bg-slate-950 p-2 rounded mt-1 overflow-x-auto">
                    {JSON.stringify(ti.details_json, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 10: TIMELINE */}
        {activeTab === 'timeline' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">REAL BACKEND EVENT TIMELINE</h3>
            <div className="space-y-3 font-mono text-xs">
              {email.events.map((ev) => (
                <div key={ev.id} className="flex gap-4 p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <div className="text-[10px] text-slate-500 whitespace-nowrap">{new Date(ev.created_at).toLocaleTimeString()}</div>
                  <div className="space-y-1">
                    <div className="font-bold text-sky-400">{ev.title}</div>
                    <div className="text-slate-300">{ev.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 11: EXPORT REPORT */}
        {activeTab === 'report' && (
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono">EXPORT INVESTIGATION EVIDENCE</h3>
            <p className="text-xs text-slate-400 font-mono">Export this incident investigation in standardized defensive cybersecurity formats.</p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3 font-mono">
                <div className="text-sky-400 font-bold text-sm">PDF Investigation Report</div>
                <p className="text-xs text-slate-400">Formal SOC forensic dossier formatted for stakeholders and incident response teams.</p>
                <button
                  onClick={() => handleGenerateReport('PDF')}
                  className="w-full py-2 bg-sky-600 hover:bg-sky-500 text-white text-xs rounded transition-colors"
                >
                  Generate & Download PDF
                </button>
              </div>

              <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3 font-mono">
                <div className="text-indigo-400 font-bold text-sm">JSON Technical Report</div>
                <p className="text-xs text-slate-400">Complete raw forensic analysis tree with headers, findings, and risk breakdowns.</p>
                <button
                  onClick={() => handleGenerateReport('JSON')}
                  className="w-full py-2 bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/50 text-indigo-300 text-xs rounded transition-colors"
                >
                  Export Raw JSON
                </button>
              </div>

              <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3 font-mono">
                <div className="text-emerald-400 font-bold text-sm">STIX 2.1 Threat Bundle</div>
                <p className="text-xs text-slate-400">OASIS standard JSON bundle of indicators, observables, file hashes, and identities.</p>
                <button
                  onClick={handleDownloadSTIX}
                  className="w-full py-2 bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700 text-emerald-400 text-xs rounded transition-colors"
                >
                  Export STIX 2.1 Bundle
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
