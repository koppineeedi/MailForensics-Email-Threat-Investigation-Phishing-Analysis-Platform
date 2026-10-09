import React, { useEffect, useState } from 'react';
import { emailsAPI } from '../services/api';
import { EmailSampleSummary, EmailComparisonResult } from '../types';
import { GitCompare, ArrowRight, ShieldAlert } from 'lucide-react';

export const EmailComparePage: React.FC = () => {
  const [samples, setSamples] = useState<EmailSampleSummary[]>([]);
  const [emailA, setEmailA] = useState('');
  const [emailB, setEmailB] = useState('');
  const [result, setResult] = useState<EmailComparisonResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    emailsAPI.list().then((data) => {
      setSamples(data);
      if (data.length >= 2) {
        setEmailA(data[0].id);
        setEmailB(data[1].id);
      }
    });
  }, []);

  const handleCompare = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailA || !emailB || emailA === emailB) return;
    setLoading(true);
    try {
      const res = await emailsAPI.compare(emailA, emailB);
      setResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-soc-border pb-4">
        <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
          <GitCompare className="w-5 h-5 text-sky-400" />
          SIDE-BY-SIDE EMAIL ARTIFACT COMPARISON
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-0.5">Compare Indicators, Headers, Infrastructure, and Hashes Between Two Email Samples</p>
      </div>

      {/* Comparison Selector Form */}
      <form onSubmit={handleCompare} className="bg-soc-card border border-soc-border rounded-xl p-5 grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
        <div>
          <label className="block text-xs font-mono text-slate-400 mb-1">Select Email Sample A</label>
          <select
            value={emailA}
            onChange={(e) => setEmailA(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="">Select Sample A...</option>
            {samples.map((s) => (
              <option key={s.id} value={s.id}>{s.subject || s.original_filename} ({s.id.substring(0, 8)})</option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-mono text-slate-400 mb-1">Select Email Sample B</label>
          <select
            value={emailB}
            onChange={(e) => setEmailB(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="">Select Sample B...</option>
            {samples.map((s) => (
              <option key={s.id} value={s.id}>{s.subject || s.original_filename} ({s.id.substring(0, 8)})</option>
            ))}
          </select>
        </div>

        <button
          type="submit"
          disabled={loading || !emailA || !emailB}
          className="w-full bg-sky-600 hover:bg-sky-500 text-white font-medium py-2 rounded-lg text-xs font-mono transition-colors flex items-center justify-center gap-2"
        >
          {loading ? 'Comparing Artifacts...' : 'Compare Artifacts'}
        </button>
      </form>

      {/* Comparison Results Display */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-3 gap-6 font-mono text-xs">
            {/* COMMON */}
            <div className="bg-soc-card border border-emerald-900/60 rounded-xl p-4 space-y-3">
              <h3 className="font-bold text-emerald-400 border-b border-emerald-900/50 pb-2">COMMON SHARED INDICATORS</h3>
              <div className="space-y-2 text-slate-300">
                <div><b>Senders:</b> {result.sender_comparison.common.join(', ') || 'None'}</div>
                <div><b>Domains:</b> {result.domain_comparison.common.join(', ') || 'None'}</div>
                <div><b>URLs:</b> {result.url_comparison.common.join(', ') || 'None'}</div>
                <div><b>Attachment Hashes:</b> {result.attachment_comparison.common.join(', ') || 'None'}</div>
                <div><b>Findings:</b> {result.finding_comparison.common.join(', ') || 'None'}</div>
              </div>
            </div>

            {/* ONLY EMAIL A */}
            <div className="bg-soc-card border border-soc-border rounded-xl p-4 space-y-3">
              <h3 className="font-bold text-sky-400 border-b border-soc-border pb-2">UNIQUE TO SAMPLE A</h3>
              <div className="space-y-2 text-slate-300">
                <div><b>Senders:</b> {result.sender_comparison.only_a.join(', ') || 'None'}</div>
                <div><b>Domains:</b> {result.domain_comparison.only_a.join(', ') || 'None'}</div>
                <div><b>URLs:</b> {result.url_comparison.only_a.join(', ') || 'None'}</div>
                <div><b>Attachment Hashes:</b> {result.attachment_comparison.only_a.join(', ') || 'None'}</div>
                <div><b>Findings:</b> {result.finding_comparison.only_a.join(', ') || 'None'}</div>
              </div>
            </div>

            {/* ONLY EMAIL B */}
            <div className="bg-soc-card border border-soc-border rounded-xl p-4 space-y-3">
              <h3 className="font-bold text-purple-400 border-b border-soc-border pb-2">UNIQUE TO SAMPLE B</h3>
              <div className="space-y-2 text-slate-300">
                <div><b>Senders:</b> {result.sender_comparison.only_b.join(', ') || 'None'}</div>
                <div><b>Domains:</b> {result.domain_comparison.only_b.join(', ') || 'None'}</div>
                <div><b>URLs:</b> {result.url_comparison.only_b.join(', ') || 'None'}</div>
                <div><b>Attachment Hashes:</b> {result.attachment_comparison.only_b.join(', ') || 'None'}</div>
                <div><b>Findings:</b> {result.finding_comparison.only_b.join(', ') || 'None'}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
