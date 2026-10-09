import React, { useEffect, useState } from 'react';
import { emailsAPI, reportsAPI } from '../services/api';
import { EmailSampleSummary } from '../types';
import { FileText, Download, ShieldCheck } from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const [emails, setEmails] = useState<EmailSampleSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    emailsAPI.list().then((data) => {
      setEmails(data);
      setLoading(false);
    });
  }, []);

  const handleDownloadPDF = async (emailId: string) => {
    try {
      const res = await reportsAPI.createReport(emailId, 'PDF');
      if (res.pdf_url) {
        window.open(res.pdf_url, '_blank');
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleDownloadJSON = async (emailId: string) => {
    try {
      const res = await reportsAPI.createReport(emailId, 'JSON');
      const jsonStr = JSON.stringify(res, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${emailId}.json`;
      a.click();
    } catch (e) {
      console.error(e);
    }
  };

  const handleDownloadSTIX = async (emailId: string) => {
    try {
      const res = await reportsAPI.getStix(emailId);
      const jsonStr = JSON.stringify(res, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `stix_bundle_${emailId}.json`;
      a.click();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-soc-border pb-4">
        <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
          <FileText className="w-5 h-5 text-sky-400" />
          FORENSIC INVESTIGATION REPORT GENERATION
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-0.5">Export Evidence-Backed JSON, PDF & STIX 2.1 SOC Investigation Reports</p>
      </div>

      <div className="bg-soc-card border border-soc-border rounded-xl p-5">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">Loading email repository...</div>
        ) : !emails.length ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
            No email samples available for report generation.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-soc-border uppercase text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Subject / Artifact</th>
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">Risk Category</th>
                  <th className="py-2.5 px-3 text-right">Generate Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {emails.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-3 font-semibold text-slate-100 max-w-sm truncate">{e.subject || e.original_filename}</td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate">{e.sender || '—'}</td>
                    <td className="py-3 px-3">{e.risk_category} ({e.risk_score})</td>
                    <td className="py-3 px-3 text-right space-x-2">
                      <button
                        onClick={() => handleDownloadPDF(e.id)}
                        className="px-2.5 py-1 bg-sky-600/20 hover:bg-sky-600/40 text-sky-300 border border-sky-500/30 rounded text-[11px] font-medium"
                      >
                        PDF Report
                      </button>
                      <button
                        onClick={() => handleDownloadJSON(e.id)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[11px]"
                      >
                        JSON Data
                      </button>
                      <button
                        onClick={() => handleDownloadSTIX(e.id)}
                        className="px-2.5 py-1 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-400 border border-emerald-800/50 rounded text-[11px] font-medium"
                      >
                        STIX 2.1
                      </button>
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
