import React, { useEffect, useState } from 'react';
import { auditAPI } from '../services/api';
import { AuditLog } from '../types';
import { ClipboardList, Shield } from 'lucide-react';

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    auditAPI.list().then((data) => {
      setLogs(data);
      setLoading(false);
    });
  }, []);

  return (
    <div className="space-y-6">
      <div className="border-b border-soc-border pb-4">
        <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
          <ClipboardList className="w-5 h-5 text-sky-400" />
          APPEND-ONLY SOC AUDIT LOG TRAIL
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-0.5">Immutable System Operations & Investigation Audit History (Secrets Auto-Redacted)</p>
      </div>

      <div className="bg-soc-card border border-soc-border rounded-xl p-5">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">Querying audit logs from database...</div>
        ) : !logs.length ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
            No audit log records found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-soc-border uppercase text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">User</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Resource</th>
                  <th className="py-2.5 px-3">Outcome</th>
                  <th className="py-2.5 px-3">Metadata</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">{new Date(log.timestamp).toUTCString()}</td>
                    <td className="py-3 px-3 font-semibold text-slate-200">{log.user_email || 'SYSTEM'}</td>
                    <td className="py-3 px-3 text-sky-400 font-bold">{log.action}</td>
                    <td className="py-3 px-3 text-slate-300">{log.resource}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${
                        log.outcome === 'SUCCESS' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-rose-950 text-rose-400 border-rose-800'
                      }`}>
                        {log.outcome}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate text-[10px]">
                      {log.metadata_json ? JSON.stringify(log.metadata_json) : '—'}
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
