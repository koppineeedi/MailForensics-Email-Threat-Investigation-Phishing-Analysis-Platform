import React, { useEffect, useState } from 'react';
import { threatIntelAPI } from '../services/api';
import { ShieldAlert, CheckCircle, XCircle, Info } from 'lucide-react';

export const ThreatIntelPage: React.FC = () => {
  const [statusMap, setStatusMap] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    threatIntelAPI.getStatus().then((data) => {
      setStatusMap(data);
      setLoading(false);
    });
  }, []);

  return (
    <div className="space-y-6">
      <div className="border-b border-soc-border pb-4">
        <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
          THREAT INTELLIGENCE PROVIDER INTEGRATIONS
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-0.5">Controlled Provider Status (VirusTotal, AlienVault OTX, AbuseIPDB)</p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl text-xs font-mono text-slate-300 space-y-2">
        <div className="flex items-center gap-2 font-bold text-sky-400">
          <Info className="w-4 h-4" />
          DISTINCTION BETWEEN OBSERVED DATA AND EXTERNAL INTELLIGENCE:
        </div>
        <div>• <b>OBSERVED EMAIL DATA:</b> Facts extracted directly from the uploaded RFC email sample (Headers, IPs, URLs, Hashes).</div>
        <div>• <b>EXTERNAL THREAT INTELLIGENCE:</b> Third-party reputation scores fetched explicitly via provider APIs. If no API key is provided, status displays <b>NOT_CONFIGURED</b>.</div>
      </div>

      {loading ? (
        <div className="p-8 text-center text-slate-400 font-mono text-xs">Querying provider configuration statuses...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
          {Object.entries(statusMap).map(([provider, st]) => {
            const isConfigured = st === 'CONFIGURED';
            return (
              <div key={provider} className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-slate-100">{provider}</h3>
                  {isConfigured ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <XCircle className="w-4 h-4 text-slate-500" />
                  )}
                </div>
                <div className="text-[11px] text-slate-400">Status:</div>
                <div className={`px-2.5 py-1 rounded text-xs border font-bold ${
                  isConfigured ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-slate-900 text-slate-400 border-slate-800'
                }`}>
                  {st}
                </div>
                <div className="text-[10px] text-slate-500 pt-2 border-t border-slate-800">
                  {isConfigured
                    ? 'Active API key detected in environment settings.'
                    : 'API key not set. Local operation active without external API calls.'}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
