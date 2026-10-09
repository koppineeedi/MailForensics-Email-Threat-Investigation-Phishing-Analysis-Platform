import React, { useState } from 'react';
import { threatIntelAPI } from '../services/api';
import { Search, ShieldAlert, Database } from 'lucide-react';

export const IOCSearchPage: React.FC = () => {
  const [iocType, setIocType] = useState('HASH');
  const [iocValue, setIocValue] = useState('');
  const [result, setResult] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!iocValue.trim()) return;
    setLoading(true);
    try {
      const res = await threatIntelAPI.lookup(iocType, iocValue.trim());
      setResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-soc-border pb-4">
        <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
          <Search className="w-5 h-5 text-sky-400" />
          INDICATOR OF COMPROMISE (IOC) SEARCH
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-0.5">Search SHA-256 Hashes, IP Addresses, and Domains across Local Forensic DB & Threat Intel</p>
      </div>

      <form onSubmit={handleSearch} className="bg-soc-card border border-soc-border rounded-xl p-5 grid grid-cols-1 sm:grid-cols-4 gap-4 items-end">
        <div>
          <label className="block text-xs font-mono text-slate-400 mb-1">IOC Type</label>
          <select
            value={iocType}
            onChange={(e) => setIocType(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono"
          >
            <option value="HASH">SHA-256 Hash</option>
            <option value="IP">IP Address</option>
          </select>
        </div>

        <div className="sm:col-span-2">
          <label className="block text-xs font-mono text-slate-400 mb-1">IOC Value</label>
          <input
            type="text"
            required
            value={iocValue}
            onChange={(e) => setIocValue(e.target.value)}
            placeholder="Paste SHA256 hash or IP address..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="bg-sky-600 hover:bg-sky-500 text-white font-medium py-2 rounded-lg text-xs font-mono transition-colors"
        >
          {loading ? 'Searching...' : 'Search Threat Intel'}
        </button>
      </form>

      {result && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-5 font-mono text-xs space-y-4">
          <h3 className="font-bold text-slate-200 border-b border-soc-border pb-2">THREAT INTELLIGENCE SEARCH RESULTS</h3>
          <pre className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 overflow-x-auto">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
