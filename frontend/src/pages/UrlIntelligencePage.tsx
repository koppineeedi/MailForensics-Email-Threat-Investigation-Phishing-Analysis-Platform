import React, { useState, useRef } from 'react';
import {
  Shield, Search, AlertTriangle, CheckCircle2, AlertCircle,
  XCircle, Copy, ChevronDown, ChevronUp, Link2, Clock, BarChart3
} from 'lucide-react';
import { urlIntelligenceAPI } from '../services/api';

type RiskCat = 'LOW' | 'GUARDED' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
type SeverityLevel = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

interface Detection {
  code: string;
  weight: number;
  title: string;
  description: string;
  severity: SeverityLevel;
}

interface ParsedInfo {
  scheme: string;
  hostname: string;
  tld: string;
  subdomain_depth: number;
  url_length: number;
}

interface AnalysisResult {
  url: string;
  risk_score: number;
  risk_category: RiskCat;
  detections: Detection[];
  summary: string;
  is_safe_to_display: boolean;
  parsed?: ParsedInfo;
}

const RISK_CONFIG: Record<RiskCat, {
  color: string; bg: string; border: string;
  icon: React.FC<{ className?: string }>; label: string;
}> = {
  LOW:        { color: 'text-emerald-400', bg: 'bg-emerald-950/40',  border: 'border-emerald-700/50', icon: CheckCircle2,  label: 'LOW RISK'    },
  GUARDED:    { color: 'text-yellow-400',  bg: 'bg-yellow-950/40',   border: 'border-yellow-700/50',  icon: AlertCircle,   label: 'GUARDED'     },
  SUSPICIOUS: { color: 'text-amber-400',   bg: 'bg-amber-950/40',    border: 'border-amber-700/50',   icon: AlertCircle,   label: 'SUSPICIOUS'  },
  HIGH:       { color: 'text-orange-400',  bg: 'bg-orange-950/40',   border: 'border-orange-700/50',  icon: AlertTriangle, label: 'HIGH RISK'   },
  CRITICAL:   { color: 'text-rose-400',    bg: 'bg-rose-950/40',     border: 'border-rose-800/50',    icon: XCircle,       label: 'CRITICAL'    },
};

const SEVERITY_CONFIG: Record<SeverityLevel, { color: string; bg: string; border: string }> = {
  INFO:     { color: 'text-slate-400',  bg: 'bg-slate-800/60',   border: 'border-slate-700/40'  },
  LOW:      { color: 'text-sky-400',    bg: 'bg-sky-950/40',     border: 'border-sky-700/40'    },
  MEDIUM:   { color: 'text-yellow-400', bg: 'bg-yellow-950/40',  border: 'border-yellow-700/40' },
  HIGH:     { color: 'text-orange-400', bg: 'bg-orange-950/40',  border: 'border-orange-700/40' },
  CRITICAL: { color: 'text-rose-400',   bg: 'bg-rose-950/40',    border: 'border-rose-700/40'   },
};

/* ── Score Arc ── */
const ScoreArc: React.FC<{ score: number; category: RiskCat }> = ({ score, category }) => {
  const cfg = RISK_CONFIG[category];
  const radius = 54;
  const circumference = Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  return (
    <svg viewBox="0 0 128 80" className="w-40 h-24">
      <path d="M 12 70 A 54 54 0 0 1 116 70" fill="none" stroke="#1E293B" strokeWidth="10" strokeLinecap="round" />
      <path
        d="M 12 70 A 54 54 0 0 1 116 70"
        fill="none"
        stroke="currentColor"
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        className={cfg.color}
        style={{ transition: 'stroke-dashoffset 0.8s ease' }}
      />
      <text x="64" y="62" textAnchor="middle" fontFamily="monospace" fontWeight="bold"
        fontSize="22" className={cfg.color} fill="currentColor">{score}</text>
      <text x="64" y="76" textAnchor="middle" fill="#64748B" fontSize="8" fontFamily="monospace">/100</text>
    </svg>
  );
};

/* ── Detection Card ── */
const DetectionCard: React.FC<{ det: Detection }> = ({ det }) => {
  const [expanded, setExpanded] = useState(false);
  const sev = SEVERITY_CONFIG[det.severity] ?? SEVERITY_CONFIG.MEDIUM;
  return (
    <div className={`rounded-lg border ${sev.bg} ${sev.border} overflow-hidden transition-all`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 text-left hover:bg-white/5 transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${sev.color} border border-current/20 shrink-0`}>
            {det.severity}
          </span>
          <span className="text-sm font-medium text-slate-200 truncate">{det.title}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0 ml-2">
          <span className="text-xs font-mono text-slate-400">+{det.weight}pts</span>
          {expanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
        </div>
      </button>
      {expanded && (
        <div className="px-3 pb-3 border-t border-slate-700/30">
          <p className="text-xs text-slate-300 leading-relaxed mt-2">{det.description}</p>
          <span className="mt-2 inline-block text-[10px] font-mono text-slate-500">CODE: {det.code}</span>
        </div>
      )}
    </div>
  );
};

/* ── DETECTOR_LIST for empty state ── */
const DETECTOR_LIST = [
  '@ Symbol Tricks', 'IP-Based Hosts', 'Punycode Domains', 'Credential Keywords',
  'Brand Impersonation', 'URL Shorteners', 'Encoding Obfuscation', 'High Entropy',
  'Subdomain Depth', 'Suspicious TLDs', 'URL Length', 'HTTP (No TLS)',
];

/* ── Main Page ── */
export const UrlIntelligencePage: React.FC = () => {
  const [inputUrl, setInputUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleAnalyze = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!inputUrl.trim()) {
      setError('Please enter a URL to analyze.');
      return;
    }
    setError('');
    setLoading(true);
    setResult(null);
    try {
      const data = await urlIntelligenceAPI.analyze(inputUrl.trim());
      setResult(data as AnalysisResult);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis failed. Please try again.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!result) return;
    const lines = [
      'URL Intelligence Analysis Report',
      '================================',
      `URL: ${result.url}`,
      `Risk Score: ${result.risk_score}/100`,
      `Risk Category: ${result.risk_category}`,
      `Summary: ${result.summary}`,
      '',
      `Detections (${result.detections.length}):`,
      ...result.detections.map(d =>
        `  [${d.severity}] ${d.title} (+${d.weight}pts)\n    ${d.description}`
      ),
    ];
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const riskCfg = result ? RISK_CONFIG[result.risk_category] : null;
  const RiskIcon = riskCfg?.icon;

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* ── Header ── */}
      <div className="flex items-center gap-4 border-b border-soc-border pb-4">
        <div className="p-2.5 bg-purple-500/10 border border-purple-500/30 rounded-xl">
          <Shield className="w-6 h-6 text-purple-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-wide">URL INTELLIGENCE</h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Static Phishing URL Analysis — Zero Network Requests to Analyzed URLs
          </p>
        </div>
      </div>

      {/* ── Safety Banner ── */}
      <div className="flex items-start gap-3 p-3 bg-sky-950/30 border border-sky-800/40 rounded-xl text-xs text-sky-300">
        <Shield className="w-4 h-4 shrink-0 mt-0.5 text-sky-400" />
        <div>
          <span className="font-semibold">Safe Analysis Mode:</span> URLs are analyzed using{' '}
          <span className="font-semibold">12 static heuristic detectors</span>.
          No browser requests, DNS lookups, or HTTP connections are made to the submitted URL —
          SSRF prevention by design.
        </div>
      </div>

      {/* ── Input Form ── */}
      <form onSubmit={handleAnalyze} className="bg-soc-card border border-soc-border rounded-xl p-5">
        <label className="block text-xs font-mono text-slate-400 mb-2">
          <Link2 className="w-3.5 h-3.5 inline mr-1.5 text-sky-400" />
          ENTER URL FOR ANALYSIS
        </label>
        <div className="flex gap-3">
          <input
            ref={inputRef}
            type="text"
            value={inputUrl}
            onChange={e => setInputUrl(e.target.value)}
            placeholder="https://suspicious-link.example.com/verify?token=abc123"
            className="flex-1 bg-slate-900/80 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-100 font-mono placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-900/50 disabled:text-purple-500 text-white font-medium text-sm rounded-lg transition-colors flex items-center gap-2 shrink-0"
          >
            {loading ? (
              <><Clock className="w-4 h-4 animate-spin" /> Analyzing...</>
            ) : (
              <><Search className="w-4 h-4" /> Analyze URL</>
            )}
          </button>
        </div>
        {error && (
          <p className="mt-2 text-xs text-rose-400 font-mono flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />{error}
          </p>
        )}
        <p className="mt-2 text-[11px] text-slate-500 font-mono">
          Try examples:{' '}
          <button type="button" className="underline hover:text-slate-300 transition-colors" onClick={() => setInputUrl('http://paypal.secure-login.xyz/verify')}>
            http://paypal.secure-login.xyz/verify
          </button>
          {' · '}
          <button type="button" className="underline hover:text-slate-300 transition-colors" onClick={() => setInputUrl('https://192.168.1.1/phish')}>
            https://192.168.1.1/phish
          </button>
          {' · '}
          <button type="button" className="underline hover:text-slate-300 transition-colors" onClick={() => setInputUrl('http://xn--pypl-poad.com/login')}>
            http://xn--pypl-poad.com/login
          </button>
        </p>
      </form>

      {/* ── Loading State ── */}
      {loading && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-10 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-purple-500/20 animate-ping" />
            <div className="absolute inset-2 rounded-full border-2 border-purple-400/40 animate-pulse" />
            <Shield className="absolute inset-0 m-auto w-6 h-6 text-purple-400" />
          </div>
          <div className="text-center">
            <p className="text-sm font-mono text-slate-300">Running 12 phishing detectors...</p>
            <p className="text-xs text-slate-500 mt-1">Static analysis only — no network requests to target URL</p>
          </div>
        </div>
      )}

      {/* ── Results ── */}
      {result && !loading && riskCfg && RiskIcon && (
        <div className="space-y-4">
          {/* Risk Score Hero */}
          <div className={`bg-soc-card border ${riskCfg.border} rounded-xl p-5`}>
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5">
              {/* Arc + badge */}
              <div className="flex flex-col items-center shrink-0">
                <ScoreArc score={result.risk_score} category={result.risk_category} />
                <div className={`flex items-center gap-1.5 mt-1 px-3 py-1 rounded-full ${riskCfg.bg} ${riskCfg.border} border`}>
                  <RiskIcon className={`w-3.5 h-3.5 ${riskCfg.color}`} />
                  <span className={`text-xs font-bold font-mono ${riskCfg.color}`}>{riskCfg.label}</span>
                </div>
              </div>

              {/* Summary */}
              <div className="flex-1 min-w-0">
                <div className="font-mono text-xs text-slate-500 mb-1">ANALYZED URL</div>
                <div className="text-sm text-slate-200 font-mono break-all bg-slate-900/60 rounded-lg p-2.5 border border-slate-800 mb-3">
                  {result.url}
                </div>
                <p className={`text-sm leading-relaxed ${riskCfg.color}`}>{result.summary}</p>

                {/* Parsed Info Grid */}
                {result.parsed && (
                  <div className="mt-3 grid grid-cols-3 gap-2 text-[11px] font-mono">
                    <div className="bg-slate-900/60 rounded p-2 border border-slate-800">
                      <div className="text-slate-500">SCHEME</div>
                      <div className="text-slate-300 mt-0.5 uppercase">{result.parsed.scheme}</div>
                    </div>
                    <div className="bg-slate-900/60 rounded p-2 border border-slate-800">
                      <div className="text-slate-500">LENGTH</div>
                      <div className="text-slate-300 mt-0.5">{result.parsed.url_length} chars</div>
                    </div>
                    <div className="bg-slate-900/60 rounded p-2 border border-slate-800">
                      <div className="text-slate-500">SUBDOMAINS</div>
                      <div className="text-slate-300 mt-0.5">{result.parsed.subdomain_depth} levels</div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Detection Details */}
          <div className="bg-soc-card border border-soc-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-purple-400" />
                DETECTION DETAILS ({result.detections.length} signal{result.detections.length !== 1 ? 's' : ''})
              </h2>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition-colors"
              >
                <Copy className="w-3.5 h-3.5" />
                {copied ? 'Copied!' : 'Copy Report'}
              </button>
            </div>

            {result.detections.length === 0 ? (
              <div className="p-6 text-center border border-dashed border-emerald-800/40 rounded-lg bg-emerald-950/20">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                <p className="text-sm text-emerald-300 font-mono">No phishing indicators detected</p>
                <p className="text-xs text-slate-500 mt-1">Static analysis found no suspicious patterns in this URL</p>
              </div>
            ) : (
              <div className="space-y-2">
                {result.detections.map(det => (
                  <DetectionCard key={det.code} det={det} />
                ))}
              </div>
            )}
          </div>

          {/* Analyze Another */}
          <button
            onClick={() => { setResult(null); setInputUrl(''); inputRef.current?.focus(); }}
            className="w-full py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded-xl transition-colors font-mono border border-soc-border"
          >
            ← Analyze Another URL
          </button>
        </div>
      )}

      {/* ── Empty State ── */}
      {!result && !loading && (
        <div className="bg-soc-card border border-soc-border rounded-xl p-10 text-center">
          <div className="inline-flex p-4 bg-purple-500/10 rounded-full mb-4">
            <Shield className="w-10 h-10 text-purple-400/60" />
          </div>
          <h3 className="text-base font-mono font-bold text-slate-400 mb-2">URL INTELLIGENCE WORKSPACE</h3>
          <p className="text-sm text-slate-500 max-w-md mx-auto leading-relaxed">
            Enter any suspicious URL above to run 12 static phishing detectors including IP detection,
            punycode analysis, brand impersonation checks, credential keyword scanning, and entropy analysis.
          </p>
          <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono text-slate-500 max-w-2xl mx-auto">
            {DETECTOR_LIST.map(d => (
              <div key={d} className="flex items-center gap-1.5 p-2 bg-slate-900/60 rounded-lg border border-slate-800">
                <Shield className="w-3 h-3 text-purple-400/60 shrink-0" />
                {d}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
