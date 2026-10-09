import React from 'react';

interface VerdictBadgeProps {
  verdict?: 'BENIGN' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS_ATTACHMENT' | 'SPAM' | 'UNRESOLVED' | string;
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({ verdict = 'UNRESOLVED' }) => {
  let colorClasses = 'bg-slate-800 text-slate-400 border-slate-700';

  switch (verdict?.toUpperCase()) {
    case 'BENIGN':
      colorClasses = 'bg-emerald-950/60 text-emerald-300 border-emerald-700/60';
      break;
    case 'SUSPICIOUS':
      colorClasses = 'bg-amber-950/60 text-amber-300 border-amber-700/60';
      break;
    case 'PHISHING':
    case 'MALICIOUS_ATTACHMENT':
      colorClasses = 'bg-rose-950/80 text-rose-300 border-rose-700/80 font-bold';
      break;
    case 'SPAM':
      colorClasses = 'bg-purple-950/60 text-purple-300 border-purple-700/60';
      break;
    case 'UNRESOLVED':
    default:
      colorClasses = 'bg-slate-800 text-slate-400 border-slate-700';
      break;
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs border font-mono tracking-wider ${colorClasses}`}>
      {verdict.replace('_', ' ')}
    </span>
  );
};
