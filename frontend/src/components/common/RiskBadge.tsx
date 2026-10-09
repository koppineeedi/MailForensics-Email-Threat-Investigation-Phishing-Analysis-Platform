import React from 'react';

interface RiskBadgeProps {
  category: 'LOW' | 'GUARDED' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' | string;
  score?: number;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ category, score }) => {
  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';

  switch (category?.toUpperCase()) {
    case 'LOW':
      colorClasses = 'bg-emerald-950/70 text-emerald-400 border-emerald-800/60';
      break;
    case 'GUARDED':
      colorClasses = 'bg-blue-950/70 text-blue-400 border-blue-800/60';
      break;
    case 'SUSPICIOUS':
      colorClasses = 'bg-amber-950/70 text-amber-400 border-amber-800/60';
      break;
    case 'HIGH':
      colorClasses = 'bg-orange-950/70 text-orange-400 border-orange-800/60';
      break;
    case 'CRITICAL':
      colorClasses = 'bg-rose-950/70 text-rose-400 border-rose-800/60 font-bold animate-pulse';
      break;
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs border font-mono tracking-wide ${colorClasses}`}>
      <span>{category?.toUpperCase()}</span>
      {score !== undefined && <span className="text-[11px] opacity-80">({score})</span>}
    </span>
  );
};
