import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, LogOut, User as UserIcon, Activity } from 'lucide-react';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();

  return (
    <header className="h-14 bg-soc-card border-b border-soc-border flex items-center justify-between px-6 sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="p-1.5 bg-sky-500/10 border border-sky-500/30 rounded-lg text-sky-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-bold text-base tracking-wider text-slate-100">MAILFORENSICS</span>
          <span className="hidden sm:inline-block ml-3 text-xs text-slate-400 font-mono">Defensive SOC Platform</span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-2.5 py-1 bg-emerald-950/40 border border-emerald-800/50 rounded-full text-xs text-emerald-400 font-mono">
          <Activity className="w-3.5 h-3.5 animate-pulse text-emerald-400" />
          <span>SOC LIVE</span>
        </div>

        {user && (
          <div className="flex items-center gap-3 border-l border-soc-border pl-4">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs text-slate-300 font-mono">
                <UserIcon className="w-4 h-4" />
              </div>
              <div className="hidden md:block">
                <div className="text-xs font-semibold text-slate-200">{user.full_name}</div>
                <div className="text-[10px] font-mono text-sky-400">{user.role}</div>
              </div>
            </div>

            <button
              onClick={logout}
              className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800/60 rounded transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
