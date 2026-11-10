import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Mail, GitCompare, Briefcase, Network,
  Search, ShieldAlert, FileText, ClipboardList, Settings,
  Link2, Shield
} from 'lucide-react';

const NavSection: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="mb-4">
    <div className="px-3 mb-1">
      <span className="text-[9px] font-bold tracking-widest text-slate-600 uppercase">{title}</span>
    </div>
    <div className="space-y-0.5">{children}</div>
  </div>
);

const NavItem: React.FC<{ to: string; label: string; icon: React.FC<{ className?: string }> }> = ({ to, label, icon: Icon }) => (
  <NavLink
    to={to}
    className={({ isActive }) =>
      `group flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 ${
        isActive
          ? 'bg-sky-500/10 text-sky-400 border-l-2 border-sky-400 pl-[10px]'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border-l-2 border-transparent'
      }`
    }
  >
    <Icon className="w-4 h-4 shrink-0 transition-transform group-hover:scale-105" />
    <span className="flex-1">{label}</span>
  </NavLink>
);

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-56 bg-soc-card border-r border-soc-border min-h-[calc(100vh-3.5rem)] py-4 flex flex-col shrink-0">
      <nav className="flex-1 px-3">
        <NavSection title="Overview">
          <NavItem to="/dashboard" label="Dashboard" icon={LayoutDashboard} />
        </NavSection>

        <NavSection title="Investigation">
          <NavItem to="/emails" label="Email Samples" icon={Mail} />
          <NavItem to="/emails/compare" label="Compare Emails" icon={GitCompare} />
          <NavItem to="/url-intelligence" label="URL Intelligence" icon={Link2} />
          <NavItem to="/iocs" label="IOC Search" icon={Search} />
        </NavSection>

        <NavSection title="Threat Analysis">
          <NavItem to="/relationships" label="Relationship Graph" icon={Network} />
          <NavItem to="/threat-intel" label="Threat Intel" icon={ShieldAlert} />
        </NavSection>

        <NavSection title="Operations">
          <NavItem to="/cases" label="Cases" icon={Briefcase} />
          <NavItem to="/reports" label="Reports" icon={FileText} />
          <NavItem to="/audit" label="Audit Logs" icon={ClipboardList} />
          <NavItem to="/settings" label="Settings &amp; YARA" icon={Settings} />
        </NavSection>
      </nav>

      <div className="px-4 py-3 border-t border-soc-border">
        <div className="flex items-center gap-2 text-[10px] font-mono text-slate-600">
          <Shield className="w-3 h-3" />
          <span>MailForensics v2.0</span>
        </div>
      </div>
    </aside>
  );
};
