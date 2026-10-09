import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Mail, GitCompare, Briefcase, Network,
  Search, ShieldAlert, FileText, ClipboardList, Settings
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/emails', label: 'Email Samples', icon: Mail },
    { to: '/emails/compare', label: 'Compare Emails', icon: GitCompare },
    { to: '/cases', label: 'Cases', icon: Briefcase },
    { to: '/relationships', label: 'Relationship Graph', icon: Network },
    { to: '/iocs', label: 'IOC Search', icon: Search },
    { to: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/audit', label: 'Audit Logs', icon: ClipboardList },
    { to: '/settings', label: 'Settings & YARA', icon: Settings },
  ];

  return (
    <aside className="w-56 bg-soc-card border-r border-soc-border min-h-[calc(100vh-3.5rem)] py-4 flex flex-col shrink-0">
      <nav className="space-y-1 px-3">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-sky-500/10 text-sky-400 border-l-2 border-sky-400'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
};
