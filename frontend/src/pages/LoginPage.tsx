import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { authAPI, getApiBaseUrl, setApiBaseUrl } from '../services/api';
import { Shield, Lock, Mail, UserCheck, Server, CheckCircle2, AlertTriangle, Key } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

export const LoginPage: React.FC = () => {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState('ANALYST');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Backend API URL management
  const [apiUrl, setApiUrl] = useState(getApiBaseUrl());
  const [showConfig, setShowConfig] = useState(false);
  const [connStatus, setConnStatus] = useState<'idle' | 'testing' | 'online' | 'offline'>('idle');
  const [connMessage, setConnMessage] = useState('');

  const { login } = useAuth();
  const navigate = useNavigate();

  // Test backend connection
  const testBackendConnection = async (targetUrl: string) => {
    setConnStatus('testing');
    setConnMessage('Connecting to backend...');
    try {
      const url = targetUrl.trim().replace(/\/+$/, '');
      const testEndpoint = url ? `${url}/health` : '/health';
      const res = await axios.get(testEndpoint, { timeout: 4000 });
      if (res.data && res.data.status === 'healthy') {
        setConnStatus('online');
        setConnMessage(`Connected: ${res.data.app_name || 'MailForensics'} v${res.data.version || '1.0.0'}`);
      } else {
        setConnStatus('offline');
        setConnMessage('Received non-healthy response from endpoint.');
      }
    } catch (err: any) {
      setConnStatus('offline');
      setConnMessage(err.message || 'Cannot reach backend at this address.');
    }
  };

  const handleSaveApiUrl = () => {
    setApiBaseUrl(apiUrl);
    testBackendConnection(apiUrl);
  };

  const handlePrefill = (prefEmail: string, prefPass: string) => {
    setEmail(prefEmail);
    setPassword(prefPass);
    setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isRegister) {
        await authAPI.register({ email, password, full_name: fullName, role });
      }
      const data = await authAPI.login({ email, password });
      login(data.access_token, data.user);
      navigate('/dashboard');
    } catch (err: any) {
      if (err.isBackendUnreachable || !err.response) {
        const currentTarget = getApiBaseUrl() || 'frontend host';
        setError(
          `Backend server is unreachable at "${currentTarget}". MailForensics requires the FastAPI backend to be running. If running locally, start the backend with: uvicorn app.main:app --port 8000. On Vercel, configure the backend URL in the settings below.`
        );
        setShowConfig(true);
      } else if (err.response?.status === 401) {
        setError('Incorrect email or password. Use the pre-seeded credentials or register a new account.');
      } else {
        setError(err.response?.data?.detail || 'Authentication failed. Please check credentials or server status.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-soc-dark flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-soc-card border border-soc-border rounded-xl p-8 shadow-2xl">
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="p-3 bg-sky-500/10 border border-sky-500/30 rounded-xl text-sky-400 mb-3">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-slate-100">MAILFORENSICS</h1>
          <p className="text-xs text-sky-400 font-mono mt-1">Analyze. Investigate. Explain.</p>
          <p className="text-xs text-slate-400 mt-2">Defensive SOC Email Threat & Phishing Analysis Platform</p>
        </div>

        {/* Quick Fill Credentials Bar */}
        <div className="mb-5 p-3 bg-slate-900/80 border border-slate-800 rounded-lg">
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-300 mb-2">
            <Key className="w-3.5 h-3.5 text-sky-400" />
            <span>Pre-Seeded Accounts:</span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => handlePrefill('admin@mailforensics.local', 'Admin@123456')}
              className="px-2.5 py-1.5 bg-sky-950/60 hover:bg-sky-900/80 border border-sky-700/50 text-sky-300 text-xs rounded transition-colors text-left"
            >
              <div className="font-semibold">Fill Admin</div>
              <div className="text-[10px] text-sky-400/80 truncate">admin@mailforensics.local</div>
            </button>
            <button
              type="button"
              onClick={() => handlePrefill('analyst@mailforensics.local', 'Analyst@123456')}
              className="px-2.5 py-1.5 bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700/50 text-emerald-300 text-xs rounded transition-colors text-left"
            >
              <div className="font-semibold">Fill Analyst</div>
              <div className="text-[10px] text-emerald-400/80 truncate">analyst@mailforensics.local</div>
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-rose-950/60 border border-rose-800 text-rose-300 text-xs rounded-md leading-relaxed">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Full Name</label>
              <div className="relative">
                <UserCheck className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Analyst Name"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Analyst Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.corp"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          {isRegister && (
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
              >
                <option value="ANALYST">ANALYST</option>
                <option value="ADMIN">ADMIN</option>
                <option value="VIEWER">VIEWER</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 bg-sky-600 hover:bg-sky-500 text-white font-medium py-2.5 rounded-lg text-sm transition-colors flex items-center justify-center gap-2"
          >
            {loading ? 'Authenticating...' : isRegister ? 'Register Account' : 'Sign In to SOC'}
          </button>
        </form>

        <div className="mt-5 text-center border-t border-slate-800 pt-3">
          <button
            type="button"
            onClick={() => setIsRegister(!isRegister)}
            className="text-xs text-slate-400 hover:text-sky-400 transition-colors"
          >
            {isRegister ? 'Already registered? Sign In' : "Don't have an account? Register"}
          </button>
        </div>

        {/* Backend Endpoint Settings Accordion */}
        <div className="mt-4 border-t border-slate-800/80 pt-3">
          <button
            type="button"
            onClick={() => setShowConfig(!showConfig)}
            className="w-full flex items-center justify-between text-[11px] font-mono text-slate-400 hover:text-slate-200"
          >
            <span className="flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-sky-400" />
              <span>Backend API Server Settings</span>
            </span>
            <span className="text-slate-500">{showConfig ? '▲ Hide' : '▼ Configure'}</span>
          </button>

          {showConfig && (
            <div className="mt-3 p-3 bg-slate-950/70 border border-slate-800 rounded-lg text-xs space-y-2.5">
              <p className="text-[11px] text-slate-400 leading-normal">
                MailForensics uses a separated FastAPI Python backend. When deployed on Vercel, point this frontend to your active backend URL.
              </p>
              <div>
                <label className="block text-[10px] font-mono text-slate-400 mb-1">Backend API URL</label>
                <input
                  type="text"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="e.g. http://localhost:8000 or https://api.yourdomain.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-sky-500"
                />
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleSaveApiUrl}
                  className="flex-1 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-medium transition-colors"
                >
                  Save URL
                </button>
                <button
                  type="button"
                  onClick={() => testBackendConnection(apiUrl)}
                  className="flex-1 py-1.5 bg-sky-950 hover:bg-sky-900 text-sky-300 border border-sky-800/60 rounded text-[11px] font-medium transition-colors"
                >
                  Test Connection
                </button>
              </div>

              {connStatus !== 'idle' && (
                <div
                  className={`p-2 rounded text-[11px] font-mono flex items-center gap-1.5 ${
                    connStatus === 'online'
                      ? 'bg-emerald-950/60 border border-emerald-800 text-emerald-300'
                      : connStatus === 'offline'
                      ? 'bg-rose-950/60 border border-rose-800 text-rose-300'
                      : 'bg-slate-900 border border-slate-800 text-slate-400'
                  }`}
                >
                  {connStatus === 'online' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                  {connStatus === 'offline' && <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />}
                  <span className="truncate">{connMessage}</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
