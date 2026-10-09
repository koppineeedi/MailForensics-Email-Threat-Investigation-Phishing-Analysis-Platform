import React, { useEffect, useState } from 'react';
import { casesAPI } from '../services/api';
import { EmailCase } from '../types';
import { Briefcase, Plus, Search, Clock, CheckCircle } from 'lucide-react';
import { Link as RouterLink } from 'react-router-dom';

export const CaseListPage: React.FC = () => {
  const [cases, setCases] = useState<EmailCase[]>([]);
  const [loading, setLoading] = useState(true);

  // New Case Modal
  const [showModal, setShowModal] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('MEDIUM');
  const [severity, setSeverity] = useState('SUSPICIOUS');
  const [creating, setCreating] = useState(false);

  const fetchCases = async () => {
    setLoading(true);
    try {
      const data = await casesAPI.list();
      setCases(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      await casesAPI.create({ title, description, priority, severity });
      setShowModal(false);
      setTitle('');
      setDescription('');
      await fetchCases();
    } catch (e) {
      console.error(e);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
            <Briefcase className="w-5 h-5 text-blue-400" />
            INCIDENT & CASE MANAGEMENT
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">Manage SOC Investigation Cases, Linked Emails, and Evidence Notes</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition-colors flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          <span>Create Investigation Case</span>
        </button>
      </div>

      <div className="bg-soc-card border border-soc-border rounded-xl p-5">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">Loading case repository...</div>
        ) : !cases.length ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
            No open incident cases found. Click "Create Investigation Case" to initiate a new case.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-soc-border uppercase text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Case Number</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Priority</th>
                  <th className="py-2.5 px-3">Linked Emails</th>
                  <th className="py-2.5 px-3">Created Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {cases.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3 font-bold text-sky-400">{c.case_number}</td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-100 max-w-sm truncate">{c.title}</div>
                      <div className="text-[10px] text-slate-500 truncate">{c.description || 'No description'}</div>
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] border border-blue-800 bg-blue-950/60 text-blue-300 font-bold">
                        {c.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300">{c.priority}</td>
                    <td className="py-3 px-3 text-slate-400">{c.emails?.length || 0} samples</td>
                    <td className="py-3 px-3 text-slate-500 text-[10px]">{new Date(c.created_at).toLocaleDateString()}</td>
                    <td className="py-3 px-3 text-right">
                      <RouterLink
                        to={`/cases/${c.id}`}
                        className="px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 border border-blue-500/30 rounded text-[11px] transition-colors"
                      >
                        Open Case
                      </RouterLink>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Case Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-card border border-soc-border rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <h2 className="text-sm font-bold text-slate-100 font-mono">CREATE INCIDENT CASE</h2>
              <button onClick={() => setShowModal(false)} className="text-slate-400 text-xs">✕</button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Phishing Campaign targeting HR"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <textarea
                  rows={3}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Initial incident notes and context..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Priority</label>
                  <select
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="URGENT">URGENT</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100"
                  >
                    <option value="GUARDED">GUARDED</option>
                    <option value="SUSPICIOUS">SUSPICIOUS</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium"
                >
                  {creating ? 'Creating Case...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
