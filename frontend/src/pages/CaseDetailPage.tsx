import React, { useEffect, useState } from 'react';
import { useParams, Link as RouterLink } from 'react-router-dom';
import { casesAPI } from '../services/api';
import { EmailCase } from '../types';
import { Briefcase, Mail, Plus, Clock, FileText, CheckCircle, ShieldAlert } from 'lucide-react';
import { RiskBadge } from '../components/common/RiskBadge';

export const CaseDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [caseObj, setCaseObj] = useState<EmailCase | null>(null);
  const [loading, setLoading] = useState(true);
  const [noteContent, setNoteContent] = useState('');
  const [addingNote, setAddingNote] = useState(false);

  const fetchCaseDetail = async () => {
    if (!id) return;
    try {
      const data = await casesAPI.getDetail(id);
      setCaseObj(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCaseDetail();
  }, [id]);

  const handleStatusChange = async (newStatus: string) => {
    if (!id) return;
    try {
      await casesAPI.update(id, { status: newStatus });
      await fetchCaseDetail();
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id || !noteContent.trim()) return;
    setAddingNote(true);
    try {
      await casesAPI.addNote(id, noteContent);
      setNoteContent('');
      await fetchCaseDetail();
    } catch (e) {
      console.error(e);
    } finally {
      setAddingNote(false);
    }
  };

  if (loading || !caseObj) {
    return <div className="p-12 text-center text-slate-400 font-mono text-xs">Loading incident case #{id}...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Case Banner */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border pb-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="font-mono font-bold text-sky-400 text-sm">{caseObj.case_number}</span>
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800">
                {caseObj.status}
              </span>
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                Priority: {caseObj.priority}
              </span>
            </div>
            <h1 className="text-xl font-bold text-slate-100 mt-2">{caseObj.title}</h1>
            <p className="text-xs text-slate-400 font-mono mt-1">{caseObj.description || 'No detailed description provided.'}</p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-400">Update Status:</span>
            <select
              value={caseObj.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="CLOSED">CLOSED</option>
            </select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Linked Emails Column */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
              <Mail className="w-4 h-4 text-sky-400" />
              LINKED EMAIL SAMPLES ({caseObj.emails?.length || 0})
            </h3>

            {!caseObj.emails?.length ? (
              <div className="p-6 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
                No email samples currently linked to this case. Link email samples from the Email Detail page.
              </div>
            ) : (
              <div className="space-y-3 font-mono text-xs">
                {caseObj.emails.map((email) => (
                  <div key={email.id} className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between gap-4">
                    <div className="space-y-1 truncate">
                      <div className="font-bold text-slate-100 truncate">{email.subject || email.original_filename}</div>
                      <div className="text-[10px] text-slate-400">Sender: {email.sender || '—'}</div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <RiskBadge category={email.risk_category} score={email.risk_score} />
                      <RouterLink
                        to={`/emails/${email.id}`}
                        className="px-2.5 py-1 bg-sky-600/20 hover:bg-sky-600/40 text-sky-300 border border-sky-500/30 rounded text-[11px]"
                      >
                        Inspect
                      </RouterLink>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Case Notes Column */}
        <div className="space-y-6">
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 space-y-4 font-mono text-xs">
            <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <FileText className="w-4 h-4 text-sky-400" />
              INVESTIGATION NOTES ({caseObj.notes?.length || 0})
            </h3>

            <form onSubmit={handleAddNote} className="space-y-2">
              <textarea
                rows={3}
                required
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
                placeholder="Add investigation evidence note..."
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
              />
              <button
                type="submit"
                disabled={addingNote}
                className="w-full bg-blue-600 hover:bg-blue-500 text-white py-1.5 rounded-lg font-medium transition-colors"
              >
                {addingNote ? 'Adding Note...' : 'Add Note to Case'}
              </button>
            </form>

            <div className="space-y-3 pt-2">
              {caseObj.notes?.map((n) => (
                <div key={n.id} className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                  <div className="flex items-center justify-between text-[10px] text-slate-500">
                    <span>{n.author_name || 'Analyst'}</span>
                    <span>{new Date(n.created_at).toLocaleString()}</span>
                  </div>
                  <div className="text-slate-300 text-xs whitespace-pre-wrap">{n.content}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
