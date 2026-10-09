import React, { useEffect, useState } from 'react';
import { graphAPI } from '../services/api';
import { RelationshipGraph, GraphNode } from '../types';
import { Network, Mail, ShieldAlert, Link, Paperclip, Briefcase } from 'lucide-react';

export const RelationshipsPage: React.FC = () => {
  const [graph, setGraph] = useState<RelationshipGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    graphAPI.getGlobal().then((data) => {
      setGraph(data);
      setLoading(false);
    });
  }, []);

  return (
    <div className="space-y-6">
      <div className="border-b border-soc-border pb-4">
        <h1 className="text-xl font-bold text-slate-100 tracking-wide flex items-center gap-2">
          <Network className="w-5 h-5 text-sky-400" />
          EMAIL RELATIONSHIP GRAPH VISUALIZATION
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-0.5">Evidence-based graph linking Senders, Domains, IPs, URLs, Hashes, Attachments & Cases</p>
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-400 font-mono text-xs">Generating relationship graph from database...</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Interactive Graph Display */}
          <div className="lg:col-span-3 bg-soc-card border border-soc-border rounded-xl p-5 min-h-[500px] relative flex flex-col justify-between">
            <div className="text-xs font-mono text-slate-400 flex items-center justify-between border-b border-soc-border pb-3">
              <span>ACTIVE GRAPH NODES: {graph?.nodes.length || 0} | EVIDENCE EDGES: {graph?.edges.length || 0}</span>
              <span className="text-[11px] text-sky-400">Click any node to view forensic details</span>
            </div>

            {/* SVG/Interactive Node Canvas */}
            <div className="flex-1 py-8 flex flex-wrap gap-3 items-center justify-center">
              {graph?.nodes.map((node) => {
                let badgeBg = 'bg-slate-900 border-slate-700 text-slate-300';
                if (node.type === 'EMAIL') badgeBg = 'bg-sky-950/80 border-sky-600 text-sky-300 font-bold';
                if (node.type === 'DOMAIN') badgeBg = 'bg-amber-950/80 border-amber-600 text-amber-300';
                if (node.type === 'URL') badgeBg = 'bg-emerald-950/80 border-emerald-600 text-emerald-300';
                if (node.type === 'HASH') badgeBg = 'bg-purple-950/80 border-purple-600 text-purple-300';
                if (node.type === 'CASE') badgeBg = 'bg-blue-950/80 border-blue-600 text-blue-300 font-bold';

                const isSelected = selectedNode?.id === node.id;

                return (
                  <button
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`px-3 py-1.5 rounded-lg border font-mono text-xs transition-all flex items-center gap-2 shadow-lg ${badgeBg} ${
                      isSelected ? 'ring-2 ring-sky-400 scale-105' : 'hover:scale-102'
                    }`}
                  >
                    <span className="text-[10px] opacity-70 uppercase">[{node.type}]</span>
                    <span>{node.label}</span>
                  </button>
                );
              })}
            </div>

            <div className="border-t border-soc-border pt-3 flex flex-wrap gap-4 text-[11px] font-mono text-slate-400">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-sky-500"></span> EMAIL</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> DOMAIN</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> URL / IP</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-purple-500"></span> HASH</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span> CASE</span>
            </div>
          </div>

          {/* Node Inspector Panel */}
          <div className="bg-soc-card border border-soc-border rounded-xl p-5 font-mono text-xs space-y-4">
            <h3 className="font-bold text-slate-200 border-b border-soc-border pb-2">NODE EVIDENCE INSPECTOR</h3>

            {!selectedNode ? (
              <div className="text-slate-500 text-[11px] pt-4">Select a node from the relationship canvas to view evidence attributes.</div>
            ) : (
              <div className="space-y-3">
                <div>
                  <div className="text-[10px] text-slate-500">NODE ID</div>
                  <div className="text-sky-400 font-bold break-all">{selectedNode.id}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500">NODE TYPE</div>
                  <div className="text-slate-200 font-bold">{selectedNode.type}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500">LABEL</div>
                  <div className="text-slate-300 break-all">{selectedNode.label}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500">EVIDENCE PROPERTIES</div>
                  <pre className="p-2 bg-slate-950 border border-slate-800 rounded text-[10px] text-slate-400 mt-1 overflow-x-auto">
                    {JSON.stringify(selectedNode.properties, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
