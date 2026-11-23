import React, { useState } from 'react';
import { ArrowUpRight, CheckCircle2, Clock, FlaskConical, X } from 'lucide-react';
import { AGENT_REGISTRY } from '../shared/godCoreLogic';
import type { AgentCapabilityStatus, AgentDefinition } from '../shared/types';
import { useGodWorkspace } from '../context/GodWorkspaceContext';

export const AgentsView: React.FC = () => {
  const { startNewConversation } = useGodWorkspace();
  const [filter, setFilter] = useState<'all' | AgentCapabilityStatus>('all');
  const [selectedAgent, setSelectedAgent] = useState<AgentDefinition | null>(null);

  const visibleAgents =
    filter === 'all' ? AGENT_REGISTRY : AGENT_REGISTRY.filter((a) => a.status === filter);

  const renderStatusText = (status: AgentCapabilityStatus) => {
    if (status === 'operational') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-mono text-emerald-400">
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>Operational (GIN v0.2)</span>
        </span>
      );
    }
    if (status === 'prototype') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-mono text-amber-300">
          <FlaskConical className="w-3.5 h-3.5" />
          <span>Prototype (Core Reasoning)</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400">
        <Clock className="w-3.5 h-3.5" />
        <span>Planned (v0.3 Roadmap)</span>
      </span>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold text-white">Agent Center</h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Inspect AI GOD specialist modules. In GIN v0.2, Memory &amp; Knowledge Graph and GOD
            Internet Explorer (Gemini Search Grounding) are operational alongside Network Observer
            and Behaviour Engine, while unbuilt local/multimodal agents remain transparently staged.
          </p>
        </div>

        {/* Interactive Filter Segmented Control */}
        <div
          role="group"
          aria-label="Filter agents by readiness"
          className="flex items-center gap-1 p-1 bg-[#0f131c] border border-white/[0.08] rounded-lg self-start"
        >
          {(
            [
              { id: 'all', label: 'All (7)' },
              { id: 'operational', label: 'Operational' },
              { id: 'prototype', label: 'Prototype' },
              { id: 'planned', label: 'Planned' },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setFilter(tab.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                filter === tab.id
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Agent Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
        {visibleAgents.map((agent) => (
          <article
            key={agent.id}
            className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-5 flex flex-col justify-between space-y-5 hover:border-white/[0.16] transition-colors"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                {renderStatusText(agent.status)}
                <span className="text-xs font-mono text-slate-500">{agent.codename}</span>
              </div>

              <div>
                <h2 className="text-lg font-semibold text-white">{agent.name}</h2>
                <p className="text-sm text-slate-400 mt-1 leading-relaxed">{agent.summary}</p>
              </div>

              <div className="space-y-1.5 pt-2 border-t border-white/[0.06]">
                <p className="text-xs font-medium text-slate-300">Capabilities & Scope</p>
                <ul className="space-y-1 text-xs text-slate-400">
                  {agent.capabilities.slice(0, 3).map((cap) => (
                    <li key={cap} className="leading-relaxed">
                      · {cap}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="pt-3 border-t border-white/[0.06] flex items-center justify-between gap-3">
              <span className="text-xs font-mono text-slate-500 truncate">
                {agent.providerTarget}
              </span>
              <button
                type="button"
                onClick={() => setSelectedAgent(agent)}
                aria-label={`Inspect ${agent.name} details`}
                className="inline-flex items-center gap-1 text-xs font-semibold text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <span>Inspect Spec</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </article>
        ))}
      </div>

      {/* Agent Detail Modal */}
      {selectedAgent && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="agent-detail-heading"
          className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4"
        >
          <div className="max-w-xl w-full rounded-xl bg-[#111622] border border-white/[0.12] p-6 space-y-5 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  {renderStatusText(selectedAgent.status)}
                  <span className="text-xs font-mono text-slate-500">
                    · {selectedAgent.codename}
                  </span>
                </div>
                <h2 id="agent-detail-heading" className="text-xl font-bold text-white">
                  {selectedAgent.name}
                </h2>
              </div>

              <button
                type="button"
                onClick={() => setSelectedAgent(null)}
                aria-label="Close agent detail modal"
                className="p-1.5 text-slate-400 hover:text-white rounded-lg cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed">{selectedAgent.description}</p>

            <div className="space-y-2 pt-3 border-t border-white/[0.08]">
              <h3 className="text-xs font-semibold text-slate-200">Capability Breakdown</h3>
              <ul className="space-y-1.5 text-sm text-slate-300">
                {selectedAgent.capabilities.map((cap) => (
                  <li key={cap}>· {cap}</li>
                ))}
              </ul>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-3 border-t border-white/[0.08] text-xs">
              <div className="space-y-1">
                <p className="font-semibold text-slate-200">v0.1 Operational Truth</p>
                <p className="text-slate-400 leading-relaxed">{selectedAgent.v01Behavior}</p>
              </div>
              <div className="space-y-1">
                <p className="font-semibold text-slate-200">Security Boundary</p>
                <p className="text-slate-400 leading-relaxed">{selectedAgent.securityBoundary}</p>
              </div>
            </div>

            <div className="pt-4 border-t border-white/[0.08] flex flex-wrap items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setSelectedAgent(null)}
                className="px-4 py-2 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
              >
                Close
              </button>
              <button
                type="button"
                onClick={() => {
                  const agentName = selectedAgent.name;
                  setSelectedAgent(null);
                  startNewConversation(
                    `Provide a structured ${agentName} analysis on current cloud-hybrid system trade-offs, noting v0.1 boundaries.`
                  );
                }}
                className="px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
              >
                Consult via GOD Core Chat
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
