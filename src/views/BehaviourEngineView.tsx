import React, { useState } from 'react';
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  RefreshCw,
  Trash2,
} from 'lucide-react';
import { useGinIntelligence } from '../context/GinIntelligenceContext';

export const BehaviourEngineView: React.FC = () => {
  const {
    behaviourInsights,
    networkAssets,
    isAnalyzingBehaviour,
    behaviourError,
    runBehaviourAnalysis,
    deleteBehaviourInsight,
  } = useGinIntelligence();

  const [domainFilter, setDomainFilter] = useState<'all' | 'network' | 'internet' | 'hybrid'>('all');

  const visibleInsights =
    domainFilter === 'all'
      ? behaviourInsights
      : behaviourInsights.filter((item) => item.domain === domainFilter);

  const avgConfidence =
    behaviourInsights.length > 0
      ? Math.round(
          behaviourInsights.reduce((sum, i) => sum + i.confidenceScore, 0) /
            behaviourInsights.length
        )
      : 0;

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs font-mono text-blue-400">
            <BrainCircuit className="w-3.5 h-3.5" />
            <span>GIN v0.2 Operational · Calibrated Facts vs Predictions Analysis</span>
          </div>
          <h1 className="text-2xl font-bold text-white">GOD Behaviour Engine</h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Synthesizes authorized network telemetry and public intelligence research to surface
            drift patterns, maintain calibrated confidence scores, and rigorously separate verified
            facts from forward-looking predictions.
          </p>
        </div>

        <button
          type="button"
          disabled={isAnalyzingBehaviour}
          onClick={runBehaviourAnalysis}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzingBehaviour ? 'animate-spin' : ''}`} />
          <span>
            {isAnalyzingBehaviour ? 'Analyzing Telemetry...' : 'Synthesize Current Telemetry'}
          </span>
        </button>
      </div>

      {behaviourError && (
        <div
          role="alert"
          className="flex items-start gap-2 text-xs text-red-300 bg-red-950/30 border border-red-500/30 rounded-lg px-4 py-3"
        >
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
          <span>{behaviourError}</span>
        </div>
      )}

      {/* Metrics & Filter Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-white/[0.08]">
        <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 tabular-nums">
          <span>Insights: {behaviourInsights.length}</span>
          <span aria-hidden="true">·</span>
          <span>Mean Confidence: {avgConfidence}%</span>
          <span aria-hidden="true">·</span>
          <span>Monitored Assets: {networkAssets.length}</span>
        </div>

        <div
          role="group"
          aria-label="Filter behaviour insights by domain"
          className="flex items-center gap-1 p-1 bg-[#0f131c] border border-white/[0.08] rounded-lg self-start"
        >
          {(['all', 'network', 'internet', 'hybrid'] as const).map((dom) => (
            <button
              key={dom}
              type="button"
              onClick={() => setDomainFilter(dom)}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                domainFilter === dom
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {dom.charAt(0).toUpperCase() + dom.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Insight Cards */}
      {visibleInsights.length === 0 ? (
        <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-8 text-center text-sm text-slate-400">
          No behaviour insights match this domain filter. Click &ldquo;Synthesize Current
          Telemetry&rdquo; to evaluate your active network inventory.
        </div>
      ) : (
        <div className="space-y-5">
          {visibleInsights.map((insight) => (
            <article
              key={insight.id}
              className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                    <span
                      className={
                        insight.severity === 'critical'
                          ? 'text-red-400 font-semibold'
                          : insight.severity === 'warning'
                            ? 'text-amber-300 font-semibold'
                            : 'text-blue-400 font-semibold'
                      }
                    >
                      {insight.severity.toUpperCase()}
                    </span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-slate-300">Domain: {insight.domain}</span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-blue-400">
                      Confidence: {insight.confidenceScore}%
                    </span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-slate-500">
                      {new Date(insight.createdAtMs).toLocaleString()}
                    </span>
                  </div>
                  <h2 className="text-lg font-semibold text-white">{insight.title}</h2>
                </div>

                <button
                  type="button"
                  onClick={() => deleteBehaviourInsight(insight.id)}
                  aria-label={`Delete behaviour insight ${insight.title}`}
                  className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg cursor-pointer shrink-0"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>

              {/* Explicit Facts vs Predictions Separation */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-3 border-t border-white/[0.06]">
                <div className="space-y-2">
                  <p className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Verified Observed Facts</span>
                  </p>
                  <ul className="space-y-1.5 text-xs text-slate-200 leading-relaxed">
                    {insight.facts.map((f, idx) => (
                      <li key={idx}>· {f}</li>
                    ))}
                  </ul>
                </div>

                <div className="space-y-2">
                  <p className="text-xs font-semibold text-amber-300">
                    Probabilistic Predictions & Hypotheses
                  </p>
                  <ul className="space-y-1.5 text-xs text-slate-300 leading-relaxed">
                    {insight.predictions.map((p, idx) => (
                      <li key={idx}>· {p}</li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="pt-3 border-t border-white/[0.06] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <p className="text-slate-400 leading-relaxed">{insight.explanation}</p>
                {insight.sourceRefs.length > 0 && (
                  <p className="font-mono text-slate-500 shrink-0">
                    Refs: {insight.sourceRefs.join(', ')}
                  </p>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
};
