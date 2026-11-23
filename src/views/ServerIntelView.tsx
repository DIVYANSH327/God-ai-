import React, { useState } from 'react';
import {
  AlertTriangle,
  ExternalLink,
  Network,
  Search,
  Server,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useGriResearch } from '../context/GriResearchContext';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import { MarkdownRenderer } from '../components/MarkdownRenderer';
import { isSafeExternalUrl } from '../shared/validation';

export const ServerIntelView: React.FC = () => {
  const {
    techAnalyses,
    isAnalyzingServer,
    serverError,
    lastServerResult,
    analyzeServer,
    deleteTechAnalysis,
  } = useGriResearch();
  const { addKnowledgeNode } = useGinIntelligence();

  const [hostnameInput, setHostnameInput] = useState('rfc-editor.org');
  const [committedIds, setCommittedIds] = useState<Record<string, boolean>>({});

  const serverAnalyses = techAnalyses.filter((item) => item.category === 'server');

  const handleAnalyzeServer = async (e: React.FormEvent) => {
    e.preventDefault();
    await analyzeServer(hostnameInput);
  };

  const handleCommitServer = async (item: (typeof serverAnalyses)[number]) => {
    const res = await addKnowledgeNode({
      label: item.target,
      entityType: 'infrastructure',
      claim: `Public DNS & CT profile: ${item.detectedTechnologies.slice(0, 5).join(', ') || item.title}.`,
      sourceTitle: item.sources[0]?.title || 'GRI Server Intelligence (Public DNS / CT)',
      sourceUri: item.sources[0]?.uri || '',
      confidenceScore: item.confidenceScore,
    });
    if (res.ok) {
      setCommittedIds((prev) => ({ ...prev, [item.id]: true }));
    }
  };

  return (
    <div className="space-y-8">
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-blue-400">
          <Server className="w-3.5 h-3.5" />
          <span>GRI v0.5 Module 4 · Public DNS + Certificate Transparency (crt.sh)</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Server &amp; Cloud Infrastructure Intelligence</h1>
        <p className="text-sm text-slate-400 max-w-3xl">
          Inspect public DNS records (<code className="font-mono">A</code>,{' '}
          <code className="font-mono">AAAA</code>, <code className="font-mono">NS</code>,{' '}
          <code className="font-mono">MX</code>, <code className="font-mono">TXT</code>,{' '}
          <code className="font-mono">CAA</code>) and public Certificate Transparency logs to map
          documented cloud &amp; edge providers. Never accesses restricted server administration
          interfaces or private networks.
        </p>
      </div>

      {/* Live Public DNS & CT Inspector */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
        <form onSubmit={handleAnalyzeServer} className="flex flex-col sm:flex-row gap-2.5">
          <label htmlFor="gri-server-hostname" className="sr-only">
            Public domain name to inspect
          </label>
          <input
            id="gri-server-hostname"
            type="text"
            value={hostnameInput}
            onChange={(e) => setHostnameInput(e.target.value)}
            placeholder="e.g., cloudflare.com or rfc-editor.org"
            maxLength={240}
            className="flex-1 px-3.5 py-2 text-sm font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={isAnalyzingServer}
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Search className="w-3.5 h-3.5" />
            <span>{isAnalyzingServer ? 'Resolving Public DNS & CT...' : 'Inspect Public Infrastructure'}</span>
          </button>
        </form>

        <div className="flex items-start gap-2 text-xs text-slate-400">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <span>
            Read-only public DNS &amp; CT lookups only. Internal hosts, RFC1918 private networks,
            port scanning, and restricted administration interfaces are strictly prohibited.
          </span>
        </div>

        {serverError && (
          <div
            role="alert"
            className="flex items-start gap-2 text-xs text-amber-200 bg-amber-950/30 border border-amber-500/30 rounded-lg px-3.5 py-2.5"
          >
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
            <span>{serverError}</span>
          </div>
        )}

        {lastServerResult && (
          <div className="pt-4 border-t border-white/[0.07] space-y-4 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
              <span className="text-white font-semibold">{lastServerResult.hostname}</span>
              <span className="text-emerald-400">
                CT Log: {lastServerResult.ctLookupStatus} · {lastServerResult.confidenceScore}% conf
              </span>
            </div>
            <p className="text-slate-300 leading-relaxed">{lastServerResult.architectureSummary}</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-white/[0.06]">
              <div className="space-y-1">
                <p className="font-semibold text-blue-300">Inferred Cloud &amp; Edge Providers</p>
                <p className="font-mono text-slate-300">
                  {lastServerResult.inferredInfrastructure.join(' · ') || 'No specific CDN identified'}
                </p>
              </div>
              <div className="space-y-1">
                <p className="font-semibold text-blue-300">Public Email &amp; SPF Posture</p>
                <p className="font-mono text-slate-300">
                  {lastServerResult.emailPosture.join(' · ')}
                </p>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Persisted Server Intelligence Profiles */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            Public DNS &amp; Certificate Transparency Profiles
          </h2>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {serverAnalyses.length} profile(s)
          </span>
        </div>

        {serverAnalyses.length === 0 ? (
          <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-8 text-center text-sm text-slate-400">
            No server infrastructure analyses saved yet. Query a public domain above.
          </div>
        ) : (
          <div className="space-y-4">
            {serverAnalyses.map((item) => (
              <article
                key={item.id}
                className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 tabular-nums">
                      <span className="text-blue-400 font-semibold">{item.target}</span>
                      <span aria-hidden="true">·</span>
                      <span>Confidence {item.confidenceScore}%</span>
                      <span aria-hidden="true">·</span>
                      <span>{new Date(item.createdAtMs).toLocaleString()}</span>
                    </div>
                    <h3 className="text-base font-semibold text-white">{item.title}</h3>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={Boolean(committedIds[item.id])}
                      onClick={() => handleCommitServer(item)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600/20 hover:bg-blue-600/35 text-blue-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <Network className="w-3.5 h-3.5" />
                      <span>{committedIds[item.id] ? 'Committed to Graph' : 'Commit to Graph'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteTechAnalysis(item.id)}
                      aria-label={`Delete server profile ${item.target}`}
                      className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {item.detectedTechnologies.length > 0 && (
                  <p className="text-xs font-mono text-slate-300">
                    <span className="text-slate-500">Infrastructure Signals: </span>
                    {item.detectedTechnologies.join(' · ')}
                  </p>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-white/[0.06] text-xs">
                  <div className="space-y-1.5">
                    <p className="font-semibold text-slate-200">Public DNS Records</p>
                    {item.dnsSummary.length === 0 ? (
                      <p className="text-slate-500">No DNS records stored.</p>
                    ) : (
                      <ul className="space-y-1 font-mono text-slate-400">
                        {item.dnsSummary.map((rec) => (
                          <li key={rec} className="break-all">
                            · {rec}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  <div className="space-y-1.5">
                    <p className="font-semibold text-slate-200">
                      Certificate Transparency Issuers
                    </p>
                    {item.certSummary.length === 0 ? (
                      <p className="text-slate-500">
                        CT lookup unavailable or no recent public certificates returned.
                      </p>
                    ) : (
                      <ul className="space-y-1 font-mono text-slate-400">
                        {item.certSummary.map((cert) => (
                          <li key={cert}>· {cert}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>

                <div className="pt-3 border-t border-white/[0.06]">
                  <MarkdownRenderer content={item.summary} />
                </div>

                {item.sources.length > 0 && (
                  <div className="pt-2 border-t border-white/[0.06] flex flex-wrap gap-4">
                    {item.sources.map((src) =>
                      isSafeExternalUrl(src.uri) ? (
                        <a
                          key={src.uri}
                          href={src.uri}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 hover:underline"
                        >
                          <span>{src.title}</span>
                          <ExternalLink className="w-3 h-3 shrink-0" />
                        </a>
                      ) : null
                    )}
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
