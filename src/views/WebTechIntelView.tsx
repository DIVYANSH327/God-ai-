import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Code2,
  ExternalLink,
  Layers,
  Network,
  Search,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useGriResearch } from '../context/GriResearchContext';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import { MarkdownRenderer } from '../components/MarkdownRenderer';
import { isSafeExternalUrl } from '../shared/validation';

export const WebTechIntelView: React.FC = () => {
  const {
    techAnalyses,
    isAnalyzingWebsite,
    websiteError,
    lastFrontendResult,
    analyzeWebsite,
    isResearchingBackend,
    backendError,
    researchBackend,
    deleteTechAnalysis,
  } = useGriResearch();
  const { addKnowledgeNode } = useGinIntelligence();

  const [siteUrl, setSiteUrl] = useState('https://react.dev');
  const [backendTopic, setBackendTopic] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'frontend' | 'backend'>('all');
  const [committedIds, setCommittedIds] = useState<Record<string, boolean>>({});

  const webAnalyses = techAnalyses.filter((item) => {
    if (item.category === 'server') return false;
    if (categoryFilter === 'all') return true;
    return item.category === categoryFilter;
  });

  const handleAnalyzeWebsite = async (e: React.FormEvent) => {
    e.preventDefault();
    await analyzeWebsite(siteUrl);
  };

  const handleResearchBackend = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await researchBackend(backendTopic);
    if (res.ok) setBackendTopic('');
  };

  const handleCommitToGraph = async (item: (typeof webAnalyses)[number]) => {
    const res = await addKnowledgeNode({
      label: item.target,
      entityType: item.category === 'frontend' ? 'framework' : 'technology',
      claim: `${item.title}. Detected stack: ${item.detectedTechnologies.slice(0, 6).join(', ') || 'Public docs analyzed'}.`,
      sourceTitle: item.sources[0]?.title || `GRI ${item.category} intelligence`,
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
          <Code2 className="w-3.5 h-3.5" />
          <span>GRI v0.5 Modules 2 &amp; 3 · Respects robots.txt · Untrusted Webpage Data Isolation</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Frontend &amp; Backend Intelligence</h1>
        <p className="text-sm text-slate-400 max-w-3xl">
          Inspect publicly accessible HTML, CSS/JS signatures, and HTTP response headers to explain
          frontend architecture, and research publicly documented backend APIs and server frameworks
          with verifiable citations. Retrieved webpages are treated strictly as untrusted data,
          never as instructions.
        </p>
      </div>

      {/* Dual Analyzer Split: Frontend URL Inspector + Backend Documentation Research */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Frontend Intelligence Form */}
        <section className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-white">
              Frontend Intelligence — Public Website Fingerprint
            </h2>
            <p className="text-xs text-slate-400">
              Checks <code className="font-mono">robots.txt</code> first, blocks private/loopback
              addresses, analyzes public HTML/CSS/JS fingerprints &amp; security headers without
              executing page scripts.
            </p>
          </div>

          <form onSubmit={handleAnalyzeWebsite} className="flex flex-col sm:flex-row gap-2.5">
            <label htmlFor="gri-website-url" className="sr-only">
              Public website URL to analyze
            </label>
            <input
              id="gri-website-url"
              type="text"
              value={siteUrl}
              onChange={(e) => setSiteUrl(e.target.value)}
              placeholder="https://example.org"
              maxLength={240}
              className="flex-1 px-3.5 py-2 text-sm font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              type="submit"
              disabled={isAnalyzingWebsite}
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span>{isAnalyzingWebsite ? 'Analyzing...' : 'Inspect Public Site'}</span>
            </button>
          </form>

          {websiteError && (
            <div
              role="alert"
              className="flex items-start gap-2 text-xs text-amber-200 bg-amber-950/30 border border-amber-500/30 rounded-lg px-3.5 py-2.5"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
              <span>{websiteError}</span>
            </div>
          )}

          {lastFrontendResult && (
            <div className="pt-4 border-t border-white/[0.07] space-y-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                <span className="text-white font-semibold">{lastFrontendResult.pageTitle}</span>
                <span className="text-emerald-400 tabular-nums">
                  HTTP {lastFrontendResult.httpStatus} · {lastFrontendResult.confidenceScore}% conf
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed">
                {lastFrontendResult.architectureSummary}
              </p>
              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-white/[0.06] font-mono text-slate-400 tabular-nums">
                <span>Scripts: {lastFrontendResult.scriptCount}</span>
                <span>Stylesheets: {lastFrontendResult.stylesheetCount}</span>
                <span>
                  robots.txt: {lastFrontendResult.robotsPermitted ? 'Permitted' : 'Disallowed'}
                </span>
                <span>External Hosts: {lastFrontendResult.externalOrigins.length}</span>
              </div>
              {lastFrontendResult.missingSecurityHeaders.length > 0 && (
                <p className="text-amber-300">
                  Absent security headers:{' '}
                  {lastFrontendResult.missingSecurityHeaders.join(' · ')}
                </p>
              )}
            </div>
          )}
        </section>

        {/* Backend Intelligence Form */}
        <section className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-blue-400">
              <Layers className="w-4 h-4 shrink-0" />
              <h2 className="text-base font-semibold text-white">
                Backend Intelligence — Public APIs &amp; Architecture
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              Researches publicly documented APIs, server frameworks, runtimes, and engineering
              architecture disclosures via Gemini Google Search Grounding.
            </p>
          </div>

          <form onSubmit={handleResearchBackend} className="flex flex-col sm:flex-row gap-2.5">
            <label htmlFor="gri-backend-topic" className="sr-only">
              Backend framework or public API topic
            </label>
            <input
              id="gri-backend-topic"
              type="text"
              value={backendTopic}
              onChange={(e) => setBackendTopic(e.target.value)}
              placeholder="e.g., FastAPI async ASGI architecture & OpenAPI 3.1 patterns"
              maxLength={240}
              className="flex-1 px-3.5 py-2 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              type="submit"
              disabled={isResearchingBackend}
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-white/[0.08] hover:bg-white/[0.14] disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span>{isResearchingBackend ? 'Researching...' : 'Research Backend'}</span>
            </button>
          </form>

          {backendError && (
            <div
              role="alert"
              className="flex items-start gap-2 text-xs text-amber-200 bg-amber-950/30 border border-amber-500/30 rounded-lg px-3.5 py-2.5"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
              <span>{backendError}</span>
            </div>
          )}

          <div className="pt-3 border-t border-white/[0.06] flex items-start gap-2 text-xs text-slate-400">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>
              Governance boundary: Analyzes only public HTML/HTTP responses and official public
              documentation. Never attempts authentication bypass, private API scraping, or admin
              endpoint discovery.
            </span>
          </div>
        </section>
      </div>

      {/* Stored Frontend & Backend Analyses */}
      <section className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">
            Collected Frontend &amp; Backend Technology Analyses
          </h2>
          <div
            role="group"
            aria-label="Filter web technology analyses"
            className="flex items-center gap-1 p-1 bg-[#0f131c] border border-white/[0.08] rounded-lg self-start"
          >
            {(['all', 'frontend', 'backend'] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setCategoryFilter(tab)}
                className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  categoryFilter === tab
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tab === 'all' ? 'All Stacks' : tab === 'frontend' ? 'Frontend' : 'Backend'}
              </button>
            ))}
          </div>
        </div>

        {webAnalyses.length === 0 ? (
          <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-8 text-center text-sm text-slate-400">
            No frontend or backend analyses match this filter yet. Inspect a public site or research
            a backend stack above.
          </div>
        ) : (
          <div className="space-y-4">
            {webAnalyses.map((item) => (
              <article
                key={item.id}
                className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 tabular-nums">
                      <span className="text-blue-400 font-semibold">{item.category}</span>
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
                      onClick={() => handleCommitToGraph(item)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600/20 hover:bg-blue-600/35 text-blue-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <Network className="w-3.5 h-3.5" />
                      <span>{committedIds[item.id] ? 'Committed to Graph' : 'Commit to Graph'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteTechAnalysis(item.id)}
                      aria-label={`Delete analysis ${item.title}`}
                      className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {item.detectedTechnologies.length > 0 && (
                  <div className="text-xs text-slate-300 font-mono">
                    <span className="text-slate-500">Detected Technologies: </span>
                    {item.detectedTechnologies.join(' · ')}
                  </div>
                )}

                {item.securityHeaders.length > 0 && (
                  <div className="pt-2 border-t border-white/[0.06] space-y-1 text-xs">
                    <p className="font-semibold text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Observed HTTP Security Headers</span>
                    </p>
                    <ul className="space-y-0.5 font-mono text-slate-400">
                      {item.securityHeaders.map((h) => (
                        <li key={h}>· {h}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="pt-3 border-t border-white/[0.06]">
                  <MarkdownRenderer content={item.summary} />
                </div>

                {item.sources.length > 0 && (
                  <div className="pt-3 border-t border-white/[0.06] flex flex-wrap gap-x-5 gap-y-1.5">
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
