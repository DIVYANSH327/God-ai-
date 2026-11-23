import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ExternalLink,
  Globe,
  Network,
  Search,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import { useGriResearch } from '../context/GriResearchContext';
import { useGodWorkspace } from '../context/GodWorkspaceContext';
import { MarkdownRenderer } from '../components/MarkdownRenderer';
import type { KnowledgeEntityType } from '../shared/ginTypes';
import { isSafeExternalUrl } from '../shared/validation';

export const InternetExplorerView: React.FC = () => {
  const { setActiveSection, startNewConversation } = useGodWorkspace();
  const {
    researchReports,
    isResearching,
    researchError,
    clearResearchError,
    lastExtractedEntities,
    lastRobotsResult,
    robotsError,
    isCheckingRobots,
    runGroundedResearch,
    checkPublicRobots,
    deleteResearchReport,
    addKnowledgeNode,
  } = useGinIntelligence();
  const { techAnalyses, cveAdvisories } = useGriResearch();

  const [queryText, setQueryText] = useState('');
  const [scheduleCadence, setScheduleCadence] = useState<'manual' | 'daily' | 'weekly'>('manual');
  const [robotsUrlInput, setRobotsUrlInput] = useState('https://www.rfc-editor.org');
  const [expandedReportId, setExpandedReportId] = useState<string | null>(
    researchReports[0]?.id || null
  );
  const [committedEntityLabels, setCommittedEntityLabels] = useState<Record<string, boolean>>({});
  const [sourceOriginFilter, setSourceOriginFilter] = useState<
    'all' | 'research' | 'tech' | 'cve'
  >('all');

  const aggregatedSources = useMemo(() => {
    const items: Array<{
      id: string;
      title: string;
      uri: string;
      domain: string;
      origin: 'research' | 'tech' | 'cve';
      context: string;
    }> = [];
    const seen = new Set<string>();

    for (const r of researchReports) {
      for (const s of r.sources) {
        if (!isSafeExternalUrl(s.uri) || seen.has(s.uri)) continue;
        seen.add(s.uri);
        items.push({
          id: `rep-${r.id}-${s.uri}`,
          title: s.title,
          uri: s.uri,
          domain: s.domain,
          origin: 'research',
          context: r.query,
        });
      }
    }

    for (const t of techAnalyses) {
      for (const s of t.sources) {
        if (!isSafeExternalUrl(s.uri) || seen.has(s.uri)) continue;
        seen.add(s.uri);
        items.push({
          id: `tech-${t.id}-${s.uri}`,
          title: s.title,
          uri: s.uri,
          domain: s.domain,
          origin: 'tech',
          context: t.title,
        });
      }
    }

    for (const c of cveAdvisories) {
      if (!c.sourceUri || !isSafeExternalUrl(c.sourceUri) || seen.has(c.sourceUri)) continue;
      seen.add(c.sourceUri);
      let domain = 'nvd.nist.gov';
      try {
        domain = new URL(c.sourceUri).hostname;
      } catch {
        // default
      }
      items.push({
        id: `cve-${c.id}`,
        title: `${c.cveId} — ${c.title}`,
        uri: c.sourceUri,
        domain,
        origin: 'cve',
        context: `${c.vendorProduct} (${c.severity.toUpperCase()})`,
      });
    }

    return items;
  }, [researchReports, techAnalyses, cveAdvisories]);

  const visibleSources =
    sourceOriginFilter === 'all'
      ? aggregatedSources
      : aggregatedSources.filter((s) => s.origin === sourceOriginFilter);

  const handleRunSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await runGroundedResearch(queryText, scheduleCadence);
    if (res.ok) {
      setQueryText('');
    }
  };

  const handleRobotsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await checkPublicRobots(robotsUrlInput);
  };

  const handleCommitEntity = async (entity: {
    label: string;
    entityType: KnowledgeEntityType;
    claim: string;
  }) => {
    const latestReport = researchReports[0];
    const source = latestReport?.sources[0];
    const res = await addKnowledgeNode({
      label: entity.label,
      entityType: entity.entityType,
      claim: entity.claim,
      sourceTitle: source?.title || 'GOD Internet Explorer (Search Grounding)',
      sourceUri: source?.uri || '',
      confidenceScore: latestReport?.confidenceScore || 82,
    });
    if (res.ok) {
      setCommittedEntityLabels((prev) => ({ ...prev, [entity.label]: true }));
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
            <Globe className="w-3.5 h-3.5" />
            <span>GRI v0.5 Operational · Gemini Search Grounding, RFC 9309 Compliance &amp; Source Explorer</span>
          </div>
          <h1 className="text-2xl font-bold text-white">GOD Internet Explorer</h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Run grounded public web research with verifiable source citations, inspect public
            origins for respectful crawling compliance, and commit validated entities directly into
            your Knowledge Graph.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setActiveSection('knowledge')}
          className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 border border-white/[0.08] rounded-lg whitespace-nowrap shrink-0 cursor-pointer self-start"
        >
          <Network className="w-3.5 h-3.5 text-blue-400" />
          <span>Open Knowledge Graph</span>
        </button>
      </div>

      {/* Primary Split: Grounded Web Research + Respectful robots.txt Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Public Web Search Integration */}
        <form
          onSubmit={handleRunSearch}
          className="lg:col-span-7 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
        >
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-white">
              Public Web Research (Gemini Search Grounding)
            </h2>
            <p className="text-xs text-slate-400">
              Executes server-side Google Search grounding via Gemini, separating Verified Facts
              from Analytical Predictions with clickable source citations.
            </p>
          </div>

          <div className="space-y-2">
            <label htmlFor="gin-research-query" className="block text-xs font-medium text-slate-300">
              Intelligence Query
            </label>
            <textarea
              id="gin-research-query"
              rows={3}
              value={queryText}
              onChange={(e) => {
                setQueryText(e.target.value);
                if (researchError) clearResearchError();
              }}
              placeholder="e.g., Compare NIST SP 800-207 Zero Trust telemetry standards and RFC 9309 automated crawler compliance..."
              maxLength={400}
              className="w-full px-3.5 py-2.5 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <label htmlFor="gin-schedule-cadence" className="text-xs text-slate-400">
                Discovery Tag:
              </label>
              <select
                id="gin-schedule-cadence"
                value={scheduleCadence}
                onChange={(e) =>
                  setScheduleCadence(e.target.value as 'manual' | 'daily' | 'weekly')
                }
                className="px-2.5 py-1.5 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
              >
                <option value="manual">Manual Run (Active v0.2)</option>
                <option value="daily">Daily Schedule Tag (Cron Planned v0.3)</option>
                <option value="weekly">Weekly Schedule Tag (Cron Planned v0.3)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={isResearching}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span>{isResearching ? 'Researching Web...' : 'Run Grounded Research'}</span>
            </button>
          </div>

          {researchError && (
            <div
              role="alert"
              className="flex items-start gap-2 text-xs text-amber-200 bg-amber-950/30 border border-amber-500/30 rounded-lg px-3.5 py-2.5"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
              <span>{researchError}</span>
            </div>
          )}

          {/* Extracted Knowledge Entities ready for one-click Knowledge Graph ingestion */}
          {lastExtractedEntities.length > 0 && (
            <div className="pt-3 border-t border-white/[0.07] space-y-2.5">
              <p className="text-xs font-semibold text-blue-300">
                Extracted Knowledge Entities (Commit to Graph)
              </p>
              <div className="divide-y divide-white/[0.06]">
                {lastExtractedEntities.map((ent) => (
                  <div
                    key={ent.label}
                    className="py-2 flex items-start justify-between gap-3 text-xs"
                  >
                    <div className="space-y-0.5">
                      <p className="font-semibold text-white">
                        {ent.label}{' '}
                        <span className="font-mono font-normal text-slate-400">
                          · {ent.entityType}
                        </span>
                      </p>
                      <p className="text-slate-400">{ent.claim}</p>
                    </div>
                    <button
                      type="button"
                      disabled={Boolean(committedEntityLabels[ent.label])}
                      onClick={() => handleCommitEntity(ent)}
                      className="px-2.5 py-1 text-[11px] font-semibold bg-blue-600/20 hover:bg-blue-600/35 border border-blue-500/35 text-blue-200 rounded-md whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      {committedEntityLabels[ent.label] ? 'Committed' : 'Add to Graph'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </form>

        {/* Respectful Crawling: robots.txt & SSRF Guard Inspector */}
        <section className="lg:col-span-5 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-blue-400">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <h2 className="text-base font-semibold text-white">
                Respectful Crawler Compliance Check
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              Verifies RFC 9309 <code className="font-mono">robots.txt</code> rules & Crawl-delay
              while enforcing DNS/IP SSRF protection against private LAN or metadata hosts.
            </p>
          </div>

          <form onSubmit={handleRobotsSubmit} className="flex gap-2">
            <label htmlFor="robots-origin-input" className="sr-only">
              Public website origin URL
            </label>
            <input
              id="robots-origin-input"
              type="text"
              value={robotsUrlInput}
              onChange={(e) => setRobotsUrlInput(e.target.value)}
              placeholder="https://example.org"
              className="flex-1 min-w-0 px-3 py-2 text-xs font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              type="submit"
              disabled={isCheckingRobots}
              className="px-3.5 py-2 text-xs font-semibold bg-white/[0.08] hover:bg-white/[0.14] text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              {isCheckingRobots ? 'Checking...' : 'Check robots.txt'}
            </button>
          </form>

          {robotsError && (
            <div
              role="alert"
              className="p-3 rounded-lg bg-[#090b10] border border-amber-500/35 text-xs text-amber-200 leading-relaxed"
            >
              {robotsError}
            </div>
          )}

          {lastRobotsResult && (
            <div className="p-4 rounded-lg bg-[#090b10] border border-white/[0.08] space-y-2 text-xs">
              <div className="flex items-center justify-between gap-2 font-mono">
                <span className="text-slate-200 truncate">{lastRobotsResult.origin}</span>
                <span
                  className={
                    lastRobotsResult.allowedForGinBot
                      ? 'text-emerald-400 font-semibold'
                      : 'text-red-400 font-semibold'
                  }
                >
                  {lastRobotsResult.allowedForGinBot ? 'PERMITTED' : 'DISALLOWED'}
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed">{lastRobotsResult.policySummary}</p>
              {lastRobotsResult.disallowedPaths.length > 0 && (
                <p className="font-mono text-[11px] text-slate-500">
                  Restricted paths respected:{' '}
                  {lastRobotsResult.disallowedPaths.slice(0, 6).join(', ')}
                </p>
              )}
            </div>
          )}

          <div className="pt-3 border-t border-white/[0.06] space-y-1.5 text-xs text-slate-400">
            <p className="font-semibold text-slate-300">Public Connector Readiness (GRI v0.5)</p>
            <p>· Google Search Grounding &amp; robots.txt Inspector: Operational</p>
            <p>· Frontend HTML/Header &amp; Backend Docs Analyzer: Operational (v0.5)</p>
            <p>· Public DNS &amp; crt.sh Certificate Transparency: Operational (v0.5)</p>
            <p>· NVD CVE 2.0 &amp; Live CISA KEV Feed Connectors: Operational (v0.5)</p>
          </div>
        </section>
      </div>

      {/* GRI v0.5 Global Source Explorer */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-0.5">
            <div className="flex items-center gap-2 text-blue-400">
              <BookOpen className="w-4 h-4 shrink-0" />
              <h2 className="text-base font-semibold text-white">Global Source Explorer</h2>
            </div>
            <p className="text-xs text-slate-400">
              Consolidated verifiable HTTPS citations collected across Internet Explorer, Tech/Server
              Intelligence, and CVE Security Research.
            </p>
          </div>

          <div
            role="group"
            aria-label="Filter explored sources by module"
            className="flex items-center gap-1 p-1 bg-[#090b10] border border-white/[0.08] rounded-lg self-start"
          >
            {(
              [
                ['all', 'All'],
                ['research', 'Web'],
                ['tech', 'Tech/Server'],
                ['cve', 'CVE/KEV'],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setSourceOriginFilter(key)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  sourceOriginFilter === key
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {visibleSources.length === 0 ? (
          <p className="text-xs text-slate-400 border-t border-white/[0.06] pt-4">
            No verifiable external citations in this category yet.
          </p>
        ) : (
          <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
            {visibleSources.map((src) => (
              <div
                key={src.id}
                className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
              >
                <div className="min-w-0 space-y-0.5">
                  <a
                    href={src.uri}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 font-medium text-blue-400 hover:text-blue-300 hover:underline"
                  >
                    <span className="truncate">{src.title}</span>
                    <ExternalLink className="w-3 h-3 shrink-0" />
                  </a>
                  <p className="text-slate-400 truncate">
                    <span className="font-mono text-slate-500">{src.domain}</span> · {src.context}
                  </p>
                </div>
                <span className="font-mono text-[11px] text-slate-500 whitespace-nowrap shrink-0">
                  {src.origin}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Research History with Verifiable Citations & Facts vs Predictions */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            Research History & Verifiable Citations
          </h2>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {researchReports.length} report(s)
          </span>
        </div>

        {researchReports.length === 0 ? (
          <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-8 text-center text-sm text-slate-400">
            No public research reports saved yet. Run a grounded query above to synthesize cited
            findings.
          </div>
        ) : (
          <div className="space-y-4">
            {researchReports.map((report) => {
              const isExpanded = expandedReportId === report.id;
              return (
                <article
                  key={report.id}
                  className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 tabular-nums">
                        <span className="text-blue-400 font-semibold">
                          Confidence {report.confidenceScore}%
                        </span>
                        <span aria-hidden="true">·</span>
                        <span>{report.sources.length} source(s)</span>
                        <span aria-hidden="true">·</span>
                        <span>Cadence: {report.scheduleCadence}</span>
                        <span aria-hidden="true">·</span>
                        <span>{new Date(report.createdAtMs).toLocaleString()}</span>
                      </div>
                      <h3 className="text-base font-semibold text-white">{report.query}</h3>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedReportId(isExpanded ? null : report.id)
                        }
                        className="px-3 py-1.5 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        {isExpanded ? 'Hide Report' : 'Read Synthesis'}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          startNewConversation(
                            `Continue deep analytical follow-up based on this GIN research query: ${report.query}`
                          )
                        }
                        className="px-3 py-1.5 text-xs font-medium bg-blue-600/20 hover:bg-blue-600/35 text-blue-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Discuss in Chat
                      </button>
                      <button
                        type="button"
                        onClick={() => deleteResearchReport(report.id)}
                        aria-label={`Delete research report ${report.query}`}
                        className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg cursor-pointer"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Verified Facts vs Analytical Predictions Split */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-white/[0.06]">
                    <div className="space-y-1.5">
                      <p className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Verified Facts</span>
                      </p>
                      <ul className="space-y-1 text-xs text-slate-300 leading-relaxed">
                        {report.facts.map((fact, idx) => (
                          <li key={idx}>· {fact}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="space-y-1.5">
                      <p className="text-xs font-semibold text-amber-300">
                        Analytical Predictions
                      </p>
                      <ul className="space-y-1 text-xs text-slate-400 leading-relaxed">
                        {report.predictions.map((pred, idx) => (
                          <li key={idx}>· {pred}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Source Citations */}
                  {report.sources.length > 0 && (
                    <div className="pt-3 border-t border-white/[0.06] space-y-1.5">
                      <p className="text-xs font-semibold text-slate-300">Source Citations</p>
                      <div className="flex flex-wrap gap-x-5 gap-y-1.5">
                        {report.sources.map((src) =>
                          isSafeExternalUrl(src.uri) ? (
                            <a
                              key={src.uri}
                              href={src.uri}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 hover:underline"
                            >
                              <span>{src.title}</span>
                              <span className="text-slate-500 font-mono">({src.domain})</span>
                              <ExternalLink className="w-3 h-3 shrink-0" />
                            </a>
                          ) : null
                        )}
                      </div>
                    </div>
                  )}

                  {isExpanded && (
                    <div className="pt-4 border-t border-white/[0.07]">
                      <MarkdownRenderer content={report.summary} />
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
};
