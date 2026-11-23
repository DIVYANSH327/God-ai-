import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ExternalLink,
  Lock,
  Network,
  Search,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import { useGriResearch } from '../context/GriResearchContext';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import type { CveSeverity } from '../shared/griTypes';
import { isSafeExternalUrl } from '../shared/validation';

export const SecurityResearchView: React.FC = () => {
  const {
    cveAdvisories,
    isSearchingCves,
    cveError,
    lastCveSourcesChecked,
    searchCves,
    deleteCveAdvisory,
  } = useGriResearch();
  const { addKnowledgeNode } = useGinIntelligence();

  const [cveQuery, setCveQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'kev' | CveSeverity>('all');
  const [committedIds, setCommittedIds] = useState<Record<string, boolean>>({});

  const visibleCves = useMemo(() => {
    return cveAdvisories.filter((item) => {
      if (severityFilter === 'all') return true;
      if (severityFilter === 'kev') return item.cisaKev;
      return item.severity === severityFilter;
    });
  }, [cveAdvisories, severityFilter]);

  const kevCount = cveAdvisories.filter((c) => c.cisaKev).length;
  const criticalCount = cveAdvisories.filter((c) => c.severity === 'critical').length;

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await searchCves(cveQuery);
    if (res.ok) setCveQuery('');
  };

  const handleCommitCve = async (item: (typeof cveAdvisories)[number]) => {
    const res = await addKnowledgeNode({
      label: item.cveId,
      entityType: 'vulnerability',
      claim: `${item.title} (${item.vendorProduct}, CVSS ${item.cvssScore.toFixed(1)}, ${item.owaspCategory}). Mitigation: ${item.mitigation.slice(0, 260)}`,
      sourceTitle: item.cisaKev ? 'CISA KEV & NVD CVE 2.0' : 'NVD CVE 2.0 / Vendor Advisory',
      sourceUri: item.sourceUri,
      confidenceScore: item.cisaKev ? 96 : 90,
    });
    if (res.ok) {
      setCommittedIds((prev) => ({ ...prev, [item.id]: true }));
    }
  };

  return (
    <div className="space-y-8">
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-red-400">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>GRI v0.5 Module 5 · Live CISA KEV + NVD CVE 2.0 + OWASP Mitigation Mapping</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Security Research &amp; CVE Intelligence</h1>
        <p className="text-sm text-slate-400 max-w-3xl">
          Query public CVEs, vendor advisories, and the CISA Known Exploited Vulnerabilities (KEV)
          catalog, mapped automatically to affected versions, OWASP Top 10 categories, and defensive
          mitigations.
        </p>
      </div>

      {/* Metrics & Active-Testing Authorization Boundary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-3 p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1">
          <p className="text-xs text-slate-400">Tracked Advisories</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums">
            {cveAdvisories.length}
          </p>
          <p className="text-xs text-slate-500 tabular-nums">{criticalCount} critical CVSS &gt;= 9.0</p>
        </div>

        <div className="lg:col-span-3 p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1">
          <p className="text-xs text-slate-400">CISA KEV Matches</p>
          <p className="text-2xl font-bold font-mono text-red-400 tabular-nums">{kevCount}</p>
          <p className="text-xs text-slate-500">Known exploited in public catalog</p>
        </div>

        <div className="lg:col-span-6 p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] flex items-start gap-3">
          <Lock className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs">
            <p className="font-semibold text-white">
              Passive Defensive Research Only — Active Testing Locked
            </p>
            <p className="text-slate-400 leading-relaxed">
              GRI v0.5 ingests public NVD/CISA/OWASP vulnerability advisories and defensive patch
              guidance. Active vulnerability testing requires explicit written authorization and
              declared scope and is intentionally disabled in this web platform.
            </p>
          </div>
        </div>
      </div>

      {/* Live CVE & CISA KEV Search Form */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-2.5">
          <label htmlFor="gri-cve-query" className="sr-only">
            Search CVE ID, vendor, or product
          </label>
          <input
            id="gri-cve-query"
            type="text"
            value={cveQuery}
            onChange={(e) => setCveQuery(e.target.value)}
            placeholder="Search CVE ID or product (e.g., CVE-2024-21626, OpenSSL, nginx, kubernetes)..."
            maxLength={160}
            className="flex-1 px-3.5 py-2 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={isSearchingCves}
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Search className="w-3.5 h-3.5" />
            <span>{isSearchingCves ? 'Querying NVD & CISA...' : 'Ingest CVE Intelligence'}</span>
          </button>
        </form>

        <div className="text-xs font-mono text-slate-500">
          Connected feeds: {lastCveSourcesChecked.join(' · ')}
        </div>

        {cveError && (
          <div
            role="alert"
            className="flex items-start gap-2 text-xs text-amber-200 bg-amber-950/30 border border-amber-500/30 rounded-lg px-3.5 py-2.5"
          >
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
            <span>{cveError}</span>
          </div>
        )}
      </section>

      {/* Advisory List & Severity Filter */}
      <section className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">
            Vulnerability Advisories &amp; Defensive Mitigations
          </h2>

          <div
            role="group"
            aria-label="Filter CVEs by severity or CISA KEV status"
            className="flex flex-wrap items-center gap-1 p-1 bg-[#0f131c] border border-white/[0.08] rounded-lg self-start"
          >
            {(
              [
                { id: 'all', label: 'All' },
                { id: 'kev', label: 'CISA KEV' },
                { id: 'critical', label: 'Critical' },
                { id: 'high', label: 'High' },
                { id: 'medium', label: 'Medium' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setSeverityFilter(tab.id)}
                className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  severityFilter === tab.id
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {visibleCves.length === 0 ? (
          <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-8 text-center text-sm text-slate-400">
            No advisories match this filter.
          </div>
        ) : (
          <div className="space-y-4">
            {visibleCves.map((adv) => (
              <article
                key={adv.id}
                className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                      <span className="text-white font-bold">{adv.cveId}</span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span
                        className={
                          adv.severity === 'critical'
                            ? 'text-red-400 font-semibold'
                            : adv.severity === 'high'
                              ? 'text-amber-300 font-semibold'
                              : 'text-blue-400'
                        }
                      >
                        {adv.severity.toUpperCase()} (CVSS {adv.cvssScore.toFixed(1)})
                      </span>
                      {adv.cisaKev && (
                        <>
                          <span aria-hidden="true" className="text-slate-600">
                            ·
                          </span>
                          <span className="text-red-400 font-semibold">CISA KEV Listed</span>
                        </>
                      )}
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="text-slate-400">Published {adv.publishedDate}</span>
                    </div>
                    <h3 className="text-base font-semibold text-white">{adv.title}</h3>
                    <p className="text-xs text-slate-400">
                      {adv.vendorProduct} · <span className="text-blue-300">{adv.owaspCategory}</span>
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={Boolean(committedIds[adv.id])}
                      onClick={() => handleCommitCve(adv)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600/20 hover:bg-blue-600/35 text-blue-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <Network className="w-3.5 h-3.5" />
                      <span>{committedIds[adv.id] ? 'Committed' : 'Add to Graph'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteCveAdvisory(adv.id)}
                      aria-label={`Delete advisory ${adv.cveId}`}
                      className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-white/[0.06] text-xs">
                  <div className="space-y-1">
                    <p className="font-semibold text-slate-200">Affected Versions / Scope</p>
                    <p className="text-slate-400 leading-relaxed">{adv.affectedVersions}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="font-semibold text-emerald-400">Defensive Mitigation Guidance</p>
                    <p className="text-slate-300 leading-relaxed">{adv.mitigation}</p>
                  </div>
                </div>

                {isSafeExternalUrl(adv.sourceUri) && (
                  <div className="pt-2 border-t border-white/[0.06]">
                    <a
                      href={adv.sourceUri}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 hover:underline"
                    >
                      <span>View Official NVD / Vendor Reference</span>
                      <ExternalLink className="w-3 h-3 shrink-0" />
                    </a>
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
