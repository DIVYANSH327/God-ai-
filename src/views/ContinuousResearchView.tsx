import React, { useState } from 'react';
import {
  Clock,
  Pause,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useGriResearch } from '../context/GriResearchContext';
import type {
  MonitorCadence,
  MonitorSourcePolicy,
  MonitorType,
} from '../shared/griTypes';

const MONITOR_TYPE_LABELS: Record<MonitorType, string> = {
  web_topic: 'Public Web Docs & Releases',
  website_tech: 'Website Frontend/Header Watch',
  server_dns: 'Server DNS & CT Log Watch',
  cve_advisory: 'CVE & CISA KEV Feed Watch',
};

const SOURCE_POLICY_LABELS: Record<MonitorSourcePolicy, string> = {
  respect_robots_strict: 'Strict robots.txt & Crawl-delay',
  official_advisories_only: 'Official NVD / CISA / Vendor Feeds',
  public_docs_only: 'Public Documentation Origins Only',
};

export const ContinuousResearchView: React.FC = () => {
  const {
    researchMonitors,
    runningMonitorId,
    monitorMessage,
    addMonitor,
    toggleMonitorEnabled,
    runMonitorNow,
    deleteMonitor,
  } = useGriResearch();

  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [monitorType, setMonitorType] = useState<MonitorType>('cve_advisory');
  const [cadence, setCadence] = useState<MonitorCadence>('daily');
  const [rateLimitPerHour, setRateLimitPerHour] = useState(4);
  const [sourcePolicy, setSourcePolicy] = useState<MonitorSourcePolicy>('official_advisories_only');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const activeCount = researchMonitors.filter((m) => m.enabled).length;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);
    try {
      const res = await addMonitor({
        name,
        target,
        monitorType,
        cadence,
        rateLimitPerHour,
        sourcePolicy,
      });
      if (!res.ok) {
        setFormError(res.error || 'Could not create discovery monitor.');
      } else {
        setName('');
        setTarget('');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-blue-400">
          <Clock className="w-3.5 h-3.5" />
          <span>GRI v0.5 Module 8 · Configurable Discovery Policies &amp; Rate Limits</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Continuous Research Scheduler</h1>
        <p className="text-sm text-slate-400 max-w-3xl">
          Configure recurring discovery monitors for public documentation, technology stacks, DNS/CT
          changes, and CVE advisories with explicit per-hour rate limits and source governance
          policies.
        </p>
      </div>

      {/* Honest Execution Architecture Notice */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-5 flex items-start gap-3 text-xs">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold text-white">
            Execution Mode Disclosure ({activeCount} of {researchMonitors.length} monitors enabled)
          </p>
          <p className="text-slate-400 leading-relaxed">
            Monitor definitions, rate limits (1–12 req/hr), and source policies persist in your
            isolated Cloud Firestore workspace. Clicking <strong>Run Now</strong> executes the live
            server-side connector immediately; unattended background cron execution requires an
            external Cloud Scheduler trigger pointing to an authenticated worker and is never faked
            in the browser.
          </p>
        </div>
      </section>

      {/* Create Discovery Monitor Form */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5">
        <div>
          <h2 className="text-base font-semibold text-white">Create Discovery Monitor</h2>
          <p className="text-xs text-slate-400">
            All monitors enforce public-only host validation, robots.txt compliance, and the global
            Emergency Stop switch.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label htmlFor="mon-name" className="block text-xs font-medium text-slate-300">
                Monitor Name
              </label>
              <input
                id="mon-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., PostgreSQL CVE & Advisory Watch"
                maxLength={140}
                className="w-full px-3.5 py-2 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="mon-target" className="block text-xs font-medium text-slate-300">
                Target Topic, Public Domain, or Software Vendor
              </label>
              <input
                id="mon-target"
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g., postgresql or https://nodejs.org"
                maxLength={240}
                className="w-full px-3.5 py-2 text-sm font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="space-y-1.5">
              <label htmlFor="mon-type" className="block text-xs font-medium text-slate-300">
                Connector Type
              </label>
              <select
                id="mon-type"
                value={monitorType}
                onChange={(e) => setMonitorType(e.target.value as MonitorType)}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
              >
                <option value="cve_advisory">CVE &amp; CISA KEV Watch</option>
                <option value="web_topic">Public Web Docs &amp; Releases</option>
                <option value="website_tech">Website Frontend/Header Watch</option>
                <option value="server_dns">Server DNS &amp; CT Log Watch</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="mon-cadence" className="block text-xs font-medium text-slate-300">
                Schedule Cadence
              </label>
              <select
                id="mon-cadence"
                value={cadence}
                onChange={(e) => setCadence(e.target.value as MonitorCadence)}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="mon-rate" className="block text-xs font-medium text-slate-300">
                Rate Limit (req / hour)
              </label>
              <input
                id="mon-rate"
                type="number"
                min={1}
                max={12}
                value={rateLimitPerHour}
                onChange={(e) => setRateLimitPerHour(Number(e.target.value))}
                className="w-full px-3 py-2 text-xs font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200 tabular-nums"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="mon-policy" className="block text-xs font-medium text-slate-300">
                Source Policy
              </label>
              <select
                id="mon-policy"
                value={sourcePolicy}
                onChange={(e) => setSourcePolicy(e.target.value as MonitorSourcePolicy)}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
              >
                <option value="respect_robots_strict">Strict robots.txt &amp; Crawl-delay</option>
                <option value="official_advisories_only">Official NVD / CISA Advisories</option>
                <option value="public_docs_only">Public Documentation Only</option>
              </select>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            {formError ? (
              <p role="alert" className="text-xs text-red-400">
                {formError}
              </p>
            ) : (
              <span className="text-xs text-slate-500">
                Rate cap enforced between 1 and 12 requests/hour per monitor.
              </span>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{submitting ? 'Saving...' : 'Add Discovery Monitor'}</span>
            </button>
          </div>
        </form>
      </section>

      {monitorMessage && (
        <div
          role="status"
          className="rounded-lg bg-blue-950/30 border border-blue-500/30 px-4 py-3 text-xs text-blue-200"
        >
          {monitorMessage}
        </div>
      )}

      {/* Configured Discovery Monitors List */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Configured Discovery Monitors</h2>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {researchMonitors.length} monitor(s)
          </span>
        </div>

        {researchMonitors.length === 0 ? (
          <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-8 text-center text-sm text-slate-400">
            No discovery monitors configured yet. Add one above to track public releases or CVEs.
          </div>
        ) : (
          <div className="divide-y divide-white/[0.06] rounded-xl bg-[#0f131c] border border-white/[0.08]">
            {researchMonitors.map((mon) => (
              <div
                key={mon.id}
                className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                    <span className={mon.enabled ? 'text-emerald-400 font-semibold' : 'text-slate-500'}>
                      {mon.enabled ? 'ENABLED' : 'PAUSED'}
                    </span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-blue-400">{MONITOR_TYPE_LABELS[mon.monitorType]}</span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-slate-400">
                      {mon.cadence} ({mon.rateLimitPerHour} req/hr)
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-white">{mon.name}</h3>
                  <p className="text-xs font-mono text-slate-400 truncate">
                    Target: {mon.target} · Policy: {SOURCE_POLICY_LABELS[mon.sourcePolicy]}
                  </p>
                  <p className="text-xs text-slate-500">
                    {mon.lastRunSummary || 'No runs recorded yet.'}
                    {mon.lastRunAtMs > 0
                      ? ` (${new Date(mon.lastRunAtMs).toLocaleString()})`
                      : ''}
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    type="button"
                    disabled={runningMonitorId === mon.id}
                    onClick={() => runMonitorNow(mon.id)}
                    aria-label={`Run monitor ${mon.name} now`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <RefreshCw
                      className={`w-3.5 h-3.5 ${runningMonitorId === mon.id ? 'animate-spin' : ''}`}
                    />
                    <span>{runningMonitorId === mon.id ? 'Running...' : 'Run Now'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => toggleMonitorEnabled(mon.id)}
                    aria-label={mon.enabled ? `Pause monitor ${mon.name}` : `Resume monitor ${mon.name}`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.12] text-slate-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    {mon.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    <span>{mon.enabled ? 'Pause' : 'Resume'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => deleteMonitor(mon.id)}
                    aria-label={`Delete monitor ${mon.name}`}
                    className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg cursor-pointer"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
