import React, { useMemo, useState } from 'react';
import { OctagonAlert, Power, ShieldCheck } from 'lucide-react';
import {
  useGodWorkspace,
  type CapabilityPermissionKey,
} from '../context/GodWorkspaceContext';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import type { AuditSeverity } from '../shared/types';

export const SecurityView: React.FC = () => {
  const {
    profile,
    firebaseUser,
    systemInfo,
    auditEvents,
    toggleEmergencyStop,
    updateCapabilityPermission,
  } = useGodWorkspace();
  const { networkAssets } = useGinIntelligence();

  const [severityFilter, setSeverityFilter] = useState<'all' | AuditSeverity>('all');

  const authorizedScopes = useMemo(() => {
    const map = new Map<string, { scope: string; assets: number; anomalous: number }>();
    for (const a of networkAssets) {
      const entry = map.get(a.authorizedScope) || {
        scope: a.authorizedScope,
        assets: 0,
        anomalous: 0,
      };
      entry.assets += 1;
      if (a.status === 'anomalous') entry.anomalous += 1;
      map.set(a.authorizedScope, entry);
    }
    return Array.from(map.values());
  }, [networkAssets]);

  const permissionDefinitions: Array<{
    key: CapabilityPermissionKey;
    title: string;
    scope: string;
    description: string;
  }> = [
    {
      key: 'allowWebResearch',
      title: 'Outbound Public Web Retrieval (GIN v0.2)',
      scope: 'Operational · RFC 9309 + SSRF Guard',
      description:
        'Governs server-side Google Search Grounding and respectful robots.txt compliance checks on public HTTPS origins.',
    },
    {
      key: 'allowFileAnalysis',
      title: 'Document & Diagram Inspection Consent',
      scope: 'Staged for Vision v0.3',
      description:
        'Permits user-selected file inspection once the Multimodal Vision Agent goes live. Never grants background filesystem read access.',
    },
    {
      key: 'allowLocalBridge',
      title: 'Enrolled Local Node Relay',
      scope: '0 Nodes Paired · Disabled',
      description:
        'Master consent switch for outbound WSS/mTLS communication with paired Windows or Kali Linux workstations.',
    },
    {
      key: 'allowAutomationQueue',
      title: 'Scheduled Workflow Execution',
      scope: 'Staged for Automation v0.3',
      description:
        'Requires explicit operator authorization before recurring discovery or workflow tasks can run unattended.',
    },
  ];

  const visibleAudit =
    severityFilter === 'all'
      ? auditEvents
      : auditEvents.filter((e) => e.severity === severityFilter);

  return (
    <div className="space-y-8">
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-white">Security & Governance Center</h1>
        <p className="text-sm text-slate-400 max-w-2xl">
          Enforce explicit authorized network scopes, capability approval gates, per-UID API rate
          limits, role-based boundaries, immutable audit logs, and the global Emergency Stop switch.
        </p>
      </div>

      {/* Emergency Stop Control Panel */}
      <section
        aria-label="Emergency stop control"
        className={`rounded-xl p-6 border flex flex-col md:flex-row md:items-center justify-between gap-6 ${
          profile.emergencyStop
            ? 'bg-red-950/30 border-red-500/45'
            : 'bg-[#0f131c] border-white/[0.08]'
        }`}
      >
        <div className="space-y-2 max-w-2xl">
          <div className="flex items-center gap-2">
            <OctagonAlert
              className={`w-5 h-5 shrink-0 ${
                profile.emergencyStop ? 'text-red-400' : 'text-slate-300'
              }`}
            />
            <h2 className="text-lg font-semibold text-white">
              Emergency Stop Control — {profile.emergencyStop ? 'ENGAGED' : 'Armed & Standby'}
            </h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            Engaging Emergency Stop immediately aborts active Gemini SSE streams, locks server chat,
            halts GIN Internet Explorer & Central Brain planning, and blocks all future tool
            dispatches until manually released.
          </p>
        </div>

        <button
          type="button"
          onClick={() => toggleEmergencyStop(!profile.emergencyStop)}
          className={`inline-flex items-center justify-center gap-2 px-5 py-3 text-sm font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
            profile.emergencyStop
              ? 'bg-slate-100 hover:bg-white text-slate-950'
              : 'bg-red-600 hover:bg-red-500 text-white'
          }`}
        >
          <Power className="w-4 h-4" />
          <span>
            {profile.emergencyStop ? 'Release Emergency Stop' : 'Engage Emergency Stop'}
          </span>
        </button>
      </section>

      {/* GIN v0.2 Governance Strip: Authorized Scopes + Role-Based Access + Rate Limits */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-white">
                Declared Authorized Network Scopes
              </h2>
              <p className="text-xs text-slate-400">
                Passive telemetry ingestion is restricted to explicitly declared operator scopes.
              </p>
            </div>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {authorizedScopes.length} scope(s)
            </span>
          </div>

          {authorizedScopes.length === 0 ? (
            <p className="text-xs text-slate-400 border-t border-white/[0.06] pt-3">
              No authorized network scopes registered yet.
            </p>
          ) : (
            <div className="divide-y divide-white/[0.06] border-t border-white/[0.06] text-xs">
              {authorizedScopes.map((item) => (
                <div key={item.scope} className="py-2.5 flex items-center justify-between gap-3">
                  <span className="font-mono text-slate-200">{item.scope}</span>
                  <span className="font-mono text-slate-400 tabular-nums">
                    {item.assets} asset(s) ·{' '}
                    <span className={item.anomalous > 0 ? 'text-red-400' : 'text-emerald-400'}>
                      {item.anomalous} anomalous
                    </span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-white">
                Role-Based Access & Rate-Limit Governance
              </h2>
              <p className="text-xs text-slate-400">
                Enforced via Firebase Auth verified ID tokens and Eight-Pillar Firestore rules.
              </p>
            </div>
            <span className="text-xs font-mono text-blue-400 tabular-nums">
              {systemInfo?.rateLimitPerMinute || 25} req/min
            </span>
          </div>

          <dl className="divide-y divide-white/[0.06] border-t border-white/[0.06] text-xs">
            <div className="py-2.5 flex items-center justify-between gap-3">
              <dt className="text-slate-400">Current Session Role</dt>
              <dd className="font-mono text-white">
                {firebaseUser ? 'Tenant Owner (Verified Operator / Admin)' : 'Preview Analyst (Read-Local)'}
              </dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-3">
              <dt className="text-slate-400">Tenant Namespace Isolation</dt>
              <dd className="font-mono text-emerald-400">request.auth.uid == userId</dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-3">
              <dt className="text-slate-400">Server API Rate Limiter</dt>
              <dd className="font-mono text-slate-200 tabular-nums">
                Sliding Window ({systemInfo?.rateLimitPerMinute || 25} req / 60s per UID)
              </dd>
            </div>
          </dl>
        </div>
      </section>

      {/* Permission Gates + Hardened Guardrail Constitution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className="lg:col-span-7 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5">
          <div>
            <h2 className="text-lg font-semibold text-white">Capability Approval Gates</h2>
            <p className="text-xs text-slate-400">
              Changes persist to your isolated profile and generate an immutable audit entry.
            </p>
          </div>

          <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
            {permissionDefinitions.map((perm) => {
              const checked = Boolean(profile[perm.key]);
              return (
                <div
                  key={perm.key}
                  className="py-4 flex items-start justify-between gap-4"
                >
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-white">{perm.title}</p>
                    <p className="text-xs font-mono text-slate-500">{perm.scope}</p>
                    <p className="text-xs text-slate-400 leading-relaxed">{perm.description}</p>
                  </div>

                  <button
                    type="button"
                    role="switch"
                    aria-checked={checked}
                    aria-label={perm.title}
                    onClick={() => updateCapabilityPermission(perm.key, !checked)}
                    className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      checked
                        ? 'bg-blue-600 border-blue-500 text-white'
                        : 'bg-[#090b10] border-white/[0.1] text-slate-400 hover:text-white'
                    }`}
                  >
                    {checked ? 'Approved' : 'Locked'}
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        <section className="lg:col-span-5 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="flex items-center gap-2 text-blue-400">
            <ShieldCheck className="w-4 h-4 shrink-0" />
            <h2 className="text-base font-semibold text-white">Non-Negotiable System Guardrails</h2>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            AI GOD GRI v0.5 enforces hard server-side and rule-level prohibitions that cannot be
            overridden by prompts or toggles:
          </p>
          <ul className="space-y-2.5 text-xs text-slate-300 leading-relaxed border-t border-white/[0.06] pt-3">
            <li>· Retrieved public webpages &amp; DNS data are isolated strictly as untrusted data, never instructions</li>
            <li>· No arbitrary packet interception, password capture, or covert TLS decryption</li>
            <li>· No arbitrary shell command execution or unrestricted host device control</li>
            <li>· No unauthorized port/network scanning or active vulnerability exploitation</li>
            <li>· Strict DNS + IP network guard blocks loopback, private LAN, and cloud metadata IPs</li>
            <li>· Append-only Firestore security audit records (`allow update, delete: if false`)</li>
          </ul>
        </section>
      </div>

      {/* Immutable Audit Log */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] overflow-hidden">
        <div className="px-6 py-4 border-b border-white/[0.07] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-white">Activity & Security Audit Trail</h2>
            <p className="text-xs text-slate-400">
              Append-only event log scoped to your workspace
            </p>
          </div>

          <div
            role="group"
            aria-label="Filter audit events by severity"
            className="flex items-center gap-1 p-1 bg-[#090b10] border border-white/[0.08] rounded-lg self-start"
          >
            {(['all', 'critical', 'warning', 'info'] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {visibleAudit.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-400">
            No audit events match the selected severity filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/[0.07] bg-[#0b0e15] text-xs font-semibold text-slate-400">
                  <th className="py-2.5 px-5">Action</th>
                  <th className="py-2.5 px-4">Category</th>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Summary</th>
                  <th className="py-2.5 px-5 text-right">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.05] text-xs">
                {visibleAudit.map((evt) => (
                  <tr key={evt.id} className="hover:bg-white/[0.02]">
                    <td className="py-3 px-5 font-mono text-slate-100 whitespace-nowrap">
                      {evt.action}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {evt.category}
                    </td>
                    <td className="py-3 px-4 font-mono whitespace-nowrap">
                      <span
                        className={
                          evt.severity === 'critical'
                            ? 'text-red-400 font-semibold'
                            : evt.severity === 'warning'
                              ? 'text-amber-300 font-semibold'
                              : 'text-blue-400'
                        }
                      >
                        {evt.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-md">{evt.summary}</td>
                    <td className="py-3 px-5 text-right font-mono text-slate-500 tabular-nums whitespace-nowrap">
                      {new Date(evt.createdAtMs).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
