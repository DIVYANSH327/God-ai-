import React, { useMemo, useState } from 'react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  Activity,
  AlertTriangle,
  BookOpen,
  BrainCircuit,
  Check,
  CheckCircle2,
  ClipboardCopy,
  Clock,
  Cpu,
  FileCheck2,
  HelpCircle,
  KeyRound,
  Lock,
  Network,
  Play,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
  XCircle,
} from 'lucide-react';
import { useSentinel } from '../context/SentinelContext';
import { SentinelTopologySvg } from '../components/SentinelTopologySvg';
import { SentinelHeartbeatChart } from '../components/SentinelHeartbeatChart';
import {
  SENTINEL_INVESTIGATION_PLAYBOOKS,
  getPlaybookById,
} from '../shared/sentinelPlaybooks';
import {
  SENTINEL_VERSION,
  type DataOrigin,
  type DefensiveActionType,
  type PlaybookId,
  type SentinelEventType,
  type SentinelOsType,
} from '../shared/sentinelTypes';

type SentinelTab =
  | 'fleet'
  | 'alerts'
  | 'incidents'
  | 'topology'
  | 'approvals'
  | 'enroll';

function formatRelativeTime(iso: string | null): string {
  if (!iso) return 'Never';
  const diffSec = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function severityBadgeClass(sev: string): string {
  switch (sev) {
    case 'critical':
      return 'bg-red-500/15 text-red-300 border-red-500/30';
    case 'high':
      return 'bg-orange-500/15 text-orange-300 border-orange-500/30';
    case 'medium':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/30';
    case 'low':
      return 'bg-blue-500/15 text-blue-300 border-blue-500/30';
    default:
      return 'bg-slate-500/15 text-slate-300 border-slate-500/30';
  }
}

function agentStatusClass(status: string): string {
  switch (status) {
    case 'online':
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
    case 'degraded':
      return 'bg-orange-500/15 text-orange-300 border-orange-500/30';
    case 'isolated':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/30';
    default:
      return 'bg-slate-600/20 text-slate-400 border-slate-600/40';
  }
}

export const SentinelView: React.FC = () => {
  const {
    isLiveMode,
    agents,
    tokens,
    events,
    heartbeatHistory,
    incidents,
    approvals,
    auditLogs,
    regionalFindings,
    topology,
    queueMetrics,
    loading,
    busyAction,
    errorMessage,
    lastIssuedPlainToken,
    refreshOverview,
    sendFirestoreHeartbeatPing,
    issueEnrollmentToken,
    revokeToken,
    revokeAgent,
    updateAgentPolicy,
    runRegionalCorrelation,
    runBrainInvestigation,
    runMilestoneOneDrill,
    proposeDefensiveAction,
    decideApproval,
    clearError,
  } = useSentinel();

  const [activeTab, setActiveTab] = useState<SentinelTab>('fleet');
  const [eventFilter, setEventFilter] = useState<SentinelEventType | 'all'>('all');
  const [originFilter, setOriginFilter] = useState<DataOrigin | 'all'>('all');
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<PlaybookId>('account_takeover');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedTopologyNodeId, setSelectedTopologyNodeId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Enrollment token form state
  const [tokenLabel, setTokenLabel] = useState('Production Linux Node');
  const [tokenRegion, setTokenRegion] = useState('asia-southeast1');
  const [tokenOs, setTokenOs] = useState<SentinelOsType>('linux');
  const [tokenTtlHours, setTokenTtlHours] = useState(24);

  // Human-approval defensive proposal form state
  const [proposalAgentId, setProposalAgentId] = useState('');
  const [proposalActionType, setProposalActionType] =
    useState<DefensiveActionType>('isolate_server');
  const [proposalTarget, setProposalTarget] = useState('');
  const [proposalRationale, setProposalRationale] = useState('');
  const [decisionNotes, setDecisionNotes] = useState<Record<string, string>>({});

  const onlineAgents = useMemo(
    () => agents.filter((a) => a.status === 'online' || a.status === 'degraded').length,
    [agents]
  );
  const openIncidents = useMemo(
    () => incidents.filter((i) => i.status !== 'resolved').length,
    [incidents]
  );
  const pendingApprovals = useMemo(
    () => approvals.filter((a) => a.status === 'pending_approval').length,
    [approvals]
  );

  const selectedIncident = useMemo(() => {
    if (incidents.length === 0) return null;
    if (selectedIncidentId) {
      return incidents.find((i) => i.id === selectedIncidentId) || incidents[0];
    }
    return incidents[0];
  }, [incidents, selectedIncidentId]);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (eventFilter !== 'all' && e.eventType !== eventFilter) return false;
      const origin: DataOrigin =
        e.provenance.dataOrigin ||
        (e.provenance.simulatedDrill ? 'synthetic_demo' : 'real_telemetry');
      if (originFilter !== 'all' && origin !== originFilter) return false;
      return true;
    });
  }, [events, eventFilter, originFilter]);

  const crossServerAttackTimeline = useMemo(() => {
    return [...events]
      .filter((e) => e.severity !== 'info')
      .sort((a, b) => new Date(a.observedAt).getTime() - new Date(b.observedAt).getTime())
      .slice(-12);
  }, [events]);

  const activePlaybook = useMemo(
    () => getPlaybookById(selectedPlaybookId) || SENTINEL_INVESTIGATION_PLAYBOOKS[0],
    [selectedPlaybookId]
  );

  const selectedTopoNode = useMemo(() => {
    if (!selectedTopologyNodeId) return topology.nodes[0] || null;
    return topology.nodes.find((n) => n.id === selectedTopologyNodeId) || topology.nodes[0] || null;
  }, [topology.nodes, selectedTopologyNodeId]);

  const controllerOrigin =
    typeof window !== 'undefined' ? window.location.origin : 'https://YOUR_GOD_CONTROLLER_URL';

  const copySnippet = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((curr) => (curr === key ? null : curr)), 1800);
    } catch {
      // ignore clipboard denial in non-HTTPS contexts
    }
  };

  const handleIssueToken = async (e: React.FormEvent) => {
    e.preventDefault();
    await issueEnrollmentToken({
      label: tokenLabel,
      region: tokenRegion,
      osType: tokenOs,
      ttlHours: tokenTtlHours,
    });
  };

  const handleProposeAction = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetAgentId = proposalAgentId || agents[0]?.id || '';
    await proposeDefensiveAction({
      agentId: targetAgentId,
      incidentId: selectedIncident?.id,
      actionType: proposalActionType,
      targetDetail: proposalTarget,
      rationale: proposalRationale,
    });
    setProposalTarget('');
    setProposalRationale('');
  };

  const tabs: Array<{
    id: SentinelTab;
    label: string;
    badge?: number;
    icon: React.ComponentType<{ className?: string }>;
  }> = [
    { id: 'fleet', label: 'Fleet & Health', badge: agents.length, icon: Server },
    { id: 'alerts', label: 'Alerts & Correlation', badge: regionalFindings.length, icon: Activity },
    { id: 'incidents', label: 'Incidents & GOD Brain', badge: openIncidents, icon: BrainCircuit },
    { id: 'topology', label: 'Network Topology', icon: Network },
    { id: 'approvals', label: 'Approvals & Audit', badge: pendingApprovals, icon: ShieldCheck },
    { id: 'enroll', label: 'Enroll & Deploy', icon: KeyRound },
  ];

  const activeTokenPlain = lastIssuedPlainToken?.plainToken || 'gsen_YOUR_SINGLE_USE_TOKEN';
  const activeTokenRegion = lastIssuedPlainToken?.region || tokenRegion;
  const isLocalHttp = controllerOrigin.startsWith('http://localhost') || controllerOrigin.startsWith('http://127.0.0.1');
  const localFlag = isLocalHttp ? ' --allow-insecure-localhost' : '';

  const linuxEnrollCmd = `python3 sentinel-agent/god_sentinel_agent.py --controller ${controllerOrigin}${localFlag} --region ${activeTokenRegion} --enroll ${activeTokenPlain} --once`;
  const linuxDrillCmd = `python3 sentinel-agent/god_sentinel_agent.py --controller ${controllerOrigin}${localFlag} --simulate-suspicious`;
  const goAgentCmd = `cd sentinel-agent && go run SentinelAgent.go --controller ${controllerOrigin}${localFlag} --region ${activeTokenRegion} --enroll ${activeTokenPlain} --interval 15`;
  const goFirestoreCmd = `cd sentinel-agent && go run SentinelAgent.go --controller ${controllerOrigin}${localFlag} --firestore-project YOUR_PROJECT_ID --firestore-db ai-studio-584e6f80-ce9a-45a2-a4f1-448c9c721cfd --firestore-uid YOUR_UID --firestore-token "$FIREBASE_ID_TOKEN"`;
  const windowsEnrollCmd = `python sentinel-agent\\god_sentinel_agent.py --controller ${controllerOrigin}${localFlag} --region ${activeTokenRegion} --enroll ${activeTokenPlain} --once`;

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-white/[0.08] pb-5">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight text-white font-display">
              GOD SENTINEL v{SENTINEL_VERSION}
            </h1>
            <span className="px-2 py-0.5 text-[11px] font-mono uppercase tracking-wider rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 whitespace-nowrap shrink-0">
              Defensive Only
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Distributed authorized server monitoring, regional correlation, Gemini MITRE ATT&amp;CK investigation, and human-approved containment.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => void runMilestoneOneDrill()}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            <span>
              {busyAction === 'milestone_drill'
                ? 'Running Milestone 1 Drill...'
                : 'Run Milestone 1 Drill'}
            </span>
          </button>
          <button
            type="button"
            onClick={() => void refreshOverview()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#121722] hover:bg-[#192030] border border-white/[0.08] text-slate-300 text-xs font-medium transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Honest Operational Status Banner */}
      <div
        role="status"
        className={`px-4 py-2.5 rounded-xl border text-xs flex flex-wrap items-center justify-between gap-2 ${
          isLiveMode
            ? 'bg-emerald-950/20 border-emerald-500/25 text-emerald-200'
            : 'bg-amber-950/25 border-amber-500/30 text-amber-200'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
          <span
            className={`px-2 py-0.5 rounded font-mono text-[10px] uppercase font-semibold whitespace-nowrap shrink-0 self-start sm:self-auto ${
              isLiveMode
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                : 'bg-amber-500/20 text-amber-300 border border-amber-500/35'
            }`}
          >
            {isLiveMode ? 'LIVE TELEMETRY ONLY' : 'SYNTHETIC DEMO MODE'}
          </span>
          <span>
            {isLiveMode
              ? 'Zero fabricated hosts: servers appear online strictly after authenticated enrollment and a verified heartbeat. Optional drills are explicitly tagged SYNTHETIC DEMO.'
              : 'Preview Session displays clearly labeled synthetic demonstration servers, heartbeats, and findings. Sign in with Google to enroll real Linux/Windows agents.'}
          </span>
        </div>
        <span className="font-mono text-[11px] opacity-80">
          Real hosts: {agents.filter((a) => a.dataOrigin !== 'synthetic_demo').length} · Demo:{' '}
          {agents.filter((a) => a.dataOrigin === 'synthetic_demo').length}
        </span>
      </div>

      {/* Error Alert Banner */}
      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-500/30 text-sm text-red-200 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            type="button"
            onClick={clearError}
            aria-label="Dismiss error"
            className="p-1 text-red-300 hover:text-white cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-[#0e121b] border border-white/[0.08]">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Enrolled Servers</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-white tabular-nums">{agents.length}</p>
          <p className="mt-0.5 text-[11px] font-mono text-slate-500">
            {agents.filter((a) => a.osType === 'linux').length} Linux ·{' '}
            {agents.filter((a) => a.osType === 'windows').length} Windows
          </p>
        </div>

        <div className="p-4 rounded-xl bg-[#0e121b] border border-white/[0.08]">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Live Heartbeats</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-white tabular-nums">{onlineAgents}</p>
          <p className="mt-0.5 text-[11px] font-mono text-slate-500">
            {queueMetrics.totalDeduplicated} deduped · {events.length} events
          </p>
        </div>

        <div className="p-4 rounded-xl bg-[#0e121b] border border-white/[0.08]">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Active Incidents</span>
            <ShieldAlert className="w-4 h-4 text-orange-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-white tabular-nums">{openIncidents}</p>
          <p className="mt-0.5 text-[11px] font-mono text-slate-500">
            {regionalFindings.length} regional correlation alert(s)
          </p>
        </div>

        <div className="p-4 rounded-xl bg-[#0e121b] border border-white/[0.08]">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Pending Human Approvals</span>
            <Lock className="w-4 h-4 text-amber-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-white tabular-nums">{pendingApprovals}</p>
          <p className="mt-0.5 text-[11px] font-mono text-slate-500">
            Zero auto-destructive actions
          </p>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex flex-wrap gap-1.5 border-b border-white/[0.08] pb-3">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                isActive
                  ? 'bg-blue-600/15 text-white border border-blue-500/35'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.04] border border-transparent'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
              <span>{tab.label}</span>
              {typeof tab.badge === 'number' && tab.badge > 0 && (
                <span className="px-1.5 py-0.2 rounded bg-white/[0.08] text-[10px] font-mono text-slate-200 tabular-nums">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* TAB 1: FLEET & HEALTH */}
      {activeTab === 'fleet' && (
        <div className="space-y-5">
          {/* Real-Time 5-Minute Heartbeat Pulse Chart */}
          <SentinelHeartbeatChart
            agents={agents}
            heartbeats={heartbeatHistory}
            isAuthenticated={isLiveMode}
            busyAction={busyAction}
            onSendFirestorePing={sendFirestoreHeartbeatPing}
          />

          <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] overflow-hidden">
            <div className="px-4 py-3 border-b border-white/[0.06] flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-white">Authorized Server Inventory</h2>
              <span className="text-xs font-mono text-slate-500">
                Least-privilege telemetry · Per-device SHA-256 auth
              </span>
            </div>

            {agents.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-400">
                No enrolled Sentinel agents yet. Open <strong>Enroll &amp; Deploy</strong> to connect your first real Linux or Windows server, or click{' '}
                <strong>Run Milestone 1 Drill</strong> to run a clearly labeled synthetic verification drill.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0a0d14] text-slate-400 border-b border-white/[0.06]">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Server &amp; OS</th>
                      <th className="px-4 py-2.5 font-medium">Status &amp; Heartbeat</th>
                      <th className="px-4 py-2.5 font-medium">CPU / RAM / Disk</th>
                      <th className="px-4 py-2.5 font-medium">Version &amp; Limits</th>
                      <th className="px-4 py-2.5 font-medium">Services</th>
                      <th className="px-4 py-2.5 font-medium text-right">Governance</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.05]">
                    {agents.map((agent) => {
                      const needsUpdate = agent.agentVersion !== SENTINEL_VERSION;
                      const isDemo = agent.dataOrigin === 'synthetic_demo';
                      return (
                        <tr key={agent.id} className="hover:bg-white/[0.02]">
                          <td className="px-4 py-3 align-top">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="font-semibold text-white">{agent.hostname}</span>
                              <span
                                className={`px-1.5 py-0.2 rounded text-[9px] font-mono uppercase border ${
                                  isDemo
                                    ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                    : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                }`}
                              >
                                {isDemo ? 'SYNTHETIC DEMO' : 'REAL AGENT'}
                              </span>
                            </div>
                            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                              {agent.ipAddress} · {agent.region}
                            </div>
                            <div className="text-[11px] text-slate-500 mt-0.5">
                              {agent.osType.toUpperCase()} · {agent.osVersion}
                            </div>
                          </td>

                          <td className="px-4 py-3 align-top">
                            <span
                              className={`inline-block px-2 py-0.5 rounded border text-[11px] font-mono uppercase ${agentStatusClass(
                                agent.status
                              )}`}
                            >
                              {agent.status}
                            </span>
                            <div className="text-[11px] font-mono text-slate-500 mt-1 flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {formatRelativeTime(agent.lastHeartbeatAt)}
                            </div>
                          </td>

                          <td className="px-4 py-3 align-top min-w-[170px] space-y-1.5">
                            {[
                              { label: 'CPU', val: agent.cpuPercent },
                              { label: 'RAM', val: agent.ramPercent },
                              { label: 'DSK', val: agent.diskPercent },
                            ].map((m) => (
                              <div key={m.label} className="flex items-center gap-2">
                                <span className="w-7 text-[10px] font-mono text-slate-400">
                                  {m.label}
                                </span>
                                <div className="flex-1 h-1.5 rounded bg-slate-800 overflow-hidden">
                                  <div
                                    className={`h-full ${
                                      m.val >= 85
                                        ? 'bg-red-500'
                                        : m.val >= 65
                                          ? 'bg-amber-400'
                                          : 'bg-emerald-400'
                                    }`}
                                    style={{ width: `${Math.min(100, m.val)}%` }}
                                  />
                                </div>
                                <span className="w-8 text-right text-[10px] font-mono text-slate-300 tabular-nums">
                                  {m.val}%
                                </span>
                              </div>
                            ))}
                          </td>

                          <td className="px-4 py-3 align-top font-mono text-[11px]">
                            <div className="text-slate-200">
                              v{agent.agentVersion}{' '}
                              {needsUpdate && (
                                <span className="text-amber-300">→ v{agent.targetVersion}</span>
                              )}
                            </div>
                            <div className="text-slate-500 mt-1">
                              Cap: {agent.resourceLimits.maxCpuPercent}% CPU ·{' '}
                              {agent.resourceLimits.maxMemoryMb}MB RAM
                            </div>
                            <div className="text-slate-500">
                              Rate: {agent.resourceLimits.maxEventsPerMinute}/min
                            </div>
                          </td>

                          <td className="px-4 py-3 align-top">
                            <div className="flex flex-wrap gap-1 max-w-[180px]">
                              {agent.services.length === 0 ? (
                                <span className="text-slate-500">—</span>
                              ) : (
                                agent.services.slice(0, 4).map((svc) => (
                                  <span
                                    key={svc.name}
                                    className="px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] font-mono text-[10px] text-slate-300"
                                  >
                                    {svc.name}
                                  </span>
                                ))
                              )}
                            </div>
                          </td>

                          <td className="px-4 py-3 align-top text-right">
                            <div className="inline-flex flex-wrap justify-end gap-1.5">
                              {needsUpdate && agent.status !== 'revoked' && (
                                <button
                                  type="button"
                                  onClick={() =>
                                    void updateAgentPolicy(agent.id, {
                                      targetVersion: SENTINEL_VERSION,
                                    })
                                  }
                                  disabled={busyAction !== null}
                                  className="px-2 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 text-blue-300 text-[11px] font-medium cursor-pointer"
                                >
                                  Update v{SENTINEL_VERSION}
                                </button>
                              )}
                              {agent.status !== 'revoked' && (
                                <button
                                  type="button"
                                  onClick={() => {
                                    setProposalAgentId(agent.id);
                                    setProposalActionType('isolate_server');
                                    setProposalTarget(
                                      `Quarantine ${agent.hostname} (${agent.ipAddress}) to management VLAN`
                                    );
                                    setProposalRationale(
                                      'Operator requested precautionary containment pending forensic inspection.'
                                    );
                                    setActiveTab('approvals');
                                  }}
                                  className="px-2 py-1 rounded bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 text-[11px] font-medium cursor-pointer"
                                >
                                  Propose Isolation
                                </button>
                              )}
                              {agent.status !== 'revoked' && (
                                <button
                                  type="button"
                                  onClick={() => void revokeAgent(agent.id)}
                                  disabled={busyAction !== null}
                                  className="px-2 py-1 rounded bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-300 text-[11px] font-medium cursor-pointer"
                                >
                                  Revoke
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: ALERTS & CORRELATION */}
      {activeTab === 'alerts' && (
        <div className="space-y-5">
          {/* Regional Intelligence Panel */}
          <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  Regional Intelligence Correlation
                </h2>
                <p className="text-xs text-slate-400">
                  Cross-server detection for lateral movement, unusual auth sprays, suspicious process+egress chains, and critical FIM drift.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void runRegionalCorrelation()}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer"
              >
                <BrainCircuit className="w-3.5 h-3.5" />
                <span>
                  {busyAction === 'correlate' ? 'Correlating...' : 'Run Regional Correlation'}
                </span>
              </button>
            </div>

            {regionalFindings.length === 0 ? (
              <p className="text-xs text-slate-500 py-3">
                No cross-server anomalies detected in the active telemetry window.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {regionalFindings.map((finding, idx) => (
                  <div
                    key={`${finding.correlationType}-${idx}`}
                    className="p-3.5 rounded-lg bg-[#0a0d14] border border-white/[0.08] space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`px-2 py-0.5 rounded border text-[10px] font-mono uppercase ${severityBadgeClass(
                          finding.severity
                        )}`}
                      >
                        {finding.severity} · {finding.correlationType.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[11px] font-mono text-slate-500">
                        {finding.region}
                      </span>
                    </div>
                    <h3 className="text-sm font-semibold text-white">{finding.title}</h3>
                    <p className="text-xs text-slate-400">{finding.summary}</p>
                    {finding.mitreTechniques.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {finding.mitreTechniques.map((m) => (
                          <span
                            key={m.techniqueId}
                            className="px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/25 text-[10px] font-mono text-blue-300"
                          >
                            {m.techniqueId} · {m.tactic}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Cross-Server Attack Timeline */}
          <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-white">Cross-Server Attack Timeline</h2>
                <p className="text-xs text-slate-400">
                  Chronological sequence of suspicious telemetry correlated across enrolled regional hosts.
                </p>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                {crossServerAttackTimeline.length} suspicious event(s)
              </span>
            </div>
            {crossServerAttackTimeline.length === 0 ? (
              <p className="text-xs text-slate-500 py-2">
                No suspicious cross-server activity recorded in the current window.
              </p>
            ) : (
              <ol className="space-y-2 border-l border-blue-500/30 pl-4">
                {crossServerAttackTimeline.map((ev) => {
                  const isDemo =
                    ev.provenance.dataOrigin === 'synthetic_demo' || ev.provenance.simulatedDrill;
                  return (
                    <li key={`tl-${ev.id}`} className="text-xs space-y-0.5">
                      <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                        <span className="text-slate-400">
                          {new Date(ev.observedAt).toLocaleTimeString()}
                        </span>
                        <span className="text-white font-semibold">{ev.hostname}</span>
                        <span className="text-slate-500">({ev.region})</span>
                        <span
                          className={`px-1.5 py-0.2 rounded border text-[10px] uppercase ${severityBadgeClass(
                            ev.severity
                          )}`}
                        >
                          {ev.severity} · {ev.eventType}
                        </span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[9px] uppercase ${
                            isDemo
                              ? 'bg-amber-500/15 text-amber-300'
                              : 'bg-emerald-500/15 text-emerald-300'
                          }`}
                        >
                          {isDemo ? 'SYNTHETIC DEMO' : 'REAL TELEMETRY'}
                        </span>
                      </div>
                      <p className="text-slate-300">{ev.summary}</p>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>

          {/* Evidence Repository & Normalized Event Pipeline Feed */}
          <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] overflow-hidden">
            <div className="px-4 py-3 border-b border-white/[0.06] flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  Evidence Repository &amp; Normalized Pipeline
                </h2>
                <p className="text-[11px] font-mono text-slate-500">
                  Received: {queueMetrics.totalReceived} · Deduplicated:{' '}
                  {queueMetrics.totalDeduplicated} · Stored: {events.length}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex flex-wrap gap-1" role="group" aria-label="Filter evidence by data origin">
                  {(
                    [
                      { id: 'all', label: 'All Origins' },
                      { id: 'real_telemetry', label: 'Real Only' },
                      { id: 'synthetic_demo', label: 'Synthetic Demo' },
                    ] as const
                  ).map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setOriginFilter(opt.id)}
                      className={`px-2 py-1 rounded text-[10px] font-mono uppercase cursor-pointer ${
                        originFilter === opt.id
                          ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/35'
                          : 'bg-[#0a0d14] text-slate-400 border border-white/[0.06] hover:text-white'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap gap-1" role="group" aria-label="Filter evidence by event type">
                  {(['all', 'auth', 'process', 'network', 'fim', 'log'] as const).map((type) => (
                    <button
                      key={type}
                      type="button"
                      onClick={() => setEventFilter(type)}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono uppercase cursor-pointer ${
                        eventFilter === type
                          ? 'bg-blue-600/20 text-blue-300 border border-blue-500/35'
                          : 'bg-[#0a0d14] text-slate-400 border border-white/[0.06] hover:text-white'
                      }`}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="divide-y divide-white/[0.05]">
              {filteredEvents.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">
                  No telemetry events match the selected origin/type filter.
                </div>
              ) : (
                filteredEvents.slice(0, 35).map((ev) => {
                  const isDemo =
                    ev.provenance.dataOrigin === 'synthetic_demo' || ev.provenance.simulatedDrill;
                  return (
                    <div key={ev.id} className="px-4 py-3 hover:bg-white/[0.02] space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase ${severityBadgeClass(
                              ev.severity
                            )}`}
                          >
                            {ev.severity}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-white/[0.05] text-[10px] font-mono uppercase text-slate-300">
                            {ev.eventType}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded border text-[9px] font-mono uppercase ${
                              isDemo
                                ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            }`}
                          >
                            {isDemo ? 'SYNTHETIC DEMO' : 'REAL TELEMETRY'}
                          </span>
                          <span className="text-xs font-semibold text-white">{ev.hostname}</span>
                          <span className="text-[11px] font-mono text-slate-500">{ev.region}</span>
                          {ev.occurrenceCount > 1 && (
                            <span className="px-1.5 py-0.5 rounded bg-indigo-500/15 border border-indigo-500/30 text-[10px] font-mono text-indigo-300 tabular-nums">
                              deduped ×{ev.occurrenceCount}
                            </span>
                          )}
                          {ev.provenance.bufferedOffline && (
                            <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-[10px] font-mono text-amber-300">
                              offline-replay #{ev.provenance.retryAttempt}
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] font-mono text-slate-500">
                          {formatRelativeTime(ev.observedAt)} · {ev.provenance.collector}
                        </span>
                      </div>
                      <p className="text-xs text-slate-200">{ev.summary}</p>
                      <p className="text-[11px] font-mono text-slate-500 truncate">
                        id:{ev.id} · fp:{ev.fingerprint} · payload:{JSON.stringify(ev.payload)}
                      </p>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: INCIDENTS & GOD CENTRAL BRAIN (10 PLAYBOOKS) */}
      {activeTab === 'incidents' && (
        <div className="space-y-5">
          {/* 10 GOD Investigator Playbooks Bar */}
          <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-blue-400 shrink-0" />
                <div>
                  <h2 className="text-sm font-semibold text-white">
                    GOD Investigator Playbooks (10 Defensive Scenarios)
                  </h2>
                  <p className="text-xs text-slate-400">
                    Every investigation cites exact telemetry IDs and separates Confirmed Facts, Hypotheses, and Unknowns.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => void runBrainInvestigation({ playbookId: selectedPlaybookId })}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold shrink-0 cursor-pointer"
              >
                <BrainCircuit className="w-3.5 h-3.5" />
                <span>
                  {busyAction === 'investigate'
                    ? 'Running Playbook...'
                    : 'Run Selected Playbook'}
                </span>
              </button>
            </div>

            <div
              role="group"
              aria-label="Select defensive investigation playbook"
              className="flex flex-wrap gap-1.5"
            >
              {SENTINEL_INVESTIGATION_PLAYBOOKS.map((pb) => {
                const isSel = pb.id === selectedPlaybookId;
                return (
                  <button
                    key={pb.id}
                    type="button"
                    aria-pressed={isSel}
                    onClick={() => setSelectedPlaybookId(pb.id)}
                    className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                      isSel
                        ? 'bg-blue-600/20 text-white border border-blue-500/45'
                        : 'bg-[#0a0d14] text-slate-400 hover:text-white border border-white/[0.07]'
                    }`}
                  >
                    {pb.name}
                  </button>
                );
              })}
            </div>

            <div className="p-3 rounded-lg bg-[#0a0d14] border border-white/[0.06] grid grid-cols-1 md:grid-cols-12 gap-3 text-xs">
              <div className="md:col-span-7 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-white">{activePlaybook.name}</span>
                  <span className="text-[10px] font-mono uppercase text-slate-400">
                    {activePlaybook.category}
                  </span>
                  {activePlaybook.mitreTechniques.map((t) => (
                    <span
                      key={t}
                      className="px-1.5 py-0.2 rounded bg-blue-500/15 border border-blue-500/30 font-mono text-[10px] text-blue-300"
                    >
                      {t}
                    </span>
                  ))}
                </div>
                <p className="text-slate-400">{activePlaybook.summary}</p>
              </div>
              <div className="md:col-span-5 space-y-1 border-t md:border-t-0 md:border-l border-white/[0.06] pt-2 md:pt-0 md:pl-3">
                <p className="text-[10px] font-mono uppercase text-slate-500">Key Telemetry Signals</p>
                <ul className="text-[11px] text-slate-300 list-disc list-inside space-y-0.5">
                  {activePlaybook.telemetrySignals.slice(0, 2).map((sig, i) => (
                    <li key={i}>{sig}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Incident List */}
            <div className="lg:col-span-4 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-white">Incident Cases</h2>
                <button
                  type="button"
                  onClick={() => void runBrainInvestigation({ playbookId: selectedPlaybookId })}
                  disabled={busyAction !== null}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#151c2c] hover:bg-[#1c253a] border border-blue-500/30 disabled:opacity-50 text-blue-300 text-xs font-semibold cursor-pointer"
                >
                  <BrainCircuit className="w-3.5 h-3.5" />
                  <span>
                    {busyAction === 'investigate' ? 'Analyzing...' : 'New Gemini Investigation'}
                  </span>
                </button>
              </div>

              {incidents.length === 0 ? (
                <div className="p-5 rounded-xl bg-[#0e121b] border border-white/[0.08] text-xs text-slate-400">
                  No incident cases recorded yet. Connect a real Linux agent or run the Milestone 1 drill, then launch a Playbook Investigation.
                </div>
              ) : (
                <div className="space-y-2">
                  {incidents.map((inc) => {
                    const active = selectedIncident?.id === inc.id;
                    const isDemo = inc.dataOrigin === 'synthetic_demo';
                    return (
                      <button
                        key={inc.id}
                        type="button"
                        onClick={() => setSelectedIncidentId(inc.id)}
                        className={`w-full text-left p-3.5 rounded-xl border transition-colors cursor-pointer ${
                          active
                            ? 'bg-blue-600/10 border-blue-500/40'
                            : 'bg-[#0e121b] border-white/[0.08] hover:border-white/[0.18]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase ${severityBadgeClass(
                                inc.severity
                              )}`}
                            >
                              {inc.severity}
                            </span>
                            {isDemo && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-[9px] font-mono uppercase text-amber-300">
                                DEMO
                              </span>
                            )}
                          </div>
                          <span className="text-[11px] font-mono text-slate-500">
                            {inc.confidenceScore}% conf
                          </span>
                        </div>
                        <p className="mt-2 text-xs font-semibold text-white line-clamp-2">
                          {inc.title}
                        </p>
                        <p className="mt-1 text-[11px] font-mono text-slate-500">
                          {inc.region} · {inc.mitreTechniques.length} ATT&amp;CK ·{' '}
                          {formatRelativeTime(inc.updatedAt)}
                        </p>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Investigation Detail Workspace */}
            <div className="lg:col-span-8">
              {!selectedIncident ? (
                <div className="p-8 rounded-xl bg-[#0e121b] border border-white/[0.08] text-center text-sm text-slate-500">
                  Select an incident case to inspect GOD Central Brain reasoning, Confirmed Facts, Hypotheses, Unknowns, MITRE ATT&amp;CK mappings, and timeline.
                </div>
              ) : (
                <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-5 space-y-5">
                  <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/[0.06] pb-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded border text-[11px] font-mono uppercase ${severityBadgeClass(
                            selectedIncident.severity
                          )}`}
                        >
                          {selectedIncident.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-white/[0.06] text-[11px] font-mono uppercase text-slate-300">
                          {selectedIncident.status}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded border text-[10px] font-mono uppercase ${
                            selectedIncident.dataOrigin === 'synthetic_demo'
                              ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                              : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                          }`}
                        >
                          {selectedIncident.dataOrigin === 'synthetic_demo'
                            ? 'SYNTHETIC DEMO'
                            : 'REAL TELEMETRY'}
                        </span>
                        {selectedIncident.playbookId && (
                          <span className="px-2 py-0.5 rounded bg-blue-500/15 border border-blue-500/30 text-[10px] font-mono uppercase text-blue-300">
                            Playbook: {selectedIncident.playbookId.replace(/_/g, ' ')}
                          </span>
                        )}
                        <span className="text-xs font-mono text-slate-500">
                          Confidence {selectedIncident.confidenceScore}% · {selectedIncident.region}
                        </span>
                      </div>
                      <h2 className="mt-2 text-lg font-bold text-white">{selectedIncident.title}</h2>
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        void runBrainInvestigation({
                          incidentId: selectedIncident.id,
                          playbookId: selectedPlaybookId,
                        })
                      }
                      disabled={busyAction !== null}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#151c2c] hover:bg-[#1c253a] border border-blue-500/30 text-blue-300 text-xs font-semibold cursor-pointer"
                    >
                      <BrainCircuit className="w-3.5 h-3.5" />
                      <span>
                        {busyAction === 'investigate'
                          ? 'Re-analyzing...'
                          : 'Re-Run Gemini Investigation'}
                      </span>
                    </button>
                  </div>

                  {/* Confirmed Facts (Cited Telemetry Evidence) */}
                  <div className="p-3.5 rounded-lg bg-emerald-950/15 border border-emerald-500/25 space-y-2">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      <h3 className="text-xs font-mono uppercase tracking-wider text-emerald-300">
                        Confirmed Facts (Cited Telemetry Evidence)
                      </h3>
                    </div>
                    <ul className="text-xs text-slate-200 space-y-1 list-disc list-inside">
                      {(selectedIncident.confirmedFacts && selectedIncident.confirmedFacts.length > 0
                        ? selectedIncident.confirmedFacts
                        : selectedIncident.timeline.map(
                            (t) =>
                              `[${t.eventId || t.eventType}] ${t.hostname}: ${t.description}`
                          )
                      ).map((fact, idx) => (
                        <li key={idx}>{fact}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Evidence-Based Hypotheses */}
                  <div className="space-y-2">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                      Evidence-Based Hypotheses (Not Yet Proven)
                    </h3>
                    <div className="space-y-2">
                      {selectedIncident.hypotheses.map((hyp) => (
                        <div
                          key={hyp.id}
                          className="p-3.5 rounded-lg bg-[#0a0d14] border border-white/[0.07] space-y-2"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-semibold text-white">{hyp.title}</span>
                            <span
                              className={`px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase ${
                                hyp.likelihood === 'high'
                                  ? 'bg-red-500/15 text-red-300 border-red-500/30'
                                  : hyp.likelihood === 'medium'
                                    ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                    : 'bg-slate-500/15 text-slate-300 border-slate-500/30'
                              }`}
                            >
                              {hyp.likelihood} likelihood
                            </span>
                          </div>
                          <ul className="text-[11px] text-slate-300 space-y-1 list-disc list-inside">
                            {hyp.supportingEvidence.map((item, i) => (
                              <li key={i}>{item}</li>
                            ))}
                          </ul>
                          {hyp.refutingOrGaps.length > 0 && (
                            <p className="text-[11px] text-slate-500">
                              <strong>Verification gaps:</strong> {hyp.refutingOrGaps.join(' ')}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Unknowns & Verification Gaps */}
                  <div className="p-3.5 rounded-lg bg-amber-950/15 border border-amber-500/25 space-y-2">
                    <div className="flex items-center gap-2">
                      <HelpCircle className="w-4 h-4 text-amber-400 shrink-0" />
                      <h3 className="text-xs font-mono uppercase tracking-wider text-amber-300">
                        Unknowns &amp; Operator Verification Checklist
                      </h3>
                    </div>
                    <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                      {(selectedIncident.unknowns && selectedIncident.unknowns.length > 0
                        ? selectedIncident.unknowns
                        : [
                            'Metadata-only Sentinel agents do not capture packet payloads or file contents; verify host-level artifacts before containment.',
                          ]
                      ).map((gap, idx) => (
                        <li key={idx}>{gap}</li>
                      ))}
                    </ul>
                  </div>

                  {/* MITRE ATT&CK Mappings */}
                  <div className="space-y-2">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                      MITRE ATT&amp;CK Technique Mapping
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      {selectedIncident.mitreTechniques.map((m) => (
                        <div
                          key={m.techniqueId}
                          className="p-3 rounded-lg bg-[#0a0d14] border border-white/[0.07]"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-bold text-blue-300">
                              {m.techniqueId} · {m.tactic}
                            </span>
                            <span className="text-[11px] font-mono text-slate-400 tabular-nums">
                              {m.confidence}%
                            </span>
                          </div>
                          <p className="text-xs font-semibold text-white mt-1">{m.name}</p>
                          <p className="text-[11px] text-slate-400 mt-1">{m.evidenceSummary}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Chronological Timeline */}
                  <div className="space-y-2">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                      Incident Timeline
                    </h3>
                    <div className="space-y-1.5 border-l border-white/[0.1] pl-3.5">
                      {selectedIncident.timeline.map((entry, idx) => (
                        <div key={idx} className="text-xs">
                          <span className="font-mono text-[11px] text-slate-500">
                            {new Date(entry.timestamp).toLocaleTimeString()} · {entry.hostname} ·{' '}
                            {entry.eventType.toUpperCase()}
                          </span>
                          <p className="text-slate-200">{entry.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Investigation Markdown Report */}
                  <div className="space-y-2 pt-2 border-t border-white/[0.06]">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                      Central Brain Technical Report
                    </h3>
                    <div className="prose prose-invert prose-sm max-w-none text-slate-300 bg-[#0a0d14] p-4 rounded-lg border border-white/[0.07]">
                      <Markdown remarkPlugins={[remarkGfm]}>
                        {selectedIncident.investigationReport}
                      </Markdown>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: NETWORK TOPOLOGY */}
      {activeTab === 'topology' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-8 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">
                Multi-Region Server &amp; Observed Peer Topology
              </h2>
              <span className="text-[11px] font-mono text-slate-500">
                {topology.nodes.length} nodes · {topology.edges.length} connections
              </span>
            </div>
            <SentinelTopologySvg
              nodes={topology.nodes}
              edges={topology.edges}
              selectedNodeId={selectedTopoNode?.id || null}
              onSelectNode={setSelectedTopologyNodeId}
            />
          </div>

          <div className="lg:col-span-4 rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-3">
            <h3 className="text-sm font-semibold text-white">Node Inspector</h3>
            {!selectedTopoNode ? (
              <p className="text-xs text-slate-500">Click any node in the topology map to inspect.</p>
            ) : (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-[#0a0d14] border border-white/[0.07] space-y-1">
                  <div className="text-sm font-bold text-white">{selectedTopoNode.label}</div>
                  <div className="font-mono text-[11px] text-slate-400">
                    IP: {selectedTopoNode.ipAddress} · Region: {selectedTopoNode.region}
                  </div>
                  <div className="font-mono text-[11px] text-slate-400">
                    Type: {selectedTopoNode.kind === 'agent' ? `Enrolled ${selectedTopoNode.osType?.toUpperCase()}` : 'Observed External Peer'}
                  </div>
                  <div className="font-mono text-[11px] text-slate-300">
                    Status: <span className="uppercase">{selectedTopoNode.status}</span> · High Alerts:{' '}
                    {selectedTopoNode.alertCount}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <p className="text-[11px] font-mono uppercase text-slate-500">
                    Connected Edges
                  </p>
                  {topology.edges
                    .filter(
                      (e) => e.source === selectedTopoNode.id || e.target === selectedTopoNode.id
                    )
                    .map((e) => (
                      <div
                        key={e.id}
                        className={`p-2 rounded border font-mono text-[11px] ${
                          e.suspicious
                            ? 'bg-red-950/30 border-red-500/30 text-red-200'
                            : 'bg-[#0a0d14] border-white/[0.06] text-slate-300'
                        }`}
                      >
                        {e.source} → {e.target} ({e.label})
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: HUMAN APPROVALS & AUDIT LOG */}
      {activeTab === 'approvals' && (
        <div className="space-y-5">
          {/* Safety Guarantee Banner */}
          <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/25 flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-300 space-y-1">
              <p className="font-semibold text-white">
                Human-Approval Containment Boundary Enforced
              </p>
              <p>
                GOD SENTINEL never auto-isolates servers, auto-kills processes, or auto-mutates firewalls. Unrestricted remote shells and destructive disk operations are rejected at both the policy layer and the micro-agent. Every decision is recorded in the audit trail.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Propose Bounded Defensive Action */}
            <form
              onSubmit={handleProposeAction}
              className="lg:col-span-5 rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-3.5"
            >
              <h2 className="text-sm font-semibold text-white">Propose Defensive Action</h2>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Target Enrolled Server</label>
                <select
                  value={proposalAgentId || agents[0]?.id || ''}
                  onChange={(e) => setProposalAgentId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white"
                >
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.hostname} ({a.region} · {a.status})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Action Type (Bounded)</label>
                <select
                  value={proposalActionType}
                  onChange={(e) => setProposalActionType(e.target.value as DefensiveActionType)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white"
                >
                  <option value="isolate_server">Isolate Server (Quarantine)</option>
                  <option value="terminate_process">Terminate Process (Specific PID)</option>
                  <option value="firewall_policy">Update Firewall Policy (Peer Block)</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Target Detail</label>
                <input
                  type="text"
                  required
                  value={proposalTarget}
                  onChange={(e) => setProposalTarget(e.target.value)}
                  placeholder="e.g., PID 44120 or Block peer 198.51.100.77 TCP/4444"
                  className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white placeholder:text-slate-600"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Evidence Rationale</label>
                <textarea
                  required
                  rows={3}
                  value={proposalRationale}
                  onChange={(e) => setProposalRationale(e.target.value)}
                  placeholder="Cite correlated evidence event IDs and defensive reason..."
                  className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white placeholder:text-slate-600"
                />
              </div>

              <button
                type="submit"
                disabled={busyAction !== null || agents.length === 0}
                className="w-full py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer"
              >
                Queue for Human Approval
              </button>
            </form>

            {/* Approval Queue */}
            <div className="lg:col-span-7 rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-3">
              <h2 className="text-sm font-semibold text-white">
                Human Approval Queue ({pendingApprovals} pending)
              </h2>

              {approvals.length === 0 ? (
                <p className="text-xs text-slate-500 py-4">No containment proposals queued.</p>
              ) : (
                <div className="space-y-3">
                  {approvals.map((act) => {
                    const host =
                      agents.find((a) => a.id === act.agentId)?.hostname || act.agentId;
                    const isPending = act.status === 'pending_approval';
                    return (
                      <div
                        key={act.id}
                        className="p-3.5 rounded-lg bg-[#0a0d14] border border-white/[0.08] space-y-2.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded bg-blue-500/15 border border-blue-500/30 text-[10px] font-mono uppercase text-blue-300">
                              {act.actionType.replace(/_/g, ' ')}
                            </span>
                            <span className="text-xs font-semibold text-white">{host}</span>
                          </div>
                          <span
                            className={`px-2 py-0.5 rounded border text-[10px] font-mono uppercase ${
                              isPending
                                ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                : act.status === 'approved'
                                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                  : 'bg-slate-600/20 text-slate-400 border-slate-600/40'
                            }`}
                          >
                            {act.status.replace(/_/g, ' ')}
                          </span>
                        </div>

                        <p className="text-xs font-mono text-slate-200">{act.targetDetail}</p>
                        <p className="text-xs text-slate-400">{act.rationale}</p>
                        <p className="text-[11px] font-mono text-slate-500">
                          Requested by {act.requestedBy} · {formatRelativeTime(act.requestedAt)}
                          {act.decidedBy ? ` · Decided by ${act.decidedBy}` : ''}
                        </p>

                        {isPending && (
                          <div className="pt-2 border-t border-white/[0.06] flex flex-col sm:flex-row gap-2">
                            <input
                              type="text"
                              value={decisionNotes[act.id] || ''}
                              onChange={(e) =>
                                setDecisionNotes((prev) => ({
                                  ...prev,
                                  [act.id]: e.target.value,
                                }))
                              }
                              placeholder="Optional audit note..."
                              className="flex-1 px-2.5 py-1.5 rounded bg-[#0e121b] border border-white/[0.08] text-xs text-white placeholder:text-slate-600"
                            />
                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() =>
                                  void decideApproval(
                                    act.id,
                                    'approved',
                                    decisionNotes[act.id] || 'Approved by operator'
                                  )
                                }
                                disabled={busyAction !== null}
                                className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold cursor-pointer"
                              >
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                <span>Approve</span>
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  void decideApproval(
                                    act.id,
                                    'rejected',
                                    decisionNotes[act.id] || 'Rejected by operator'
                                  )
                                }
                                disabled={busyAction !== null}
                                className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-red-600/20 hover:bg-red-600/35 border border-red-500/30 text-red-300 text-xs font-semibold cursor-pointer"
                              >
                                <XCircle className="w-3.5 h-3.5" />
                                <span>Reject</span>
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Administrative Audit Log */}
          <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] overflow-hidden">
            <div className="px-4 py-3 border-b border-white/[0.06] flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">Administrative Audit Trail</h2>
              <span className="text-[11px] font-mono text-slate-500">
                Every enrollment, policy update, and approval is logged
              </span>
            </div>
            <div className="divide-y divide-white/[0.05]">
              {auditLogs.slice(0, 25).map((log) => (
                <div
                  key={log.id}
                  className="px-4 py-2.5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 text-xs"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-blue-300">{log.action}</span>
                      <span className="text-slate-500">·</span>
                      <span className="font-mono text-[11px] text-slate-400">{log.actor}</span>
                    </div>
                    <p className="text-slate-300">{log.details}</p>
                  </div>
                  <span className="font-mono text-[11px] text-slate-500 shrink-0">
                    {formatRelativeTime(log.createdAt)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: ENROLL & DEPLOY */}
      {activeTab === 'enroll' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Issue Single-Use Token */}
          <div className="lg:col-span-5 space-y-4">
            <form
              onSubmit={handleIssueToken}
              className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-3.5"
            >
              <h2 className="text-sm font-semibold text-white">
                Issue Single-Use Enrollment Token
              </h2>
              <p className="text-xs text-slate-400">
                Only a SHA-256 hash is stored server-side. Upon enrollment, the token is invalidated and exchanged for a unique per-device credential.
              </p>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Server Label</label>
                <input
                  type="text"
                  required
                  value={tokenLabel}
                  onChange={(e) => setTokenLabel(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs text-slate-400">Region</label>
                  <select
                    value={tokenRegion}
                    onChange={(e) => setTokenRegion(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white"
                  >
                    <option value="asia-southeast1">asia-southeast1</option>
                    <option value="us-central1">us-central1</option>
                    <option value="eu-west1">eu-west1</option>
                    <option value="ap-northeast1">ap-northeast1</option>
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-slate-400">Operating System</label>
                  <select
                    value={tokenOs}
                    onChange={(e) => setTokenOs(e.target.value as SentinelOsType)}
                    className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white"
                  >
                    <option value="linux">Linux (systemd)</option>
                    <option value="windows">Windows Server</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Expiry (Hours)</label>
                <input
                  type="number"
                  min={1}
                  max={168}
                  value={tokenTtlHours}
                  onChange={(e) => setTokenTtlHours(Number(e.target.value) || 24)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.1] text-xs text-white tabular-nums"
                />
              </div>

              <button
                type="submit"
                disabled={busyAction !== null}
                className="w-full py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer"
              >
                {busyAction === 'issue_token' ? 'Issuing Token...' : 'Generate Enrollment Token'}
              </button>
            </form>

            {/* Issued Tokens Table */}
            <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-2.5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Enrollment Token Ledger
              </h3>
              {tokens.length === 0 ? (
                <p className="text-xs text-slate-500">No tokens issued yet.</p>
              ) : (
                <div className="space-y-2">
                  {tokens.slice(0, 8).map((tok) => {
                    const status = tok.revokedAt
                      ? 'revoked'
                      : tok.usedAt
                        ? 'used'
                        : new Date(tok.expiresAt).getTime() < Date.now()
                          ? 'expired'
                          : 'active';
                    return (
                      <div
                        key={tok.id}
                        className="p-2.5 rounded-lg bg-[#0a0d14] border border-white/[0.06] flex items-center justify-between gap-2 text-xs"
                      >
                        <div className="min-w-0">
                          <p className="font-semibold text-white truncate">{tok.label}</p>
                          <p className="font-mono text-[11px] text-slate-500">
                            {tok.tokenPrefix}... · {tok.osType} · {tok.region}
                          </p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="font-mono text-[10px] uppercase text-slate-400">
                            {status}
                          </span>
                          {status === 'active' && (
                            <button
                              type="button"
                              onClick={() => void revokeToken(tok.id)}
                              className="px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-300 text-[10px] cursor-pointer"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Agent Installation & Hardening Instructions */}
          <div className="lg:col-span-7 space-y-4">
            {lastIssuedPlainToken && (
              <div className="p-4 rounded-xl bg-emerald-950/25 border border-emerald-500/30 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-emerald-300">
                    One-Time Enrollment Token Ready (Copy Now)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copySnippet('plain_tok', lastIssuedPlainToken.plainToken)}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded bg-emerald-600/25 text-emerald-200 text-[11px] cursor-pointer"
                  >
                    {copiedKey === 'plain_tok' ? (
                      <Check className="w-3 h-3" />
                    ) : (
                      <ClipboardCopy className="w-3 h-3" />
                    )}
                    <span>{copiedKey === 'plain_tok' ? 'Copied' : 'Copy Token'}</span>
                  </button>
                </div>
                <code className="block p-2.5 rounded bg-[#080b12] font-mono text-xs text-emerald-200 break-all">
                  {lastIssuedPlainToken.plainToken}
                </code>
              </div>
            )}

            <div className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 space-y-4">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-blue-400" />
                <h2 className="text-sm font-semibold text-white">
                  Sentinel Micro-Agent Deployment (Linux &amp; Windows)
                </h2>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium">
                    1. Linux Authorized Enrollment (Python 3.9+ stdlib, zero external deps)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copySnippet('linux_enroll', linuxEnrollCmd)}
                    className="inline-flex items-center gap-1 text-[11px] text-blue-300 hover:text-white cursor-pointer"
                  >
                    {copiedKey === 'linux_enroll' ? (
                      <Check className="w-3 h-3" />
                    ) : (
                      <ClipboardCopy className="w-3 h-3" />
                    )}
                    <span>{copiedKey === 'linux_enroll' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 rounded-lg bg-[#080b12] border border-white/[0.06] text-[11px] font-mono text-slate-200 overflow-x-auto">
                  {linuxEnrollCmd}
                </pre>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium">
                    2. First Milestone Verification Drill (Simulated Suspicious Event Chain)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copySnippet('linux_drill', linuxDrillCmd)}
                    className="inline-flex items-center gap-1 text-[11px] text-blue-300 hover:text-white cursor-pointer"
                  >
                    {copiedKey === 'linux_drill' ? (
                      <Check className="w-3 h-3" />
                    ) : (
                      <ClipboardCopy className="w-3 h-3" />
                    )}
                    <span>{copiedKey === 'linux_drill' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 rounded-lg bg-[#080b12] border border-white/[0.06] text-[11px] font-mono text-slate-200 overflow-x-auto">
                  {linuxDrillCmd}
                </pre>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium">
                    3. Go Micro-Agent (<code>SentinelAgent.go</code> — HTTPS Controller + System Load Metrics)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copySnippet('go_enroll', goAgentCmd)}
                    className="inline-flex items-center gap-1 text-[11px] text-blue-300 hover:text-white cursor-pointer"
                  >
                    {copiedKey === 'go_enroll' ? (
                      <Check className="w-3 h-3" />
                    ) : (
                      <ClipboardCopy className="w-3 h-3" />
                    )}
                    <span>{copiedKey === 'go_enroll' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 rounded-lg bg-[#080b12] border border-white/[0.06] text-[11px] font-mono text-slate-200 overflow-x-auto">
                  {goAgentCmd}
                </pre>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium">
                    4. Go Agent Direct Firestore Heartbeat Stream (<code>users/&#123;uid&#125;/sentinelHeartbeats</code>)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copySnippet('go_fs', goFirestoreCmd)}
                    className="inline-flex items-center gap-1 text-[11px] text-blue-300 hover:text-white cursor-pointer"
                  >
                    {copiedKey === 'go_fs' ? (
                      <Check className="w-3 h-3" />
                    ) : (
                      <ClipboardCopy className="w-3 h-3" />
                    )}
                    <span>{copiedKey === 'go_fs' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 rounded-lg bg-[#080b12] border border-white/[0.06] text-[11px] font-mono text-slate-200 overflow-x-auto">
                  {goFirestoreCmd}
                </pre>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium">
                    5. Windows Server Enrollment (PowerShell)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copySnippet('win_enroll', windowsEnrollCmd)}
                    className="inline-flex items-center gap-1 text-[11px] text-blue-300 hover:text-white cursor-pointer"
                  >
                    {copiedKey === 'win_enroll' ? (
                      <Check className="w-3 h-3" />
                    ) : (
                      <ClipboardCopy className="w-3 h-3" />
                    )}
                    <span>{copiedKey === 'win_enroll' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 rounded-lg bg-[#080b12] border border-white/[0.06] text-[11px] font-mono text-slate-200 overflow-x-auto">
                  {windowsEnrollCmd}
                </pre>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-white/[0.06] text-xs">
                <div className="p-3 rounded-lg bg-[#0a0d14] border border-white/[0.06] space-y-1">
                  <div className="flex items-center gap-1.5 font-semibold text-white">
                    <Cpu className="w-3.5 h-3.5 text-blue-400" />
                    <span>Hardened Resource Limits</span>
                  </div>
                  <p className="text-slate-400 text-[11px]">
                    Default <code>systemd</code> unit enforces <code>MemoryMax=64M</code>,{' '}
                    <code>CPUQuota=5%</code>, <code>NoNewPrivileges=yes</code>, and{' '}
                    <code>ProtectSystem=strict</code> with durable offline JSONL retries.
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-[#0a0d14] border border-white/[0.06] space-y-1">
                  <div className="flex items-center gap-1.5 font-semibold text-white">
                    <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Least-Privilege Telemetry Scope</span>
                  </div>
                  <p className="text-slate-400 text-[11px]">
                    Collects CPU/RAM/disk/service health, process lifecycle, auth metadata, socket metadata, and SHA-256 FIM. Zero password/secret capture and zero remote shell.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
