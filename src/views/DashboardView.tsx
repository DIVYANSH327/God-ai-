import React, { useState } from 'react';
import {
  Activity,
  ArrowUpRight,
  BrainCircuit,
  CheckCircle2,
  Code2,
  GitCompareArrows,
  Globe,
  MessageSquarePlus,
  Network,
  Plus,
  Radar,
  Server,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import { useGodWorkspace } from '../context/GodWorkspaceContext';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import { useGriResearch } from '../context/GriResearchContext';
import { NeuralCoreOrb } from '../components/NeuralCoreOrb';
import { NetworkTopologySvg } from '../components/NetworkTopologySvg';
import { KnowledgeGraphSvg } from '../components/KnowledgeGraphSvg';
import { AGENT_REGISTRY, GOD_CORE_MODEL } from '../shared/godCoreLogic';
import { GRI_VERSION } from '../shared/griAnalytics';
import type { IntentCategory, TaskPriority, TaskStatus } from '../shared/types';

function formatRelativeTime(timestampMs: number): string {
  const diffSec = Math.max(0, Math.floor((Date.now() - timestampMs) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return new Date(timestampMs).toLocaleDateString();
}

export const DashboardView: React.FC = () => {
  const {
    profile,
    firebaseUser,
    systemInfo,
    conversations,
    tasks,
    auditEvents,
    isStreamingChat,
    setActiveSection,
    startNewConversation,
    createTask,
    updateTaskStatus,
    deleteTask,
  } = useGodWorkspace();

  const {
    networkAssets,
    researchReports,
    knowledgeNodes,
    knowledgeConflicts,
    behaviourInsights,
    brainPlan,
    isPlanningBrain,
    brainPlanError,
    generateCentralBrainPlan,
  } = useGinIntelligence();

  const {
    techAnalyses,
    cveAdvisories,
    researchMonitors,
    comparisonReport,
    isComparingSources,
    comparisonError,
    generateComparisonReport,
  } = useGriResearch();

  const [taskTitle, setTaskTitle] = useState('');
  const [taskCategory, setTaskCategory] = useState<IntentCategory>('research');
  const [taskPriority, setTaskPriority] = useState<TaskPriority>('medium');
  const [taskFormError, setTaskFormError] = useState<string | null>(null);
  const [submittingTask, setSubmittingTask] = useState(false);

  const [brainObjective, setBrainObjective] = useState('');
  const [comparisonTopic, setComparisonTopic] = useState('Edge Infrastructure, Web Stacks & Active CVE Mitigations');
  const [planStagedMessage, setPlanStagedMessage] = useState<string | null>(null);
  const [backdropFailed, setBackdropFailed] = useState(false);

  const operationalAgentsCount = AGENT_REGISTRY.filter((a) => a.status === 'operational').length;
  const prototypeAgentsCount = AGENT_REGISTRY.filter((a) => a.status === 'prototype').length;
  const plannedAgentsCount = AGENT_REGISTRY.filter((a) => a.status === 'planned').length;

  const anomalousAssetsCount = networkAssets.filter((a) => a.status === 'anomalous').length;
  const cisaKevCount = cveAdvisories.filter((c) => c.cisaKev).length;
  const activeMonitorsCount = researchMonitors.filter((m) => m.enabled).length;
  const totalCitationsCount =
    researchReports.reduce((sum, r) => sum + r.sources.length, 0) +
    techAnalyses.reduce((sum, t) => sum + t.sources.length, 0) +
    cveAdvisories.filter((c) => Boolean(c.sourceUri)).length;
  const activeTasksCount = tasks.filter(
    (t) => t.status === 'queued' || t.status === 'in_progress'
  ).length;
  const completedTasksCount = tasks.filter((t) => t.status === 'completed').length;

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    setTaskFormError(null);
    setSubmittingTask(true);
    try {
      const res = await createTask({
        title: taskTitle,
        category: taskCategory,
        priority: taskPriority,
      });
      if (!res.ok) {
        setTaskFormError(res.error || 'Please enter a valid task title.');
      } else {
        setTaskTitle('');
      }
    } finally {
      setSubmittingTask(false);
    }
  };

  const handleGeneratePlan = async (e: React.FormEvent) => {
    e.preventDefault();
    setPlanStagedMessage(null);
    await generateCentralBrainPlan(brainObjective);
  };

  const handleStagePlanSteps = async () => {
    if (!brainPlan) return;
    let staged = 0;
    for (const step of brainPlan.steps.slice(0, 4)) {
      const res = await createTask({
        title: `[${step.agentModule}] ${step.objective}`,
        category: step.agentModule.toLowerCase().includes('security') ? 'security' : 'research',
        priority: 'high',
      });
      if (res.ok) staged += 1;
    }
    setPlanStagedMessage(`Staged ${staged} Central Brain step(s) into your Operational Task Queue.`);
  };

  const nextStatusFor = (current: TaskStatus): TaskStatus => {
    if (current === 'queued') return 'in_progress';
    if (current === 'in_progress') return 'completed';
    return 'queued';
  };

  const coreStateLabel = profile.emergencyStop
    ? 'Halted — Emergency Stop Engaged'
    : profile.executionMode === 'local'
      ? 'Standby — Local Node Unpaired'
      : 'Nominal — GIN Central Brain Active';

  return (
    <div className="space-y-8">
      {/* GOD Live Command Center Identity & Neural Core Hero */}
      <section className="relative rounded-xl border border-white/[0.08] bg-[#0f131c] overflow-hidden p-6 lg:p-8">
        {!backdropFailed && (
          <img
            src="/src/assets/images/god_core_backdrop_1795262096906.jpg"
            alt="Obsidian command center backdrop"
            referrerPolicy="no-referrer"
            onError={() => setBackdropFailed(true)}
            className="absolute inset-0 w-full h-full object-cover opacity-20 pointer-events-none"
          />
        )}
        <div className="absolute inset-0 bg-gradient-to-r from-[#090b10]/95 via-[#0f131c]/85 to-[#090b10]/75 pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-8">
          <div className="space-y-4 max-w-2xl">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 tabular-nums">
              <span>AI GOD · Global Research Intelligence (GRI) v{systemInfo?.griVersion || GRI_VERSION}</span>
              <span aria-hidden="true">·</span>
              <span>Research Brain: {systemInfo?.coreModel || GOD_CORE_MODEL}</span>
              <span aria-hidden="true">·</span>
              <span>
                {firebaseUser ? 'Cloud Firestore (Isolated)' : 'Preview Session'}
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Global Research &amp; Command Center — {profile.displayName}
            </h1>

            <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
              Research Brain Status:{' '}
              <span
                className={
                  profile.emergencyStop
                    ? 'text-red-400 font-semibold'
                    : profile.executionMode === 'local'
                      ? 'text-amber-300 font-semibold'
                      : 'text-blue-400 font-semibold'
                }
              >
                {coreStateLabel}
              </span>
              . Tracking <span className="font-mono tabular-nums">{techAnalyses.length}</span>{' '}
              website/server profiles,{' '}
              <span className="font-mono tabular-nums">{cveAdvisories.length}</span> CVE advisories,{' '}
              <span className="font-mono tabular-nums">{knowledgeNodes.length}</span> D3 knowledge
              entities, and{' '}
              <span className="font-mono tabular-nums">{networkAssets.length}</span> authorized
              network assets.
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                type="button"
                onClick={() => setActiveSection('research')}
                className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Globe className="w-4 h-4" />
                <span>Launch Internet Explorer</span>
              </button>

              <button
                type="button"
                onClick={() => startNewConversation()}
                className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 border border-white/[0.08] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <MessageSquarePlus className="w-4 h-4" />
                <span>Open AI Chat</span>
              </button>
            </div>
          </div>

          <div className="flex flex-col items-center justify-center shrink-0 lg:pr-4">
            <NeuralCoreOrb
              emergencyStop={profile.emergencyStop}
              isStreaming={isStreamingChat}
              size="md"
            />
            <span className="mt-2 text-xs font-mono text-slate-400 tabular-nums">
              {profile.emergencyStop ? 'GIN LOCKDOWN' : 'GIN BRAIN ONLINE'}
            </span>
          </div>
        </div>
      </section>

      {/* Global Intelligence Telemetry Strip (Single Elevation, Tabular Figures) */}
      <section
        aria-label="Global intelligence metrics"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1.5">
          <p className="text-xs text-slate-400">Tech &amp; Server Profiles</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums whitespace-nowrap">
            {techAnalyses.length}{' '}
            <span className="text-sm font-normal text-slate-400">
              · {researchReports.length} reports
            </span>
          </p>
          <p className="text-xs text-slate-500 tabular-nums">
            {totalCitationsCount} verifiable public citations
          </p>
        </div>

        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1.5">
          <p className="text-xs text-slate-400">CVE &amp; Advisory Intelligence</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums whitespace-nowrap">
            {cveAdvisories.length}{' '}
            <span
              className={`text-sm font-normal ${
                cisaKevCount > 0 ? 'text-red-400' : 'text-emerald-400'
              }`}
            >
              ({cisaKevCount} CISA KEV)
            </span>
          </p>
          <p className="text-xs text-slate-500 tabular-nums">
            {activeMonitorsCount}/{researchMonitors.length} discovery monitors enabled
          </p>
        </div>

        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1.5">
          <p className="text-xs text-slate-400">D3 Knowledge Graph Entities</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums whitespace-nowrap">
            {knowledgeNodes.length}{' '}
            <span
              className={`text-sm font-normal ${
                knowledgeConflicts.length > 0 ? 'text-amber-300' : 'text-slate-400'
              }`}
            >
              ({knowledgeConflicts.length} flags)
            </span>
          </p>
          <p className="text-xs text-slate-500 tabular-nums">
            {behaviourInsights.length} behaviour insights · {anomalousAssetsCount} net alert(s)
          </p>
        </div>

        <div className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.08] space-y-1.5">
          <p className="text-xs text-slate-400">Core Workspace &amp; Agents</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums whitespace-nowrap">
            {conversations.length}{' '}
            <span className="text-sm font-normal text-slate-400">chats</span> · {activeTasksCount}{' '}
            <span className="text-sm font-normal text-slate-400">tasks</span>
          </p>
          <p className="text-xs text-slate-500 tabular-nums">
            {operationalAgentsCount} live · {prototypeAgentsCount} prototype · {plannedAgentsCount}{' '}
            planned
          </p>
        </div>
      </section>

      {/* Live Visual Intelligence Split: Network Topology + Knowledge Graph */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-base font-semibold text-white">Live Network Topology</h2>
            <button
              type="button"
              onClick={() => setActiveSection('network')}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <span>Open Network Observer</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
          <NetworkTopologySvg
            assets={networkAssets}
            onSelectAsset={() => setActiveSection('network')}
            compact
          />
        </div>

        <div className="space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-base font-semibold text-white">Knowledge Graph Overview</h2>
            <button
              type="button"
              onClick={() => setActiveSection('knowledge')}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <span>Explore Knowledge Graph</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
          <KnowledgeGraphSvg
            nodes={knowledgeNodes}
            conflicts={knowledgeConflicts}
            onSelectNode={() => setActiveSection('knowledge')}
            compact
          />
        </div>
      </section>

      {/* GOD Central Brain Multi-Agent Planner */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-white">
              GOD Central Brain — Research & Verification Planner
            </h2>
            <p className="text-xs text-slate-400">
              Generate a structured multi-agent execution plan routed across GIN modules with
              explicit verification criteria and readiness disclosure.
            </p>
          </div>
          {brainPlan && (
            <button
              type="button"
              onClick={handleStagePlanSteps}
              className="px-3.5 py-2 text-xs font-semibold bg-white/[0.07] hover:bg-white/[0.12] text-slate-100 rounded-lg whitespace-nowrap shrink-0 cursor-pointer self-start"
            >
              Stage Plan Steps as Tasks
            </button>
          )}
        </div>

        <form onSubmit={handleGeneratePlan} className="flex flex-col sm:flex-row gap-2.5">
          <label htmlFor="central-brain-objective" className="sr-only">
            Intelligence planning objective
          </label>
          <input
            id="central-brain-objective"
            type="text"
            value={brainObjective}
            onChange={(e) => setBrainObjective(e.target.value)}
            placeholder="Describe an intelligence objective (e.g., Correlate VLAN10 DNS spikes with public advisories)..."
            maxLength={400}
            className="flex-1 px-3.5 py-2 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={isPlanningBrain}
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            <BrainCircuit className="w-4 h-4" />
            <span>{isPlanningBrain ? 'Planning...' : 'Generate Plan'}</span>
          </button>
        </form>

        {brainPlanError && (
          <p role="alert" className="text-xs text-amber-300">
            {brainPlanError}
          </p>
        )}
        {planStagedMessage && <p className="text-xs text-emerald-400">{planStagedMessage}</p>}

        {brainPlan && (
          <div className="pt-4 border-t border-white/[0.07] space-y-4">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 tabular-nums">
                <span className="text-blue-400 font-semibold">
                  Plan Confidence: {brainPlan.confidenceScore}%
                </span>
                <span aria-hidden="true">·</span>
                <span>{brainPlan.steps.length} routed stages</span>
              </div>
              <p className="text-sm font-semibold text-white">{brainPlan.objective}</p>
              <p className="text-xs text-slate-400 leading-relaxed">{brainPlan.strategySummary}</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {brainPlan.steps.map((step) => (
                <div
                  key={step.stepNumber}
                  className="p-4 rounded-lg bg-[#090b10] border border-white/[0.07] space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2 text-xs font-mono">
                    <span className="text-blue-400 font-semibold">
                      0{step.stepNumber}. {step.agentModule}
                    </span>
                    <span className="text-slate-500">{step.status}</span>
                  </div>
                  <p className="text-xs text-slate-200 leading-relaxed">{step.objective}</p>
                  <p className="text-[11px] text-slate-500">
                    Verify: {step.verificationCriteria}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* GRI v0.5 Cross-Source Comparison & Technical Report */}
        <div className="pt-5 border-t border-white/[0.07] space-y-3">
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-white">
              Research Brain — Cross-Source Comparison &amp; Technical Report
            </h3>
            <p className="text-xs text-slate-400">
              Compare collected public reports, frontend/server profiles, and CVE advisories to
              surface consensus, conflicts, and defensive actions.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-2.5">
            <label htmlFor="gri-compare-topic" className="sr-only">
              Cross-source technical comparison topic
            </label>
            <input
              id="gri-compare-topic"
              type="text"
              value={comparisonTopic}
              onChange={(e) => setComparisonTopic(e.target.value)}
              placeholder="Comparison focus (e.g., Edge TLS, React stacks & container CVEs)..."
              maxLength={240}
              className="flex-1 px-3.5 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              type="button"
              disabled={isComparingSources}
              onClick={() => generateComparisonReport(comparisonTopic)}
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-white/[0.08] hover:bg-white/[0.14] disabled:opacity-50 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              <GitCompareArrows className="w-3.5 h-3.5 text-blue-400" />
              <span>{isComparingSources ? 'Comparing Sources...' : 'Compare Collected Sources'}</span>
            </button>
          </div>

          {comparisonError && (
            <p role="alert" className="text-xs text-amber-300">
              {comparisonError}
            </p>
          )}

          {comparisonReport && (
            <div className="p-4 rounded-lg bg-[#090b10] border border-white/[0.08] space-y-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-slate-400 tabular-nums">
                <span className="text-white font-semibold">{comparisonReport.topic}</span>
                <span className="text-blue-400">
                  Confidence {comparisonReport.confidenceScore}% · {comparisonReport.sourceCount}{' '}
                  sources compared
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed">{comparisonReport.executiveSummary}</p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-white/[0.06]">
                <div className="space-y-1">
                  <p className="font-semibold text-emerald-400">Cross-Source Agreements</p>
                  <ul className="space-y-1 text-slate-300">
                    {comparisonReport.agreements.map((pt, i) => (
                      <li key={i}>· {pt}</li>
                    ))}
                  </ul>
                </div>
                <div className="space-y-1">
                  <p className="font-semibold text-amber-300">Discrepancies &amp; Gaps</p>
                  <ul className="space-y-1 text-slate-400">
                    {comparisonReport.discrepancies.map((gap, i) => (
                      <li key={i}>· {gap}</li>
                    ))}
                  </ul>
                </div>
                <div className="space-y-1">
                  <p className="font-semibold text-blue-400">Recommended Actions</p>
                  <ul className="space-y-1 text-slate-300">
                    {comparisonReport.recommendedActions.map((act, i) => (
                      <li key={i}>· {act}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Quick Action Cards */}
      <section aria-label="Quick actions" className="space-y-3">
        <h2 className="text-lg font-semibold text-white">GRI v0.5 &amp; GIN Modules</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <button
            type="button"
            onClick={() => setActiveSection('webintel')}
            className="text-left p-4 rounded-xl bg-[#0f131c] hover:bg-[#141a26] border border-white/[0.08] transition-colors space-y-2 cursor-pointer"
          >
            <div className="flex items-center justify-between text-blue-400">
              <Code2 className="w-4 h-4" />
              <ArrowUpRight className="w-4 h-4" />
            </div>
            <p className="text-sm font-semibold text-white">Web &amp; Backend Tech Intel</p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Inspect public HTML/headers and research documented backend stacks.
            </p>
          </button>

          <button
            type="button"
            onClick={() => setActiveSection('serverintel')}
            className="text-left p-4 rounded-xl bg-[#0f131c] hover:bg-[#141a26] border border-white/[0.08] transition-colors space-y-2 cursor-pointer"
          >
            <div className="flex items-center justify-between text-blue-400">
              <Server className="w-4 h-4" />
              <ArrowUpRight className="w-4 h-4" />
            </div>
            <p className="text-sm font-semibold text-white">Server &amp; DNS Intelligence</p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Study public DNS records, CAA policies, and crt.sh Certificate Transparency.
            </p>
          </button>

          <button
            type="button"
            onClick={() => setActiveSection('cveintel')}
            className="text-left p-4 rounded-xl bg-[#0f131c] hover:bg-[#141a26] border border-white/[0.08] transition-colors space-y-2 cursor-pointer"
          >
            <div className="flex items-center justify-between text-red-400">
              <ShieldAlert className="w-4 h-4" />
              <ArrowUpRight className="w-4 h-4" />
            </div>
            <p className="text-sm font-semibold text-white">Security &amp; CVE Research</p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Query NVD CVE 2.0, CISA KEV catalog, and OWASP defensive mitigations.
            </p>
          </button>

          <button
            type="button"
            onClick={() => setActiveSection('monitors')}
            className="text-left p-4 rounded-xl bg-[#0f131c] hover:bg-[#141a26] border border-white/[0.08] transition-colors space-y-2 cursor-pointer"
          >
            <div className="flex items-center justify-between text-blue-400">
              <Radar className="w-4 h-4" />
              <ArrowUpRight className="w-4 h-4" />
            </div>
            <p className="text-sm font-semibold text-white">Continuous Research</p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Configure rate-limited discovery monitors and run connectors on demand.
            </p>
          </button>
        </div>
      </section>

      {/* Two-Column Split: Operational Task Queue + Alerts & Event Timeline */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-7 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Operational Task Queue</h2>
              <p className="text-xs text-slate-400">
                Track human-approved tasks isolated to your workspace ({completedTasksCount}{' '}
                completed).
              </p>
            </div>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {tasks.length} total
            </span>
          </div>

          <form onSubmit={handleCreateTask} className="space-y-3">
            <div className="flex flex-col sm:flex-row gap-2.5">
              <label htmlFor="dashboard-task-title" className="sr-only">
                New task title
              </label>
              <input
                id="dashboard-task-title"
                type="text"
                value={taskTitle}
                onChange={(e) => setTaskTitle(e.target.value)}
                placeholder="Add a command task (e.g., Audit VLAN10 DNS spikes)..."
                maxLength={200}
                className="flex-1 px-3.5 py-2 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />

              <label htmlFor="dashboard-task-category" className="sr-only">
                Task category
              </label>
              <select
                id="dashboard-task-category"
                value={taskCategory}
                onChange={(e) => setTaskCategory(e.target.value as IntentCategory)}
                className="px-3 py-2 text-xs font-medium bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="research">Research</option>
                <option value="coding">Coding</option>
                <option value="security">Security</option>
                <option value="automation">Automation</option>
                <option value="vision">Vision</option>
                <option value="chat">General</option>
              </select>

              <label htmlFor="dashboard-task-priority" className="sr-only">
                Task priority
              </label>
              <select
                id="dashboard-task-priority"
                value={taskPriority}
                onChange={(e) => setTaskPriority(e.target.value as TaskPriority)}
                className="px-3 py-2 text-xs font-medium bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

              <button
                type="submit"
                disabled={submittingTask}
                className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>Add Task</span>
              </button>
            </div>
            {taskFormError && (
              <p role="alert" className="text-xs text-red-400">
                {taskFormError}
              </p>
            )}
          </form>

          {tasks.length === 0 ? (
            <div className="py-8 text-center text-sm text-slate-400 border-t border-white/[0.06]">
              No tasks queued yet. Add your first operational task above.
            </div>
          ) : (
            <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
              {tasks.slice(0, 6).map((task) => (
                <div
                  key={task.id}
                  className="py-3 flex items-center justify-between gap-4 hover:bg-white/[0.02] px-1 transition-colors"
                >
                  <div className="min-w-0 space-y-0.5">
                    <p
                      className={`text-sm font-medium truncate ${
                        task.status === 'completed'
                          ? 'line-through text-slate-500'
                          : 'text-slate-100'
                      }`}
                    >
                      {task.title}
                    </p>
                    <div className="flex items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                      <span>{task.category}</span>
                      <span aria-hidden="true">·</span>
                      <span>{task.priority} priority</span>
                      <span aria-hidden="true">·</span>
                      <span>{task.status.replace('_', ' ')}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {task.status !== 'archived' && (
                      <button
                        type="button"
                        onClick={() => updateTaskStatus(task.id, nextStatusFor(task.status))}
                        aria-label={`Advance status for "${task.title}"`}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium bg-white/[0.05] hover:bg-white/[0.1] text-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                        <span>
                          {task.status === 'queued'
                            ? 'Start'
                            : task.status === 'in_progress'
                              ? 'Complete'
                              : 'Reopen'}
                        </span>
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => deleteTask(task.id)}
                      aria-label={`Delete task "${task.title}"`}
                      className="p-1.5 text-slate-400 hover:text-red-400 rounded-md transition-colors cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Alerts & Event Timeline */}
        <div className="lg:col-span-5 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Alerts & Event Timeline</h2>
              <p className="text-xs text-slate-400">Latest GIN telemetry, research & security logs</p>
            </div>
            <button
              type="button"
              onClick={() => setActiveSection('security')}
              className="text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
            >
              Full Audit Log
            </button>
          </div>

          {auditEvents.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-400 border-t border-white/[0.06]">
              No activity events recorded in this session yet.
            </p>
          ) : (
            <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
              {auditEvents.slice(0, 6).map((evt) => (
                <div key={evt.id} className="py-3 space-y-1">
                  <div className="flex items-center justify-between gap-2 text-xs font-mono tabular-nums">
                    <span
                      className={
                        evt.severity === 'critical'
                          ? 'text-red-400 font-medium'
                          : evt.severity === 'warning'
                            ? 'text-amber-300 font-medium'
                            : 'text-blue-400 font-medium'
                      }
                    >
                      {evt.action}
                    </span>
                    <span className="text-slate-500">{formatRelativeTime(evt.createdAtMs)}</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{evt.summary}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
