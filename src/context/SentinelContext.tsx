import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useGodWorkspace } from './GodWorkspaceContext';
import {
  DEFAULT_RESOURCE_LIMITS,
  buildIncidentTimeline,
  buildSentinelTopology,
  evaluateRegionalIntelligence,
  mapHeuristicMitreTechniques,
  normalizeSentinelEvent,
  validateDefensiveActionRequest,
} from '../shared/sentinelAnalytics';
import {
  SENTINEL_VERSION,
  type DefensiveActionType,
  type RegionalCorrelationFinding,
  type SentinelAgentRecord,
  type SentinelApprovalActionRecord,
  type SentinelAuditLogRecord,
  type SentinelEnrollmentTokenRecord,
  type SentinelEventRecord,
  type SentinelIncidentRecord,
  type SentinelOsType,
  type SentinelQueueMetrics,
  type SentinelResourceLimits,
  type SentinelTopologyEdge,
  type SentinelTopologyNode,
} from '../shared/sentinelTypes';

function buildPreviewSeed(): {
  agents: SentinelAgentRecord[];
  tokens: SentinelEnrollmentTokenRecord[];
  events: SentinelEventRecord[];
  incidents: SentinelIncidentRecord[];
  approvals: SentinelApprovalActionRecord[];
  auditLogs: SentinelAuditLogRecord[];
} {
  const now = Date.now();
  const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString();

  const agents: SentinelAgentRecord[] = [
    {
      id: 'srv-sg-edge01',
      hostname: 'sg-edge-linux-01',
      region: 'asia-southeast1',
      ipAddress: '10.14.2.11',
      osType: 'linux',
      osVersion: 'Ubuntu 24.04.1 LTS (Linux 6.8)',
      agentVersion: SENTINEL_VERSION,
      targetVersion: SENTINEL_VERSION,
      status: 'online',
      cpuPercent: 31,
      ramPercent: 54,
      diskPercent: 42,
      uptimeSec: 1296400,
      services: [
        { name: 'sshd', state: 'running', pid: 814 },
        { name: 'nginx', state: 'running', pid: 1412 },
        { name: 'systemd-journald', state: 'running', pid: 402 },
      ],
      resourceLimits: DEFAULT_RESOURCE_LIMITS,
      tags: ['edge-gateway', 'authorized-linux'],
      lastHeartbeatAt: iso(-12_000),
      enrolledAt: iso(-86_400_000 * 5),
      revokedAt: null,
    },
    {
      id: 'srv-sg-app02',
      hostname: 'sg-app-linux-02',
      region: 'asia-southeast1',
      ipAddress: '10.14.2.24',
      osType: 'linux',
      osVersion: 'Debian 12.7 (Linux 6.1)',
      agentVersion: '0.7.9',
      targetVersion: SENTINEL_VERSION,
      status: 'degraded',
      cpuPercent: 89,
      ramPercent: 72,
      diskPercent: 58,
      uptimeSec: 648100,
      services: [
        { name: 'sshd', state: 'running', pid: 720 },
        { name: 'node', state: 'running', pid: 2104 },
        { name: 'postgresql', state: 'running', pid: 950 },
      ],
      resourceLimits: DEFAULT_RESOURCE_LIMITS,
      tags: ['app-tier', 'authorized-linux'],
      lastHeartbeatAt: iso(-18_000),
      enrolledAt: iso(-86_400_000 * 3),
      revokedAt: null,
    },
    {
      id: 'srv-us-win01',
      hostname: 'us-ad-win-01',
      region: 'us-central1',
      ipAddress: '10.22.4.15',
      osType: 'windows',
      osVersion: 'Windows Server 2022 Datacenter',
      agentVersion: SENTINEL_VERSION,
      targetVersion: SENTINEL_VERSION,
      status: 'online',
      cpuPercent: 24,
      ramPercent: 61,
      diskPercent: 49,
      uptimeSec: 912300,
      services: [
        { name: 'WinDefend', state: 'running' },
        { name: 'EventLog', state: 'running' },
        { name: 'MpsSvc', state: 'running' },
      ],
      resourceLimits: DEFAULT_RESOURCE_LIMITS,
      tags: ['identity-tier', 'authorized-windows'],
      lastHeartbeatAt: iso(-21_000),
      enrolledAt: iso(-86_400_000 * 9),
      revokedAt: null,
    },
  ];

  const rawEvents: Array<{ id: string; agent: SentinelAgentRecord; raw: Parameters<typeof normalizeSentinelEvent>[0]; count?: number }> = [
    {
      id: 'sevt-prev-01',
      agent: agents[0],
      count: 14,
      raw: {
        eventType: 'auth',
        severity: 'high',
        summary: 'Repeated failed SSH logins for deploy from 198.51.100.77 followed by accepted key login',
        payload: { sourceIp: '198.51.100.77', username: 'deploy', remotePort: 22, action: 'ssh_pivot_observed' },
        collector: 'sentinel-auth-log',
        observedAt: iso(-420_000),
      },
    },
    {
      id: 'sevt-prev-02',
      agent: agents[1],
      count: 3,
      raw: {
        eventType: 'auth',
        severity: 'high',
        summary: 'SSH session opened for deploy from 198.51.100.77 across regional subnet',
        payload: { sourceIp: '198.51.100.77', username: 'deploy', remotePort: 22, action: 'auth_accepted' },
        collector: 'sentinel-auth-log',
        observedAt: iso(-360_000),
      },
    },
    {
      id: 'sevt-prev-03',
      agent: agents[1],
      count: 1,
      raw: {
        eventType: 'process',
        severity: 'high',
        summary: 'Suspicious child shell executed from /tmp/stage_diag.sh',
        payload: { pid: 44120, processName: 'bash', parentProcess: 'sshd', command: 'bash /tmp/stage_diag.sh' },
        collector: 'sentinel-process-watcher',
        observedAt: iso(-300_000),
      },
    },
    {
      id: 'sevt-prev-04',
      agent: agents[1],
      count: 2,
      raw: {
        eventType: 'network',
        severity: 'high',
        summary: 'Unexpected outbound TCP socket to 198.51.100.77:4444',
        payload: { protocol: 'TCP', remoteIp: '198.51.100.77', remotePort: 4444, state: 'ESTABLISHED' },
        collector: 'sentinel-net-metadata',
        observedAt: iso(-270_000),
      },
    },
    {
      id: 'sevt-prev-05',
      agent: agents[1],
      count: 1,
      raw: {
        eventType: 'fim',
        severity: 'critical',
        summary: 'SHA-256 checksum drift detected on /etc/ssh/sshd_config',
        payload: { filePath: '/etc/ssh/sshd_config', previousSha256: '8b7df143d91c716e', currentSha256: 'f31c9a02e81b4451' },
        collector: 'sentinel-fim-sha256',
        observedAt: iso(-210_000),
      },
    },
    {
      id: 'sevt-prev-06',
      agent: agents[2],
      count: 1,
      raw: {
        eventType: 'network',
        severity: 'info',
        summary: 'Established HTTPS telemetry sync to regional controller peer',
        payload: { protocol: 'TCP', remoteIp: '10.14.2.11', remotePort: 443, state: 'ESTABLISHED' },
        collector: 'sentinel-win-net',
        observedAt: iso(-90_000),
      },
    },
  ];

  const events: SentinelEventRecord[] = rawEvents.map((item) => {
    const normalized = normalizeSentinelEvent(
      item.raw,
      {
        agentId: item.agent.id,
        agentVersion: item.agent.agentVersion,
        hostname: item.agent.hostname,
        region: item.agent.region,
      },
      item.raw.observedAt || iso(0)
    );
    return {
      id: item.id,
      ...normalized,
      occurrenceCount: item.count || 1,
    };
  });

  const incidents: SentinelIncidentRecord[] = [
    {
      id: 'sinc-prev-01',
      title: 'Correlated SSH Lateral Movement & Config Tampering in asia-southeast1',
      severity: 'critical',
      status: 'investigating',
      region: 'asia-southeast1',
      correlationType: 'lateral_movement',
      affectedAgentIds: ['srv-sg-edge01', 'srv-sg-app02'],
      evidenceEventIds: ['sevt-prev-01', 'sevt-prev-02', 'sevt-prev-03', 'sevt-prev-04', 'sevt-prev-05'],
      mitreTechniques: mapHeuristicMitreTechniques(events.slice(0, 5)),
      hypotheses: [
        {
          id: 'hyp-1',
          title: 'Compromised deploy SSH key pivoted from sg-edge-linux-01 to sg-app-linux-02',
          likelihood: 'high',
          supportingEvidence: [
            '[sevt-prev-01] 14 failed SSH logins followed by accepted key authentication from 198.51.100.77.',
            '[sevt-prev-02] Same source IP opened an SSH session on sg-app-linux-02 60 seconds later.',
            '[sevt-prev-03] Unapproved shell execution from /tmp/stage_diag.sh paired with port 4444 egress.',
            '[sevt-prev-05] Unauthorized SHA-256 drift on /etc/ssh/sshd_config.',
          ],
          refutingOrGaps: [
            'Verify whether any emergency change ticket authorized sshd_config updates for deploy.',
          ],
        },
        {
          id: 'hyp-2',
          title: 'Unannounced automated infrastructure patching script',
          likelihood: 'low',
          supportingEvidence: ['Authentication succeeded using existing deploy service account.'],
          refutingOrGaps: [
            'Standard CI/CD pipelines never execute scripts from /tmp or connect outbound to TCP/4444.',
          ],
        },
      ],
      timeline: buildIncidentTimeline(events.slice(0, 5)),
      investigationReport: [
        '## GOD Sentinel Central Brain Investigation Summary',
        'Cross-host regional correlation identified a high-confidence defensive incident spanning **sg-edge-linux-01** and **sg-app-linux-02** in `asia-southeast1`.',
        '',
        '### Key Evidence Findings',
        '- **Credential Access & Lateral Movement**: Source `198.51.100.77` triggered 14 failed SSH attempts on `sg-edge-linux-01` (`sevt-prev-01`) before authenticating as `deploy` and opening a session on `sg-app-linux-02` (`sevt-prev-02`).',
        '- **Execution & Egress**: Process watcher captured `bash /tmp/stage_diag.sh` (PID `44120`, `sevt-prev-03`) followed by outbound `TCP/4444` metadata (`sevt-prev-04`).',
        '- **Persistence / Tampering**: File integrity monitoring flagged SHA-256 hash drift on `/etc/ssh/sshd_config` (`sevt-prev-05`).',
        '',
        '### Governance & Human Approval Status',
        'Two bounded defensive actions (`terminate_process` and `firewall_policy`) are queued under **Approvals & Audit**. No destructive action has been auto-executed.',
      ].join('\n'),
      confidenceScore: 92,
      createdAt: iso(-180_000),
      updatedAt: iso(-120_000),
    },
  ];

  const approvals: SentinelApprovalActionRecord[] = [
    {
      id: 'sact-prev-01',
      agentId: 'srv-sg-app02',
      incidentId: 'sinc-prev-01',
      actionType: 'terminate_process',
      targetDetail: 'PID 44120 (bash /tmp/stage_diag.sh)',
      rationale:
        'Suspicious /tmp execution correlated with outbound TCP/4444 connection and /etc/ssh/sshd_config checksum drift.',
      status: 'pending_approval',
      requestedBy: 'GOD Sentinel Brain (Gemini)',
      decidedBy: null,
      decisionNote: null,
      requestedAt: iso(-115_000),
      decidedAt: null,
    },
    {
      id: 'sact-prev-02',
      agentId: 'srv-sg-edge01',
      incidentId: 'sinc-prev-01',
      actionType: 'firewall_policy',
      targetDetail: 'Deny ingress & egress for peer 198.51.100.77 on TCP/22 and TCP/4444',
      rationale:
        'Correlated multi-host authentication anomaly and non-standard port 4444 outbound connection.',
      status: 'pending_approval',
      requestedBy: 'Regional Intelligence Engine',
      decidedBy: null,
      decisionNote: null,
      requestedAt: iso(-110_000),
      decidedAt: null,
    },
  ];

  const tokens: SentinelEnrollmentTokenRecord[] = [
    {
      id: 'tok-prev-01',
      tokenPrefix: 'gsen_94f1c2a',
      label: 'Singapore Edge Linux 01',
      region: 'asia-southeast1',
      osType: 'linux',
      expiresAt: iso(86_400_000),
      usedAt: iso(-86_400_000 * 5),
      usedByAgentId: 'srv-sg-edge01',
      revokedAt: null,
      createdAt: iso(-86_400_000 * 5 - 60_000),
    },
  ];

  const auditLogs: SentinelAuditLogRecord[] = [
    {
      id: 'saud-prev-01',
      action: 'AGENT_ENROLLED',
      actor: 'agent:sg-edge-linux-01',
      targetId: 'srv-sg-edge01',
      severity: 'info',
      details: 'Enrolled authorized linux Sentinel agent sg-edge-linux-01 (10.14.2.11) in asia-southeast1.',
      createdAt: iso(-86_400_000 * 5),
    },
    {
      id: 'saud-prev-02',
      action: 'DEFENSIVE_ACTION_PROPOSED',
      actor: 'GOD Sentinel Brain (Gemini)',
      targetId: 'sact-prev-01',
      severity: 'warning',
      details: 'Proposed terminate_process on sg-app-linux-02 (PID 44120). Awaiting human operator approval.',
      createdAt: iso(-115_000),
    },
  ];

  return { agents, tokens, events, incidents, approvals, auditLogs };
}

interface SentinelContextValue {
  agents: SentinelAgentRecord[];
  tokens: SentinelEnrollmentTokenRecord[];
  events: SentinelEventRecord[];
  incidents: SentinelIncidentRecord[];
  approvals: SentinelApprovalActionRecord[];
  auditLogs: SentinelAuditLogRecord[];
  regionalFindings: RegionalCorrelationFinding[];
  topology: { nodes: SentinelTopologyNode[]; edges: SentinelTopologyEdge[] };
  queueMetrics: SentinelQueueMetrics;
  loading: boolean;
  busyAction: string | null;
  errorMessage: string | null;
  lastIssuedPlainToken: { id: string; plainToken: string; region: string; osType: SentinelOsType } | null;
  refreshOverview: () => Promise<void>;
  issueEnrollmentToken: (input: { label: string; region: string; osType: SentinelOsType; ttlHours: number }) => Promise<void>;
  revokeToken: (tokenId: string) => Promise<void>;
  revokeAgent: (agentId: string) => Promise<void>;
  updateAgentPolicy: (agentId: string, updates: { targetVersion?: string; resourceLimits?: Partial<SentinelResourceLimits> }) => Promise<void>;
  runRegionalCorrelation: () => Promise<void>;
  runBrainInvestigation: (options?: { incidentId?: string; agentId?: string }) => Promise<void>;
  runMilestoneOneDrill: () => Promise<void>;
  proposeDefensiveAction: (input: { agentId: string; incidentId?: string; actionType: DefensiveActionType; targetDetail: string; rationale: string }) => Promise<void>;
  decideApproval: (actionId: string, decision: 'approved' | 'rejected', decisionNote?: string) => Promise<void>;
  clearError: () => void;
}

const SentinelContext = createContext<SentinelContextValue | null>(null);

export const SentinelProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { firebaseUser } = useGodWorkspace();
  const initialSeed = useMemo(() => buildPreviewSeed(), []);

  const getAuthHeaders = useCallback(async (): Promise<Record<string, string>> => {
    if (!firebaseUser) return {};
    const token = await firebaseUser.getIdToken();
    return { Authorization: `Bearer ${token}` };
  }, [firebaseUser]);

  const [agents, setAgents] = useState<SentinelAgentRecord[]>(initialSeed.agents);
  const [tokens, setTokens] = useState<SentinelEnrollmentTokenRecord[]>(initialSeed.tokens);
  const [events, setEvents] = useState<SentinelEventRecord[]>(initialSeed.events);
  const [incidents, setIncidents] = useState<SentinelIncidentRecord[]>(initialSeed.incidents);
  const [approvals, setApprovals] = useState<SentinelApprovalActionRecord[]>(initialSeed.approvals);
  const [auditLogs, setAuditLogs] = useState<SentinelAuditLogRecord[]>(initialSeed.auditLogs);
  const [queueMetrics, setQueueMetrics] = useState<SentinelQueueMetrics>({
    pendingDepth: 0,
    totalReceived: 22,
    totalDeduplicated: 16,
    totalPersisted: 6,
    deadLetterCount: 0,
  });
  const [loading, setLoading] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastIssuedPlainToken, setLastIssuedPlainToken] = useState<{
    id: string;
    plainToken: string;
    region: string;
    osType: SentinelOsType;
  } | null>(null);

  const regionalFindings = useMemo(
    () => evaluateRegionalIntelligence(agents, events),
    [agents, events]
  );

  const topology = useMemo(() => buildSentinelTopology(agents, events), [agents, events]);

  const refreshOverview = useCallback(async () => {
    if (!firebaseUser) {
      const seed = buildPreviewSeed();
      setAgents(seed.agents);
      setTokens(seed.tokens);
      setEvents(seed.events);
      setIncidents(seed.incidents);
      setApprovals(seed.approvals);
      setAuditLogs(seed.auditLogs);
      return;
    }

    setLoading(true);
    setErrorMessage(null);
    try {
      const headers = await getAuthHeaders();
      const res = await fetch('/api/sentinel/overview', { headers });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Unable to load Sentinel fleet overview.');
      }
      setAgents(data.agents || []);
      setTokens(data.tokens || []);
      setEvents(data.events || []);
      setIncidents(data.incidents || []);
      setApprovals(data.approvals || []);
      setAuditLogs(data.auditLogs || []);
      if (data.queueMetrics) setQueueMetrics(data.queueMetrics);
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Unable to refresh Sentinel fleet.');
    } finally {
      setLoading(false);
    }
  }, [firebaseUser, getAuthHeaders]);

  useEffect(() => {
    void refreshOverview();
  }, [refreshOverview]);

  const issueEnrollmentToken = useCallback(
    async (input: { label: string; region: string; osType: SentinelOsType; ttlHours: number }) => {
      setBusyAction('issue_token');
      setErrorMessage(null);
      try {
        if (!firebaseUser) {
          const rand = Math.random().toString(16).slice(2, 14) + Math.random().toString(16).slice(2, 14);
          const plainToken = `gsen_${rand}`;
          const nowIso = new Date().toISOString();
          const tok: SentinelEnrollmentTokenRecord = {
            id: `tok-${Date.now().toString(36)}`,
            tokenPrefix: plainToken.slice(0, 12),
            label: input.label.trim() || 'Authorized Server',
            region: input.region,
            osType: input.osType,
            expiresAt: new Date(Date.now() + input.ttlHours * 3600_000).toISOString(),
            usedAt: null,
            usedByAgentId: null,
            revokedAt: null,
            createdAt: nowIso,
          };
          setTokens((prev) => [tok, ...prev]);
          setLastIssuedPlainToken({ id: tok.id, plainToken, region: tok.region, osType: tok.osType });
          setAuditLogs((prev) => [
            {
              id: `saud-${Date.now().toString(36)}`,
              action: 'ENROLLMENT_TOKEN_ISSUED',
              actor: 'preview-operator',
              targetId: tok.id,
              severity: 'info',
              details: `Issued single-use enrollment token (${tok.tokenPrefix}...) for ${tok.osType} in ${tok.region}.`,
              createdAt: nowIso,
            },
            ...prev,
          ]);
          return;
        }

        const headers = await getAuthHeaders();
        const res = await fetch('/api/sentinel/tokens', {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to issue enrollment token.');
        setLastIssuedPlainToken({
          id: data.tokenRecord.id,
          plainToken: data.plainToken,
          region: data.tokenRecord.region,
          osType: data.tokenRecord.osType,
        });
        await refreshOverview();
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to issue token.');
      } finally {
        setBusyAction(null);
      }
    },
    [firebaseUser, getAuthHeaders, refreshOverview]
  );

  const revokeToken = useCallback(
    async (tokenId: string) => {
      setBusyAction(`revoke_token:${tokenId}`);
      setErrorMessage(null);
      try {
        if (!firebaseUser) {
          const nowIso = new Date().toISOString();
          setTokens((prev) =>
            prev.map((t) => (t.id === tokenId ? { ...t, revokedAt: nowIso } : t))
          );
          setAuditLogs((prev) => [
            {
              id: `saud-${Date.now().toString(36)}`,
              action: 'ENROLLMENT_TOKEN_REVOKED',
              actor: 'preview-operator',
              targetId: tokenId,
              severity: 'warning',
              details: `Revoked unused enrollment token ${tokenId}.`,
              createdAt: nowIso,
            },
            ...prev,
          ]);
          return;
        }

        const headers = await getAuthHeaders();
        const res = await fetch(`/api/sentinel/tokens/${encodeURIComponent(tokenId)}/revoke`, {
          method: 'POST',
          headers,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to revoke token.');
        await refreshOverview();
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to revoke token.');
      } finally {
        setBusyAction(null);
      }
    },
    [firebaseUser, getAuthHeaders, refreshOverview]
  );

  const revokeAgent = useCallback(
    async (agentId: string) => {
      setBusyAction(`revoke_agent:${agentId}`);
      setErrorMessage(null);
      try {
        if (!firebaseUser) {
          const nowIso = new Date().toISOString();
          setAgents((prev) =>
            prev.map((a) =>
              a.id === agentId ? { ...a, status: 'revoked', revokedAt: nowIso } : a
            )
          );
          setAuditLogs((prev) => [
            {
              id: `saud-${Date.now().toString(36)}`,
              action: 'AGENT_REVOKED',
              actor: 'preview-operator',
              targetId: agentId,
              severity: 'warning',
              details: `Revoked Sentinel agent ${agentId} credentials.`,
              createdAt: nowIso,
            },
            ...prev,
          ]);
          return;
        }

        const headers = await getAuthHeaders();
        const res = await fetch(`/api/sentinel/agents/${encodeURIComponent(agentId)}/revoke`, {
          method: 'POST',
          headers,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to revoke agent.');
        await refreshOverview();
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to revoke agent.');
      } finally {
        setBusyAction(null);
      }
    },
    [firebaseUser, getAuthHeaders, refreshOverview]
  );

  const updateAgentPolicy = useCallback(
    async (
      agentId: string,
      updates: { targetVersion?: string; resourceLimits?: Partial<SentinelResourceLimits> }
    ) => {
      setBusyAction(`policy:${agentId}`);
      setErrorMessage(null);
      try {
        if (!firebaseUser) {
          const nowIso = new Date().toISOString();
          setAgents((prev) =>
            prev.map((a) =>
              a.id === agentId
                ? {
                    ...a,
                    targetVersion: updates.targetVersion || a.targetVersion,
                    agentVersion: updates.targetVersion || a.agentVersion,
                    resourceLimits: { ...a.resourceLimits, ...(updates.resourceLimits || {}) },
                  }
                : a
            )
          );
          setAuditLogs((prev) => [
            {
              id: `saud-${Date.now().toString(36)}`,
              action: 'AGENT_POLICY_UPDATED',
              actor: 'preview-operator',
              targetId: agentId,
              severity: 'info',
              details: `Updated Sentinel version/resource limits for ${agentId}.`,
              createdAt: nowIso,
            },
            ...prev,
          ]);
          return;
        }

        const headers = await getAuthHeaders();
        const res = await fetch(`/api/sentinel/agents/${encodeURIComponent(agentId)}/policy`, {
          method: 'PATCH',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(updates),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to update agent policy.');
        await refreshOverview();
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to update agent policy.');
      } finally {
        setBusyAction(null);
      }
    },
    [firebaseUser, getAuthHeaders, refreshOverview]
  );

  const runRegionalCorrelation = useCallback(async () => {
    setBusyAction('correlate');
    setErrorMessage(null);
    try {
      if (!firebaseUser) {
        const nowIso = new Date().toISOString();
        const findings = evaluateRegionalIntelligence(agents, events);
        setAuditLogs((prev) => [
          {
            id: `saud-${Date.now().toString(36)}`,
            action: 'REGIONAL_CORRELATION_EXECUTED',
            actor: 'preview-operator',
            targetId: 'regional-engine',
            severity: 'info',
            details: `Correlated ${events.length} events across ${agents.length} hosts; identified ${findings.length} regional finding(s).`,
            createdAt: nowIso,
          },
          ...prev,
        ]);
        return;
      }

      const headers = await getAuthHeaders();
      const res = await fetch('/api/sentinel/correlate', {
        method: 'POST',
        headers,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Regional correlation failed.');
      await refreshOverview();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Regional correlation failed.');
    } finally {
      setBusyAction(null);
    }
  }, [agents, events, firebaseUser, getAuthHeaders, refreshOverview]);

  const runBrainInvestigation = useCallback(
    async (options?: { incidentId?: string; agentId?: string }) => {
      setBusyAction('investigate');
      setErrorMessage(null);
      try {
        if (!firebaseUser) {
          const nowIso = new Date().toISOString();
          const targetEvents = options?.agentId
            ? events.filter((e) => e.agentId === options.agentId)
            : events.filter((e) => e.severity !== 'info');
          const subset = targetEvents.length > 0 ? targetEvents : events;
          const mitre = mapHeuristicMitreTechniques(subset);
          const newInc: SentinelIncidentRecord = {
            id: options?.incidentId || `sinc-${Date.now().toString(36)}`,
            title: `GOD Brain Investigation (${subset.length} evidence events)`,
            severity: subset.some((e) => e.severity === 'critical') ? 'critical' : 'high',
            status: 'investigating',
            region: Array.from(new Set(subset.map((e) => e.region))).join(', ') || 'asia-southeast1',
            correlationType: 'multi_signal_intrusion',
            affectedAgentIds: Array.from(new Set(subset.map((e) => e.agentId))),
            evidenceEventIds: subset.map((e) => e.id),
            mitreTechniques: mitre,
            hypotheses: [
              {
                id: 'hyp-live-1',
                title: 'Coordinated unauthorized execution with configuration persistence attempt',
                likelihood: 'high',
                supportingEvidence: subset.slice(0, 4).map((e) => `[${e.id}] ${e.hostname}: ${e.summary}`),
                refutingOrGaps: ['Sign in with Google to run full live Gemini Central Brain synthesis.'],
              },
            ],
            timeline: buildIncidentTimeline(subset),
            investigationReport:
              '## Preview Mode Investigation\nTelemetry evidence was correlated locally and mapped to MITRE ATT&CK techniques. Sign in with Google to run live server-side Gemini Central Brain analysis and persist to PostgreSQL.',
            confidenceScore: 86,
            createdAt: nowIso,
            updatedAt: nowIso,
          };
          setIncidents((prev) => [newInc, ...prev.filter((i) => i.id !== newInc.id)]);
          return;
        }

        const headers = await getAuthHeaders();
        const res = await fetch('/api/sentinel/investigate', {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(options || {}),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Central Brain investigation failed.');
        await refreshOverview();
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Investigation failed.');
      } finally {
        setBusyAction(null);
      }
    },
    [events, firebaseUser, getAuthHeaders, refreshOverview]
  );

  const runMilestoneOneDrill = useCallback(async () => {
    setBusyAction('milestone_drill');
    setErrorMessage(null);
    try {
      if (!firebaseUser) {
        const nowIso = new Date().toISOString();
        const id = `srv-m1-${Date.now().toString(36).slice(-4)}`;
        const hostname = `sg-milestone1-linux-${id.slice(-3)}`;
        const newAgent: SentinelAgentRecord = {
          id,
          hostname,
          region: 'asia-southeast1',
          ipAddress: '10.14.8.42',
          osType: 'linux',
          osVersion: 'Ubuntu 24.04.1 LTS (Linux 6.8)',
          agentVersion: SENTINEL_VERSION,
          targetVersion: SENTINEL_VERSION,
          status: 'online',
          cpuPercent: 26,
          ramPercent: 44,
          diskPercent: 37,
          uptimeSec: 184200,
          services: [
            { name: 'sshd', state: 'running', pid: 810 },
            { name: 'nginx', state: 'running', pid: 1205 },
          ],
          resourceLimits: DEFAULT_RESOURCE_LIMITS,
          tags: ['milestone-1', 'authorized-linux'],
          lastHeartbeatAt: nowIso,
          enrolledAt: nowIso,
          revokedAt: null,
        };
        const drillEvents: SentinelEventRecord[] = [
          {
            id: `sevt-m1-${Date.now().toString(36)}-a`,
            ...normalizeSentinelEvent(
              {
                eventType: 'process',
                severity: 'high',
                summary: `[SIMULATED DRILL] Suspicious child shell launched from /tmp/audit_probe.sh on ${hostname}`,
                payload: { pid: 49122, processName: 'bash', command: 'bash /tmp/audit_probe.sh --check' },
                collector: 'sentinel-process-drill',
                observedAt: nowIso,
                simulatedDrill: true,
              },
              { agentId: id, agentVersion: SENTINEL_VERSION, hostname, region: 'asia-southeast1' },
              nowIso
            ),
          },
          {
            id: `sevt-m1-${Date.now().toString(36)}-b`,
            ...normalizeSentinelEvent(
              {
                eventType: 'fim',
                severity: 'critical',
                summary: `[SIMULATED DRILL] SHA-256 checksum drift detected on /etc/ssh/sshd_config`,
                payload: { filePath: '/etc/ssh/sshd_config', previousSha256: '8b7df143', currentSha256: 'd2f9e0a7' },
                collector: 'sentinel-fim-drill',
                observedAt: nowIso,
                simulatedDrill: true,
              },
              { agentId: id, agentVersion: SENTINEL_VERSION, hostname, region: 'asia-southeast1' },
              nowIso
            ),
          },
        ];
        const newInc: SentinelIncidentRecord = {
          id: `sinc-m1-${Date.now().toString(36)}`,
          title: `Milestone 1 Drill: Suspicious Process & FIM Drift on ${hostname}`,
          severity: 'critical',
          status: 'investigating',
          region: 'asia-southeast1',
          correlationType: 'multi_signal_intrusion',
          affectedAgentIds: [id],
          evidenceEventIds: drillEvents.map((e) => e.id),
          mitreTechniques: mapHeuristicMitreTechniques(drillEvents),
          hypotheses: [
            {
              id: 'hyp-m1',
              title: 'Simulated Milestone 1 intrusion chain validated end-to-end',
              likelihood: 'high',
              supportingEvidence: drillEvents.map((e) => `[${e.id}] ${e.summary}`),
              refutingOrGaps: ['Marked simulatedDrill=true for verification.'],
            },
          ],
          timeline: buildIncidentTimeline(drillEvents),
          investigationReport: `## Milestone 1 Verification Complete\nEnrolled **${hostname}**, received live heartbeat (CPU 26%, RAM 44%, Disk 37%), normalized simulated suspicious events, mapped MITRE ATT&CK techniques, and queued a human-approval containment action.`,
          confidenceScore: 91,
          createdAt: nowIso,
          updatedAt: nowIso,
        };
        const newApproval: SentinelApprovalActionRecord = {
          id: `sact-m1-${Date.now().toString(36)}`,
          agentId: id,
          incidentId: newInc.id,
          actionType: 'terminate_process',
          targetDetail: 'PID 49122 (bash /tmp/audit_probe.sh --check)',
          rationale: 'Milestone 1 drill process correlated with critical /etc/ssh/sshd_config drift. Human approval required.',
          status: 'pending_approval',
          requestedBy: 'GOD Sentinel Brain',
          decidedBy: null,
          decisionNote: null,
          requestedAt: nowIso,
          decidedAt: null,
        };

        setAgents((prev) => [newAgent, ...prev]);
        setEvents((prev) => [...drillEvents, ...prev]);
        setIncidents((prev) => [newInc, ...prev]);
        setApprovals((prev) => [newApproval, ...prev]);
        setQueueMetrics((prev) => ({
          ...prev,
          totalReceived: prev.totalReceived + drillEvents.length,
          totalPersisted: prev.totalPersisted + drillEvents.length,
        }));
        setAuditLogs((prev) => [
          {
            id: `saud-${Date.now().toString(36)}`,
            action: 'MILESTONE_1_DRILL_COMPLETED',
            actor: 'preview-operator',
            targetId: id,
            severity: 'info',
            details: `Enrolled ${hostname}, recorded heartbeat, analyzed simulated suspicious chain, queued human-approval action.`,
            createdAt: nowIso,
          },
          ...prev,
        ]);
        return;
      }

      const headers = await getAuthHeaders();
      const res = await fetch('/api/sentinel/milestone-drill', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ region: 'asia-southeast1' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Milestone 1 drill failed.');
      await refreshOverview();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Milestone 1 drill failed.');
    } finally {
      setBusyAction(null);
    }
  }, [firebaseUser, getAuthHeaders, refreshOverview]);

  const proposeDefensiveAction = useCallback(
    async (input: {
      agentId: string;
      incidentId?: string;
      actionType: DefensiveActionType;
      targetDetail: string;
      rationale: string;
    }) => {
      setBusyAction('propose_action');
      setErrorMessage(null);
      const validation = validateDefensiveActionRequest(input);
      if (!validation.valid) {
        setErrorMessage(validation.error || 'Invalid defensive action request.');
        setBusyAction(null);
        return;
      }
      try {
        if (!firebaseUser) {
          const nowIso = new Date().toISOString();
          const rec: SentinelApprovalActionRecord = {
            id: `sact-${Date.now().toString(36)}`,
            agentId: input.agentId,
            incidentId: input.incidentId || null,
            actionType: input.actionType,
            targetDetail: input.targetDetail.trim(),
            rationale: input.rationale.trim(),
            status: 'pending_approval',
            requestedBy: 'preview-operator',
            decidedBy: null,
            decisionNote: null,
            requestedAt: nowIso,
            decidedAt: null,
          };
          setApprovals((prev) => [rec, ...prev]);
          setAuditLogs((prev) => [
            {
              id: `saud-${Date.now().toString(36)}`,
              action: 'DEFENSIVE_ACTION_PROPOSED',
              actor: 'preview-operator',
              targetId: rec.id,
              severity: 'warning',
              details: `Proposed ${rec.actionType} on ${rec.agentId}: ${rec.targetDetail}`,
              createdAt: nowIso,
            },
            ...prev,
          ]);
          return;
        }

        const headers = await getAuthHeaders();
        const res = await fetch('/api/sentinel/approvals', {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to queue defensive action.');
        await refreshOverview();
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to queue defensive action.');
      } finally {
        setBusyAction(null);
      }
    },
    [firebaseUser, getAuthHeaders, refreshOverview]
  );

  const decideApproval = useCallback(
    async (actionId: string, decision: 'approved' | 'rejected', decisionNote?: string) => {
      setBusyAction(`decide:${actionId}`);
      setErrorMessage(null);
      try {
        if (!firebaseUser) {
          const nowIso = new Date().toISOString();
          const target = approvals.find((a) => a.id === actionId);
          setApprovals((prev) =>
            prev.map((a) =>
              a.id === actionId
                ? {
                    ...a,
                    status: decision,
                    decidedBy: 'preview-operator',
                    decisionNote: decisionNote || '',
                    decidedAt: nowIso,
                  }
                : a
            )
          );
          if (decision === 'approved' && target?.actionType === 'isolate_server') {
            setAgents((prev) =>
              prev.map((ag) => (ag.id === target.agentId ? { ...ag, status: 'isolated' } : ag))
            );
          }
          setAuditLogs((prev) => [
            {
              id: `saud-${Date.now().toString(36)}`,
              action:
                decision === 'approved'
                  ? 'DEFENSIVE_ACTION_APPROVED'
                  : 'DEFENSIVE_ACTION_REJECTED',
              actor: 'preview-operator',
              targetId: actionId,
              severity: decision === 'approved' ? 'critical' : 'info',
              details: `Operator ${decision} defensive action ${actionId}. ${decisionNote || ''}`.trim(),
              createdAt: nowIso,
            },
            ...prev,
          ]);
          return;
        }

        const headers = await getAuthHeaders();
        const res = await fetch(`/api/sentinel/approvals/${encodeURIComponent(actionId)}/decision`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ decision, decisionNote: decisionNote || '' }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to record decision.');
        await refreshOverview();
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to record approval decision.');
      } finally {
        setBusyAction(null);
      }
    },
    [approvals, firebaseUser, getAuthHeaders, refreshOverview]
  );

  const clearError = useCallback(() => setErrorMessage(null), []);

  const value: SentinelContextValue = {
    agents,
    tokens,
    events,
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
  };

  return <SentinelContext.Provider value={value}>{children}</SentinelContext.Provider>;
};

export function useSentinel(): SentinelContextValue {
  const ctx = useContext(SentinelContext);
  if (!ctx) {
    throw new Error('useSentinel must be used within SentinelProvider');
  }
  return ctx;
}
