import type {
  DefensiveActionType,
  IncidentTimelineEntry,
  MitreTechniqueMapping,
  RegionalCorrelationFinding,
  SentinelAgentRecord,
  SentinelAgentStatus,
  SentinelEventRecord,
  SentinelEventType,
  SentinelResourceLimits,
  SentinelSeverity,
  SentinelTopologyEdge,
  SentinelTopologyNode,
} from './sentinelTypes.ts';

export const DEFAULT_RESOURCE_LIMITS: SentinelResourceLimits = {
  maxCpuPercent: 5,
  maxMemoryMb: 64,
  maxEventsPerMinute: 120,
  heartbeatIntervalSec: 30,
  offlineBufferMaxEvents: 5000,
};

const FORBIDDEN_CREDENTIAL_KEY_RE =
  /(password|passwd|secret|private[_-]?key|access[_-]?token|refresh[_-]?token|api[_-]?key|shadow|ntlm|cookie|authorization|bearer|credential)/i;

const FORBIDDEN_CREDENTIAL_VALUE_RE =
  /(-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})/i;

const ALLOWED_EVENT_TYPES: ReadonlySet<SentinelEventType> = new Set([
  'process',
  'auth',
  'network',
  'fim',
  'log',
  'heartbeat',
]);

const ALLOWED_SEVERITIES: ReadonlySet<SentinelSeverity> = new Set([
  'info',
  'low',
  'medium',
  'high',
  'critical',
]);

const ALLOWED_DEFENSIVE_ACTIONS: ReadonlySet<DefensiveActionType> = new Set([
  'isolate_server',
  'terminate_process',
  'firewall_policy',
]);

const FORBIDDEN_REMOTE_SHELL_RE =
  /(reverse[_-]?shell|remote[_-]?shell|interactive[_-]?shell|exec[_-]?arbitrary|bash\s+-i|nc\s+-e|powershell\s+-enc|rm\s+-rf|format\s+c:|mkfs|wipe[_-]?disk)/i;

const SUSPICIOUS_PROCESS_RE =
  /(\/tmp\/|\/dev\/shm\/|curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash)|base64\s+-d|nc\s+-|python3?\s+-c|powershell.*-encodedcommand|certutil\s+-urlcache|xmrig|socat\s+)/i;

const CRITICAL_FIM_PATHS = [
  '/etc/ssh/sshd_config',
  '/etc/sudoers',
  '/etc/passwd',
  '/etc/crontab',
  '/etc/ld.so.preload',
  'c:\\windows\\system32\\drivers\\etc\\hosts',
];

const SUSPICIOUS_EGRESS_PORTS = new Set([4444, 1337, 5555, 6667, 8443, 9001, 31337]);

/**
 * Deterministic 64-bit hex hash (FNV-1a pair) usable in both browser and Node without crypto deps.
 */
export function stableFingerprint(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x811c9dc5 ^ 0x9e3779b9;
  for (let i = 0; i < input.length; i += 1) {
    const ch = input.charCodeAt(i);
    h1 ^= ch;
    h1 = Math.imul(h1, 0x01000193);
    h2 ^= ch + ((i & 0xff) << 1);
    h2 = Math.imul(h2, 0x01000193);
  }
  return `${(h1 >>> 0).toString(16).padStart(8, '0')}${(h2 >>> 0).toString(16).padStart(8, '0')}`;
}

/**
 * Scrubs credential-like keys or secret values from telemetry payloads so GOD Sentinel
 * strictly upholds the "No credential collection" safety rule.
 */
export function scrubSensitiveTelemetryPayload(
  payload: Record<string, unknown>
): { sanitized: Record<string, unknown>; redactedFields: string[] } {
  const redactedFields: string[] = [];

  const cleanValue = (key: string, val: unknown, depth: number): unknown => {
    if (depth > 4) return '[TRUNCATED]';
    if (FORBIDDEN_CREDENTIAL_KEY_RE.test(key)) {
      redactedFields.push(key);
      return '[REDACTED_BY_SAFETY_POLICY]';
    }
    if (typeof val === 'string') {
      if (FORBIDDEN_CREDENTIAL_VALUE_RE.test(val)) {
        redactedFields.push(key);
        return '[REDACTED_SECRET_PATTERN]';
      }
      return val.slice(0, 600);
    }
    if (Array.isArray(val)) {
      return val.slice(0, 40).map((item, idx) => cleanValue(`${key}[${idx}]`, item, depth + 1));
    }
    if (val && typeof val === 'object') {
      const nested: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
        nested[k] = cleanValue(k, v, depth + 1);
      }
      return nested;
    }
    return val;
  };

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload || {})) {
    sanitized[key] = cleanValue(key, value, 0);
  }
  return { sanitized, redactedFields };
}

export interface RawSentinelEventInput {
  eventType: string;
  severity?: string;
  summary: string;
  payload?: Record<string, unknown>;
  collector?: string;
  observedAt?: string;
  bufferedOffline?: boolean;
  retryAttempt?: number;
  simulatedDrill?: boolean;
}

export interface AgentProvenanceContext {
  agentId: string;
  agentVersion: string;
  hostname: string;
  region: string;
}

export function normalizeSentinelEvent(
  raw: RawSentinelEventInput,
  agent: AgentProvenanceContext,
  nowIso = new Date().toISOString()
): Omit<SentinelEventRecord, 'id'> {
  const eventType: SentinelEventType = ALLOWED_EVENT_TYPES.has(raw.eventType as SentinelEventType)
    ? (raw.eventType as SentinelEventType)
    : 'log';

  const { sanitized, redactedFields } = scrubSensitiveTelemetryPayload(raw.payload || {});
  const summary = String(raw.summary || `${eventType} telemetry event`)
    .replace(FORBIDDEN_CREDENTIAL_VALUE_RE, '[REDACTED_SECRET]')
    .trim()
    .slice(0, 320);

  let severity: SentinelSeverity = ALLOWED_SEVERITIES.has(raw.severity as SentinelSeverity)
    ? (raw.severity as SentinelSeverity)
    : 'info';

  // Automatic defensive severity elevation when clear high-risk indicators appear
  const serialized = JSON.stringify(sanitized).toLowerCase();
  if (eventType === 'process' && SUSPICIOUS_PROCESS_RE.test(`${summary} ${serialized}`)) {
    severity = severity === 'critical' ? 'critical' : 'high';
  }
  if (
    eventType === 'fim' &&
    CRITICAL_FIM_PATHS.some((p) => serialized.includes(p) || summary.toLowerCase().includes(p))
  ) {
    severity = 'critical';
  }
  if (eventType === 'network') {
    const port = Number(sanitized.remotePort ?? sanitized.dstPort ?? 0);
    if (SUSPICIOUS_EGRESS_PORTS.has(port)) {
      severity = severity === 'critical' ? 'critical' : 'high';
    }
  }

  const parsedObserved = raw.observedAt ? new Date(raw.observedAt) : new Date(nowIso);
  const observedAt = Number.isNaN(parsedObserved.getTime())
    ? nowIso
    : parsedObserved.toISOString();

  // Deduplication fingerprint based on agent, eventType, canonical key attributes, and summary
  const fpSource = [
    agent.agentId,
    eventType,
    summary.toLowerCase().replace(/\b\d{4,}\b/g, '<num>'),
    String(sanitized.processName ?? sanitized.command ?? sanitized.filePath ?? sanitized.remoteIp ?? sanitized.sourceIp ?? ''),
    String(sanitized.remotePort ?? sanitized.username ?? sanitized.action ?? ''),
  ].join('|');

  const fingerprint = stableFingerprint(fpSource);

  return {
    agentId: agent.agentId,
    region: agent.region,
    hostname: agent.hostname,
    eventType,
    severity,
    fingerprint,
    occurrenceCount: 1,
    summary,
    payload: sanitized,
    provenance: {
      agentId: agent.agentId,
      agentVersion: agent.agentVersion,
      hostname: agent.hostname,
      region: agent.region,
      collector: String(raw.collector || `sentinel-${eventType}-collector`).slice(0, 80),
      receivedAtIso: nowIso,
      bufferedOffline: Boolean(raw.bufferedOffline),
      retryAttempt: Math.max(0, Math.min(20, Number(raw.retryAttempt || 0))),
      redactedFields,
      ...(raw.simulatedDrill ? { simulatedDrill: true } : {}),
    },
    observedAt,
    ingestedAt: nowIso,
  };
}

export function deduplicateNormalizedEvents(
  events: Array<Omit<SentinelEventRecord, 'id'>>
): { deduplicated: Array<Omit<SentinelEventRecord, 'id'>>; collapsedCount: number } {
  const byFingerprint = new Map<string, Omit<SentinelEventRecord, 'id'>>();
  let collapsedCount = 0;

  for (const evt of events) {
    const existing = byFingerprint.get(evt.fingerprint);
    if (existing) {
      existing.occurrenceCount += evt.occurrenceCount;
      if (evt.observedAt > existing.observedAt) {
        existing.observedAt = evt.observedAt;
      }
      collapsedCount += 1;
    } else {
      byFingerprint.set(evt.fingerprint, { ...evt });
    }
  }

  return {
    deduplicated: Array.from(byFingerprint.values()),
    collapsedCount,
  };
}

export function deriveAgentHealthStatus(
  agent: Pick<
    SentinelAgentRecord,
    'status' | 'cpuPercent' | 'ramPercent' | 'diskPercent' | 'lastHeartbeatAt' | 'resourceLimits'
  >,
  nowMs = Date.now()
): SentinelAgentStatus {
  if (agent.status === 'revoked' || agent.status === 'isolated') {
    return agent.status;
  }
  if (!agent.lastHeartbeatAt) {
    return 'offline';
  }
  const hbMs = new Date(agent.lastHeartbeatAt).getTime();
  if (Number.isNaN(hbMs)) return 'offline';

  const staleThresholdMs = Math.max(90_000, (agent.resourceLimits?.heartbeatIntervalSec || 30) * 3500);
  if (nowMs - hbMs > staleThresholdMs) {
    return 'offline';
  }
  if (agent.cpuPercent >= 88 || agent.ramPercent >= 90 || agent.diskPercent >= 92) {
    return 'degraded';
  }
  return 'online';
}

export function mapHeuristicMitreTechniques(
  events: SentinelEventRecord[]
): MitreTechniqueMapping[] {
  const mapped = new Map<string, MitreTechniqueMapping>();

  for (const ev of events) {
    const text = `${ev.summary} ${JSON.stringify(ev.payload)}`.toLowerCase();
    if (ev.eventType === 'auth' && (text.includes('failed') || text.includes('brute') || text.includes('invalid user'))) {
      mapped.set('T1110', {
        techniqueId: 'T1110',
        tactic: 'Credential Access',
        name: 'Brute Force',
        confidence: 86,
        evidenceSummary: `Repeated authentication failures observed on ${ev.hostname} (${ev.occurrenceCount}x).`,
      });
    }
    if (
      (ev.eventType === 'auth' || ev.eventType === 'network') &&
      (text.includes('ssh') || text.includes('port 22') || text.includes('rdp') || text.includes('3389')) &&
      (text.includes('accepted') || text.includes('pivot') || text.includes('lateral'))
    ) {
      mapped.set('T1021.004', {
        techniqueId: 'T1021.004',
        tactic: 'Lateral Movement',
        name: 'Remote Services: SSH / Admin Pivot',
        confidence: 84,
        evidenceSummary: `Cross-host remote administrative session activity traced on ${ev.hostname}.`,
      });
    }
    if (ev.eventType === 'process' && SUSPICIOUS_PROCESS_RE.test(text)) {
      const isPowerShell = text.includes('powershell') || text.includes('certutil');
      const id = isPowerShell ? 'T1059.001' : 'T1059.004';
      mapped.set(id, {
        techniqueId: id,
        tactic: 'Execution',
        name: isPowerShell
          ? 'Command and Scripting Interpreter: PowerShell'
          : 'Command and Scripting Interpreter: Unix Shell',
        confidence: 91,
        evidenceSummary: `Suspicious process execution on ${ev.hostname}: ${ev.summary}`,
      });
    }
    if (ev.eventType === 'fim') {
      mapped.set('T1565.001', {
        techniqueId: 'T1565.001',
        tactic: 'Impact / Persistence',
        name: 'Stored Data Manipulation / Critical Config Tampering',
        confidence: 93,
        evidenceSummary: `File integrity checksum drift detected on ${ev.hostname}: ${ev.summary}`,
      });
    }
    if (ev.eventType === 'network') {
      const port = Number(ev.payload.remotePort ?? ev.payload.dstPort ?? 0);
      if (SUSPICIOUS_EGRESS_PORTS.has(port) || ev.severity === 'high' || ev.severity === 'critical') {
        mapped.set('T1071.001', {
          techniqueId: 'T1071.001',
          tactic: 'Command and Control',
          name: 'Application Layer Protocol / Non-Standard Egress',
          confidence: 82,
          evidenceSummary: `Suspicious outbound connection metadata on ${ev.hostname} (port ${port || 'unknown'}).`,
        });
      }
    }
  }

  return Array.from(mapped.values());
}

/**
 * Regional Intelligence Correlation Engine:
 * Correlates telemetry across multiple servers to identify lateral movement,
 * unusual authentication patterns, suspicious process+network chains, and FIM tampering.
 */
export function evaluateRegionalIntelligence(
  agents: SentinelAgentRecord[],
  events: SentinelEventRecord[]
): RegionalCorrelationFinding[] {
  const findings: RegionalCorrelationFinding[] = [];
  const agentById = new Map(agents.map((a) => [a.id, a]));

  // 1. Cross-server source IP / user pivot correlation (Lateral Movement & Auth Spray)
  const authEventsBySourceIp = new Map<string, SentinelEventRecord[]>();
  for (const ev of events) {
    if (ev.eventType !== 'auth' && ev.eventType !== 'network') continue;
    const srcIp = String(ev.payload.sourceIp ?? ev.payload.remoteIp ?? '').trim();
    if (!srcIp) continue;
    const list = authEventsBySourceIp.get(srcIp) || [];
    list.push(ev);
    authEventsBySourceIp.set(srcIp, list);
  }

  for (const [srcIp, related] of authEventsBySourceIp.entries()) {
    const distinctAgents = Array.from(new Set(related.map((e) => e.agentId)));
    const hasAuthFailure = related.some(
      (e) =>
        e.eventType === 'auth' &&
        (e.severity === 'high' ||
          e.severity === 'critical' ||
          /failed|brute|invalid/i.test(e.summary) ||
          e.occurrenceCount >= 3)
    );
    const hasAuthSuccessOrSsh = related.some(
      (e) =>
        /accepted|session opened|ssh|rdp|pivot/i.test(`${e.summary} ${JSON.stringify(e.payload)}`)
    );

    if (distinctAgents.length >= 2 && (hasAuthFailure || hasAuthSuccessOrSsh)) {
      const regions = Array.from(new Set(related.map((e) => e.region)));
      const primaryAgentId = distinctAgents[0];
      const hostnames = distinctAgents.map((id) => agentById.get(id)?.hostname || id);
      findings.push({
        correlationType: hasAuthSuccessOrSsh ? 'lateral_movement' : 'unusual_auth',
        region: regions.length === 1 ? regions[0] : 'multi-region',
        severity: hasAuthSuccessOrSsh ? 'critical' : 'high',
        title: hasAuthSuccessOrSsh
          ? `Possible Lateral Movement from ${srcIp} across ${distinctAgents.length} servers`
          : `Distributed Authentication Spray from ${srcIp} (${distinctAgents.length} hosts)`,
        summary: `Source ${srcIp} touched ${hostnames.join(', ')} with ${related.length} correlated auth/network records.`,
        affectedAgentIds: distinctAgents,
        evidenceEventIds: related.map((e) => e.id),
        mitreTechniques: mapHeuristicMitreTechniques(related),
        recommendedAction: {
          agentId: primaryAgentId,
          actionType: 'firewall_policy',
          targetDetail: `Block ingress/egress peer ${srcIp} on ports 22, 3389`,
          rationale: `Observed correlated multi-host activity from ${srcIp} across ${hostnames.join(', ')}. Requires operator review before applying firewall rule.`,
        },
      });
    }
  }

  // 2. Per-host multi-signal intrusion chain (Suspicious process + Network egress or FIM tamper)
  const eventsByAgent = new Map<string, SentinelEventRecord[]>();
  for (const ev of events) {
    const arr = eventsByAgent.get(ev.agentId) || [];
    arr.push(ev);
    eventsByAgent.set(ev.agentId, arr);
  }

  for (const [agentId, hostEvents] of eventsByAgent.entries()) {
    const suspiciousProcs = hostEvents.filter(
      (e) =>
        e.eventType === 'process' &&
        (e.severity === 'high' ||
          e.severity === 'critical' ||
          SUSPICIOUS_PROCESS_RE.test(`${e.summary} ${JSON.stringify(e.payload)}`))
    );
    const suspiciousNet = hostEvents.filter(
      (e) =>
        e.eventType === 'network' &&
        (e.severity === 'high' ||
          e.severity === 'critical' ||
          SUSPICIOUS_EGRESS_PORTS.has(Number(e.payload.remotePort ?? e.payload.dstPort ?? 0)))
    );
    const fimAlerts = hostEvents.filter(
      (e) => e.eventType === 'fim' && (e.severity === 'high' || e.severity === 'critical')
    );

    const combined = [...suspiciousProcs, ...suspiciousNet, ...fimAlerts];
    if (combined.length >= 2 || (suspiciousProcs.length >= 1 && (suspiciousNet.length >= 1 || fimAlerts.length >= 1))) {
      const agent = agentById.get(agentId);
      const hostname = agent?.hostname || hostEvents[0]?.hostname || agentId;
      const region = agent?.region || hostEvents[0]?.region || 'unknown';
      const firstPid = suspiciousProcs[0]?.payload?.pid;
      const firstProcName = String(
        suspiciousProcs[0]?.payload?.processName || suspiciousProcs[0]?.payload?.command || 'suspicious-process'
      );

      findings.push({
        correlationType: fimAlerts.length > 0 ? 'multi_signal_intrusion' : 'suspicious_process_network',
        region,
        severity: fimAlerts.length > 0 || suspiciousProcs.some((p) => p.severity === 'critical') ? 'critical' : 'high',
        title: `Multi-Signal Suspicious Execution & Integrity Chain on ${hostname}`,
        summary: `Detected ${suspiciousProcs.length} suspicious process, ${suspiciousNet.length} anomalous network egress, and ${fimAlerts.length} critical file integrity events on ${hostname}.`,
        affectedAgentIds: [agentId],
        evidenceEventIds: combined.map((e) => e.id),
        mitreTechniques: mapHeuristicMitreTechniques(combined),
        recommendedAction: suspiciousProcs.length > 0
          ? {
              agentId,
              actionType: 'terminate_process',
              targetDetail: firstPid ? `PID ${firstPid} (${firstProcName})` : firstProcName,
              rationale: `Correlated suspicious execution with outbound network/FIM drift on ${hostname}. Human confirmation required before process termination.`,
            }
          : {
              agentId,
              actionType: 'isolate_server',
              targetDetail: `Quarantine host ${hostname} (${agent?.ipAddress || 'unknown IP'})`,
              rationale: `Critical file integrity modification detected on ${hostname}. Human approval required before host isolation.`,
            },
      });
    } else if (fimAlerts.length === 1) {
      const agent = agentById.get(agentId);
      const hostname = agent?.hostname || fimAlerts[0].hostname;
      findings.push({
        correlationType: 'file_integrity_tamper',
        region: agent?.region || fimAlerts[0].region,
        severity: 'high',
        title: `Critical File Integrity Drift on ${hostname}`,
        summary: fimAlerts[0].summary,
        affectedAgentIds: [agentId],
        evidenceEventIds: fimAlerts.map((e) => e.id),
        mitreTechniques: mapHeuristicMitreTechniques(fimAlerts),
        recommendedAction: {
          agentId,
          actionType: 'isolate_server',
          targetDetail: `Quarantine host ${hostname} pending forensic diff`,
          rationale: `Critical system configuration checksum changed unexpectedly on ${hostname}.`,
        },
      });
    }
  }

  return findings;
}

export function buildIncidentTimeline(events: SentinelEventRecord[]): IncidentTimelineEntry[] {
  return [...events]
    .sort((a, b) => new Date(a.observedAt).getTime() - new Date(b.observedAt).getTime())
    .map((ev) => ({
      timestamp: ev.observedAt,
      hostname: ev.hostname,
      eventType: ev.eventType,
      description: `${ev.summary}${ev.occurrenceCount > 1 ? ` (deduplicated ×${ev.occurrenceCount})` : ''}`,
      eventId: ev.id,
    }));
}

export function validateDefensiveActionRequest(input: {
  agentId: string;
  actionType: string;
  targetDetail: string;
  rationale: string;
}): { valid: boolean; error?: string; actionType?: DefensiveActionType } {
  const agentId = String(input.agentId || '').trim();
  const actionType = String(input.actionType || '').trim();
  const targetDetail = String(input.targetDetail || '').trim();
  const rationale = String(input.rationale || '').trim();

  if (!agentId) {
    return { valid: false, error: 'Target enrolled server ID is required.' };
  }
  if (!ALLOWED_DEFENSIVE_ACTIONS.has(actionType as DefensiveActionType)) {
    return {
      valid: false,
      error:
        'Only bounded defensive actions (isolate_server, terminate_process, firewall_policy) are permitted. Unrestricted remote shells are disabled by design.',
    };
  }
  if (targetDetail.length < 3 || targetDetail.length > 240) {
    return { valid: false, error: 'Action target detail must be between 3 and 240 characters.' };
  }
  if (rationale.length < 8 || rationale.length > 500) {
    return { valid: false, error: 'Operator rationale must be between 8 and 500 characters.' };
  }
  if (FORBIDDEN_REMOTE_SHELL_RE.test(targetDetail) || FORBIDDEN_REMOTE_SHELL_RE.test(rationale)) {
    return {
      valid: false,
      error: 'Blocked by Sentinel Safety Policy: arbitrary shell commands and destructive disk operations are prohibited.',
    };
  }
  return { valid: true, actionType: actionType as DefensiveActionType };
}

export function buildSentinelTopology(
  agents: SentinelAgentRecord[],
  events: SentinelEventRecord[]
): { nodes: SentinelTopologyNode[]; edges: SentinelTopologyEdge[] } {
  const alertCounts = new Map<string, number>();
  for (const ev of events) {
    if (ev.severity === 'high' || ev.severity === 'critical') {
      alertCounts.set(ev.agentId, (alertCounts.get(ev.agentId) || 0) + 1);
    }
  }

  const nodes: SentinelTopologyNode[] = agents.map((agent) => ({
    id: agent.id,
    label: agent.hostname,
    kind: 'agent',
    region: agent.region,
    osType: agent.osType,
    status: deriveAgentHealthStatus(agent),
    alertCount: alertCounts.get(agent.id) || 0,
    ipAddress: agent.ipAddress,
  }));

  const agentByIp = new Map(agents.map((a) => [a.ipAddress, a]));
  const externalNodes = new Map<string, SentinelTopologyNode>();
  const edgesMap = new Map<string, SentinelTopologyEdge>();

  for (const ev of events) {
    if (ev.eventType !== 'network' && ev.eventType !== 'auth') continue;
    const peerIp = String(ev.payload.remoteIp ?? ev.payload.sourceIp ?? '').trim();
    if (!peerIp) continue;
    const port = Number(ev.payload.remotePort ?? ev.payload.dstPort ?? (ev.eventType === 'auth' ? 22 : 443));
    const protocol = String(ev.payload.protocol ?? 'TCP').toUpperCase();
    const suspicious =
      ev.severity === 'high' || ev.severity === 'critical' || SUSPICIOUS_EGRESS_PORTS.has(port);

    const matchedAgent = agentByIp.get(peerIp);
    let targetId: string;
    if (matchedAgent && matchedAgent.id !== ev.agentId) {
      targetId = matchedAgent.id;
    } else {
      targetId = `ext-${stableFingerprint(peerIp).slice(0, 8)}`;
      const existingExt = externalNodes.get(targetId);
      externalNodes.set(targetId, {
        id: targetId,
        label: peerIp,
        kind: 'external_peer',
        region: 'external',
        status:
          suspicious || existingExt?.status === 'external_flagged'
            ? 'external_flagged'
            : 'external_observed',
        alertCount: (existingExt?.alertCount || 0) + (suspicious ? 1 : 0),
        ipAddress: peerIp,
      });
    }

    const edgeKey = `${ev.agentId}->${targetId}:${port}`;
    const existingEdge = edgesMap.get(edgeKey);
    edgesMap.set(edgeKey, {
      id: edgeKey,
      source: ev.agentId,
      target: targetId,
      protocol,
      port,
      suspicious: Boolean(suspicious || existingEdge?.suspicious),
      label: `${protocol}/${port}`,
    });
  }

  return {
    nodes: [...nodes, ...Array.from(externalNodes.values())],
    edges: Array.from(edgesMap.values()),
  };
}
