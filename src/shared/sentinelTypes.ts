export const SENTINEL_VERSION = '0.8.0';

export type SentinelOsType = 'linux' | 'windows';

export type SentinelAgentStatus =
  | 'online'
  | 'degraded'
  | 'offline'
  | 'isolated'
  | 'revoked';

export type SentinelEventType =
  | 'process'
  | 'auth'
  | 'network'
  | 'fim'
  | 'log'
  | 'heartbeat';

export type SentinelSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SentinelIncidentStatus =
  | 'open'
  | 'investigating'
  | 'contained'
  | 'resolved';

export type DefensiveActionType =
  | 'isolate_server'
  | 'terminate_process'
  | 'firewall_policy';

export type ApprovalActionStatus =
  | 'pending_approval'
  | 'approved'
  | 'rejected'
  | 'executed';

export interface SentinelServiceStatus {
  name: string;
  state: 'running' | 'stopped' | 'degraded';
  pid?: number;
}

export interface SentinelResourceLimits {
  maxCpuPercent: number;
  maxMemoryMb: number;
  maxEventsPerMinute: number;
  heartbeatIntervalSec: number;
  offlineBufferMaxEvents: number;
}

export interface SentinelAgentRecord {
  id: string;
  hostname: string;
  region: string;
  ipAddress: string;
  osType: SentinelOsType;
  osVersion: string;
  agentVersion: string;
  targetVersion: string;
  status: SentinelAgentStatus;
  cpuPercent: number;
  ramPercent: number;
  diskPercent: number;
  uptimeSec: number;
  services: SentinelServiceStatus[];
  resourceLimits: SentinelResourceLimits;
  tags: string[];
  lastHeartbeatAt: string | null;
  enrolledAt: string;
  revokedAt: string | null;
}

export interface SentinelEnrollmentTokenRecord {
  id: string;
  tokenPrefix: string;
  label: string;
  region: string;
  osType: SentinelOsType;
  expiresAt: string;
  usedAt: string | null;
  usedByAgentId: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface SentinelEventProvenance {
  agentId: string;
  agentVersion: string;
  hostname: string;
  region: string;
  collector: string;
  receivedAtIso: string;
  bufferedOffline: boolean;
  retryAttempt: number;
  redactedFields: string[];
  simulatedDrill?: boolean;
}

export interface SentinelEventRecord {
  id: string;
  agentId: string;
  region: string;
  hostname: string;
  eventType: SentinelEventType;
  severity: SentinelSeverity;
  fingerprint: string;
  occurrenceCount: number;
  summary: string;
  payload: Record<string, unknown>;
  provenance: SentinelEventProvenance;
  observedAt: string;
  ingestedAt: string;
}

export interface MitreTechniqueMapping {
  techniqueId: string;
  tactic: string;
  name: string;
  confidence: number;
  evidenceSummary: string;
}

export interface InvestigationHypothesis {
  id: string;
  title: string;
  likelihood: 'high' | 'medium' | 'low';
  supportingEvidence: string[];
  refutingOrGaps: string[];
}

export interface IncidentTimelineEntry {
  timestamp: string;
  hostname: string;
  eventType: SentinelEventType | 'correlation' | 'governance';
  description: string;
  eventId?: string;
}

export interface SentinelIncidentRecord {
  id: string;
  title: string;
  severity: Exclude<SentinelSeverity, 'info'>;
  status: SentinelIncidentStatus;
  region: string;
  correlationType:
    | 'lateral_movement'
    | 'unusual_auth'
    | 'suspicious_process_network'
    | 'file_integrity_tamper'
    | 'multi_signal_intrusion';
  affectedAgentIds: string[];
  evidenceEventIds: string[];
  mitreTechniques: MitreTechniqueMapping[];
  hypotheses: InvestigationHypothesis[];
  timeline: IncidentTimelineEntry[];
  investigationReport: string;
  confidenceScore: number;
  createdAt: string;
  updatedAt: string;
}

export interface SentinelApprovalActionRecord {
  id: string;
  agentId: string;
  incidentId: string | null;
  actionType: DefensiveActionType;
  targetDetail: string;
  rationale: string;
  status: ApprovalActionStatus;
  requestedBy: string;
  decidedBy: string | null;
  decisionNote: string | null;
  requestedAt: string;
  decidedAt: string | null;
}

export interface SentinelAuditLogRecord {
  id: string;
  action: string;
  actor: string;
  targetId: string;
  severity: 'info' | 'warning' | 'critical';
  details: string;
  createdAt: string;
}

export interface RegionalCorrelationFinding {
  correlationType: SentinelIncidentRecord['correlationType'];
  region: string;
  severity: Exclude<SentinelSeverity, 'info'>;
  title: string;
  summary: string;
  affectedAgentIds: string[];
  evidenceEventIds: string[];
  mitreTechniques: MitreTechniqueMapping[];
  recommendedAction?: {
    agentId: string;
    actionType: DefensiveActionType;
    targetDetail: string;
    rationale: string;
  };
}

export interface SentinelTopologyNode {
  id: string;
  label: string;
  kind: 'agent' | 'external_peer';
  region: string;
  osType?: SentinelOsType;
  status: SentinelAgentStatus | 'external_observed' | 'external_flagged';
  alertCount: number;
  ipAddress: string;
}

export interface SentinelTopologyEdge {
  id: string;
  source: string;
  target: string;
  protocol: string;
  port: number;
  suspicious: boolean;
  label: string;
}

export interface SentinelQueueMetrics {
  pendingDepth: number;
  totalReceived: number;
  totalDeduplicated: number;
  totalPersisted: number;
  deadLetterCount: number;
}
