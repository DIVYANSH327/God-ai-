export type GinNavSection =
  | 'dashboard'
  | 'network'
  | 'research'
  | 'behaviour'
  | 'knowledge'
  | 'chat'
  | 'agents'
  | 'vision'
  | 'voice'
  | 'memory'
  | 'security'
  | 'automation'
  | 'settings';

export type AccessRole = 'operator' | 'analyst' | 'admin';

export type NetworkAssetType = 'gateway' | 'workstation' | 'server' | 'sensor' | 'kali_node' | 'windows_node';

export type NetworkAssetStatus = 'nominal' | 'degraded' | 'anomalous' | 'isolated';

export interface NetworkAssetRecord {
  id: string;
  userId: string;
  hostname: string;
  ipRange: string;
  authorizedScope: string;
  assetType: NetworkAssetType;
  status: NetworkAssetStatus;
  dnsQueriesPerMin: number;
  nxdomainRatio: number;
  outboundMbps: number;
  baselineMbps: number;
  anomalyScore: number;
  threatMatch: string;
  lastSeenMs: number;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface ResearchSourceCitation {
  title: string;
  uri: string;
  domain: string;
}

export interface ResearchReportRecord {
  id: string;
  userId: string;
  query: string;
  summary: string;
  facts: string[];
  predictions: string[];
  confidenceScore: number;
  sources: ResearchSourceCitation[];
  scheduleCadence: 'manual' | 'daily' | 'weekly';
  createdAtMs: number;
}

export type KnowledgeEntityType =
  | 'concept'
  | 'organization'
  | 'technology'
  | 'asset'
  | 'threat'
  | 'protocol'
  | 'vulnerability'
  | 'framework'
  | 'infrastructure';

export interface KnowledgeRelation {
  targetId: string;
  targetLabel: string;
  predicate: string;
}

export interface KnowledgeNodeRecord {
  id: string;
  userId: string;
  label: string;
  entityType: KnowledgeEntityType;
  claim: string;
  sourceTitle: string;
  sourceUri: string;
  confidenceScore: number;
  confidenceExplanation?: string;
  relations: KnowledgeRelation[];
  createdAtMs: number;
  updatedAtMs: number;
}

export interface BehaviourInsightRecord {
  id: string;
  userId: string;
  title: string;
  domain: 'network' | 'internet' | 'hybrid';
  severity: 'info' | 'warning' | 'critical';
  confidenceScore: number;
  facts: string[];
  predictions: string[];
  explanation: string;
  sourceRefs: string[];
  createdAtMs: number;
}

export interface RobotsCheckResult {
  origin: string;
  robotsUrl: string;
  reachable: boolean;
  allowedForGinBot: boolean;
  crawlDelaySeconds: number | null;
  disallowedPaths: string[];
  policySummary: string;
}

export interface BrainPlanStep {
  stepNumber: number;
  agentModule: string;
  objective: string;
  verificationCriteria: string;
  status: 'ready_v02' | 'prototype' | 'planned';
}

export interface BrainResearchPlan {
  objective: string;
  strategySummary: string;
  confidenceScore: number;
  steps: BrainPlanStep[];
  verificationChecklist: string[];
}

export interface KnowledgeConflictFinding {
  kind: 'duplicate' | 'contradiction';
  nodeAId: string;
  nodeALabel: string;
  nodeBId: string;
  nodeBLabel: string;
  reason: string;
}

export interface SensorNodeInterfaceSpec {
  id: string;
  platform: 'Windows 11' | 'Kali Linux' | 'Cloud Passive Sensor';
  transport: string;
  authMechanism: string;
  permittedTelemetry: string[];
  prohibitedCapabilities: string[];
  enrollmentStatus: 'unpaired_v02_spec' | 'active_cloud_ingestion';
}
