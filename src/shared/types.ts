export type NavSection =
  | 'dashboard'
  | 'sentinel'
  | 'research'
  | 'webintel'
  | 'serverintel'
  | 'cveintel'
  | 'monitors'
  | 'knowledge'
  | 'network'
  | 'behaviour'
  | 'chat'
  | 'agents'
  | 'vision'
  | 'voice'
  | 'memory'
  | 'security'
  | 'automation'
  | 'settings';

export type IntentCategory =
  | 'chat'
  | 'research'
  | 'coding'
  | 'vision'
  | 'security'
  | 'automation';

export type ExecutionMode = 'cloud' | 'local' | 'hybrid';

export type AgentCapabilityStatus = 'operational' | 'prototype' | 'planned';

export type TaskStatus = 'queued' | 'in_progress' | 'completed' | 'archived';

export type TaskPriority = 'low' | 'medium' | 'high';

export type AuditCategory =
  | 'auth'
  | 'chat'
  | 'security'
  | 'sentinel'
  | 'settings'
  | 'memory'
  | 'task'
  | 'network'
  | 'research'
  | 'knowledge'
  | 'behaviour';

export type AuditSeverity = 'info' | 'warning' | 'critical';

export interface UserProfileRecord {
  uid: string;
  displayName: string;
  photoURL: string;
  executionMode: ExecutionMode;
  emergencyStop: boolean;
  allowWebResearch: boolean;
  allowFileAnalysis: boolean;
  allowLocalBridge: boolean;
  allowAutomationQueue: boolean;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface ConversationRecord {
  id: string;
  userId: string;
  title: string;
  lastIntent: IntentCategory;
  lastMessagePreview: string;
  messageCount: number;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface MessageRecord {
  id: string;
  conversationId: string;
  userId: string;
  role: 'user' | 'assistant';
  content: string;
  intent: IntentCategory;
  agentModuleNote: string;
  modelUsed: string;
  createdAtMs: number;
}

export interface TaskRecord {
  id: string;
  userId: string;
  title: string;
  category: IntentCategory;
  status: TaskStatus;
  priority: TaskPriority;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface AuditEventRecord {
  id: string;
  userId: string;
  action: string;
  category: AuditCategory;
  severity: AuditSeverity;
  summary: string;
  createdAtMs: number;
}

export interface AgentDefinition {
  id: string;
  name: string;
  codename: string;
  intentMapping: IntentCategory | 'memory' | 'voice';
  status: AgentCapabilityStatus;
  versionTarget: string;
  summary: string;
  description: string;
  capabilities: string[];
  v01Behavior: string;
  securityBoundary: string;
  providerTarget: string;
}

export interface ProviderDescriptor {
  id: string;
  name: string;
  environment: 'cloud' | 'local';
  status: 'active' | 'unpaired_disabled';
  defaultModel: string;
  transport: string;
  summary: string;
}

export interface IntentClassificationResult {
  intent: IntentCategory;
  confidence: number;
  executedBy: 'god-core-gemini-cloud' | 'blocked-policy' | 'blocked-local-unpaired' | 'blocked-emergency-stop';
  specialistStatus: AgentCapabilityStatus;
  agentModuleNote: string;
  policyBlockedReason?: string;
}
