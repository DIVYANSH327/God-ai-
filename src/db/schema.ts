import { relations } from 'drizzle-orm';
import { integer, pgTable, text, timestamp } from 'drizzle-orm/pg-core';

// Linked to Firebase Auth UID directly as primary key for type-safe foreign keys
export const users = pgTable('users', {
  uid: text('uid').primaryKey(),
  email: text('email').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// Authorized enrolled servers running GOD Sentinel Micro Agent
export const sentinelAgents = pgTable('sentinel_agents', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .references(() => users.uid, { onDelete: 'cascade' })
    .notNull(),
  hostname: text('hostname').notNull(),
  region: text('region').notNull(),
  ipAddress: text('ip_address').notNull(),
  osType: text('os_type').notNull(), // 'linux' | 'windows'
  osVersion: text('os_version').notNull(),
  agentVersion: text('agent_version').notNull(),
  targetVersion: text('target_version').notNull(),
  status: text('status').notNull(), // 'online' | 'degraded' | 'offline' | 'isolated' | 'revoked'
  deviceTokenHash: text('device_token_hash').notNull(),
  cpuPercent: integer('cpu_percent').default(0).notNull(),
  ramPercent: integer('ram_percent').default(0).notNull(),
  diskPercent: integer('disk_percent').default(0).notNull(),
  uptimeSec: integer('uptime_sec').default(0).notNull(),
  servicesJson: text('services_json').default('[]').notNull(),
  resourceLimitsJson: text('resource_limits_json').notNull(),
  tagsJson: text('tags_json').default('[]').notNull(),
  lastHeartbeatAt: timestamp('last_heartbeat_at'),
  enrolledAt: timestamp('enrolled_at').defaultNow().notNull(),
  revokedAt: timestamp('revoked_at'),
});

// Single-use enrollment tokens (only SHA-256 hash is persisted)
export const sentinelEnrollmentTokens = pgTable('sentinel_enrollment_tokens', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .references(() => users.uid, { onDelete: 'cascade' })
    .notNull(),
  tokenHash: text('token_hash').notNull().unique(),
  tokenPrefix: text('token_prefix').notNull(),
  label: text('label').notNull(),
  region: text('region').notNull(),
  osType: text('os_type').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  usedAt: timestamp('used_at'),
  usedByAgentId: text('used_by_agent_id'),
  revokedAt: timestamp('revoked_at'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// Normalized, deduplicated security telemetry with provenance
export const sentinelEvents = pgTable('sentinel_events', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .references(() => users.uid, { onDelete: 'cascade' })
    .notNull(),
  agentId: text('agent_id')
    .references(() => sentinelAgents.id, { onDelete: 'cascade' })
    .notNull(),
  region: text('region').notNull(),
  hostname: text('hostname').notNull(),
  eventType: text('event_type').notNull(), // 'process' | 'auth' | 'network' | 'fim' | 'log' | 'heartbeat'
  severity: text('severity').notNull(), // 'info' | 'low' | 'medium' | 'high' | 'critical'
  fingerprint: text('fingerprint').notNull(),
  occurrenceCount: integer('occurrence_count').default(1).notNull(),
  summary: text('summary').notNull(),
  payloadJson: text('payload_json').notNull(),
  provenanceJson: text('provenance_json').notNull(),
  observedAt: timestamp('observed_at').notNull(),
  ingestedAt: timestamp('ingested_at').defaultNow().notNull(),
});

// Correlated incidents and Gemini Central Brain investigation reports
export const sentinelIncidents = pgTable('sentinel_incidents', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .references(() => users.uid, { onDelete: 'cascade' })
    .notNull(),
  title: text('title').notNull(),
  severity: text('severity').notNull(), // 'low' | 'medium' | 'high' | 'critical'
  status: text('status').notNull(), // 'open' | 'investigating' | 'contained' | 'resolved'
  region: text('region').notNull(),
  correlationType: text('correlation_type').notNull(),
  affectedAgentIdsJson: text('affected_agent_ids_json').notNull(),
  evidenceEventIdsJson: text('evidence_event_ids_json').notNull(),
  mitreTechniquesJson: text('mitre_techniques_json').notNull(),
  hypothesesJson: text('hypotheses_json').notNull(),
  timelineJson: text('timeline_json').notNull(),
  investigationReport: text('investigation_report').notNull(),
  confidenceScore: integer('confidence_score').default(0).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// Human-in-the-loop defensive remediation queue (never auto-executed)
export const sentinelApprovalActions = pgTable('sentinel_approval_actions', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .references(() => users.uid, { onDelete: 'cascade' })
    .notNull(),
  agentId: text('agent_id')
    .references(() => sentinelAgents.id, { onDelete: 'cascade' })
    .notNull(),
  incidentId: text('incident_id'),
  actionType: text('action_type').notNull(), // 'isolate_server' | 'terminate_process' | 'firewall_policy'
  targetDetail: text('target_detail').notNull(),
  rationale: text('rationale').notNull(),
  status: text('status').notNull(), // 'pending_approval' | 'approved' | 'rejected' | 'executed'
  requestedBy: text('requested_by').notNull(),
  decidedBy: text('decided_by'),
  decisionNote: text('decision_note'),
  requestedAt: timestamp('requested_at').defaultNow().notNull(),
  decidedAt: timestamp('decided_at'),
});

// Immutable administrative audit log for all Sentinel governance actions
export const sentinelAuditLogs = pgTable('sentinel_audit_logs', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .references(() => users.uid, { onDelete: 'cascade' })
    .notNull(),
  action: text('action').notNull(),
  actor: text('actor').notNull(),
  targetId: text('target_id').notNull(),
  severity: text('severity').default('info').notNull(),
  details: text('details').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const usersRelations = relations(users, ({ many }) => ({
  agents: many(sentinelAgents),
  enrollmentTokens: many(sentinelEnrollmentTokens),
  events: many(sentinelEvents),
  incidents: many(sentinelIncidents),
  approvalActions: many(sentinelApprovalActions),
  auditLogs: many(sentinelAuditLogs),
}));

export const sentinelAgentsRelations = relations(sentinelAgents, ({ one, many }) => ({
  owner: one(users, {
    fields: [sentinelAgents.userId],
    references: [users.uid],
  }),
  events: many(sentinelEvents),
  approvalActions: many(sentinelApprovalActions),
}));

export const sentinelEventsRelations = relations(sentinelEvents, ({ one }) => ({
  owner: one(users, {
    fields: [sentinelEvents.userId],
    references: [users.uid],
  }),
  agent: one(sentinelAgents, {
    fields: [sentinelEvents.agentId],
    references: [sentinelAgents.id],
  }),
}));

export const sentinelApprovalActionsRelations = relations(sentinelApprovalActions, ({ one }) => ({
  owner: one(users, {
    fields: [sentinelApprovalActions.userId],
    references: [users.uid],
  }),
  agent: one(sentinelAgents, {
    fields: [sentinelApprovalActions.agentId],
    references: [sentinelAgents.id],
  }),
}));
