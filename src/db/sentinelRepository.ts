import crypto from 'node:crypto';
import { and, desc, eq, gte, isNull } from 'drizzle-orm';
import { db } from './index.ts';
import {
  sentinelAgents,
  sentinelApprovalActions,
  sentinelAuditLogs,
  sentinelEnrollmentTokens,
  sentinelEvents,
  sentinelIncidents,
  users,
} from './schema.ts';
import {
  DEFAULT_RESOURCE_LIMITS,
  deriveAgentHealthStatus,
} from '../shared/sentinelAnalytics.ts';
import {
  SENTINEL_VERSION,
  type DefensiveActionType,
  type SentinelAgentRecord,
  type SentinelApprovalActionRecord,
  type SentinelAuditLogRecord,
  type SentinelEnrollmentTokenRecord,
  type SentinelEventRecord,
  type SentinelIncidentRecord,
  type SentinelOsType,
  type SentinelResourceLimits,
  type SentinelServiceStatus,
} from '../shared/sentinelTypes.ts';

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function safeJsonParse<T>(raw: string, fallback: T): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function mapAgentRow(row: typeof sentinelAgents.$inferSelect): SentinelAgentRecord {
  const resourceLimits = safeJsonParse<SentinelResourceLimits>(
    row.resourceLimitsJson,
    DEFAULT_RESOURCE_LIMITS
  );
  const mapped: SentinelAgentRecord = {
    id: row.id,
    hostname: row.hostname,
    region: row.region,
    ipAddress: row.ipAddress,
    osType: (row.osType === 'windows' ? 'windows' : 'linux') as SentinelOsType,
    osVersion: row.osVersion,
    agentVersion: row.agentVersion,
    targetVersion: row.targetVersion,
    status: row.status as SentinelAgentRecord['status'],
    cpuPercent: row.cpuPercent,
    ramPercent: row.ramPercent,
    diskPercent: row.diskPercent,
    uptimeSec: row.uptimeSec,
    services: safeJsonParse<SentinelServiceStatus[]>(row.servicesJson, []),
    resourceLimits,
    tags: safeJsonParse<string[]>(row.tagsJson, []),
    lastHeartbeatAt: row.lastHeartbeatAt ? row.lastHeartbeatAt.toISOString() : null,
    enrolledAt: row.enrolledAt.toISOString(),
    revokedAt: row.revokedAt ? row.revokedAt.toISOString() : null,
  };
  mapped.status = deriveAgentHealthStatus(mapped);
  return mapped;
}

function mapTokenRow(
  row: typeof sentinelEnrollmentTokens.$inferSelect
): SentinelEnrollmentTokenRecord {
  return {
    id: row.id,
    tokenPrefix: row.tokenPrefix,
    label: row.label,
    region: row.region,
    osType: (row.osType === 'windows' ? 'windows' : 'linux') as SentinelOsType,
    expiresAt: row.expiresAt.toISOString(),
    usedAt: row.usedAt ? row.usedAt.toISOString() : null,
    usedByAgentId: row.usedByAgentId,
    revokedAt: row.revokedAt ? row.revokedAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

function mapEventRow(row: typeof sentinelEvents.$inferSelect): SentinelEventRecord {
  return {
    id: row.id,
    agentId: row.agentId,
    region: row.region,
    hostname: row.hostname,
    eventType: row.eventType as SentinelEventRecord['eventType'],
    severity: row.severity as SentinelEventRecord['severity'],
    fingerprint: row.fingerprint,
    occurrenceCount: row.occurrenceCount,
    summary: row.summary,
    payload: safeJsonParse<Record<string, unknown>>(row.payloadJson, {}),
    provenance: safeJsonParse(row.provenanceJson, {
      agentId: row.agentId,
      agentVersion: SENTINEL_VERSION,
      hostname: row.hostname,
      region: row.region,
      collector: 'sentinel-collector',
      receivedAtIso: row.ingestedAt.toISOString(),
      bufferedOffline: false,
      retryAttempt: 0,
      redactedFields: [],
    }),
    observedAt: row.observedAt.toISOString(),
    ingestedAt: row.ingestedAt.toISOString(),
  };
}

function mapIncidentRow(row: typeof sentinelIncidents.$inferSelect): SentinelIncidentRecord {
  return {
    id: row.id,
    title: row.title,
    severity: row.severity as SentinelIncidentRecord['severity'],
    status: row.status as SentinelIncidentRecord['status'],
    region: row.region,
    correlationType: row.correlationType as SentinelIncidentRecord['correlationType'],
    affectedAgentIds: safeJsonParse(row.affectedAgentIdsJson, []),
    evidenceEventIds: safeJsonParse(row.evidenceEventIdsJson, []),
    mitreTechniques: safeJsonParse(row.mitreTechniquesJson, []),
    hypotheses: safeJsonParse(row.hypothesesJson, []),
    timeline: safeJsonParse(row.timelineJson, []),
    investigationReport: row.investigationReport,
    confidenceScore: row.confidenceScore,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

function mapApprovalRow(
  row: typeof sentinelApprovalActions.$inferSelect
): SentinelApprovalActionRecord {
  return {
    id: row.id,
    agentId: row.agentId,
    incidentId: row.incidentId,
    actionType: row.actionType as DefensiveActionType,
    targetDetail: row.targetDetail,
    rationale: row.rationale,
    status: row.status as SentinelApprovalActionRecord['status'],
    requestedBy: row.requestedBy,
    decidedBy: row.decidedBy,
    decisionNote: row.decisionNote,
    requestedAt: row.requestedAt.toISOString(),
    decidedAt: row.decidedAt ? row.decidedAt.toISOString() : null,
  };
}

function mapAuditRow(row: typeof sentinelAuditLogs.$inferSelect): SentinelAuditLogRecord {
  return {
    id: row.id,
    action: row.action,
    actor: row.actor,
    targetId: row.targetId,
    severity: row.severity as SentinelAuditLogRecord['severity'],
    details: row.details,
    createdAt: row.createdAt.toISOString(),
  };
}

export async function upsertSentinelUser(uid: string, email: string): Promise<void> {
  try {
    await db
      .insert(users)
      .values({ uid, email: email || 'operator@local' })
      .onConflictDoUpdate({
        target: users.uid,
        set: { email: email || 'operator@local' },
      });
  } catch (error) {
    console.error('Sentinel upsert user failed:', error);
    throw new Error('Unable to synchronize operator identity.', { cause: error });
  }
}

export async function appendSentinelAuditLog(input: {
  userId: string;
  action: string;
  actor: string;
  targetId: string;
  severity?: 'info' | 'warning' | 'critical';
  details: string;
}): Promise<SentinelAuditLogRecord> {
  try {
    const id = `saud-${crypto.randomUUID().slice(0, 12)}`;
    const [row] = await db
      .insert(sentinelAuditLogs)
      .values({
        id,
        userId: input.userId,
        action: input.action.slice(0, 120),
        actor: input.actor.slice(0, 120),
        targetId: input.targetId.slice(0, 120),
        severity: input.severity || 'info',
        details: input.details.slice(0, 600),
      })
      .returning();
    return mapAuditRow(row);
  } catch (error) {
    console.error('Sentinel audit write failed:', error);
    throw new Error('Unable to persist audit log entry.', { cause: error });
  }
}

export async function createEnrollmentToken(input: {
  userId: string;
  actor: string;
  label: string;
  region: string;
  osType: SentinelOsType;
  ttlHours?: number;
}): Promise<{ tokenRecord: SentinelEnrollmentTokenRecord; plainToken: string }> {
  try {
    const plainToken = `gsen_${crypto.randomBytes(24).toString('hex')}`;
    const tokenHash = sha256Hex(plainToken);
    const id = `tok-${crypto.randomUUID().slice(0, 10)}`;
    const ttlMs = Math.max(1, Math.min(168, input.ttlHours || 24)) * 3600 * 1000;
    const expiresAt = new Date(Date.now() + ttlMs);

    const [row] = await db
      .insert(sentinelEnrollmentTokens)
      .values({
        id,
        userId: input.userId,
        tokenHash,
        tokenPrefix: plainToken.slice(0, 12),
        label: input.label.trim().slice(0, 80) || 'Authorized Server',
        region: input.region.trim().slice(0, 48) || 'asia-southeast1',
        osType: input.osType === 'windows' ? 'windows' : 'linux',
        expiresAt,
      })
      .returning();

    await appendSentinelAuditLog({
      userId: input.userId,
      action: 'ENROLLMENT_TOKEN_ISSUED',
      actor: input.actor,
      targetId: id,
      severity: 'info',
      details: `Issued single-use enrollment token (${row.tokenPrefix}...) for ${row.osType} host in ${row.region}.`,
    });

    return { tokenRecord: mapTokenRow(row), plainToken };
  } catch (error) {
    console.error('Create enrollment token failed:', error);
    throw new Error('Failed to issue enrollment token.', { cause: error });
  }
}

export async function revokeEnrollmentToken(
  userId: string,
  actor: string,
  tokenId: string
): Promise<SentinelEnrollmentTokenRecord | null> {
  try {
    const [row] = await db
      .update(sentinelEnrollmentTokens)
      .set({ revokedAt: new Date() })
      .where(
        and(eq(sentinelEnrollmentTokens.id, tokenId), eq(sentinelEnrollmentTokens.userId, userId))
      )
      .returning();

    if (!row) return null;

    await appendSentinelAuditLog({
      userId,
      action: 'ENROLLMENT_TOKEN_REVOKED',
      actor,
      targetId: tokenId,
      severity: 'warning',
      details: `Revoked enrollment token ${row.tokenPrefix}...`,
    });

    return mapTokenRow(row);
  } catch (error) {
    console.error('Revoke enrollment token failed:', error);
    throw new Error('Failed to revoke enrollment token.', { cause: error });
  }
}

export async function enrollAgentWithToken(input: {
  enrollmentToken: string;
  hostname: string;
  ipAddress: string;
  osType: SentinelOsType;
  osVersion: string;
  agentVersion: string;
  region?: string;
  tags?: string[];
  resourceLimits?: Partial<SentinelResourceLimits>;
}): Promise<{ agent: SentinelAgentRecord; deviceToken: string; userId: string } | null> {
  try {
    const tokenHash = sha256Hex(input.enrollmentToken.trim());
    const now = new Date();
    const [tok] = await db
      .select()
      .from(sentinelEnrollmentTokens)
      .where(
        and(
          eq(sentinelEnrollmentTokens.tokenHash, tokenHash),
          isNull(sentinelEnrollmentTokens.usedAt),
          isNull(sentinelEnrollmentTokens.revokedAt),
          gte(sentinelEnrollmentTokens.expiresAt, now)
        )
      )
      .limit(1);

    if (!tok) return null;

    const agentId = `srv-${crypto.randomUUID().slice(0, 10)}`;
    const deviceToken = `gsdev_${crypto.randomBytes(28).toString('hex')}`;
    const deviceTokenHash = sha256Hex(deviceToken);
    const mergedLimits: SentinelResourceLimits = {
      ...DEFAULT_RESOURCE_LIMITS,
      ...(input.resourceLimits || {}),
    };

    const [agentRow] = await db
      .insert(sentinelAgents)
      .values({
        id: agentId,
        userId: tok.userId,
        hostname: input.hostname.trim().slice(0, 96) || 'authorized-server',
        region: (input.region || tok.region || 'asia-southeast1').trim().slice(0, 48),
        ipAddress: input.ipAddress.trim().slice(0, 64) || '127.0.0.1',
        osType: input.osType === 'windows' ? 'windows' : 'linux',
        osVersion: input.osVersion.trim().slice(0, 96) || 'Linux 6.x',
        agentVersion: input.agentVersion.trim().slice(0, 32) || SENTINEL_VERSION,
        targetVersion: SENTINEL_VERSION,
        status: 'online',
        deviceTokenHash,
        cpuPercent: 0,
        ramPercent: 0,
        diskPercent: 0,
        uptimeSec: 0,
        servicesJson: JSON.stringify([]),
        resourceLimitsJson: JSON.stringify(mergedLimits),
        tagsJson: JSON.stringify((input.tags || []).slice(0, 8)),
        lastHeartbeatAt: now,
      })
      .returning();

    await db
      .update(sentinelEnrollmentTokens)
      .set({ usedAt: now, usedByAgentId: agentId })
      .where(eq(sentinelEnrollmentTokens.id, tok.id));

    await appendSentinelAuditLog({
      userId: tok.userId,
      action: 'AGENT_ENROLLED',
      actor: `agent:${agentRow.hostname}`,
      targetId: agentId,
      severity: 'info',
      details: `Enrolled authorized ${agentRow.osType} Sentinel agent ${agentRow.hostname} (${agentRow.ipAddress}) in ${agentRow.region} via token ${tok.tokenPrefix}...`,
    });

    return {
      agent: mapAgentRow(agentRow),
      deviceToken,
      userId: tok.userId,
    };
  } catch (error) {
    console.error('Enroll agent failed:', error);
    throw new Error('Agent enrollment failed.', { cause: error });
  }
}

export async function authenticateAgentDevice(
  agentId: string,
  deviceToken: string
): Promise<{ agent: SentinelAgentRecord; userId: string } | null> {
  try {
    const [row] = await db
      .select()
      .from(sentinelAgents)
      .where(eq(sentinelAgents.id, agentId))
      .limit(1);

    if (!row || row.status === 'revoked' || row.revokedAt) {
      return null;
    }

    const candidateHash = sha256Hex(deviceToken.trim());
    const a = Buffer.from(row.deviceTokenHash, 'hex');
    const b = Buffer.from(candidateHash, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    return { agent: mapAgentRow(row), userId: row.userId };
  } catch (error) {
    console.error('Authenticate agent failed:', error);
    throw new Error('Agent authentication verification failed.', { cause: error });
  }
}

export async function recordAgentHeartbeat(input: {
  agentId: string;
  cpuPercent: number;
  ramPercent: number;
  diskPercent: number;
  uptimeSec: number;
  agentVersion?: string;
  services?: SentinelServiceStatus[];
}): Promise<SentinelAgentRecord | null> {
  try {
    const [existing] = await db
      .select()
      .from(sentinelAgents)
      .where(eq(sentinelAgents.id, input.agentId))
      .limit(1);
    if (!existing || existing.status === 'revoked') return null;

    const cpu = Math.max(0, Math.min(100, Math.round(input.cpuPercent)));
    const ram = Math.max(0, Math.min(100, Math.round(input.ramPercent)));
    const disk = Math.max(0, Math.min(100, Math.round(input.diskPercent)));
    const nextStatus =
      existing.status === 'isolated'
        ? 'isolated'
        : cpu >= 88 || ram >= 90 || disk >= 92
          ? 'degraded'
          : 'online';

    const [updated] = await db
      .update(sentinelAgents)
      .set({
        cpuPercent: cpu,
        ramPercent: ram,
        diskPercent: disk,
        uptimeSec: Math.max(0, Math.round(input.uptimeSec || 0)),
        agentVersion: input.agentVersion
          ? input.agentVersion.slice(0, 32)
          : existing.agentVersion,
        servicesJson: input.services
          ? JSON.stringify(input.services.slice(0, 30))
          : existing.servicesJson,
        status: nextStatus,
        lastHeartbeatAt: new Date(),
      })
      .where(eq(sentinelAgents.id, input.agentId))
      .returning();

    return updated ? mapAgentRow(updated) : null;
  } catch (error) {
    console.error('Heartbeat update failed:', error);
    throw new Error('Failed to record agent heartbeat.', { cause: error });
  }
}

export async function revokeSentinelAgent(
  userId: string,
  actor: string,
  agentId: string
): Promise<SentinelAgentRecord | null> {
  try {
    const [row] = await db
      .update(sentinelAgents)
      .set({ status: 'revoked', revokedAt: new Date() })
      .where(and(eq(sentinelAgents.id, agentId), eq(sentinelAgents.userId, userId)))
      .returning();
    if (!row) return null;

    await appendSentinelAuditLog({
      userId,
      action: 'AGENT_REVOKED',
      actor,
      targetId: agentId,
      severity: 'warning',
      details: `Revoked Sentinel credentials and deactivated monitoring for ${row.hostname}.`,
    });
    return mapAgentRow(row);
  } catch (error) {
    console.error('Revoke agent failed:', error);
    throw new Error('Failed to revoke agent.', { cause: error });
  }
}

export async function updateAgentGovernanceConfig(
  userId: string,
  actor: string,
  agentId: string,
  updates: { targetVersion?: string; resourceLimits?: Partial<SentinelResourceLimits> }
): Promise<SentinelAgentRecord | null> {
  try {
    const [existing] = await db
      .select()
      .from(sentinelAgents)
      .where(and(eq(sentinelAgents.id, agentId), eq(sentinelAgents.userId, userId)))
      .limit(1);
    if (!existing) return null;

    const currentLimits = safeJsonParse<SentinelResourceLimits>(
      existing.resourceLimitsJson,
      DEFAULT_RESOURCE_LIMITS
    );
    const nextLimits: SentinelResourceLimits = {
      maxCpuPercent: Math.max(
        1,
        Math.min(25, Number(updates.resourceLimits?.maxCpuPercent ?? currentLimits.maxCpuPercent))
      ),
      maxMemoryMb: Math.max(
        32,
        Math.min(512, Number(updates.resourceLimits?.maxMemoryMb ?? currentLimits.maxMemoryMb))
      ),
      maxEventsPerMinute: Math.max(
        10,
        Math.min(
          1000,
          Number(updates.resourceLimits?.maxEventsPerMinute ?? currentLimits.maxEventsPerMinute)
        )
      ),
      heartbeatIntervalSec: Math.max(
        10,
        Math.min(
          300,
          Number(updates.resourceLimits?.heartbeatIntervalSec ?? currentLimits.heartbeatIntervalSec)
        )
      ),
      offlineBufferMaxEvents: Math.max(
        100,
        Math.min(
          50000,
          Number(
            updates.resourceLimits?.offlineBufferMaxEvents ?? currentLimits.offlineBufferMaxEvents
          )
        )
      ),
    };

    const nextTargetVersion = updates.targetVersion
      ? updates.targetVersion.trim().slice(0, 32)
      : existing.targetVersion;

    const [updated] = await db
      .update(sentinelAgents)
      .set({
        targetVersion: nextTargetVersion,
        resourceLimitsJson: JSON.stringify(nextLimits),
      })
      .where(and(eq(sentinelAgents.id, agentId), eq(sentinelAgents.userId, userId)))
      .returning();

    await appendSentinelAuditLog({
      userId,
      action: 'AGENT_POLICY_UPDATED',
      actor,
      targetId: agentId,
      severity: 'info',
      details: `Updated target version (${nextTargetVersion}) and resource limits (CPU<=${nextLimits.maxCpuPercent}%, RAM<=${nextLimits.maxMemoryMb}MB) for ${existing.hostname}.`,
    });

    return updated ? mapAgentRow(updated) : null;
  } catch (error) {
    console.error('Update agent config failed:', error);
    throw new Error('Failed to update agent configuration.', { cause: error });
  }
}

export async function persistNormalizedSentinelEvents(
  userId: string,
  events: Array<Omit<SentinelEventRecord, 'id'>>
): Promise<{ persisted: SentinelEventRecord[]; deduplicatedInDb: number }> {
  try {
    const persisted: SentinelEventRecord[] = [];
    let deduplicatedInDb = 0;
    const dedupeSince = new Date(Date.now() - 5 * 60_000);

    for (const evt of events) {
      const [existing] = await db
        .select()
        .from(sentinelEvents)
        .where(
          and(
            eq(sentinelEvents.userId, userId),
            eq(sentinelEvents.agentId, evt.agentId),
            eq(sentinelEvents.fingerprint, evt.fingerprint),
            gte(sentinelEvents.ingestedAt, dedupeSince)
          )
        )
        .orderBy(desc(sentinelEvents.ingestedAt))
        .limit(1);

      if (existing) {
        const [updated] = await db
          .update(sentinelEvents)
          .set({
            occurrenceCount: existing.occurrenceCount + evt.occurrenceCount,
            observedAt: new Date(evt.observedAt),
            ingestedAt: new Date(),
          })
          .where(eq(sentinelEvents.id, existing.id))
          .returning();
        deduplicatedInDb += 1;
        if (updated) persisted.push(mapEventRow(updated));
      } else {
        const id = `sevt-${crypto.randomUUID().slice(0, 12)}`;
        const [inserted] = await db
          .insert(sentinelEvents)
          .values({
            id,
            userId,
            agentId: evt.agentId,
            region: evt.region,
            hostname: evt.hostname,
            eventType: evt.eventType,
            severity: evt.severity,
            fingerprint: evt.fingerprint,
            occurrenceCount: evt.occurrenceCount,
            summary: evt.summary,
            payloadJson: JSON.stringify(evt.payload),
            provenanceJson: JSON.stringify(evt.provenance),
            observedAt: new Date(evt.observedAt),
          })
          .returning();
        if (inserted) persisted.push(mapEventRow(inserted));
      }
    }

    return { persisted, deduplicatedInDb };
  } catch (error) {
    console.error('Persist sentinel events failed:', error);
    throw new Error('Failed to store normalized telemetry events.', { cause: error });
  }
}

export async function createOrUpdateSentinelIncident(
  userId: string,
  actor: string,
  incident: Omit<SentinelIncidentRecord, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }
): Promise<SentinelIncidentRecord> {
  try {
    const id = incident.id || `sinc-${crypto.randomUUID().slice(0, 10)}`;
    const now = new Date();
    const [row] = await db
      .insert(sentinelIncidents)
      .values({
        id,
        userId,
        title: incident.title.slice(0, 180),
        severity: incident.severity,
        status: incident.status,
        region: incident.region.slice(0, 64),
        correlationType: incident.correlationType,
        affectedAgentIdsJson: JSON.stringify(incident.affectedAgentIds),
        evidenceEventIdsJson: JSON.stringify(incident.evidenceEventIds),
        mitreTechniquesJson: JSON.stringify(incident.mitreTechniques),
        hypothesesJson: JSON.stringify(incident.hypotheses),
        timelineJson: JSON.stringify(incident.timeline),
        investigationReport: incident.investigationReport,
        confidenceScore: Math.max(0, Math.min(100, Math.round(incident.confidenceScore))),
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: sentinelIncidents.id,
        set: {
          title: incident.title.slice(0, 180),
          severity: incident.severity,
          status: incident.status,
          mitreTechniquesJson: JSON.stringify(incident.mitreTechniques),
          hypothesesJson: JSON.stringify(incident.hypotheses),
          timelineJson: JSON.stringify(incident.timeline),
          investigationReport: incident.investigationReport,
          confidenceScore: Math.max(0, Math.min(100, Math.round(incident.confidenceScore))),
          updatedAt: now,
        },
      })
      .returning();

    await appendSentinelAuditLog({
      userId,
      action: incident.id ? 'INCIDENT_INVESTIGATION_UPDATED' : 'INCIDENT_CREATED',
      actor,
      targetId: id,
      severity: incident.severity === 'critical' ? 'critical' : 'warning',
      details: `${incident.title} (${incident.severity}, ${incident.mitreTechniques.length} MITRE mappings).`,
    });

    return mapIncidentRow(row);
  } catch (error) {
    console.error('Save sentinel incident failed:', error);
    throw new Error('Failed to store incident record.', { cause: error });
  }
}

export async function createHumanApprovalAction(input: {
  userId: string;
  agentId: string;
  incidentId?: string | null;
  actionType: DefensiveActionType;
  targetDetail: string;
  rationale: string;
  requestedBy: string;
}): Promise<SentinelApprovalActionRecord> {
  try {
    const id = `sact-${crypto.randomUUID().slice(0, 10)}`;
    const [row] = await db
      .insert(sentinelApprovalActions)
      .values({
        id,
        userId: input.userId,
        agentId: input.agentId,
        incidentId: input.incidentId || null,
        actionType: input.actionType,
        targetDetail: input.targetDetail.slice(0, 240),
        rationale: input.rationale.slice(0, 500),
        status: 'pending_approval',
        requestedBy: input.requestedBy.slice(0, 120),
      })
      .returning();

    await appendSentinelAuditLog({
      userId: input.userId,
      action: 'DEFENSIVE_ACTION_PROPOSED',
      actor: input.requestedBy,
      targetId: id,
      severity: 'warning',
      details: `Proposed human-approval action ${input.actionType} on ${input.agentId}: ${input.targetDetail}`,
    });

    return mapApprovalRow(row);
  } catch (error) {
    console.error('Create approval action failed:', error);
    throw new Error('Failed to queue defensive action for human approval.', { cause: error });
  }
}

export async function decideHumanApprovalAction(input: {
  userId: string;
  actionId: string;
  decision: 'approved' | 'rejected';
  decidedBy: string;
  decisionNote?: string;
}): Promise<SentinelApprovalActionRecord | null> {
  try {
    const [existing] = await db
      .select()
      .from(sentinelApprovalActions)
      .where(
        and(
          eq(sentinelApprovalActions.id, input.actionId),
          eq(sentinelApprovalActions.userId, input.userId)
        )
      )
      .limit(1);

    if (!existing || existing.status !== 'pending_approval') return null;

    const [updated] = await db
      .update(sentinelApprovalActions)
      .set({
        status: input.decision,
        decidedBy: input.decidedBy.slice(0, 120),
        decisionNote: (input.decisionNote || '').slice(0, 320),
        decidedAt: new Date(),
      })
      .where(eq(sentinelApprovalActions.id, input.actionId))
      .returning();

    // If operator explicitly approved isolating the server, reflect isolated containment state
    if (input.decision === 'approved' && existing.actionType === 'isolate_server') {
      await db
        .update(sentinelAgents)
        .set({ status: 'isolated' })
        .where(
          and(eq(sentinelAgents.id, existing.agentId), eq(sentinelAgents.userId, input.userId))
        );
    }

    await appendSentinelAuditLog({
      userId: input.userId,
      action:
        input.decision === 'approved'
          ? 'DEFENSIVE_ACTION_APPROVED'
          : 'DEFENSIVE_ACTION_REJECTED',
      actor: input.decidedBy,
      targetId: input.actionId,
      severity: input.decision === 'approved' ? 'critical' : 'info',
      details: `Operator ${input.decision} ${existing.actionType} on ${existing.agentId} (${existing.targetDetail}). Note: ${input.decisionNote || 'none'}`,
    });

    return updated ? mapApprovalRow(updated) : null;
  } catch (error) {
    console.error('Decide approval action failed:', error);
    throw new Error('Failed to record human approval decision.', { cause: error });
  }
}

export async function getSentinelOverviewForUser(userId: string): Promise<{
  agents: SentinelAgentRecord[];
  tokens: SentinelEnrollmentTokenRecord[];
  events: SentinelEventRecord[];
  incidents: SentinelIncidentRecord[];
  approvals: SentinelApprovalActionRecord[];
  auditLogs: SentinelAuditLogRecord[];
}> {
  try {
    const [agentRows, tokenRows, eventRows, incidentRows, approvalRows, auditRows] =
      await Promise.all([
        db
          .select()
          .from(sentinelAgents)
          .where(eq(sentinelAgents.userId, userId))
          .orderBy(desc(sentinelAgents.enrolledAt))
          .limit(100),
        db
          .select()
          .from(sentinelEnrollmentTokens)
          .where(eq(sentinelEnrollmentTokens.userId, userId))
          .orderBy(desc(sentinelEnrollmentTokens.createdAt))
          .limit(50),
        db
          .select()
          .from(sentinelEvents)
          .where(eq(sentinelEvents.userId, userId))
          .orderBy(desc(sentinelEvents.observedAt))
          .limit(150),
        db
          .select()
          .from(sentinelIncidents)
          .where(eq(sentinelIncidents.userId, userId))
          .orderBy(desc(sentinelIncidents.updatedAt))
          .limit(50),
        db
          .select()
          .from(sentinelApprovalActions)
          .where(eq(sentinelApprovalActions.userId, userId))
          .orderBy(desc(sentinelApprovalActions.requestedAt))
          .limit(50),
        db
          .select()
          .from(sentinelAuditLogs)
          .where(eq(sentinelAuditLogs.userId, userId))
          .orderBy(desc(sentinelAuditLogs.createdAt))
          .limit(100),
      ]);

    return {
      agents: agentRows.map(mapAgentRow),
      tokens: tokenRows.map(mapTokenRow),
      events: eventRows.map(mapEventRow),
      incidents: incidentRows.map(mapIncidentRow),
      approvals: approvalRows.map(mapApprovalRow),
      auditLogs: auditRows.map(mapAuditRow),
    };
  } catch (error) {
    console.error('Load Sentinel overview failed:', error);
    throw new Error('Unable to load Sentinel fleet overview.', { cause: error });
  }
}

export async function getPendingApprovedCommandsForAgent(
  agentId: string
): Promise<SentinelApprovalActionRecord[]> {
  try {
    const rows = await db
      .select()
      .from(sentinelApprovalActions)
      .where(
        and(
          eq(sentinelApprovalActions.agentId, agentId),
          eq(sentinelApprovalActions.status, 'approved')
        )
      )
      .orderBy(desc(sentinelApprovalActions.decidedAt))
      .limit(10);
    return rows.map(mapApprovalRow);
  } catch (error) {
    console.error('Fetch approved commands failed:', error);
    throw new Error('Unable to fetch approved containment directives.', { cause: error });
  }
}
