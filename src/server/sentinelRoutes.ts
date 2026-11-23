import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import {
  appendSentinelAuditLog,
  authenticateAgentDevice,
  createEnrollmentToken,
  createHumanApprovalAction,
  createOrUpdateSentinelIncident,
  decideHumanApprovalAction,
  enrollAgentWithToken,
  getPendingApprovedCommandsForAgent,
  getSentinelOverviewForUser,
  recordAgentHeartbeat,
  revokeEnrollmentToken,
  revokeSentinelAgent,
  updateAgentGovernanceConfig,
  upsertSentinelUser,
} from '../db/sentinelRepository.ts';
import {
  buildIncidentTimeline,
  buildSentinelTopology,
  evaluateRegionalIntelligence,
  validateDefensiveActionRequest,
  type RawSentinelEventInput,
} from '../shared/sentinelAnalytics.ts';
import { SENTINEL_VERSION, type SentinelOsType } from '../shared/sentinelTypes.ts';
import { sentinelEventQueue } from './sentinelQueue.ts';
import { runSentinelBrainInvestigation } from './sentinelBrain.ts';

export interface SentinelAuthenticatedRequest extends Request {
  authUser?: {
    uid: string;
    email?: string;
  };
}

// Per-agent / per-IP rate limiter for agent ingest endpoints
const AGENT_RATE_WINDOW_MS = 60_000;
const AGENT_RATE_MAX = 180;
const agentRateWindows = new Map<string, number[]>();

function checkAgentRateLimit(key: string): boolean {
  const now = Date.now();
  const timestamps = (agentRateWindows.get(key) || []).filter(
    (ts) => now - ts < AGENT_RATE_WINDOW_MS
  );
  if (timestamps.length >= AGENT_RATE_MAX) {
    agentRateWindows.set(key, timestamps);
    return false;
  }
  timestamps.push(now);
  agentRateWindows.set(key, timestamps);
  return true;
}

export function createSentinelRouter(
  requireVerifiedFirebaseUser: (
    req: SentinelAuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) => Promise<void>
): express.Router {
  const router = express.Router();

  // =========================================================================
  // 1. AGENT-FACING INBOUND ENDPOINTS (Enrolled Device Token Authentication)
  // =========================================================================

  router.post('/agent/enroll', async (req: Request, res: Response) => {
    const clientIp = req.ip || 'unknown';
    if (!checkAgentRateLimit(`enroll:${clientIp}`)) {
      res.status(429).json({ error: 'Enrollment rate limit exceeded. Retry shortly.' });
      return;
    }

    const body = (req.body || {}) as Record<string, unknown>;
    const enrollmentToken = String(body.enrollmentToken || '').trim();
    const hostname = String(body.hostname || '').trim();
    const ipAddress = String(body.ipAddress || clientIp).trim();
    const osType: SentinelOsType = body.osType === 'windows' ? 'windows' : 'linux';
    const osVersion = String(body.osVersion || (osType === 'windows' ? 'Windows Server' : 'Linux')).trim();
    const agentVersion = String(body.agentVersion || SENTINEL_VERSION).trim();
    const region = typeof body.region === 'string' ? body.region.trim() : undefined;

    if (!enrollmentToken || !hostname) {
      res.status(400).json({ error: 'enrollmentToken and hostname are required.' });
      return;
    }

    try {
      const result = await enrollAgentWithToken({
        enrollmentToken,
        hostname,
        ipAddress,
        osType,
        osVersion,
        agentVersion,
        region,
        tags: Array.isArray(body.tags) ? body.tags.map(String) : ['authorized'],
        resourceLimits:
          body.resourceLimits && typeof body.resourceLimits === 'object'
            ? (body.resourceLimits as Record<string, number>)
            : undefined,
      });

      if (!result) {
        res.status(401).json({
          error: 'Invalid, expired, revoked, or already-used enrollment token.',
        });
        return;
      }

      res.status(201).json({
        ok: true,
        agent: result.agent,
        deviceToken: result.deviceToken,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Agent enrollment failed.';
      res.status(500).json({ error: msg });
    }
  });

  router.post('/agent/heartbeat', async (req: Request, res: Response) => {
    const agentId = String(req.headers['x-sentinel-agent-id'] || '').trim();
    const authHeader = String(req.headers.authorization || '');
    const deviceToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice('Bearer '.length).trim()
      : '';

    if (!agentId || !deviceToken) {
      res.status(401).json({ error: 'Missing agent identity or per-device bearer token.' });
      return;
    }

    if (!checkAgentRateLimit(`hb:${agentId}`)) {
      res.status(429).json({ error: 'Agent heartbeat rate limit exceeded.' });
      return;
    }

    try {
      const verified = await authenticateAgentDevice(agentId, deviceToken);
      if (!verified) {
        res.status(401).json({ error: 'Unauthorized or revoked Sentinel agent.' });
        return;
      }

      const body = (req.body || {}) as Record<string, unknown>;
      const updated = await recordAgentHeartbeat({
        agentId,
        cpuPercent: Number(body.cpuPercent ?? 0),
        ramPercent: Number(body.ramPercent ?? 0),
        diskPercent: Number(body.diskPercent ?? 0),
        uptimeSec: Number(body.uptimeSec ?? 0),
        agentVersion: typeof body.agentVersion === 'string' ? body.agentVersion : undefined,
        services: Array.isArray(body.services)
          ? (body.services as Array<{ name: string; state: 'running' | 'stopped' | 'degraded'; pid?: number }>)
          : undefined,
      });

      const approvedActions = await getPendingApprovedCommandsForAgent(agentId);

      res.json({
        ok: true,
        agent: updated,
        targetVersion: updated?.targetVersion || SENTINEL_VERSION,
        resourceLimits: updated?.resourceLimits,
        approvedActions,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Heartbeat processing failed.';
      res.status(500).json({ error: msg });
    }
  });

  router.post('/agent/events', async (req: Request, res: Response) => {
    const agentId = String(req.headers['x-sentinel-agent-id'] || '').trim();
    const authHeader = String(req.headers.authorization || '');
    const deviceToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice('Bearer '.length).trim()
      : '';

    if (!agentId || !deviceToken) {
      res.status(401).json({ error: 'Missing agent identity or per-device bearer token.' });
      return;
    }

    if (!checkAgentRateLimit(`ev:${agentId}`)) {
      res.status(429).json({ error: 'Agent telemetry rate limit exceeded; retain offline buffer.' });
      return;
    }

    try {
      const verified = await authenticateAgentDevice(agentId, deviceToken);
      if (!verified) {
        res.status(401).json({ error: 'Unauthorized or revoked Sentinel agent.' });
        return;
      }

      const body = (req.body || {}) as { events?: RawSentinelEventInput[] };
      const rawEvents = Array.isArray(body.events) ? body.events : [];
      if (rawEvents.length === 0) {
        res.status(400).json({ error: 'events array must contain at least one telemetry record.' });
        return;
      }

      const result = await sentinelEventQueue.enqueueBatch(
        verified.userId,
        {
          agentId: verified.agent.id,
          agentVersion: verified.agent.agentVersion,
          hostname: verified.agent.hostname,
          region: verified.agent.region,
        },
        rawEvents
      );

      res.status(202).json({
        ok: true,
        persistedCount: result.persisted.length,
        deduplicatedCount: result.deduplicatedCount,
        queueMetrics: sentinelEventQueue.getMetrics(),
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Telemetry ingestion failed.';
      res.status(500).json({ error: msg });
    }
  });

  // =========================================================================
  // 2. OPERATOR COMMAND CENTER ENDPOINTS (Verified Firebase Auth)
  // =========================================================================

  router.get(
    '/overview',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const email = req.authUser!.email || 'operator@local';
        await upsertSentinelUser(uid, email);

        const overview = await getSentinelOverviewForUser(uid);
        const regionalFindings = evaluateRegionalIntelligence(overview.agents, overview.events);
        const topology = buildSentinelTopology(overview.agents, overview.events);

        res.json({
          sentinelVersion: SENTINEL_VERSION,
          ...overview,
          regionalFindings,
          topology,
          queueMetrics: sentinelEventQueue.getMetrics(),
        });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to load Sentinel overview.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/tokens',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        await upsertSentinelUser(uid, actor);

        const body = (req.body || {}) as Record<string, unknown>;
        const label = String(body.label || 'Authorized Server').trim();
        const region = String(body.region || 'asia-southeast1').trim();
        const osType: SentinelOsType = body.osType === 'windows' ? 'windows' : 'linux';
        const ttlHours = Number(body.ttlHours ?? 24);

        const created = await createEnrollmentToken({
          userId: uid,
          actor,
          label,
          region,
          osType,
          ttlHours,
        });
        res.status(201).json(created);
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to create enrollment token.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/tokens/:tokenId/revoke',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        const revoked = await revokeEnrollmentToken(uid, actor, req.params.tokenId);
        if (!revoked) {
          res.status(404).json({ error: 'Enrollment token not found.' });
          return;
        }
        res.json({ ok: true, tokenRecord: revoked });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to revoke enrollment token.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/agents/:agentId/revoke',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        const revoked = await revokeSentinelAgent(uid, actor, req.params.agentId);
        if (!revoked) {
          res.status(404).json({ error: 'Enrolled agent not found.' });
          return;
        }
        res.json({ ok: true, agent: revoked });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to revoke agent.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.patch(
    '/agents/:agentId/policy',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        const body = (req.body || {}) as Record<string, unknown>;
        const updated = await updateAgentGovernanceConfig(uid, actor, req.params.agentId, {
          targetVersion: typeof body.targetVersion === 'string' ? body.targetVersion : undefined,
          resourceLimits:
            body.resourceLimits && typeof body.resourceLimits === 'object'
              ? (body.resourceLimits as Record<string, number>)
              : undefined,
        });
        if (!updated) {
          res.status(404).json({ error: 'Enrolled agent not found.' });
          return;
        }
        res.json({ ok: true, agent: updated });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to update agent policy.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/correlate',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        await upsertSentinelUser(uid, actor);

        const overview = await getSentinelOverviewForUser(uid);
        const findings = evaluateRegionalIntelligence(overview.agents, overview.events);

        const createdIncidents = [];
        const createdApprovals = [];

        for (const finding of findings) {
          const alreadyOpen = overview.incidents.some(
            (inc) => inc.status !== 'resolved' && inc.title === finding.title
          );
          if (alreadyOpen) continue;

          const relatedEvents = overview.events.filter((e) =>
            finding.evidenceEventIds.includes(e.id)
          );
          const incident = await createOrUpdateSentinelIncident(uid, actor, {
            title: finding.title,
            severity: finding.severity,
            status: 'open',
            region: finding.region,
            correlationType: finding.correlationType,
            affectedAgentIds: finding.affectedAgentIds,
            evidenceEventIds: finding.evidenceEventIds,
            mitreTechniques: finding.mitreTechniques,
            hypotheses: [
              {
                id: 'hyp-corr-1',
                title: finding.summary,
                likelihood: finding.severity === 'critical' ? 'high' : 'medium',
                supportingEvidence: relatedEvents.map((e) => `[${e.id}] ${e.hostname}: ${e.summary}`),
                refutingOrGaps: ['Pending Gemini Central Brain deep investigation and operator confirmation.'],
              },
            ],
            timeline: buildIncidentTimeline(relatedEvents),
            investigationReport: `### Automated Regional Correlation Alert\n${finding.summary}\n\nRun **Gemini Central Brain Investigation** for hypothesis ranking and detailed MITRE ATT&CK analysis.`,
            confidenceScore: finding.severity === 'critical' ? 84 : 74,
          });
          createdIncidents.push(incident);

          if (finding.recommendedAction) {
            const action = await createHumanApprovalAction({
              userId: uid,
              agentId: finding.recommendedAction.agentId,
              incidentId: incident.id,
              actionType: finding.recommendedAction.actionType,
              targetDetail: finding.recommendedAction.targetDetail,
              rationale: finding.recommendedAction.rationale,
              requestedBy: 'Regional Intelligence Engine',
            });
            createdApprovals.push(action);
          }
        }

        await appendSentinelAuditLog({
          userId: uid,
          action: 'REGIONAL_CORRELATION_EXECUTED',
          actor,
          targetId: 'regional-engine',
          severity: 'info',
          details: `Correlated ${overview.events.length} events across ${overview.agents.length} agents; detected ${findings.length} finding(s), opened ${createdIncidents.length} new incident(s).`,
        });

        res.json({
          ok: true,
          findings,
          createdIncidents,
          createdApprovals,
        });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Regional correlation failed.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/investigate',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        await upsertSentinelUser(uid, actor);

        const body = (req.body || {}) as { incidentId?: string; agentId?: string };
        const overview = await getSentinelOverviewForUser(uid);

        const existingIncident = body.incidentId
          ? overview.incidents.find((i) => i.id === body.incidentId)
          : undefined;

        let targetEvents = overview.events;
        if (existingIncident && existingIncident.evidenceEventIds.length > 0) {
          const evSet = new Set(existingIncident.evidenceEventIds);
          const subset = overview.events.filter((e) => evSet.has(e.id));
          if (subset.length > 0) targetEvents = subset;
        } else if (body.agentId) {
          const subset = overview.events.filter((e) => e.agentId === body.agentId);
          if (subset.length > 0) targetEvents = subset;
        } else {
          const highPriority = overview.events.filter((e) => e.severity !== 'info');
          if (highPriority.length > 0) targetEvents = highPriority;
        }

        if (targetEvents.length === 0) {
          res.status(400).json({
            error: 'No telemetry events available to investigate yet. Enroll an agent or run the Milestone 1 drill first.',
          });
          return;
        }

        const brainResult = await runSentinelBrainInvestigation({
          agents: overview.agents,
          events: targetEvents,
          focusTitle: existingIncident?.title,
          region: existingIncident?.region,
        });

        const affectedAgentIds = Array.from(new Set(targetEvents.map((e) => e.agentId)));
        const incident = await createOrUpdateSentinelIncident(uid, actor, {
          id: existingIncident?.id,
          title: brainResult.title,
          severity: brainResult.severity,
          status: 'investigating',
          region:
            existingIncident?.region ||
            Array.from(new Set(targetEvents.map((e) => e.region))).join(', ') ||
            'asia-southeast1',
          correlationType: existingIncident?.correlationType || 'multi_signal_intrusion',
          affectedAgentIds,
          evidenceEventIds: targetEvents.slice(0, 30).map((e) => e.id),
          mitreTechniques: brainResult.mitreTechniques,
          hypotheses: brainResult.hypotheses,
          timeline: brainResult.timeline,
          investigationReport: brainResult.investigationReport,
          confidenceScore: brainResult.confidenceScore,
        });

        const queuedApprovals = [];
        for (const rec of brainResult.recommendedHumanActions.slice(0, 2)) {
          const validation = validateDefensiveActionRequest(rec);
          if (!validation.valid || !validation.actionType) continue;
          const dupPending = overview.approvals.some(
            (a) =>
              a.status === 'pending_approval' &&
              a.agentId === rec.agentId &&
              a.actionType === validation.actionType &&
              a.targetDetail === rec.targetDetail
          );
          if (dupPending) continue;
          const approval = await createHumanApprovalAction({
            userId: uid,
            agentId: rec.agentId,
            incidentId: incident.id,
            actionType: validation.actionType,
            targetDetail: rec.targetDetail,
            rationale: rec.rationale,
            requestedBy: 'GOD Sentinel Brain (Gemini)',
          });
          queuedApprovals.push(approval);
        }

        res.json({
          ok: true,
          incident,
          queuedApprovals,
        });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Central Brain investigation failed.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/milestone-drill',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        await upsertSentinelUser(uid, actor);

        const body = (req.body || {}) as { region?: string; hostname?: string };
        const region = String(body.region || 'asia-southeast1').trim();
        const hostname =
          String(body.hostname || `sg-linux-sentinel-${crypto.randomBytes(2).toString('hex')}`).trim();

        const { plainToken } = await createEnrollmentToken({
          userId: uid,
          actor,
          label: `Milestone 1 Linux Agent (${hostname})`,
          region,
          osType: 'linux',
          ttlHours: 1,
        });

        const enrolled = await enrollAgentWithToken({
          enrollmentToken: plainToken,
          hostname,
          ipAddress: `10.14.${Math.floor(Math.random() * 20) + 1}.${Math.floor(Math.random() * 200) + 20}`,
          osType: 'linux',
          osVersion: 'Ubuntu 24.04.1 LTS (Linux 6.8)',
          agentVersion: SENTINEL_VERSION,
          region,
          tags: ['milestone-1', 'authorized-linux'],
        });

        if (!enrolled) {
          res.status(500).json({ error: 'Failed to enroll Milestone 1 Linux agent.' });
          return;
        }

        const updatedAgent = await recordAgentHeartbeat({
          agentId: enrolled.agent.id,
          cpuPercent: 28,
          ramPercent: 46,
          diskPercent: 39,
          uptimeSec: 172800,
          agentVersion: SENTINEL_VERSION,
          services: [
            { name: 'sshd', state: 'running', pid: 812 },
            { name: 'systemd-journald', state: 'running', pid: 404 },
            { name: 'nginx', state: 'running', pid: 1120 },
          ],
        });

        const nowIso = new Date().toISOString();
        const drillEvents: RawSentinelEventInput[] = [
          {
            eventType: 'auth',
            severity: 'high',
            summary: `[SIMULATED DRILL] Repeated failed SSH logins for deploy from 198.51.100.77 on ${hostname}`,
            payload: { sourceIp: '198.51.100.77', username: 'deploy', remotePort: 22, failedAttempts: 18 },
            collector: 'sentinel-auth-drill',
            observedAt: nowIso,
            simulatedDrill: true,
          },
          {
            eventType: 'process',
            severity: 'high',
            summary: '[SIMULATED DRILL] Suspicious child shell launched from /tmp/audit_probe.sh',
            payload: { pid: 49122, processName: 'bash', parentProcess: 'sshd', command: 'bash /tmp/audit_probe.sh --check' },
            collector: 'sentinel-process-drill',
            observedAt: nowIso,
            simulatedDrill: true,
          },
          {
            eventType: 'network',
            severity: 'high',
            summary: '[SIMULATED DRILL] Unexpected outbound TCP socket to 198.51.100.77:4444',
            payload: { protocol: 'TCP', remoteIp: '198.51.100.77', remotePort: 4444, state: 'ESTABLISHED' },
            collector: 'sentinel-net-drill',
            observedAt: nowIso,
            simulatedDrill: true,
          },
          {
            eventType: 'fim',
            severity: 'critical',
            summary: '[SIMULATED DRILL] SHA-256 checksum drift detected on /etc/ssh/sshd_config',
            payload: { filePath: '/etc/ssh/sshd_config', previousSha256: '8b7df143d91c716e', currentSha256: 'd2f9e0a7c13144a9' },
            collector: 'sentinel-fim-drill',
            observedAt: nowIso,
            simulatedDrill: true,
          },
        ];

        const ingested = await sentinelEventQueue.enqueueBatch(
          uid,
          {
            agentId: enrolled.agent.id,
            agentVersion: SENTINEL_VERSION,
            hostname: enrolled.agent.hostname,
            region: enrolled.agent.region,
          },
          drillEvents
        );

        const brain = await runSentinelBrainInvestigation({
          agents: [updatedAgent || enrolled.agent],
          events: ingested.persisted,
          focusTitle: `Milestone 1 Drill: Suspicious Execution & FIM Drift on ${hostname}`,
          region,
        });

        const incident = await createOrUpdateSentinelIncident(uid, actor, {
          title: brain.title,
          severity: brain.severity,
          status: 'investigating',
          region,
          correlationType: 'multi_signal_intrusion',
          affectedAgentIds: [enrolled.agent.id],
          evidenceEventIds: ingested.persisted.map((e) => e.id),
          mitreTechniques: brain.mitreTechniques,
          hypotheses: brain.hypotheses,
          timeline: brain.timeline,
          investigationReport: brain.investigationReport,
          confidenceScore: brain.confidenceScore,
        });

        const approval = await createHumanApprovalAction({
          userId: uid,
          agentId: enrolled.agent.id,
          incidentId: incident.id,
          actionType: 'terminate_process',
          targetDetail: 'PID 49122 (bash /tmp/audit_probe.sh --check)',
          rationale:
            'Milestone 1 simulated suspicious process paired with port 4444 egress and sshd_config checksum drift. Awaiting explicit human operator approval.',
          requestedBy: 'GOD Sentinel Brain (Gemini)',
        });

        res.status(201).json({
          ok: true,
          agent: updatedAgent || enrolled.agent,
          ingestedEvents: ingested.persisted,
          incident,
          approval,
        });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Milestone 1 drill failed.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/approvals',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        await upsertSentinelUser(uid, actor);

        const body = (req.body || {}) as Record<string, unknown>;
        const validation = validateDefensiveActionRequest({
          agentId: String(body.agentId || ''),
          actionType: String(body.actionType || ''),
          targetDetail: String(body.targetDetail || ''),
          rationale: String(body.rationale || ''),
        });
        if (!validation.valid || !validation.actionType) {
          res.status(400).json({ error: validation.error });
          return;
        }

        const action = await createHumanApprovalAction({
          userId: uid,
          agentId: String(body.agentId),
          incidentId: typeof body.incidentId === 'string' ? body.incidentId : null,
          actionType: validation.actionType,
          targetDetail: String(body.targetDetail),
          rationale: String(body.rationale),
          requestedBy: actor,
        });

        res.status(201).json({ ok: true, action });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to queue defensive action.';
        res.status(500).json({ error: msg });
      }
    }
  );

  router.post(
    '/approvals/:actionId/decision',
    requireVerifiedFirebaseUser,
    async (req: SentinelAuthenticatedRequest, res: Response) => {
      try {
        const uid = req.authUser!.uid;
        const actor = req.authUser!.email || uid;
        const body = (req.body || {}) as { decision?: string; decisionNote?: string };
        const decision = body.decision === 'approved' || body.decision === 'rejected' ? body.decision : null;
        if (!decision) {
          res.status(400).json({ error: 'decision must be "approved" or "rejected".' });
          return;
        }

        const decided = await decideHumanApprovalAction({
          userId: uid,
          actionId: req.params.actionId,
          decision,
          decidedBy: actor,
          decisionNote: typeof body.decisionNote === 'string' ? body.decisionNote : '',
        });

        if (!decided) {
          res.status(404).json({ error: 'Pending approval action not found.' });
          return;
        }

        res.json({ ok: true, action: decided });
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to record approval decision.';
        res.status(500).json({ error: msg });
      }
    }
  );

  return router;
}
