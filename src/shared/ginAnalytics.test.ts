import test from 'node:test';
import assert from 'node:assert/strict';
import {
  detectKnowledgeConflicts,
  evaluateNetworkAssetTelemetry,
  isPrivateOrReservedIp,
  parseRobotsTxt,
  searchKnowledgeNodes,
  synthesizeDeterministicBehaviourInsight,
  validateAuthorizedScopeInput,
  validatePublicCrawlTarget,
} from './ginAnalytics';
import type { KnowledgeNodeRecord, NetworkAssetRecord } from './ginTypes';

test('Network Observer telemetry scoring detects DNS/flow anomalies accurately', () => {
  const nominal = evaluateNetworkAssetTelemetry({
    dnsQueriesPerMin: 22,
    nxdomainRatio: 0.02,
    outboundMbps: 12,
    baselineMbps: 15,
  });
  assert.equal(nominal.status, 'nominal');
  assert.ok(nominal.anomalyScore < 35);

  const anomalous = evaluateNetworkAssetTelemetry({
    dnsQueriesPerMin: 240,
    nxdomainRatio: 0.34,
    outboundMbps: 95,
    baselineMbps: 20,
  });
  assert.equal(anomalous.status, 'anomalous');
  assert.ok(anomalous.anomalyScore >= 65);
  assert.ok(anomalous.signals.length >= 3);
});

test('Authorized scope validator blocks covert interception and unauthorized terms', () => {
  assert.equal(
    validateAuthorizedScopeInput({
      hostname: 'gw-edge-01',
      ipRange: '10.42.0.1/24',
      authorizedScope: 'Lab-Authorized-VLAN',
    }).valid,
    true
  );

  const blocked = validateAuthorizedScopeInput({
    hostname: 'tls-decrypt-proxy',
    ipRange: '10.42.0.5',
    authorizedScope: 'Covert MITM',
  });
  assert.equal(blocked.valid, false);
  assert.ok(blocked.error?.includes('GIN Security Governance'));
});

test('SSRF validator blocks localhost, RFC1918 private IPs, and cloud metadata endpoints', () => {
  assert.equal(validatePublicCrawlTarget('https://example.org').valid, true);
  assert.equal(validatePublicCrawlTarget('http://localhost:3000').valid, false);
  assert.equal(validatePublicCrawlTarget('http://127.0.0.1/admin').valid, false);
  assert.equal(validatePublicCrawlTarget('http://169.254.169.254/latest/meta-data/').valid, false);
  assert.equal(validatePublicCrawlTarget('http://metadata.google.internal/').valid, false);
  assert.equal(validatePublicCrawlTarget('http://192.168.1.10').valid, false);
  assert.equal(validatePublicCrawlTarget('ftp://example.org').valid, false);

  assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('172.16.4.2'), true);
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
});

test('robots.txt parser respects Disallow rules and Crawl-delay directives', () => {
  const restrictive = parseRobotsTxt(
    'https://private.example',
    'User-agent: *\nDisallow: /\nCrawl-delay: 10\n'
  );
  assert.equal(restrictive.allowedForGinBot, false);
  assert.equal(restrictive.crawlDelaySeconds, 10);

  const selective = parseRobotsTxt(
    'https://docs.example',
    'User-agent: *\nDisallow: /admin\nDisallow: /private\nCrawl-delay: 3\n'
  );
  assert.equal(selective.allowedForGinBot, true);
  assert.deepEqual(selective.disallowedPaths, ['/admin', '/private']);
  assert.equal(selective.crawlDelaySeconds, 3);
});

test('Knowledge Graph detects duplicate claims, contradictions, and scores semantic search', () => {
  const now = Date.now();
  const nodes: KnowledgeNodeRecord[] = [
    {
      id: 'kn_1',
      userId: 'u1',
      label: 'Outbound WSS Relay',
      entityType: 'protocol',
      claim: 'Local workstation nodes initiate outbound TLS 1.3 WebSocket tunnels with zero inbound ports.',
      sourceTitle: 'GIN Spec v0.2',
      sourceUri: 'https://example.org/spec',
      confidenceScore: 95,
      relations: [{ targetId: 'kn_2', targetLabel: 'Cloud Run Relay', predicate: 'connects_to' }],
      createdAtMs: now,
      updatedAtMs: now,
    },
    {
      id: 'kn_2',
      userId: 'u1',
      label: 'Outbound WSS Relay',
      entityType: 'protocol',
      claim: 'Local workstation nodes initiate outbound TLS 1.3 WebSocket tunnels with zero inbound ports.',
      sourceTitle: 'External Blog Mirror',
      sourceUri: 'https://example.com/mirror',
      confidenceScore: 80,
      relations: [],
      createdAtMs: now,
      updatedAtMs: now,
    },
    {
      id: 'kn_3',
      userId: 'u1',
      label: 'TLS Decryption',
      entityType: 'protocol',
      claim: 'Covert TLS decryption is enabled on passive edge sensors.',
      sourceTitle: 'Unverified Draft',
      sourceUri: 'https://example.net/draft',
      confidenceScore: 30,
      relations: [],
      createdAtMs: now,
      updatedAtMs: now,
    },
    {
      id: 'kn_4',
      userId: 'u1',
      label: 'TLS Decryption',
      entityType: 'protocol',
      claim: 'Covert TLS decryption is strictly prohibited and never enabled on passive edge sensors.',
      sourceTitle: 'GIN Security Governance',
      sourceUri: 'https://example.org/policy',
      confidenceScore: 99,
      relations: [],
      createdAtMs: now,
      updatedAtMs: now,
    },
  ];

  const conflicts = detectKnowledgeConflicts(nodes);
  assert.ok(conflicts.some((c) => c.kind === 'duplicate'));
  assert.ok(conflicts.some((c) => c.kind === 'contradiction'));

  const results = searchKnowledgeNodes(nodes, 'outbound websocket tls');
  assert.ok(results.length >= 1);
  assert.equal(results[0].node.label, 'Outbound WSS Relay');
});

test('Behaviour Engine clearly separates verified facts from analytical predictions', () => {
  const now = Date.now();
  const assets: NetworkAssetRecord[] = [
    {
      id: 'asset_1',
      userId: 'u1',
      hostname: 'lab-sensor-01',
      ipRange: '10.20.0.14/32',
      authorizedScope: 'Lab-Segment-A',
      assetType: 'sensor',
      status: 'anomalous',
      dnsQueriesPerMin: 210,
      nxdomainRatio: 0.31,
      outboundMbps: 88,
      baselineMbps: 20,
      anomalyScore: 82,
      threatMatch: 'High DNS rate',
      lastSeenMs: now,
      createdAtMs: now,
      updatedAtMs: now,
    },
  ];

  const insight = synthesizeDeterministicBehaviourInsight(assets);
  assert.equal(insight.severity, 'critical');
  assert.ok(insight.confidenceScore >= 70);
  assert.ok(insight.facts.length >= 2);
  assert.ok(insight.predictions.length >= 1);
});
