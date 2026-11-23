import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ENTITY_TYPE_STYLE,
  KNOWLEDGE_ENTITY_TYPES,
  buildD3KnowledgeGraph,
  getEndpointId,
  truncateNodeLabel,
} from './knowledgeGraphLayout';
import type { KnowledgeConflictFinding, KnowledgeNodeRecord } from './ginTypes';

const SAMPLE_NODES: KnowledgeNodeRecord[] = [
  {
    id: 'n1',
    userId: 'u1',
    label: 'Next.js Edge Architecture',
    entityType: 'framework',
    claim: 'Serves React SSR pages behind CDN edge caching.',
    sourceTitle: 'Web Tech Intel',
    sourceUri: 'https://react.dev',
    confidenceScore: 92,
    relations: [
      { targetId: 'n2', targetLabel: 'Cloudflare Dual-Stack', predicate: 'hosted_on' },
      { targetId: 'missing', targetLabel: 'Missing Node', predicate: 'dangling' },
    ],
    createdAtMs: 1000,
    updatedAtMs: 1000,
  },
  {
    id: 'n2',
    userId: 'u1',
    label: 'Cloudflare Dual-Stack',
    entityType: 'infrastructure',
    claim: 'Provides IPv4/IPv6 edge termination with CAA pinning.',
    sourceTitle: 'Server Intel',
    sourceUri: 'https://crt.sh/?q=rfc-editor.org',
    confidenceScore: 91,
    relations: [
      { targetId: 'n3', targetLabel: 'CVE-2024-21626', predicate: 'mitigates_exposure_for' },
    ],
    createdAtMs: 2000,
    updatedAtMs: 2000,
  },
  {
    id: 'n3',
    userId: 'u1',
    label: 'CVE-2024-21626',
    entityType: 'vulnerability',
    claim: 'runc container breakout via leaked file descriptor.',
    sourceTitle: 'CISA KEV',
    sourceUri: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21626',
    confidenceScore: 96,
    relations: [],
    createdAtMs: 3000,
    updatedAtMs: 3000,
  },
  {
    id: 'n4',
    userId: 'u1',
    label: 'Legacy Draft Claim',
    entityType: 'concept',
    claim: 'Contradictory low-confidence note.',
    sourceTitle: 'Old Draft',
    sourceUri: '',
    confidenceScore: 30,
    relations: [],
    createdAtMs: 4000,
    updatedAtMs: 4000,
  },
];

const SAMPLE_CONFLICTS: KnowledgeConflictFinding[] = [
  {
    nodeAId: 'n1',
    nodeALabel: 'Next.js Edge Architecture',
    nodeBId: 'n4',
    nodeBLabel: 'Legacy Draft Claim',
    kind: 'contradiction',
    reason: 'Conflicting deployment claim.',
  },
];

test('all 9 GRI v0.5 entity types have distinct visual style definitions', () => {
  assert.equal(KNOWLEDGE_ENTITY_TYPES.length, 9);
  for (const t of KNOWLEDGE_ENTITY_TYPES) {
    assert.ok(ENTITY_TYPE_STYLE[t]);
    assert.ok(ENTITY_TYPE_STYLE[t].stroke.startsWith('#'));
  }
});

test('buildD3KnowledgeGraph prunes dangling relations and includes conflict edges', () => {
  const graph = buildD3KnowledgeGraph(SAMPLE_NODES, SAMPLE_CONFLICTS);
  assert.equal(graph.nodes.length, 4);
  assert.equal(graph.stats.relationEdges, 2);
  assert.equal(graph.stats.conflictEdges, 1);
  assert.equal(graph.links.length, 3);

  const hub = graph.nodes.find((n) => n.id === 'n2');
  assert.ok(hub);
  assert.equal(hub.degree, 2);
  assert.equal(hub.radius, 21);

  const conflicted = graph.nodes.find((n) => n.id === 'n4');
  assert.ok(conflicted);
  assert.equal(conflicted.hasConflict, true);
});

test('buildD3KnowledgeGraph filters by entityType and minimum confidence cleanly', () => {
  const vulnOnly = buildD3KnowledgeGraph(SAMPLE_NODES, SAMPLE_CONFLICTS, {
    entityTypeFilter: 'vulnerability',
  });
  assert.equal(vulnOnly.nodes.length, 1);
  assert.equal(vulnOnly.nodes[0].id, 'n3');
  assert.equal(vulnOnly.links.length, 0);

  const highConf = buildD3KnowledgeGraph(SAMPLE_NODES, SAMPLE_CONFLICTS, {
    minConfidence: 80,
  });
  assert.equal(highConf.nodes.length, 3);
  assert.equal(highConf.stats.conflictEdges, 0);
});

test('focusNeighborhoodOnly restricts graph to selected node and 1-hop neighbors', () => {
  const focused = buildD3KnowledgeGraph(SAMPLE_NODES, SAMPLE_CONFLICTS, {
    selectedNodeId: 'n3',
    focusNeighborhoodOnly: true,
  });
  const ids = focused.nodes.map((n) => n.id).sort();
  assert.deepEqual(ids, ['n2', 'n3']);
  assert.equal(focused.links.length, 1);
  assert.equal(getEndpointId(focused.links[0].source), 'n2');
  assert.equal(getEndpointId(focused.links[0].target), 'n3');
});

test('parallel edges between same node pair receive non-zero opposing curve offsets', () => {
  const parallelConflicts: KnowledgeConflictFinding[] = [
    {
      nodeAId: 'n1',
      nodeALabel: 'Next.js Edge Architecture',
      nodeBId: 'n2',
      nodeBLabel: 'Cloudflare Dual-Stack',
      kind: 'duplicate',
      reason: 'Overlap',
    },
  ];
  const graph = buildD3KnowledgeGraph(SAMPLE_NODES, parallelConflicts);
  const between12 = graph.links.filter((l) => {
    const s = getEndpointId(l.source);
    const t = getEndpointId(l.target);
    return (s === 'n1' && t === 'n2') || (s === 'n2' && t === 'n1');
  });
  assert.equal(between12.length, 2);
  assert.notEqual(between12[0].curveOffset, 0);
  assert.equal(between12[0].curveOffset, -between12[1].curveOffset);
});

test('truncateNodeLabel shortens long labels deterministically', () => {
  assert.equal(truncateNodeLabel('Short', 10), 'Short');
  assert.equal(truncateNodeLabel('A Very Long Entity Name Here', 14), 'A Very Long ..');
});
