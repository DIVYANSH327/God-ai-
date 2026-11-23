import type {
  KnowledgeConflictFinding,
  KnowledgeEntityType,
  KnowledgeNodeRecord,
} from './ginTypes';

export interface EntityTypeStyle {
  label: string;
  stroke: string;
  fill: string;
  text: string;
}

export const KNOWLEDGE_ENTITY_TYPES: readonly KnowledgeEntityType[] = [
  'concept',
  'organization',
  'technology',
  'asset',
  'threat',
  'protocol',
  'vulnerability',
  'framework',
  'infrastructure',
] as const;

export const ENTITY_TYPE_STYLE: Record<KnowledgeEntityType, EntityTypeStyle> = {
  concept: {
    label: 'Concept',
    stroke: '#60a5fa',
    fill: '#111b2e',
    text: '#93c5fd',
  },
  organization: {
    label: 'Organization',
    stroke: '#818cf8',
    fill: '#151933',
    text: '#a5b4fc',
  },
  technology: {
    label: 'Technology',
    stroke: '#38bdf8',
    fill: '#0e2030',
    text: '#7dd3fc',
  },
  asset: {
    label: 'Asset',
    stroke: '#34d399',
    fill: '#0d231e',
    text: '#6ee7b7',
  },
  threat: {
    label: 'Threat',
    stroke: '#f87171',
    fill: '#2a1317',
    text: '#fca5a5',
  },
  protocol: {
    label: 'Protocol',
    stroke: '#c084fc',
    fill: '#1e1530',
    text: '#d8b4fe',
  },
  vulnerability: {
    label: 'Vulnerability (CVE)',
    stroke: '#fb7185',
    fill: '#2c121b',
    text: '#fda4af',
  },
  framework: {
    label: 'Framework',
    stroke: '#2dd4bf',
    fill: '#0d2324',
    text: '#5eead4',
  },
  infrastructure: {
    label: 'Infrastructure',
    stroke: '#fbbf24',
    fill: '#261e0e',
    text: '#fcd34d',
  },
};

export interface D3KnowledgeNode {
  id: string;
  record: KnowledgeNodeRecord;
  label: string;
  shortLabel: string;
  entityType: KnowledgeEntityType;
  confidenceScore: number;
  degree: number;
  radius: number;
  hasConflict: boolean;
  isHighlighted: boolean;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface D3KnowledgeLink {
  id: string;
  source: string | D3KnowledgeNode;
  target: string | D3KnowledgeNode;
  predicate: string;
  kind: 'relation' | 'contradiction' | 'duplicate';
  curveOffset: number;
}

export interface KnowledgeGraphBuildOptions {
  entityTypeFilter?: 'all' | KnowledgeEntityType;
  minConfidence?: number;
  selectedNodeId?: string | null;
  focusNeighborhoodOnly?: boolean;
  highlightedNodeIds?: ReadonlySet<string>;
  maxNodes?: number;
}

export interface KnowledgeGraphProjection {
  nodes: D3KnowledgeNode[];
  links: D3KnowledgeLink[];
  connectedNodeIds: Set<string>;
  stats: {
    totalNodes: number;
    visibleNodes: number;
    relationEdges: number;
    conflictEdges: number;
    typeCounts: Partial<Record<KnowledgeEntityType, number>>;
  };
}

export function truncateNodeLabel(label: string, maxLen = 20): string {
  const clean = label.trim();
  if (clean.length <= maxLen) return clean;
  return `${clean.slice(0, Math.max(1, maxLen - 2))}..`;
}

export function getEndpointId(endpoint: string | D3KnowledgeNode): string {
  return typeof endpoint === 'string' ? endpoint : endpoint.id;
}

export function buildD3KnowledgeGraph(
  records: readonly KnowledgeNodeRecord[],
  conflicts: readonly KnowledgeConflictFinding[],
  options: KnowledgeGraphBuildOptions = {}
): KnowledgeGraphProjection {
  const {
    entityTypeFilter = 'all',
    minConfidence = 0,
    selectedNodeId = null,
    focusNeighborhoodOnly = false,
    highlightedNodeIds,
    maxNodes = 60,
  } = options;

  const typeCounts: Partial<Record<KnowledgeEntityType, number>> = {};
  for (const r of records) {
    typeCounts[r.entityType] = (typeCounts[r.entityType] || 0) + 1;
  }

  // First filter by entity type and minimum confidence
  let filtered = records.filter((node) => {
    if (entityTypeFilter !== 'all' && node.entityType !== entityTypeFilter) {
      return false;
    }
    if (node.confidenceScore < minConfidence) {
      return false;
    }
    return true;
  });

  // Collect adjacency across filtered nodes for neighborhood focus & selection highlight
  const filteredIdSet = new Set(filtered.map((n) => n.id));
  const adjacency = new Map<string, Set<string>>();
  for (const n of filtered) {
    adjacency.set(n.id, new Set<string>());
  }
  for (const n of filtered) {
    for (const rel of n.relations) {
      if (rel.targetId !== n.id && filteredIdSet.has(rel.targetId)) {
        adjacency.get(n.id)?.add(rel.targetId);
        adjacency.get(rel.targetId)?.add(n.id);
      }
    }
  }
  for (const c of conflicts) {
    if (c.nodeAId !== c.nodeBId && filteredIdSet.has(c.nodeAId) && filteredIdSet.has(c.nodeBId)) {
      adjacency.get(c.nodeAId)?.add(c.nodeBId);
      adjacency.get(c.nodeBId)?.add(c.nodeAId);
    }
  }

  const connectedNodeIds = new Set<string>();
  if (selectedNodeId && filteredIdSet.has(selectedNodeId)) {
    connectedNodeIds.add(selectedNodeId);
    for (const neighbor of adjacency.get(selectedNodeId) || []) {
      connectedNodeIds.add(neighbor);
    }
  }

  if (focusNeighborhoodOnly && selectedNodeId && connectedNodeIds.size > 0) {
    filtered = filtered.filter((n) => connectedNodeIds.has(n.id));
  }

  const visibleRecords = filtered.slice(0, maxNodes);
  const visibleIdSet = new Set(visibleRecords.map((n) => n.id));

  const conflictNodeIds = new Set<string>();
  const rawLinks: Array<Omit<D3KnowledgeLink, 'curveOffset'>> = [];
  const seenLinkKeys = new Set<string>();

  // Directed relation links
  for (const node of visibleRecords) {
    for (const rel of node.relations) {
      if (rel.targetId === node.id || !visibleIdSet.has(rel.targetId)) continue;
      const key = `rel:${node.id}->${rel.targetId}:${rel.predicate}`;
      if (seenLinkKeys.has(key)) continue;
      seenLinkKeys.add(key);
      rawLinks.push({
        id: key,
        source: node.id,
        target: rel.targetId,
        predicate: rel.predicate,
        kind: 'relation',
      });
    }
  }

  // Conflict / duplicate links
  let conflictEdges = 0;
  for (const conflict of conflicts) {
    if (
      conflict.nodeAId === conflict.nodeBId ||
      !visibleIdSet.has(conflict.nodeAId) ||
      !visibleIdSet.has(conflict.nodeBId)
    ) {
      continue;
    }
    const [a, b] =
      conflict.nodeAId < conflict.nodeBId
        ? [conflict.nodeAId, conflict.nodeBId]
        : [conflict.nodeBId, conflict.nodeAId];
    const key = `conf:${conflict.kind}:${a}<->${b}`;
    if (seenLinkKeys.has(key)) continue;
    seenLinkKeys.add(key);
    conflictNodeIds.add(a);
    conflictNodeIds.add(b);
    conflictEdges += 1;
    rawLinks.push({
      id: key,
      source: conflict.nodeAId,
      target: conflict.nodeBId,
      predicate: conflict.kind.toUpperCase(),
      kind: conflict.kind,
    });
  }

  // Group parallel edges between the same unordered node pair to assign clean curve offsets
  const pairGroups = new Map<string, number[]>();
  rawLinks.forEach((link, idx) => {
    const s = getEndpointId(link.source);
    const t = getEndpointId(link.target);
    const pairKey = s < t ? `${s}::${t}` : `${t}::${s}`;
    const arr = pairGroups.get(pairKey) || [];
    arr.push(idx);
    pairGroups.set(pairKey, arr);
  });

  const links: D3KnowledgeLink[] = rawLinks.map((link, idx) => {
    const s = getEndpointId(link.source);
    const t = getEndpointId(link.target);
    const pairKey = s < t ? `${s}::${t}` : `${t}::${s}`;
    const group = pairGroups.get(pairKey) || [idx];
    const pos = group.indexOf(idx);
    const count = group.length;
    const curveOffset = count === 1 ? 0 : (pos - (count - 1) / 2) * 32;
    return {
      ...link,
      curveOffset,
    };
  });

  // Compute node degree from visible links
  const degreeMap = new Map<string, number>();
  for (const link of links) {
    const s = getEndpointId(link.source);
    const t = getEndpointId(link.target);
    degreeMap.set(s, (degreeMap.get(s) || 0) + 1);
    degreeMap.set(t, (degreeMap.get(t) || 0) + 1);
  }

  const nodes: D3KnowledgeNode[] = visibleRecords.map((record) => {
    const degree = degreeMap.get(record.id) || 0;
    const radius = Math.min(28, 16 + degree * 2.5);
    return {
      id: record.id,
      record,
      label: record.label,
      shortLabel: truncateNodeLabel(record.label, 22),
      entityType: record.entityType,
      confidenceScore: record.confidenceScore,
      degree,
      radius,
      hasConflict: conflictNodeIds.has(record.id),
      isHighlighted: Boolean(highlightedNodeIds?.has(record.id)),
    };
  });

  return {
    nodes,
    links,
    connectedNodeIds,
    stats: {
      totalNodes: records.length,
      visibleNodes: nodes.length,
      relationEdges: links.length - conflictEdges,
      conflictEdges,
      typeCounts,
    },
  };
}
