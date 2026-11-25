import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ExternalLink,
  Focus,
  Link2,
  Network,
  Plus,
  Search,
  Tag,
  Trash2,
} from 'lucide-react';
import { useGinIntelligence } from '../context/GinIntelligenceContext';
import { KnowledgeGraphSvg } from '../components/KnowledgeGraphSvg';
import { searchKnowledgeNodes } from '../shared/ginAnalytics';
import {
  ENTITY_TYPE_STYLE,
  KNOWLEDGE_ENTITY_TYPES,
} from '../shared/knowledgeGraphLayout';
import type { KnowledgeEntityType, KnowledgeNodeRecord } from '../shared/ginTypes';
import { isSafeExternalUrl } from '../shared/validation';

export const KnowledgeGraphView: React.FC = () => {
  const {
    knowledgeNodes,
    knowledgeConflicts,
    addKnowledgeNode,
    linkKnowledgeNodes,
    deleteKnowledgeNode,
  } = useGinIntelligence();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(
    knowledgeNodes[0]?.id || null
  );

  // Interactive D3 graph filters
  const [typeFilter, setTypeFilter] = useState<'all' | KnowledgeEntityType>('all');
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [focusNeighborhoodOnly, setFocusNeighborhoodOnly] = useState<boolean>(false);
  const [showEdgeLabels, setShowEdgeLabels] = useState<boolean>(true);

  // Add node form state
  const [label, setLabel] = useState('');
  const [entityType, setEntityType] = useState<KnowledgeEntityType>('concept');
  const [claim, setClaim] = useState('');
  const [sourceTitle, setSourceTitle] = useState('');
  const [sourceUri, setSourceUri] = useState('');
  const [confidenceScore, setConfidenceScore] = useState('85');
  const [confidenceExplanation, setConfidenceExplanation] = useState('');
  const [nodeError, setNodeError] = useState<string | null>(null);
  const [nodeNotice, setNodeNotice] = useState<string | null>(null);

  // Link relation state
  const [linkTargetId, setLinkTargetId] = useState('');
  const [linkPredicate, setLinkPredicate] = useState('correlates_with');
  const [linkFeedback, setLinkFeedback] = useState<string | null>(null);

  const rankedMatches = useMemo(
    () => searchKnowledgeNodes(knowledgeNodes, searchQuery),
    [knowledgeNodes, searchQuery]
  );

  const highlightedNodeIds = useMemo(() => {
    if (!searchQuery.trim()) return undefined;
    return new Set(rankedMatches.map((m) => m.node.id));
  }, [rankedMatches, searchQuery]);

  const selectedNode: KnowledgeNodeRecord | null =
    knowledgeNodes.find((n) => n.id === selectedNodeId) || rankedMatches[0]?.node || null;

  // Incoming relations pointing to selectedNode
  const incomingRelations = useMemo(() => {
    if (!selectedNode) return [];
    const results: Array<{ fromId: string; fromLabel: string; predicate: string }> = [];
    for (const n of knowledgeNodes) {
      for (const rel of n.relations) {
        if (rel.targetId === selectedNode.id) {
          results.push({ fromId: n.id, fromLabel: n.label, predicate: rel.predicate });
        }
      }
    }
    return results;
  }, [knowledgeNodes, selectedNode]);

  // Distinct entity types currently present in the graph for compact filter buttons
  const presentTypes = useMemo(() => {
    const counts = new Map<KnowledgeEntityType, number>();
    for (const n of knowledgeNodes) {
      counts.set(n.entityType, (counts.get(n.entityType) || 0) + 1);
    }
    return KNOWLEDGE_ENTITY_TYPES.filter((t) => (counts.get(t) || 0) > 0).map((t) => ({
      type: t,
      count: counts.get(t) || 0,
    }));
  }, [knowledgeNodes]);

  const handleAddNode = async (e: React.FormEvent) => {
    e.preventDefault();
    setNodeError(null);
    setNodeNotice(null);
    const res = await addKnowledgeNode({
      label,
      entityType,
      claim,
      sourceTitle,
      sourceUri,
      confidenceScore: Number(confidenceScore) || 80,
      confidenceExplanation,
    });
    if (!res.ok) {
      setNodeError(res.error || 'Could not add knowledge entity.');
    } else {
      if (res.conflictDetected) {
        setNodeNotice(res.conflictDetected);
      } else {
        setNodeNotice(`Stored "${label}" with timestamp and source provenance.`);
      }
      setLabel('');
      setClaim('');
      setSourceTitle('');
      setSourceUri('');
      setConfidenceExplanation('');
    }
  };

  const handleCreateLink = async (e: React.FormEvent) => {
    e.preventDefault();
    setLinkFeedback(null);
    if (!selectedNode) return;
    const res = await linkKnowledgeNodes(selectedNode.id, linkTargetId, linkPredicate);
    if (!res.ok) {
      setLinkFeedback(res.error || 'Select a target entity.');
    } else {
      setLinkFeedback(`Linked "${selectedNode.label}" via "${linkPredicate}".`);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-blue-400">
          <Network className="w-3.5 h-3.5" />
          <span>GRI v0.5 Operational · D3.js Force-Directed Entity-Relation Memory &amp; Conflict Audit</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Global Knowledge Graph</h1>
        <p className="text-sm text-slate-400 max-w-3xl">
          Visually explore relationships between entities discovered by Internet Explorer, Frontend
          &amp; Server Intelligence, Security Research, and Network Observer. Drag nodes, zoom,
          filter by entity type, and surface contradictory claims automatically.
        </p>
      </div>

      {/* Automated Duplicate & Contradiction Audit Banner */}
      {knowledgeConflicts.length > 0 && (
        <section
          aria-label="Knowledge graph conflicts"
          className="rounded-xl bg-red-950/20 border border-red-500/35 px-4 py-3 space-y-2"
        >
          <div className="flex items-center gap-2 text-red-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <h2 className="text-sm font-semibold">
              {knowledgeConflicts.length} Claim Conflict / Duplicate Flag(s) Detected
            </h2>
          </div>
          <div className="divide-y divide-white/[0.06]">
            {knowledgeConflicts.map((c, idx) => (
              <div
                key={`${c.nodeAId}-${c.nodeBId}-${idx}`}
                className="py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
              >
                <div className="space-y-0.5">
                  <p className="font-mono">
                    <span
                      className={
                        c.kind === 'contradiction'
                          ? 'text-red-400 font-semibold'
                          : 'text-amber-300 font-semibold'
                      }
                    >
                      {c.kind.toUpperCase()}
                    </span>{' '}
                    · <span className="text-white">{c.nodeALabel}</span> ↔{' '}
                    <span className="text-white">{c.nodeBLabel}</span>
                  </p>
                  <p className="text-slate-300">{c.reason}</p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setTypeFilter('all');
                    setMinConfidence(0);
                    setFocusNeighborhoodOnly(false);
                    setSelectedNodeId(c.nodeBId);
                  }}
                  className="px-2.5 py-1 text-[11px] font-medium bg-white/[0.08] hover:bg-white/[0.14] text-slate-100 rounded-md whitespace-nowrap shrink-0 cursor-pointer self-start"
                >
                  Inspect Conflicting Node
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Interactive Filter Toolbar for D3 Graph */}
      <section
        aria-label="Knowledge graph visualization filters"
        className="rounded-xl bg-[#0f131c] border border-white/[0.08] px-4 py-3 space-y-2.5"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div
            role="group"
            aria-label="Filter graph by entity type"
            className="flex flex-wrap items-center gap-1.5"
          >
            <button
              type="button"
              onClick={() => setTypeFilter('all')}
              className={`px-2.5 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                typeFilter === 'all'
                  ? 'bg-blue-600 text-white'
                  : 'bg-[#090b10] text-slate-400 hover:text-white border border-white/[0.08]'
              }`}
            >
              All ({knowledgeNodes.length})
            </button>
            {presentTypes.map(({ type, count }) => (
              <button
                key={type}
                type="button"
                onClick={() => setTypeFilter(type)}
                className={`px-2.5 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  typeFilter === type
                    ? 'bg-blue-600 text-white'
                    : 'bg-[#090b10] text-slate-400 hover:text-white border border-white/[0.08]'
                }`}
              >
                {ENTITY_TYPE_STYLE[type].label} ({count})
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <label
                htmlFor="kg-min-confidence"
                className="text-xs font-mono text-slate-400 whitespace-nowrap tabular-nums"
              >
                Min Confidence: {minConfidence}%
              </label>
              <input
                id="kg-min-confidence"
                type="range"
                min={0}
                max={95}
                step={5}
                value={minConfidence}
                onChange={(e) => setMinConfidence(Number(e.target.value))}
                className="w-24 accent-blue-500 cursor-pointer"
              />
            </div>

            <button
              type="button"
              aria-pressed={focusNeighborhoodOnly}
              onClick={() => setFocusNeighborhoodOnly((v) => !v)}
              disabled={!selectedNode}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40 ${
                focusNeighborhoodOnly
                  ? 'bg-blue-600/20 border-blue-500/45 text-blue-200'
                  : 'bg-[#090b10] border-white/[0.08] text-slate-300 hover:text-white'
              }`}
            >
              <Focus className="w-3.5 h-3.5" />
              <span>Focus 1-Hop</span>
            </button>

            <button
              type="button"
              aria-pressed={showEdgeLabels}
              onClick={() => setShowEdgeLabels((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                showEdgeLabels
                  ? 'bg-blue-600/20 border-blue-500/45 text-blue-200'
                  : 'bg-[#090b10] border-white/[0.08] text-slate-300 hover:text-white'
              }`}
            >
              <Tag className="w-3.5 h-3.5" />
              <span>Edge Labels</span>
            </button>
          </div>
        </div>
      </section>

      {/* D3 Force-Directed Graph Visualization + Selected Entity Inspector */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-8 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-base font-semibold text-white">
              Interactive Entity Relationship Graph (D3.js)
            </h2>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {knowledgeNodes.length} entities stored
            </span>
          </div>
          <KnowledgeGraphSvg
            nodes={knowledgeNodes}
            conflicts={knowledgeConflicts}
            selectedNodeId={selectedNode?.id || null}
            onSelectNode={(node) => setSelectedNodeId(node.id)}
            entityTypeFilter={typeFilter}
            minConfidence={minConfidence}
            focusNeighborhoodOnly={focusNeighborhoodOnly}
            showEdgeLabels={showEdgeLabels}
            highlightedNodeIds={highlightedNodeIds}
          />
        </div>

        <div className="lg:col-span-4 rounded-xl bg-[#0f131c] border border-white/[0.08] p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-base font-semibold text-white">Selected Entity</h2>
            {selectedNode && (
              <button
                type="button"
                onClick={() => deleteKnowledgeNode(selectedNode.id)}
                aria-label={`Delete entity ${selectedNode.label}`}
                className="p-1.5 text-slate-400 hover:text-red-400 rounded-md cursor-pointer"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>

          {!selectedNode ? (
            <p className="text-sm text-slate-400">Select or add a Knowledge Graph entity.</p>
          ) : (
            <div className="space-y-4">
              <div className="space-y-1">
                <p className="text-xs font-mono tabular-nums" style={{ color: ENTITY_TYPE_STYLE[selectedNode.entityType]?.text || '#60a5fa' }}>
                  {ENTITY_TYPE_STYLE[selectedNode.entityType]?.label || selectedNode.entityType} · Confidence {selectedNode.confidenceScore}%
                </p>
                <h3 className="text-base font-semibold text-white">{selectedNode.label}</h3>
                <p className="text-xs text-slate-300 leading-relaxed">{selectedNode.claim}</p>
              </div>

              <div className="pt-3 border-t border-white/[0.06] space-y-1.5 text-xs">
                <p className="text-slate-400">
                  Source: <span className="text-slate-200">{selectedNode.sourceTitle}</span>
                </p>
                {selectedNode.sourceUri && isSafeExternalUrl(selectedNode.sourceUri) && (
                  <a
                    href={selectedNode.sourceUri}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-blue-400 hover:underline break-all"
                  >
                    <span>Verify Primary Source</span>
                    <ExternalLink className="w-3 h-3 shrink-0" />
                  </a>
                )}
                <div className="p-2.5 rounded-lg bg-[#090b10] border border-white/[0.06] space-y-1">
                  <p className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    Confidence Explanation ({selectedNode.confidenceScore}%)
                  </p>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    {selectedNode.confidenceExplanation ||
                      `${selectedNode.confidenceScore}% calibrated from "${selectedNode.sourceTitle}"${
                        selectedNode.sourceUri
                          ? ' with verifiable external citation URL.'
                          : ' (internal/operator observation without external URI).'
                      }`}
                  </p>
                </div>
                <div className="font-mono text-[11px] text-slate-500 tabular-nums space-y-0.5">
                  <p>Observed: {new Date(selectedNode.createdAtMs).toLocaleString()}</p>
                  <p>Updated: {new Date(selectedNode.updatedAtMs).toLocaleString()}</p>
                </div>
              </div>

              {/* Outgoing & Incoming edges + Link form */}
              <div className="pt-3 border-t border-white/[0.06] space-y-2">
                <p className="text-xs font-semibold text-slate-300">Connected Relations</p>
                {selectedNode.relations.length === 0 && incomingRelations.length === 0 ? (
                  <p className="text-xs text-slate-500">No connected relations yet.</p>
                ) : (
                  <ul className="space-y-1.5 text-xs font-mono text-slate-300">
                    {selectedNode.relations.map((rel, i) => (
                      <li key={`out-${rel.targetId}-${i}`}>
                        <button
                          type="button"
                          onClick={() => setSelectedNodeId(rel.targetId)}
                          className="text-left hover:text-blue-300 transition-colors cursor-pointer"
                        >
                          · [{rel.predicate}] → {rel.targetLabel}
                        </button>
                      </li>
                    ))}
                    {incomingRelations.map((rel, i) => (
                      <li key={`in-${rel.fromId}-${i}`} className="text-slate-400">
                        <button
                          type="button"
                          onClick={() => setSelectedNodeId(rel.fromId)}
                          className="text-left hover:text-blue-300 transition-colors cursor-pointer"
                        >
                          · {rel.fromLabel} → [{rel.predicate}]
                        </button>
                      </li>
                    ))}
                  </ul>
                )}

                <form onSubmit={handleCreateLink} className="pt-2 space-y-2">
                  <div className="flex gap-2">
                    <select
                      aria-label="Relationship predicate"
                      value={linkPredicate}
                      onChange={(e) => setLinkPredicate(e.target.value)}
                      className="px-2 py-1.5 text-xs font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
                    >
                      <option value="correlates_with">correlates_with</option>
                      <option value="depends_on">depends_on</option>
                      <option value="hosted_on">hosted_on</option>
                      <option value="affects_version">affects_version</option>
                      <option value="mitigates">mitigates</option>
                      <option value="monitors">monitors</option>
                      <option value="contradicts">contradicts</option>
                    </select>
                    <select
                      aria-label="Target knowledge entity"
                      value={linkTargetId}
                      onChange={(e) => setLinkTargetId(e.target.value)}
                      className="flex-1 min-w-0 px-2 py-1.5 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
                    >
                      <option value="">Target entity...</option>
                      {knowledgeNodes
                        .filter((n) => n.id !== selectedNode.id)
                        .map((n) => (
                          <option key={n.id} value={n.id}>
                            {n.label}
                          </option>
                        ))}
                    </select>
                  </div>
                  <button
                    type="submit"
                    className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-white/[0.08] hover:bg-white/[0.14] text-white rounded-lg cursor-pointer"
                  >
                    <Link2 className="w-3.5 h-3.5" />
                    <span>Connect Entity</span>
                  </button>
                  {linkFeedback && <p className="text-[11px] text-blue-300">{linkFeedback}</p>}
                </form>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Two-Column Split: Semantic Search Index + Add Knowledge Node */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className="lg:col-span-7 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <h2 className="text-base font-semibold text-white">Semantic Search &amp; Retrieval</h2>
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <label htmlFor="kg-search-input" className="sr-only">
                Search knowledge graph entities
              </label>
              <input
                id="kg-search-input"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search entities, CVEs, stacks..."
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
            {rankedMatches.length === 0 ? (
              <p className="py-6 text-center text-xs text-slate-400">
                No entities matched &ldquo;{searchQuery}&rdquo;.
              </p>
            ) : (
              rankedMatches.map(({ node, relevance }) => (
                <div
                  key={node.id}
                  className="py-3 flex items-start justify-between gap-3 hover:bg-white/[0.02] px-1"
                >
                  <button
                    type="button"
                    onClick={() => setSelectedNodeId(node.id)}
                    className="text-left space-y-1 min-w-0 cursor-pointer"
                  >
                    <p className="text-sm font-medium text-white">
                      {node.label}{' '}
                      <span className="text-xs font-mono font-normal text-slate-400">
                        · {ENTITY_TYPE_STYLE[node.entityType]?.label || node.entityType} ·{' '}
                        {node.confidenceScore}% conf
                        {searchQuery.trim() ? ` · ${Math.round(relevance * 100)}% match` : ''}
                      </span>
                    </p>
                    <p className="text-xs text-slate-400 leading-relaxed">{node.claim}</p>
                    <p className="text-[11px] font-mono text-slate-500">
                      Source: {node.sourceTitle}
                    </p>
                  </button>
                </div>
              ))
            )}
          </div>
        </section>

        <form
          onSubmit={handleAddNode}
          className="lg:col-span-5 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
        >
          <h2 className="text-base font-semibold text-white">Add Knowledge Entity</h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label htmlFor="kg-label" className="block text-xs text-slate-300">
                Entity Label
              </label>
              <input
                id="kg-label"
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g., CVE-2024-6387 or RFC 9309"
                maxLength={120}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="kg-type" className="block text-xs text-slate-300">
                Entity Type
              </label>
              <select
                id="kg-type"
                value={entityType}
                onChange={(e) => setEntityType(e.target.value as KnowledgeEntityType)}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
              >
                <option value="concept">Concept</option>
                <option value="framework">Framework</option>
                <option value="infrastructure">Infrastructure</option>
                <option value="vulnerability">Vulnerability (CVE)</option>
                <option value="protocol">Protocol</option>
                <option value="technology">Technology</option>
                <option value="organization">Organization</option>
                <option value="asset">Asset</option>
                <option value="threat">Threat Indicator</option>
              </select>
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="kg-claim" className="block text-xs text-slate-300">
              Verified Claim or Observation
            </label>
            <textarea
              id="kg-claim"
              rows={3}
              value={claim}
              onChange={(e) => setClaim(e.target.value)}
              placeholder="State the structured claim with clear polarity for conflict checks..."
              maxLength={600}
              className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2 space-y-1">
              <label htmlFor="kg-source-title" className="block text-xs text-slate-300">
                Source Title
              </label>
              <input
                id="kg-source-title"
                type="text"
                value={sourceTitle}
                onChange={(e) => setSourceTitle(e.target.value)}
                placeholder="e.g., IETF RFC Editor / NVD"
                maxLength={160}
                className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="kg-confidence" className="block text-xs text-slate-300">
                Confidence (%)
              </label>
              <input
                id="kg-confidence"
                type="number"
                min={0}
                max={100}
                value={confidenceScore}
                onChange={(e) => setConfidenceScore(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#090b10] border border-white/[0.1] rounded-lg text-white"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="kg-source-uri" className="block text-xs text-slate-300">
              Source URL (optional HTTPS)
            </label>
            <input
              id="kg-source-uri"
              type="url"
              value={sourceUri}
              onChange={(e) => setSourceUri(e.target.value)}
              placeholder="https://www.rfc-editor.org/rfc/rfc9309"
              className="w-full px-3 py-2 text-xs font-mono bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="kg-conf-explain" className="block text-xs text-slate-300">
              Confidence Explanation (optional)
            </label>
            <input
              id="kg-conf-explain"
              type="text"
              value={confidenceExplanation}
              onChange={(e) => setConfidenceExplanation(e.target.value)}
              placeholder="Why this confidence score? (e.g., corroborated by 2 independent logs)"
              maxLength={240}
              className="w-full px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
            <p className="text-[11px] text-slate-500">
              Conflicting claims for an existing entity label are preserved side-by-side and auto-linked via <code>[contradicts]</code> — never silently overwritten.
            </p>
          </div>

          {nodeError && (
            <p role="alert" className="text-xs text-red-400">
              {nodeError}
            </p>
          )}
          {nodeNotice && (
            <p role="status" className="text-xs text-amber-300 bg-amber-950/30 border border-amber-500/30 rounded-lg px-3 py-2">
              {nodeNotice}
            </p>
          )}

          <button
            type="submit"
            className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Commit to Knowledge Graph</span>
          </button>
        </form>
      </div>
    </div>
  );
};
