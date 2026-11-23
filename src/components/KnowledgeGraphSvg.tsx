import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Maximize2, RefreshCw, ZoomIn, ZoomOut } from 'lucide-react';
import type {
  KnowledgeConflictFinding,
  KnowledgeEntityType,
  KnowledgeNodeRecord,
} from '../shared/ginTypes';
import {
  ENTITY_TYPE_STYLE,
  buildD3KnowledgeGraph,
  getEndpointId,
  type D3KnowledgeLink,
  type D3KnowledgeNode,
} from '../shared/knowledgeGraphLayout';

interface KnowledgeGraphSvgProps {
  nodes: KnowledgeNodeRecord[];
  conflicts: KnowledgeConflictFinding[];
  selectedNodeId?: string | null;
  onSelectNode?: (node: KnowledgeNodeRecord) => void;
  compact?: boolean;
  entityTypeFilter?: 'all' | KnowledgeEntityType;
  minConfidence?: number;
  focusNeighborhoodOnly?: boolean;
  showEdgeLabels?: boolean;
  highlightedNodeIds?: ReadonlySet<string>;
}

interface HoveredNodeState {
  node: D3KnowledgeNode;
  x: number;
  y: number;
}

function computeQuadraticPath(
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  targetRadius: number,
  curveOffset: number
): { pathD: string; labelX: number; labelY: number } {
  const dx = tx - sx;
  const dy = ty - sy;
  const dist = Math.hypot(dx, dy) || 1;

  // Trim end so arrowhead stops cleanly at the target node's perimeter
  const pad = targetRadius + 7;
  const ratio = Math.max(0.15, (dist - pad) / dist);
  const ex = sx + dx * ratio;
  const ey = sy + dy * ratio;

  const mx = (sx + ex) / 2;
  const my = (sy + ey) / 2;

  if (Math.abs(curveOffset) < 0.5) {
    return {
      pathD: `M ${sx} ${sy} L ${ex} ${ey}`,
      labelX: mx,
      labelY: my - 6,
    };
  }

  // Perpendicular unit vector
  const nx = -dy / dist;
  const ny = dx / dist;
  const cx = mx + nx * curveOffset;
  const cy = my + ny * curveOffset;

  // Quadratic midpoint at t=0.5
  const labelX = 0.25 * sx + 0.5 * cx + 0.25 * ex;
  const labelY = 0.25 * sy + 0.5 * cy + 0.25 * ey;

  return {
    pathD: `M ${sx} ${sy} Q ${cx} ${cy} ${ex} ${ey}`,
    labelX,
    labelY,
  };
}

export const KnowledgeGraphSvg: React.FC<KnowledgeGraphSvgProps> = ({
  nodes,
  conflicts,
  selectedNodeId = null,
  onSelectNode,
  compact = false,
  entityTypeFilter = 'all',
  minConfidence = 0,
  focusNeighborhoodOnly = false,
  showEdgeLabels = true,
  highlightedNodeIds,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const simulationRef = useRef<d3.Simulation<D3KnowledgeNode, D3KnowledgeLink> | null>(null);
  const onSelectNodeRef = useRef(onSelectNode);
  onSelectNodeRef.current = onSelectNode;

  const [hovered, setHovered] = useState<HoveredNodeState | null>(null);
  const [zoomPercent, setZoomPercent] = useState<number>(100);
  const [layoutSeed, setLayoutSeed] = useState<number>(0);

  const width = compact ? 680 : 880;
  const height = compact ? 290 : 420;

  const projection = useMemo(
    () =>
      buildD3KnowledgeGraph(nodes, conflicts, {
        entityTypeFilter,
        minConfidence,
        selectedNodeId,
        focusNeighborhoodOnly,
        highlightedNodeIds,
        maxNodes: compact ? 14 : 60,
      }),
    [
      nodes,
      conflicts,
      entityTypeFilter,
      minConfidence,
      selectedNodeId,
      focusNeighborhoodOnly,
      highlightedNodeIds,
      compact,
    ]
  );

  // Build and drive the D3 force-directed simulation
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    if (projection.nodes.length === 0) {
      return;
    }

    // Clone nodes/links so D3 mutates fresh simulation objects cleanly
    const simNodes: D3KnowledgeNode[] = projection.nodes.map((n, idx) => {
      const angle = (idx / Math.max(projection.nodes.length, 1)) * Math.PI * 2;
      const spread = compact ? 95 : 155;
      return {
        ...n,
        x: width / 2 + Math.cos(angle) * spread,
        y: height / 2 + Math.sin(angle) * (spread * 0.72),
      };
    });

    const simLinks: D3KnowledgeLink[] = projection.links.map((l) => ({ ...l }));

    // SVG Definitions: directed arrowheads & subtle drop filter for selected node
    const defs = svg.append('defs');

    const createArrowMarker = (id: string, color: string) => {
      defs
        .append('marker')
        .attr('id', id)
        .attr('viewBox', '0 -4 8 8')
        .attr('refX', 7)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-3.5L8,0L0,3.5')
        .attr('fill', color);
    };

    createArrowMarker('kg-arrow-rel', '#60a5fa');
    createArrowMarker('kg-arrow-rel-active', '#93c5fd');
    createArrowMarker('kg-arrow-contradiction', '#f87171');
    createArrowMarker('kg-arrow-duplicate', '#fbbf24');

    // Subtle background dot grid for spatial orientation during pan/zoom
    const pattern = defs
      .append('pattern')
      .attr('id', compact ? 'kg-grid-compact' : 'kg-grid-full')
      .attr('width', 28)
      .attr('height', 28)
      .attr('patternUnits', 'userSpaceOnUse');

    pattern
      .append('circle')
      .attr('cx', 1)
      .attr('cy', 1)
      .attr('r', 0.9)
      .attr('fill', 'rgba(148, 163, 184, 0.14)');

    svg
      .append('rect')
      .attr('width', width)
      .attr('height', height)
      .attr('fill', `url(#${compact ? 'kg-grid-compact' : 'kg-grid-full'})`)
      .style('pointer-events', 'none');

    const viewport = svg.append('g').attr('class', 'kg-viewport');

    // Zoom & pan (interactive in full view; disabled scroll hijack in compact dashboard preview)
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.45, 2.6])
      .on('zoom', (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        viewport.attr('transform', event.transform.toString());
        setZoomPercent(Math.round(event.transform.k * 100));
      });

    zoomBehaviorRef.current = zoom;
    if (!compact) {
      svg.call(zoom).on('dblclick.zoom', null);
    }

    // Force simulation setup (aspect-ratio aware so nodes spread across full widescreen canvas)
    const linkForce = d3
      .forceLink<D3KnowledgeNode, D3KnowledgeLink>(simLinks)
      .id((d) => d.id)
      .distance((l) => (l.kind === 'relation' ? (compact ? 118 : 168) : compact ? 105 : 145))
      .strength((l) => (l.kind === 'relation' ? 0.55 : 0.4));

    const simulation = d3
      .forceSimulation<D3KnowledgeNode>(simNodes)
      .force('link', linkForce)
      .force('charge', d3.forceManyBody().strength(compact ? -540 : -860))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('x', d3.forceX(width / 2).strength(0.032))
      .force('y', d3.forceY(height / 2).strength(0.095))
      .force(
        'collide',
        d3.forceCollide<D3KnowledgeNode>((d) => d.radius + (compact ? 42 : 58)).iterations(4)
      )
      .alphaDecay(0.038);

    simulationRef.current = simulation;

    // Pre-settle layout synchronously so first render is stable and non-overlapping
    simulation.stop();
    for (let i = 0; i < 200; i += 1) {
      simulation.tick();
    }

    // Normalize settled coordinates into padded canvas bounds so full width/height is utilized cleanly
    const padX = compact ? 84 : 96;
    const padY = compact ? 42 : 52;
    const bottomPad = compact ? 46 : 62;
    if (simNodes.length > 1) {
      let minX = Infinity;
      let maxX = -Infinity;
      let minY = Infinity;
      let maxY = -Infinity;
      for (const n of simNodes) {
        const nx = n.x ?? width / 2;
        const ny = n.y ?? height / 2;
        if (nx < minX) minX = nx;
        if (nx > maxX) maxX = nx;
        if (ny < minY) minY = ny;
        if (ny > maxY) maxY = ny;
      }
      const spanX = Math.max(maxX - minX, 1);
      const spanY = Math.max(maxY - minY, 1);
      const availW = Math.max(width - padX * 2, 120);
      const availH = Math.max(height - padY - bottomPad, 100);
      // Scale uniformly if overflowing, or expand gently horizontally/vertically when compact
      const scaleX = availW / spanX;
      const scaleY = availH / spanY;
      const cxRaw = (minX + maxX) / 2;
      const cyRaw = (minY + maxY) / 2;
      const targetCx = width / 2;
      const targetCy = padY + availH / 2;
      const appliedScaleX = Math.min(Math.max(scaleX, 0.55), 1.35);
      const appliedScaleY = Math.min(Math.max(scaleY, 0.55), 1.25);

      for (const n of simNodes) {
        const nx = targetCx + ((n.x ?? cxRaw) - cxRaw) * appliedScaleX;
        const ny = targetCy + ((n.y ?? cyRaw) - cyRaw) * appliedScaleY;
        n.x = Math.max(padX, Math.min(width - padX, nx));
        n.y = Math.max(padY, Math.min(height - bottomPad, ny));
      }
    } else if (simNodes.length === 1) {
      simNodes[0].x = width / 2;
      simNodes[0].y = height / 2;
    }

    const hasSelection = Boolean(selectedNodeId && projection.connectedNodeIds.size > 0);
    const isLinkActive = (l: D3KnowledgeLink) => {
      if (!hasSelection) return true;
      const sId = getEndpointId(l.source);
      const tId = getEndpointId(l.target);
      return sId === selectedNodeId || tId === selectedNodeId;
    };

    // Render links layer
    const linksGroup = viewport.append('g').attr('class', 'kg-links');
    const linkPaths = linksGroup
      .selectAll<SVGPathElement, D3KnowledgeLink>('path')
      .data(simLinks, (d) => d.id)
      .join('path')
      .attr('fill', 'none')
      .attr('stroke', (d) => {
        if (d.kind === 'contradiction') return '#ef4444';
        if (d.kind === 'duplicate') return '#f59e0b';
        return isLinkActive(d) ? '#60a5fa' : '#3b82f6';
      })
      .attr('stroke-width', (d) => {
        if (d.kind !== 'relation') return 1.85;
        return isLinkActive(d) && hasSelection ? 1.9 : 1.3;
      })
      .attr('stroke-dasharray', (d) => (d.kind === 'relation' ? null : '5 4'))
      .attr('stroke-opacity', (d) => {
        if (!hasSelection) return d.kind === 'relation' ? 0.58 : 0.85;
        return isLinkActive(d) ? 0.92 : 0.16;
      })
      .attr('marker-end', (d) => {
        if (d.kind === 'contradiction') return 'url(#kg-arrow-contradiction)';
        if (d.kind === 'duplicate') return 'url(#kg-arrow-duplicate)';
        return isLinkActive(d) && hasSelection
          ? 'url(#kg-arrow-rel-active)'
          : 'url(#kg-arrow-rel)';
      });

    // Edge predicate labels (hidden in compact view or when toggled off)
    const linkLabelsGroup = viewport.append('g').attr('class', 'kg-link-labels');
    const linkLabels =
      !compact && showEdgeLabels
        ? linkLabelsGroup
            .selectAll<SVGTextElement, D3KnowledgeLink>('text')
            .data(simLinks, (d) => d.id)
            .join('text')
            .attr('text-anchor', 'middle')
            .attr('font-family', 'JetBrains Mono, monospace')
            .attr('font-size', '9')
            .attr('font-weight', (d) => (d.kind === 'relation' ? '500' : '700'))
            .attr('fill', (d) => {
              if (d.kind === 'contradiction') return '#fca5a5';
              if (d.kind === 'duplicate') return '#fcd34d';
              return isLinkActive(d) && hasSelection ? '#dbeafe' : '#94a3b8';
            })
            .attr('opacity', (d) => (!hasSelection || isLinkActive(d) ? 0.92 : 0.22))
            .style('pointer-events', 'none')
            .style('paint-order', 'stroke')
            .attr('stroke', '#090b10')
            .attr('stroke-width', 3)
            .text((d) => d.predicate)
        : null;

    // Render nodes layer
    const nodesGroup = viewport.append('g').attr('class', 'kg-nodes');
    const nodeGroups = nodesGroup
      .selectAll<SVGGElement, D3KnowledgeNode>('g')
      .data(simNodes, (d) => d.id)
      .join('g')
      .attr('class', 'kg-node')
      .attr('role', onSelectNodeRef.current ? 'button' : null)
      .attr('tabindex', onSelectNodeRef.current ? '0' : null)
      .attr(
        'aria-label',
        (d) =>
          `Inspect knowledge entity ${d.label} (${d.entityType}, ${d.confidenceScore}% confidence, ${d.degree} connections)`
      )
      .style('cursor', compact ? 'pointer' : 'grab')
      .attr('opacity', (d) => {
        if (highlightedNodeIds && highlightedNodeIds.size > 0) {
          return highlightedNodeIds.has(d.id) ? 1 : 0.28;
        }
        if (!hasSelection) return 1;
        return projection.connectedNodeIds.has(d.id) ? 1 : 0.34;
      });

    // Outer halo ring for selected or search-matched or conflicted nodes
    nodeGroups
      .filter((d) => d.id === selectedNodeId || d.isHighlighted || d.hasConflict)
      .append('circle')
      .attr('r', (d) => d.radius + 5.5)
      .attr('fill', 'none')
      .attr('stroke', (d) => {
        if (d.id === selectedNodeId) return '#e2e8f0';
        if (d.isHighlighted) return '#38bdf8';
        return '#ef4444';
      })
      .attr('stroke-width', (d) => (d.id === selectedNodeId ? 1.75 : 1.25))
      .attr('stroke-dasharray', (d) => (d.id === selectedNodeId ? null : '3 3'))
      .attr('opacity', 0.85);

    // Main entity node circle
    nodeGroups
      .append('circle')
      .attr('r', (d) => d.radius)
      .attr('fill', (d) => ENTITY_TYPE_STYLE[d.entityType]?.fill || '#111b2e')
      .attr('stroke', (d) => ENTITY_TYPE_STYLE[d.entityType]?.stroke || '#60a5fa')
      .attr('stroke-width', (d) => (d.id === selectedNodeId ? 2.4 : 1.6));

    // Confidence score centered inside the node circle
    nodeGroups
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '0.35em')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('font-size', compact ? '8.5' : '9.5')
      .attr('font-weight', '700')
      .attr('fill', (d) => ENTITY_TYPE_STYLE[d.entityType]?.text || '#93c5fd')
      .style('pointer-events', 'none')
      .text((d) => `${d.confidenceScore}%`);

    // Entity label beneath node circle
    nodeGroups
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('y', (d) => d.radius + 13)
      .attr('font-family', 'Plus Jakarta Sans, sans-serif')
      .attr('font-size', compact ? '9.5' : '10.5')
      .attr('font-weight', (d) => (d.id === selectedNodeId ? '700' : '600'))
      .attr('fill', '#f8fafc')
      .style('pointer-events', 'none')
      .style('paint-order', 'stroke')
      .attr('stroke', '#090b10')
      .attr('stroke-width', 3.5)
      .text((d) => d.shortLabel);

    // Subtle entity type subtitle beneath label in full mode
    if (!compact) {
      nodeGroups
        .append('text')
        .attr('text-anchor', 'middle')
        .attr('y', (d) => d.radius + 25)
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('font-size', '8.5')
        .attr('fill', '#94a3b8')
        .style('pointer-events', 'none')
        .style('paint-order', 'stroke')
        .attr('stroke', '#090b10')
        .attr('stroke-width', 2.5)
        .text((d) => d.entityType);
    }

    // Interactions: click, keyboard Enter/Space, hover tooltip
    nodeGroups
      .on('click', (event: MouseEvent, d: D3KnowledgeNode) => {
        event.stopPropagation();
        onSelectNodeRef.current?.(d.record);
      })
      .on('keydown', (event: KeyboardEvent, d: D3KnowledgeNode) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onSelectNodeRef.current?.(d.record);
        }
      })
      .on('mouseenter', (event: MouseEvent, d: D3KnowledgeNode) => {
        if (compact || !containerRef.current) return;
        const rect = containerRef.current.getBoundingClientRect();
        setHovered({
          node: d,
          x: Math.min(Math.max(event.clientX - rect.left + 14, 12), rect.width - 260),
          y: Math.min(Math.max(event.clientY - rect.top - 12, 12), rect.height - 130),
        });
      })
      .on('mousemove', (event: MouseEvent, d: D3KnowledgeNode) => {
        if (compact || !containerRef.current) return;
        const rect = containerRef.current.getBoundingClientRect();
        setHovered({
          node: d,
          x: Math.min(Math.max(event.clientX - rect.left + 14, 12), rect.width - 260),
          y: Math.min(Math.max(event.clientY - rect.top - 12, 12), rect.height - 130),
        });
      })
      .on('mouseleave', () => {
        setHovered(null);
      });

    // Update DOM coordinates function
    const updatePositions = () => {
      linkPaths.each(function (d) {
        const src = d.source as D3KnowledgeNode;
        const tgt = d.target as D3KnowledgeNode;
        const geom = computeQuadraticPath(
          src.x ?? width / 2,
          src.y ?? height / 2,
          tgt.x ?? width / 2,
          tgt.y ?? height / 2,
          tgt.radius,
          d.curveOffset
        );
        d3.select(this).attr('d', geom.pathD);
      });

      if (linkLabels) {
        linkLabels.each(function (d) {
          const src = d.source as D3KnowledgeNode;
          const tgt = d.target as D3KnowledgeNode;
          const geom = computeQuadraticPath(
            src.x ?? width / 2,
            src.y ?? height / 2,
            tgt.x ?? width / 2,
            tgt.y ?? height / 2,
            tgt.radius,
            d.curveOffset
          );
          d3.select(this).attr('x', geom.labelX).attr('y', geom.labelY);
        });
      }

      nodeGroups.attr('transform', (d) => `translate(${d.x ?? width / 2}, ${d.y ?? height / 2})`);
    };

    // Draw initial settled positions immediately
    updatePositions();

    // Drag behavior in full mode (drag a node to reposition smoothly)
    if (!compact) {
      const dragBehavior = d3
        .drag<SVGGElement, D3KnowledgeNode>()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.25).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        });

      nodeGroups.call(dragBehavior);
    }

    simulation.on('tick', updatePositions);

    return () => {
      simulation.stop();
      simulationRef.current = null;
    };
  }, [projection, selectedNodeId, highlightedNodeIds, compact, showEdgeLabels, width, height, layoutSeed]);

  const handleZoomBy = (factor: number) => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(180).call(zoomBehaviorRef.current.scaleBy, factor);
  };

  const handleResetView = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(220)
      .call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
  };

  const handleReheat = () => {
    setLayoutSeed((s) => s + 1);
  };

  // Distinct entity types currently visible for the legend
  const activeTypes = useMemo(() => {
    const seen = new Set<KnowledgeEntityType>();
    for (const n of projection.nodes) seen.add(n.entityType);
    return Array.from(seen);
  }, [projection.nodes]);

  return (
    <div
      ref={containerRef}
      data-testid="knowledge-graph-d3"
      data-node-count={projection.nodes.length}
      data-link-count={projection.links.length}
      className="relative w-full rounded-xl bg-[#090b10] border border-white/[0.08] overflow-hidden"
    >
      {/* Interactive D3 Viewport Controls (Full Mode Only) */}
      {!compact && (
        <div className="px-4 py-2.5 border-b border-white/[0.07] bg-[#0b0e15] flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400 tabular-nums">
            <span className="text-slate-200 font-semibold">D3 Force-Directed Engine</span>
            <span aria-hidden="true">·</span>
            <span>
              {projection.stats.visibleNodes}/{projection.stats.totalNodes} entities
            </span>
            <span aria-hidden="true">·</span>
            <span>{projection.stats.relationEdges} relations</span>
            <span aria-hidden="true">·</span>
            <span
              className={
                projection.stats.conflictEdges > 0 ? 'text-red-400 font-semibold' : undefined
              }
            >
              {projection.stats.conflictEdges} conflict link(s)
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-500 tabular-nums mr-1">
              {zoomPercent}%
            </span>
            <button
              type="button"
              onClick={() => handleZoomBy(1.25)}
              aria-label="Zoom in knowledge graph"
              className="p-1.5 rounded-md bg-white/[0.05] hover:bg-white/[0.12] text-slate-300 hover:text-white cursor-pointer"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => handleZoomBy(0.8)}
              aria-label="Zoom out knowledge graph"
              className="p-1.5 rounded-md bg-white/[0.05] hover:bg-white/[0.12] text-slate-300 hover:text-white cursor-pointer"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleResetView}
              aria-label="Reset knowledge graph zoom"
              className="p-1.5 rounded-md bg-white/[0.05] hover:bg-white/[0.12] text-slate-300 hover:text-white cursor-pointer"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleReheat}
              aria-label="Recompute force layout"
              className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded-md bg-white/[0.05] hover:bg-white/[0.12] text-slate-300 hover:text-white whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Re-layout</span>
            </button>
          </div>
        </div>
      )}

      {/* Main D3 SVG Canvas */}
      <div className="relative">
        {projection.nodes.length === 0 ? (
          <div className="py-16 px-6 text-center space-y-1">
            <p className="text-sm font-medium text-slate-300">
              No knowledge entities match the active filters.
            </p>
            <p className="text-xs text-slate-500">
              Adjust the entity type or confidence filter, or commit discoveries from research
              agents.
            </p>
          </div>
        ) : (
          <svg
            ref={svgRef}
            viewBox={`0 0 ${width} ${height}`}
            className="w-full h-auto block select-none"
            role="img"
            aria-label="Interactive D3.js force-directed knowledge graph of entities and relationships"
          />
        )}

        {/* Hover Entity Inspector Tooltip (Full Mode) */}
        {!compact && hovered && (
          <div
            role="tooltip"
            style={{ left: hovered.x, top: hovered.y }}
            className="pointer-events-none absolute z-20 w-64 rounded-lg bg-[#0f131c]/95 border border-white/[0.14] px-3 py-2.5 shadow-lg space-y-1"
          >
            <div className="flex items-center justify-between gap-2 text-[11px] font-mono">
              <span style={{ color: ENTITY_TYPE_STYLE[hovered.node.entityType]?.text }}>
                {ENTITY_TYPE_STYLE[hovered.node.entityType]?.label || hovered.node.entityType}
              </span>
              <span className="text-slate-300 tabular-nums">{hovered.node.confidenceScore}% conf</span>
            </div>
            <p className="text-xs font-semibold text-white truncate">{hovered.node.label}</p>
            <p className="text-[11px] text-slate-300 line-clamp-2 leading-relaxed">
              {hovered.node.record.claim}
            </p>
            <p className="text-[10px] font-mono text-slate-500 truncate">
              Source: {hovered.node.record.sourceTitle} · {hovered.node.degree} link(s)
            </p>
          </div>
        )}
      </div>

      {/* Footer Legend (Unboxed Clean Typographic Legend) */}
      <div className="px-4 py-2.5 border-t border-white/[0.06] bg-[#0b0e15] space-y-1.5 text-[11px] font-mono text-slate-400 tabular-nums">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span>
            {compact
              ? `${nodes.length} entities · ${conflicts.length} conflict flag(s)`
              : 'Drag nodes to rearrange · Scroll to zoom · Click a node to focus connections'}
          </span>
          <span>Solid Blue: Verified Relation · Dashed Red: Contradiction · Dashed Amber: Duplicate</span>
        </div>

        {!compact && activeTypes.length > 0 && (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 pt-1 border-t border-white/[0.05]">
            {activeTypes.map((typeKey) => {
              const style = ENTITY_TYPE_STYLE[typeKey];
              return (
                <span key={typeKey} className="inline-flex items-center gap-1.5 text-[10.5px]">
                  <span
                    aria-hidden="true"
                    className="inline-block w-2.5 h-2.5 rounded-full border"
                    style={{
                      backgroundColor: style.fill,
                      borderColor: style.stroke,
                    }}
                  />
                  <span className="text-slate-300">{style.label}</span>
                </span>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
