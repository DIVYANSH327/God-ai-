import React, { useMemo } from 'react';
import type { SentinelTopologyEdge, SentinelTopologyNode } from '../shared/sentinelTypes';

interface SentinelTopologySvgProps {
  nodes: SentinelTopologyNode[];
  edges: SentinelTopologyEdge[];
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}

export const SentinelTopologySvg: React.FC<SentinelTopologySvgProps> = ({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
}) => {
  const layout = useMemo(() => {
    const width = 820;
    const height = 380;
    const agentNodes = nodes.filter((n) => n.kind === 'agent');
    const externalNodes = nodes.filter((n) => n.kind === 'external_peer');

    const positioned = new Map<string, { x: number; y: number; node: SentinelTopologyNode }>();

    // Group enrolled agents by region in columns on the left/center
    const regions = Array.from(new Set(agentNodes.map((a) => a.region)));
    const regionColCount = Math.max(1, regions.length);
    const leftAreaWidth = externalNodes.length > 0 ? 540 : 740;

    regions.forEach((region, rIdx) => {
      const inRegion = agentNodes.filter((a) => a.region === region);
      const colX = 110 + (rIdx * (leftAreaWidth - 140)) / Math.max(1, regionColCount - 1 || 1);
      const x = regionColCount === 1 ? leftAreaWidth / 2 : colX;
      inRegion.forEach((node, idx) => {
        const y =
          inRegion.length === 1
            ? height / 2
            : 88 + (idx * (height - 176)) / Math.max(1, inRegion.length - 1);
        positioned.set(node.id, { x, y, node });
      });
    });

    // External observed/flagged peers along the right boundary
    externalNodes.forEach((node, idx) => {
      const x = 690;
      const y =
        externalNodes.length === 1
          ? height / 2
          : 92 + (idx * (height - 184)) / Math.max(1, externalNodes.length - 1);
      positioned.set(node.id, { x, y, node });
    });

    return { width, height, positioned, regions };
  }, [nodes]);

  if (nodes.length === 0) {
    return (
      <div className="h-[340px] flex items-center justify-center text-sm text-slate-500 border border-white/[0.06] rounded-xl bg-[#0a0d14]">
        Enroll at least one server or run the Milestone 1 drill to visualize fleet topology.
      </div>
    );
  }

  const getStatusStroke = (node: SentinelTopologyNode) => {
    if (node.kind === 'external_peer') {
      return node.status === 'external_flagged' ? '#ef4444' : '#64748b';
    }
    if (node.status === 'isolated') return '#f59e0b';
    if (node.status === 'revoked' || node.status === 'offline') return '#64748b';
    if (node.status === 'degraded') return '#f97316';
    return '#10b981';
  };

  return (
    <div className="w-full overflow-x-auto rounded-xl border border-white/[0.08] bg-[#0a0d14]">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        className="w-full min-w-[620px] h-[360px] block"
        role="img"
        aria-label="GOD Sentinel multi-region server and peer connection topology"
      >
        <defs>
          <marker
            id="sentinel-arrow-normal"
            viewBox="0 0 10 10"
            refX="26"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
          </marker>
          <marker
            id="sentinel-arrow-alert"
            viewBox="0 0 10 10"
            refX="26"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
          </marker>
        </defs>

        {/* Subtle structural grid lines */}
        <line x1="590" y1="24" x2="590" y2="356" stroke="#1e293b" strokeDasharray="4 4" />
        <text x="32" y="28" fill="#64748b" fontSize="11" fontFamily="monospace">
          ENROLLED AUTHORIZED SERVERS
        </text>
        <text x="612" y="28" fill="#64748b" fontSize="11" fontFamily="monospace">
          OBSERVED PEERS
        </text>

        {/* Edges */}
        {edges.map((edge) => {
          const src = layout.positioned.get(edge.source);
          const dst = layout.positioned.get(edge.target);
          if (!src || !dst) return null;
          const midX = (src.x + dst.x) / 2;
          const midY = (src.y + dst.y) / 2 - (edge.suspicious ? 18 : 10);
          return (
            <g key={edge.id}>
              <path
                d={`M ${src.x} ${src.y} Q ${midX} ${midY} ${dst.x} ${dst.y}`}
                fill="none"
                stroke={edge.suspicious ? '#ef4444' : '#334155'}
                strokeWidth={edge.suspicious ? 2 : 1.3}
                strokeDasharray={edge.suspicious ? '5 3' : undefined}
                markerEnd={
                  edge.suspicious ? 'url(#sentinel-arrow-alert)' : 'url(#sentinel-arrow-normal)'
                }
              />
              <rect
                x={midX - 28}
                y={midY - 9}
                width="56"
                height="16"
                rx="4"
                fill="#0b0f19"
                stroke={edge.suspicious ? '#7f1d1d' : '#1e293b'}
              />
              <text
                x={midX}
                y={midY + 2}
                textAnchor="middle"
                fill={edge.suspicious ? '#fca5a5' : '#94a3b8'}
                fontSize="9.5"
                fontFamily="monospace"
              >
                {edge.label}
              </text>
            </g>
          );
        })}

        {/* Nodes */}
        {Array.from(layout.positioned.values()).map(({ x, y, node }) => {
          const isSelected = selectedNodeId === node.id;
          const stroke = getStatusStroke(node);
          const isExternal = node.kind === 'external_peer';
          return (
            <g
              key={node.id}
              transform={`translate(${x}, ${y})`}
              onClick={() => onSelectNode(node.id)}
              className="cursor-pointer"
            >
              {isSelected && (
                <circle r={30} fill="none" stroke="#3b82f6" strokeWidth={2} strokeDasharray="3 3" />
              )}
              {isExternal ? (
                <rect
                  x={-22}
                  y={-22}
                  width={44}
                  height={44}
                  rx={8}
                  fill="#131824"
                  stroke={stroke}
                  strokeWidth={2}
                />
              ) : (
                <circle r={23} fill="#111827" stroke={stroke} strokeWidth={2.2} />
              )}
              <text
                y={3}
                textAnchor="middle"
                fill="#f8fafc"
                fontSize="10"
                fontWeight="600"
                fontFamily="monospace"
              >
                {isExternal ? 'PEER' : node.osType === 'windows' ? 'WIN' : 'LNX'}
              </text>
              {node.alertCount > 0 && (
                <g transform="translate(18, -18)">
                  <circle r={9} fill="#dc2626" />
                  <text y={3} textAnchor="middle" fill="#ffffff" fontSize="9" fontWeight="700">
                    {node.alertCount}
                  </text>
                </g>
              )}
              <text
                y={38}
                textAnchor="middle"
                fill="#e2e8f0"
                fontSize="11"
                fontWeight="600"
              >
                {node.label}
              </text>
              <text
                y={52}
                textAnchor="middle"
                fill="#64748b"
                fontSize="9.5"
                fontFamily="monospace"
              >
                {isExternal ? node.status.replace('_', ' ') : `${node.region} · ${node.ipAddress}`}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
