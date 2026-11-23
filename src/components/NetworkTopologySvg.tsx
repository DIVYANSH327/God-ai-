import React from 'react';
import type { NetworkAssetRecord, NetworkAssetStatus } from '../shared/ginTypes';

interface NetworkTopologySvgProps {
  assets: NetworkAssetRecord[];
  selectedAssetId?: string | null;
  onSelectAsset?: (asset: NetworkAssetRecord) => void;
  compact?: boolean;
}

const STATUS_STROKE: Record<NetworkAssetStatus, string> = {
  nominal: '#3b82f6',
  degraded: '#f59e0b',
  anomalous: '#ef4444',
  isolated: '#94a3b8',
};

const STATUS_TEXT: Record<NetworkAssetStatus, string> = {
  nominal: '#93c5fd',
  degraded: '#fcd34d',
  anomalous: '#fca5a5',
  isolated: '#cbd5e1',
};

export const NetworkTopologySvg: React.FC<NetworkTopologySvgProps> = ({
  assets,
  selectedAssetId,
  onSelectAsset,
  compact = false,
}) => {
  const width = 680;
  const height = compact ? 250 : 320;
  const cx = width / 2;
  const cy = height / 2;
  const rx = compact ? 225 : 235;
  const ry = compact ? 86 : 114;

  const displayed = assets.slice(0, 8);

  return (
    <div
      data-testid="network-topology-svg"
      className="relative w-full rounded-xl bg-[#090b10] border border-white/[0.08] overflow-hidden"
    >
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-auto block"
        role="img"
        aria-label="Authorized network topology visualization"
      >
        <defs>
          <radialGradient id="ginCoreHubGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#090b10" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Subtle geometric coordinate grid */}
        <ellipse
          cx={cx}
          cy={cy}
          rx={rx}
          ry={ry}
          fill="none"
          stroke="rgba(148,163,184,0.12)"
          strokeDasharray="4 6"
        />
        <circle cx={cx} cy={cy} r={compact ? 56 : 68} fill="url(#ginCoreHubGlow)" />

        {/* Links from Central GIN Hub to authorized assets */}
        {displayed.map((asset, idx) => {
          const angle = (idx / Math.max(displayed.length, 1)) * Math.PI * 2 - Math.PI / 2;
          const nx = cx + Math.cos(angle) * rx;
          const ny = cy + Math.sin(angle) * ry;
          const stroke = STATUS_STROKE[asset.status];
          const isSelected = selectedAssetId === asset.id;

          return (
            <g key={`edge-${asset.id}`}>
              <line
                x1={cx}
                y1={cy}
                x2={nx}
                y2={ny}
                stroke={stroke}
                strokeOpacity={isSelected ? 0.9 : 0.35}
                strokeWidth={isSelected ? 2 : 1.25}
                strokeDasharray={asset.status === 'isolated' ? '5 4' : undefined}
              />
            </g>
          );
        })}

        {/* Central GIN Cloud Relay Hub */}
        <g>
          <circle
            cx={cx}
            cy={cy}
            r={compact ? 28 : 34}
            fill="#0f131c"
            stroke="#3b82f6"
            strokeWidth="1.5"
          />
          <text
            x={cx}
            y={cy - 3}
            textAnchor="middle"
            fill="#f8fafc"
            fontSize="10"
            fontFamily="JetBrains Mono, monospace"
            fontWeight="700"
          >
            GIN HUB
          </text>
          <text
            x={cx}
            y={cy + 11}
            textAnchor="middle"
            fill="#94a3b8"
            fontSize="8.5"
            fontFamily="JetBrains Mono, monospace"
          >
            Passive API
          </text>
        </g>

        {/* Authorized Asset Nodes */}
        {displayed.map((asset, idx) => {
          const angle = (idx / Math.max(displayed.length, 1)) * Math.PI * 2 - Math.PI / 2;
          const nx = cx + Math.cos(angle) * rx;
          const ny = cy + Math.sin(angle) * ry;
          const stroke = STATUS_STROKE[asset.status];
          const labelColor = STATUS_TEXT[asset.status];
          const isSelected = selectedAssetId === asset.id;
          const shortHost =
            asset.hostname.length > 18 ? `${asset.hostname.slice(0, 16)}..` : asset.hostname;

          return (
            <g
              key={asset.id}
              onClick={() => onSelectAsset?.(asset)}
              className={onSelectAsset ? 'cursor-pointer' : undefined}
              role={onSelectAsset ? 'button' : undefined}
              tabIndex={onSelectAsset ? 0 : undefined}
              aria-label={`Inspect ${asset.hostname} (${asset.status}, score ${asset.anomalyScore})`}
              onKeyDown={(e) => {
                if (onSelectAsset && (e.key === 'Enter' || e.key === ' ')) {
                  e.preventDefault();
                  onSelectAsset(asset);
                }
              }}
            >
              <rect
                x={nx - 66}
                y={ny - 22}
                width={132}
                height={44}
                rx={8}
                fill={isSelected ? '#172033' : '#0f131c'}
                stroke={stroke}
                strokeWidth={isSelected ? 1.8 : 1}
              />
              <text
                x={nx}
                y={ny - 5}
                textAnchor="middle"
                fill="#f8fafc"
                fontSize="10"
                fontFamily="JetBrains Mono, monospace"
                fontWeight="600"
              >
                {shortHost}
              </text>
              <text
                x={nx}
                y={ny + 11}
                textAnchor="middle"
                fill={labelColor}
                fontSize="8.5"
                fontFamily="JetBrains Mono, monospace"
              >
                {asset.status} · {asset.anomalyScore}/100
              </text>
            </g>
          );
        })}

        {displayed.length === 0 && (
          <text
            x={cx}
            y={cy + 65}
            textAnchor="middle"
            fill="#64748b"
            fontSize="11"
            fontFamily="Plus Jakarta Sans, sans-serif"
          >
            No authorized assets registered yet.
          </text>
        )}
      </svg>

      {/* Clean unboxed legend footer */}
      <div className="px-4 py-2 border-t border-white/[0.06] bg-[#0b0e15] flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
        <span>Topology: Passive Metadata Only (No Packet Interception)</span>
        <span className="tabular-nums">
          Nominal (Blue) · Degraded (Amber) · Anomalous (Crimson) · Isolated (Slate)
        </span>
      </div>
    </div>
  );
};
