import React, { useEffect, useMemo, useState } from 'react';
import { Activity, Clock, Radio, Send } from 'lucide-react';
import {
  buildFiveMinuteHeartbeatWindow,
  deriveHeartbeatHealthTransitions,
  type HeartbeatBucketSlot,
} from '../shared/sentinelPlaybooks';
import type {
  HeartbeatPingHealth,
  SentinelAgentRecord,
  SentinelHeartbeatPing,
} from '../shared/sentinelTypes';

interface SentinelHeartbeatChartProps {
  agents: SentinelAgentRecord[];
  heartbeats: SentinelHeartbeatPing[];
  isAuthenticated: boolean;
  busyAction: string | null;
  onSendFirestorePing?: (agentId?: string) => Promise<void>;
}

const HEALTH_STYLE: Record<
  HeartbeatPingHealth,
  {
    stroke: string;
    fill: string;
    barClass: string;
    badgeClass: string;
    label: string;
  }
> = {
  healthy: {
    stroke: '#10b981',
    fill: '#10b981',
    barClass: 'bg-emerald-500/85 border-emerald-400/60',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    label: 'Healthy',
  },
  warning: {
    stroke: '#f59e0b',
    fill: '#f59e0b',
    barClass: 'bg-amber-400/90 border-amber-300/70',
    badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    label: 'Degraded',
  },
  critical: {
    stroke: '#ef4444',
    fill: '#ef4444',
    barClass: 'bg-red-500/90 border-red-400/70',
    badgeClass: 'bg-red-500/15 text-red-300 border-red-500/30',
    label: 'Critical',
  },
  missed: {
    stroke: '#334155',
    fill: '#1e293b',
    barClass: 'bg-slate-800/80 border-slate-700/60',
    badgeClass: 'bg-slate-700/30 text-slate-400 border-slate-600/40',
    label: 'No Ping',
  },
};

export const SentinelHeartbeatChart: React.FC<SentinelHeartbeatChartProps> = ({
  agents,
  heartbeats,
  isAuthenticated,
  busyAction,
  onSendFirestorePing,
}) => {
  const [selectedAgentId, setSelectedAgentId] = useState<string>('all');
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [selectedSlotIdx, setSelectedSlotIdx] = useState<number | null>(null);

  // Tick every 2s to smoothly advance the sliding 5-minute window
  useEffect(() => {
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 2000);
    return () => window.clearInterval(timer);
  }, []);

  const filteredPings = useMemo(() => {
    if (selectedAgentId === 'all') return heartbeats;
    return heartbeats.filter((p) => p.agentId === selectedAgentId);
  }, [heartbeats, selectedAgentId]);

  const slots = useMemo(
    () => buildFiveMinuteHeartbeatWindow(filteredPings, nowMs, 20, 300),
    [filteredPings, nowMs]
  );

  const transitions = useMemo(() => deriveHeartbeatHealthTransitions(slots), [slots]);
  const transitionSlotSet = useMemo(
    () => new Set(transitions.map((t) => t.slotIndex)),
    [transitions]
  );

  const latestActiveSlot: HeartbeatBucketSlot | null = useMemo(() => {
    for (let i = slots.length - 1; i >= 0; i -= 1) {
      if (slots[i].pingCount > 0) return slots[i];
    }
    return null;
  }, [slots]);

  const inspectedSlot =
    selectedSlotIdx !== null && slots[selectedSlotIdx]
      ? slots[selectedSlotIdx]
      : latestActiveSlot || slots[slots.length - 1] || null;

  const summary = useMemo(() => {
    let healthy = 0;
    let warning = 0;
    let critical = 0;
    let missed = 0;
    let realCount = 0;
    let demoCount = 0;
    for (const s of slots) {
      if (s.health === 'healthy') healthy += 1;
      else if (s.health === 'warning') warning += 1;
      else if (s.health === 'critical') critical += 1;
      else missed += 1;
      if (s.latestPing?.dataOrigin === 'real_telemetry') realCount += 1;
      else if (s.latestPing?.dataOrigin === 'synthetic_demo') demoCount += 1;
    }
    const overall: HeartbeatPingHealth =
      critical > 0
        ? 'critical'
        : warning > 0
          ? 'warning'
          : healthy > 0
            ? 'healthy'
            : 'missed';
    return { healthy, warning, critical, missed, realCount, demoCount, overall };
  }, [slots]);

  const activeColor = HEALTH_STYLE[summary.overall];

  return (
    <section
      aria-label="Real-time 5-minute server heartbeat pulse chart"
      data-testid="sentinel-heartbeat-chart"
      className="rounded-xl bg-[#0e121b] border border-white/[0.08] p-4 sm:p-5 space-y-4"
    >
      {/* Top Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-white">
              Real-Time Server Heartbeat Pulse (Last 5 Minutes)
            </h2>
            <span
              className={`px-2 py-0.5 rounded border text-[10px] font-mono uppercase ${activeColor.badgeClass}`}
            >
              {activeColor.label}
            </span>
            {summary.realCount > 0 && (
              <span className="px-2 py-0.5 rounded border bg-emerald-500/10 border-emerald-500/30 text-[10px] font-mono uppercase text-emerald-300">
                Real Telemetry
              </span>
            )}
            {summary.demoCount > 0 && summary.realCount === 0 && (
              <span className="px-2 py-0.5 rounded border bg-amber-500/15 border-amber-500/35 text-[10px] font-mono uppercase text-amber-300">
                Synthetic Demo
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400">
            20 × 15-second health buckets tracking green (nominal), yellow (degraded load/latency), and red (critical/offline) pings from HTTPS agents &amp; Firestore streams.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <label htmlFor="sentinel-hb-host-select" className="sr-only">
            Filter heartbeat chart by server
          </label>
          <select
            id="sentinel-hb-host-select"
            value={selectedAgentId}
            onChange={(e) => {
              setSelectedAgentId(e.target.value);
              setSelectedSlotIdx(null);
            }}
            className="px-2.5 py-1.5 rounded-lg bg-[#090b10] border border-white/[0.1] text-xs text-slate-200 font-mono"
          >
            <option value="all">All Servers ({agents.length})</option>
            {agents.map((ag) => (
              <option key={ag.id} value={ag.id}>
                {ag.hostname} ({ag.region})
              </option>
            ))}
          </select>

          {onSendFirestorePing && (
            <button
              type="button"
              onClick={() =>
                void onSendFirestorePing(selectedAgentId === 'all' ? undefined : selectedAgentId)
              }
              disabled={busyAction !== null}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#151c2c] hover:bg-[#1e273d] border border-emerald-500/30 text-emerald-300 text-xs font-medium disabled:opacity-50 transition-colors cursor-pointer"
            >
              <Send className="w-3 h-3" />
              <span>
                {busyAction === 'firestore_ping'
                  ? 'Sending Ping...'
                  : isAuthenticated
                    ? 'Test Firestore Ping'
                    : 'Simulate Demo Ping'}
              </span>
            </button>
          )}
        </div>
      </div>

      {/* SVG Animated ECG Pulse Waveform + 20-Slot Health Histogram */}
      <div className="rounded-lg bg-[#080b12] border border-white/[0.06] p-3 sm:p-4 space-y-2.5">
        <div className="relative w-full h-24 sm:h-28 overflow-hidden">
          <svg
            viewBox="0 0 1000 100"
            preserveAspectRatio="none"
            className="w-full h-full select-none block"
            role="img"
            aria-label={`Server heartbeat waveform across 20 fifteen-second intervals. ${summary.healthy} healthy, ${summary.warning} degraded, ${summary.critical} critical, ${summary.missed} no-ping slots.`}
          >
            {/* Subtle horizontal reference grid lines */}
            <line x1="0" y1="20" x2="1000" y2="20" stroke="rgba(148,163,184,0.08)" strokeDasharray="4 6" vectorEffect="non-scaling-stroke" />
            <line x1="0" y1="62" x2="1000" y2="62" stroke="rgba(148,163,184,0.12)" vectorEffect="non-scaling-stroke" />
            <line x1="0" y1="88" x2="1000" y2="88" stroke="rgba(148,163,184,0.06)" vectorEffect="non-scaling-stroke" />

            {/* Per-bucket subtle color-coded background strips aligned 1:1 with the 20 bars below */}
            {slots.map((slot, idx) => {
              const step = 1000 / slots.length;
              const x = idx * step;
              const color = HEALTH_STYLE[slot.health].fill;
              const isSelected = inspectedSlot?.slotIndex === slot.slotIndex;
              return (
                <rect
                  key={slot.slotIndex}
                  x={x + 2}
                  y={4}
                  width={step - 4}
                  height={92}
                  rx={4}
                  fill={slot.health === 'missed' ? 'rgba(30,41,59,0.25)' : color}
                  fillOpacity={
                    slot.health === 'missed'
                      ? isSelected
                        ? 0.45
                        : 0.18
                      : isSelected
                        ? 0.2
                        : 0.07
                  }
                  stroke={isSelected ? color : 'transparent'}
                  strokeOpacity={0.75}
                  strokeWidth={isSelected ? 1.2 : 0}
                  vectorEffect="non-scaling-stroke"
                />
              );
            })}

            {/* Per-bucket Green / Yellow / Red / Slate ECG Waveform Segments */}
            {slots.map((slot, idx) => {
              const step = 1000 / slots.length;
              const x0 = idx * step;
              const baselineY = 62;
              const st = HEALTH_STYLE[slot.health];
              let d: string;
              if (slot.pingCount === 0 || slot.health === 'missed') {
                d = `M ${x0.toFixed(1)} ${baselineY} L ${(x0 + step).toFixed(1)} ${baselineY}`;
              } else {
                const amp =
                  slot.health === 'critical'
                    ? 46
                    : slot.health === 'warning'
                      ? 34
                      : Math.max(20, Math.min(36, (slot.cpuPercent / 100) * 38 + 14));
                const dip = Math.min(18, Math.round(amp * 0.45));
                const x1 = x0 + step * 0.22;
                const x2 = x0 + step * 0.38;
                const x3 = x0 + step * 0.54;
                const x4 = x0 + step * 0.7;
                const x5 = x0 + step * 0.86;
                const xEnd = x0 + step;
                d = [
                  `M ${x0.toFixed(1)} ${baselineY}`,
                  `L ${x1.toFixed(1)} ${baselineY}`,
                  `L ${x2.toFixed(1)} ${(baselineY + dip).toFixed(1)}`,
                  `L ${x3.toFixed(1)} ${(baselineY - amp).toFixed(1)}`,
                  `L ${x4.toFixed(1)} ${(baselineY + Math.round(dip * 0.65)).toFixed(1)}`,
                  `L ${x5.toFixed(1)} ${baselineY}`,
                  `L ${xEnd.toFixed(1)} ${baselineY}`,
                ].join(' ');
              }
              return (
                <path
                  key={`seg-${selectedAgentId}-${filteredPings.length}-${slot.slotIndex}`}
                  d={d}
                  fill="none"
                  stroke={st.stroke}
                  strokeWidth={slot.health === 'missed' ? 1.4 : 2.1}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                  className={slot.health === 'missed' ? undefined : 'sentinel-ecg-trace'}
                />
              );
            })}

            {/* Vertical SVG transition boundary markers where server health shifted (green/yellow/red) */}
            {transitions.map((tr) => {
              const step = 1000 / slots.length;
              const boundaryX = tr.slotIndex * step;
              const markerColor = HEALTH_STYLE[tr.toHealth].stroke;
              return (
                <line
                  key={tr.id}
                  x1={boundaryX}
                  y1={4}
                  x2={boundaryX}
                  y2={96}
                  stroke={markerColor}
                  strokeOpacity={0.7}
                  strokeWidth={1.25}
                  strokeDasharray="3 3"
                  vectorEffect="non-scaling-stroke"
                />
              );
            })}
          </svg>

          {/* Crisp circular peak markers & animated beacon ring overlaid at exact bucket percentages */}
          <div className="pointer-events-none absolute inset-0" aria-hidden="true">
            {slots.map((slot, idx) => {
              if (slot.pingCount === 0 || slot.health === 'missed') return null;
              const amp =
                slot.health === 'critical'
                  ? 46
                  : slot.health === 'warning'
                    ? 34
                    : Math.max(20, Math.min(36, (slot.cpuPercent / 100) * 38 + 14));
              const leftPct = ((idx + 0.54) / slots.length) * 100;
              const topPct = 62 - amp;
              const dotColor = HEALTH_STYLE[slot.health].fill;
              const isLatest = latestActiveSlot?.slotIndex === slot.slotIndex;
              return (
                <span
                  key={`dot-${slot.slotIndex}`}
                  className="absolute -translate-x-1/2 -translate-y-1/2 flex items-center justify-center"
                  style={{ left: `${leftPct}%`, top: `${topPct}%` }}
                >
                  {isLatest && (
                    <span
                      className="absolute w-4 h-4 rounded-full border sentinel-beacon-ring"
                      style={{ borderColor: dotColor }}
                    />
                  )}
                  <span
                    className={`rounded-full ${isLatest ? 'w-2 h-2' : 'w-1.5 h-1.5'}`}
                    style={{ backgroundColor: dotColor }}
                  />
                </span>
              );
            })}
          </div>
        </div>

        {/* Interactive 20-Slot Pulse Bar Strip (Green / Yellow / Red / Missed) */}
        <div
          role="group"
          aria-label="5-minute heartbeat interval buckets"
          className="grid grid-cols-10 sm:grid-cols-20 gap-1"
        >
          {slots.map((slot) => {
            const st = HEALTH_STYLE[slot.health];
            const isSelected = inspectedSlot?.slotIndex === slot.slotIndex;
            const barHeight =
              slot.pingCount === 0
                ? 'h-2.5'
                : slot.health === 'critical'
                  ? 'h-6'
                  : slot.health === 'warning'
                    ? 'h-5'
                    : 'h-4';
            return (
              <button
                key={slot.slotIndex}
                type="button"
                onClick={() => setSelectedSlotIdx(slot.slotIndex)}
                aria-label={`Heartbeat bucket ${slot.label}: ${st.label}, ${slot.pingCount} ping(s)`}
                aria-pressed={isSelected}
                className={`group flex flex-col items-center justify-end h-7 rounded px-0.5 py-0.5 transition-all cursor-pointer ${
                  isSelected ? 'ring-1 ring-white/50 bg-white/[0.06]' : 'hover:bg-white/[0.04]'
                }`}
              >
                <span
                  className={`w-full rounded-sm border ${barHeight} ${st.barClass} ${
                    latestActiveSlot?.slotIndex === slot.slotIndex ? 'sentinel-slot-active' : ''
                  }`}
                />
              </button>
            );
          })}
        </div>

        {/* Spanned 5-Minute Time Axis */}
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
          <span>-5m 00s</span>
          <span className="hidden sm:inline">-2m 30s</span>
          <span className="text-slate-300">Now (15s buckets)</span>
        </div>

        {/* Health Status Legend */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-500 pt-2 border-t border-white/[0.05]">
          <span className="text-slate-400">
            5-Min Pulse Window ({slots.length} buckets)
          </span>
          <div className="flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-1.5 text-emerald-300">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              Healthy ({summary.healthy})
            </span>
            <span className="inline-flex items-center gap-1.5 text-amber-300">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              Degraded ({summary.warning})
            </span>
            <span className="inline-flex items-center gap-1.5 text-red-300">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              Critical ({summary.critical})
            </span>
            <span className="inline-flex items-center gap-1.5 text-slate-400">
              <span className="w-2 h-2 rounded-full bg-slate-700" />
              No Ping ({summary.missed})
            </span>
          </div>
        </div>

        {/* Real-Time Health Status Transitions (Green / Yellow / Red) */}
        <div className="pt-2 border-t border-white/[0.05] flex flex-wrap items-center gap-2 text-[11px] font-mono">
          <span className="text-slate-500 uppercase tracking-wider text-[10px]">
            Status Transitions ({transitions.length}):
          </span>
          {transitions.length === 0 ? (
            <span className="text-slate-500">
              No health state transitions detected in the last 5 minutes.
            </span>
          ) : (
            transitions.slice(-5).map((tr) => (
              <button
                key={tr.id}
                type="button"
                onClick={() => setSelectedSlotIdx(tr.slotIndex)}
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] transition-colors cursor-pointer ${
                  transitionSlotSet.has(tr.slotIndex) && inspectedSlot?.slotIndex === tr.slotIndex
                    ? 'bg-white/[0.08] border-white/30 text-white'
                    : 'bg-[#0c101a] border-white/[0.08] text-slate-300 hover:border-white/25'
                }`}
              >
                <span className="text-slate-500">{tr.slotLabel}</span>
                <span
                  className={
                    tr.fromHealth === 'healthy'
                      ? 'text-emerald-300'
                      : tr.fromHealth === 'warning'
                        ? 'text-amber-300'
                        : 'text-red-300'
                  }
                >
                  {HEALTH_STYLE[tr.fromHealth].label}
                </span>
                <span className="text-slate-500">→</span>
                <span
                  className={
                    tr.toHealth === 'healthy'
                      ? 'text-emerald-300'
                      : tr.toHealth === 'warning'
                        ? 'text-amber-300'
                        : 'text-red-300'
                  }
                >
                  {HEALTH_STYLE[tr.toHealth].label}
                </span>
              </button>
            ))
          )}
        </div>
      </div>

      {/* Selected Bucket Inspector Footer */}
      {inspectedSlot && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3 py-2 rounded-lg bg-[#0a0d14] border border-white/[0.06] text-xs">
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <Radio className="w-3.5 h-3.5 text-blue-400 shrink-0" />
            <span className="text-slate-400">Slot {inspectedSlot.label}:</span>
            {inspectedSlot.latestPing ? (
              <>
                <span className="text-white font-semibold">{inspectedSlot.latestPing.hostname}</span>
                <span className="text-slate-400">
                  CPU {inspectedSlot.cpuPercent}% · RAM {inspectedSlot.ramPercent}% · Load{' '}
                  {inspectedSlot.loadAvg1.toFixed(2)} · {inspectedSlot.latencyMs}ms
                </span>
                <span
                  className={`px-1.5 py-0.2 rounded text-[10px] uppercase ${
                    inspectedSlot.latestPing.dataOrigin === 'real_telemetry'
                      ? 'bg-emerald-500/15 text-emerald-300'
                      : 'bg-amber-500/15 text-amber-300'
                  }`}
                >
                  {inspectedSlot.latestPing.dataOrigin === 'real_telemetry'
                    ? 'REAL TELEMETRY'
                    : 'SYNTHETIC DEMO'}
                </span>
                <span className="text-slate-500">via {inspectedSlot.latestPing.transport}</span>
              </>
            ) : (
              <span className="text-slate-500">
                No verified agent heartbeat received in this 15-second window.
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-500 shrink-0">
            <Clock className="w-3 h-3" />
            <span>
              {inspectedSlot.latestPing
                ? new Date(inspectedSlot.latestPing.observedAt).toLocaleTimeString()
                : new Date(inspectedSlot.endMs).toLocaleTimeString()}
            </span>
          </div>
        </div>
      )}
    </section>
  );
};
