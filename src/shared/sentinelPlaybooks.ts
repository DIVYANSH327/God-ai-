import type {
  DefensiveActionType,
  HeartbeatPingHealth,
  PlaybookId,
  SentinelHeartbeatPing,
} from './sentinelTypes.ts';

export interface SentinelInvestigationPlaybook {
  id: PlaybookId;
  name: string;
  category: string;
  summary: string;
  mitreTechniques: string[];
  telemetrySignals: string[];
  evidenceQuestions: string[];
  recommendedContainment: DefensiveActionType[];
}

export const SENTINEL_INVESTIGATION_PLAYBOOKS: readonly SentinelInvestigationPlaybook[] = [
  {
    id: 'phishing',
    name: 'Phishing & Initial Access',
    category: 'Initial Access',
    summary:
      'Investigates deceptive lure delivery, suspicious attachment execution, and post-click outbound beacons.',
    mitreTechniques: ['T1566.001', 'T1566.002', 'T1204.002'],
    telemetrySignals: [
      'Child shell or script interpreter spawned from mail/browser/office process',
      'Newly created executable in /tmp or user Downloads directory',
      'Outbound HTTPS/non-standard port egress immediately after user session open',
    ],
    evidenceQuestions: [
      'Which exact process parent-child PID chain initiated the execution?',
      'Are there corroborated auth or outbound network events within 5 minutes?',
    ],
    recommendedContainment: ['terminate_process', 'firewall_policy'],
  },
  {
    id: 'ransomware',
    name: 'Ransomware & Mass File Tampering',
    category: 'Impact',
    summary:
      'Detects rapid file integrity checksum drift, shadow-copy/backup disruption, and high disk I/O encryption loops.',
    mitreTechniques: ['T1486', 'T1490', 'T1565.001'],
    telemetrySignals: [
      'Burst of SHA-256 FIM hash modifications across critical system or data paths',
      'High sustained CPU/disk utilization paired with unsigned process execution',
      'Service stop attempts against backup or logging daemons',
    ],
    evidenceQuestions: [
      'Which enrolled hosts show simultaneous FIM drift or backup service interruption?',
      'Has lateral movement via SSH/SMB been observed to adjacent regional hosts?',
    ],
    recommendedContainment: ['isolate_server', 'terminate_process'],
  },
  {
    id: 'credential_stuffing',
    name: 'Credential Stuffing',
    category: 'Credential Access',
    summary:
      'Correlates distributed low-and-slow authentication attempts across multiple usernames and enrolled servers.',
    mitreTechniques: ['T1110.004', 'T1078'],
    telemetrySignals: [
      'High ratio of failed auth attempts across many distinct usernames from rotating peers',
      'Sudden successful login from an anomalous ASN or IP following failed attempts',
    ],
    evidenceQuestions: [
      'Did any single source IP or ASN authenticate across 2+ regional hosts?',
      'Which accounts succeeded after repeated failed attempts?',
    ],
    recommendedContainment: ['firewall_policy'],
  },
  {
    id: 'brute_force',
    name: 'SSH / RDP Brute Force',
    category: 'Credential Access',
    summary:
      'Identifies high-frequency repeated password or key guessing targeting administrative accounts.',
    mitreTechniques: ['T1110.001', 'T1021.004'],
    telemetrySignals: [
      'Deduplicated high-occurrence SSH/RDP auth failures against root, admin, or deploy',
      'Source peer probing TCP/22 or TCP/3389 across regional fleet',
    ],
    evidenceQuestions: [
      'Were all brute-force attempts rejected or did an accepted session follow?',
      'Is rate limiting or key-only SSH enforcement intact in /etc/ssh/sshd_config?',
    ],
    recommendedContainment: ['firewall_policy'],
  },
  {
    id: 'malware',
    name: 'Malware & Persistence Implants',
    category: 'Execution & Persistence',
    summary:
      'Investigates unauthorized binaries, cron/systemd persistence changes, and C2 callback metadata.',
    mitreTechniques: ['T1059.004', 'T1543.002', 'T1071.001'],
    telemetrySignals: [
      'Execution from /tmp, /dev/shm, or encoded PowerShell/bash one-liners',
      'FIM checksum drift on /etc/crontab, systemd units, or /etc/ld.so.preload',
      'Periodic outbound sockets to non-standard high ports (e.g., 4444, 1337, 9001)',
    ],
    evidenceQuestions: [
      'What binary path, PID, and parent process launched the suspect workload?',
      'Does any FIM event confirm persistence modification?',
    ],
    recommendedContainment: ['terminate_process', 'isolate_server'],
  },
  {
    id: 'sql_injection',
    name: 'SQL Injection Exploitation',
    category: 'Web & App Defense',
    summary:
      'Investigates anomalous database query errors, web-worker child shells, and unexpected DB egress.',
    mitreTechniques: ['T1190', 'T1505.003'],
    telemetrySignals: [
      'Application log spikes with SQL syntax/UNION error patterns',
      'Web server or database process spawning unexpected OS shell commands',
      'Elevated outbound transfer from database tier hosts',
    ],
    evidenceQuestions: [
      'Do web/application journal logs show injection payloads preceding process/network events?',
      'Are database credentials or schema exports implicated without confirmed proof?',
    ],
    recommendedContainment: ['firewall_policy', 'isolate_server'],
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS) Abuse',
    category: 'Web & App Defense',
    summary:
      'Assesses stored/reflected script injection indicators in web logs and unexpected frontend asset drift.',
    mitreTechniques: ['T1189', 'T1059.007'],
    telemetrySignals: [
      'FIM checksum drift on served static HTML/JS bundles or nginx templates',
      'Web server access logs containing suspicious script/event-handler query spikes',
    ],
    evidenceQuestions: [
      'Were any static web root files modified outside an authorized release window?',
      'Are CSP headers and output encoding verified intact?',
    ],
    recommendedContainment: ['firewall_policy'],
  },
  {
    id: 'ddos',
    name: 'Distributed Denial of Service (DDoS)',
    category: 'Availability',
    summary:
      'Correlates volumetric connection exhaustion, CPU/RAM saturation, and degraded heartbeat latency across regions.',
    mitreTechniques: ['T1498', 'T1499'],
    telemetrySignals: [
      'Simultaneous CPU/RAM saturation (>88%) across edge servers',
      'Surge in established/SYN_RECV socket counts and heartbeat latency degradation',
      'Edge proxy service health flapping to degraded or stopped',
    ],
    evidenceQuestions: [
      'Which regions and edge gateways experienced synchronized resource exhaustion?',
      'Is traffic concentrated from specific peer ranges or broadly distributed?',
    ],
    recommendedContainment: ['firewall_policy'],
  },
  {
    id: 'mitm',
    name: 'Man-in-the-Middle (MITM) & TLS Downgrade',
    category: 'Network Integrity',
    summary:
      'Investigates unexpected proxy peers, /etc/hosts or trust-store FIM tampering, and DNS/TLS anomalies.',
    mitreTechniques: ['T1557', 'T1553.004'],
    telemetrySignals: [
      'FIM drift on /etc/hosts, /etc/resolv.conf, or system CA certificate bundle',
      'Unexpected outbound relay peer IP replacing known controller or gateway address',
    ],
    evidenceQuestions: [
      'Were DNS resolver configs, hosts files, or trust stores modified?',
      'Did outbound TLS validation errors appear in system journal logs?',
    ],
    recommendedContainment: ['isolate_server', 'firewall_policy'],
  },
  {
    id: 'account_takeover',
    name: 'Account Takeover & Lateral Pivot',
    category: 'Identity & Lateral Movement',
    summary:
      'Tracks compromised privileged accounts pivoting across multiple enrolled hosts and modifying SSH/sudoers configs.',
    mitreTechniques: ['T1078', 'T1021.004', 'T1098.004'],
    telemetrySignals: [
      'Successful privileged login from unusual source followed by rapid cross-host SSH hops',
      'FIM modification to /etc/ssh/sshd_config, authorized_keys, or /etc/sudoers',
    ],
    evidenceQuestions: [
      'Which hosts were accessed by the suspected account in chronological order?',
      'Were any new SSH keys or sudoers rules introduced?',
    ],
    recommendedContainment: ['isolate_server', 'firewall_policy'],
  },
];

export function getPlaybookById(id?: PlaybookId | string): SentinelInvestigationPlaybook | undefined {
  if (!id) return undefined;
  return SENTINEL_INVESTIGATION_PLAYBOOKS.find((p) => p.id === id);
}

export interface HeartbeatBucketSlot {
  slotIndex: number;
  startMs: number;
  endMs: number;
  label: string;
  health: HeartbeatPingHealth;
  pingCount: number;
  cpuPercent: number;
  ramPercent: number;
  loadAvg1: number;
  latencyMs: number;
  latestPing: SentinelHeartbeatPing | null;
}

export function classifyHeartbeatPingHealth(input: {
  cpuPercent: number;
  ramPercent: number;
  diskPercent: number;
  loadAvg1?: number;
  latencyMs?: number;
  agentStatus?: string;
}): HeartbeatPingHealth {
  if (input.agentStatus === 'isolated' || input.agentStatus === 'revoked' || input.agentStatus === 'offline') {
    return 'critical';
  }
  const latency = input.latencyMs ?? 0;
  const load = input.loadAvg1 ?? 0;
  if (
    input.cpuPercent >= 88 ||
    input.ramPercent >= 90 ||
    input.diskPercent >= 92 ||
    latency >= 1500 ||
    load >= 6.0
  ) {
    return 'critical';
  }
  if (
    input.cpuPercent >= 68 ||
    input.ramPercent >= 75 ||
    input.diskPercent >= 80 ||
    latency >= 500 ||
    load >= 2.5
  ) {
    return 'warning';
  }
  return 'healthy';
}

/**
 * Buckets the last 5 minutes (300 seconds) of heartbeat pings into fixed slots
 * (default 20 slots x 15 seconds = 5 minutes) for the real-time SVG/CSS pulse chart.
 */
export function buildFiveMinuteHeartbeatWindow(
  pings: SentinelHeartbeatPing[],
  nowMs = Date.now(),
  slotCount = 20,
  windowSec = 300
): HeartbeatBucketSlot[] {
  const bucketMs = Math.floor((windowSec * 1000) / slotCount);
  const windowStartMs = nowMs - slotCount * bucketMs;

  const slots: HeartbeatBucketSlot[] = Array.from({ length: slotCount }, (_, idx) => {
    const startMs = windowStartMs + idx * bucketMs;
    const endMs = startMs + bucketMs;
    const secAgo = Math.round((nowMs - endMs) / 1000);
    const label =
      secAgo <= 5
        ? 'now'
        : secAgo < 60
          ? `-${secAgo}s`
          : `-${Math.floor(secAgo / 60)}m${secAgo % 60 ? `${secAgo % 60}s` : ''}`;
    return {
      slotIndex: idx,
      startMs,
      endMs,
      label,
      health: 'missed',
      pingCount: 0,
      cpuPercent: 0,
      ramPercent: 0,
      loadAvg1: 0,
      latencyMs: 0,
      latestPing: null,
    };
  });

  const sortedPings = [...pings].sort(
    (a, b) => new Date(a.observedAt).getTime() - new Date(b.observedAt).getTime()
  );

  for (const ping of sortedPings) {
    const ts = new Date(ping.observedAt).getTime();
    if (Number.isNaN(ts) || ts < windowStartMs || ts > nowMs + 5_000) continue;
    const rawIdx = Math.floor((ts - windowStartMs) / bucketMs);
    const idx = Math.max(0, Math.min(slotCount - 1, rawIdx));
    const slot = slots[idx];
    slot.pingCount += 1;
    slot.latestPing = ping;
    slot.cpuPercent = ping.cpuPercent;
    slot.ramPercent = ping.ramPercent;
    slot.loadAvg1 = ping.loadAvg1;
    slot.latencyMs = ping.latencyMs;

    // Worst health within the bucket wins (critical > warning > healthy)
    if (
      slot.health === 'missed' ||
      ping.health === 'critical' ||
      (ping.health === 'warning' && slot.health === 'healthy')
    ) {
      slot.health = ping.health;
    }
  }

  return slots;
}

/**
 * Generates an ECG-style SVG polyline path across the 5-minute slots where
 * each received ping creates a distinct pulse spike proportional to server load
 * and missed slots remain flatline.
 */
export function buildHeartbeatPulsePath(
  slots: HeartbeatBucketSlot[],
  width = 640,
  height = 84
): string {
  if (slots.length === 0) return `M 0 ${height / 2} L ${width} ${height / 2}`;
  const baseline = Math.round(height * 0.62);
  const stepX = width / slots.length;
  const pts: string[] = [`M 0 ${baseline}`];

  slots.forEach((slot, i) => {
    const x0 = i * stepX;
    if (slot.pingCount === 0 || slot.health === 'missed') {
      pts.push(`L ${(x0 + stepX).toFixed(1)} ${baseline}`);
      return;
    }
    const amplitude =
      slot.health === 'critical'
        ? height * 0.48
        : slot.health === 'warning'
          ? height * 0.34
          : Math.max(height * 0.2, Math.min(height * 0.36, (slot.cpuPercent / 100) * height * 0.38 + 12));
    const dip = Math.min(height * 0.2, amplitude * 0.42);

    pts.push(`L ${(x0 + stepX * 0.22).toFixed(1)} ${baseline}`);
    pts.push(`L ${(x0 + stepX * 0.34).toFixed(1)} ${(baseline - amplitude * 0.28).toFixed(1)}`);
    pts.push(`L ${(x0 + stepX * 0.44).toFixed(1)} ${(baseline + dip * 0.45).toFixed(1)}`);
    pts.push(`L ${(x0 + stepX * 0.54).toFixed(1)} ${(baseline - amplitude).toFixed(1)}`);
    pts.push(`L ${(x0 + stepX * 0.65).toFixed(1)} ${(baseline + dip).toFixed(1)}`);
    pts.push(`L ${(x0 + stepX * 0.78).toFixed(1)} ${baseline}`);
    pts.push(`L ${(x0 + stepX).toFixed(1)} ${baseline}`);
  });

  return pts.join(' ');
}

export interface HeartbeatHealthTransition {
  id: string;
  slotIndex: number;
  slotLabel: string;
  fromHealth: Exclude<HeartbeatPingHealth, 'missed'>;
  toHealth: Exclude<HeartbeatPingHealth, 'missed'>;
  direction: 'degrading' | 'recovering';
  hostname: string;
  observedAt: string;
}

const HEALTH_RANK: Record<Exclude<HeartbeatPingHealth, 'missed'>, number> = {
  healthy: 0,
  warning: 1,
  critical: 2,
};

/**
 * Extracts chronological server health status transitions (e.g. healthy -> warning -> critical)
 * across populated 5-minute heartbeat buckets so the SVG pulse chart highlights exact state shifts.
 */
export function deriveHeartbeatHealthTransitions(
  slots: HeartbeatBucketSlot[]
): HeartbeatHealthTransition[] {
  const transitions: HeartbeatHealthTransition[] = [];
  let previousHealth: Exclude<HeartbeatPingHealth, 'missed'> | null = null;

  for (const slot of slots) {
    if (slot.pingCount === 0 || slot.health === 'missed') continue;
    const currentHealth = slot.health;
    if (previousHealth !== null && previousHealth !== currentHealth) {
      transitions.push({
        id: `tr-${slot.slotIndex}-${previousHealth}-${currentHealth}`,
        slotIndex: slot.slotIndex,
        slotLabel: slot.label,
        fromHealth: previousHealth,
        toHealth: currentHealth,
        direction:
          HEALTH_RANK[currentHealth] > HEALTH_RANK[previousHealth] ? 'degrading' : 'recovering',
        hostname: slot.latestPing?.hostname || 'fleet',
        observedAt: slot.latestPing?.observedAt || new Date(slot.endMs).toISOString(),
      });
    }
    previousHealth = currentHealth;
  }

  return transitions;
}

