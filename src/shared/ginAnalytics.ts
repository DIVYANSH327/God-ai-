import type {
  BehaviourInsightRecord,
  KnowledgeConflictFinding,
  KnowledgeNodeRecord,
  NetworkAssetRecord,
  NetworkAssetStatus,
  RobotsCheckResult,
  SensorNodeInterfaceSpec,
} from './ginTypes.ts';

export const GIN_VERSION = '0.2.0';

export const GIN_SCHEMA_LIMITS = {
  HOSTNAME_MAX: 120,
  IP_RANGE_MAX: 64,
  SCOPE_MAX: 120,
  THREAT_MATCH_MAX: 240,
  QUERY_MAX: 400,
  SUMMARY_MAX: 16000,
  ITEM_TEXT_MAX: 400,
  MAX_ARRAY_ITEMS: 12,
  LABEL_MAX: 120,
  CLAIM_MAX: 600,
  URI_MAX: 1024,
  EXPLANATION_MAX: 2000,
} as const;

export const SENSOR_NODE_SPECS: readonly SensorNodeInterfaceSpec[] = [
  {
    id: 'cloud-passive-sensor',
    platform: 'Cloud Passive Sensor',
    transport: 'Authenticated HTTPS JSON Telemetry API (/api/gin/telemetry/analyze)',
    authMechanism: 'Firebase Verified ID Token (Bearer JWT) + Owner UID Scope',
    permittedTelemetry: [
      'Authorized asset inventory metadata',
      'Aggregated DNS query rates & NXDOMAIN ratios',
      'NetFlow / IPFIX bandwidth summaries (Mbps)',
      'Public threat-feed indicator correlation',
    ],
    prohibitedCapabilities: [
      'Raw packet payload capture or covert TLS interception',
      'Credential or cookie harvesting',
      'Unauthorized active scanning outside declared scope',
    ],
    enrollmentStatus: 'active_cloud_ingestion',
  },
  {
    id: 'windows-node-agent',
    platform: 'Windows 11',
    transport: 'Outbound TLS 1.3 WSS Relay (Zero Inbound Firewall Ports)',
    authMechanism: 'Single-use UID Enrollment Token + DPAPI Ed25519 Keypair',
    permittedTelemetry: [
      'Local Ollama model health & inference relay',
      'Authorized interface flow counters (ETW summary only)',
      'Read-only DNS client cache statistics',
    ],
    prohibitedCapabilities: [
      'Arbitrary PowerShell / cmd execution',
      'LSASS / credential store access',
      'Unrestricted registry or filesystem mutation',
    ],
    enrollmentStatus: 'unpaired_v02_spec',
  },
  {
    id: 'kali-node-agent',
    platform: 'Kali Linux',
    transport: 'Outbound TLS 1.3 WSS Relay (systemd DynamicUser=yes + AppArmor)',
    authMechanism: 'Single-use UID Enrollment Token + mTLS Client Certificate',
    permittedTelemetry: [
      'Defensive posture & authorized host inventory sync',
      'Local Ollama / vLLM inference routing',
      'Passive authorized DNS metadata aggregation',
    ],
    prohibitedCapabilities: [
      'Unauthorized nmap/masscan sweeps or exploitation modules',
      'Root privilege escalation or raw AF_PACKET sniffing',
      'Covert TLS MitM proxy injection',
    ],
    enrollmentStatus: 'unpaired_v02_spec',
  },
];

const KNOWN_PUBLIC_THREAT_SIGNATURES: ReadonlyArray<{
  indicator: string;
  description: string;
  weight: number;
}> = [
  {
    indicator: 'dga-burst',
    description: 'Elevated NXDOMAIN ratio matches public DGA beacon heuristic (OSINT feed)',
    weight: 34,
  },
  {
    indicator: 'egress-spike',
    description: 'Sustained outbound flow > 2.5x baseline deviates from authorized profile',
    weight: 32,
  },
  {
    indicator: 'dns-tunnel-rate',
    description: 'High-frequency DNS metadata volume exceeds normal workstation threshold',
    weight: 28,
  },
];

/**
 * Pure deterministic anomaly detector for authorized network metadata.
 * Operates strictly on aggregated metadata (DNS rate, NXDOMAIN ratio, flow Mbps)
 * — never inspects packet payloads or encrypted content.
 */
export function evaluateNetworkAssetTelemetry(input: {
  dnsQueriesPerMin: number;
  nxdomainRatio: number;
  outboundMbps: number;
  baselineMbps: number;
}): {
  anomalyScore: number;
  status: NetworkAssetStatus;
  threatMatch: string;
  signals: string[];
} {
  let score = 5;
  const signals: string[] = [];

  const safeBaseline = Math.max(0.5, input.baselineMbps);
  const flowRatio = input.outboundMbps / safeBaseline;

  if (input.nxdomainRatio >= 0.25) {
    score += KNOWN_PUBLIC_THREAT_SIGNATURES[0].weight;
    signals.push(
      `NXDOMAIN ratio ${(input.nxdomainRatio * 100).toFixed(1)}% exceeds 25% defensive threshold`
    );
  } else if (input.nxdomainRatio >= 0.12) {
    score += 14;
    signals.push(`Moderate NXDOMAIN elevation (${(input.nxdomainRatio * 100).toFixed(1)}%)`);
  }

  if (flowRatio >= 2.5) {
    score += KNOWN_PUBLIC_THREAT_SIGNATURES[1].weight;
    signals.push(
      `Outbound flow ${input.outboundMbps.toFixed(1)} Mbps is ${flowRatio.toFixed(1)}x baseline (${safeBaseline.toFixed(1)} Mbps)`
    );
  } else if (flowRatio >= 1.6) {
    score += 15;
    signals.push(`Outbound flow elevated at ${flowRatio.toFixed(1)}x baseline`);
  }

  if (input.dnsQueriesPerMin >= 180) {
    score += KNOWN_PUBLIC_THREAT_SIGNATURES[2].weight;
    signals.push(`High DNS metadata rate (${input.dnsQueriesPerMin} q/min)`);
  } else if (input.dnsQueriesPerMin >= 90) {
    score += 10;
    signals.push(`Above-average DNS rate (${input.dnsQueriesPerMin} q/min)`);
  }

  const clampedScore = Math.min(99, Math.max(0, Math.round(score)));
  const status: NetworkAssetStatus =
    clampedScore >= 65 ? 'anomalous' : clampedScore >= 35 ? 'degraded' : 'nominal';

  const threatMatch =
    signals.length > 0
      ? signals.join('; ')
      : 'No public OSINT threat indicators correlated; telemetry within authorized baseline.';

  return {
    anomalyScore: clampedScore,
    status,
    threatMatch,
    signals,
  };
}

/**
 * Validates that a network scope declaration is an explicit authorized label/CIDR
 * and rejects forbidden interception/exploitation directives.
 */
export function validateAuthorizedScopeInput(input: {
  hostname: string;
  ipRange: string;
  authorizedScope: string;
}): { valid: boolean; error?: string } {
  const hostname = input.hostname.trim();
  const ipRange = input.ipRange.trim();
  const scope = input.authorizedScope.trim();

  if (!hostname || hostname.length > GIN_SCHEMA_LIMITS.HOSTNAME_MAX) {
    return { valid: false, error: 'Asset hostname is required (max 120 characters).' };
  }
  if (!ipRange || ipRange.length > GIN_SCHEMA_LIMITS.IP_RANGE_MAX) {
    return { valid: false, error: 'IP address or CIDR range is required.' };
  }
  if (!scope || scope.length > GIN_SCHEMA_LIMITS.SCOPE_MAX) {
    return {
      valid: false,
      error: 'Explicit authorization scope label (e.g., Lab-VLAN-10) is required.',
    };
  }

  const combined = `${hostname} ${ipRange} ${scope}`.toLowerCase();
  if (/\b(mitm|tls[- ]?decrypt|sniff[- ]?password|credential[- ]?harvest|exploit|unauthorized)\b/.test(combined)) {
    return {
      valid: false,
      error:
        'Blocked by GIN Security Governance: covert interception, credential collection, and unauthorized scanning are prohibited.',
    };
  }

  return { valid: true };
}

/**
 * Strict SSRF guard for public website robots.txt & URL inspection.
 * Blocks loopback, RFC1918 private networks, link-local / cloud metadata IPs,
 * IPv6 private ranges, and internal TLDs.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.trim().toLowerCase();

  // IPv6 checks
  if (clean.includes(':')) {
    if (
      clean === '::1' ||
      clean === '::' ||
      clean.startsWith('fe80:') ||
      clean.startsWith('fc') ||
      clean.startsWith('fd') ||
      clean.startsWith('::ffff:127.') ||
      clean.startsWith('::ffff:10.') ||
      clean.startsWith('::ffff:192.168.') ||
      clean.startsWith('::ffff:169.254.')
    ) {
      return true;
    }
    return false;
  }

  const parts = clean.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }

  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // Link-local & cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // Multicast / reserved
  return false;
}

export function validatePublicCrawlTarget(rawUrl: string): {
  valid: boolean;
  normalizedOrigin?: string;
  hostname?: string;
  error?: string;
} {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return { valid: false, error: 'Enter a public HTTPS domain or URL to inspect.' };
  }

  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return { valid: false, error: 'Invalid URL format.' };
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { valid: false, error: 'Only public http:// and https:// targets are permitted.' };
  }

  const host = parsed.hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.lan') ||
    host === 'metadata.google.internal' ||
    !host.includes('.')
  ) {
    return {
      valid: false,
      error: 'Blocked by SSRF guard: localhost, metadata, and private internal hosts are forbidden.',
    };
  }

  // If hostname is a raw IPv4 or bracketed IPv6 literal, reject private ranges immediately
  const unbracketed = host.replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(unbracketed) || unbracketed.includes(':')) {
    if (isPrivateOrReservedIp(unbracketed)) {
      return {
        valid: false,
        error: 'Blocked by SSRF guard: private, loopback, or link-local IP addresses are forbidden.',
      };
    }
  }

  return {
    valid: true,
    normalizedOrigin: parsed.origin,
    hostname: host,
  };
}

/**
 * Pure RFC 9309 robots.txt parser evaluating rules for `*` and `AIGOD-GIN-Bot`.
 */
export function parseRobotsTxt(origin: string, robotsBody: string): RobotsCheckResult {
  const lines = robotsBody.split(/\r?\n/);
  let currentGroupApplies = false;
  let crawlDelaySeconds: number | null = null;
  const disallowedPaths: string[] = [];

  for (const rawLine of lines) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    const sepIdx = line.indexOf(':');
    if (sepIdx === -1) continue;

    const directive = line.slice(0, sepIdx).trim().toLowerCase();
    const value = line.slice(sepIdx + 1).trim();

    if (directive === 'user-agent') {
      const agent = value.toLowerCase();
      currentGroupApplies = agent === '*' || agent.includes('aigod') || agent.includes('gin');
    } else if (currentGroupApplies) {
      if (directive === 'disallow' && value) {
        if (!disallowedPaths.includes(value) && disallowedPaths.length < 25) {
          disallowedPaths.push(value);
        }
      } else if (directive === 'crawl-delay') {
        const parsedDelay = Number(value);
        if (Number.isFinite(parsedDelay) && parsedDelay >= 0) {
          crawlDelaySeconds = parsedDelay;
        }
      }
    }
  }

  const rootDisallowed = disallowedPaths.includes('/');
  const allowedForGinBot = !rootDisallowed;
  const delayNote =
    crawlDelaySeconds !== null
      ? `Honoring Crawl-delay: ${crawlDelaySeconds}s.`
      : 'Default respectful rate limit (<= 1 req / 5s) applied.';

  return {
    origin,
    robotsUrl: `${origin}/robots.txt`,
    reachable: true,
    allowedForGinBot,
    crawlDelaySeconds,
    disallowedPaths,
    policySummary: allowedForGinBot
      ? `Permitted public crawling for non-disallowed routes (${disallowedPaths.length} restricted path rules respected). ${delayNote}`
      : 'Disallowed at root (Disallow: /). GIN Internet Explorer will not crawl this origin.',
  };
}

function tokenize(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, ' ')
      .split(/\s+/)
      .filter((t) => t.length >= 3)
  );
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection += 1;
  }
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

const NEGATION_MARKERS =
  /\b(not|never|no|none|zero|disabled|prohibited|forbidden|disallowed|inactive|false|cannot|without|forbids|blocks)\b/i;

/**
 * Pure Knowledge Graph duplicate & contradictory claim detector.
 */
export function detectKnowledgeConflicts(nodes: readonly KnowledgeNodeRecord[]): KnowledgeConflictFinding[] {
  const findings: KnowledgeConflictFinding[] = [];

  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      const a = nodes[i];
      const b = nodes[j];

      const labelSim = jaccardSimilarity(tokenize(a.label), tokenize(b.label));
      const claimSim = jaccardSimilarity(tokenize(a.claim), tokenize(b.claim));
      const sameLabel = a.label.trim().toLowerCase() === b.label.trim().toLowerCase();

      if ((sameLabel && claimSim >= 0.72) || claimSim >= 0.82) {
        findings.push({
          kind: 'duplicate',
          nodeAId: a.id,
          nodeALabel: a.label,
          nodeBId: b.id,
          nodeBLabel: b.label,
          reason: `High claim overlap (${Math.round(claimSim * 100)}%) across "${a.sourceTitle}" and "${b.sourceTitle}".`,
        });
        continue;
      }

      if (sameLabel || labelSim >= 0.5 || claimSim >= 0.35) {
        const negA = NEGATION_MARKERS.test(a.claim);
        const negB = NEGATION_MARKERS.test(b.claim);
        if (negA !== negB) {
          findings.push({
            kind: 'contradiction',
            nodeAId: a.id,
            nodeALabel: a.label,
            nodeBId: b.id,
            nodeBLabel: b.label,
            reason: `Conflicting assertion polarity detected between "${a.sourceTitle}" and "${b.sourceTitle}". Review source timestamps and confidence.`,
          });
        } else if (sameLabel && claimSim < 0.72) {
          findings.push({
            kind: 'contradiction',
            nodeAId: a.id,
            nodeALabel: a.label,
            nodeBId: b.id,
            nodeBLabel: b.label,
            reason: `Divergent observations for "${a.label}" recorded across "${a.sourceTitle}" and "${b.sourceTitle}". Both claims are preserved side-by-side without overwriting.`,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Pure semantic/token relevance search across Knowledge Graph nodes.
 */
export function searchKnowledgeNodes(
  nodes: readonly KnowledgeNodeRecord[],
  rawQuery: string
): Array<{ node: KnowledgeNodeRecord; relevance: number }> {
  const queryText = rawQuery.trim().toLowerCase();
  if (!queryText) {
    return nodes.map((node) => ({ node, relevance: 1 }));
  }

  const queryTokens = tokenize(queryText);

  return nodes
    .map((node) => {
      const haystack = `${node.label} ${node.entityType} ${node.claim} ${node.sourceTitle} ${node.relations
        .map((r) => `${r.predicate} ${r.targetLabel}`)
        .join(' ')}`.toLowerCase();

      let score = 0;
      if (node.label.toLowerCase().includes(queryText)) score += 0.55;
      if (haystack.includes(queryText)) score += 0.25;

      const nodeTokens = tokenize(haystack);
      let matched = 0;
      for (const qt of queryTokens) {
        if (nodeTokens.has(qt)) {
          matched += 1;
        } else {
          for (const nt of nodeTokens) {
            if (nt.includes(qt) || qt.includes(nt)) {
              matched += 0.6;
              break;
            }
          }
        }
      }
      if (queryTokens.size > 0) {
        score += (matched / queryTokens.size) * 0.65;
      }

      return { node, relevance: Math.min(1, Number(score.toFixed(2))) };
    })
    .filter((entry) => entry.relevance > 0.12)
    .sort((a, b) => b.relevance - a.relevance);
}

/**
 * Pure Behaviour Engine synthesizer that separates verified telemetry facts
 * from probabilistic predictions with calibrated confidence scores.
 */
export function synthesizeDeterministicBehaviourInsight(
  assets: readonly NetworkAssetRecord[]
): Omit<BehaviourInsightRecord, 'id' | 'userId' | 'createdAtMs'> {
  const anomalous = assets.filter((a) => a.status === 'anomalous');
  const degraded = assets.filter((a) => a.status === 'degraded');

  if (anomalous.length > 0) {
    const worst = [...anomalous].sort((a, b) => b.anomalyScore - a.anomalyScore)[0];
    return {
      title: `Elevated Anomaly Pattern on ${worst.hostname}`,
      domain: 'network',
      severity: 'critical',
      confidenceScore: Math.min(95, Math.max(70, worst.anomalyScore)),
      facts: [
        `${worst.hostname} (${worst.ipRange}) reported anomaly score ${worst.anomalyScore}/100 inside authorized scope ${worst.authorizedScope}.`,
        `Observed DNS metadata rate: ${worst.dnsQueriesPerMin} q/min with ${(worst.nxdomainRatio * 100).toFixed(1)}% NXDOMAIN ratio.`,
        `Observed outbound flow: ${worst.outboundMbps.toFixed(1)} Mbps vs ${worst.baselineMbps.toFixed(1)} Mbps baseline.`,
      ],
      predictions: [
        'Pattern may indicate misconfigured service retry loops, noisy automated DNS lookups, or an anomalous egress job.',
        'If sustained across two consecutive intervals, review local process telemetry on the authorized host.',
      ],
      explanation:
        'Computed deterministically from authorized flow and DNS metadata counters without inspecting encrypted payloads.',
      sourceRefs: [worst.hostname, worst.authorizedScope],
    };
  }

  if (degraded.length > 0) {
    const target = degraded[0];
    return {
      title: `Moderate Drift Observed on ${target.hostname}`,
      domain: 'network',
      severity: 'warning',
      confidenceScore: 76,
      facts: [
        `${degraded.length} authorized asset(s) show moderate metric elevation above baseline.`,
        `${target.hostname} is operating at ${target.outboundMbps.toFixed(1)} Mbps (${target.dnsQueriesPerMin} DNS q/min).`,
      ],
      predictions: [
        'Likely benign burst traffic (package updates or batch sync); monitor for return to nominal baseline.',
      ],
      explanation:
        'Baseline deviation falls between 35 and 64 anomaly threshold; no high-severity threat correlation triggered.',
      sourceRefs: [target.hostname],
    };
  }

  return {
    title: 'Authorized Network Baseline Nominal',
    domain: 'hybrid',
    severity: 'info',
    confidenceScore: 91,
    facts: [
      `All ${assets.length} authorized inventory asset(s) are operating within configured DNS and flow baselines.`,
      'Zero active threat-intelligence correlations detected across registered scopes.',
    ],
    predictions: [
      'Continued nominal operation expected unless new scheduled workloads or enrolled workstation nodes come online.',
    ],
    explanation:
      'Verified from current authorized network inventory counters and passive metadata baselines.',
    sourceRefs: assets.slice(0, 3).map((a) => a.hostname),
  };
}
