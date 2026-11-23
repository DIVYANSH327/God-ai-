import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  Timestamp,
  collection,
  deleteDoc,
  doc,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
} from 'firebase/firestore';
import { OperationType, db, handleFirestoreError } from '../lib/firebase';
import { useGodWorkspace } from './GodWorkspaceContext';
import {
  GIN_SCHEMA_LIMITS,
  detectKnowledgeConflicts,
  evaluateNetworkAssetTelemetry,
  synthesizeDeterministicBehaviourInsight,
  validateAuthorizedScopeInput,
  validatePublicCrawlTarget,
} from '../shared/ginAnalytics';
import type {
  BehaviourInsightRecord,
  BrainResearchPlan,
  KnowledgeConflictFinding,
  KnowledgeEntityType,
  KnowledgeNodeRecord,
  KnowledgeRelation,
  NetworkAssetRecord,
  NetworkAssetType,
  ResearchReportRecord,
  ResearchSourceCitation,
  RobotsCheckResult,
} from '../shared/ginTypes';
import { createSafeId, isSafeExternalUrl, sanitizeBoundedString } from '../shared/validation';

interface ExtractedEntityDraft {
  label: string;
  entityType: KnowledgeEntityType;
  claim: string;
}

interface GinIntelligenceContextValue {
  networkAssets: NetworkAssetRecord[];
  addNetworkAsset: (input: {
    hostname: string;
    ipRange: string;
    authorizedScope: string;
    assetType: NetworkAssetType;
    dnsQueriesPerMin: number;
    nxdomainRatio: number;
    outboundMbps: number;
    baselineMbps: number;
  }) => Promise<{ ok: boolean; error?: string }>;
  ingestAssetTelemetry: (
    assetId: string,
    metrics: {
      dnsQueriesPerMin: number;
      nxdomainRatio: number;
      outboundMbps: number;
      baselineMbps: number;
    }
  ) => Promise<void>;
  toggleIsolateAsset: (assetId: string) => Promise<void>;
  deleteNetworkAsset: (assetId: string) => Promise<void>;

  researchReports: ResearchReportRecord[];
  isResearching: boolean;
  researchError: string | null;
  clearResearchError: () => void;
  lastExtractedEntities: ExtractedEntityDraft[];
  lastRobotsResult: RobotsCheckResult | null;
  robotsError: string | null;
  isCheckingRobots: boolean;
  runGroundedResearch: (
    queryText: string,
    scheduleCadence: 'manual' | 'daily' | 'weekly'
  ) => Promise<{ ok: boolean; error?: string }>;
  checkPublicRobots: (url: string) => Promise<void>;
  deleteResearchReport: (reportId: string) => Promise<void>;

  knowledgeNodes: KnowledgeNodeRecord[];
  knowledgeConflicts: KnowledgeConflictFinding[];
  addKnowledgeNode: (input: {
    label: string;
    entityType: KnowledgeEntityType;
    claim: string;
    sourceTitle: string;
    sourceUri: string;
    confidenceScore: number;
    relations?: KnowledgeRelation[];
  }) => Promise<{ ok: boolean; error?: string }>;
  linkKnowledgeNodes: (
    sourceId: string,
    targetId: string,
    predicate: string
  ) => Promise<{ ok: boolean; error?: string }>;
  deleteKnowledgeNode: (nodeId: string) => Promise<void>;

  behaviourInsights: BehaviourInsightRecord[];
  isAnalyzingBehaviour: boolean;
  behaviourError: string | null;
  runBehaviourAnalysis: () => Promise<void>;
  deleteBehaviourInsight: (insightId: string) => Promise<void>;

  brainPlan: BrainResearchPlan | null;
  isPlanningBrain: boolean;
  brainPlanError: string | null;
  generateCentralBrainPlan: (objective: string) => Promise<void>;
}

const GinIntelligenceContext = createContext<GinIntelligenceContextValue | null>(null);

function tsToMillis(val: unknown, fallback: number): number {
  if (val instanceof Timestamp) return val.toMillis();
  if (
    val &&
    typeof val === 'object' &&
    'seconds' in val &&
    typeof (val as { seconds: unknown }).seconds === 'number'
  ) {
    return (val as { seconds: number }).seconds * 1000;
  }
  if (typeof val === 'number') return val;
  return fallback;
}

const SEED_NOW = 1795350000000;

function createPreviewGinSeed() {
  const networkAssets: NetworkAssetRecord[] = [
    {
      id: 'asset_gw_edge_01',
      userId: 'preview_operator',
      hostname: 'gw-edge-01.lab.internal',
      ipRange: '10.42.0.1/24',
      authorizedScope: 'Lab-Authorized-VLAN10',
      assetType: 'gateway',
      status: 'nominal',
      dnsQueriesPerMin: 44,
      nxdomainRatio: 0.03,
      outboundMbps: 18.4,
      baselineMbps: 22.0,
      anomalyScore: 5,
      threatMatch: 'No public OSINT threat indicators correlated; telemetry within authorized baseline.',
      lastSeenMs: SEED_NOW - 120_000,
      createdAtMs: SEED_NOW - 86_400_000,
      updatedAtMs: SEED_NOW - 120_000,
    },
    {
      id: 'asset_srv_telemetry_02',
      userId: 'preview_operator',
      hostname: 'srv-cloudrun-relay.dmz',
      ipRange: '10.42.10.12/32',
      authorizedScope: 'Authorized-DMZ-Relay',
      assetType: 'server',
      status: 'nominal',
      dnsQueriesPerMin: 68,
      nxdomainRatio: 0.04,
      outboundMbps: 41.2,
      baselineMbps: 38.0,
      anomalyScore: 5,
      threatMatch: 'No public OSINT threat indicators correlated; telemetry within authorized baseline.',
      lastSeenMs: SEED_NOW - 90_000,
      createdAtMs: SEED_NOW - 72_000_000,
      updatedAtMs: SEED_NOW - 90_000,
    },
    {
      id: 'asset_sensor_dns_03',
      userId: 'preview_operator',
      hostname: 'sensor-dns-passive-03',
      ipRange: '10.42.20.4/32',
      authorizedScope: 'Lab-Authorized-VLAN20',
      assetType: 'sensor',
      status: 'degraded',
      dnsQueriesPerMin: 132,
      nxdomainRatio: 0.16,
      outboundMbps: 24.5,
      baselineMbps: 14.0,
      anomalyScore: 44,
      threatMatch: 'Moderate NXDOMAIN elevation (16.0%); Outbound flow elevated at 1.8x baseline; Above-average DNS rate (132 q/min)',
      lastSeenMs: SEED_NOW - 45_000,
      createdAtMs: SEED_NOW - 43_200_000,
      updatedAtMs: SEED_NOW - 45_000,
    },
    {
      id: 'asset_ws_build_04',
      userId: 'preview_operator',
      hostname: 'ws-builder-04.lab',
      ipRange: '10.42.10.48/32',
      authorizedScope: 'Lab-Authorized-VLAN10',
      assetType: 'workstation',
      status: 'anomalous',
      dnsQueriesPerMin: 215,
      nxdomainRatio: 0.29,
      outboundMbps: 86.0,
      baselineMbps: 25.0,
      anomalyScore: 99,
      threatMatch: 'NXDOMAIN ratio 29.0% exceeds 25% defensive threshold; Outbound flow 86.0 Mbps is 3.4x baseline (25.0 Mbps); High DNS metadata rate (215 q/min)',
      lastSeenMs: SEED_NOW - 20_000,
      createdAtMs: SEED_NOW - 28_800_000,
      updatedAtMs: SEED_NOW - 20_000,
    },
  ];

  const researchReports: ResearchReportRecord[] = [
    {
      id: 'rep_gin_dns_telemetry',
      userId: 'preview_operator',
      query: 'Passive DNS metadata anomaly detection without TLS decryption best practices',
      summary: `## Executive Summary

Modern defensive network observability relies on passive DNS metadata (query rate, NXDOMAIN ratios, query entropy) and NetFlow/IPFIX summaries rather than invasive TLS interception. This preserves end-to-end encryption integrity while still surfacing command-and-control beaconing or misconfigured retry storms.

Public security frameworks (RFC 9309, NIST SP 800-207 Zero Trust Architecture) emphasize explicit scope boundaries, least-privilege telemetry agents, and cryptographic mutual authentication for distributed sensors.

## Verified Facts
- Passive DNS NXDOMAIN ratio spikes are a standard metadata indicator for Domain Generation Algorithm (DGA) activity and broken service discovery.
- NIST SP 800-207 defines continuous diagnostics and mitigation using metadata flows without requiring covert TLS decryption.
- Outbound-only mTLS WebSocket relays eliminate inbound firewall exposure on remote monitoring nodes.

## Analytical Predictions
- Lightweight metadata-only eBPF and ETW sensors are likely to replace heavy deep packet inspection appliances on developer workstations over the next 24 months.
- Correlating public OSINT indicators with local baseline drift should reduce false-positive alert fatigue by prioritizing sustained multi-metric anomalies.`,
      facts: [
        'Passive DNS NXDOMAIN ratio spikes are a standard metadata indicator for DGA activity and broken service discovery.',
        'NIST SP 800-207 defines continuous diagnostics using flow metadata without requiring covert TLS decryption.',
        'Outbound-only mTLS WebSocket relays eliminate inbound firewall exposure on remote monitoring nodes.',
      ],
      predictions: [
        'Metadata-only eBPF and ETW sensors will increasingly replace deep packet inspection appliances on developer workstations.',
        'Correlating public OSINT indicators with local baseline drift should reduce false-positive alert volume.',
      ],
      confidenceScore: 88,
      sources: [
        {
          title: 'NIST SP 800-207: Zero Trust Architecture',
          uri: 'https://csrc.nist.gov/publications/detail/sp/800-207/final',
          domain: 'csrc.nist.gov',
        },
        {
          title: 'RFC 9309: Robots Exclusion Protocol',
          uri: 'https://www.rfc-editor.org/rfc/rfc9309',
          domain: 'www.rfc-editor.org',
        },
      ],
      scheduleCadence: 'weekly',
      createdAtMs: SEED_NOW - 3_600_000,
    },
    {
      id: 'rep_gin_robots_compliance',
      userId: 'preview_operator',
      query: 'Respectful automated web research robots.txt and SSRF prevention architecture',
      summary: `## Executive Summary

Server-side research agents that inspect public web resources must combine RFC 9309 \`robots.txt\` compliance with strict Server-Side Request Forgery (SSRF) defenses. Resolving hostnames prior to outbound requests and rejecting loopback, RFC1918, link-local, and cloud metadata IPs prevents internal network probing.

## Verified Facts
- RFC 9309 standardizes User-agent and Disallow parsing for automated crawlers on public origins.
- Disabling automatic HTTP redirects and validating every DNS-resolved IP address mitigates DNS rebinding and cloud metadata SSRF risks.

## Analytical Predictions
- Public knowledge platforms will adopt stricter per-agent crawl-delay enforcement and authenticated public JSON APIs for structured research ingestion.`,
      facts: [
        'RFC 9309 standardizes User-agent and Disallow parsing for automated crawlers on public origins.',
        'Disabling automatic HTTP redirects and validating DNS-resolved IPs mitigates SSRF and cloud metadata probing.',
      ],
      predictions: [
        'Public knowledge platforms will increasingly prefer authenticated JSON APIs and explicit crawl-delay limits.',
      ],
      confidenceScore: 91,
      sources: [
        {
          title: 'OWASP Server-Side Request Forgery Prevention Cheat Sheet',
          uri: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
          domain: 'cheatsheetseries.owasp.org',
        },
      ],
      scheduleCadence: 'manual',
      createdAtMs: SEED_NOW - 7_200_000,
    },
  ];

  const knowledgeNodes: KnowledgeNodeRecord[] = [
    {
      id: 'kn_passive_dns',
      userId: 'preview_operator',
      label: 'Passive DNS Metadata Analytics',
      entityType: 'technology',
      claim: 'Tracks aggregated DNS query rates and NXDOMAIN ratios inside authorized scopes without inspecting packet payloads.',
      sourceTitle: 'NIST SP 800-207',
      sourceUri: 'https://csrc.nist.gov/publications/detail/sp/800-207/final',
      confidenceScore: 94,
      relations: [
        { targetId: 'kn_ws_builder', targetLabel: 'ws-builder-04.lab', predicate: 'monitors' },
        { targetId: 'kn_dga_heuristic', targetLabel: 'DGA NXDOMAIN Heuristic', predicate: 'correlates_with' },
      ],
      createdAtMs: SEED_NOW - 5_000_000,
      updatedAtMs: SEED_NOW - 5_000_000,
    },
    {
      id: 'kn_dga_heuristic',
      userId: 'preview_operator',
      label: 'DGA NXDOMAIN Heuristic',
      entityType: 'threat',
      claim: 'Sustained NXDOMAIN ratio above 25% alongside egress spikes signals potential DGA beaconing or misconfigured retry loops.',
      sourceTitle: 'GIN OSINT Feed v0.2',
      sourceUri: 'https://csrc.nist.gov/publications/detail/sp/800-207/final',
      confidenceScore: 86,
      relations: [
        { targetId: 'kn_ws_builder', targetLabel: 'ws-builder-04.lab', predicate: 'flagged_on' },
      ],
      createdAtMs: SEED_NOW - 4_500_000,
      updatedAtMs: SEED_NOW - 4_500_000,
    },
    {
      id: 'kn_ws_builder',
      userId: 'preview_operator',
      label: 'ws-builder-04.lab',
      entityType: 'asset',
      claim: 'Authorized workstation in Lab-Authorized-VLAN10 exhibiting 3.4x outbound bandwidth drift and 29% NXDOMAIN rate.',
      sourceTitle: 'GOD Network Observer',
      sourceUri: '',
      confidenceScore: 92,
      relations: [
        { targetId: 'kn_outbound_wss', targetLabel: 'Outbound WSS mTLS Relay', predicate: 'planned_transport' },
      ],
      createdAtMs: SEED_NOW - 3_800_000,
      updatedAtMs: SEED_NOW - 3_800_000,
    },
    {
      id: 'kn_outbound_wss',
      userId: 'preview_operator',
      label: 'Outbound WSS mTLS Relay',
      entityType: 'protocol',
      claim: 'Remote Windows and Kali Linux nodes initiate outbound TLS 1.3 WebSocket tunnels with zero inbound open ports.',
      sourceTitle: 'AI GOD Hybrid Architecture Spec',
      sourceUri: '',
      confidenceScore: 96,
      relations: [],
      createdAtMs: SEED_NOW - 6_400_000,
      updatedAtMs: SEED_NOW - 6_400_000,
    },
    {
      id: 'kn_tls_policy_ok',
      userId: 'preview_operator',
      label: 'Covert TLS Decryption Policy',
      entityType: 'concept',
      claim: 'Covert TLS decryption is strictly prohibited and never enabled on GIN Network Observer sensors.',
      sourceTitle: 'GIN Security Governance Charter',
      sourceUri: '',
      confidenceScore: 99,
      relations: [
        { targetId: 'kn_passive_dns', targetLabel: 'Passive DNS Metadata Analytics', predicate: 'enforces_boundary_for' },
      ],
      createdAtMs: SEED_NOW - 6_000_000,
      updatedAtMs: SEED_NOW - 6_000_000,
    },
    {
      id: 'kn_tls_policy_conflict',
      userId: 'preview_operator',
      label: 'Covert TLS Decryption Policy',
      entityType: 'concept',
      claim: 'Legacy third-party draft proposed enabling transparent TLS decryption on edge sensors.',
      sourceTitle: 'Archived External Draft (Unverified)',
      sourceUri: '',
      confidenceScore: 28,
      relations: [],
      createdAtMs: SEED_NOW - 8_000_000,
      updatedAtMs: SEED_NOW - 8_000_000,
    },
    {
      id: 'kn_nextjs_edge',
      userId: 'preview_operator',
      label: 'Next.js / React Edge Stack',
      entityType: 'framework',
      claim: 'Public HTML and HTTP header inspection on react.dev indicates Next.js SSR with HSTS and nosniff security headers.',
      sourceTitle: 'GRI Frontend Intelligence (react.dev)',
      sourceUri: 'https://react.dev',
      confidenceScore: 92,
      relations: [
        { targetId: 'kn_cloudflare_dualstack', targetLabel: 'rfc-editor.org Cloudflare Edge', predicate: 'shares_edge_pattern' },
      ],
      createdAtMs: SEED_NOW - 2_400_000,
      updatedAtMs: SEED_NOW - 2_400_000,
    },
    {
      id: 'kn_cloudflare_dualstack',
      userId: 'preview_operator',
      label: 'rfc-editor.org Cloudflare Edge',
      entityType: 'infrastructure',
      claim: 'Public DNS and crt.sh logs confirm IPv4/IPv6 dual-stack hosting with explicit CAA Let’s Encrypt certificate pinning.',
      sourceTitle: 'GRI Server Intelligence (crt.sh)',
      sourceUri: 'https://crt.sh/?q=rfc-editor.org',
      confidenceScore: 91,
      relations: [
        { targetId: 'kn_passive_dns', targetLabel: 'Passive DNS Metadata Analytics', predicate: 'observed_via_dns' },
      ],
      createdAtMs: SEED_NOW - 2_100_000,
      updatedAtMs: SEED_NOW - 2_100_000,
    },
    {
      id: 'kn_cve_runc',
      userId: 'preview_operator',
      label: 'CVE-2024-21626 (runc)',
      entityType: 'vulnerability',
      claim: 'CISA KEV listed container breakout via leaked file descriptor (CVSS 8.6); mitigated by upgrading to runc >= 1.1.12.',
      sourceTitle: 'GRI Security Research (CISA KEV / NVD)',
      sourceUri: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21626',
      confidenceScore: 96,
      relations: [
        { targetId: 'kn_ws_builder', targetLabel: 'ws-builder-04.lab', predicate: 'audit_runtime_on' },
      ],
      createdAtMs: SEED_NOW - 1_800_000,
      updatedAtMs: SEED_NOW - 1_800_000,
    },
  ];

  const behaviourInsights: BehaviourInsightRecord[] = [
    {
      id: 'beh_seed_1',
      userId: 'preview_operator',
      title: 'Elevated Anomaly Pattern on ws-builder-04.lab',
      domain: 'network',
      severity: 'critical',
      confidenceScore: 91,
      facts: [
        'ws-builder-04.lab (10.42.10.48/32) reported anomaly score 99/100 inside authorized scope Lab-Authorized-VLAN10.',
        'Observed DNS metadata rate: 215 q/min with 29.0% NXDOMAIN ratio.',
        'Observed outbound flow: 86.0 Mbps vs 25.0 Mbps baseline (3.4x drift).',
      ],
      predictions: [
        'Pattern may indicate misconfigured CI dependency retry loops, noisy automated DNS lookups, or an anomalous egress job.',
        'If sustained across two consecutive intervals, isolate the asset flag and review local host process logs.',
      ],
      explanation:
        'Computed deterministically from authorized passive DNS and NetFlow metadata counters without inspecting encrypted payloads.',
      sourceRefs: ['ws-builder-04.lab', 'Lab-Authorized-VLAN10', 'DGA NXDOMAIN Heuristic'],
      createdAtMs: SEED_NOW - 1_500_000,
    },
    {
      id: 'beh_seed_2',
      userId: 'preview_operator',
      title: 'Cross-Session Policy Contradiction Surfaced in Knowledge Graph',
      domain: 'hybrid',
      severity: 'warning',
      confidenceScore: 84,
      facts: [
        'Knowledge Graph identified conflicting claims on "Covert TLS Decryption Policy" across two ingested sources.',
        'GIN Security Governance Charter (99% confidence) contradicts Archived External Draft (28% confidence).',
      ],
      predictions: [
        'Removing or superseding the low-confidence archived claim will keep downstream Central Brain planning aligned with strict zero-interception governance.',
      ],
      explanation:
        'Detected by cross-referencing claim polarity and source confidence timestamps across stored Knowledge Graph entities.',
      sourceRefs: ['Covert TLS Decryption Policy', 'GIN Security Governance Charter'],
      createdAtMs: SEED_NOW - 2_900_000,
    },
  ];

  const brainPlan: BrainResearchPlan = {
    objective: 'Investigate elevated DNS NXDOMAIN & egress drift on authorized Lab-VLAN10 workstation',
    strategySummary:
      'Correlate passive DNS metadata with public threat indicators, verify governance scope boundaries, and persist validated findings into the user-isolated Knowledge Graph.',
    confidenceScore: 89,
    steps: [
      {
        stepNumber: 1,
        agentModule: 'GOD Network Observer',
        objective: 'Validate passive DNS query rate, NXDOMAIN ratio, and outbound Mbps drift for ws-builder-04.lab.',
        verificationCriteria: 'Confirmed within declared Lab-Authorized-VLAN10 scope with zero payload capture.',
        status: 'ready_v02',
      },
      {
        stepNumber: 2,
        agentModule: 'GOD Internet Explorer',
        objective: 'Query public OSINT advisories via Gemini Google Search Grounding for matching DGA/DNS retry signatures.',
        verificationCriteria: 'At least 2 verifiable public HTTPS source citations attached.',
        status: 'ready_v02',
      },
      {
        stepNumber: 3,
        agentModule: 'GOD Behaviour Engine',
        objective: 'Synthesize verified telemetry facts separately from predictive root-cause hypotheses with calibrated confidence.',
        verificationCriteria: 'Output explicitly partitions Facts vs Predictions with numeric confidence score.',
        status: 'ready_v02',
      },
      {
        stepNumber: 4,
        agentModule: 'GOD Knowledge Graph',
        objective: 'Commit validated indicators and run duplicate/contradiction audit across prior sessions.',
        verificationCriteria: 'Entity persisted with source URI, timestamp, and conflict check executed.',
        status: 'ready_v02',
      },
    ],
    verificationChecklist: [
      'Confirm asset belongs to an explicitly authorized network scope',
      'Verify every external citation uses a safe public HTTPS origin',
      'Confirm zero covert TLS decryption or active unauthorized scanning was invoked',
    ],
  };

  return { networkAssets, researchReports, knowledgeNodes, behaviourInsights, brainPlan };
}

export function GinIntelligenceProvider({ children }: { children: React.ReactNode }) {
  const { firebaseUser, bootstrapReadyUid, profile, recordAuditEvent } = useGodWorkspace();

  const seed = useMemo(() => createPreviewGinSeed(), []);
  const [previewAssets, setPreviewAssets] = useState<NetworkAssetRecord[]>(seed.networkAssets);
  const [previewReports, setPreviewReports] = useState<ResearchReportRecord[]>(seed.researchReports);
  const [previewNodes, setPreviewNodes] = useState<KnowledgeNodeRecord[]>(seed.knowledgeNodes);
  const [previewInsights, setPreviewInsights] = useState<BehaviourInsightRecord[]>(
    seed.behaviourInsights
  );

  const [cloudAssets, setCloudAssets] = useState<NetworkAssetRecord[]>([]);
  const [cloudReports, setCloudReports] = useState<ResearchReportRecord[]>([]);
  const [cloudNodes, setCloudNodes] = useState<KnowledgeNodeRecord[]>([]);
  const [cloudInsights, setCloudInsights] = useState<BehaviourInsightRecord[]>([]);

  const [isResearching, setIsResearching] = useState(false);
  const [researchError, setResearchError] = useState<string | null>(null);
  const [lastExtractedEntities, setLastExtractedEntities] = useState<ExtractedEntityDraft[]>([]);

  const [isCheckingRobots, setIsCheckingRobots] = useState(false);
  const [lastRobotsResult, setLastRobotsResult] = useState<RobotsCheckResult | null>(null);
  const [robotsError, setRobotsError] = useState<string | null>(null);

  const [isAnalyzingBehaviour, setIsAnalyzingBehaviour] = useState(false);
  const [behaviourError, setBehaviourError] = useState<string | null>(null);

  const [brainPlan, setBrainPlan] = useState<BrainResearchPlan | null>(seed.brainPlan);
  const [isPlanningBrain, setIsPlanningBrain] = useState(false);
  const [brainPlanError, setBrainPlanError] = useState<string | null>(null);

  // Real-time Firestore listeners for all 4 GIN v0.2 collections
  useEffect(() => {
    if (!firebaseUser || bootstrapReadyUid !== firebaseUser.uid) {
      setCloudAssets([]);
      setCloudReports([]);
      setCloudNodes([]);
      setCloudInsights([]);
      return;
    }

    const uid = firebaseUser.uid;
    const unsubs: Array<() => void> = [];

    // 1. networkAssets
    const assetsPath = `users/${uid}/networkAssets`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'networkAssets'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: NetworkAssetRecord[] = snap.docs.map((dSnap) => {
            const d = dSnap.data();
            const updatedAtMs = tsToMillis(d.updatedAt, now);
            return {
              id: dSnap.id,
              userId: String(d.userId),
              hostname: String(d.hostname || ''),
              ipRange: String(d.ipRange || ''),
              authorizedScope: String(d.authorizedScope || ''),
              assetType: (d.assetType as NetworkAssetType) || 'sensor',
              status: (d.status as NetworkAssetRecord['status']) || 'nominal',
              dnsQueriesPerMin: Number(d.dnsQueriesPerMin || 0),
              nxdomainRatio: Number(d.nxdomainRatio || 0),
              outboundMbps: Number(d.outboundMbps || 0),
              baselineMbps: Number(d.baselineMbps || 1),
              anomalyScore: Number(d.anomalyScore || 0),
              threatMatch: String(d.threatMatch || ''),
              lastSeenMs: updatedAtMs,
              createdAtMs: tsToMillis(d.createdAt, now),
              updatedAtMs,
            };
          });
          items.sort((a, b) => b.anomalyScore - a.anomalyScore || b.updatedAtMs - a.updatedAtMs);
          setCloudAssets(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, assetsPath)
      )
    );

    // 2. researchReports
    const reportsPath = `users/${uid}/researchReports`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'researchReports'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: ResearchReportRecord[] = snap.docs.map((dSnap) => {
            const d = dSnap.data();
            return {
              id: dSnap.id,
              userId: String(d.userId),
              query: String(d.query || ''),
              summary: String(d.summary || ''),
              facts: Array.isArray(d.facts) ? d.facts.map(String) : [],
              predictions: Array.isArray(d.predictions) ? d.predictions.map(String) : [],
              confidenceScore: Number(d.confidenceScore || 0),
              sources: Array.isArray(d.sources)
                ? (d.sources as ResearchSourceCitation[])
                : [],
              scheduleCadence:
                d.scheduleCadence === 'daily' || d.scheduleCadence === 'weekly'
                  ? d.scheduleCadence
                  : 'manual',
              createdAtMs: tsToMillis(d.createdAt, now),
            };
          });
          items.sort((a, b) => b.createdAtMs - a.createdAtMs);
          setCloudReports(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, reportsPath)
      )
    );

    // 3. knowledgeNodes
    const nodesPath = `users/${uid}/knowledgeNodes`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'knowledgeNodes'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: KnowledgeNodeRecord[] = snap.docs.map((dSnap) => {
            const d = dSnap.data();
            return {
              id: dSnap.id,
              userId: String(d.userId),
              label: String(d.label || ''),
              entityType: (d.entityType as KnowledgeEntityType) || 'concept',
              claim: String(d.claim || ''),
              sourceTitle: String(d.sourceTitle || 'Operator Entry'),
              sourceUri: String(d.sourceUri || ''),
              confidenceScore: Number(d.confidenceScore || 0),
              relations: Array.isArray(d.relations)
                ? (d.relations as KnowledgeRelation[])
                : [],
              createdAtMs: tsToMillis(d.createdAt, now),
              updatedAtMs: tsToMillis(d.updatedAt, now),
            };
          });
          items.sort((a, b) => b.updatedAtMs - a.updatedAtMs);
          setCloudNodes(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, nodesPath)
      )
    );

    // 4. behaviourInsights
    const insightsPath = `users/${uid}/behaviourInsights`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'behaviourInsights'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: BehaviourInsightRecord[] = snap.docs.map((dSnap) => {
            const d = dSnap.data();
            return {
              id: dSnap.id,
              userId: String(d.userId),
              title: String(d.title || ''),
              domain:
                d.domain === 'network' || d.domain === 'internet' || d.domain === 'hybrid'
                  ? d.domain
                  : 'hybrid',
              severity:
                d.severity === 'critical' || d.severity === 'warning' ? d.severity : 'info',
              confidenceScore: Number(d.confidenceScore || 0),
              facts: Array.isArray(d.facts) ? d.facts.map(String) : [],
              predictions: Array.isArray(d.predictions) ? d.predictions.map(String) : [],
              explanation: String(d.explanation || ''),
              sourceRefs: Array.isArray(d.sourceRefs) ? d.sourceRefs.map(String) : [],
              createdAtMs: tsToMillis(d.createdAt, now),
            };
          });
          items.sort((a, b) => b.createdAtMs - a.createdAtMs);
          setCloudInsights(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, insightsPath)
      )
    );

    return () => {
      for (const u of unsubs) u();
    };
  }, [firebaseUser, bootstrapReadyUid]);

  const networkAssets = firebaseUser ? cloudAssets : previewAssets;
  const researchReports = firebaseUser ? cloudReports : previewReports;
  const knowledgeNodes = firebaseUser ? cloudNodes : previewNodes;
  const behaviourInsights = firebaseUser ? cloudInsights : previewInsights;

  const knowledgeConflicts = useMemo(
    () => detectKnowledgeConflicts(knowledgeNodes),
    [knowledgeNodes]
  );

  const addNetworkAsset = useCallback(
    async (input: {
      hostname: string;
      ipRange: string;
      authorizedScope: string;
      assetType: NetworkAssetType;
      dnsQueriesPerMin: number;
      nxdomainRatio: number;
      outboundMbps: number;
      baselineMbps: number;
    }) => {
      const check = validateAuthorizedScopeInput({
        hostname: input.hostname,
        ipRange: input.ipRange,
        authorizedScope: input.authorizedScope,
      });
      if (!check.valid) {
        return { ok: false, error: check.error };
      }

      const dnsQpm = Math.max(0, Math.min(1_000_000, Number(input.dnsQueriesPerMin) || 0));
      const nxRatio = Math.max(0, Math.min(1, Number(input.nxdomainRatio) || 0));
      const outMbps = Math.max(0, Math.min(100_000, Number(input.outboundMbps) || 0));
      const baseMbps = Math.max(0.5, Math.min(100_000, Number(input.baselineMbps) || 1));

      const scored = evaluateNetworkAssetTelemetry({
        dnsQueriesPerMin: dnsQpm,
        nxdomainRatio: nxRatio,
        outboundMbps: outMbps,
        baselineMbps: baseMbps,
      });

      const hostname = sanitizeBoundedString(input.hostname, GIN_SCHEMA_LIMITS.HOSTNAME_MAX);
      const ipRange = sanitizeBoundedString(input.ipRange, GIN_SCHEMA_LIMITS.IP_RANGE_MAX);
      const authorizedScope = sanitizeBoundedString(
        input.authorizedScope,
        GIN_SCHEMA_LIMITS.SCOPE_MAX
      );
      const threatMatch = sanitizeBoundedString(
        scored.threatMatch,
        GIN_SCHEMA_LIMITS.THREAT_MATCH_MAX
      );

      if (!firebaseUser) {
        const now = Date.now();
        const record: NetworkAssetRecord = {
          id: createSafeId('asset'),
          userId: 'preview_operator',
          hostname,
          ipRange,
          authorizedScope,
          assetType: input.assetType,
          status: scored.status,
          dnsQueriesPerMin: dnsQpm,
          nxdomainRatio: nxRatio,
          outboundMbps: outMbps,
          baselineMbps: baseMbps,
          anomalyScore: scored.anomalyScore,
          threatMatch,
          lastSeenMs: now,
          createdAtMs: now,
          updatedAtMs: now,
        };
        setPreviewAssets((prev) => [record, ...prev]);
        await recordAuditEvent({
          action: 'NETWORK_ASSET_REGISTERED',
          category: 'network',
          severity: scored.status === 'anomalous' ? 'warning' : 'info',
          summary: `Registered authorized asset ${hostname} (${authorizedScope}) — anomaly score ${scored.anomalyScore}/100.`,
        });
        return { ok: true };
      }

      const uid = firebaseUser.uid;
      const assetId = createSafeId('asset');
      const path = `users/${uid}/networkAssets/${assetId}`;
      try {
        await setDoc(doc(db, 'users', uid, 'networkAssets', assetId), {
          id: assetId,
          userId: uid,
          hostname,
          ipRange,
          authorizedScope,
          assetType: input.assetType,
          status: scored.status,
          dnsQueriesPerMin: dnsQpm,
          nxdomainRatio: nxRatio,
          outboundMbps: outMbps,
          baselineMbps: baseMbps,
          anomalyScore: scored.anomalyScore,
          threatMatch,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'NETWORK_ASSET_REGISTERED',
          category: 'network',
          severity: scored.status === 'anomalous' ? 'warning' : 'info',
          summary: `Registered authorized asset ${hostname} in scope ${authorizedScope} (score ${scored.anomalyScore}/100).`,
        });
        return { ok: true };
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, path);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const ingestAssetTelemetry = useCallback(
    async (
      assetId: string,
      metrics: {
        dnsQueriesPerMin: number;
        nxdomainRatio: number;
        outboundMbps: number;
        baselineMbps: number;
      }
    ) => {
      const dnsQpm = Math.max(0, Math.min(1_000_000, Number(metrics.dnsQueriesPerMin) || 0));
      const nxRatio = Math.max(0, Math.min(1, Number(metrics.nxdomainRatio) || 0));
      const outMbps = Math.max(0, Math.min(100_000, Number(metrics.outboundMbps) || 0));
      const baseMbps = Math.max(0.5, Math.min(100_000, Number(metrics.baselineMbps) || 1));

      const scored = evaluateNetworkAssetTelemetry({
        dnsQueriesPerMin: dnsQpm,
        nxdomainRatio: nxRatio,
        outboundMbps: outMbps,
        baselineMbps: baseMbps,
      });
      const threatMatch = sanitizeBoundedString(
        scored.threatMatch,
        GIN_SCHEMA_LIMITS.THREAT_MATCH_MAX
      );

      if (!firebaseUser) {
        const now = Date.now();
        setPreviewAssets((prev) =>
          prev.map((a) =>
            a.id === assetId
              ? {
                  ...a,
                  dnsQueriesPerMin: dnsQpm,
                  nxdomainRatio: nxRatio,
                  outboundMbps: outMbps,
                  baselineMbps: baseMbps,
                  anomalyScore: scored.anomalyScore,
                  status: a.status === 'isolated' ? 'isolated' : scored.status,
                  threatMatch,
                  lastSeenMs: now,
                  updatedAtMs: now,
                }
              : a
          )
        );
        await recordAuditEvent({
          action: 'TELEMETRY_SAMPLE_INGESTED',
          category: 'network',
          severity: scored.status === 'anomalous' ? 'warning' : 'info',
          summary: `Updated passive metadata telemetry for ${assetId}: ${dnsQpm} DNS q/min, ${outMbps} Mbps (score ${scored.anomalyScore}).`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const path = `users/${uid}/networkAssets/${assetId}`;
      try {
        await updateDoc(doc(db, 'users', uid, 'networkAssets', assetId), {
          dnsQueriesPerMin: dnsQpm,
          nxdomainRatio: nxRatio,
          outboundMbps: outMbps,
          baselineMbps: baseMbps,
          anomalyScore: scored.anomalyScore,
          status: scored.status,
          threatMatch,
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'TELEMETRY_SAMPLE_INGESTED',
          category: 'network',
          severity: scored.status === 'anomalous' ? 'warning' : 'info',
          summary: `Ingested passive telemetry on ${assetId}: score ${scored.anomalyScore}/100 (${scored.status}).`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, path);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const toggleIsolateAsset = useCallback(
    async (assetId: string) => {
      const target = networkAssets.find((a) => a.id === assetId);
      if (!target) return;

      const recomputed = evaluateNetworkAssetTelemetry({
        dnsQueriesPerMin: target.dnsQueriesPerMin,
        nxdomainRatio: target.nxdomainRatio,
        outboundMbps: target.outboundMbps,
        baselineMbps: target.baselineMbps,
      });
      const nextStatus = target.status === 'isolated' ? recomputed.status : 'isolated';

      if (!firebaseUser) {
        setPreviewAssets((prev) =>
          prev.map((a) =>
            a.id === assetId ? { ...a, status: nextStatus, updatedAtMs: Date.now() } : a
          )
        );
        await recordAuditEvent({
          action: nextStatus === 'isolated' ? 'ASSET_MARKED_ISOLATED' : 'ASSET_ISOLATION_CLEARED',
          category: 'security',
          severity: nextStatus === 'isolated' ? 'warning' : 'info',
          summary: `Asset ${target.hostname} status changed to ${nextStatus}.`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const path = `users/${uid}/networkAssets/${assetId}`;
      try {
        await updateDoc(doc(db, 'users', uid, 'networkAssets', assetId), {
          status: nextStatus,
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: nextStatus === 'isolated' ? 'ASSET_MARKED_ISOLATED' : 'ASSET_ISOLATION_CLEARED',
          category: 'security',
          severity: nextStatus === 'isolated' ? 'warning' : 'info',
          summary: `Asset ${target.hostname} status set to ${nextStatus}.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, path);
      }
    },
    [networkAssets, firebaseUser, recordAuditEvent]
  );

  const deleteNetworkAsset = useCallback(
    async (assetId: string) => {
      if (!firebaseUser) {
        setPreviewAssets((prev) => prev.filter((a) => a.id !== assetId));
        await recordAuditEvent({
          action: 'NETWORK_ASSET_REMOVED',
          category: 'network',
          severity: 'info',
          summary: `Removed network inventory record ${assetId}.`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const path = `users/${uid}/networkAssets/${assetId}`;
      try {
        await deleteDoc(doc(db, 'users', uid, 'networkAssets', assetId));
        await recordAuditEvent({
          action: 'NETWORK_ASSET_REMOVED',
          category: 'network',
          severity: 'info',
          summary: `Removed network inventory record ${assetId} from Cloud Firestore.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, path);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const clearResearchError = useCallback(() => setResearchError(null), []);

  const runGroundedResearch = useCallback(
    async (queryText: string, scheduleCadence: 'manual' | 'daily' | 'weekly') => {
      setResearchError(null);
      setLastExtractedEntities([]);
      const trimmed = queryText.trim();
      if (!trimmed || trimmed.length > GIN_SCHEMA_LIMITS.QUERY_MAX) {
        const err = 'Enter a research query between 1 and 400 characters.';
        setResearchError(err);
        return { ok: false, error: err };
      }
      if (profile.emergencyStop) {
        const err = 'Emergency Stop is active. Release Emergency Stop in Security Center before running web research.';
        setResearchError(err);
        return { ok: false, error: err };
      }
      if (!firebaseUser) {
        const err =
          'Live public web search via Gemini Search Grounding requires Google Sign-In so requests are authenticated, rate-limited, and saved to Cloud Firestore.';
        setResearchError(err);
        return { ok: false, error: err };
      }

      setIsResearching(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gin/research', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({
            query: trimmed,
            emergencyStop: profile.emergencyStop,
          }),
        });

        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          report?: {
            query: string;
            summary: string;
            facts: string[];
            predictions: string[];
            confidenceScore: number;
            sources: ResearchSourceCitation[];
            extractedEntities?: ExtractedEntityDraft[];
          };
        };

        if (!resp.ok || !payload.report) {
          throw new Error(payload.error || `Research request failed (${resp.status}).`);
        }

        const report = payload.report;
        const uid = firebaseUser.uid;
        const reportId = createSafeId('rep');
        const path = `users/${uid}/researchReports/${reportId}`;

        const safeFacts = report.facts
          .slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS)
          .map((f) => sanitizeBoundedString(String(f), GIN_SCHEMA_LIMITS.ITEM_TEXT_MAX));
        const safePredictions = report.predictions
          .slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS)
          .map((p) => sanitizeBoundedString(String(p), GIN_SCHEMA_LIMITS.ITEM_TEXT_MAX));
        const safeSources = report.sources.slice(0, 15).map((s) => ({
          title: sanitizeBoundedString(String(s.title || 'Public Source'), 140, 'Public Source'),
          uri: sanitizeBoundedString(String(s.uri || ''), GIN_SCHEMA_LIMITS.URI_MAX),
          domain: sanitizeBoundedString(String(s.domain || 'web'), 120, 'web'),
        }));

        try {
          await setDoc(doc(db, 'users', uid, 'researchReports', reportId), {
            id: reportId,
            userId: uid,
            query: sanitizeBoundedString(report.query, GIN_SCHEMA_LIMITS.QUERY_MAX),
            summary: sanitizeBoundedString(report.summary, GIN_SCHEMA_LIMITS.SUMMARY_MAX, 'Completed.'),
            facts: safeFacts,
            predictions: safePredictions,
            confidenceScore: Math.min(100, Math.max(0, Number(report.confidenceScore) || 75)),
            sources: safeSources,
            scheduleCadence,
            createdAt: serverTimestamp(),
          });
        } catch (err) {
          handleFirestoreError(err, OperationType.CREATE, path);
        }

        if (Array.isArray(report.extractedEntities)) {
          setLastExtractedEntities(report.extractedEntities);
        }

        await recordAuditEvent({
          action: 'GIN_RESEARCH_COMPLETED',
          category: 'research',
          severity: 'info',
          summary: `Executed Gemini Search Grounding for "${trimmed.slice(0, 80)}" (${safeSources.length} citations).`,
        });

        return { ok: true };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setResearchError(msg);
        return { ok: false, error: msg };
      } finally {
        setIsResearching(false);
      }
    },
    [firebaseUser, profile.emergencyStop, recordAuditEvent]
  );

  const checkPublicRobots = useCallback(
    async (rawUrl: string) => {
      setRobotsError(null);
      setLastRobotsResult(null);

      const clientCheck = validatePublicCrawlTarget(rawUrl);
      if (!clientCheck.valid) {
        setRobotsError(clientCheck.error || 'Invalid public URL.');
        await recordAuditEvent({
          action: 'ROBOTS_TARGET_BLOCKED',
          category: 'security',
          severity: 'warning',
          summary: `Blocked crawl inspection target "${rawUrl.slice(0, 80)}": ${clientCheck.error}`,
        });
        return;
      }

      if (profile.emergencyStop) {
        setRobotsError('Emergency Stop is active. Release Emergency Stop before inspecting origins.');
        return;
      }

      if (!firebaseUser) {
        setRobotsError(
          `Target ${clientCheck.normalizedOrigin} passed client-side SSRF validation. Sign in with Google to perform live server-side robots.txt inspection.`
        );
        return;
      }

      setIsCheckingRobots(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gin/robots-check', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({
            url: rawUrl,
            emergencyStop: profile.emergencyStop,
          }),
        });
        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          result?: RobotsCheckResult;
        };
        if (!resp.ok || !payload.result) {
          throw new Error(payload.error || `robots.txt check failed (${resp.status}).`);
        }
        setLastRobotsResult(payload.result);
        await recordAuditEvent({
          action: 'ROBOTS_COMPLIANCE_CHECKED',
          category: 'research',
          severity: 'info',
          summary: `Checked ${payload.result.robotsUrl}: ${payload.result.allowedForGinBot ? 'Permitted' : 'Disallowed'}.`,
        });
      } catch (err) {
        setRobotsError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsCheckingRobots(false);
      }
    },
    [firebaseUser, profile.emergencyStop, recordAuditEvent]
  );

  const deleteResearchReport = useCallback(
    async (reportId: string) => {
      if (!firebaseUser) {
        setPreviewReports((prev) => prev.filter((r) => r.id !== reportId));
        return;
      }
      const uid = firebaseUser.uid;
      const path = `users/${uid}/researchReports/${reportId}`;
      try {
        await deleteDoc(doc(db, 'users', uid, 'researchReports', reportId));
        await recordAuditEvent({
          action: 'RESEARCH_REPORT_DELETED',
          category: 'research',
          severity: 'info',
          summary: `Deleted research report ${reportId}.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, path);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const addKnowledgeNode = useCallback(
    async (input: {
      label: string;
      entityType: KnowledgeEntityType;
      claim: string;
      sourceTitle: string;
      sourceUri: string;
      confidenceScore: number;
      relations?: KnowledgeRelation[];
    }) => {
      const label = sanitizeBoundedString(input.label, GIN_SCHEMA_LIMITS.LABEL_MAX);
      const claim = sanitizeBoundedString(input.claim, GIN_SCHEMA_LIMITS.CLAIM_MAX);
      const sourceTitle = sanitizeBoundedString(input.sourceTitle, 160, 'Operator Assertion');
      const rawUri = input.sourceUri.trim();
      if (!label) return { ok: false, error: 'Entity label is required.' };
      if (!claim) return { ok: false, error: 'Entity claim is required.' };
      if (rawUri && !isSafeExternalUrl(rawUri)) {
        return { ok: false, error: 'Source URL must be a safe http:// or https:// address.' };
      }

      const safeUri = rawUri.slice(0, GIN_SCHEMA_LIMITS.URI_MAX);
      const safeConf = Math.min(100, Math.max(0, Math.round(Number(input.confidenceScore) || 80)));
      const safeRelations = (input.relations || []).slice(0, 20);

      if (!firebaseUser) {
        const now = Date.now();
        const node: KnowledgeNodeRecord = {
          id: createSafeId('kn'),
          userId: 'preview_operator',
          label,
          entityType: input.entityType,
          claim,
          sourceTitle,
          sourceUri: safeUri,
          confidenceScore: safeConf,
          relations: safeRelations,
          createdAtMs: now,
          updatedAtMs: now,
        };
        setPreviewNodes((prev) => [node, ...prev]);
        await recordAuditEvent({
          action: 'KNOWLEDGE_NODE_ADDED',
          category: 'knowledge',
          severity: 'info',
          summary: `Added Knowledge Graph entity "${label}" (${input.entityType}, ${safeConf}% confidence).`,
        });
        return { ok: true };
      }

      const uid = firebaseUser.uid;
      const nodeId = createSafeId('kn');
      const path = `users/${uid}/knowledgeNodes/${nodeId}`;
      try {
        await setDoc(doc(db, 'users', uid, 'knowledgeNodes', nodeId), {
          id: nodeId,
          userId: uid,
          label,
          entityType: input.entityType,
          claim,
          sourceTitle,
          sourceUri: safeUri,
          confidenceScore: safeConf,
          relations: safeRelations,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'KNOWLEDGE_NODE_ADDED',
          category: 'knowledge',
          severity: 'info',
          summary: `Committed Knowledge Graph node "${label}" (${input.entityType}) to Cloud Firestore.`,
        });
        return { ok: true };
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, path);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const linkKnowledgeNodes = useCallback(
    async (sourceId: string, targetId: string, predicate: string) => {
      if (sourceId === targetId) {
        return { ok: false, error: 'Select two distinct entities to connect.' };
      }
      const source = knowledgeNodes.find((n) => n.id === sourceId);
      const target = knowledgeNodes.find((n) => n.id === targetId);
      const cleanPred = sanitizeBoundedString(predicate, 48);
      if (!source || !target || !cleanPred) {
        return { ok: false, error: 'Source entity, target entity, and relationship predicate are required.' };
      }
      if (source.relations.length >= 20) {
        return { ok: false, error: 'Entity has reached the 20-relation safety limit.' };
      }

      const nextRelations: KnowledgeRelation[] = [
        ...source.relations.filter((r) => !(r.targetId === targetId && r.predicate === cleanPred)),
        { targetId: target.id, targetLabel: target.label, predicate: cleanPred },
      ];

      if (!firebaseUser) {
        setPreviewNodes((prev) =>
          prev.map((n) =>
            n.id === sourceId ? { ...n, relations: nextRelations, updatedAtMs: Date.now() } : n
          )
        );
        return { ok: true };
      }

      const uid = firebaseUser.uid;
      const path = `users/${uid}/knowledgeNodes/${sourceId}`;
      try {
        await updateDoc(doc(db, 'users', uid, 'knowledgeNodes', sourceId), {
          relations: nextRelations,
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'KNOWLEDGE_EDGE_LINKED',
          category: 'knowledge',
          severity: 'info',
          summary: `Connected "${source.label}" -[${cleanPred}]-> "${target.label}".`,
        });
        return { ok: true };
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, path);
      }
    },
    [knowledgeNodes, firebaseUser, recordAuditEvent]
  );

  const deleteKnowledgeNode = useCallback(
    async (nodeId: string) => {
      if (!firebaseUser) {
        setPreviewNodes((prev) => prev.filter((n) => n.id !== nodeId));
        return;
      }
      const uid = firebaseUser.uid;
      const path = `users/${uid}/knowledgeNodes/${nodeId}`;
      try {
        await deleteDoc(doc(db, 'users', uid, 'knowledgeNodes', nodeId));
        await recordAuditEvent({
          action: 'KNOWLEDGE_NODE_DELETED',
          category: 'knowledge',
          severity: 'info',
          summary: `Removed Knowledge Graph node ${nodeId}.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, path);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const runBehaviourAnalysis = useCallback(async () => {
    setBehaviourError(null);
    if (profile.emergencyStop) {
      setBehaviourError('Emergency Stop is engaged. Release it before running Behaviour Engine analysis.');
      return;
    }

    // Preview mode runs the deterministic local metadata synthesizer honestly (no fake LLM call)
    if (!firebaseUser) {
      const det = synthesizeDeterministicBehaviourInsight(networkAssets);
      const record: BehaviourInsightRecord = {
        id: createSafeId('beh'),
        userId: 'preview_operator',
        ...det,
        createdAtMs: Date.now(),
      };
      setPreviewInsights((prev) => [record, ...prev]);
      await recordAuditEvent({
        action: 'BEHAVIOUR_SYNTHESIS_COMPLETED',
        category: 'behaviour',
        severity: det.severity,
        summary: `Deterministic Behaviour Engine generated "${det.title}" (${det.confidenceScore}% confidence).`,
      });
      return;
    }

    setIsAnalyzingBehaviour(true);
    try {
      const idToken = await firebaseUser.getIdToken();
      const resp = await fetch('/api/gin/telemetry/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify({
          assets: networkAssets.slice(0, 20),
          recentQueries: researchReports.slice(0, 5).map((r) => r.query),
          emergencyStop: profile.emergencyStop,
        }),
      });
      const payload = (await resp.json().catch(() => ({}))) as {
        error?: string;
        insight?: Omit<BehaviourInsightRecord, 'id' | 'userId' | 'createdAtMs'>;
      };
      if (!resp.ok || !payload.insight) {
        throw new Error(payload.error || `Behaviour analysis failed (${resp.status}).`);
      }

      const uid = firebaseUser.uid;
      const insightId = createSafeId('beh');
      const path = `users/${uid}/behaviourInsights/${insightId}`;
      const ins = payload.insight;

      try {
        await setDoc(doc(db, 'users', uid, 'behaviourInsights', insightId), {
          id: insightId,
          userId: uid,
          title: sanitizeBoundedString(ins.title, 180, 'Behaviour Synthesis'),
          domain: ins.domain,
          severity: ins.severity,
          confidenceScore: Math.min(100, Math.max(0, Number(ins.confidenceScore) || 75)),
          facts: ins.facts.slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS),
          predictions: ins.predictions.slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS),
          explanation: sanitizeBoundedString(ins.explanation, GIN_SCHEMA_LIMITS.EXPLANATION_MAX),
          sourceRefs: ins.sourceRefs.slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS),
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, path);
      }

      await recordAuditEvent({
        action: 'BEHAVIOUR_SYNTHESIS_COMPLETED',
        category: 'behaviour',
        severity: ins.severity,
        summary: `Gemini Behaviour Engine produced "${ins.title}" (${ins.confidenceScore}% confidence).`,
      });
    } catch (err) {
      setBehaviourError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsAnalyzingBehaviour(false);
    }
  }, [firebaseUser, networkAssets, researchReports, profile.emergencyStop, recordAuditEvent]);

  const deleteBehaviourInsight = useCallback(
    async (insightId: string) => {
      if (!firebaseUser) {
        setPreviewInsights((prev) => prev.filter((i) => i.id !== insightId));
        return;
      }
      const uid = firebaseUser.uid;
      const path = `users/${uid}/behaviourInsights/${insightId}`;
      try {
        await deleteDoc(doc(db, 'users', uid, 'behaviourInsights', insightId));
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, path);
      }
    },
    [firebaseUser]
  );

  const generateCentralBrainPlan = useCallback(
    async (objective: string) => {
      setBrainPlanError(null);
      const trimmed = objective.trim();
      if (!trimmed || trimmed.length > 400) {
        setBrainPlanError('Enter a planning objective between 1 and 400 characters.');
        return;
      }
      if (profile.emergencyStop) {
        setBrainPlanError('Emergency Stop is engaged. Disengage before planning.');
        return;
      }
      if (!firebaseUser) {
        setBrainPlanError(
          'Live Gemini Central Brain planning requires Google Sign-In. The sample GIN v0.2 plan below illustrates the structured output schema.'
        );
        return;
      }

      setIsPlanningBrain(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gin/brain/plan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({
            objective: trimmed,
            emergencyStop: profile.emergencyStop,
          }),
        });
        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          plan?: BrainResearchPlan;
        };
        if (!resp.ok || !payload.plan) {
          throw new Error(payload.error || `Central Brain planning failed (${resp.status}).`);
        }
        setBrainPlan(payload.plan);
        await recordAuditEvent({
          action: 'CENTRAL_BRAIN_PLAN_GENERATED',
          category: 'research',
          severity: 'info',
          summary: `Generated ${payload.plan.steps.length}-step GIN plan for "${trimmed.slice(0, 75)}".`,
        });
      } catch (err) {
        setBrainPlanError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsPlanningBrain(false);
      }
    },
    [firebaseUser, profile.emergencyStop, recordAuditEvent]
  );

  const value = useMemo<GinIntelligenceContextValue>(
    () => ({
      networkAssets,
      addNetworkAsset,
      ingestAssetTelemetry,
      toggleIsolateAsset,
      deleteNetworkAsset,
      researchReports,
      isResearching,
      researchError,
      clearResearchError,
      lastExtractedEntities,
      lastRobotsResult,
      robotsError,
      isCheckingRobots,
      runGroundedResearch,
      checkPublicRobots,
      deleteResearchReport,
      knowledgeNodes,
      knowledgeConflicts,
      addKnowledgeNode,
      linkKnowledgeNodes,
      deleteKnowledgeNode,
      behaviourInsights,
      isAnalyzingBehaviour,
      behaviourError,
      runBehaviourAnalysis,
      deleteBehaviourInsight,
      brainPlan,
      isPlanningBrain,
      brainPlanError,
      generateCentralBrainPlan,
    }),
    [
      networkAssets,
      addNetworkAsset,
      ingestAssetTelemetry,
      toggleIsolateAsset,
      deleteNetworkAsset,
      researchReports,
      isResearching,
      researchError,
      clearResearchError,
      lastExtractedEntities,
      lastRobotsResult,
      robotsError,
      isCheckingRobots,
      runGroundedResearch,
      checkPublicRobots,
      deleteResearchReport,
      knowledgeNodes,
      knowledgeConflicts,
      addKnowledgeNode,
      linkKnowledgeNodes,
      deleteKnowledgeNode,
      behaviourInsights,
      isAnalyzingBehaviour,
      behaviourError,
      runBehaviourAnalysis,
      deleteBehaviourInsight,
      brainPlan,
      isPlanningBrain,
      brainPlanError,
      generateCentralBrainPlan,
    ]
  );

  return (
    <GinIntelligenceContext.Provider value={value}>{children}</GinIntelligenceContext.Provider>
  );
}

export function useGinIntelligence(): GinIntelligenceContextValue {
  const ctx = useContext(GinIntelligenceContext);
  if (!ctx) {
    throw new Error('useGinIntelligence must be used inside GinIntelligenceProvider.');
  }
  return ctx;
}
