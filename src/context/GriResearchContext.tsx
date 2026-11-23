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
import { useGinIntelligence } from './GinIntelligenceContext';
import { validatePublicCrawlTarget } from '../shared/ginAnalytics';
import {
  GRI_SCHEMA_LIMITS,
  validateResearchMonitorInput,
} from '../shared/griAnalytics';
import type {
  CveAdvisoryRecord,
  FrontendInspectionResult,
  MonitorCadence,
  MonitorSourcePolicy,
  MonitorType,
  ResearchMonitorRecord,
  ServerIntelResult,
  SourceComparisonReport,
  TechAnalysisCategory,
  TechAnalysisRecord,
} from '../shared/griTypes';
import type { ResearchSourceCitation } from '../shared/ginTypes';
import { createSafeId, sanitizeBoundedString } from '../shared/validation';

interface GriResearchContextValue {
  techAnalyses: TechAnalysisRecord[];
  isAnalyzingWebsite: boolean;
  websiteError: string | null;
  lastFrontendResult: FrontendInspectionResult | null;
  analyzeWebsite: (url: string) => Promise<{ ok: boolean; error?: string }>;

  isResearchingBackend: boolean;
  backendError: string | null;
  researchBackend: (topic: string) => Promise<{ ok: boolean; error?: string }>;

  isAnalyzingServer: boolean;
  serverError: string | null;
  lastServerResult: ServerIntelResult | null;
  analyzeServer: (hostname: string) => Promise<{ ok: boolean; error?: string }>;
  deleteTechAnalysis: (analysisId: string) => Promise<void>;

  cveAdvisories: CveAdvisoryRecord[];
  isSearchingCves: boolean;
  cveError: string | null;
  lastCveSourcesChecked: string[];
  searchCves: (queryText: string) => Promise<{ ok: boolean; error?: string }>;
  deleteCveAdvisory: (advisoryId: string) => Promise<void>;

  researchMonitors: ResearchMonitorRecord[];
  runningMonitorId: string | null;
  monitorMessage: string | null;
  addMonitor: (input: {
    name: string;
    target: string;
    monitorType: MonitorType;
    cadence: MonitorCadence;
    rateLimitPerHour: number;
    sourcePolicy: MonitorSourcePolicy;
  }) => Promise<{ ok: boolean; error?: string }>;
  toggleMonitorEnabled: (monitorId: string) => Promise<void>;
  runMonitorNow: (monitorId: string) => Promise<void>;
  deleteMonitor: (monitorId: string) => Promise<void>;

  comparisonReport: SourceComparisonReport | null;
  isComparingSources: boolean;
  comparisonError: string | null;
  generateComparisonReport: (topic: string) => Promise<void>;
}

const GriResearchContext = createContext<GriResearchContextValue | null>(null);

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

const GRI_SEED_NOW = 1795380000000;

function createPreviewGriSeed() {
  const techAnalyses: TechAnalysisRecord[] = [
    {
      id: 'ta_frontend_react_docs',
      userId: 'preview_operator',
      target: 'https://react.dev',
      category: 'frontend',
      title: 'Frontend Stack Fingerprint: react.dev',
      summary:
        'Public HTML and response header inspection indicates a Next.js / React documentation portal served behind Vercel Edge Network with Tailwind CSS utility styling. Strict Transport Security (HSTS) and X-Content-Type-Options are enforced on public document routes, with static assets served from first-party edge chunks.',
      detectedTechnologies: ['Next.js', 'React', 'Tailwind CSS'],
      securityHeaders: [
        'HSTS (Strict-Transport-Security): max-age=63072000; includeSubDomains',
        'X-Content-Type-Options: nosniff',
        'Referrer-Policy: strict-origin-when-cross-origin',
      ],
      dnsSummary: [],
      certSummary: [],
      sources: [
        {
          title: 'react.dev Public HTML & HTTP Headers',
          uri: 'https://react.dev',
          domain: 'react.dev',
        },
      ],
      confidenceScore: 92,
      createdAtMs: GRI_SEED_NOW - 2_400_000,
    },
    {
      id: 'ta_backend_cloudflare_workers',
      userId: 'preview_operator',
      target: 'Cloudflare Workers & V8 Isolates Architecture',
      category: 'backend',
      title: 'Backend Architecture: Cloudflare Workers & Edge Runtime',
      summary:
        '## Architecture Overview\n\nCloudflare Workers execute JavaScript, TypeScript, and WebAssembly workloads inside V8 Isolates rather than traditional Linux containers, minimizing cold-start overhead across global Points of Presence. Public API documentation highlights WinterCG-aligned Fetch APIs, Durable Objects for strongly consistent state, and D1/R2 storage bindings.\n\n## Public API & Defensive Design Notes\n- Enforces per-request CPU time limits and strict isolate memory boundaries.\n- Recommends signed JWT verification and per-tenant rate limiting at the edge layer.',
      detectedTechnologies: [
        'V8 Isolates',
        'WinterCG Fetch API',
        'Durable Objects',
        'WebAssembly (Wasm)',
        'HTTP/3 QUIC',
      ],
      securityHeaders: [],
      dnsSummary: [],
      certSummary: [],
      sources: [
        {
          title: 'Cloudflare Workers Public Architecture Docs',
          uri: 'https://developers.cloudflare.com/workers/reference/how-workers-works/',
          domain: 'developers.cloudflare.com',
        },
      ],
      confidenceScore: 90,
      createdAtMs: GRI_SEED_NOW - 5_100_000,
    },
    {
      id: 'ta_server_rfc_editor',
      userId: 'preview_operator',
      target: 'rfc-editor.org',
      category: 'server',
      title: 'Server & DNS Intelligence: rfc-editor.org',
      summary:
        'Public DNS and Certificate Transparency analysis for rfc-editor.org reveals dual-stack IPv4/IPv6 hosting backed by Cloudflare edge infrastructure, explicit CAA certificate pinning, and SPF mail protection. No restricted administration endpoints were queried; all observations originate from public DNS and CT logs.',
      detectedTechnologies: [
        'Cloudflare DNS / Edge',
        'IPv6 Dual-Stack Enabled',
        'CAA Certificate Pinning Configured',
        "TLS CA: Let's Encrypt",
      ],
      securityHeaders: [],
      dnsSummary: [
        'A: 104.18.18.188',
        'AAAA: 2606:4700::6812:12bc',
        'NS: ns1.ietf.org',
        'TXT: v=spf1 include:_spf.ietf.org ~all',
        'CAA: 0 issue "letsencrypt.org"',
      ],
      certSummary: [
        "CN=www.rfc-editor.org · Issuer: Let's Encrypt E5 (Valid 2026-09-14 to 2026-12-13)",
        'CN=rfc-editor.org · Issuer: Google Trust Services WE1 (Valid 2026-10-01 to 2026-12-30)',
      ],
      sources: [
        {
          title: 'crt.sh Certificate Transparency Public Log',
          uri: 'https://crt.sh/?q=rfc-editor.org',
          domain: 'crt.sh',
        },
      ],
      confidenceScore: 91,
      createdAtMs: GRI_SEED_NOW - 4_200_000,
    },
  ];

  const cveAdvisories: CveAdvisoryRecord[] = [
    {
      id: 'cve_2024_3094',
      userId: 'preview_operator',
      cveId: 'CVE-2024-3094',
      title: 'XZ Utils Backdoor in Upstream Tarballs (liblzma)',
      vendorProduct: 'Tukaani — XZ Utils 5.6.0 / 5.6.1',
      severity: 'critical',
      cvssScore: 10.0,
      cisaKev: false,
      owaspCategory: 'A08:2021 — Software & Data Integrity Failures',
      affectedVersions: 'xz-utils 5.6.0 and 5.6.1 (downstream Linux distributions packaging these builds)',
      mitigation:
        'Downgrade immediately to verified xz-utils 5.4.x or clean upstream 5.6.2+ builds. Enforce SBOM verification, reproducible build checks, and cryptographic maintainer signing audits.',
      sourceUri: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094',
      publishedDate: '2024-03-29',
      createdAtMs: GRI_SEED_NOW - 9_000_000,
    },
    {
      id: 'cve_2024_21626',
      userId: 'preview_operator',
      cveId: 'CVE-2024-21626',
      title: 'runc Container Breakout via Leaked File Descriptor',
      vendorProduct: 'Open Containers — runc',
      severity: 'high',
      cvssScore: 8.6,
      cisaKev: true,
      owaspCategory: 'A01:2021 — Broken Access Control',
      affectedVersions: 'runc >= 1.0.0-rc93 and <= 1.1.11',
      mitigation:
        'Upgrade container runtime hosts to runc >= 1.1.12 (or patched Docker / containerd / Kubernetes node images). Enforce seccomp profiles, rootless containers, and read-only root filesystems.',
      sourceUri: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21626',
      publishedDate: '2024-01-31',
      createdAtMs: GRI_SEED_NOW - 6_500_000,
    },
    {
      id: 'cve_2024_6387',
      userId: 'preview_operator',
      cveId: 'CVE-2024-6387',
      title: 'OpenSSH Server Signal Handler Race Condition (regreSSHion)',
      vendorProduct: 'OpenBSD — OpenSSH sshd (glibc-based Linux)',
      severity: 'high',
      cvssScore: 8.1,
      cisaKev: false,
      owaspCategory: 'A06:2021 — Vulnerable & Outdated Components',
      affectedVersions: 'OpenSSH 8.5p1 through 9.7p1 on glibc Linux systems',
      mitigation:
        'Upgrade OpenSSH to 9.8p1 or distribution backport. Restrict SSH access via bastion/VPN allowlists, disable direct internet exposure of port 22, or temporarily set LoginGraceTime 0 as documented by vendor advisories.',
      sourceUri: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
      publishedDate: '2024-07-01',
      createdAtMs: GRI_SEED_NOW - 3_200_000,
    },
  ];

  const researchMonitors: ResearchMonitorRecord[] = [
    {
      id: 'mon_cisa_kev_containers',
      userId: 'preview_operator',
      name: 'Container Runtime & Kubernetes Advisories',
      target: 'kubernetes',
      monitorType: 'cve_advisory',
      cadence: 'daily',
      rateLimitPerHour: 4,
      sourcePolicy: 'official_advisories_only',
      enabled: true,
      lastRunSummary: 'Verified 2 public advisories across CISA KEV & NVD CVE 2.0.',
      lastRunAtMs: GRI_SEED_NOW - 3_600_000,
      createdAtMs: GRI_SEED_NOW - 86_400_000,
      updatedAtMs: GRI_SEED_NOW - 3_600_000,
    },
    {
      id: 'mon_rfc_server_dns',
      userId: 'preview_operator',
      name: 'RFC Editor Public DNS & TLS Watch',
      target: 'rfc-editor.org',
      monitorType: 'server_dns',
      cadence: 'weekly',
      rateLimitPerHour: 2,
      sourcePolicy: 'respect_robots_strict',
      enabled: true,
      lastRunSummary: 'Resolved public DNS A/AAAA/NS/CAA records and CT issuers.',
      lastRunAtMs: GRI_SEED_NOW - 14_400_000,
      createdAtMs: GRI_SEED_NOW - 172_800_000,
      updatedAtMs: GRI_SEED_NOW - 14_400_000,
    },
    {
      id: 'mon_web_docs_edge',
      userId: 'preview_operator',
      name: 'Edge Web Runtime & HTTP/3 Releases',
      target: 'Cloudflare Workers HTTP/3 WinterCG architecture updates',
      monitorType: 'web_topic',
      cadence: 'weekly',
      rateLimitPerHour: 3,
      sourcePolicy: 'public_docs_only',
      enabled: false,
      lastRunSummary: 'Monitor paused by operator.',
      lastRunAtMs: GRI_SEED_NOW - 43_200_000,
      createdAtMs: GRI_SEED_NOW - 259_200_000,
      updatedAtMs: GRI_SEED_NOW - 43_200_000,
    },
  ];

  return { techAnalyses, cveAdvisories, researchMonitors };
}

export function GriResearchProvider({ children }: { children: React.ReactNode }) {
  const { firebaseUser, bootstrapReadyUid, profile, recordAuditEvent } = useGodWorkspace();
  const { researchReports, runGroundedResearch } = useGinIntelligence();

  const seed = useMemo(() => createPreviewGriSeed(), []);
  const [previewTech, setPreviewTech] = useState<TechAnalysisRecord[]>(seed.techAnalyses);
  const [previewCves, setPreviewCves] = useState<CveAdvisoryRecord[]>(seed.cveAdvisories);
  const [previewMonitors, setPreviewMonitors] = useState<ResearchMonitorRecord[]>(
    seed.researchMonitors
  );

  const [cloudTech, setCloudTech] = useState<TechAnalysisRecord[]>([]);
  const [cloudCves, setCloudCves] = useState<CveAdvisoryRecord[]>([]);
  const [cloudMonitors, setCloudMonitors] = useState<ResearchMonitorRecord[]>([]);

  const [isAnalyzingWebsite, setIsAnalyzingWebsite] = useState(false);
  const [websiteError, setWebsiteError] = useState<string | null>(null);
  const [lastFrontendResult, setLastFrontendResult] = useState<FrontendInspectionResult | null>(
    null
  );

  const [isResearchingBackend, setIsResearchingBackend] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);

  const [isAnalyzingServer, setIsAnalyzingServer] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const [lastServerResult, setLastServerResult] = useState<ServerIntelResult | null>(null);

  const [isSearchingCves, setIsSearchingCves] = useState(false);
  const [cveError, setCveError] = useState<string | null>(null);
  const [lastCveSourcesChecked, setLastCveSourcesChecked] = useState<string[]>([
    'CISA KEV Live Catalog',
    'NVD CVE 2.0 Public API',
  ]);

  const [runningMonitorId, setRunningMonitorId] = useState<string | null>(null);
  const [monitorMessage, setMonitorMessage] = useState<string | null>(null);

  const [comparisonReport, setComparisonReport] = useState<SourceComparisonReport | null>(null);
  const [isComparingSources, setIsComparingSources] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);

  // Real-time Firestore listeners for GRI v0.5 collections
  useEffect(() => {
    if (!firebaseUser || bootstrapReadyUid !== firebaseUser.uid) {
      setCloudTech([]);
      setCloudCves([]);
      setCloudMonitors([]);
      return;
    }

    const uid = firebaseUser.uid;
    const unsubs: Array<() => void> = [];

    const techPath = `users/${uid}/techAnalyses`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'techAnalyses'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: TechAnalysisRecord[] = snap.docs.map((dSnap) => {
            const d = dSnap.data();
            return {
              id: dSnap.id,
              userId: String(d.userId),
              target: String(d.target || ''),
              category:
                d.category === 'backend' || d.category === 'server'
                  ? (d.category as TechAnalysisCategory)
                  : 'frontend',
              title: String(d.title || ''),
              summary: String(d.summary || ''),
              detectedTechnologies: Array.isArray(d.detectedTechnologies)
                ? d.detectedTechnologies.map(String)
                : [],
              securityHeaders: Array.isArray(d.securityHeaders)
                ? d.securityHeaders.map(String)
                : [],
              dnsSummary: Array.isArray(d.dnsSummary) ? d.dnsSummary.map(String) : [],
              certSummary: Array.isArray(d.certSummary) ? d.certSummary.map(String) : [],
              sources: Array.isArray(d.sources) ? (d.sources as ResearchSourceCitation[]) : [],
              confidenceScore: Number(d.confidenceScore || 0),
              createdAtMs: tsToMillis(d.createdAt, now),
            };
          });
          items.sort((a, b) => b.createdAtMs - a.createdAtMs);
          setCloudTech(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, techPath)
      )
    );

    const cvePath = `users/${uid}/cveAdvisories`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'cveAdvisories'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: CveAdvisoryRecord[] = snap.docs.map((dSnap) => {
            const d = dSnap.data();
            return {
              id: dSnap.id,
              userId: String(d.userId),
              cveId: String(d.cveId || ''),
              title: String(d.title || ''),
              vendorProduct: String(d.vendorProduct || ''),
              severity: (d.severity as CveAdvisoryRecord['severity']) || 'unknown',
              cvssScore: Number(d.cvssScore || 0),
              cisaKev: Boolean(d.cisaKev),
              owaspCategory: String(d.owaspCategory || ''),
              affectedVersions: String(d.affectedVersions || ''),
              mitigation: String(d.mitigation || ''),
              sourceUri: String(d.sourceUri || ''),
              publishedDate: String(d.publishedDate || ''),
              createdAtMs: tsToMillis(d.createdAt, now),
            };
          });
          items.sort((a, b) => b.cvssScore - a.cvssScore || b.createdAtMs - a.createdAtMs);
          setCloudCves(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, cvePath)
      )
    );

    const monPath = `users/${uid}/researchMonitors`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'researchMonitors'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: ResearchMonitorRecord[] = snap.docs.map((dSnap) => {
            const d = dSnap.data();
            return {
              id: dSnap.id,
              userId: String(d.userId),
              name: String(d.name || ''),
              target: String(d.target || ''),
              monitorType: (d.monitorType as MonitorType) || 'web_topic',
              cadence: (d.cadence as MonitorCadence) || 'daily',
              rateLimitPerHour: Number(d.rateLimitPerHour || 2),
              sourcePolicy: (d.sourcePolicy as MonitorSourcePolicy) || 'respect_robots_strict',
              enabled: Boolean(d.enabled),
              lastRunSummary: String(d.lastRunSummary || ''),
              lastRunAtMs: Number(d.lastRunAtMs || 0),
              createdAtMs: tsToMillis(d.createdAt, now),
              updatedAtMs: tsToMillis(d.updatedAt, now),
            };
          });
          items.sort((a, b) => b.updatedAtMs - a.updatedAtMs);
          setCloudMonitors(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, monPath)
      )
    );

    return () => {
      for (const u of unsubs) u();
    };
  }, [firebaseUser, bootstrapReadyUid]);

  const techAnalyses = firebaseUser ? cloudTech : previewTech;
  const cveAdvisories = firebaseUser ? cloudCves : previewCves;
  const researchMonitors = firebaseUser ? cloudMonitors : previewMonitors;

  const persistTechAnalysis = useCallback(
    async (draft: Omit<TechAnalysisRecord, 'id' | 'userId' | 'createdAtMs'>) => {
      if (!firebaseUser) {
        const record: TechAnalysisRecord = {
          ...draft,
          id: createSafeId('ta'),
          userId: 'preview_operator',
          createdAtMs: Date.now(),
        };
        setPreviewTech((prev) => [record, ...prev]);
        return;
      }

      const uid = firebaseUser.uid;
      const analysisId = createSafeId('ta');
      const docPath = `users/${uid}/techAnalyses/${analysisId}`;
      try {
        await setDoc(doc(db, 'users', uid, 'techAnalyses', analysisId), {
          id: analysisId,
          userId: uid,
          target: sanitizeBoundedString(draft.target, GRI_SCHEMA_LIMITS.TARGET_MAX),
          category: draft.category,
          title: sanitizeBoundedString(draft.title, GRI_SCHEMA_LIMITS.TITLE_MAX),
          summary: sanitizeBoundedString(draft.summary, GRI_SCHEMA_LIMITS.SUMMARY_MAX, 'Completed.'),
          detectedTechnologies: draft.detectedTechnologies
            .slice(0, GRI_SCHEMA_LIMITS.TECH_LIST_MAX)
            .map((t) => sanitizeBoundedString(t, 120)),
          securityHeaders: draft.securityHeaders
            .slice(0, GRI_SCHEMA_LIMITS.HEADER_LIST_MAX)
            .map((h) => sanitizeBoundedString(h, 160)),
          dnsSummary: draft.dnsSummary
            .slice(0, GRI_SCHEMA_LIMITS.DNS_LIST_MAX)
            .map((r) => sanitizeBoundedString(r, 180)),
          certSummary: draft.certSummary
            .slice(0, GRI_SCHEMA_LIMITS.CERT_LIST_MAX)
            .map((c) => sanitizeBoundedString(c, 200)),
          sources: draft.sources.slice(0, 15).map((s) => ({
            title: sanitizeBoundedString(s.title, 140, 'Public Source'),
            uri: sanitizeBoundedString(s.uri, 1024),
            domain: sanitizeBoundedString(s.domain, 120, 'web'),
          })),
          confidenceScore: Math.min(100, Math.max(0, Number(draft.confidenceScore) || 80)),
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, docPath);
      }
    },
    [firebaseUser]
  );

  const analyzeWebsite = useCallback(
    async (rawUrl: string) => {
      setWebsiteError(null);
      setLastFrontendResult(null);

      const urlCheck = validatePublicCrawlTarget(rawUrl);
      if (!urlCheck.valid) {
        const err = urlCheck.error || 'Enter a valid public HTTPS website URL.';
        setWebsiteError(err);
        await recordAuditEvent({
          action: 'WEBSITE_ANALYSIS_BLOCKED',
          category: 'security',
          severity: 'warning',
          summary: `Blocked website target "${rawUrl.slice(0, 80)}": ${err}`,
        });
        return { ok: false, error: err };
      }

      if (profile.emergencyStop) {
        const err = 'Emergency Stop is active. Release Emergency Stop before inspecting public websites.';
        setWebsiteError(err);
        return { ok: false, error: err };
      }

      if (!firebaseUser) {
        const err = `Target ${urlCheck.normalizedOrigin} passed public network safety checks. Sign in with Google to run live server-side HTML/header fingerprinting and save results to Cloud Firestore.`;
        setWebsiteError(err);
        return { ok: false, error: err };
      }

      setIsAnalyzingWebsite(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gri/analyze-website', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({ url: rawUrl, emergencyStop: profile.emergencyStop }),
        });
        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          result?: FrontendInspectionResult;
        };
        if (!resp.ok || !payload.result) {
          throw new Error(payload.error || `Website analysis failed (${resp.status}).`);
        }

        const res = payload.result;
        setLastFrontendResult(res);

        await persistTechAnalysis({
          target: res.origin,
          category: 'frontend',
          title: `Frontend Stack Fingerprint: ${new URL(res.origin).hostname}`,
          summary: res.architectureSummary,
          detectedTechnologies: [...res.detectedTechnologies, ...res.backendIndicators].slice(
            0,
            GRI_SCHEMA_LIMITS.TECH_LIST_MAX
          ),
          securityHeaders: res.securityHeaders,
          dnsSummary: [],
          certSummary: [],
          sources: [
            {
              title: `${res.pageTitle} (Public HTML & Headers)`,
              uri: res.origin,
              domain: new URL(res.origin).hostname,
            },
          ],
          confidenceScore: res.confidenceScore,
        });

        await recordAuditEvent({
          action: 'GRI_FRONTEND_ANALYZED',
          category: 'research',
          severity: 'info',
          summary: `Analyzed public frontend/headers for ${res.origin} (${res.detectedTechnologies.length} frontend, ${res.backendIndicators.length} header indicators).`,
        });

        return { ok: true };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setWebsiteError(msg);
        return { ok: false, error: msg };
      } finally {
        setIsAnalyzingWebsite(false);
      }
    },
    [firebaseUser, profile.emergencyStop, persistTechAnalysis, recordAuditEvent]
  );

  const researchBackend = useCallback(
    async (rawTopic: string) => {
      setBackendError(null);
      const topic = rawTopic.trim();
      if (!topic || topic.length > GRI_SCHEMA_LIMITS.TARGET_MAX) {
        const err = 'Enter a backend framework, public API, or server technology topic (1–240 chars).';
        setBackendError(err);
        return { ok: false, error: err };
      }
      if (profile.emergencyStop) {
        const err = 'Emergency Stop is active.';
        setBackendError(err);
        return { ok: false, error: err };
      }
      if (!firebaseUser) {
        const err =
          'Sign in with Google to run live Gemini Search Grounding for public backend architecture and API documentation.';
        setBackendError(err);
        return { ok: false, error: err };
      }

      setIsResearchingBackend(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gri/backend-research', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({ topic, emergencyStop: profile.emergencyStop }),
        });
        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          result?: {
            target: string;
            title: string;
            summary: string;
            detectedTechnologies: string[];
            sources: ResearchSourceCitation[];
            confidenceScore: number;
          };
        };
        if (!resp.ok || !payload.result) {
          throw new Error(payload.error || `Backend research failed (${resp.status}).`);
        }

        await persistTechAnalysis({
          target: payload.result.target,
          category: 'backend',
          title: payload.result.title,
          summary: payload.result.summary,
          detectedTechnologies: payload.result.detectedTechnologies,
          securityHeaders: [],
          dnsSummary: [],
          certSummary: [],
          sources: payload.result.sources,
          confidenceScore: payload.result.confidenceScore,
        });

        await recordAuditEvent({
          action: 'GRI_BACKEND_RESEARCHED',
          category: 'research',
          severity: 'info',
          summary: `Completed public backend documentation research for "${topic.slice(0, 80)}".`,
        });

        return { ok: true };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setBackendError(msg);
        return { ok: false, error: msg };
      } finally {
        setIsResearchingBackend(false);
      }
    },
    [firebaseUser, profile.emergencyStop, persistTechAnalysis, recordAuditEvent]
  );

  const analyzeServer = useCallback(
    async (rawHostname: string) => {
      setServerError(null);
      setLastServerResult(null);

      const hostCheck = validatePublicCrawlTarget(rawHostname);
      if (!hostCheck.valid || !hostCheck.hostname) {
        const err = hostCheck.error || 'Enter a valid public domain name (e.g., cloudflare.com).';
        setServerError(err);
        await recordAuditEvent({
          action: 'SERVER_ANALYSIS_BLOCKED',
          category: 'security',
          severity: 'warning',
          summary: `Blocked server DNS/CT target "${rawHostname.slice(0, 80)}": ${err}`,
        });
        return { ok: false, error: err };
      }

      if (profile.emergencyStop) {
        const err = 'Emergency Stop is active.';
        setServerError(err);
        return { ok: false, error: err };
      }

      if (!firebaseUser) {
        const err = `Domain ${hostCheck.hostname} passed public DNS safety validation. Sign in with Google to run live server-side DNS & Certificate Transparency lookups.`;
        setServerError(err);
        return { ok: false, error: err };
      }

      setIsAnalyzingServer(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gri/analyze-server', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({ hostname: rawHostname, emergencyStop: profile.emergencyStop }),
        });
        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          result?: ServerIntelResult;
        };
        if (!resp.ok || !payload.result) {
          throw new Error(payload.error || `Server intelligence query failed (${resp.status}).`);
        }

        const res = payload.result;
        setLastServerResult(res);

        const dnsSummary = [
          ...res.aRecords.slice(0, 4).map((ip) => `A: ${ip}`),
          ...res.aaaaRecords.slice(0, 2).map((ip) => `AAAA: ${ip}`),
          ...res.nsRecords.slice(0, 4).map((ns) => `NS: ${ns}`),
          ...res.mxRecords.slice(0, 3).map((mx) => `MX: ${mx}`),
          ...res.caaRecords.slice(0, 3).map((caa) => `CAA: ${caa}`),
          ...res.txtRecords.slice(0, 4).map((txt) => `TXT: ${txt}`),
        ].slice(0, GRI_SCHEMA_LIMITS.DNS_LIST_MAX);

        const certSummary = res.certEntries
          .slice(0, 8)
          .map(
            (c) =>
              `CN=${c.commonName} · Issuer: ${c.issuerName} (${c.notBefore} to ${c.notAfter})`
          );

        await persistTechAnalysis({
          target: res.hostname,
          category: 'server',
          title: `Server & DNS Intelligence: ${res.hostname}`,
          summary: res.architectureSummary,
          detectedTechnologies: [...res.inferredInfrastructure, ...res.emailPosture].slice(
            0,
            GRI_SCHEMA_LIMITS.TECH_LIST_MAX
          ),
          securityHeaders: [],
          dnsSummary,
          certSummary,
          sources: [
            {
              title: `crt.sh Public CT Log (${res.hostname})`,
              uri: `https://crt.sh/?q=${encodeURIComponent(res.hostname)}`,
              domain: 'crt.sh',
            },
          ],
          confidenceScore: res.confidenceScore,
        });

        await recordAuditEvent({
          action: 'GRI_SERVER_ANALYZED',
          category: 'research',
          severity: 'info',
          summary: `Inspected public DNS & Certificate Transparency records for ${res.hostname}.`,
        });

        return { ok: true };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setServerError(msg);
        return { ok: false, error: msg };
      } finally {
        setIsAnalyzingServer(false);
      }
    },
    [firebaseUser, profile.emergencyStop, persistTechAnalysis, recordAuditEvent]
  );

  const deleteTechAnalysis = useCallback(
    async (analysisId: string) => {
      if (!firebaseUser) {
        setPreviewTech((prev) => prev.filter((item) => item.id !== analysisId));
        return;
      }
      const uid = firebaseUser.uid;
      try {
        await deleteDoc(doc(db, 'users', uid, 'techAnalyses', analysisId));
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, `users/${uid}/techAnalyses/${analysisId}`);
      }
    },
    [firebaseUser]
  );

  const searchCves = useCallback(
    async (rawQuery: string) => {
      setCveError(null);
      const q = rawQuery.trim();
      if (!q || q.length > 160) {
        const err = 'Enter a CVE ID (e.g., CVE-2024-3094), vendor, or software name.';
        setCveError(err);
        return { ok: false, error: err };
      }
      if (profile.emergencyStop) {
        const err = 'Emergency Stop is active.';
        setCveError(err);
        return { ok: false, error: err };
      }
      if (!firebaseUser) {
        const err =
          'Sign in with Google to query live CISA KEV and NVD CVE 2.0 public feeds and persist advisories to Cloud Firestore.';
        setCveError(err);
        return { ok: false, error: err };
      }

      setIsSearchingCves(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gri/cve-search', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({ query: q, emergencyStop: profile.emergencyStop }),
        });
        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          advisories?: Array<Omit<CveAdvisoryRecord, 'id' | 'userId' | 'createdAtMs'>>;
          sourcesChecked?: string[];
        };
        if (!resp.ok || !Array.isArray(payload.advisories)) {
          throw new Error(payload.error || `CVE intelligence query failed (${resp.status}).`);
        }

        if (Array.isArray(payload.sourcesChecked)) {
          setLastCveSourcesChecked(payload.sourcesChecked);
        }

        if (payload.advisories.length === 0) {
          setCveError(`No public CVE or CISA KEV advisories matched "${q}". Try another vendor or CVE ID.`);
          return { ok: false, error: 'No advisories matched.' };
        }

        const uid = firebaseUser.uid;
        for (const adv of payload.advisories.slice(0, 6)) {
          const docId = createSafeId('cve');
          const path = `users/${uid}/cveAdvisories/${docId}`;
          try {
            await setDoc(doc(db, 'users', uid, 'cveAdvisories', docId), {
              id: docId,
              userId: uid,
              cveId: sanitizeBoundedString(adv.cveId, GRI_SCHEMA_LIMITS.CVE_ID_MAX, 'CVE-UNKNOWN'),
              title: sanitizeBoundedString(adv.title, GRI_SCHEMA_LIMITS.CVE_TITLE_MAX, 'Advisory'),
              vendorProduct: sanitizeBoundedString(
                adv.vendorProduct,
                GRI_SCHEMA_LIMITS.VENDOR_PRODUCT_MAX,
                q
              ),
              severity: adv.severity,
              cvssScore: Math.min(10, Math.max(0, Number(adv.cvssScore) || 0)),
              cisaKev: Boolean(adv.cisaKev),
              owaspCategory: sanitizeBoundedString(
                adv.owaspCategory,
                GRI_SCHEMA_LIMITS.OWASP_MAX,
                'A06:2021 — Vulnerable & Outdated Components'
              ),
              affectedVersions: sanitizeBoundedString(
                adv.affectedVersions,
                GRI_SCHEMA_LIMITS.AFFECTED_VERSIONS_MAX,
                'See advisory'
              ),
              mitigation: sanitizeBoundedString(
                adv.mitigation,
                GRI_SCHEMA_LIMITS.MITIGATION_MAX,
                'Apply vendor security updates.'
              ),
              sourceUri: sanitizeBoundedString(adv.sourceUri, 1024),
              publishedDate: sanitizeBoundedString(
                adv.publishedDate,
                GRI_SCHEMA_LIMITS.PUBLISHED_DATE_MAX,
                'unknown'
              ),
              createdAt: serverTimestamp(),
            });
          } catch (err) {
            handleFirestoreError(err, OperationType.CREATE, path);
          }
        }

        await recordAuditEvent({
          action: 'GRI_CVE_INGESTED',
          category: 'security',
          severity: 'info',
          summary: `Ingested ${payload.advisories.length} public CVE/KEV advisory record(s) for "${q.slice(0, 60)}".`,
        });

        return { ok: true };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setCveError(msg);
        return { ok: false, error: msg };
      } finally {
        setIsSearchingCves(false);
      }
    },
    [firebaseUser, profile.emergencyStop, recordAuditEvent]
  );

  const deleteCveAdvisory = useCallback(
    async (advisoryId: string) => {
      if (!firebaseUser) {
        setPreviewCves((prev) => prev.filter((item) => item.id !== advisoryId));
        return;
      }
      const uid = firebaseUser.uid;
      try {
        await deleteDoc(doc(db, 'users', uid, 'cveAdvisories', advisoryId));
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, `users/${uid}/cveAdvisories/${advisoryId}`);
      }
    },
    [firebaseUser]
  );

  const addMonitor = useCallback(
    async (input: {
      name: string;
      target: string;
      monitorType: MonitorType;
      cadence: MonitorCadence;
      rateLimitPerHour: number;
      sourcePolicy: MonitorSourcePolicy;
    }) => {
      const check = validateResearchMonitorInput(input);
      if (!check.valid) {
        return { ok: false, error: check.error };
      }

      const name = sanitizeBoundedString(input.name, GRI_SCHEMA_LIMITS.MONITOR_NAME_MAX);
      const target = sanitizeBoundedString(input.target, GRI_SCHEMA_LIMITS.TARGET_MAX);

      if (!firebaseUser) {
        const now = Date.now();
        const record: ResearchMonitorRecord = {
          id: createSafeId('mon'),
          userId: 'preview_operator',
          name,
          target,
          monitorType: input.monitorType,
          cadence: input.cadence,
          rateLimitPerHour: input.rateLimitPerHour,
          sourcePolicy: input.sourcePolicy,
          enabled: true,
          lastRunSummary: 'Configured — click Run Now to execute discovery.',
          lastRunAtMs: 0,
          createdAtMs: now,
          updatedAtMs: now,
        };
        setPreviewMonitors((prev) => [record, ...prev]);
        await recordAuditEvent({
          action: 'CONTINUOUS_MONITOR_CREATED',
          category: 'research',
          severity: 'info',
          summary: `Created ${input.cadence} ${input.monitorType} monitor "${name}" (${input.rateLimitPerHour} req/hr).`,
        });
        return { ok: true };
      }

      const uid = firebaseUser.uid;
      const monId = createSafeId('mon');
      const path = `users/${uid}/researchMonitors/${monId}`;
      try {
        await setDoc(doc(db, 'users', uid, 'researchMonitors', monId), {
          id: monId,
          userId: uid,
          name,
          target,
          monitorType: input.monitorType,
          cadence: input.cadence,
          rateLimitPerHour: input.rateLimitPerHour,
          sourcePolicy: input.sourcePolicy,
          enabled: true,
          lastRunSummary: 'Configured — ready for on-demand discovery run.',
          lastRunAtMs: 0,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'CONTINUOUS_MONITOR_CREATED',
          category: 'research',
          severity: 'info',
          summary: `Created discovery monitor "${name}" (${input.cadence}, max ${input.rateLimitPerHour} req/hr).`,
        });
        return { ok: true };
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, path);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const toggleMonitorEnabled = useCallback(
    async (monitorId: string) => {
      const target = researchMonitors.find((m) => m.id === monitorId);
      if (!target) return;
      const nextEnabled = !target.enabled;

      if (!firebaseUser) {
        setPreviewMonitors((prev) =>
          prev.map((m) =>
            m.id === monitorId ? { ...m, enabled: nextEnabled, updatedAtMs: Date.now() } : m
          )
        );
        return;
      }

      const uid = firebaseUser.uid;
      try {
        await updateDoc(doc(db, 'users', uid, 'researchMonitors', monitorId), {
          enabled: nextEnabled,
          updatedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(
          err,
          OperationType.UPDATE,
          `users/${uid}/researchMonitors/${monitorId}`
        );
      }
    },
    [researchMonitors, firebaseUser]
  );

  const runMonitorNow = useCallback(
    async (monitorId: string) => {
      const mon = researchMonitors.find((m) => m.id === monitorId);
      if (!mon) return;
      setMonitorMessage(null);

      if (profile.emergencyStop) {
        setMonitorMessage('Emergency Stop is engaged. Release Emergency Stop before running monitors.');
        return;
      }

      if (!firebaseUser) {
        setMonitorMessage(
          `Monitor "${mon.name}" is validated (${mon.sourcePolicy}, max ${mon.rateLimitPerHour} req/hr). Sign in with Google to execute live server-side discovery.`
        );
        return;
      }

      setRunningMonitorId(monitorId);
      try {
        let outcome: { ok: boolean; error?: string };
        if (mon.monitorType === 'website_tech') {
          outcome = await analyzeWebsite(mon.target);
        } else if (mon.monitorType === 'server_dns') {
          outcome = await analyzeServer(mon.target);
        } else if (mon.monitorType === 'cve_advisory') {
          outcome = await searchCves(mon.target);
        } else {
          const cadenceMap = mon.cadence === 'weekly' ? 'weekly' : 'daily';
          outcome = await runGroundedResearch(mon.target, cadenceMap);
        }

        const summary = outcome.ok
          ? `Last run succeeded on ${new Date().toLocaleTimeString()} via ${mon.monitorType} connector.`
          : `Run halted: ${outcome.error || 'upstream error'}`;

        const uid = firebaseUser.uid;
        await updateDoc(doc(db, 'users', uid, 'researchMonitors', monitorId), {
          lastRunSummary: sanitizeBoundedString(summary, GRI_SCHEMA_LIMITS.MONITOR_SUMMARY_MAX),
          lastRunAtMs: Date.now(),
          updatedAt: serverTimestamp(),
        });
        setMonitorMessage(summary);
      } finally {
        setRunningMonitorId(null);
      }
    },
    [
      researchMonitors,
      profile.emergencyStop,
      firebaseUser,
      analyzeWebsite,
      analyzeServer,
      searchCves,
      runGroundedResearch,
    ]
  );

  const deleteMonitor = useCallback(
    async (monitorId: string) => {
      if (!firebaseUser) {
        setPreviewMonitors((prev) => prev.filter((m) => m.id !== monitorId));
        return;
      }
      const uid = firebaseUser.uid;
      try {
        await deleteDoc(doc(db, 'users', uid, 'researchMonitors', monitorId));
      } catch (err) {
        handleFirestoreError(
          err,
          OperationType.DELETE,
          `users/${uid}/researchMonitors/${monitorId}`
        );
      }
    },
    [firebaseUser]
  );

  const generateComparisonReport = useCallback(
    async (rawTopic: string) => {
      setComparisonError(null);
      const topic = rawTopic.trim();
      if (!topic) {
        setComparisonError('Enter a technical comparison topic (e.g., Zero Trust & Edge Security Posture).');
        return;
      }
      if (profile.emergencyStop) {
        setComparisonError('Emergency Stop is active.');
        return;
      }

      const corpus = [
        ...researchReports.slice(0, 3).map((r) => ({
          title: r.query,
          kind: 'Web Research',
          excerpt: r.facts.join(' '),
          confidence: r.confidenceScore,
        })),
        ...techAnalyses.slice(0, 3).map((t) => ({
          title: t.title,
          kind: `${t.category} tech`,
          excerpt: `${t.detectedTechnologies.join(', ')} — ${t.summary.slice(0, 350)}`,
          confidence: t.confidenceScore,
        })),
        ...cveAdvisories.slice(0, 2).map((c) => ({
          title: `${c.cveId}: ${c.title}`,
          kind: 'CVE Advisory',
          excerpt: `${c.owaspCategory} — ${c.mitigation.slice(0, 300)}`,
          confidence: c.cisaKev ? 95 : 85,
        })),
      ];

      if (corpus.length < 2) {
        setComparisonError('Collect at least 2 research reports, tech analyses, or CVEs to compare.');
        return;
      }

      if (!firebaseUser) {
        // Honest deterministic structural comparison in preview without faking Gemini prose
        setComparisonReport({
          topic,
          executiveSummary: `Preview cross-index assembled ${corpus.length} stored workspace sources (${researchReports.length} research reports, ${techAnalyses.length} tech analyses, ${cveAdvisories.length} CVE advisories). Sign in with Google to run live Gemini Research Brain cross-source reasoning and contradiction synthesis.`,
          agreements: corpus.slice(0, 3).map((c) => `Source indexed (${c.kind}, ${c.confidence}% conf): ${c.title}`),
          discrepancies: [
            'Live semantic discrepancy comparison requires Google Sign-In for authenticated server-side Gemini Research Brain execution.',
          ],
          verifiedFindings: corpus.slice(0, 3).map((c) => c.excerpt.slice(0, 180)),
          recommendedActions: [
            'Sign in with Google to generate a full Gemini-verified multi-source technical report.',
            'Review flagged claims in the Global Knowledge Graph conflict audit.',
          ],
          confidenceScore: 78,
          sourceCount: corpus.length,
          generatedAtMs: Date.now(),
        });
        return;
      }

      setIsComparingSources(true);
      try {
        const idToken = await firebaseUser.getIdToken();
        const resp = await fetch('/api/gri/brain/compare-report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({
            topic,
            sourceSnippets: corpus,
            emergencyStop: profile.emergencyStop,
          }),
        });
        const payload = (await resp.json().catch(() => ({}))) as {
          error?: string;
          report?: SourceComparisonReport;
        };
        if (!resp.ok || !payload.report) {
          throw new Error(payload.error || `Source comparison failed (${resp.status}).`);
        }
        setComparisonReport(payload.report);
        await recordAuditEvent({
          action: 'GRI_BRAIN_COMPARISON_GENERATED',
          category: 'research',
          severity: 'info',
          summary: `Generated Research Brain technical comparison across ${payload.report.sourceCount} sources for "${topic.slice(0, 70)}".`,
        });
      } catch (err) {
        setComparisonError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsComparingSources(false);
      }
    },
    [
      firebaseUser,
      profile.emergencyStop,
      researchReports,
      techAnalyses,
      cveAdvisories,
      recordAuditEvent,
    ]
  );

  const value = useMemo<GriResearchContextValue>(
    () => ({
      techAnalyses,
      isAnalyzingWebsite,
      websiteError,
      lastFrontendResult,
      analyzeWebsite,
      isResearchingBackend,
      backendError,
      researchBackend,
      isAnalyzingServer,
      serverError,
      lastServerResult,
      analyzeServer,
      deleteTechAnalysis,
      cveAdvisories,
      isSearchingCves,
      cveError,
      lastCveSourcesChecked,
      searchCves,
      deleteCveAdvisory,
      researchMonitors,
      runningMonitorId,
      monitorMessage,
      addMonitor,
      toggleMonitorEnabled,
      runMonitorNow,
      deleteMonitor,
      comparisonReport,
      isComparingSources,
      comparisonError,
      generateComparisonReport,
    }),
    [
      techAnalyses,
      isAnalyzingWebsite,
      websiteError,
      lastFrontendResult,
      analyzeWebsite,
      isResearchingBackend,
      backendError,
      researchBackend,
      isAnalyzingServer,
      serverError,
      lastServerResult,
      analyzeServer,
      deleteTechAnalysis,
      cveAdvisories,
      isSearchingCves,
      cveError,
      lastCveSourcesChecked,
      searchCves,
      deleteCveAdvisory,
      researchMonitors,
      runningMonitorId,
      monitorMessage,
      addMonitor,
      toggleMonitorEnabled,
      runMonitorNow,
      deleteMonitor,
      comparisonReport,
      isComparingSources,
      comparisonError,
      generateComparisonReport,
    ]
  );

  return <GriResearchContext.Provider value={value}>{children}</GriResearchContext.Provider>;
}

export function useGriResearch(): GriResearchContextValue {
  const ctx = useContext(GriResearchContext);
  if (!ctx) {
    throw new Error('useGriResearch must be used inside GriResearchProvider');
  }
  return ctx;
}
