import type {
  AgentCapabilityStatus,
  AgentDefinition,
  ExecutionMode,
  IntentCategory,
  IntentClassificationResult,
  ProviderDescriptor,
} from './types.ts';
import { SCHEMA_LIMITS, sanitizeBoundedString } from './validation.ts';

export const GOD_CORE_MODEL = 'gemini-4-hydrogen';
export const GOD_CORE_VERSION = '0.5.0';

export const AGENT_REGISTRY: readonly AgentDefinition[] = [
  {
    id: 'memory',
    name: 'Memory & Knowledge Graph Agent',
    codename: 'MNEMOSYNE-02',
    intentMapping: 'memory',
    status: 'operational',
    versionTarget: 'GIN v0.2 Active',
    summary: 'User-isolated Cloud Firestore persistence for threads, tasks, audit logs, and Knowledge Graph entities.',
    description:
      'Maintains strict per-user tenant isolation in Cloud Firestore. Persists multi-turn conversations, structured tasks, knowledge entities with duplicate/contradiction checks, and append-only security events.',
    capabilities: [
      'Real-time Firestore conversation, task & knowledge persistence',
      'Semantic/token retrieval across research sessions',
      'Automated duplicate & contradictory claim detection',
      'Split PII account isolation under Eight-Pillar security rules',
    ],
    v01Behavior: 'Fully operational via Cloud Firestore SDK and hardened tenant-isolated rules.',
    securityBoundary: 'Restricted strictly to authenticated owner UID (request.auth.uid == userId).',
    providerTarget: 'Cloud Firestore (Enterprise)',
  },
  {
    id: 'research',
    name: 'GOD Internet Explorer',
    codename: 'ORACLE-02',
    intentMapping: 'research',
    status: 'operational',
    versionTarget: 'GIN v0.2 Active',
    summary: 'Public web search via Gemini Search Grounding with verifiable citations and SSRF-safe robots.txt inspection.',
    description:
      'Executes server-side public web research using Gemini Google Search grounding, extracts source citations, inspects permitted public robots.txt directives, and commits findings to the Knowledge Graph.',
    capabilities: [
      'Server-side Google Search grounding with live source citations (v0.2)',
      'Respectful robots.txt & crawl-delay inspection with SSRF guardrails (v0.2)',
      'Structured Facts vs Predictions synthesis & research history (v0.2)',
      'Unattended scheduled background crawling (Planned v0.3)',
    ],
    v01Behavior:
      'Operational in GIN v0.2 via server-side Gemini Search Grounding and robots.txt inspection; scheduled background cron runs remain planned.',
    securityBoundary: 'Blocks loopback, RFC1918 LAN, and cloud metadata targets; respects robots.txt.',
    providerTarget: 'Gemini Search Grounding (gemini-4-hydrogen)',
  },
  {
    id: 'coder',
    name: 'Systems Coder Agent',
    codename: 'FORGE-03',
    intentMapping: 'coding',
    status: 'prototype',
    versionTarget: 'v0.1 Prototype · Sandbox Runner v0.2',
    summary: 'Architecture synthesis, debugging, and code generation in chat; isolated execution sandbox planned.',
    description:
      'Provides multi-language software design, TypeScript/Python/Rust code generation, and static review via GOD Core. Direct repository mutation and container code execution remain disabled in v0.1.',
    capabilities: [
      'Code generation, refactoring, and root-cause analysis in chat (v0.1)',
      'Syntax-formatted code blocks with one-click copy (v0.1)',
      'Ephemeral sandboxed test execution (Planned v0.2)',
      'Enrolled local workstation workspace diffing (Planned v0.2)',
    ],
    v01Behavior:
      'Generates and reviews code via GOD Core Gemini without executing code or modifying local filesystems.',
    securityBoundary: 'Zero arbitrary shell or host filesystem execution permitted.',
    providerTarget: 'Gemini Cloud / Future Ollama Coder Node',
  },
  {
    id: 'security',
    name: 'Security Research & CVE Intelligence Agent',
    codename: 'AEGIS-05',
    intentMapping: 'security',
    status: 'operational',
    versionTarget: 'GRI v0.5 Active (Passive Public Intel)',
    summary: 'Correlates live NVD CVE 2.0, CISA KEV advisories, OWASP mitigations, and enforces prompt/scope guardrails.',
    description:
      'Queries public CISA KEV and NVD CVE feeds, maps vulnerabilities to OWASP Top 10 categories and defensive mitigations, enforces prompt/URL safety policies, and maintains append-only audit trails. Active testing remains locked without explicit authorization.',
    capabilities: [
      'Live CISA KEV & NVD CVE 2.0 public advisory ingestion (GRI v0.5)',
      'OWASP Top 10 defensive mitigation mapping & Knowledge Graph commit (GRI v0.5)',
      'Granular capability approval toggles, rate limits & global Emergency Stop',
      'Enrolled Kali/Windows host telemetry & authorized active testing (Planned)',
    ],
    v01Behavior:
      'Operational for passive public CVE/KEV/OWASP security research and prompt guardrails; active penetration testing or unauthorized scanning is strictly disabled.',
    securityBoundary: 'Strictly forbids unauthorized scanning, automatic exploitation, credential theft, or unrestricted device control.',
    providerTarget: 'CISA KEV + NVD API + Gemini Cloud',
  },
  {
    id: 'vision',
    name: 'Multimodal Vision Agent',
    codename: 'OPTIC-05',
    intentMapping: 'vision',
    status: 'planned',
    versionTarget: 'Planned v0.2',
    summary: 'Planned diagram parsing, screenshot inspection, and multimodal artifact analysis.',
    description:
      'Designed to ingest user-approved screenshots, architecture diagrams, and technical schematics for spatial and visual reasoning.',
    capabilities: [
      'UI screenshot & architecture diagram inspection (Planned v0.2)',
      'Structured table & OCR extraction (Planned v0.2)',
      'Explicit per-file upload consent gating (Planned v0.2)',
    ],
    v01Behavior:
      'Not yet operational for image uploads in v0.1. Vision-related text queries receive architectural guidance via GOD Core with an explicit planned-capability notice.',
    securityBoundary: 'Requires File Analysis approval toggle and strict MIME/size verification.',
    providerTarget: 'Gemini Multimodal Pipeline (Staged)',
  },
  {
    id: 'voice',
    name: 'Neural Voice Interface',
    codename: 'VOX-06',
    intentMapping: 'voice',
    status: 'planned',
    versionTarget: 'Planned v0.2',
    summary: 'Planned low-latency bidirectional speech link for hands-free command center operation.',
    description:
      'Staged real-time WebSocket audio bridge targeting Gemini Live native audio models with push-to-talk hardware mute.',
    capabilities: [
      'Push-to-talk bidirectional PCM audio streaming (Planned v0.2)',
      'Spoken command intent transcription & confirmation (Planned v0.2)',
      'Instant Emergency Stop audio session severance (Planned v0.2)',
    ],
    v01Behavior:
      'Not operational in v0.1. Microphone capture is intentionally unrequested in v0.1 metadata permissions.',
    securityBoundary: 'Microphone access disabled by default; requires explicit browser & Security Center consent.',
    providerTarget: 'gemini-3.8-live (Staged)',
  },
  {
    id: 'automation',
    name: 'Workflow Automation Agent',
    codename: 'CHRONOS-07',
    intentMapping: 'automation',
    status: 'planned',
    versionTarget: 'Planned v0.2',
    summary: 'Planned event-driven pipelines and approved task dispatch across cloud and enrolled local nodes.',
    description:
      'Coordinates multi-step task queues with human-in-the-loop approval checkpoints before any external side effect can occur.',
    capabilities: [
      'Human-approved task queue staging in Dashboard (v0.1)',
      'Scheduled recurring research & digest pipelines (Planned v0.2)',
      'Signed outbound command dispatch to enrolled nodes (Planned v0.2)',
    ],
    v01Behavior:
      'Autonomous background execution is disabled in v0.1. Automation prompts generate structured workflow plans in AI Chat without claiming execution.',
    securityBoundary: 'Blocked whenever Emergency Stop is active or Automation Queue approval is off.',
    providerTarget: 'GOD Core Orchestrator (Staged)',
  },
];

export const PROVIDER_DESCRIPTORS: readonly ProviderDescriptor[] = [
  {
    id: 'gemini-cloud',
    name: 'Google Gemini Cloud',
    environment: 'cloud',
    status: 'active',
    defaultModel: GOD_CORE_MODEL,
    transport: 'Server-Side HTTPS (@google/genai SDK)',
    summary: 'Primary operational intelligence engine in v0.1. API keys remain strictly on the Node.js backend.',
  },
  {
    id: 'ollama-local',
    name: 'Ollama Local Runtime Adapter',
    environment: 'local',
    status: 'unpaired_disabled',
    defaultModel: 'qwen2.5-coder / llama3.3 (Unpaired)',
    transport: 'Outbound WSS + mTLS Node Relay (Staged)',
    summary:
      'Provider interface defined for local inference on enrolled Windows or Kali Linux hosts. Disabled until a node completes outbound cryptographic pairing.',
  },
];

const PROHIBITED_SECURITY_PATTERNS: ReadonlyArray<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /\b(rm\s+-rf\s+\/|mkfs\.|format\s+c:|powershell\s+-enc|invoke-mimikatz)\b/i,
    reason: 'Destructive host command or credential-dumping payload blocked by AI GOD Security Policy.',
  },
  {
    pattern: /\b(auto[- ]?exploit|sqlmap\s+--os-shell|metasploit\s+autopwn|reverse\s+shell\s+payload\s+against)\b/i,
    reason: 'Automatic exploitation and unauthorized offensive payload generation are prohibited.',
  },
  {
    pattern: /\b(nmap\s+-s[SUVT]|masscan\s+\d+\.\d+\.\d+\.\d+|scan\s+unauthorized\s+network)\b/i,
    reason: 'Unauthorized active network scanning is prohibited by AI GOD v0.1 guardrails.',
  },
];

export function checkSecurityPolicy(prompt: string): { allowed: boolean; reason?: string } {
  for (const rule of PROHIBITED_SECURITY_PATTERNS) {
    if (rule.pattern.test(prompt)) {
      return { allowed: false, reason: rule.reason };
    }
  }
  return { allowed: true };
}

export function classifyPromptHeuristic(prompt: string): IntentCategory {
  const text = prompt.toLowerCase();

  if (
    /\b(vulnerability|firewall|cve-|audit|encryption|mtls|zero[- ]trust|auth|security|hardening|permissions?|owasp|xss|csrf|ssrf)\b/.test(
      text
    )
  ) {
    return 'security';
  }

  if (
    /\b(typescript|javascript|python|rust|golang|sql|react|function|compile|refactor|bug|stack\s*trace|algorithm|regex|dockerfile|api\s+route|code)\b/.test(
      text
    ) ||
    text.includes('```')
  ) {
    return 'coding';
  }

  if (/\b(image|screenshot|diagram|photo|ocr|bounding\s+box|camera|visual|pixel|vision)\b/.test(text)) {
    return 'vision';
  }

  if (/\b(cron|schedule|automate|workflow|pipeline|webhook|trigger|recurring|batch\s+job)\b/.test(text)) {
    return 'automation';
  }

  if (
    /\b(research|compare|literature|benchmark|survey|whitepaper|investigate|synthesize|cite|deep\s+dive|market\s+analysis)\b/.test(
      text
    )
  ) {
    return 'research';
  }

  return 'chat';
}

export function getSpecialistStatusForIntent(intent: IntentCategory): AgentCapabilityStatus {
  switch (intent) {
    case 'chat':
      return 'operational';
    case 'research':
    case 'coding':
    case 'security':
      return 'prototype';
    case 'vision':
    case 'automation':
      return 'planned';
  }
}

export function buildAgentModuleDisclosure(intent: IntentCategory, executionMode: ExecutionMode): string {
  const modeSuffix =
    executionMode === 'hybrid'
      ? ' · Hybrid mode active (0 local nodes paired; routed via Gemini Cloud)'
      : '';

  switch (intent) {
    case 'chat':
      return sanitizeBoundedString(
        `GOD Core · Executed via Gemini Cloud (${GOD_CORE_MODEL})${modeSuffix}`,
        SCHEMA_LIMITS.AGENT_NOTE_MAX
      );
    case 'research':
      return sanitizeBoundedString(
        `Classified: Research · Answered via Gemini Cloud (${GOD_CORE_MODEL}). Autonomous web crawling Agent is Prototype (v0.2)${modeSuffix}`,
        SCHEMA_LIMITS.AGENT_NOTE_MAX
      );
    case 'coding':
      return sanitizeBoundedString(
        `Classified: Coding · Answered via Gemini Cloud (${GOD_CORE_MODEL}). Sandboxed code runner Agent is Prototype (v0.2)${modeSuffix}`,
        SCHEMA_LIMITS.AGENT_NOTE_MAX
      );
    case 'security':
      return sanitizeBoundedString(
        `Classified: Security · Defensive reasoning via Gemini Cloud (${GOD_CORE_MODEL}). Active host telemetry Agent is Prototype (v0.2)${modeSuffix}`,
        SCHEMA_LIMITS.AGENT_NOTE_MAX
      );
    case 'vision':
      return sanitizeBoundedString(
        `Classified: Vision · Text reasoning via Gemini Cloud (${GOD_CORE_MODEL}). Vision file-inspection Agent is Planned (v0.2) — no image tool executed${modeSuffix}`,
        SCHEMA_LIMITS.AGENT_NOTE_MAX
      );
    case 'automation':
      return sanitizeBoundedString(
        `Classified: Automation · Workflow design via Gemini Cloud (${GOD_CORE_MODEL}). Background Automation Agent is Planned (v0.2) — no job scheduled${modeSuffix}`,
        SCHEMA_LIMITS.AGENT_NOTE_MAX
      );
  }
}

export function evaluateGodCoreRouting(params: {
  prompt: string;
  executionMode: ExecutionMode;
  emergencyStop: boolean;
  pairedLocalNodesCount?: number;
}): IntentClassificationResult {
  const { prompt, executionMode, emergencyStop, pairedLocalNodesCount = 0 } = params;
  const intent = classifyPromptHeuristic(prompt);
  const specialistStatus = getSpecialistStatusForIntent(intent);

  if (emergencyStop) {
    return {
      intent,
      confidence: 1,
      executedBy: 'blocked-emergency-stop',
      specialistStatus,
      agentModuleNote: 'Execution halted: Emergency Stop kill-switch is engaged in Security Center.',
      policyBlockedReason:
        'Emergency Stop is active. Disengage Emergency Stop in the Security Center before running GOD Core requests.',
    };
  }

  const policy = checkSecurityPolicy(prompt);
  if (!policy.allowed) {
    return {
      intent: 'security',
      confidence: 0.99,
      executedBy: 'blocked-policy',
      specialistStatus: 'prototype',
      agentModuleNote: 'Blocked by AI GOD Security Policy Guardrail.',
      policyBlockedReason: policy.reason,
    };
  }

  if (executionMode === 'local' && pairedLocalNodesCount === 0) {
    return {
      intent,
      confidence: 0.92,
      executedBy: 'blocked-local-unpaired',
      specialistStatus,
      agentModuleNote: 'Local mode selected with 0 paired nodes — execution withheld.',
      policyBlockedReason:
        'Strict Local Mode is selected in Settings, but no Windows or Kali Linux node is paired yet. Switch to Cloud or Hybrid mode to execute via Gemini Cloud.',
    };
  }

  return {
    intent,
    confidence: 0.9,
    executedBy: 'god-core-gemini-cloud',
    specialistStatus,
    agentModuleNote: buildAgentModuleDisclosure(intent, executionMode),
  };
}

export function deriveConversationTitle(firstMessage: string): string {
  const cleaned = firstMessage.replace(/\s+/g, ' ').trim();
  if (!cleaned) return 'New Command Thread';
  if (cleaned.length <= 56) return cleaned;
  return `${cleaned.slice(0, 53).trimEnd()}...`;
}

export const GOD_CORE_SYSTEM_INSTRUCTION = `You are GOD Core (GOD-X v0.1), the central orchestration intelligence of the AI GOD personal command center.

CORE IDENTITY & TONE:
- Calm, precise, architecturally rigorous, and transparent.
- Structure complex technical, research, or architectural answers clearly using concise Markdown headings, bullet lists, and fenced code blocks with language identifiers.
- Never claim to be a deity or supernatural entity; "AI GOD (GOD-X)" is the product name of this modular multi-agent command center.

STRICT v0.1 HONESTY & CAPABILITY BOUNDARIES:
- In version 0.1, ONLY conversational intelligence (via server-side Gemini Cloud) and user-isolated Memory/Tasks/Audit persistence (via Cloud Firestore) are operational.
- Specialized autonomous agents (Research web crawler, Coder sandbox runner, Vision file analyzer, Voice live stream, Security host sensor, Automation scheduler) are marked Prototype or Planned (v0.2) and HAVE NOT executed any external tool, shell command, file scan, network request, or scheduled job.
- NEVER pretend or imply that you executed a background agent, browsed a live URL, inspected a local machine, ran terminal commands, or scheduled an automated job. If the user asks for an action requiring an unimplemented v0.2 module, provide the best analytical plan, code snippet, or reasoning you can right now, and state plainly what v0.1 does versus what remains a planned v0.2 capability.

STRICT SECURITY BOUNDARIES:
- Refuse arbitrary destructive shell commands, unauthorized network scanning, automatic exploitation, credential harvesting, or unrestricted device access. Offer safe defensive engineering guidance instead.`;
