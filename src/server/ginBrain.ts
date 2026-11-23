import dns from 'node:dns/promises';
import { GoogleGenAI, Type } from '@google/genai';
import { GOD_CORE_MODEL } from '../shared/godCoreLogic.ts';
import {
  GIN_SCHEMA_LIMITS,
  isPrivateOrReservedIp,
  parseRobotsTxt,
  synthesizeDeterministicBehaviourInsight,
  validatePublicCrawlTarget,
} from '../shared/ginAnalytics.ts';
import type {
  BehaviourInsightRecord,
  BrainResearchPlan,
  KnowledgeEntityType,
  NetworkAssetRecord,
  ResearchSourceCitation,
  RobotsCheckResult,
} from '../shared/ginTypes.ts';
import { isSafeExternalUrl, sanitizeBoundedString } from '../shared/validation.ts';

let sharedBrainClient: GoogleGenAI | null = null;

function getBrainClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new Error(
      'GEMINI_API_KEY is not configured on the server. Configure your Gemini API key in Settings > Secrets.'
    );
  }
  if (!sharedBrainClient) {
    sharedBrainClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return sharedBrainClient;
}

export interface GroundedResearchOutput {
  query: string;
  summary: string;
  facts: string[];
  predictions: string[];
  confidenceScore: number;
  sources: ResearchSourceCitation[];
  extractedEntities: Array<{
    label: string;
    entityType: KnowledgeEntityType;
    claim: string;
  }>;
}

function extractBulletsAfterHeading(markdown: string, headingRegex: RegExp): string[] {
  const match = headingRegex.exec(markdown);
  if (!match || match.index === undefined) return [];
  const after = markdown.slice(match.index + match[0].length);
  const nextHeading = after.search(/\n##\s+/);
  const section = nextHeading === -1 ? after : after.slice(0, nextHeading);

  return section
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => /^[-*•]\s+/.test(line) || /^\d+\.\s+/.test(line))
    .map((line) => line.replace(/^([-*•]|\d+\.)\s+/, '').trim())
    .filter(Boolean)
    .slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS)
    .map((item) => sanitizeBoundedString(item, GIN_SCHEMA_LIMITS.ITEM_TEXT_MAX));
}

function extractDomain(uri: string): string {
  try {
    return new URL(uri).hostname;
  } catch {
    return 'web-source';
  }
}

/**
 * GOD Internet Explorer: Executes real public web search via Gemini Google Search Grounding,
 * returns verifiable groundingChunks source citations, and separates facts from predictions.
 */
export async function executeGroundedWebResearch(query: string): Promise<GroundedResearchOutput> {
  const ai = getBrainClient();

  const prompt = `Conduct a rigorous public intelligence research synthesis on the following topic:
"${query}"

Structure your response using these EXACT Markdown headings:
## Executive Summary
(2 concise paragraphs synthesizing public findings.)

## Verified Facts
- List 3 to 5 directly grounded factual findings supported by public search sources.

## Analytical Predictions
- List 2 to 4 forward-looking trends, implications, or hypotheses clearly framed as predictions rather than established facts.

## Knowledge Entities
- Format each bullet strictly as: Entity Name | type (concept/organization/technology/threat/protocol) | Concise factual claim`;

  const response = await ai.models.generateContent({
    model: GOD_CORE_MODEL,
    contents: prompt,
    config: {
      systemInstruction:
        'You are GOD Internet Explorer inside AI GOD GIN v0.2. Ground claims in Google Search results, distinguish verified facts from analytical predictions, and never fabricate URLs.',
      tools: [{ googleSearch: {} }],
    },
  });

  const text = (response.text || '').trim();
  const rawChunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];

  const seenUris = new Set<string>();
  const sources: ResearchSourceCitation[] = [];

  for (const chunk of rawChunks) {
    const web = chunk.web;
    if (!web?.uri || !isSafeExternalUrl(web.uri)) continue;
    if (seenUris.has(web.uri)) continue;
    seenUris.add(web.uri);
    sources.push({
      title: sanitizeBoundedString(web.title || extractDomain(web.uri), 140, 'Public Source'),
      uri: web.uri.slice(0, GIN_SCHEMA_LIMITS.URI_MAX),
      domain: extractDomain(web.uri),
    });
    if (sources.length >= 12) break;
  }

  const facts = extractBulletsAfterHeading(text, /##\s+Verified Facts/i);
  const predictions = extractBulletsAfterHeading(text, /##\s+Analytical Predictions/i);
  const rawEntityLines = extractBulletsAfterHeading(text, /##\s+Knowledge Entities/i);

  const validEntityTypes: KnowledgeEntityType[] = [
    'concept',
    'organization',
    'technology',
    'asset',
    'threat',
    'protocol',
  ];

  const extractedEntities = rawEntityLines
    .map((line) => {
      const parts = line.split('|').map((p) => p.trim());
      if (parts.length < 3) return null;
      const rawType = parts[1].toLowerCase() as KnowledgeEntityType;
      const entityType: KnowledgeEntityType = validEntityTypes.includes(rawType)
        ? rawType
        : 'concept';
      return {
        label: sanitizeBoundedString(parts[0], GIN_SCHEMA_LIMITS.LABEL_MAX, 'Entity'),
        entityType,
        claim: sanitizeBoundedString(parts.slice(2).join(' | '), GIN_SCHEMA_LIMITS.CLAIM_MAX),
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item && item.label && item.claim))
    .slice(0, 5);

  const confidenceScore = Math.min(
    96,
    Math.max(58, 60 + sources.length * 6 + (facts.length >= 3 ? 8 : 0))
  );

  return {
    query: sanitizeBoundedString(query, GIN_SCHEMA_LIMITS.QUERY_MAX),
    summary: sanitizeBoundedString(text, GIN_SCHEMA_LIMITS.SUMMARY_MAX, 'Research completed.'),
    facts:
      facts.length > 0
        ? facts
        : ['Grounded synthesis produced from public web search results; inspect full summary above.'],
    predictions:
      predictions.length > 0
        ? predictions
        : ['Further longitudinal monitoring recommended as public documentation evolves.'],
    confidenceScore,
    sources,
    extractedEntities,
  };
}

/**
 * Respectful robots.txt & crawl-delay compliance checker with strict DNS + IP SSRF guard.
 */
export async function inspectPublicRobotsTxt(rawUrl: string): Promise<RobotsCheckResult> {
  const targetCheck = validatePublicCrawlTarget(rawUrl);
  if (!targetCheck.valid || !targetCheck.normalizedOrigin || !targetCheck.hostname) {
    throw new Error(targetCheck.error || 'Invalid public crawl target.');
  }

  // Resolve DNS and verify EVERY returned IP is non-private (prevents DNS rebinding / SSRF)
  let resolvedAddrs: Array<{ address: string }>;
  try {
    resolvedAddrs = await dns.lookup(targetCheck.hostname, { all: true });
  } catch {
    throw new Error(`Could not resolve public hostname "${targetCheck.hostname}".`);
  }

  if (!resolvedAddrs.length || resolvedAddrs.some((entry) => isPrivateOrReservedIp(entry.address))) {
    throw new Error(
      'Blocked by SSRF guard: target hostname resolved to a private, loopback, or reserved IP address.'
    );
  }

  const robotsUrl = `${targetCheck.normalizedOrigin}/robots.txt`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const resp = await fetch(robotsUrl, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'User-Agent': 'AIGOD-GIN-Bot/0.2 (+respectful-robots-check)',
        Accept: 'text/plain, */*;q=0.5',
      },
      signal: controller.signal,
    });

    if (resp.status === 404) {
      return {
        origin: targetCheck.normalizedOrigin,
        robotsUrl,
        reachable: true,
        allowedForGinBot: true,
        crawlDelaySeconds: null,
        disallowedPaths: [],
        policySummary:
          'No robots.txt found (HTTP 404). Public metadata access permitted under conservative default rate limit (<= 1 req / 5s).',
      };
    }

    if (resp.status >= 300 && resp.status < 400) {
      return {
        origin: targetCheck.normalizedOrigin,
        robotsUrl,
        reachable: true,
        allowedForGinBot: true,
        crawlDelaySeconds: null,
        disallowedPaths: [],
        policySummary: `Target returned HTTP ${resp.status} redirect for robots.txt. Redirects are not auto-followed for SSRF safety; inspect canonical origin.`,
      };
    }

    if (!resp.ok) {
      return {
        origin: targetCheck.normalizedOrigin,
        robotsUrl,
        reachable: false,
        allowedForGinBot: false,
        crawlDelaySeconds: null,
        disallowedPaths: [],
        policySummary: `Robots endpoint returned HTTP ${resp.status}. Crawling deferred out of caution.`,
      };
    }

    const rawText = (await resp.text()).slice(0, 64_000);
    return parseRobotsTxt(targetCheck.normalizedOrigin, rawText);
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * GOD Central Brain: Generates a verified multi-agent research & analysis plan via structured JSON.
 */
export async function generateBrainResearchPlan(objective: string): Promise<BrainResearchPlan> {
  const ai = getBrainClient();

  const response = await ai.models.generateContent({
    model: GOD_CORE_MODEL,
    contents: `Create a structured Global Research & Intelligence (GRI v0.5 / GIN) research and verification plan for:
"${objective}"

Assign steps only to valid modules: GOD Research Brain, GOD Internet Explorer, Frontend & Backend Intelligence, Server Intelligence, Security Research (CVE/KEV), Global Knowledge Graph, GOD Network Observer, GOD Behaviour Engine, or Continuous Research. Be honest about what executes now in v0.5 (ready_v02) vs prototype/planned.`,
    config: {
      systemInstruction:
        'You are GOD Research Brain (GRI v0.5). Produce concise, verifiable, strictly defensive intelligence plans that respect robots.txt, rate limits, and authorization boundaries.',
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          objective: { type: Type.STRING },
          strategySummary: { type: Type.STRING },
          confidenceScore: { type: Type.INTEGER },
          steps: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                stepNumber: { type: Type.INTEGER },
                agentModule: { type: Type.STRING },
                objective: { type: Type.STRING },
                verificationCriteria: { type: Type.STRING },
                status: { type: Type.STRING },
              },
              required: [
                'stepNumber',
                'agentModule',
                'objective',
                'verificationCriteria',
                'status',
              ],
            },
          },
          verificationChecklist: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
          },
        },
        required: [
          'objective',
          'strategySummary',
          'confidenceScore',
          'steps',
          'verificationChecklist',
        ],
      },
    },
  });

  const parsed = JSON.parse((response.text || '{}').trim()) as Partial<BrainResearchPlan>;
  const rawSteps = Array.isArray(parsed.steps) ? parsed.steps : [];

  return {
    objective: sanitizeBoundedString(parsed.objective || objective, 240),
    strategySummary: sanitizeBoundedString(
      parsed.strategySummary || 'Multi-stage GIN verification workflow.',
      600
    ),
    confidenceScore: Math.min(100, Math.max(40, Number(parsed.confidenceScore) || 84)),
    steps: rawSteps.slice(0, 6).map((s, idx) => ({
      stepNumber: Number(s.stepNumber) || idx + 1,
      agentModule: sanitizeBoundedString(String(s.agentModule || 'GOD Central Brain'), 60),
      objective: sanitizeBoundedString(String(s.objective || ''), 280),
      verificationCriteria: sanitizeBoundedString(String(s.verificationCriteria || ''), 240),
      status:
        s.status === 'ready_v02' || s.status === 'prototype' || s.status === 'planned'
          ? s.status
          : 'ready_v02',
    })),
    verificationChecklist: (Array.isArray(parsed.verificationChecklist)
      ? parsed.verificationChecklist
      : ['Verify primary source citations', 'Separate factual observations from predictions']
    )
      .slice(0, 6)
      .map((item) => sanitizeBoundedString(String(item), 220)),
  };
}

/**
 * GOD Behaviour Engine server synthesis: combines deterministic anomaly baseline with Gemini explanation.
 */
export async function analyzeTelemetryWithBrain(
  assets: NetworkAssetRecord[],
  recentResearchQueries: string[]
): Promise<Omit<BehaviourInsightRecord, 'id' | 'userId' | 'createdAtMs'>> {
  const baseline = synthesizeDeterministicBehaviourInsight(assets);

  try {
    const ai = getBrainClient();
    const compactAssets = assets.slice(0, 12).map((a) => ({
      hostname: a.hostname,
      scope: a.authorizedScope,
      status: a.status,
      dnsQpm: a.dnsQueriesPerMin,
      nxdomainRatio: a.nxdomainRatio,
      outboundMbps: a.outboundMbps,
      baselineMbps: a.baselineMbps,
      anomalyScore: a.anomalyScore,
    }));

    const response = await ai.models.generateContent({
      model: GOD_CORE_MODEL,
      contents: `Analyze this authorized passive network metadata inventory and recent public research context. Strictly separate factual observations from predictions and provide a calibrated confidence score (0-100).

Authorized Assets: ${JSON.stringify(compactAssets)}
Recent Research Topics: ${JSON.stringify(recentResearchQueries.slice(0, 5))}`,
      config: {
        systemInstruction:
          'You are GOD Behaviour Engine (GIN v0.2). Analyze only the provided authorized metadata. Never invent packet contents. Clearly separate verified facts from predictions.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            title: { type: Type.STRING },
            explanation: { type: Type.STRING },
            confidenceScore: { type: Type.INTEGER },
            facts: { type: Type.ARRAY, items: { type: Type.STRING } },
            predictions: { type: Type.ARRAY, items: { type: Type.STRING } },
          },
          required: ['title', 'explanation', 'confidenceScore', 'facts', 'predictions'],
        },
      },
    });

    const parsed = JSON.parse((response.text || '{}').trim()) as {
      title?: string;
      explanation?: string;
      confidenceScore?: number;
      facts?: string[];
      predictions?: string[];
    };

    return {
      title: sanitizeBoundedString(parsed.title || baseline.title, 180),
      domain: recentResearchQueries.length > 0 ? 'hybrid' : baseline.domain,
      severity: baseline.severity,
      confidenceScore: Math.min(
        98,
        Math.max(45, Number(parsed.confidenceScore) || baseline.confidenceScore)
      ),
      facts:
        Array.isArray(parsed.facts) && parsed.facts.length > 0
          ? parsed.facts
              .slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS)
              .map((f) => sanitizeBoundedString(String(f), GIN_SCHEMA_LIMITS.ITEM_TEXT_MAX))
          : baseline.facts,
      predictions:
        Array.isArray(parsed.predictions) && parsed.predictions.length > 0
          ? parsed.predictions
              .slice(0, GIN_SCHEMA_LIMITS.MAX_ARRAY_ITEMS)
              .map((p) => sanitizeBoundedString(String(p), GIN_SCHEMA_LIMITS.ITEM_TEXT_MAX))
          : baseline.predictions,
      explanation: sanitizeBoundedString(
        parsed.explanation || baseline.explanation,
        GIN_SCHEMA_LIMITS.EXPLANATION_MAX
      ),
      sourceRefs: baseline.sourceRefs,
    };
  } catch {
    return baseline;
  }
}
