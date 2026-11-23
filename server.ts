import 'dotenv/config';
import express, { type NextFunction, type Request, type Response } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getApp, getApps, initializeApp as initializeAdminApp } from 'firebase-admin/app';
import { getAuth as getAdminAuth } from 'firebase-admin/auth';
import firebaseConfig from './firebase-applet-config.json' with { type: 'json' };
import {
  GOD_CORE_MODEL,
  GOD_CORE_VERSION,
  PROVIDER_DESCRIPTORS,
  evaluateGodCoreRouting,
} from './src/shared/godCoreLogic.ts';
import { GIN_VERSION, SENSOR_NODE_SPECS } from './src/shared/ginAnalytics.ts';
import { GRI_VERSION } from './src/shared/griAnalytics.ts';
import { SENTINEL_VERSION } from './src/shared/sentinelTypes.ts';
import {
  ALLOWED_EXECUTION_MODES,
  SCHEMA_LIMITS,
  validateChatPrompt,
} from './src/shared/validation.ts';
import type { ExecutionMode } from './src/shared/types.ts';
import type { NetworkAssetRecord } from './src/shared/ginTypes.ts';
import { geminiCloudProvider, type ChatTurnInput } from './src/server/providers.ts';
import {
  analyzeTelemetryWithBrain,
  executeGroundedWebResearch,
  generateBrainResearchPlan,
  inspectPublicRobotsTxt,
} from './src/server/ginBrain.ts';
import {
  analyzePublicServerInfrastructure,
  analyzePublicWebsite,
  generateSourceComparisonReport,
  researchBackendArchitecture,
  searchPublicCveIntelligence,
} from './src/server/griConnectors.ts';
import { createSentinelRouter } from './src/server/sentinelRoutes.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Per-UID sliding-window rate limiter (Security & Governance)
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 25;
const uidRequestWindows = new Map<string, number[]>();

function checkUidRateLimit(uid: string): { allowed: boolean; remaining: number; retryAfterSec: number } {
  const now = Date.now();
  const timestamps = (uidRequestWindows.get(uid) || []).filter(
    (ts) => now - ts < RATE_LIMIT_WINDOW_MS
  );
  if (timestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    const oldest = timestamps[0] || now;
    const retryAfterSec = Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now - oldest)) / 1000));
    uidRequestWindows.set(uid, timestamps);
    return { allowed: false, remaining: 0, retryAfterSec };
  }
  timestamps.push(now);
  uidRequestWindows.set(uid, timestamps);
  return {
    allowed: true,
    remaining: Math.max(0, RATE_LIMIT_MAX_REQUESTS - timestamps.length),
    retryAfterSec: 0,
  };
}

function getFirebaseAdminAuth() {
  if (!firebaseConfig.projectId || firebaseConfig.projectId === 'remixed-project-id') {
    throw new Error('Firebase project configuration is missing.');
  }
  const adminApp = getApps().length
    ? getApp()
    : initializeAdminApp({ projectId: firebaseConfig.projectId });
  return getAdminAuth(adminApp);
}

interface AuthenticatedRequest extends Request {
  authUser?: {
    uid: string;
    email?: string;
  };
}

async function requireVerifiedFirebaseUser(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'Authentication required. Sign in with Google to run live GOD Core & GIN intelligence.',
    });
    return;
  }

  const idToken = authHeader.slice('Bearer '.length).trim();
  if (!idToken) {
    res.status(401).json({ error: 'Missing Firebase authentication token.' });
    return;
  }

  try {
    const adminAuth = getFirebaseAdminAuth();
    // verifyIdToken(idToken) verifies cryptographic JWT signature & projectId without requiring IAM
    const decoded = await adminAuth.verifyIdToken(idToken);
    if (!decoded.email_verified) {
      res.status(403).json({
        error: 'Verified Google account email is required to execute GOD Core requests.',
      });
      return;
    }

    const rate = checkUidRateLimit(decoded.uid);
    res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT_MAX_REQUESTS));
    res.setHeader('X-RateLimit-Remaining', String(rate.remaining));
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfterSec));
      res.status(429).json({
        error: `Rate limit exceeded (${RATE_LIMIT_MAX_REQUESTS} req/min). Retry in ${rate.retryAfterSec}s.`,
      });
      return;
    }

    req.authUser = {
      uid: decoded.uid,
      email: decoded.email,
    };
    next();
  } catch {
    res.status(401).json({
      error: 'Invalid or expired session token. Please sign in with Google again.',
    });
  }
}

function formatUpstreamGeminiError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  if (raw.includes('API_KEY_INVALID') || raw.includes('PERMISSION_DENIED') || raw.includes('403')) {
    return 'Gemini API authentication error. Please check your GEMINI_API_KEY in the Settings > Secrets panel.';
  }
  if (raw.includes('RESOURCE_EXHAUSTED') || raw.includes('429')) {
    return 'Gemini API rate limit or quota reached. Wait a moment or attach a billing-enabled key in Settings > Secrets.';
  }
  if (raw.includes('NOT_FOUND') || raw.includes('404')) {
    return `Requested Gemini model (${GOD_CORE_MODEL}) was not found by the upstream API.`;
  }
  return raw || 'Unexpected error communicating with GOD Core Gemini service.';
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.disable('x-powered-by');
  app.use(express.json({ limit: '512kb' }));

  app.use('/api/sentinel', createSentinelRouter(requireVerifiedFirebaseUser));

  // Read-only non-sensitive runtime status endpoint
  app.get('/api/system/info', (_req: Request, res: Response) => {
    res.json({
      name: 'AI GOD — GRI v0.5 & SENTINEL v0.8',
      version: GOD_CORE_VERSION,
      ginVersion: GIN_VERSION,
      griVersion: GRI_VERSION,
      sentinelVersion: SENTINEL_VERSION,
      coreModel: GOD_CORE_MODEL,
      geminiConfigured: geminiCloudProvider.isAvailable(),
      searchGroundingEnabled: geminiCloudProvider.isAvailable(),
      pairedLocalNodes: 0,
      rateLimitPerMinute: RATE_LIMIT_MAX_REQUESTS,
      providers: PROVIDER_DESCRIPTORS,
      sensorInterfaces: SENSOR_NODE_SPECS,
    });
  });

  // GIN v0.2: Grounded Public Web Research (Gemini Search Grounding)
  app.post(
    '/api/gin/research',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged. Disengage before running research.' });
        return;
      }
      const rawQuery = typeof req.body?.query === 'string' ? req.body.query.trim() : '';
      if (!rawQuery || rawQuery.length > 400) {
        res.status(400).json({ error: 'Research query must be between 1 and 400 characters.' });
        return;
      }
      try {
        const report = await executeGroundedWebResearch(rawQuery);
        res.json({ report });
      } catch (err) {
        res.status(502).json({ error: formatUpstreamGeminiError(err) });
      }
    }
  );

  // GIN v0.2: Respectful Public robots.txt & Crawl-Delay Compliance Inspector (SSRF-hardened)
  app.post(
    '/api/gin/robots-check',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
      if (!rawUrl || rawUrl.length > 300) {
        res.status(400).json({ error: 'Provide a valid public HTTPS domain or URL.' });
        return;
      }
      try {
        const result = await inspectPublicRobotsTxt(rawUrl);
        res.json({ result });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const status = msg.includes('SSRF') || msg.includes('Invalid') ? 400 : 502;
        res.status(status).json({ error: msg });
      }
    }
  );

  // GIN v0.2: Authorized Telemetry & Behaviour Engine Analysis
  app.post(
    '/api/gin/telemetry/analyze',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawAssets = Array.isArray(req.body?.assets) ? (req.body.assets as NetworkAssetRecord[]) : [];
      const recentQueries = Array.isArray(req.body?.recentQueries)
        ? req.body.recentQueries.filter((q: unknown): q is string => typeof q === 'string').slice(0, 5)
        : [];
      try {
        const insight = await analyzeTelemetryWithBrain(rawAssets.slice(0, 20), recentQueries);
        res.json({ insight });
      } catch (err) {
        res.status(502).json({ error: formatUpstreamGeminiError(err) });
      }
    }
  );

  // GIN v0.2: GOD Central Brain Structured Research Planner
  app.post(
    '/api/gin/brain/plan',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawObjective = typeof req.body?.objective === 'string' ? req.body.objective.trim() : '';
      if (!rawObjective || rawObjective.length > 400) {
        res.status(400).json({ error: 'Provide a research objective (1–400 characters).' });
        return;
      }
      try {
        const plan = await generateBrainResearchPlan(rawObjective);
        res.json({ plan });
      } catch (err) {
        res.status(502).json({ error: formatUpstreamGeminiError(err) });
      }
    }
  );

  // GRI v0.5: Frontend & Public HTTP Header Intelligence Analyzer
  app.post(
    '/api/gri/analyze-website',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
      if (!rawUrl || rawUrl.length > 240) {
        res.status(400).json({ error: 'Provide a valid public HTTPS website URL (max 240 chars).' });
        return;
      }
      try {
        const result = await analyzePublicWebsite(rawUrl);
        res.json({ result });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const status =
          msg.includes('Blocked') || msg.includes('Invalid') || msg.includes('Enter a valid')
            ? 400
            : 502;
        res.status(status).json({ error: msg });
      }
    }
  );

  // GRI v0.5: Backend Architecture & Public Documentation Research
  app.post(
    '/api/gri/backend-research',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawTopic = typeof req.body?.topic === 'string' ? req.body.topic.trim() : '';
      if (!rawTopic || rawTopic.length > 240) {
        res.status(400).json({ error: 'Provide a backend technology or public API topic (1–240 chars).' });
        return;
      }
      try {
        const result = await researchBackendArchitecture(rawTopic);
        res.json({ result });
      } catch (err) {
        res.status(502).json({ error: formatUpstreamGeminiError(err) });
      }
    }
  );

  // GRI v0.5: Server Intelligence (Public DNS + Certificate Transparency)
  app.post(
    '/api/gri/analyze-server',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawHost = typeof req.body?.hostname === 'string' ? req.body.hostname.trim() : '';
      if (!rawHost || rawHost.length > 240) {
        res.status(400).json({ error: 'Provide a valid public hostname or domain.' });
        return;
      }
      try {
        const result = await analyzePublicServerInfrastructure(rawHost);
        res.json({ result });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const status =
          msg.includes('Blocked') || msg.includes('Invalid') || msg.includes('Enter a valid')
            ? 400
            : 502;
        res.status(status).json({ error: msg });
      }
    }
  );

  // GRI v0.5: Security Research (Live CISA KEV + NVD CVE 2.0 + OWASP Mitigation Mapper)
  app.post(
    '/api/gri/cve-search',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawQuery = typeof req.body?.query === 'string' ? req.body.query.trim() : '';
      if (!rawQuery || rawQuery.length > 160) {
        res.status(400).json({ error: 'Enter a CVE ID, vendor, or software keyword (1–160 chars).' });
        return;
      }
      try {
        const result = await searchPublicCveIntelligence(rawQuery);
        res.json(result);
      } catch (err) {
        res.status(502).json({ error: formatUpstreamGeminiError(err) });
      }
    }
  );

  // GRI v0.5: Research Brain Source Comparison & Technical Report Generator
  app.post(
    '/api/gri/brain/compare-report',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      if (req.body?.emergencyStop) {
        res.status(423).json({ error: 'Emergency Stop is engaged.' });
        return;
      }
      const rawTopic = typeof req.body?.topic === 'string' ? req.body.topic.trim() : '';
      const rawSnippets = Array.isArray(req.body?.sourceSnippets) ? req.body.sourceSnippets : [];
      if (!rawTopic || rawSnippets.length < 2) {
        res.status(400).json({ error: 'Provide a topic and at least 2 collected sources to compare.' });
        return;
      }
      try {
        const report = await generateSourceComparisonReport({
          topic: rawTopic,
          sourceSnippets: rawSnippets,
        });
        res.json({ report });
      } catch (err) {
        res.status(502).json({ error: formatUpstreamGeminiError(err) });
      }
    }
  );

  // Protected intent classification endpoint
  app.post(
    '/api/god-core/classify',
    requireVerifiedFirebaseUser,
    (req: AuthenticatedRequest, res: Response) => {
      const rawPrompt = typeof req.body?.prompt === 'string' ? req.body.prompt : '';
      const check = validateChatPrompt(rawPrompt);
      if (!check.valid) {
        res.status(400).json({ error: check.error });
        return;
      }

      const rawMode = req.body?.executionMode;
      const executionMode: ExecutionMode = ALLOWED_EXECUTION_MODES.includes(rawMode)
        ? rawMode
        : 'cloud';
      const emergencyStop = Boolean(req.body?.emergencyStop);

      const classification = evaluateGodCoreRouting({
        prompt: check.sanitizedPrompt,
        executionMode,
        emergencyStop,
        pairedLocalNodesCount: 0,
      });

      res.json({ classification });
    }
  );

  // Protected GOD Core streaming chat endpoint (SSE)
  app.post(
    '/api/god-core/chat',
    requireVerifiedFirebaseUser,
    async (req: AuthenticatedRequest, res: Response) => {
      const rawMessage = typeof req.body?.message === 'string' ? req.body.message : '';
      const promptCheck = validateChatPrompt(rawMessage);
      if (!promptCheck.valid) {
        res.status(400).json({ error: promptCheck.error });
        return;
      }

      const rawMode = req.body?.executionMode;
      const executionMode: ExecutionMode = ALLOWED_EXECUTION_MODES.includes(rawMode)
        ? rawMode
        : 'cloud';
      const emergencyStop = Boolean(req.body?.emergencyStop);

      const rawHistory = Array.isArray(req.body?.history) ? req.body.history : [];
      const sanitizedHistory: ChatTurnInput[] = [];
      for (const item of rawHistory.slice(-16)) {
        if (
          item &&
          typeof item === 'object' &&
          (item.role === 'user' || item.role === 'assistant') &&
          typeof item.content === 'string'
        ) {
          sanitizedHistory.push({
            role: item.role,
            content: item.content.slice(0, SCHEMA_LIMITS.MESSAGE_CONTENT_MAX),
          });
        }
      }

      const routing = evaluateGodCoreRouting({
        prompt: promptCheck.sanitizedPrompt,
        executionMode,
        emergencyStop,
        pairedLocalNodesCount: 0,
      });

      if (routing.executedBy === 'blocked-emergency-stop') {
        res.status(423).json({
          error: routing.policyBlockedReason,
          classification: routing,
        });
        return;
      }

      if (routing.executedBy === 'blocked-policy') {
        res.status(403).json({
          error: routing.policyBlockedReason,
          classification: routing,
        });
        return;
      }

      if (routing.executedBy === 'blocked-local-unpaired') {
        res.status(409).json({
          error: routing.policyBlockedReason,
          classification: routing,
        });
        return;
      }

      res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders?.();

      const writeSse = (event: string, payload: unknown) => {
        if (!res.writableEnded) {
          res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
        }
      };

      writeSse('meta', routing);

      let clientClosed = false;
      req.on('close', () => {
        clientClosed = true;
      });

      try {
        for await (const chunkText of geminiCloudProvider.streamCompletion({
          prompt: promptCheck.sanitizedPrompt,
          history: sanitizedHistory,
          classifiedIntent: routing.intent,
          agentModuleNote: routing.agentModuleNote,
        })) {
          if (clientClosed) break;
          writeSse('delta', { text: chunkText });
        }

        if (!clientClosed) {
          writeSse('done', {
            modelUsed: GOD_CORE_MODEL,
            intent: routing.intent,
            agentModuleNote: routing.agentModuleNote,
          });
        }
      } catch (err) {
        writeSse('error', {
          error: formatUpstreamGeminiError(err),
        });
      } finally {
        if (!res.writableEnded) {
          res.end();
        }
      }
    }
  );

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*all', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AI GOD (GOD-X) v${GOD_CORE_VERSION} server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
