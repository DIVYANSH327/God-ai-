# AI GOD — Global Intelligence Network (GIN) v0.2 Architecture & Operations Guide

## 1. Overview

AI GOD (GOD-X) v0.2 extends the v0.1 personal AI command center into the **Global Intelligence Network (GIN)**—a modular, user-isolated digital intelligence platform combining authorized passive network observability, grounded public web research, behavioural synthesis, entity-relation knowledge management, and server-side Gemini reasoning.

All v0.1 features (GOD Dashboard, AI Chat SSE streaming, Agents, Vision/Voice/Automation specifications, Memory Vault, Security Center, and Settings) remain fully preserved and extended.

---

## 2. Implemented Modules vs. Staged / Planned Roadmap

| Module | Status in v0.2 | Implemented Capabilities | Honestly Labeled Planned Capabilities |
| :--- | :--- | :--- | :--- |
| **GOD Live Command Center** | Operational | Real-time GIN telemetry overview, interactive SVG Network Topology & Knowledge Graph previews, Central Brain planner, Operational Task Queue, Audit Timeline | Multi-tenant team collaboration dashboards |
| **GOD Network Observer** | Operational | Authorized asset inventory, passive DNS metadata & NetFlow drift scoring, interactive SVG topology, anomaly & OSINT heuristic correlation, isolation flags | Live Windows 11 / Kali Linux outbound WSS sensor pairing (specs defined; 0 local nodes paired) |
| **GOD Internet Explorer** | Operational | Server-side Gemini Google Search Grounding with verifiable citations, Facts vs Predictions synthesis, SSRF-hardened RFC 9309 `robots.txt` & Crawl-delay compliance checker, Knowledge Graph entity commit | Unattended scheduled background crawling (daily/weekly cron); NVD/CISA KEV/arXiv live connectors |
| **GOD Behaviour Engine** | Operational | Server-side Gemini + deterministic telemetry analysis separating Verified Facts from Analytical Predictions with calibrated confidence scores | Continuous streaming anomaly windows |
| **GOD Knowledge Graph** | Operational | Entity & directed relationship persistence in Cloud Firestore, interactive SVG graph visualization, ranked semantic search, automated duplicate & contradictory claim detection | Vector embedding index via `gemini-embedding-2` |
| **GOD Central Brain** | Operational | Server-side Gemini SSE chat streaming (`gemini-4-hydrogen`), intent routing, structured JSON multi-agent research & verification planning, one-click staging into Task Queue | Autonomous background task execution |
| **Security & Governance** | Operational | Firebase Google Auth JWT verification, Eight-Pillar Firestore rules, declared authorized scopes, sliding-window per-UID rate limiting (25 req/min), immutable audit logs, Emergency Stop | Hardware-backed Ed25519 local node attestation relay |

---

## 3. Server-Side API Endpoints (`/server.ts`)

All intelligence routes verify the caller's Firebase ID token (`Authorization: Bearer <token>`), require `email_verified === true`, enforce per-UID sliding-window rate limits (`25 req/min`), and keep `GEMINI_API_KEY` strictly on the server:

- `GET /api/system/info` — Read-only runtime version, model, rate limit, and modular sensor interface metadata.
- `POST /api/god-core/classify` — Server-side prompt intent classification and guardrail screening.
- `POST /api/god-core/chat` — Server-Sent Events (SSE) streaming chat via `@google/genai`.
- `POST /api/gin/research` — Public web research via Gemini Google Search Grounding returning verifiable `groundingChunks` citations, Facts, Predictions, and extracted Knowledge Graph entities.
- `POST /api/gin/robots-check` — SSRF-hardened (DNS lookup + IPv4/IPv6 private/loopback/metadata block, `redirect: 'manual'`) RFC 9309 `robots.txt` compliance checker.
- `POST /api/gin/telemetry/analyze` — Authorized passive telemetry & public research synthesis via GOD Behaviour Engine.
- `POST /api/gin/brain/plan` — Structured JSON multi-agent research & verification planner via GOD Central Brain.

---

## 4. User-Isolated Cloud Firestore Collections

Defined in `firebase-blueprint.json` and enforced by `firestore.rules` (strict owner UID isolation `request.auth.uid == userId`, bounded arrays/strings, immutable audit logs):

- `/users/{userId}` — Operational profile, execution mode, emergency stop, capability gates.
- `/users/{userId}/private/account` — Isolated PII email record.
- `/users/{userId}/conversations/{conversationId}` & `/messages/{messageId}` — Chat history.
- `/users/{userId}/tasks/{taskId}` — Operational tasks.
- `/users/{userId}/auditEvents/{eventId}` — Append-only, immutable audit events (`allow update, delete: if false`).
- `/users/{userId}/networkAssets/{assetId}` — Authorized network assets and passive DNS/flow telemetry.
- `/users/{userId}/researchReports/{reportId}` — Grounded web research reports and citations.
- `/users/{userId}/knowledgeNodes/{nodeId}` — Knowledge Graph entities, claims, sources, and relations.
- `/users/{userId}/behaviourInsights/{insightId}` — Behaviour Engine findings (Facts, Predictions, Confidence).

---

## 5. Security Boundaries & Non-Negotiable Prohibitions

1. **No unauthorized interception**: Passive metadata only—never raw packet capture, credential harvesting, or covert TLS decryption.
2. **No arbitrary host control**: No shell execution, unauthorized port scanning (`nmap`/`masscan` blocked), or automatic exploitation.
3. **SSRF defense**: Outbound `robots.txt` inspection rejects `localhost`, `.internal`, RFC1918 private IPs (`10/8`, `172.16/12`, `192.168/16`), link-local/cloud metadata (`169.254.169.254`), and IPv6 loopback/ULA addresses both lexically and post-DNS resolution.
4. **Outbound-only remote node enrollment**: Future Windows 11 and Kali Linux nodes initiate authenticated outbound TLS 1.3 WSS relays with zero inbound open ports.

---

## 6. Verification & Automated Tests

Run ESLint security rules validation and all deterministic unit test suites:

```bash
npx eslint firestore.rules
npx --yes tsx --test firestore.rules.test.ts src/shared/godCoreLogic.test.ts src/shared/ginAnalytics.test.ts
```
