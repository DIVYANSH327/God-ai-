import { validatePublicCrawlTarget } from './ginAnalytics.ts';
import type {
  CveSeverity,
  MonitorCadence,
  MonitorSourcePolicy,
  MonitorType,
} from './griTypes.ts';

export const GRI_VERSION = '0.5.0';

// Synchronized verbatim with firebase-blueprint.json & firestore.rules
export const GRI_SCHEMA_LIMITS = {
  TARGET_MAX: 240,
  TITLE_MAX: 180,
  SUMMARY_MAX: 6000,
  TECH_LIST_MAX: 20,
  HEADER_LIST_MAX: 15,
  DNS_LIST_MAX: 20,
  CERT_LIST_MAX: 15,
  CVE_ID_MAX: 40,
  CVE_TITLE_MAX: 200,
  VENDOR_PRODUCT_MAX: 160,
  OWASP_MAX: 120,
  AFFECTED_VERSIONS_MAX: 300,
  MITIGATION_MAX: 2000,
  PUBLISHED_DATE_MAX: 40,
  MONITOR_NAME_MAX: 140,
  MONITOR_SUMMARY_MAX: 300,
  MAX_RATE_LIMIT_PER_HOUR: 12,
} as const;

/**
 * Strips script/style tags, HTML markup, and control characters so untrusted
 * public webpage text can be safely displayed or wrapped inside data delimiters.
 */
export function sanitizeUntrustedWebText(raw: string, maxLength: number): string {
  const withoutScripts = raw
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ');

  const cleaned = withoutScripts
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return cleaned.slice(0, maxLength);
}

const FRONTEND_SIGNATURES: ReadonlyArray<{
  name: string;
  htmlPattern?: RegExp;
  headerKey?: string;
  headerPattern?: RegExp;
  layer: 'frontend' | 'backend';
}> = [
  { name: 'Next.js', htmlPattern: /__NEXT_DATA__|\/_next\/static\//i, layer: 'frontend' },
  { name: 'React', htmlPattern: /data-reactroot|react-dom|__REACT_DEVTOOLS|react\.production/i, layer: 'frontend' },
  { name: 'Nuxt', htmlPattern: /__NUXT__|\/_nuxt\//i, layer: 'frontend' },
  { name: 'Vue.js', htmlPattern: /data-v-[a-f0-9]{6,}|vue\.runtime|vue\.global/i, layer: 'frontend' },
  { name: 'Angular', htmlPattern: /ng-version=|ng-app|angular\.min\.js/i, layer: 'frontend' },
  { name: 'Svelte / SvelteKit', htmlPattern: /__sveltekit|svelte-[a-z0-9]+/i, layer: 'frontend' },
  { name: 'Astro', htmlPattern: /astro-island|generator["']\s+content=["']Astro/i, layer: 'frontend' },
  { name: 'Vite', htmlPattern: /@vite\/client|type=["']module["'][^>]+assets\/index-[a-z0-9_-]+\.js/i, layer: 'frontend' },
  { name: 'Tailwind CSS', htmlPattern: /tailwindcss|class=["'][^"']*(?:flex\s+items-center|grid-cols-|bg-slate-|text-slate-)/i, layer: 'frontend' },
  { name: 'Bootstrap', htmlPattern: /bootstrap(?:\.min)?\.(?:css|js)|class=["'][^"']*container-fluid/i, layer: 'frontend' },
  { name: 'jQuery', htmlPattern: /jquery(?:-\d+\.\d+\.\d+)?(?:\.min)?\.js/i, layer: 'frontend' },
  { name: 'WordPress', htmlPattern: /\/wp-content\/|\/wp-includes\/|generator["']\s+content=["']WordPress/i, layer: 'frontend' },
  { name: 'Shopify', htmlPattern: /cdn\.shopify\.com|Shopify\.theme/i, layer: 'frontend' },
  { name: 'Webflow', htmlPattern: /data-wf-site|assets\.website-files\.com/i, layer: 'frontend' },
  { name: 'Cloudflare Edge', headerKey: 'cf-ray', headerPattern: /.+/, layer: 'backend' },
  { name: 'Cloudflare Server', headerKey: 'server', headerPattern: /cloudflare/i, layer: 'backend' },
  { name: 'Vercel Edge Network', headerKey: 'x-vercel-id', headerPattern: /.+/, layer: 'backend' },
  { name: 'Netlify CDN', headerKey: 'x-nf-request-id', headerPattern: /.+/, layer: 'backend' },
  { name: 'AWS CloudFront', headerKey: 'x-amz-cf-id', headerPattern: /.+/, layer: 'backend' },
  { name: 'Fastly CDN', headerKey: 'x-served-by', headerPattern: /cache-/i, layer: 'backend' },
  { name: 'Google Frontend (GFE)', headerKey: 'server', headerPattern: /\b(gws|gfe|sffe|Google Frontend)\b/i, layer: 'backend' },
  { name: 'Nginx', headerKey: 'server', headerPattern: /nginx/i, layer: 'backend' },
  { name: 'Apache HTTP Server', headerKey: 'server', headerPattern: /apache/i, layer: 'backend' },
  { name: 'Express.js', headerKey: 'x-powered-by', headerPattern: /express/i, layer: 'backend' },
  { name: 'Next.js Server', headerKey: 'x-powered-by', headerPattern: /next\.js/i, layer: 'backend' },
  { name: 'PHP Runtime', headerKey: 'x-powered-by', headerPattern: /php/i, layer: 'backend' },
  { name: 'ASP.NET', headerKey: 'x-powered-by', headerPattern: /asp\.net/i, layer: 'backend' },
  { name: 'HTTP/3 (QUIC Alt-Svc)', headerKey: 'alt-svc', headerPattern: /h3=/i, layer: 'backend' },
];

const SECURITY_HEADER_CHECKS: ReadonlyArray<{ key: string; label: string }> = [
  { key: 'strict-transport-security', label: 'HSTS (Strict-Transport-Security)' },
  { key: 'content-security-policy', label: 'CSP (Content-Security-Policy)' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options' },
  { key: 'x-frame-options', label: 'X-Frame-Options' },
  { key: 'referrer-policy', label: 'Referrer-Policy' },
  { key: 'permissions-policy', label: 'Permissions-Policy' },
];

/**
 * Deterministic analyzer for publicly accessible HTML, CSS/JS references, and HTTP headers.
 * Never executes downloaded JavaScript or renders raw HTML.
 */
export function analyzePublicFrontendHtml(input: {
  origin: string;
  html: string;
  headers: Record<string, string>;
}): {
  pageTitle: string;
  metaDescription: string;
  detectedTechnologies: string[];
  backendIndicators: string[];
  securityHeaders: string[];
  missingSecurityHeaders: string[];
  scriptCount: number;
  stylesheetCount: number;
  externalOrigins: string[];
  publicHeadings: string[];
} {
  const normalizedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) {
    normalizedHeaders[k.toLowerCase()] = String(v).slice(0, 300);
  }

  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(input.html);
  const pageTitle = titleMatch
    ? sanitizeUntrustedWebText(titleMatch[1], 140)
    : input.origin;

  const metaDescMatch =
    /<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i.exec(input.html) ||
    /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i.exec(input.html);
  const metaDescription = metaDescMatch
    ? sanitizeUntrustedWebText(metaDescMatch[1], 240)
    : 'No public meta description declared.';

  const generatorMatch =
    /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(input.html);

  const detectedFrontend = new Set<string>();
  const detectedBackend = new Set<string>();

  if (generatorMatch) {
    const gen = sanitizeUntrustedWebText(generatorMatch[1], 60);
    if (gen) detectedFrontend.add(`Generator: ${gen}`);
  }

  for (const sig of FRONTEND_SIGNATURES) {
    let matched = false;
    if (sig.htmlPattern && sig.htmlPattern.test(input.html)) {
      matched = true;
    }
    if (sig.headerKey && sig.headerPattern) {
      const hv = normalizedHeaders[sig.headerKey];
      if (hv && sig.headerPattern.test(hv)) {
        matched = true;
      }
    }
    if (matched) {
      if (sig.layer === 'frontend') {
        detectedFrontend.add(sig.name);
      } else {
        detectedBackend.add(sig.name);
      }
    }
  }

  if (normalizedHeaders['server']) {
    detectedBackend.add(`Server header: ${normalizedHeaders['server'].slice(0, 60)}`);
  }
  if (normalizedHeaders['x-powered-by']) {
    detectedBackend.add(`X-Powered-By: ${normalizedHeaders['x-powered-by'].slice(0, 60)}`);
  }

  const securityHeaders: string[] = [];
  const missingSecurityHeaders: string[] = [];
  for (const h of SECURITY_HEADER_CHECKS) {
    const value = normalizedHeaders[h.key];
    if (value) {
      securityHeaders.push(`${h.label}: ${value.slice(0, 90)}`);
    } else {
      missingSecurityHeaders.push(h.label);
    }
  }

  const scriptMatches = input.html.match(/<script\b[^>]*>/gi) || [];
  const stylesheetMatches =
    input.html.match(/<link\b[^>]*rel=["'][^"']*stylesheet[^"']*["'][^>]*>/gi) || [];

  const externalOriginSet = new Set<string>();
  const srcHrefRegex = /\b(?:src|href)=["'](https?:\/\/[^"'\s>]+)["']/gi;
  let linkMatch: RegExpExecArray | null;
  while ((linkMatch = srcHrefRegex.exec(input.html)) !== null) {
    try {
      const parsed = new URL(linkMatch[1]);
      if (parsed.origin !== input.origin) {
        externalOriginSet.add(parsed.hostname);
      }
    } catch {
      // Ignore malformed attribute URLs
    }
    if (externalOriginSet.size >= 12) break;
  }

  const publicHeadings: string[] = [];
  const headingRegex = /<h[12][^>]*>([\s\S]*?)<\/h[12]>/gi;
  let hMatch: RegExpExecArray | null;
  while ((hMatch = headingRegex.exec(input.html)) !== null) {
    const clean = sanitizeUntrustedWebText(hMatch[1], 110);
    if (clean && !publicHeadings.includes(clean)) {
      publicHeadings.push(clean);
    }
    if (publicHeadings.length >= 6) break;
  }

  return {
    pageTitle,
    metaDescription,
    detectedTechnologies: Array.from(detectedFrontend).slice(0, GRI_SCHEMA_LIMITS.TECH_LIST_MAX),
    backendIndicators: Array.from(detectedBackend).slice(0, GRI_SCHEMA_LIMITS.TECH_LIST_MAX),
    securityHeaders: securityHeaders.slice(0, GRI_SCHEMA_LIMITS.HEADER_LIST_MAX),
    missingSecurityHeaders,
    scriptCount: scriptMatches.length,
    stylesheetCount: stylesheetMatches.length,
    externalOrigins: Array.from(externalOriginSet),
    publicHeadings,
  };
}

/**
 * Deterministic classifier for public DNS records and Certificate Transparency metadata.
 * Never probes restricted ports or server admin panels.
 */
export function classifyPublicServerInfrastructure(input: {
  hostname: string;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: string[];
  nsRecords: string[];
  txtRecords: string[];
  caaRecords: string[];
  certIssuers: string[];
}): {
  inferredInfrastructure: string[];
  emailPosture: string[];
} {
  const infra = new Set<string>();
  const emailPosture: string[] = [];

  const nsJoined = input.nsRecords.join(' ').toLowerCase();
  const mxJoined = input.mxRecords.join(' ').toLowerCase();
  const txtJoined = input.txtRecords.join(' ').toLowerCase();
  const issuerJoined = input.certIssuers.join(' ').toLowerCase();

  if (nsJoined.includes('cloudflare')) infra.add('Cloudflare DNS / Edge');
  if (nsJoined.includes('awsdns')) infra.add('AWS Route 53 DNS');
  if (nsJoined.includes('googledomains') || nsJoined.includes('ns-cloud-')) {
    infra.add('Google Cloud DNS');
  }
  if (nsJoined.includes('azure-dns')) infra.add('Microsoft Azure DNS');
  if (nsJoined.includes('vercel-dns')) infra.add('Vercel DNS');
  if (nsJoined.includes('fastly')) infra.add('Fastly Edge DNS');
  if (nsJoined.includes('akamai')) infra.add('Akamai Edge DNS');

  if (input.aaaaRecords.length > 0) {
    infra.add(`IPv6 Dual-Stack Enabled (${input.aaaaRecords.length} AAAA record(s))`);
  }
  if (input.caaRecords.length > 0) {
    infra.add(`CAA Certificate Pinning Configured (${input.caaRecords.length} record(s))`);
  }

  if (issuerJoined.includes("let's encrypt")) infra.add("TLS CA: Let's Encrypt");
  if (issuerJoined.includes('google trust services')) infra.add('TLS CA: Google Trust Services');
  if (issuerJoined.includes('digicert')) infra.add('TLS CA: DigiCert');
  if (issuerJoined.includes('sectigo')) infra.add('TLS CA: Sectigo');
  if (issuerJoined.includes('amazon')) infra.add('TLS CA: Amazon Trust Services');

  if (mxJoined.includes('google.com') || mxJoined.includes('googlemail.com')) {
    emailPosture.push('Mail Exchange: Google Workspace');
  } else if (mxJoined.includes('outlook.com') || mxJoined.includes('protection.outlook')) {
    emailPosture.push('Mail Exchange: Microsoft 365');
  } else if (mxJoined.includes('protonmail')) {
    emailPosture.push('Mail Exchange: Proton Mail');
  } else if (input.mxRecords.length > 0) {
    emailPosture.push(`Mail Exchange: ${input.mxRecords[0]}`);
  } else {
    emailPosture.push('No public MX records published for this host');
  }

  if (txtJoined.includes('v=spf1')) {
    emailPosture.push('SPF (Sender Policy Framework) record present');
  } else {
    emailPosture.push('SPF record not detected on apex TXT');
  }

  if (txtJoined.includes('google-site-verification=')) {
    infra.add('Google Search Console / Cloud Verification TXT');
  }
  if (txtJoined.includes('ms=')) {
    infra.add('Microsoft Domain Verification TXT');
  }

  if (infra.size === 0 && input.aRecords.length > 0) {
    infra.add(`Public IPv4 Hosting (${input.aRecords.length} A record(s))`);
  }

  return {
    inferredInfrastructure: Array.from(infra).slice(0, GRI_SCHEMA_LIMITS.TECH_LIST_MAX),
    emailPosture,
  };
}

export function classifyCvssSeverity(score: number): CveSeverity {
  if (!Number.isFinite(score) || score <= 0) return 'unknown';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

export function mapOwaspCategory(description: string, cweIds: string[] = []): string {
  const joined = `${description} ${cweIds.join(' ')}`.toLowerCase();

  if (/\b(cwe-918|ssrf|server-side request forgery)\b/.test(joined)) {
    return 'A10:2021 — Server-Side Request Forgery (SSRF)';
  }
  if (/\b(cwe-89|cwe-78|cwe-79|cwe-77|cwe-94|sql injection|xss|cross-site scripting|command injection|code injection|remote code execution|rce)\b/.test(joined)) {
    return 'A03:2021 — Injection & Code Execution';
  }
  if (/\b(cwe-22|cwe-284|cwe-285|cwe-862|cwe-863|path traversal|privilege escalation|broken access|authorization bypass|idor)\b/.test(joined)) {
    return 'A01:2021 — Broken Access Control';
  }
  if (/\b(cwe-287|cwe-306|cwe-798|authentication bypass|hardcoded credential|session fixation)\b/.test(joined)) {
    return 'A07:2021 — Identification & Authentication Failures';
  }
  if (/\b(cwe-502|deserialization|supply chain|backdoor|integrity)\b/.test(joined)) {
    return 'A08:2021 — Software & Data Integrity Failures';
  }
  if (/\b(cwe-295|cwe-327|cwe-311|tls|certificate validation|cryptographic|weak cipher)\b/.test(joined)) {
    return 'A02:2021 — Cryptographic Failures';
  }
  if (/\b(cwe-16|misconfiguration|default credential|directory listing|cors)\b/.test(joined)) {
    return 'A05:2021 — Security Misconfiguration';
  }
  return 'A06:2021 — Vulnerable & Outdated Components';
}

export function validateResearchMonitorInput(input: {
  name: string;
  target: string;
  monitorType: MonitorType;
  cadence: MonitorCadence;
  rateLimitPerHour: number;
  sourcePolicy: MonitorSourcePolicy;
}): { valid: boolean; error?: string } {
  const name = input.name.trim();
  const target = input.target.trim();

  if (!name || name.length > GRI_SCHEMA_LIMITS.MONITOR_NAME_MAX) {
    return { valid: false, error: 'Monitor name is required (max 140 characters).' };
  }
  if (!target || target.length > GRI_SCHEMA_LIMITS.TARGET_MAX) {
    return { valid: false, error: 'Monitor target query, domain, or vendor is required.' };
  }
  if (
    !Number.isInteger(input.rateLimitPerHour) ||
    input.rateLimitPerHour < 1 ||
    input.rateLimitPerHour > GRI_SCHEMA_LIMITS.MAX_RATE_LIMIT_PER_HOUR
  ) {
    return {
      valid: false,
      error: `Rate limit must be an integer between 1 and ${GRI_SCHEMA_LIMITS.MAX_RATE_LIMIT_PER_HOUR} requests/hour.`,
    };
  }

  if (input.monitorType === 'website_tech' || input.monitorType === 'server_dns') {
    const urlCheck = validatePublicCrawlTarget(target);
    if (!urlCheck.valid) {
      return {
        valid: false,
        error: urlCheck.error || 'Target must be a valid public domain or HTTPS URL.',
      };
    }
  }

  const forbidden = /\b(exploit|metasploit|sqlmap|brute[- ]?force|credential[- ]?dump|unauthorized[- ]?scan|admin[- ]?panel[- ]?bypass)\b/i;
  if (forbidden.test(`${name} ${target}`)) {
    return {
      valid: false,
      error:
        'Blocked by GRI Security Governance: unauthorized access, credential theft, and exploitation targets are prohibited.',
    };
  }

  return { valid: true };
}
