import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzePublicFrontendHtml,
  classifyCvssSeverity,
  classifyPublicServerInfrastructure,
  mapOwaspCategory,
  sanitizeUntrustedWebText,
  validateResearchMonitorInput,
} from './griAnalytics';

test('sanitizeUntrustedWebText strips script/style tags and control characters', () => {
  const dirty = '<script>alert(1)</script><h1>Hello\u0007 World</h1><style>body{color:red}</style>';
  const clean = sanitizeUntrustedWebText(dirty, 100);
  assert.equal(clean, 'Hello World');
});

test('analyzePublicFrontendHtml detects React, Next.js, Tailwind, and security headers without executing HTML', () => {
  const html = `<!doctype html>
    <html>
      <head>
        <title>Acme Cloud Docs</title>
        <meta name="description" content="Public engineering architecture guide." />
        <link rel="stylesheet" href="https://cdn.example.net/app.css" />
        <script src="/_next/static/chunks/main.js"></script>
      </head>
      <body class="flex items-center bg-slate-900">
        <h1>Architecture Overview</h1>
        <script id="__NEXT_DATA__">{"props":{}}</script>
      </body>
    </html>`;

  const res = analyzePublicFrontendHtml({
    origin: 'https://docs.acme.org',
    html,
    headers: {
      server: 'cloudflare',
      'cf-ray': '8abc123-SJC',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'",
    },
  });

  assert.equal(res.pageTitle, 'Acme Cloud Docs');
  assert.ok(res.detectedTechnologies.includes('Next.js'));
  assert.ok(res.detectedTechnologies.includes('Tailwind CSS'));
  assert.ok(res.backendIndicators.some((b) => b.includes('Cloudflare')));
  assert.ok(res.securityHeaders.some((h) => h.includes('HSTS')));
  assert.ok(res.securityHeaders.some((h) => h.includes('CSP')));
  assert.ok(res.missingSecurityHeaders.includes('X-Frame-Options'));
  assert.equal(res.scriptCount, 2);
  assert.equal(res.stylesheetCount, 1);
  assert.deepEqual(res.externalOrigins, ['cdn.example.net']);
});

test('classifyPublicServerInfrastructure identifies cloud DNS, TLS CA, and email posture', () => {
  const res = classifyPublicServerInfrastructure({
    hostname: 'example.org',
    aRecords: ['93.184.216.34'],
    aaaaRecords: ['2606:2800:220:1::'],
    mxRecords: ['10 aspmx.l.google.com'],
    nsRecords: ['dana.ns.cloudflare.com'],
    txtRecords: ['v=spf1 include:_spf.google.com ~all'],
    caaRecords: ['0 issue "letsencrypt.org"'],
    certIssuers: ["Let's Encrypt R3"],
  });

  assert.ok(res.inferredInfrastructure.includes('Cloudflare DNS / Edge'));
  assert.ok(res.inferredInfrastructure.some((i) => i.includes('IPv6 Dual-Stack')));
  assert.ok(res.inferredInfrastructure.some((i) => i.includes("Let's Encrypt")));
  assert.ok(res.emailPosture.some((e) => e.includes('Google Workspace')));
  assert.ok(res.emailPosture.some((e) => e.includes('SPF')));
});

test('classifyCvssSeverity and mapOwaspCategory produce accurate defensive mappings', () => {
  assert.equal(classifyCvssSeverity(9.8), 'critical');
  assert.equal(classifyCvssSeverity(7.5), 'high');
  assert.equal(classifyCvssSeverity(5.3), 'medium');
  assert.equal(classifyCvssSeverity(2.1), 'low');

  assert.ok(mapOwaspCategory('Remote code execution via SQL injection', ['CWE-89']).includes('A03:2021'));
  assert.ok(mapOwaspCategory('Server-Side Request Forgery in webhook fetcher', ['CWE-918']).includes('A10:2021'));
  assert.ok(mapOwaspCategory('Path traversal allows reading arbitrary files', ['CWE-22']).includes('A01:2021'));
});

test('validateResearchMonitorInput enforces public targets, rate limits, and governance boundaries', () => {
  const badPrivate = validateResearchMonitorInput({
    name: 'Localhost watch',
    target: 'http://127.0.0.1:8080',
    monitorType: 'website_tech',
    cadence: 'daily',
    rateLimitPerHour: 2,
    sourcePolicy: 'respect_robots_strict',
  });
  assert.equal(badPrivate.valid, false);

  const badRate = validateResearchMonitorInput({
    name: 'Fast watch',
    target: 'OpenSSL CVEs',
    monitorType: 'cve_advisory',
    cadence: 'hourly',
    rateLimitPerHour: 50,
    sourcePolicy: 'official_advisories_only',
  });
  assert.equal(badRate.valid, false);

  const badExploit = validateResearchMonitorInput({
    name: 'Exploit watch',
    target: 'sqlmap exploit target',
    monitorType: 'web_topic',
    cadence: 'daily',
    rateLimitPerHour: 2,
    sourcePolicy: 'public_docs_only',
  });
  assert.equal(badExploit.valid, false);

  const validMonitor = validateResearchMonitorInput({
    name: 'Kubernetes Security Advisories',
    target: 'kubernetes',
    monitorType: 'cve_advisory',
    cadence: 'daily',
    rateLimitPerHour: 4,
    sourcePolicy: 'official_advisories_only',
  });
  assert.equal(validMonitor.valid, true);
});
