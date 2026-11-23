import type { ResearchSourceCitation } from './ginTypes.ts';

export type TechAnalysisCategory = 'frontend' | 'backend' | 'server';

export interface TechAnalysisRecord {
  id: string;
  userId: string;
  target: string;
  category: TechAnalysisCategory;
  title: string;
  summary: string;
  detectedTechnologies: string[];
  securityHeaders: string[];
  dnsSummary: string[];
  certSummary: string[];
  sources: ResearchSourceCitation[];
  confidenceScore: number;
  createdAtMs: number;
}

export type CveSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface CveAdvisoryRecord {
  id: string;
  userId: string;
  cveId: string;
  title: string;
  vendorProduct: string;
  severity: CveSeverity;
  cvssScore: number;
  cisaKev: boolean;
  owaspCategory: string;
  affectedVersions: string;
  mitigation: string;
  sourceUri: string;
  publishedDate: string;
  createdAtMs: number;
}

export type MonitorType = 'web_topic' | 'website_tech' | 'server_dns' | 'cve_advisory';
export type MonitorCadence = 'hourly' | 'daily' | 'weekly';
export type MonitorSourcePolicy =
  | 'respect_robots_strict'
  | 'official_advisories_only'
  | 'public_docs_only';

export interface ResearchMonitorRecord {
  id: string;
  userId: string;
  name: string;
  target: string;
  monitorType: MonitorType;
  cadence: MonitorCadence;
  rateLimitPerHour: number;
  sourcePolicy: MonitorSourcePolicy;
  enabled: boolean;
  lastRunSummary: string;
  lastRunAtMs: number;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface FrontendInspectionResult {
  origin: string;
  finalUrl: string;
  httpStatus: number;
  pageTitle: string;
  metaDescription: string;
  robotsPermitted: boolean;
  robotsPolicySummary: string;
  detectedTechnologies: string[];
  backendIndicators: string[];
  securityHeaders: string[];
  missingSecurityHeaders: string[];
  scriptCount: number;
  stylesheetCount: number;
  externalOrigins: string[];
  publicHeadings: string[];
  architectureSummary: string;
  confidenceScore: number;
}

export interface CertificateTransparencyEntry {
  issuerName: string;
  commonName: string;
  notBefore: string;
  notAfter: string;
}

export interface ServerIntelResult {
  hostname: string;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: string[];
  nsRecords: string[];
  txtRecords: string[];
  caaRecords: string[];
  certEntries: CertificateTransparencyEntry[];
  ctLookupStatus: 'live' | 'rate_limited_or_unavailable';
  inferredInfrastructure: string[];
  emailPosture: string[];
  architectureSummary: string;
  confidenceScore: number;
}

export interface SourceComparisonReport {
  topic: string;
  executiveSummary: string;
  agreements: string[];
  discrepancies: string[];
  verifiedFindings: string[];
  recommendedActions: string[];
  confidenceScore: number;
  sourceCount: number;
  generatedAtMs: number;
}
