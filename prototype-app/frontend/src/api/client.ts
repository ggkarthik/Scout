import * as Sentry from '@sentry/react';
import type {
  OwnershipRuleRequest,
  OwnershipRuleResponse,
  RiskPolicy,
  SuppressionRule,
  SuppressionRuleRequest,
} from '../features/configurations/types';
import type {
  Finding,
  FindingBulkWorkflowRequest,
  FindingBulkWorkflowResponse,
  FindingBacklogHealth,
  FindingDistributions,
  FindingFilterValues,
  FindingProjectionStatus,
  FindingQueueDefinition,
  FindingQueueUpsertRequest,
  FindingPage,
  FindingsFilterModel,
  FindingSummary
} from '../features/findings/types';
import type {
  ApplicableSoftwarePage,
  Dashboard,
  DashboardCveInventoryMap,
  GridExposure,
  ImpactedCvePage
} from '../features/dashboard/types';
import type { CreateServiceNowIncidentRequest, ServiceNowIncidentResponse } from '../features/cve-workbench/types';
import type {
  ClusterImpactResult,
  ConnectorIssueGroup,
  CorrelationOverridePayload,
  NormalizationOverridePayload,
  OperationalDashboard,
  PerformanceScorecard,
  OperationalQualityFilterValues,
  OperationalQualityIssueDetail,
  OperationalQualityIssuePage,
  OperationalQualitySummary,
  OperationalSectionResponse,
  SloStatus,
  TenantAttentionRow,
  SoftwareIdentitySearchResult
} from '../features/operations/types';
import type {
  AwsConnectionTestResponse,
  AwsDiscoveryConfig,
  AwsDiscoveryConfigRequest,
  AwsDiscoveryTarget,
  AwsDiscoveryTargetRequest,
  AzureConnectionTestResponse,
  AzureDiscoveryConfig,
  AzureDiscoveryConfigRequest,
  AzureDiscoveryTarget,
  AzureDiscoveryTargetRequest,
  CmdbAssetRecord,
  CmdbAssetSyncResponse,
  GithubSbomSource,
  IngestionEvidence,
  IngestionResult,
  SccmCmdbConfig,
  SccmCmdbConfigRequest,
  SccmConnectionTestResponse,
  ServiceNowCmdbConfig,
  ServiceNowCmdbConfigRequest,
  ServiceNowCmdbConnectionTest,
  SyncRun,
  SyncTriggerResponse,
  VexAssertionRepairSummary,
  VulnerabilitySourceFilterConfig,
  VulnerabilitySourceFilterConfigRequest,
  VulnerabilitySourceSystem
} from '../features/connect/types';
import type {
  Asset,
  HostAssetDetail,
  InventoryComponentFilterValues,
  InventoryComponentPage
} from '../features/inventory/api-types';
import type { PlatformVulnIntelDetail, PlatformVulnSourceStats, VulnRepoDashboard } from '../features/vuln-repo-dashboard/types';
import type {
  AuditEvent,
  AllowedTenant,
  AuthContext,
  DemoInvite,
  DemoInviteValidationResponse,
  DemoSetupLink,
  DemoRequest,
  DemoRequestCreateRequest,
  DemoStatus,
  AuthTokenResponse,
  InventoryConnectorHealth,
  PlatformUser,
  PlatformUserRequest,
  PlatformUserSetupLink,
  PlatformOwnerTenantMembershipRequest,
  ServiceAccount,
  ServiceAccountRequest,
  Tenant,
  TenantBulkInviteResponse,
  TenantInvite,
  TenantInviteRequest,
  TenantInviteValidationResponse,
  TenantCreateRequest,
  TenantSchemaStatusPage,
  TenantMember,
  TenantMemberRequest,
  TenantMemberUpdateRequest,
  TenantSupportGrant,
  TenantSupportGrantRequest
} from '../features/admin/types';

export type BomType = 'SBOM' | 'AI_BOM' | 'CBOM' | 'VENDOR';

export type BomFetchPayload = {
  bomType: BomType;
  assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
  assetName: string;
  assetIdentifier: string;
  sourceUrl: string;
  sourceLabel?: string;
  supplier?: string;
  authorizationHeader?: string;
};

export type BomIngestionResult = {
  bomId: string;
  assetId: string;
  bomType: string;
  format: string;
  formatVersion: string;
  specFamily: string;
  documentFormat: string;
  supportLevel: string;
  supported: boolean;
  warnings: string[];
  componentCount: number;
  findingsGenerated: number;
  status: string;
  action: string;
};

export type CbomPostureSummary = {
  id: string;
  assetId: string;
  assetName: string;
  lastSourceBomId: string | null;
  totalComponents: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  acceptedFindings: number;
  quantumVulnerable: number;
  weakAlgorithms: number;
  expiringCerts: number;
  postureScore: number | null;
  lastEvaluatedAt: string | null;
};

export type CbomComponent = {
  id: string;
  assetId: string;
  sourceBomId: string;
  bomRef: string | null;
  name: string;
  description: string | null;
  assetType: string;
  componentType: string | null;
  primitive: string | null;
  keySize: number | null;
  curve: string | null;
  padding: string | null;
  protocolVersion: string | null;
  state: string | null;
  format: string | null;
  storageLocation: string | null;
  transmission: string | null;
  sensitivity: string | null;
  usedIn: string | null;
  notAfter: string | null;
  riskScore: number | null;
  openFindingCount: number;
  highFindingCount: number;
  criticalFindingCount: number;
};

export type CbomRiskFinding = {
  id: string;
  componentId: string;
  componentName: string;
  assetId: string;
  ruleId: string;
  riskClass: string;
  severity: string;
  title: string;
  detail: string | null;
  evidence: string | null;
  recommendation: string | null;
  status: string;
  firstSeenAt: string;
  lastSeenAt: string;
};

export type IngestionJobAccepted = {
  jobId: string;
  status: string;
  message: string;
  existingJob: boolean;
  retryAfterSeconds: number | null;
};

export type IngestionJob = {
  jobId: string;
  jobType: string;
  sourceType: string;
  assetIdentifier: string;
  status: string;
  requestedBy: string | null;
  requestedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  attemptCount: number;
  failureCode: string | null;
  failureMessage: string | null;
  sbomUploadId: string | null;
  resultJson: string | null;
};

export type BomComponentSummaryItem = {
  componentId: string;
  packageName: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  license: string | null;
  assetId: string;
  assetName: string;
  bomTypes: string[];
  isEol: boolean;
  eolDate: string | null;
  criticalCveCount: number;
  highCveCount: number;
  mediumCveCount: number;
  lowCveCount: number;
  totalCveCount: number;
  correlationState: 'APPLICABLE' | 'NOT_APPLICABLE' | 'UNKNOWN' | 'UNCHECKED';
  riskLevel: string;
  findingCount: number;
  criticalFindingCount: number;
  highFindingCount: number;
};

export type ApplicationCveItem = {
  vulnerabilityId: string;
  componentId: string;
  externalId: string;
  severity: string | null;
  cvssScore: number | null;
  epssScore: number | null;
  packageName: string;
  version: string | null;
  lastEvaluatedAt: string | null;
};

export type BomComponentCveSummary = {
  cveId: string;
  externalId: string;
  severity: string | null;
  title: string | null;
  applicabilityState: string;
  epssScore: number | null;
  cvssScore: number | null;
};

export type EolReleaseSummary = {
  cycle: string;
  releaseDate: string | null;
  eolDate: string | null;
  supportEndDate: string | null;
  latestVersion: string | null;
  latestReleaseDate: string | null;
  isEol: boolean;
  isLts: boolean;
};

export type BomComponentDetail = BomComponentSummaryItem & {
  packageGroup: string | null;
  scope: string | null;
  normalizedName: string | null;
  eolSlug: string | null;
  eolCycle: string | null;
  eolSupportEndDate: string | null;
  supportPhase: string | null;
  eolCheckedAt: string | null;
  ingestedAt: string;
  lastObservedAt: string;
  assetIdentifier: string;
  assetType: string | null;
  cves: BomComponentCveSummary[];
  eolReleases: EolReleaseSummary[];
};

export type ApplicationRiskSummary = {
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  businessCriticality: string;
  bomTypes: string[];
  totalComponents: number;
  vulnerableComponents: number;
  eolComponents: number;
  criticalCveCount: number;
  highCveCount: number;
  mediumCveCount: number;
  lowCveCount: number;
  totalCveCount: number;
  riskScore: number;
  riskLevel: string;
  lastIngestedAt: string | null;
  findingCount: number;
};

export type BomInventoryItem = {
  id: string;
  assetId: string;
  bomType: string;
  format: string;
  formatVersion: string;
  specFamily: string;
  documentFormat: string;
  serialNumber: string;
  supplier: string;
  sourceMethod: string;
  sourceType: string;
  sourceSystem: string;
  sourceUrl: string;
  supportLevel: string;
  supported: boolean;
  componentCount: number;
  evidenceCount: number;
  vulnerabilityLinkCount: number;
  correlatedComponentCount: number;
  status: string;
  ingestedAt: string;
  ingestedBy: string;
};

export type BomComponent = {
  id: string;
  name: string;
  version: string;
  purl: string;
  cpe: string;
  license: string;
  supplier: string;
  componentType: string;
  category: string;
  workflowStatus: string;
  vulnerabilityCount: number;
  evidenceCount: number;
  active: boolean;
};

export type BomWorkflowSummary = {
  workflowStatus: string;
  componentCount: number;
};

export type BomInspection = {
  format: string;
  formatVersion: string;
  specFamily: string;
  documentFormat: string;
  supportLevel: string;
  supported: boolean;
  warnings: string[];
};

export type BomSupportEntry = {
  specFamily: string;
  documentFormat: string;
  version: string;
  supportLevel: string;
  supported: boolean;
  notes: string;
};

export type BomSupportMatrix = {
  entries: BomSupportEntry[];
};

export type BomDashboardBreakdownItem = {
  key: string;
  label: string;
  count: number;
};

export type BomDashboard = {
  documentCount: number;
  componentCount: number;
  evidenceCount: number;
  vulnerabilityLinkCount: number;
  correlatedComponentCount: number;
  activeWorkflowCount: number;
  openRemediationCount: number;
  sourceSystemCount: number;
  bomTypes: BomDashboardBreakdownItem[];
  specFamilies: BomDashboardBreakdownItem[];
  sourceSystems: BomDashboardBreakdownItem[];
  workflowStatuses: BomDashboardBreakdownItem[];
};

export type BomLineageItem = {
  id: string;
  previousBomId: string | null;
  supersededBy: string | null;
  bomType: string;
  status: string;
  format: string;
  formatVersion: string;
  specFamily: string;
  documentFormat: string;
  sourceType: string;
  sourceSystem: string;
  sourceReference: string;
  checksumSha256: string;
  componentCount: number;
  ingestedAt: string;
};

export type BomDetail = BomInventoryItem & {
  sourceReference: string;
  checksumSha256: string;
  inspection: BomInspection;
  workflowSummary: BomWorkflowSummary[];
  components: BomComponent[];
};

export type VulnIntelSourceStatus = {
  status: 'completed' | 'failed' | 'running' | 'never';
  completedAt?: string;
  recordsInserted: number;
  recordsUpdated: number;
  recordsFetched: number;
  errorMessage?: string;
};
export type VulnIntelSourcesSummary = {
  sources: Record<string, VulnIntelSourceStatus>;
};
import type {
  EolComponentPage,
  EolProductCatalog,
  EolRelease,
  EolSlugSuggestion,
  EolSummary,
  PackageAssetPage,
  PackageEolStatusPage,
  UnresolvedEolMappingPage
} from '../features/eol/types';
import type {
  SoftwareIdentityCoverage,
  SoftwareIdentityDetail,
  SoftwareIdentityFunnel,
  SoftwareIdentityMetadata,
  SoftwareIdentityMetadataRequest,
  SoftwareIdentityPage,
  VulnRepoSoftwareAssetsDetail
} from '../features/software-identities/types';
import type {
  CampaignCreateRequest,
  CampaignDetail,
  CampaignException,
  CampaignExceptionRequest,
  CampaignExceptionStatus,
  CampaignNote,
  CampaignNotifyGroupRequest,
  CampaignStatus,
  CampaignSummary,
  CampaignWatchlistEntryUpdateRequest,
} from '../features/campaigns/types';

export type CampaignAdvisory = {
  title: string;
  cveId: string;
  severity: string;
  type: string;
  publishedDate: string | null;
  summary: string;
};

export type CampaignAiResponse = {
  text: string | null;
  advisories: CampaignAdvisory[] | null;
  generatedAt: string;
};
import { resolveApiBase } from './base';
import type {
  AiArtifactSummary,
  AiSecurityArtifact,
  AiSecurityConnectionTest,
  AiSecurityConnectorConfig,
  AiSecurityAzureConnectionTest,
  AiSecurityAzureConnector,
  AiSecurityAzureCredentialProfile,
  AiSecurityAzureFoundryConfig,
  AiSecurityAzureRequirements,
  AiSecurityFinding,
  AiSecurityGraph,
  AiSecurityPage,
  AiSecurityPolicy,
  AiSecurityRun,
  AiSecurityScope,
  AiSecuritySummary,
  AiSeverityGrid,
  AiTopRiskArtifact,
  AiGridSystem,
  AiGridCoverage,
  AiGridCoverageDimension,
  AiGridPolicy,
  AiGridPolicyDistribution,
  AiGridPolicyImpactPreview,
  AiGridPolicyReleaseReadiness,
  AiGridPolicyTenantReconciliation,
  AiGridPolicyRetirementStatus,
  AiGridOwaspCoverage,
  AiGridPolicyCandidate,
  AiGridPolicySelection,
  AiGridOwner,
  AiGridRunMetrics,
  AiGridExposurePage,
  AiGridExposureDetail,
  AiExposureIntelligenceOverview,
  AiExposurePriority,
  AiActionQueueItem,
  AiAssetPosture,
  PolicyAssistExplanation,
  PolicyConfiguration,
  PolicyExceptionOverride,
  PolicyScopeCondition,
  PolicyScopeMode,
} from '../features/ai-security/types';

const API_BASE = resolveApiBase();
const API_KEY = import.meta.env.VITE_API_KEY ?? (import.meta.env.DEV ? 'change-me-in-prod' : '');
const CREATOR_KEY = import.meta.env.VITE_CREATOR_KEY ?? (import.meta.env.DEV ? 'local-creator' : '');
const DEFAULT_TENANT_ID = import.meta.env.VITE_TENANT_ID ?? (import.meta.env.DEV ? '1' : '');
const DEFAULT_USER_ID = import.meta.env.VITE_USER_ID ?? (import.meta.env.DEV ? 'local-analyst' : '');
const STATIC_AUTH_TOKEN = import.meta.env.VITE_AUTH_TOKEN ?? '';
const AUTH_TOKEN_STORAGE_KEY = 'vulnwatch.authToken';

export type TestPersona = {
  key: string;
  label: string;
  subject: string;
  tenantSlug: string | null;
  tenantName: string | null;
  roles: string[];
};

export type TestPersonaToken = {
  token: string;
  tokenType: 'Bearer';
  expiresAt: string;
  persona: TestPersona;
};

type ApiErrorPayload = {
  code?: string;
  error?: string;
  message?: string;
  fields?: Record<string, string>;
};

function isJwtAuthFailure(status: number, payload?: ApiErrorPayload, fallbackText?: string): boolean {
  if (status !== 401 && status !== 403) {
    return false;
  }
  const combined = [
    payload?.code,
    payload?.error,
    payload?.message,
    fallbackText,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  const tokenFailure = combined.includes('invalid jwt')
    || combined.includes('jwt')
    || combined.includes('token expired')
    || combined.includes('expired token')
    || combined.includes('invalid token')
    || combined.includes('token invalid')
    || combined.includes('bearer token');
  if (tokenFailure) {
    return true;
  }
  return status === 401 && combined.includes('unauthorized');
}

function handleJwtAuthFailure(): void {
  clearStoredAuthToken();
  if (typeof window === 'undefined') {
    return;
  }
  const next = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  const isLoginPage = window.location.pathname === '/login';
  if (!isLoginPage) {
    window.location.assign(`/login?next=${encodeURIComponent(next)}`);
  }
}

function formatApiError(payload: ApiErrorPayload, fallback: string): string {
  const baseMessage = payload.error || payload.message || fallback;
  const codePrefix = payload.code ? `[${payload.code}] ` : '';
  if (!payload.fields || Object.keys(payload.fields).length === 0) {
    return `${codePrefix}${baseMessage}`;
  }
  const fieldDetails = Object.entries(payload.fields)
    .map(([field, msg]) => `${field}: ${msg}`)
    .join(', ');
  return `${codePrefix}${baseMessage} (${fieldDetails})`;
}

async function parseApiError(response: Response): Promise<Error> {
  const fallback = `Request failed (${response.status})`;
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    try {
      const payload = await response.json() as ApiErrorPayload;
      if (isJwtAuthFailure(response.status, payload)) {
        handleJwtAuthFailure();
      }
      return new Error(formatApiError(payload, fallback));
    } catch {
      return new Error(fallback);
    }
  }

  const text = (await response.text()).trim();
  if (isJwtAuthFailure(response.status, undefined, text)) {
    handleJwtAuthFailure();
  }
  return new Error(text || fallback);
}

export function getStoredAuthToken(): string {
  return typeof window === 'undefined' ? '' : window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY) ?? '';
}

export function setStoredAuthToken(token: string): void {
  if (typeof window === 'undefined') {
    return;
  }
  const normalized = token.trim();
  if (normalized.length === 0) {
    window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
    return;
  }
  window.localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, normalized);
}

export function clearStoredAuthToken(): void {
  if (typeof window !== 'undefined') {
    window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
  }
}

function applyAuthHeaders(headers: Headers): void {
  const authToken = getStoredAuthToken().trim() || STATIC_AUTH_TOKEN.trim();
  if (authToken.length > 0) {
    headers.set('Authorization', `Bearer ${authToken}`);
    return;
  }
  if (API_KEY.trim().length > 0) {
    headers.set('X-API-Key', API_KEY.trim());
  }
  if (CREATOR_KEY.trim().length > 0) {
    headers.set('X-Creator-Key', CREATOR_KEY);
  }
  if (DEFAULT_TENANT_ID.trim().length > 0) {
    headers.set('X-Tenant-ID', DEFAULT_TENANT_ID.trim());
  }
  if (DEFAULT_USER_ID.trim().length > 0) {
    headers.set('X-User-ID', DEFAULT_USER_ID.trim());
  }
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) {
    return null;
  }
  try {
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function extractTokenRoles(payload: Record<string, unknown>): string[] {
  const directRoles = Array.isArray(payload.roles) ? payload.roles : null;
  if (directRoles) {
    return directRoles.map(String);
  }

  for (const [claimName, value] of Object.entries(payload)) {
    if (!claimName.endsWith('/roles') || !Array.isArray(value)) {
      continue;
    }
    return value.map(String);
  }

  return [];
}

function currentPlatformTenantContext():
  | { tenantId: string; roles: string[] }
  | null {
  const token = getStoredAuthToken().trim() || STATIC_AUTH_TOKEN.trim();
  if (!token) {
    return null;
  }
  const payload = decodeJwtPayload(token);
  if (!payload) {
    return null;
  }
  const rawRoles = extractTokenRoles(payload);
  const roles = rawRoles.map((role) => role.replace(/^ROLE_/, '').toUpperCase());
  if (!roles.includes('PLATFORM_OWNER')) {
    return null;
  }
  const tenantId = String(payload.active_tenant_id ?? payload.tenant_id ?? '').trim();
  return tenantId ? { tenantId, roles } : null;
}

function shouldConfirmPlatformAction(path: string, method: string): boolean {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
    return false;
  }
  if (path.startsWith('/auth/')) {
    return false;
  }
  const sensitivePrefixes = [
    '/tenants/',
    '/service-accounts',
    '/connectors/aws-discovery',
    '/connectors/servicenow-cmdb',
    '/connectors/sccm-cmdb',
    '/connectors/vulnerability-sources',
    '/github-sbom-sources',
    '/suppression-rules',
    '/ownership-rules',
    '/risk-policy',
    '/findings',
    '/cve-detail',
    '/operations/quality/issues/',
    '/inventory/software-identities/',
  ];
  return sensitivePrefixes.some((prefix) => path.startsWith(prefix));
}

function buildApiHeaders(base?: HeadersInit, includeJsonContentType = true): Headers {
  const headers = new Headers(base ?? {});
  if (includeJsonContentType) {
    headers.set('Content-Type', 'application/json');
  }
  applyAuthHeaders(headers);
  return headers;
}

function recordApiTiming(path: string, method: string, durationMs: number, status: number, requestId: string | null) {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('scout:api-request', {
      detail: {
        path,
        method,
        durationMs,
        status,
        requestId,
      }
    }));
  }

  Sentry.addBreadcrumb({
    category: 'api',
    level: status >= 400 ? 'warning' : 'info',
    message: `${method} ${path} -> ${status} (${durationMs}ms)`,
    data: requestId ? { requestId } : undefined
  });
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = buildApiHeaders(options?.headers);
  const method = options?.method?.toUpperCase() ?? 'GET';
  const startedAt = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const platformTenantContext = typeof window === 'undefined' ? null : currentPlatformTenantContext();
  if (platformTenantContext && shouldConfirmPlatformAction(path, method)) {
    const confirmed = window.confirm(`Confirm action for tenant ${platformTenantContext.tenantId} as Platform Owner.`);
    if (!confirmed) {
      throw new Error('Action cancelled');
    }
    headers.set('X-Platform-Action-Confirm', 'true');
    headers.set('X-Platform-Action-Tenant', platformTenantContext.tenantId);
    headers.set('X-Platform-Action-Time', new Date().toISOString());
  }
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: 'include'
  });
  const endedAt = typeof performance !== 'undefined' ? performance.now() : Date.now();
  recordApiTiming(
    path,
    method,
    Math.round(endedAt - startedAt),
    response.status,
    response.headers.get('X-Request-ID')
  );

  if (!response.ok) {
    throw await parseApiError(response);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    return undefined as T;
  }
  return response.json();
}

export { request as apiRequest };

async function publicRequest<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers ?? {});
  if (!(options?.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: 'include'
  });
  if (!response.ok) {
    throw await parseApiError(response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  const contentType = response.headers.get('content-type') ?? '';
  return contentType.includes('application/json') ? response.json() : undefined as T;
}

function buildFindingsSearchParams(params?: FindingsFilterModel): URLSearchParams {
  const searchParams = new URLSearchParams();
  if (params?.page != null) searchParams.set('page', String(params.page));
  if (params?.size != null) searchParams.set('size', String(params.size));
  if (params?.cursor && params.cursor.trim().length > 0) searchParams.set('cursor', params.cursor.trim());
  if (params?.limit != null) searchParams.set('limit', String(params.limit));
  if (params?.queueKey && params.queueKey.trim().length > 0) searchParams.set('queueKey', params.queueKey.trim());
  params?.severity?.forEach((value) => searchParams.append('severity', value));
  params?.status?.forEach((value) => searchParams.append('status', value));
  params?.decisionState?.forEach((value) => searchParams.append('decisionState', value));
  params?.creationSource?.forEach((value) => searchParams.append('creationSource', value));
  params?.matchMethod?.forEach((value) => searchParams.append('matchMethod', value));
  params?.vexStatus?.forEach((value) => searchParams.append('vexStatus', value));
  params?.vexFreshness?.forEach((value) => searchParams.append('vexFreshness', value));
  params?.vexProvider?.forEach((value) => searchParams.append('vexProvider', value));
  if (params?.minConfidence != null) searchParams.set('minConfidence', String(params.minConfidence));
  if (params?.vulnerabilityId && params.vulnerabilityId.trim().length > 0) searchParams.set('vulnerabilityId', params.vulnerabilityId.trim());
  if (params?.packageName && params.packageName.trim().length > 0) searchParams.set('packageName', params.packageName.trim());
  if (params?.ecosystem && params.ecosystem.trim().length > 0) searchParams.set('ecosystem', params.ecosystem.trim());
  if (params?.ownerGroup && params.ownerGroup.trim().length > 0) searchParams.set('ownerGroup', params.ownerGroup.trim());
  if (params?.assignedTo && params.assignedTo.trim().length > 0) searchParams.set('assignedTo', params.assignedTo.trim());
  if (params?.unassignedOnly != null) searchParams.set('unassignedOnly', String(params.unassignedOnly));
  if (params?.incidentLinked != null) searchParams.set('incidentLinked', String(params.incidentLinked));
  if (params?.dueDateBand) searchParams.set('dueDateBand', params.dueDateBand);
  if (params?.assetName && params.assetName.trim().length > 0) searchParams.set('assetName', params.assetName.trim());
  if (params?.supportGroup && params.supportGroup.trim().length > 0) searchParams.set('supportGroup', params.supportGroup.trim());
  if (params?.patchAvailable != null) searchParams.set('patchAvailable', String(params.patchAvailable));
  if (params?.suppressedUntilBand) searchParams.set('suppressedUntilBand', params.suppressedUntilBand);
  params?.assetType?.forEach((value) => searchParams.append('assetType', value));
  return searchParams;
}

export const api = {
  createDemoRequest: (payload: DemoRequestCreateRequest) => publicRequest<DemoRequest>('/demo-requests', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  listAssignmentGroups: () => request<string[]>('/cve-detail/servicenow/assignment-groups'),
  validateDemoInvite: (token: string) => publicRequest<DemoInviteValidationResponse>(`/demo-invites/${encodeURIComponent(token)}`),
  acceptDemoInvite: (token: string) => publicRequest<DemoInviteValidationResponse>(`/demo-invites/${encodeURIComponent(token)}/accept`, {
    method: 'POST'
  }),
  validateTenantInvite: (token: string) => publicRequest<TenantInviteValidationResponse>(`/tenant-invites/${encodeURIComponent(token)}`),
  acceptTenantInvite: (token: string) => publicRequest<TenantInviteValidationResponse>(`/tenant-invites/${encodeURIComponent(token)}/accept`, {
    method: 'POST'
  }),
  getDemoStatus: () => request<DemoStatus>('/demo/status'),
  listDemoRequests: () => request<DemoRequest[]>('/platform/demo-requests'),
  approveDemoRequest: (requestId: string, addDemoData = false) => request<DemoRequest>(`/platform/demo-requests/${requestId}/approve`, {
    method: 'POST',
    body: JSON.stringify({ addDemoData })
  }),
  seedTenantDemoData: (tenantId: string) => request<unknown>(`/platform/tenants/${encodeURIComponent(tenantId)}/demo-data`, {
    method: 'POST'
  }),
  rejectDemoRequest: (requestId: string, reason?: string) => request<DemoRequest>(`/platform/demo-requests/${requestId}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason: reason ?? '' })
  }),
  resendDemoInvite: (requestId: string) => request<DemoInvite>(`/platform/demo-requests/${requestId}/resend-invite`, { method: 'POST' }),
  issueDemoSetupLink: (requestId: string) => request<DemoSetupLink>(`/platform/demo-requests/${requestId}/issue-setup-link`, { method: 'POST' }),
  deleteDemoRequest: (requestId: string) => request<void>(`/platform/demo-requests/${requestId}`, { method: 'DELETE' }),
  getDashboard: () => request<Dashboard>('/dashboard'),
  getVulnRepoDashboard: () => request<VulnRepoDashboard>('/vuln-repo/dashboard'),
  getPlatformVulnRepoDashboard: () => request<VulnRepoDashboard>('/platform/vuln-repo/dashboard'),
  getPlatformVulnSourceStats: () => request<PlatformVulnSourceStats>('/platform/vuln-repo/source-stats'),
  getPlatformVulnIntelDetail: (externalId: string) => request<PlatformVulnIntelDetail>(`/platform/vuln-repo/intel/${encodeURIComponent(externalId)}`),
  listApplicableSoftware: (params?: { page?: number; size?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<ApplicableSoftwarePage>(`/dashboard/applicable-software${suffix}`);
  },
  listImpactedCves: (params?: { page?: number; size?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<ImpactedCvePage>(`/dashboard/impacted-cves${suffix}`);
  },
  getCveInventoryMap: (limit = 5) => request<DashboardCveInventoryMap>(`/dashboard/cve-inventory-map?limit=${limit}`),
  getGridExposure: () => request<GridExposure>('/dashboard/grid-exposure'),
  listFindings: (params?: FindingsFilterModel) => {
    const searchParams = buildFindingsSearchParams(params);
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<FindingPage>(`/findings${suffix}`);
  },
  getFinding: (findingId: string) => request<Finding>(`/findings/${encodeURIComponent(findingId)}`),
  getFindingSummary: (params?: FindingsFilterModel) => {
    const searchParams = buildFindingsSearchParams(params);
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<FindingSummary>(`/findings/summary${suffix}`);
  },
  getFindingDistributions: (params?: FindingsFilterModel) => {
    const searchParams = buildFindingsSearchParams(params);
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<FindingDistributions>(`/findings/distributions${suffix}`);
  },
  getFindingBacklogHealth: (params?: FindingsFilterModel) => {
    const searchParams = buildFindingsSearchParams(params);
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<FindingBacklogHealth>(`/findings/backlog-health${suffix}`);
  },
  getFindingProjectionStatus: () => request<FindingProjectionStatus>('/findings/projection-status'),
  rebuildFindingProjection: () => request<FindingProjectionStatus>('/findings/projection-rebuild', { method: 'POST' }),
  listFindingQueues: () => request<FindingQueueDefinition[]>('/findings/queues'),
  getFindingQueue: (queueKey: string) => request<FindingQueueDefinition>(`/findings/queues/${encodeURIComponent(queueKey)}`),
  createFindingQueue: (payload: FindingQueueUpsertRequest) => request<FindingQueueDefinition>('/findings/queues', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  updateFindingQueue: (queueRef: string, payload: FindingQueueUpsertRequest) => request<FindingQueueDefinition>(
    `/findings/queues/${encodeURIComponent(queueRef)}`,
    {
      method: 'PUT',
      body: JSON.stringify(payload)
    }
  ),
  duplicateFindingQueue: (queueRef: string) => request<FindingQueueDefinition>(
    `/findings/queues/${encodeURIComponent(queueRef)}/duplicate`,
    { method: 'POST' }
  ),
  setDefaultFindingQueue: (queueRef: string) => request<void>(
    `/findings/queues/${encodeURIComponent(queueRef)}/default`,
    { method: 'POST' }
  ),
  deleteFindingQueue: (queueRef: string) => request<void>(
    `/findings/queues/${encodeURIComponent(queueRef)}`,
    { method: 'DELETE' }
  ),
  listFindingFilters: () => request<FindingFilterValues>('/findings/filters'),
  getOperationalDashboard: () => request<OperationalDashboard>('/operations/dashboard'),
  getOperationalOverview: () => request<OperationalSectionResponse<OperationalDashboard['executiveHealth']>>('/operations/overview'),
  getOperationalIngestionEfficiency: () => request<OperationalSectionResponse<OperationalDashboard['ingestionEfficiency']>>('/operations/ingestion-efficiency'),
  getOperationalNormalizationQuality: () => request<OperationalSectionResponse<OperationalDashboard['normalizationQuality']>>('/operations/normalization-quality'),
  getOperationalCorrelationEffectiveness: () => request<OperationalSectionResponse<OperationalDashboard['correlationEffectiveness']>>('/operations/correlation-effectiveness'),
  getOperationalNoiseLifecycle: () => request<OperationalSectionResponse<OperationalDashboard['noiseLifecycle']>>('/operations/noise-lifecycle'),
  getOperationalApiReadPath: () => request<OperationalSectionResponse<OperationalDashboard['apiReadPath']>>('/operations/api-read-path'),
  getOperationalFreshnessDrift: () => request<OperationalSectionResponse<OperationalDashboard['freshnessDrift']>>('/operations/freshness-drift'),
  getOperationalMetricCatalog: () => request<OperationalSectionResponse<OperationalDashboard['metricCatalog']>>('/operations/metric-catalog'),
  getOperationalPerformanceScorecard: () => request<PerformanceScorecard>('/operations/performance-scorecard'),
  getOperationalTenantAttention: () => request<TenantAttentionRow[]>('/operations/tenant-attention'),
  getOperationalConnectorIssues: () => request<ConnectorIssueGroup[]>('/operations/connector-issues'),
  getOperationalQualitySummary: () => request<OperationalQualitySummary>('/operations/quality/summary'),
  listOperationalQualityIssues: (
    params?: {
      domain?: string;
      issueType?: string;
      severity?: string;
      affectsActiveFindings?: boolean;
      assetType?: Array<'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'>;
      sourceSystem?: string[];
      ecosystem?: string[];
      query?: string;
      page?: number;
      size?: number;
    }
  ) => {
    const searchParams = new URLSearchParams();
    if (params?.domain) searchParams.set('domain', params.domain);
    if (params?.issueType) searchParams.set('issueType', params.issueType);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.affectsActiveFindings != null) searchParams.set('affectsActiveFindings', String(params.affectsActiveFindings));
    params?.assetType?.forEach((value) => searchParams.append('assetType', value));
    params?.sourceSystem?.forEach((value) => searchParams.append('sourceSystem', value));
    params?.ecosystem?.forEach((value) => searchParams.append('ecosystem', value));
    if (params?.query && params.query.trim().length > 0) searchParams.set('query', params.query.trim());
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<OperationalQualityIssuePage>(`/operations/quality/issues${suffix}`);
  },
  getOperationalQualityIssue: (issueId: string) => request<OperationalQualityIssueDetail>(
    `/operations/quality/issues/${encodeURIComponent(issueId)}`
  ),
  getOperationalQualityFilters: () => request<OperationalQualityFilterValues>('/operations/quality/filters'),
  getNormalizationImpact: (issueId: string) =>
    request<ClusterImpactResult>(
      `/operations/quality/issues/${encodeURIComponent(issueId)}/normalize/impact`
    ),
  applyNormalizationOverride: (issueId: string, payload: NormalizationOverridePayload) =>
    request<{ issueId: string; overrideActive: boolean; actor: string }>(
      `/operations/quality/issues/${encodeURIComponent(issueId)}/normalize`,
      { method: 'POST', body: JSON.stringify(payload) }
    ),
  revokeNormalizationOverride: (issueId: string) =>
    request<{ issueId: string; overrideActive: boolean; actor: string }>(
      `/operations/quality/issues/${encodeURIComponent(issueId)}/normalize`,
      { method: 'DELETE' }
    ),
  applyCorrelationOverride: (issueId: string, payload: CorrelationOverridePayload) =>
    request<{ issueId: string; overrideActive: boolean; actor: string }>(
      `/operations/quality/issues/${encodeURIComponent(issueId)}/correlate`,
      { method: 'POST', body: JSON.stringify(payload) }
    ),
  revokeCorrelationOverride: (issueId: string) =>
    request<{ issueId: string; overrideActive: boolean; actor: string }>(
      `/operations/quality/issues/${encodeURIComponent(issueId)}/correlate`,
      { method: 'DELETE' }
    ),
  searchSoftwareIdentities: (q: string, limit = 10) =>
    request<SoftwareIdentitySearchResult[]>(
      `/operations/software-identities/search?q=${encodeURIComponent(q)}&limit=${limit}`
    ),
  getSloStatus: () => request<SloStatus>('/slo/status'),
  listAssets: () => request<Asset[]>('/assets'),
  getHostAssetDetail: (assetId: string, params?: { sourceSystem?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.sourceSystem && params.sourceSystem.trim().length > 0) {
      searchParams.set('sourceSystem', params.sourceSystem.trim());
    }
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<HostAssetDetail>(`/assets/hosts/${encodeURIComponent(assetId)}${suffix}`);
  },
  listInventoryComponents: (
    params?: {
      assetType?: Array<'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'>;
      componentStatus?: Array<'ACTIVE' | 'RETIRED'>;
      sourceSystem?: string[];
      ecosystem?: string[];
      reviewCategory?: string[];
      query?: string;
      page?: number;
      size?: number;
    }
  ) => {
    const searchParams = new URLSearchParams();
    params?.assetType?.forEach((value) => searchParams.append('assetType', value));
    params?.componentStatus?.forEach((value) => searchParams.append('componentStatus', value));
    params?.sourceSystem?.forEach((value) => searchParams.append('sourceSystem', value));
    params?.ecosystem?.forEach((value) => searchParams.append('ecosystem', value));
    params?.reviewCategory?.forEach((value) => searchParams.append('reviewCategory', value));
    if (params?.query && params.query.trim().length > 0) searchParams.set('query', params.query.trim());
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<InventoryComponentPage>(`/inventory/components${suffix}`);
  },
  listInventoryComponentFilters: () => request<InventoryComponentFilterValues>('/inventory/components/filters'),
  listSoftwareIdentities: (
    params?: {
      assetType?: Array<'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'>;
      sourceSystem?: string[];
      ecosystem?: string[];
      lifecycle?: 'eol' | 'near-eol' | 'unknown' | 'supported';
      mappingState?: 'needs-review' | 'mapped' | 'manual' | 'automatic';
      coverage?: SoftwareIdentityCoverage;
      operatingSystem?: string;
      query?: string;
      page?: number;
      size?: number;
    }
  ) => {
    const searchParams = new URLSearchParams();
    params?.assetType?.forEach((value) => searchParams.append('assetType', value));
    params?.sourceSystem?.forEach((value) => searchParams.append('sourceSystem', value));
    params?.ecosystem?.forEach((value) => searchParams.append('ecosystem', value));
    if (params?.lifecycle) searchParams.set('lifecycle', params.lifecycle);
    if (params?.mappingState) searchParams.set('mappingState', params.mappingState);
    if (params?.coverage) searchParams.set('coverage', params.coverage);
    if (params?.operatingSystem && params.operatingSystem.trim().length > 0) searchParams.set('operatingSystem', params.operatingSystem.trim());
    if (params?.query && params.query.trim().length > 0) searchParams.set('query', params.query.trim());
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<SoftwareIdentityPage>(`/inventory/software-identities${suffix}`);
  },
  getSoftwareIdentityFunnel: () => request<SoftwareIdentityFunnel>('/inventory/software-identities/funnel'),
  getSoftwareIdentityDetail: (softwareIdentityId: string) => request<SoftwareIdentityDetail>(
    `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`
  ),
  getSoftwareIdentityMetadata: (softwareIdentityId: string) => request<SoftwareIdentityMetadata>(
    `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}/metadata`
  ),
  saveSoftwareIdentityMetadata: (softwareIdentityId: string, req: SoftwareIdentityMetadataRequest) => request<SoftwareIdentityMetadata>(
    `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}/metadata`,
    { method: 'PUT', body: JSON.stringify(req) }
  ),
  getVulnRepoSoftwareAssets: (softwareIdentityId: string) => request<VulnRepoSoftwareAssetsDetail>(
    `/vuln-repo/software-assets/${encodeURIComponent(softwareIdentityId)}`
  ),
  syncAssetsFromCmdb: (assets: CmdbAssetRecord[]) => request<CmdbAssetSyncResponse>('/assets/cmdb-sync', {
    method: 'POST',
    body: JSON.stringify({ assets })
  }),
  getServiceNowCmdbConfig: () => request<ServiceNowCmdbConfig>('/connectors/servicenow-cmdb'),
  saveServiceNowCmdbConfig: (payload: ServiceNowCmdbConfigRequest) => request<ServiceNowCmdbConfig>('/connectors/servicenow-cmdb', {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  listVulnerabilitySourceFilterConfigs: () =>
    request<VulnerabilitySourceFilterConfig[]>('/connectors/vulnerability-sources'),
  getVulnerabilitySourceFilterConfig: (sourceSystem: VulnerabilitySourceSystem) =>
    request<VulnerabilitySourceFilterConfig>(`/connectors/vulnerability-sources/${encodeURIComponent(sourceSystem)}`),
  saveVulnerabilitySourceFilterConfig: (
    sourceSystem: VulnerabilitySourceSystem,
    payload: VulnerabilitySourceFilterConfigRequest
  ) => request<VulnerabilitySourceFilterConfig>(`/connectors/vulnerability-sources/${encodeURIComponent(sourceSystem)}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  testServiceNowCmdbConnection: () => request<ServiceNowCmdbConnectionTest>('/connectors/servicenow-cmdb/test', {
    method: 'POST'
  }),
  triggerServiceNowCmdbSync: () => request<SyncTriggerResponse>('/connectors/servicenow-cmdb/sync', {
    method: 'POST'
  }),
  getSccmCmdbConfig: () => request<SccmCmdbConfig>('/connectors/sccm-cmdb'),
  saveSccmCmdbConfig: (payload: SccmCmdbConfigRequest) => request<SccmCmdbConfig>('/connectors/sccm-cmdb', {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  testSccmCmdbConnection: () => request<SccmConnectionTestResponse>('/connectors/sccm-cmdb/test', {
    method: 'POST'
  }),
  triggerSccmCmdbSync: () => request<SyncTriggerResponse>('/connectors/sccm-cmdb/sync', {
    method: 'POST'
  }),
  getAwsDiscoveryConfig: () => request<AwsDiscoveryConfig>('/connectors/aws-discovery'),
  saveAwsDiscoveryConfig: (payload: AwsDiscoveryConfigRequest) => request<AwsDiscoveryConfig>('/connectors/aws-discovery', {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  testAwsDiscoveryConnection: () => request<AwsConnectionTestResponse>('/connectors/aws-discovery/test', {
    method: 'POST'
  }),
  triggerAwsDiscoverySync: () => request<SyncTriggerResponse>('/connectors/aws-discovery/sync', {
    method: 'POST'
  }),
  listAwsDiscoveryTargets: () => request<AwsDiscoveryTarget[]>('/connectors/aws-discovery/targets'),
  createAwsDiscoveryTarget: (payload: AwsDiscoveryTargetRequest) => request<AwsDiscoveryTarget>('/connectors/aws-discovery/targets', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  updateAwsDiscoveryTarget: (targetId: string, payload: AwsDiscoveryTargetRequest) => request<AwsDiscoveryTarget>(`/connectors/aws-discovery/targets/${encodeURIComponent(targetId)}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  deleteAwsDiscoveryTarget: (targetId: string) => request<void>(`/connectors/aws-discovery/targets/${encodeURIComponent(targetId)}`, {
    method: 'DELETE'
  }),
  testAwsDiscoveryTarget: (targetId: string) => request<AwsConnectionTestResponse>(`/connectors/aws-discovery/targets/${encodeURIComponent(targetId)}/test`, {
    method: 'POST'
  }),
  triggerAwsDiscoveryTargetSync: (targetId: string) => request<SyncTriggerResponse>(`/connectors/aws-discovery/targets/${encodeURIComponent(targetId)}/sync`, {
    method: 'POST'
  }),
  getAzureDiscoveryConfig: () => request<AzureDiscoveryConfig>('/connectors/azure-discovery'),
  saveAzureDiscoveryConfig: (payload: AzureDiscoveryConfigRequest) => request<AzureDiscoveryConfig>('/connectors/azure-discovery', {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  testAzureDiscoveryConnection: () => request<AzureConnectionTestResponse>('/connectors/azure-discovery/test', {
    method: 'POST'
  }),
  triggerAzureDiscoverySync: () => request<SyncTriggerResponse>('/connectors/azure-discovery/sync', {
    method: 'POST'
  }),
  listAzureDiscoveryTargets: () => request<AzureDiscoveryTarget[]>('/connectors/azure-discovery/targets'),
  createAzureDiscoveryTarget: (payload: AzureDiscoveryTargetRequest) => request<AzureDiscoveryTarget>('/connectors/azure-discovery/targets', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  updateAzureDiscoveryTarget: (targetId: string, payload: AzureDiscoveryTargetRequest) => request<AzureDiscoveryTarget>(`/connectors/azure-discovery/targets/${encodeURIComponent(targetId)}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  deleteAzureDiscoveryTarget: (targetId: string) => request<void>(`/connectors/azure-discovery/targets/${encodeURIComponent(targetId)}`, {
    method: 'DELETE'
  }),
  testAzureDiscoveryTarget: (targetId: string) => request<AzureConnectionTestResponse>(`/connectors/azure-discovery/targets/${encodeURIComponent(targetId)}/test`, {
    method: 'POST'
  }),
  triggerAzureDiscoveryTargetSync: (targetId: string) => request<SyncTriggerResponse>(`/connectors/azure-discovery/targets/${encodeURIComponent(targetId)}/sync`, {
    method: 'POST'
  }),
  listGithubSbomSources: () => request<GithubSbomSource[]>('/github-sbom-sources'),
  createGithubSbomSource: (
    payload: {
      name: string;
      owner: string;
      repo: string;
      path?: string;
      assetType?: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
      assetName?: string;
      assetIdentifier?: string;
      frequency?: 'ONCE' | 'INTERVAL';
      intervalMinutes?: number;
      enabled?: boolean;
      githubToken?: string;
    }
  ) => request<GithubSbomSource>('/github-sbom-sources', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  updateGithubSbomSource: (
    sourceId: string,
    payload: {
      name: string;
      owner: string;
      repo: string;
      path?: string;
      assetType?: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
      assetName?: string;
      assetIdentifier?: string;
      frequency?: 'ONCE' | 'INTERVAL';
      intervalMinutes?: number;
      enabled?: boolean;
      githubToken?: string;
    }
  ) => request<GithubSbomSource>(`/github-sbom-sources/${sourceId}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  deleteGithubSbomSource: (sourceId: string) => request<void>(`/github-sbom-sources/${sourceId}`, { method: 'DELETE' }),
  runGithubSbomSource: (sourceId: string) => request<SyncTriggerResponse>(`/github-sbom-sources/${sourceId}/run`, { method: 'POST' }),
  queueGithubGhcrRun: (owner: string) => request<SyncTriggerResponse>('/github-sbom-sources/ghcr/run', {
    method: 'POST',
    body: JSON.stringify({ owner })
  }),
  queueGithubRepositoryRun: (
    payload: {
      owner: string;
      repo?: string;
      includeAllRepos?: boolean;
      assetType?: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
      assetName?: string;
      assetIdentifier?: string;
      path?: string;
    }
  ) => request<SyncTriggerResponse>('/github-sbom-sources/repository/run', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  getRiskPolicy: () => request<RiskPolicy>('/risk-policy'),
  updateRiskPolicy: (policy: Partial<RiskPolicy>) => request<RiskPolicy>('/risk-policy', {
    method: 'POST',
    body: JSON.stringify(policy)
  }),
  executeAutoCloseNow: () => request<{ updated: number }>('/risk-policy/auto-close/execute-now', {
    method: 'POST'
  }),
  recomputeFindingsScores: () => request<{ updated: number }>('/risk-policy/recompute-findings-scores', {
    method: 'POST'
  }),
  listOwnershipRules: () => request<OwnershipRuleResponse[]>('/ownership-rules'),
  listCampaigns: (status?: CampaignStatus) =>
    request<CampaignSummary[]>(status ? `/campaigns?status=${encodeURIComponent(status)}` : '/campaigns'),
  getCampaign: (campaignId: string) =>
    request<CampaignDetail>(`/campaigns/${encodeURIComponent(campaignId)}`),
  generateCampaignAiInsights: (campaignId: string) =>
    request<CampaignAiResponse>(`/campaigns/${encodeURIComponent(campaignId)}/ai-insights`, {
      method: 'POST',
    }),
  generateCampaignAiAdvisories: (campaignId: string) =>
    request<CampaignAiResponse>(`/campaigns/${encodeURIComponent(campaignId)}/ai-advisories`, {
      method: 'POST',
    }),
  createCampaign: (payload: CampaignCreateRequest) =>
    request<CampaignDetail>('/campaigns', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateCampaignStatus: (campaignId: string, status: CampaignStatus, note?: string) =>
    request<CampaignDetail>(`/campaigns/${encodeURIComponent(campaignId)}/status`, {
      method: 'POST',
      body: JSON.stringify({ status, note }),
    }),
  addCampaignNote: (campaignId: string, body: string) =>
    request<CampaignNote>(`/campaigns/${encodeURIComponent(campaignId)}/notes`, {
      method: 'POST',
      body: JSON.stringify({ body }),
    }),
  addCampaignException: (campaignId: string, payload: CampaignExceptionRequest) =>
    request<CampaignException>(`/campaigns/${encodeURIComponent(campaignId)}/exceptions`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateCampaignExceptionStatus: (campaignId: string, exceptionId: string, status: CampaignExceptionStatus) =>
    request<CampaignDetail>(`/campaigns/${encodeURIComponent(campaignId)}/exceptions/${encodeURIComponent(exceptionId)}/status`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    }),
  updateCampaignNotifyGroup: (campaignId: string, notifyGroupId: string, payload: CampaignNotifyGroupRequest) =>
    request<CampaignDetail>(`/campaigns/${encodeURIComponent(campaignId)}/notify-groups/${encodeURIComponent(notifyGroupId)}`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateCampaignWatchlistEntry: (campaignId: string, watchlistEntryId: string, payload: CampaignWatchlistEntryUpdateRequest) =>
    request<CampaignDetail>(`/campaigns/${encodeURIComponent(campaignId)}/watchlist/${encodeURIComponent(watchlistEntryId)}`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getAiSecuritySummary: () => request<AiSecuritySummary>('/ai-security/summary'),
  listAiGridSystems: () => request<AiGridSystem[]>('/ai-systems'),
  getAiGridCoverage: () => request<AiGridCoverage>('/ai-coverage'),
  getAiGridCoverageDimensions: () => request<AiGridCoverageDimension[]>('/ai-coverage/dimensions'),
  listAiGridPolicies: () => request<AiGridPolicy[]>('/ai-policies'),
  listPlatformAiGridPolicies: () => request<AiGridPolicyDistribution[]>('/platform/ai-grid/policies'),
  updatePlatformAiGridPolicyDistribution: (
    policyId: string,
    payload: Pick<AiGridPolicyDistribution, 'available' | 'defaultSelection' | 'rolloutStage' | 'pinnedVersion'> & { canaryTenantIds: string[] },
  ) => request<AiGridPolicyDistribution>(`/platform/ai-grid/policies/${encodeURIComponent(policyId)}/distribution`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  }),
  getPlatformAiGridPolicyImpactPreview: (policyId: string, version: string, tenantId: string) => request<AiGridPolicyImpactPreview>(
    `/platform/ai-grid/policies/${encodeURIComponent(policyId)}/versions/${encodeURIComponent(version)}/impact-preview?tenantId=${encodeURIComponent(tenantId)}`,
  ),
  getPlatformAiGridPolicyReleaseReadiness: (policyId: string, version: string) => request<AiGridPolicyReleaseReadiness>(
    `/platform/ai-grid/policies/${encodeURIComponent(policyId)}/versions/${encodeURIComponent(version)}/release-readiness`,
  ),
  publishPlatformAiGridPolicy: (policyId: string, version: string) => request<{ published: boolean; reason: string }>(
    `/platform/ai-grid/policies/${encodeURIComponent(policyId)}/versions/${encodeURIComponent(version)}/publish`, { method: 'POST' },
  ),
  getPlatformAiGridPolicyReconciliation: () => request<AiGridPolicyTenantReconciliation[]>('/platform/ai-grid/policies/reconciliation'),
  migratePlatformAiGridLegacySelections: () => request<AiGridPolicyTenantReconciliation[]>('/platform/ai-grid/policies/reconciliation/migrate-legacy-selections', { method: 'POST' }),
  getPlatformAiGridPolicyRetirementStatus: () => request<AiGridPolicyRetirementStatus>('/platform/ai-grid/policies/reconciliation/retirement-status'),
  getPlatformAiGridOwaspCoverage: () => request<AiGridOwaspCoverage[]>('/platform/ai-grid/policies/portfolio/owasp'),
  getPlatformAiGridPolicyCandidates: () => request<AiGridPolicyCandidate[]>('/platform/ai-grid/policies/portfolio/candidates'),
  createPlatformAiGridPolicyCandidate: (payload: {
    title: string; sourceType: string; status: string; technologyId?: string; rationale: string;
    frameworkMappings: Record<string, unknown>; riskScore: number; reachScore: number;
    evidenceMaturity: number; remediationClarity: number; owner?: string;
  }) => request<AiGridPolicyCandidate>('/platform/ai-grid/policies/portfolio/candidates', { method: 'POST', body: JSON.stringify(payload) }),
  updateAiGridPolicySelection: (policyId: string, selection: AiGridPolicySelection, reason?: string) =>
    request<AiGridPolicy[]>(`/ai-policies/${encodeURIComponent(policyId)}/selection`, {
      method: 'PUT',
      body: JSON.stringify({ selection, reason }),
    }),
  getAiGridRunMetrics: (runId: string) => request<AiGridRunMetrics>(
    `/ai-assessment-runs/${encodeURIComponent(runId)}/metrics`,
  ),
  listAiGridExposures: (cursor?: string, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (cursor) params.set('cursor', cursor);
    return request<AiGridExposurePage>(`/ai-exposures?${params.toString()}`);
  },
  getAiExposureIntelligenceOverview: () => request<AiExposureIntelligenceOverview>('/ai-overview'),
  listAiExposurePriorities: () => request<AiExposurePriority[]>('/ai-exposure-priorities'),
  listAiActionQueue: () => request<AiActionQueueItem[]>('/ai-action-queue'),
  getAiAssetPosture: (artifactId: string) => request<AiAssetPosture>(
    `/ai-assets/${encodeURIComponent(artifactId)}/posture`,
  ),
  getAiGridExposure: (exposureId: string) => request<AiGridExposureDetail>(
    `/ai-exposures/${encodeURIComponent(exposureId)}`,
  ),
  dispositionAiGridExposure: (exposureId: string, disposition: string, reason: string) => request<void>(
    `/ai-exposures/${encodeURIComponent(exposureId)}/disposition`, {
      method: 'POST', body: JSON.stringify({ disposition, reason }),
    },
  ),
  confirmAiGridArtifactOwner: (artifactId: string, ownerName: string, reason?: string) => request<AiGridOwner>(
    `/ai-artifacts/${encodeURIComponent(artifactId)}/owner`, {
      method: 'PUT',
      body: JSON.stringify({ ownerName, reason }),
    },
  ),
  listAiSecurityArtifacts: (
    artifactType?: string,
    page = 0,
    size = 50,
    provider?: 'AWS' | 'AZURE',
    subscription?: string,
    nativeKind?: string,
    severity?: string,
  ) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (artifactType) params.set('artifactType', artifactType);
    if (provider) params.set('provider', provider);
    if (subscription) params.set('subscription', subscription);
    if (nativeKind) params.set('nativeKind', nativeKind);
    if (severity) params.set('severity', severity);
    return request<AiSecurityPage<AiSecurityArtifact>>(`/ai-security/artifacts?${params.toString()}`);
  },
  listAiArtifactSummaries: (
    artifactType?: string,
    page = 0,
    size = 50,
    provider?: 'AWS' | 'AZURE',
    subscription?: string,
    nativeKind?: string,
    severity?: string,
  ) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (artifactType) params.set('artifactType', artifactType);
    if (provider) params.set('provider', provider);
    if (subscription) params.set('subscription', subscription);
    if (nativeKind) params.set('nativeKind', nativeKind);
    if (severity) params.set('severity', severity);
    return request<AiSecurityPage<AiArtifactSummary>>(`/ai-security/artifact-summaries?${params.toString()}`);
  },
  getAiSecurityArtifact: (artifactId: string) =>
    request<AiSecurityArtifact>(`/ai-security/artifacts/${encodeURIComponent(artifactId)}`),
  getAiSecurityGraph: (rootArtifactId?: string, depth?: number) => {
    const params = new URLSearchParams();
    if (rootArtifactId) params.set('rootArtifactId', rootArtifactId);
    if (depth) params.set('depth', String(depth));
    const suffix = params.toString() ? `?${params.toString()}` : '';
    return request<AiSecurityGraph>(`/ai-security/graph${suffix}`);
  },
  listAiSecurityFindings: (
    policyId?: string,
    status?: string,
    page = 0,
    size = 50,
    provider?: 'AWS' | 'AZURE',
    subscription?: string,
    severity?: string,
    nativeKind?: string,
  ) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (policyId) params.set('policyId', policyId);
    if (status) params.set('status', status);
    if (provider) params.set('provider', provider);
    if (subscription) params.set('subscription', subscription);
    if (severity) params.set('severity', severity);
    if (nativeKind) params.set('nativeKind', nativeKind);
    return request<AiSecurityPage<AiSecurityFinding>>(`/ai-security/findings?${params.toString()}`);
  },
  getAiSeverityGrid: () => request<AiSeverityGrid>('/ai-security/severity-grid'),
  getAiTopRiskArtifacts: (limit = 5) =>
    request<AiTopRiskArtifact[]>(`/ai-security/top-risk-artifacts?limit=${limit}`),
  getAiSecurityFinding: (findingId: string) =>
    request<AiSecurityFinding>(`/ai-security/findings/${encodeURIComponent(findingId)}`),
  updateFindingWorkflow: (findingId: string, payload: Record<string, unknown>) =>
    request(`/findings/${encodeURIComponent(findingId)}/workflow`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  createFindingIncident: (findingId: string, payload: CreateServiceNowIncidentRequest) =>
    request<ServiceNowIncidentResponse>(`/findings/${encodeURIComponent(findingId)}/servicenow-incident`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  reviewAiSecurityFinding: (
    findingId: string,
    disposition: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NEEDS_INVESTIGATION',
    reason?: string,
  ) => request<AiSecurityFinding>(`/ai-security/findings/${encodeURIComponent(findingId)}/review`, {
    method: 'PUT',
    body: JSON.stringify({ disposition, reason }),
  }),
  listAiSecurityPolicies: () => request<AiSecurityPolicy[]>('/ai-security/policies'),
  updateAiSecurityPolicy: (policyId: string, enabled: boolean) =>
    request<AiSecurityPolicy>(`/ai-security/policies/${encodeURIComponent(policyId)}/enabled`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }),
  getAiSecurityPolicyConfiguration: (policyId: string) =>
    request<PolicyConfiguration>(`/ai-security/policies/${encodeURIComponent(policyId)}/configuration`),
  updateAiSecurityPolicyScope: (
    policyId: string,
    mode: PolicyScopeMode,
    conditionLogic: 'AND' | 'OR',
    conditions: PolicyScopeCondition[],
  ) => request<PolicyConfiguration>(`/ai-security/policies/${encodeURIComponent(policyId)}/scope`, {
    method: 'PUT',
    body: JSON.stringify({ mode, conditionLogic, conditions }),
  }),
  addAiSecurityPolicyException: (
    policyId: string,
    artifactId: string,
    override: PolicyExceptionOverride,
    reason?: string,
  ) => request<PolicyConfiguration>(`/ai-security/policies/${encodeURIComponent(policyId)}/exceptions`, {
    method: 'POST',
    body: JSON.stringify({ artifactId, override, reason }),
  }),
  removeAiSecurityPolicyException: (policyId: string, artifactId: string) =>
    request<PolicyConfiguration>(
      `/ai-security/policies/${encodeURIComponent(policyId)}/exceptions/${encodeURIComponent(artifactId)}`,
      { method: 'DELETE' },
    ),
  updateAiSecurityPolicyParameters: (policyId: string, parameters: Record<string, string>) =>
    request<PolicyConfiguration>(`/ai-security/policies/${encodeURIComponent(policyId)}/parameters`, {
      method: 'PUT',
      body: JSON.stringify({ parameters }),
    }),
  explainAiSecurityPolicy: (policyId: string) =>
    request<PolicyAssistExplanation>(`/ai-security/policies/${encodeURIComponent(policyId)}/assist/explain`),
  listAiSecurityRuns: (provider?: 'AWS' | 'AZURE') =>
    request<AiSecurityRun[]>(`/ai-security/runs${provider ? `?provider=${provider}` : ''}`),
  listAiSecurityRunScopes: (runId: string) =>
    request<AiSecurityScope[]>(`/ai-security/runs/${encodeURIComponent(runId)}/scopes`),
  getAiSecurityConnector: () => request<AiSecurityConnectorConfig | null>('/connectors/ai-security/aws'),
  saveAiSecurityConnector: (payload: {
    accountId: string;
    roleArn?: string;
    externalId?: string;
    regions: string[];
    enabled: boolean;
  }) => request<AiSecurityConnectorConfig>('/connectors/ai-security/aws', {
    method: 'PUT',
    body: JSON.stringify(payload),
  }),
  testAiSecurityConnector: () =>
    request<AiSecurityConnectionTest>('/connectors/ai-security/aws/test', { method: 'POST' }),
  runAiSecurityConnector: () =>
    request<{ jobId: string; status: string; message: string }>('/connectors/ai-security/aws/run', { method: 'POST' }),
  listAiSecurityAzureConnectors: () =>
    request<AiSecurityAzureConnector[]>('/connectors/ai-security/azure'),
  getAiSecurityAzureRequirements: () =>
    request<AiSecurityAzureRequirements>('/connectors/ai-security/azure/requirements'),
  saveAiSecurityAzureConnector: (payload: {
    credentialProfileId: string;
    targetId: string;
    resourceFamilies?: string[];
    enabled: boolean;
  }) => request<AiSecurityAzureConnector>('/connectors/ai-security/azure', {
    method: 'PUT',
    body: JSON.stringify(payload),
  }),
  testAiSecurityAzureConnector: (connectorId: string) =>
    request<AiSecurityAzureConnectionTest>(
      `/connectors/ai-security/azure/${encodeURIComponent(connectorId)}/test`,
      { method: 'POST' },
    ),
  getAiSecurityAzureFoundryConfig: () =>
    request<AiSecurityAzureFoundryConfig>('/connectors/ai-security/azure-foundry'),
  saveAiSecurityAzureFoundryConfig: (payload: {
    foundryEndpointUrl?: string;
    azureTenantId: string;
    clientId: string;
    clientSecret?: string;
    subscriptionIds: string;
    region?: string;
  }) => request<AiSecurityAzureFoundryConfig>('/connectors/ai-security/azure-foundry', {
    method: 'PUT',
    body: JSON.stringify(payload),
  }),
  testAiSecurityAzureFoundryConfig: () =>
    request<AiSecurityAzureConnectionTest>('/connectors/ai-security/azure-foundry/test', { method: 'POST' }),
  runAiSecurityAzureFoundryConfig: () =>
    request<{ jobId: string; status: string; message: string }>(
      '/connectors/ai-security/azure-foundry/run',
      { method: 'POST' },
    ),
  runAiSecurityAzureConnector: (connectorId: string) =>
    request<{ jobId: string; status: string; message: string }>(
      `/connectors/ai-security/azure/${encodeURIComponent(connectorId)}/run`,
      { method: 'POST' },
    ),
  runAiSecurityAzureTarget: (targetId: string) =>
    request<{ jobId: string; status: string; message: string }>(
      `/connectors/ai-security/azure/targets/${encodeURIComponent(targetId)}/run`,
      { method: 'POST' },
    ),
  listAiSecurityAzureCredentials: () =>
    request<AiSecurityAzureCredentialProfile[]>('/connectors/ai-security/azure/credentials'),
  createAiSecurityAzureCredential: (payload: {
    name: string;
    azureTenantId: string;
    clientId?: string;
    clientSecret?: string;
    expiresAt?: string;
  }) => request<AiSecurityAzureCredentialProfile>('/connectors/ai-security/azure/credentials', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  testAiSecurityAzureCredential: (profileId: string, subscriptionId: string) =>
    request<{ success: boolean; code: string | null; message: string; retryable: boolean }>(
      `/connectors/ai-security/azure/credentials/${encodeURIComponent(profileId)}/test?subscriptionId=${encodeURIComponent(subscriptionId)}`,
      { method: 'POST' },
    ),
  rotateAiSecurityAzureCredential: (
    profileId: string,
    payload: { clientSecret: string; expiresAt: string; subscriptionId: string },
  ) => request<AiSecurityAzureCredentialProfile>(
    `/connectors/ai-security/azure/credentials/${encodeURIComponent(profileId)}/rotate`,
    { method: 'POST', body: JSON.stringify(payload) },
  ),
  revokeAiSecurityAzureCredential: (profileId: string) =>
    request<void>(`/connectors/ai-security/azure/credentials/${encodeURIComponent(profileId)}`, {
      method: 'DELETE',
    }),
  createOwnershipRule: (payload: OwnershipRuleRequest) => request<OwnershipRuleResponse>('/ownership-rules', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  updateOwnershipRule: (id: string, payload: OwnershipRuleRequest) => request<OwnershipRuleResponse>(`/ownership-rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  deleteOwnershipRule: (id: string) => request<void>(`/ownership-rules/${id}`, { method: 'DELETE' }),
  applyOwnershipRules: () => request<{ updated: number }>('/ownership-rules/apply', { method: 'POST' }),
  applyOwnershipRule: (id: string) => request<{ updated: number }>(`/ownership-rules/${id}/apply`, { method: 'POST' }),
  listSuppressionRules: () => request<SuppressionRule[]>('/suppression-rules'),
  createSuppressionRule: (payload: SuppressionRuleRequest) => request<SuppressionRule>('/suppression-rules', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  updateSuppressionRule: (id: string, payload: SuppressionRuleRequest) => request<SuppressionRule>(`/suppression-rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  deleteSuppressionRule: (id: string) => request<void>(`/suppression-rules/${id}`, { method: 'DELETE' }),
  executeSuppressionRule: (id: string) => request<{ suppressed: number; error?: string }>(`/suppression-rules/${id}/execute`, { method: 'POST' }),
  reopenCveRecord: (recordId: string) => request<void>(`/suppression-rules/cve-reopen/${recordId}`, { method: 'POST' }),
  reopenAllByRule: (ruleId: string) => request<{ reopened: number }>(`/suppression-rules/${ruleId}/reopen-all`, { method: 'POST' }),
  bulkUpdateFindingWorkflow: (payload: FindingBulkWorkflowRequest) =>
    request<FindingBulkWorkflowResponse>('/findings/bulk-workflow', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  bulkDeleteFindings: (findingIds: string[]) =>
    request<{ deleted: number; message: string }>('/findings/bulk', {
      method: 'DELETE',
      body: JSON.stringify({ findingIds })
    }),
  getVulnIntelSourcesSummary: () => request<VulnIntelSourcesSummary>('/sync-runs/sources-summary'),
  syncNvd: (lookbackHours = 24) => request<SyncTriggerResponse>(`/ingestion/nvd-sync?lookbackHours=${lookbackHours}`, { method: 'POST' }),
  syncNvdFull: (payload?: { apiKey?: string }) => request<SyncTriggerResponse>('/ingestion/nvd-full-sync', {
    method: 'POST',
    body: JSON.stringify({
      apiKey: payload?.apiKey?.trim() || undefined
    })
  }),
  syncKev: () => request<SyncTriggerResponse>('/ingestion/kev-sync', { method: 'POST' }),
  syncGhsa: () => request<SyncTriggerResponse>('/ingestion/ghsa-sync', { method: 'POST' }),
  syncEuvd: () => request<SyncTriggerResponse>('/ingestion/euvd-sync', { method: 'POST' }),
  syncJvn: () => request<SyncTriggerResponse>('/ingestion/jvn-sync', { method: 'POST' }),
  syncMicrosoftCsaf: () => request<SyncTriggerResponse>('/ingestion/csaf/microsoft-sync', { method: 'POST' }),
  syncRedhatCsaf: () => request<SyncTriggerResponse>('/ingestion/csaf/redhat-sync', { method: 'POST' }),
  triggerVexAssertionRepair: () => request<SyncTriggerResponse>('/ingestion/vex-assertion-repair', { method: 'POST' }),
  triggerVexRolloutBackfill: () => request<SyncTriggerResponse>('/ingestion/vex-rollout-backfill', { method: 'POST' }),
  getVexAssertionRepairSummary: () => request<VexAssertionRepairSummary>('/ingestion/vex-assertion-repair/summary'),
  ingestAdvisories: (advisories: unknown[]) => request<IngestionResult>('/ingestion/advisories', {
    method: 'POST',
    body: JSON.stringify({ advisories })
  }),
  getUpgradeRecommendation: (payload: {
    softwareName: string;
    vendor?: string;
    currentVersion?: string;
    eolDate?: string;
    cveIds?: string[];
  }) => request<{ recommendedVersion: string; upgradeNotes: string; urgency: string }>(
    '/upgrade-recommendation',
    { method: 'POST', body: JSON.stringify(payload) }
  ),
  seedDemo: () => request<IngestionResult>('/demo/seed', { method: 'POST' }),
  getEolSummary: () => request<EolSummary>('/eol/status/summary'),
  getEolComponentStatuses: (params?: { filter?: string; page?: number; size?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.filter) searchParams.set('filter', params.filter);
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<EolComponentPage>(`/eol/status/components${suffix}`);
  },
  listEolProducts: () => request<EolProductCatalog[]>('/eol/products'),
  listEolProductReleases: (slug: string) => request<EolRelease[]>(`/eol/products/${encodeURIComponent(slug)}/releases`),
  confirmEolMapping: (normalizedKey: string, eolSlug: string) => request<{ status: string }>('/eol/mappings/confirm', {
    method: 'POST',
    body: JSON.stringify({ normalizedKey, eolSlug })
  }),
  listEolUnresolvedMappings: (params?: { page?: number; size?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<UnresolvedEolMappingPage>(`/eol/mappings/unresolved${suffix}`);
  },
  listEolMappingSuggestions: (normalizedKey: string) =>
    request<EolSlugSuggestion[]>(`/eol/mappings/suggestions?normalizedKey=${encodeURIComponent(normalizedKey)}`),
  getEolPackageStatuses: (params?: { filter?: string; page?: number; size?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.filter) searchParams.set('filter', params.filter);
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<PackageEolStatusPage>(`/eol/status/packages${suffix}`);
  },
  getEolPackageAssets: (params: { packageName: string; ecosystem?: string; page?: number; size?: number }) => {
    const searchParams = new URLSearchParams();
    searchParams.set('packageName', params.packageName);
    if (params.ecosystem) searchParams.set('ecosystem', params.ecosystem);
    if (params.page != null) searchParams.set('page', String(params.page));
    if (params.size != null) searchParams.set('size', String(params.size));
    return request<PackageAssetPage>(`/eol/status/packages/assets?${searchParams.toString()}`);
  },
  triggerEolCatalogRefresh: () => request<SyncTriggerResponse>('/eol/admin/refresh/catalog', { method: 'POST' }),
  triggerEolReleaseRefresh: () => request<SyncTriggerResponse>('/eol/admin/refresh/releases', { method: 'POST' }),
  triggerEolMappingResolve: () => request<SyncTriggerResponse>('/eol/admin/refresh/mappings', { method: 'POST' }),
  triggerEolDenormalize: () => request<SyncTriggerResponse>('/eol/admin/refresh/denormalize', { method: 'POST' }),
  triggerEolFullRefresh: () => request<SyncTriggerResponse>('/eol/admin/refresh/full', { method: 'POST' }),
  listSyncRuns: (params?: { category?: 'all' | 'inventory' | 'vulnerability' | 'vuln-intel' | 'processing'; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.category && params.category.trim().length > 0) {
      searchParams.set('category', params.category.trim());
    }
    if (params?.limit != null) {
      searchParams.set('limit', String(params.limit));
    }
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<SyncRun[]>(`/sync-runs${suffix}`);
  },
  listIngestions: (params?: { sourceSystem?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.sourceSystem && params.sourceSystem.trim().length > 0) {
      searchParams.set('sourceSystem', params.sourceSystem.trim());
    }
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<IngestionEvidence[]>(`/ingestions${suffix}`);
  },
  fetchSbomFromEndpoint: (
    payload: {
      assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
      assetName: string;
      assetIdentifier: string;
      sourceUrl: string;
      sourceLabel?: string;
      authorizationHeader?: string;
    }
  ) => request<{ assetId: string; sbomUploadId: string; componentsIngested: number; findingsGenerated: number }>(
    '/sbom-fetch',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    }
  ),
  getAuthContext: () => request<AuthContext>('/me'),
  login: (email: string, password: string) => publicRequest<AuthTokenResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password })
  }),
  selectTenantContext: (tenantId: string) => request<AuthTokenResponse>('/auth/tenant-context', {
    method: 'POST',
    body: JSON.stringify({ tenantId })
  }),
  clearTenantContext: () => request<AuthTokenResponse>('/auth/tenant-context', {
    method: 'DELETE'
  }),
  listAuthorizedWorkspaces: () => request<AllowedTenant[]>('/auth/authorized-workspaces'),
  listInvitedSupportGrants: () => request<TenantSupportGrant[]>('/auth/support-grants'),
  acceptSupportGrant: (grantId: string) =>
    request<TenantSupportGrant>(`/auth/support-grants/${encodeURIComponent(grantId)}/accept`, {
      method: 'POST'
    }),
  setupPassword: (password: string) => publicRequest<AuthTokenResponse>('/auth/setup-password', {
    method: 'POST',
    headers: { 'X-Scout-Setup': '1' },
    body: JSON.stringify({ password })
  }),
  startPasswordSetupSession: (setupToken: string) => publicRequest<void>('/auth/setup-session', {
    method: 'POST',
    headers: { 'X-Scout-Setup': '1' },
    body: JSON.stringify({ setupToken })
  }),
  listTestPersonas: () => request<TestPersona[]>('/dev/test-personas'),
  issueTestPersonaToken: (personaKey: string) =>
    request<TestPersonaToken>(`/dev/test-personas/${encodeURIComponent(personaKey)}/token`, {
      method: 'POST'
    }),
  listTenants: () => request<Tenant[]>('/tenants'),
  createTenant: (payload: TenantCreateRequest) =>
    request<Tenant>('/platform/tenants', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  retryTenantProvisioning: (tenantId: string) =>
    request<Tenant>(`/platform/tenants/${encodeURIComponent(tenantId)}/provisioning-retry`, {
      method: 'POST'
    }),
  extendTenantDemoExpiry: (tenantId: string, payload: { expiresAt: string }) =>
    request<Tenant>(`/platform/tenants/${encodeURIComponent(tenantId)}/demo-expiry`, {
      method: 'PATCH',
      body: JSON.stringify(payload)
    }),
  updateTenantStatus: (tenantId: string, status: 'ACTIVE' | 'SUSPENDED') =>
    request<Tenant>(`/platform/tenants/${encodeURIComponent(tenantId)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    }),
  getTenantSchemaStatus: () =>
    request<TenantSchemaStatusPage>('/platform/tenant-schema-status?page=0&size=200'),
  deleteTenant: (tenantId: string) =>
    request<void>(`/platform/tenants/${encodeURIComponent(tenantId)}`, {
      method: 'DELETE'
    }),
  listPlatformUsers: () => request<PlatformUser[]>('/platform/users'),
  listInventoryConnectorHealth: () => request<InventoryConnectorHealth[]>('/platform/inventory-connectors/health'),
  upsertPlatformUser: (payload: PlatformUserRequest) =>
    request<PlatformUser>('/platform/users', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  issuePlatformUserSetupLink: (userId: string) =>
    request<PlatformUserSetupLink>(`/platform/users/${encodeURIComponent(userId)}/setup-link`, {
      method: 'POST'
    }),
  revokePlatformUserRole: (userId: string, role: string) =>
    request<void>(`/platform/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(role)}`, {
      method: 'DELETE'
    }),
  listTenantMembers: (tenantId: string) =>
    request<TenantMember[]>(`/tenants/${encodeURIComponent(tenantId)}/members`),
  addTenantMember: (tenantId: string, payload: TenantMemberRequest) =>
    request<TenantMember>(`/tenants/${encodeURIComponent(tenantId)}/members`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  updateTenantMember: (tenantId: string, memberId: string, payload: TenantMemberUpdateRequest) =>
    request<TenantMember>(`/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(memberId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload)
    }),
  deleteTenantMember: (tenantId: string, memberId: string) =>
    request<void>(`/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(memberId)}`, {
      method: 'DELETE'
    }),
  listTenantSupportGrants: (tenantId: string) =>
    request<TenantSupportGrant[]>(`/tenants/${encodeURIComponent(tenantId)}/support-grants`),
  createTenantSupportGrant: (tenantId: string, payload: TenantSupportGrantRequest) =>
    request<TenantSupportGrant>(`/tenants/${encodeURIComponent(tenantId)}/support-grants`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  revokeTenantSupportGrant: (tenantId: string, grantId: string) =>
    request<TenantSupportGrant>(`/tenants/${encodeURIComponent(tenantId)}/support-grants/${encodeURIComponent(grantId)}`, {
      method: 'DELETE'
    }),
  grantPlatformOwnerMembership: (tenantId: string, payload: PlatformOwnerTenantMembershipRequest) =>
    request<TenantMember>(`/tenants/${encodeURIComponent(tenantId)}/platform-memberships`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  listTenantInvites: (tenantId: string) =>
    request<TenantInvite[]>(`/tenants/${encodeURIComponent(tenantId)}/invites`),
  createTenantInvite: (tenantId: string, payload: TenantInviteRequest) =>
    request<TenantInvite>(`/tenants/${encodeURIComponent(tenantId)}/invites`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  createTenantBulkInvites: (tenantId: string, payload: { invites: TenantInviteRequest[] }) =>
    request<TenantBulkInviteResponse>(`/tenants/${encodeURIComponent(tenantId)}/invites/bulk`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  resendTenantInvite: (tenantId: string, inviteId: string) =>
    request<TenantInvite>(`/tenants/${encodeURIComponent(tenantId)}/invites/${encodeURIComponent(inviteId)}/resend`, {
      method: 'POST'
    }),
  cancelTenantInvite: (tenantId: string, inviteId: string) =>
    request<void>(`/tenants/${encodeURIComponent(tenantId)}/invites/${encodeURIComponent(inviteId)}`, {
      method: 'DELETE'
    }),
  listServiceAccounts: () => request<ServiceAccount[]>('/service-accounts'),
  createServiceAccount: (payload: ServiceAccountRequest) =>
    request<ServiceAccount>('/service-accounts', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  deactivateServiceAccount: (accountId: string) =>
    request<ServiceAccount>(`/service-accounts/${encodeURIComponent(accountId)}/deactivate`, {
      method: 'POST'
    }),
  deleteServiceAccount: (accountId: string) =>
    request<void>(`/service-accounts/${encodeURIComponent(accountId)}`, {
      method: 'DELETE'
    }),
  listAuditEvents: () => request<AuditEvent[]>('/audit-events'),
  listPlatformUserAuditEvents: () => request<AuditEvent[]>('/audit-events/platform-users'),
  exportAuditEventsCsv: async (): Promise<{ filename: string; csv: string }> => {
    const headers = buildApiHeaders(undefined, false);
    const response = await fetch(`${API_BASE}/audit-events/export`, { headers });
    if (!response.ok) {
      throw await parseApiError(response);
    }
    const disposition = response.headers.get('content-disposition') ?? '';
    const match = /filename="?([^";]+)"?/i.exec(disposition);
    const filename = match?.[1] ?? 'vulnwatch-audit-events.csv';
    return { filename, csv: await response.text() };
  },
  bomFetch: (payload: BomFetchPayload) =>
    request<IngestionJobAccepted>('/bom/fetch', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  getIngestionJob: (jobId: string) =>
    request<IngestionJob>(`/ingestion-jobs/${encodeURIComponent(jobId)}`),
  bomUpload: async (formData: FormData): Promise<BomIngestionResult> => {
    const headers = buildApiHeaders(undefined, false);
    const response = await fetch(`${API_BASE}/bom/upload`, { method: 'POST', body: formData, headers });
    if (!response.ok) throw await parseApiError(response);
    return response.json() as Promise<BomIngestionResult>;
  },
  getApplicationRisk: () =>
    request<ApplicationRiskSummary[]>('/bom/application-risk'),
  listBomComponents: (page = 0, size = 2000) =>
    request<BomComponentSummaryItem[]>(`/bom/components?page=${page}&size=${size}`),
  getBomComponentDetail: (componentId: string) =>
    request<BomComponentDetail>(`/bom/components/${encodeURIComponent(componentId)}`),
  getApplicationCves: (assetId: string) =>
    request<ApplicationCveItem[]>(`/bom/assets/${encodeURIComponent(assetId)}/cves`),
  listBomInventory: (page = 0, size = 50) =>
    request<BomInventoryItem[]>(`/bom/inventory?page=${page}&size=${size}`),
  getBomDashboard: () =>
    request<BomDashboard>('/bom/dashboard'),
  getBomSupportMatrix: () =>
    request<BomSupportMatrix>('/bom/support'),
  getBomDetail: (bomId: string) =>
    request<BomDetail>(`/bom/inventory/${encodeURIComponent(bomId)}`),
  getBomLineage: (bomId: string) =>
    request<BomLineageItem[]>(`/bom/inventory/${encodeURIComponent(bomId)}/lineage`),
  deleteBom: (bomId: string) =>
    request<void>(`/bom/inventory/${encodeURIComponent(bomId)}`, { method: 'DELETE' }),
  listCbomPosture: () =>
    request<CbomPostureSummary[]>('/bom/cbom/posture'),
  getCbomPosture: (assetId: string) =>
    request<CbomPostureSummary>(`/bom/cbom/posture/${encodeURIComponent(assetId)}`),
  listCbomComponents: (assetId: string, page = 0, size = 100) =>
    request<CbomComponent[]>(`/bom/cbom/components?assetId=${encodeURIComponent(assetId)}&page=${page}&size=${size}`),
  listCbomFindings: (assetId: string, severity?: string) => {
    const params = new URLSearchParams({ assetId });
    if (severity) params.set('severity', severity);
    return request<CbomRiskFinding[]>(`/bom/cbom/findings?${params.toString()}`);
  },
  acceptCbomFinding: (findingId: string) =>
    request<CbomRiskFinding>(`/bom/cbom/findings/${encodeURIComponent(findingId)}/accept`, { method: 'POST' }),
};
