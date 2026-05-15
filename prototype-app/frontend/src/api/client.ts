import type {
  PrototypeDataResetResponse,
  RiskPolicy,
  SuppressionRule,
  SuppressionRuleRequest,
} from '../features/configurations/types';
import type {
  FindingBulkWorkflowRequest,
  FindingBulkWorkflowResponse,
  FindingFilterValues,
  FindingPage
} from '../features/findings/types';
import type {
  ApplicableSoftwarePage,
  Dashboard,
  DashboardCveInventoryMap,
  ImpactedCvePage
} from '../features/dashboard/types';
import type {
  ClusterImpactResult,
  CorrelationOverridePayload,
  NormalizationOverridePayload,
  OperationalDashboard,
  OperationalQualityFilterValues,
  OperationalQualityIssueDetail,
  OperationalQualityIssuePage,
  OperationalQualitySummary,
  OperationalSectionResponse,
  SloStatus,
  SoftwareIdentitySearchResult
} from '../features/operations/types';
import type {
  AwsConnectionTestResponse,
  AwsDiscoveryConfig,
  AwsDiscoveryConfigRequest,
  AwsDiscoveryTarget,
  AwsDiscoveryTargetRequest,
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
import type { VulnRepoDashboard } from '../features/vuln-repo-dashboard/types';
import type {
  AuditEvent,
  AuthContext,
  DemoInvite,
  DemoInviteValidationResponse,
  DemoRequest,
  DemoRequestCreateRequest,
  DemoStatus,
  AuthTokenResponse,
  ServiceAccount,
  ServiceAccountRequest,
  Tenant,
  TenantCreateRequest,
  TenantMember,
  TenantMemberRequest
} from '../features/admin/types';

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

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8080/api';
const API_KEY = import.meta.env.VITE_API_KEY ?? 'change-me-in-prod';
const CREATOR_KEY = import.meta.env.VITE_CREATOR_KEY ?? 'local-creator';
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
      return new Error(formatApiError(payload, fallback));
    } catch {
      return new Error(fallback);
    }
  }

  const text = (await response.text()).trim();
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
  headers.set('X-API-Key', API_KEY);
  if (CREATOR_KEY.trim().length > 0) {
    headers.set('X-Creator-Key', CREATOR_KEY);
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
  const rawRoles = Array.isArray(payload.roles) ? payload.roles.map(String) : [];
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

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = buildApiHeaders(options?.headers);
  const method = options?.method?.toUpperCase() ?? 'GET';
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
    headers
  });

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
    headers
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
  getDemoStatus: () => request<DemoStatus>('/demo/status'),
  listDemoRequests: () => request<DemoRequest[]>('/platform/demo-requests'),
  approveDemoRequest: (requestId: string) => request<DemoRequest>(`/platform/demo-requests/${requestId}/approve`, { method: 'POST' }),
  rejectDemoRequest: (requestId: string, reason?: string) => request<DemoRequest>(`/platform/demo-requests/${requestId}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason: reason ?? '' })
  }),
  resendDemoInvite: (requestId: string) => request<DemoInvite>(`/platform/demo-requests/${requestId}/resend-invite`, { method: 'POST' }),
  getDashboard: () => request<Dashboard>('/dashboard'),
  getVulnRepoDashboard: () => request<VulnRepoDashboard>('/vuln-repo/dashboard'),
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
  listFindings: (
    params?: {
      page?: number;
      size?: number;
      severity?: string[];
      status?: string[];
      decisionState?: string[];
      matchMethod?: string[];
      vexStatus?: string[];
      vexFreshness?: string[];
      vexProvider?: string[];
      minConfidence?: number;
      vulnerabilityId?: string;
      packageName?: string;
      ecosystem?: string;
    }
  ) => {
    const searchParams = new URLSearchParams();
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    params?.severity?.forEach((value) => searchParams.append('severity', value));
    params?.status?.forEach((value) => searchParams.append('status', value));
    params?.decisionState?.forEach((value) => searchParams.append('decisionState', value));
    params?.matchMethod?.forEach((value) => searchParams.append('matchMethod', value));
    params?.vexStatus?.forEach((value) => searchParams.append('vexStatus', value));
    params?.vexFreshness?.forEach((value) => searchParams.append('vexFreshness', value));
    params?.vexProvider?.forEach((value) => searchParams.append('vexProvider', value));
    if (params?.minConfidence != null) searchParams.set('minConfidence', String(params.minConfidence));
    if (params?.vulnerabilityId && params.vulnerabilityId.trim().length > 0) {
      searchParams.set('vulnerabilityId', params.vulnerabilityId.trim());
    }
    if (params?.packageName && params.packageName.trim().length > 0) {
      searchParams.set('packageName', params.packageName.trim());
    }
    if (params?.ecosystem && params.ecosystem.trim().length > 0) {
      searchParams.set('ecosystem', params.ecosystem.trim());
    }
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<FindingPage>(`/findings${suffix}`);
  },
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
    }
  ) => request<GithubSbomSource>('/github-sbom-sources', {
    method: 'POST',
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
  recomputeFindingsScores: () => request<{ updated: number }>('/risk-policy/recompute-findings-scores', {
    method: 'POST'
  }),
  cleanAllPrototypeData: () => request<PrototypeDataResetResponse>('/configurations/clean-all', {
    method: 'POST'
  }),
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
  setupPassword: (setupToken: string, password: string) => publicRequest<AuthTokenResponse>('/auth/setup-password', {
    method: 'POST',
    body: JSON.stringify({ setupToken, password })
  }),
  selectTenantContext: (tenantId: string) => request<AuthTokenResponse>('/auth/context/tenant', {
    method: 'POST',
    body: JSON.stringify({ tenantId })
  }),
  clearTenantContext: () => request<AuthTokenResponse>('/auth/context/clear', {
    method: 'POST'
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
  listTenantMembers: (tenantId: string) =>
    request<TenantMember[]>(`/tenants/${encodeURIComponent(tenantId)}/members`),
  addTenantMember: (tenantId: string, payload: TenantMemberRequest) =>
    request<TenantMember>(`/tenants/${encodeURIComponent(tenantId)}/members`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  listServiceAccounts: () => request<ServiceAccount[]>('/service-accounts'),
  createServiceAccount: (payload: ServiceAccountRequest) =>
    request<ServiceAccount>('/service-accounts', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),
  listAuditEvents: () => request<AuditEvent[]>('/audit-events'),
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
  }
};
