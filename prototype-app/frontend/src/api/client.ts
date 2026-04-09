import type {
  PrototypeDataResetResponse,
  RiskPolicy
} from '../features/configurations/types';
import type {
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
  OperationalDashboard,
  OperationalQualityFilterValues,
  OperationalQualityIssueDetail,
  OperationalQualityIssuePage,
  OperationalQualitySummary,
  OperationalSectionResponse,
  SloStatus
} from '../features/operations/types';
import type {
  CmdbAssetRecord,
  CmdbAssetSyncResponse,
  GithubSbomSource,
  IngestionEvidence,
  IngestionResult,
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
import type {
  VulnerabilityIntelDashboardSummary,
  VulnerabilityIntelDetail,
  VulnerabilityIntelFilterValues,
  VulnerabilityIntelPage
} from '../features/vulnerability-intel/types';
import type { VulnRepoDashboard } from '../features/vuln-repo-dashboard/types';
import type {
  EolComponentPage,
  EolProductCatalog,
  EolRelease,
  EolSummary,
  UnresolvedEolMapping
} from '../features/eol/types';
import type {
  SoftwareIdentityDetail,
  SoftwareIdentityPage,
  VulnRepoSoftwareAssetsDetail
} from '../features/software-identities/types';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8080/api';
const API_KEY = import.meta.env.VITE_API_KEY ?? 'change-me-in-prod';
const CREATOR_KEY = import.meta.env.VITE_CREATOR_KEY ?? 'local-creator';

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

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers ?? {});
  headers.set('Content-Type', 'application/json');
  headers.set('X-API-Key', API_KEY);
  if (CREATOR_KEY.trim().length > 0) {
    headers.set('X-Creator-Key', CREATOR_KEY);
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

export const api = {
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
    if (params?.query && params.query.trim().length > 0) searchParams.set('query', params.query.trim());
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<SoftwareIdentityPage>(`/inventory/software-identities${suffix}`);
  },
  getSoftwareIdentityDetail: (softwareIdentityId: string) => request<SoftwareIdentityDetail>(
    `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`
  ),
  getVulnRepoSoftwareAssets: (softwareIdentityId: string) => request<VulnRepoSoftwareAssetsDetail>(
    `/vuln-repo/software-assets/${encodeURIComponent(softwareIdentityId)}`
  ),
  listVulnerabilityIntelligence: (
    params?: {
      page?: number;
      size?: number;
      query?: string;
      affectedPackage?: string;
      minCvssExclusive?: number;
      severity?: string[];
      source?: string[];
      vulnStatus?: string[];
      inKev?: boolean;
    }
  ) => {
    const searchParams = new URLSearchParams();
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    if (params?.query && params.query.trim().length > 0) searchParams.set('query', params.query.trim());
    if (params?.affectedPackage && params.affectedPackage.trim().length > 0) {
      searchParams.set('affectedPackage', params.affectedPackage.trim());
    }
    if (params?.minCvssExclusive != null) searchParams.set('minCvssExclusive', String(params.minCvssExclusive));
    params?.severity?.forEach((value) => searchParams.append('severity', value));
    params?.source?.forEach((value) => searchParams.append('source', value));
    params?.vulnStatus?.forEach((value) => searchParams.append('vulnStatus', value));
    if (params?.inKev != null) searchParams.set('inKev', String(params.inKev));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<VulnerabilityIntelPage>(`/vulnerability-intelligence${suffix}`);
  },
  getVulnerabilityIntelDashboardSummary: (params?: { minCvssExclusive?: number; criticalLimit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.minCvssExclusive != null) searchParams.set('minCvssExclusive', String(params.minCvssExclusive));
    if (params?.criticalLimit != null) searchParams.set('criticalLimit', String(params.criticalLimit));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<VulnerabilityIntelDashboardSummary>(`/vulnerability-intelligence/dashboard-summary${suffix}`);
  },
  listVulnerabilityIntelligenceSources: () => request<string[]>('/vulnerability-intelligence/sources'),
  listVulnerabilityIntelligenceFilters: () => request<VulnerabilityIntelFilterValues>('/vulnerability-intelligence/filters'),
  getVulnerabilityIntelligenceDetail: (externalId: string) => request<VulnerabilityIntelDetail>(
    `/vulnerability-intelligence/${encodeURIComponent(externalId)}`
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
  cleanAllPrototypeData: () => request<PrototypeDataResetResponse>('/configurations/clean-all', {
    method: 'POST'
  }),
  syncNvd: (lookbackHours = 24) => request<SyncTriggerResponse>(`/ingestion/nvd-sync?lookbackHours=${lookbackHours}`, { method: 'POST' }),
  syncNvdFull: (payload?: { apiKey?: string }) => request<SyncTriggerResponse>('/ingestion/nvd-full-sync', {
    method: 'POST',
    body: JSON.stringify({
      apiKey: payload?.apiKey?.trim() || undefined
    })
  }),
  syncKev: () => request<SyncTriggerResponse>('/ingestion/kev-sync', { method: 'POST' }),
  syncGhsa: () => request<SyncTriggerResponse>('/ingestion/ghsa-sync', { method: 'POST' }),
  syncMicrosoftCsaf: () => request<SyncTriggerResponse>('/ingestion/csaf/microsoft-sync', { method: 'POST' }),
  syncRedhatCsaf: () => request<SyncTriggerResponse>('/ingestion/csaf/redhat-sync', { method: 'POST' }),
  triggerVexAssertionRepair: () => request<SyncTriggerResponse>('/ingestion/vex-assertion-repair', { method: 'POST' }),
  triggerVexRolloutBackfill: () => request<SyncTriggerResponse>('/ingestion/vex-rollout-backfill', { method: 'POST' }),
  getVexAssertionRepairSummary: () => request<VexAssertionRepairSummary>('/ingestion/vex-assertion-repair/summary'),
  ingestAdvisories: (advisories: unknown[]) => request<IngestionResult>('/ingestion/advisories', {
    method: 'POST',
    body: JSON.stringify({ advisories })
  }),
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
  listEolUnresolvedMappings: () => request<UnresolvedEolMapping[]>('/eol/mappings/unresolved'),
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
  )
};
