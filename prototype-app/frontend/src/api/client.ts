import {
  ApplicableSoftwarePage,
  AuthContext,
  Asset,
  CmdbAssetRecord,
  CmdbAssetSyncResponse,
  DashboardCveInventoryMap,
  Dashboard,
  ImpactedCvePage,
  FindingFilterValues,
  FindingPage,
  GithubSbomSource,
  GithubSbomIngestionBatchResponse,
  InventoryComponentRecord,
  InventoryComponentFilterValues,
  InventoryComponentPage,
  IngestionResult,
  OrgSpecificCveExposurePage,
  OrgSpecificCveExposureRecomputeResponse,
  OperationalDashboard,
  PrototypeDataResetResponse,
  RiskPolicy,
  SbomUploadEvidence,
  SoftwareModelPage,
  SoftwareModelRecord,
  SyncRun,
  SyncTriggerResponse,
  VulnerabilityIntelDetail,
  VulnerabilityIntelFilterValues,
  VulnerabilityIntelPage
} from '../types';

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

export const api = {
  getAuthContext: () => request<AuthContext>('/auth/context'),
  getDashboard: () => request<Dashboard>('/dashboard'),
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
  listAssets: () => request<Asset[]>('/assets'),
  listInventoryComponents: (
    params?: {
      assetType?: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
      componentStatus?: 'ACTIVE' | 'RETIRED';
      sourceSystem?: string;
      page?: number;
      size?: number;
    }
  ) => {
    const searchParams = new URLSearchParams();
    if (params?.assetType) searchParams.set('assetType', params.assetType);
    if (params?.componentStatus) searchParams.set('componentStatus', params.componentStatus);
    if (params?.sourceSystem) searchParams.set('sourceSystem', params.sourceSystem);
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<InventoryComponentPage>(`/inventory/components${suffix}`);
  },
  listInventoryComponentFilters: () => request<InventoryComponentFilterValues>('/inventory/components/filters'),
  listSoftwareModels: (
    params?: {
      page?: number;
      size?: number;
    }
  ) => {
    const searchParams = new URLSearchParams();
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<SoftwareModelPage>(`/inventory/software-models${suffix}`);
  },
  listVulnerabilityIntelligence: (
    params?: {
      page?: number;
      size?: number;
      query?: string;
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
    if (params?.minCvssExclusive != null) searchParams.set('minCvssExclusive', String(params.minCvssExclusive));
    params?.severity?.forEach((value) => searchParams.append('severity', value));
    params?.source?.forEach((value) => searchParams.append('source', value));
    params?.vulnStatus?.forEach((value) => searchParams.append('vulnStatus', value));
    if (params?.inKev != null) searchParams.set('inKev', String(params.inKev));
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<VulnerabilityIntelPage>(`/vulnerability-intelligence${suffix}`);
  },
  listVulnerabilityIntelligenceSources: () => request<string[]>('/vulnerability-intelligence/sources'),
  listVulnerabilityIntelligenceFilters: () => request<VulnerabilityIntelFilterValues>('/vulnerability-intelligence/filters'),
  listOrgSpecificCves: (
    params?: {
      page?: number;
      size?: number;
      query?: string;
    }
  ) => {
    const searchParams = new URLSearchParams();
    if (params?.page != null) searchParams.set('page', String(params.page));
    if (params?.size != null) searchParams.set('size', String(params.size));
    if (params?.query && params.query.trim().length > 0) searchParams.set('query', params.query.trim());
    const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
    return request<OrgSpecificCveExposurePage>(`/vulnerability-intelligence/org-cves${suffix}`);
  },
  recomputeOrgSpecificCves: () => request<OrgSpecificCveExposureRecomputeResponse>(
    '/vulnerability-intelligence/org-cves/recompute',
    { method: 'POST' }
  ),
  getVulnerabilityIntelligenceDetail: (externalId: string) => request<VulnerabilityIntelDetail>(
    `/vulnerability-intelligence/${encodeURIComponent(externalId)}`
  ),
  syncAssetsFromCmdb: (assets: CmdbAssetRecord[]) => request<CmdbAssetSyncResponse>('/assets/cmdb-sync', {
    method: 'POST',
    body: JSON.stringify({ assets })
  }),
  listGithubSbomSources: () => request<GithubSbomSource[]>('/github-sbom-sources'),
  createGithubSbomSource: (
    payload: {
      name: string;
      owner: string;
      repo: string;
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
  updateGithubSbomSource: (
    sourceId: string,
    payload: {
      name: string;
      owner: string;
      repo: string;
      assetType?: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
      assetName?: string;
      assetIdentifier?: string;
      frequency?: 'ONCE' | 'INTERVAL';
      intervalMinutes?: number;
      enabled?: boolean;
    }
  ) => request<GithubSbomSource>(`/github-sbom-sources/${sourceId}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  }),
  runGithubSbomSource: (sourceId: string) => request<void>(`/github-sbom-sources/${sourceId}/run`, { method: 'POST' }),
  getRiskPolicy: () => request<RiskPolicy>('/risk-policy'),
  updateRiskPolicy: (policy: Partial<RiskPolicy>) => request<RiskPolicy>('/risk-policy', {
    method: 'POST',
    body: JSON.stringify(policy)
  }),
  cleanAllPrototypeData: () => request<PrototypeDataResetResponse>('/configurations/clean-all', {
    method: 'POST'
  }),
  syncNvd: (lookbackHours = 24) => request<SyncTriggerResponse>(`/ingestion/nvd-sync?lookbackHours=${lookbackHours}`, { method: 'POST' }),
  syncNvdFull: () => request<SyncTriggerResponse>('/ingestion/nvd-full-sync', { method: 'POST' }),
  syncKev: () => request<SyncTriggerResponse>('/ingestion/kev-sync', { method: 'POST' }),
  syncGhsa: () => request<SyncTriggerResponse>('/ingestion/ghsa-sync', { method: 'POST' }),
  syncMicrosoftCsaf: () => request<SyncTriggerResponse>('/ingestion/csaf/microsoft-sync', { method: 'POST' }),
  syncRedhatCsaf: () => request<SyncTriggerResponse>('/ingestion/csaf/redhat-sync', { method: 'POST' }),
  ingestAdvisories: (advisories: unknown[]) => request<IngestionResult>('/ingestion/advisories', {
    method: 'POST',
    body: JSON.stringify({ advisories })
  }),
  seedDemo: () => request<IngestionResult>('/demo/seed', { method: 'POST' }),
  listSyncRuns: () => request<SyncRun[]>('/sync-runs'),
  listSbomUploads: () => request<SbomUploadEvidence[]>('/sbom-uploads'),
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
  fetchSbomFromGithub: (
    payload: {
      owner: string;
      repo?: string;
      includeAllRepos?: boolean;
      assetType?: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
      assetName?: string;
      assetIdentifier?: string;
    }
  ) => request<GithubSbomIngestionBatchResponse>(
    '/sbom-fetch/github',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    }
  )
};

export async function uploadSbom(
  payload: { assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'; assetName: string; assetIdentifier: string; file: File }
): Promise<{ assetId: string; sbomUploadId: string; componentsIngested: number; findingsGenerated: number }> {
  const form = new FormData();
  form.append('assetType', payload.assetType);
  form.append('assetName', payload.assetName);
  form.append('assetIdentifier', payload.assetIdentifier);
  form.append('file', payload.file);

  const headers = new Headers();
  headers.set('X-API-Key', API_KEY);
  if (CREATOR_KEY.trim().length > 0) {
    headers.set('X-Creator-Key', CREATOR_KEY);
  }
  const response = await fetch(`${API_BASE}/sbom-upload`, {
    method: 'POST',
    headers,
    body: form
  });

  if (!response.ok) {
    throw await parseApiError(response);
  }

  return response.json();
}
