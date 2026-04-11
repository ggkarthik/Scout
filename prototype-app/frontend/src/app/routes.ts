import type { InventoryViewKey } from '../features/inventory/types';

export type AppTab =
  | 'dashboard'
  | 'findings'
  | 'operations'
  | 'vuln-repo'
  | 'inventory'
  | 'end-of-life'
  | 'connect'
  | 'configurations';

export type OperationsRouteView = 'quality' | 'pipeline' | 'platform-health';
export type VulnerabilityIntelRouteView = 'dashboard' | 'vulnerabilities' | 'org-cves';
export type ConnectRouteView = 'sources' | 'inventory-run-queue' | 'vuln-intel-queue' | 'processing-jobs';

export const INVENTORY_DEFAULT_VIEW: InventoryViewKey = 'sbom';
export const OPERATIONS_DEFAULT_VIEW: OperationsRouteView = 'pipeline';
export const CONNECT_DEFAULT_VIEW: ConnectRouteView = 'sources';

const OPERATIONS_VIEW_ALIASES: Record<string, OperationsRouteView> = {
  dashboard: 'pipeline',
  overview: 'pipeline',
  pipeline: 'pipeline',
  quality: 'quality',
  'ingestion-efficiency': 'pipeline',
  ingestion: 'pipeline',
  'normalization-quality': 'pipeline',
  normalization: 'pipeline',
  'correlation-effectiveness': 'pipeline',
  correlation: 'pipeline',
  'noise-lifecycle': 'pipeline',
  noise: 'pipeline',
  lifecycle: 'pipeline',
  freshness: 'pipeline',
  'freshness-drift': 'pipeline',
  'platform-health': 'platform-health',
  'api-read-path': 'platform-health',
  readPath: 'platform-health',
  'metric-catalog': 'platform-health',
  catalog: 'platform-health',
  slo: 'platform-health'
};

const INVENTORY_VIEWS = new Set<InventoryViewKey>([
  'vulnerability-intelligence',
  'software-identities',
  'technologies',
  'service-catalog',
  'cloud-resources',
  'hosts',
  'kubernetes-clusters',
  'container-images',
  'secured-image-catalog',
  'container-registries',
  'datastores',
  'subscriptions',
  'iam',
  'hosted-technologies',
  'sbom',
  'api-endpoints',
  'application-endpoints',
  'code-repositories',
  'source-mappings',
  'developers'
]);

const CONNECT_VIEWS = new Set<ConnectRouteView>([
  'sources',
  'inventory-run-queue',
  'vuln-intel-queue',
  'processing-jobs'
]);

export function normalizeOperationsRouteView(value: string | null | undefined): OperationsRouteView {
  if (!value) {
    return OPERATIONS_DEFAULT_VIEW;
  }
  if (value === 'quality' || value === 'pipeline' || value === 'platform-health') {
    return value;
  }
  return OPERATIONS_VIEW_ALIASES[value] ?? OPERATIONS_DEFAULT_VIEW;
}

export function normalizeInventoryRouteView(value: string | null | undefined): InventoryViewKey {
  if (!value) {
    return INVENTORY_DEFAULT_VIEW;
  }
  if (value === 'imported-assets') {
    return 'software-identities';
  }
  if (value === 'host-review-queue' || value === 'host-details') {
    return 'hosts';
  }
  return INVENTORY_VIEWS.has(value as InventoryViewKey) ? value as InventoryViewKey : INVENTORY_DEFAULT_VIEW;
}

export function normalizeConnectRouteView(value: string | null | undefined): ConnectRouteView {
  if (!value) {
    return CONNECT_DEFAULT_VIEW;
  }
  if (value === 'github-pipelines') {
    return 'sources';
  }
  if (value === 'integration-queue') {
    return 'vuln-intel-queue';
  }
  return CONNECT_VIEWS.has(value as ConnectRouteView) ? value as ConnectRouteView : CONNECT_DEFAULT_VIEW;
}

export function pathForTab(tab: AppTab): string {
  switch (tab) {
    case 'dashboard':
      return '/';
    case 'findings':
      return '/findings';
    case 'operations':
      return `/operations/${OPERATIONS_DEFAULT_VIEW}`;
    case 'vuln-repo':
      return '/vuln-repo';
    case 'inventory':
      return `/inventory/${INVENTORY_DEFAULT_VIEW}`;
    case 'end-of-life':
      return '/end-of-life';
    case 'connect':
      return `/connect/${CONNECT_DEFAULT_VIEW}`;
    case 'configurations':
      return '/configurations';
  }
}

export function pathForInventoryView(view: InventoryViewKey): string {
  return view === 'software-identities' ? '/inventory/software-identities' : `/inventory/${view}`;
}

export function pathForOperationsView(view: OperationsRouteView): string {
  return `/operations/${normalizeOperationsRouteView(view)}`;
}

export function pathForVulnRepoView(view: VulnerabilityIntelRouteView, cveId?: string | null): string {
  if (view === 'dashboard') {
    return '/vuln-repo';
  }
  if (view === 'vulnerabilities') {
    return '/vuln-repo/vulnerabilities';
  }
  return cveId ? `/vuln-repo/org-cves/${encodeURIComponent(cveId)}` : '/vuln-repo/org-cves';
}

export function pathForVulnRepoCveAssets(cveId: string): string {
  return `/vuln-repo/org-cves/${encodeURIComponent(cveId)}/assets`;
}

export function pathForVulnRepoCveSoftware(cveId: string): string {
  return `/vuln-repo/org-cves/${encodeURIComponent(cveId)}/software`;
}

export function pathForVulnRepoSoftwareAssets(softwareIdentityId: string, software?: string): string {
  const searchParams = new URLSearchParams();
  searchParams.set('softwareIdentityId', softwareIdentityId);
  if (software && software.trim().length > 0) {
    searchParams.set('software', software.trim());
  }
  return `/vuln-repo/software-assets?${searchParams.toString()}`;
}

export function pathForVulnRepoHostAsset(assetId: string, returnTo?: string): string {
  const encodedAssetId = encodeURIComponent(assetId);
  if (!returnTo || returnTo.trim().length === 0) {
    return `/vuln-repo/host-assets/${encodedAssetId}`;
  }
  const searchParams = new URLSearchParams();
  searchParams.set('returnTo', returnTo.trim());
  return `/vuln-repo/host-assets/${encodedAssetId}?${searchParams.toString()}`;
}

export function pathForConnectView(view: ConnectRouteView): string {
  return `/connect/${normalizeConnectRouteView(view)}`;
}

export function activeTabForPath(pathname: string): AppTab {
  if (pathname.startsWith('/findings')) return 'findings';
  if (pathname.startsWith('/operations')) return 'operations';
  if (pathname.startsWith('/vulnerability-intelligence')) return 'vuln-repo';
  if (pathname.startsWith('/vuln-repo')) return 'vuln-repo';
  if (pathname.startsWith('/inventory')) return 'inventory';
  if (pathname.startsWith('/end-of-life')) return 'end-of-life';
  if (pathname.startsWith('/connect')) return 'connect';
  if (pathname.startsWith('/configurations')) return 'configurations';
  return 'dashboard';
}

export function titleForTab(tab: AppTab): string {
  switch (tab) {
    case 'dashboard':
      return 'Overview';
    case 'findings':
      return 'Findings';
    case 'operations':
      return 'Operational Dashboard';
    case 'vuln-repo':
      return 'Vulnerability Repository';
    case 'inventory':
      return 'Inventory';
    case 'end-of-life':
      return 'End-of-Life';
    case 'connect':
      return 'Connect';
    case 'configurations':
      return 'Configurations';
  }
}

export function buildLegacyCompatiblePath(search: string): string | null {
  const params = new URLSearchParams(search);
  const tab = params.get('tab');
  const inventoryView = params.get('inventoryView');
  const operationsView = params.get('operationsView');
  const vulnIntelView = params.get('vulnIntelView');
  const vulnRepoView = params.get('vulnRepoView');
  const connectView = params.get('connectView');
  const cveId = params.get('cveId');

  if (!tab && !inventoryView && !operationsView && !vulnIntelView && !vulnRepoView && !connectView && !cveId) {
    return null;
  }

  let nextPath = '/';
  if (tab === 'findings') {
    nextPath = '/findings';
  } else if (tab === 'operations') {
    nextPath = pathForOperationsView(normalizeOperationsRouteView(operationsView));
  } else if (tab === 'vulnerability-intelligence') {
    const normalizedView = vulnIntelView === 'vulnerabilities'
      ? 'vulnerabilities'
      : vulnIntelView === 'org-cves'
        ? 'org-cves'
        : 'vulnerabilities';
    nextPath = pathForVulnRepoView(normalizedView, cveId);
  } else if (tab === 'vuln-repo') {
    const normalizedView = vulnRepoView === 'vulnerabilities'
      ? 'vulnerabilities'
      : vulnRepoView === 'org-cves'
        ? 'org-cves'
        : 'dashboard';
    nextPath = pathForVulnRepoView(normalizedView, cveId);
  } else if (tab === 'inventory' || tab === 'assets') {
    nextPath = pathForInventoryView(normalizeInventoryRouteView(inventoryView));
  } else if (tab === 'connect' || tab === 'ingestion' || tab === 'sources') {
    nextPath = pathForConnectView(normalizeConnectRouteView(connectView));
  } else if (tab === 'configurations') {
    nextPath = '/configurations';
  } else if (tab === 'end-of-life') {
    nextPath = '/end-of-life';
  }

  ['tab', 'inventoryView', 'operationsView', 'vulnIntelView', 'vulnRepoView', 'connectView', 'cveId'].forEach((key) => params.delete(key));
  const nextSearch = params.toString();
  return nextSearch ? `${nextPath}?${nextSearch}` : nextPath;
}
