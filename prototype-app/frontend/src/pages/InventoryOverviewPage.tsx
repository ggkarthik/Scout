import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import {
  pathForInventoryHostAsset,
  pathForInventoryView,
  pathForInventoryViewWithSearch,
} from '../app/routes';
import { InventoryQualityWorkspace } from '../components/InventoryQualityWorkspace';
import { useDashboardSummaryQuery } from '../features/dashboard/queries';
import type { ApplicableSoftwareRecord } from '../features/dashboard/types';
import { useEolSummaryQuery, useEolUnresolvedMappingsQuery } from '../features/eol/queries';
import type { Asset, HostAssetDetail, HostSoftwareInstanceRecord, InventoryComponentRecord } from '../features/inventory/api-types';
import type { InventoryViewKey } from '../features/inventory/types';
import { useOperationalQualitySummaryQuery } from '../features/operations/queries';
import type { OperationalQualitySummary } from '../features/operations/types';
import { useSoftwareIdentitiesQuery } from '../features/software-identities/queries';
import type { SoftwareIdentitySummary } from '../features/software-identities/types';

const HOST_STALE_DAYS = 30;
const HOST_AGING_DAYS = 7;
const INVENTORY_COMPONENT_PAGE_SIZE = 250;
const SOFTWARE_PAGE_SIZE = 50;
const SOFTWARE_TABLE_ROWS = 8;
const HOST_TABLE_ROWS = 8;

const OS_MATCHERS: Array<{ label: string; test: (value: string) => boolean }> = [
  { label: 'Windows Server', test: (value) => value.includes('windows server') },
  { label: 'Windows', test: (value) => value.includes('windows') },
  { label: 'Ubuntu', test: (value) => value.includes('ubuntu') },
  { label: 'Debian', test: (value) => value.includes('debian') },
  { label: 'Amazon Linux', test: (value) => value.includes('amazon linux') },
  { label: 'RHEL', test: (value) => value.includes('red hat') || value.includes('rhel') },
  { label: 'CentOS', test: (value) => value.includes('centos') },
  { label: 'Rocky Linux', test: (value) => value.includes('rocky') },
  { label: 'SUSE Linux', test: (value) => value.includes('suse') },
  { label: 'macOS', test: (value) => value.includes('mac os') || value.includes('macos') || value.includes('os x') },
  { label: 'Linux', test: (value) => value.includes('linux') }
];

type SupportedAssetType = 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';

type FreshnessState = {
  label: 'Fresh' | 'Aging' | 'Stale' | 'Unknown';
  className: string;
};

type NormalizationState = {
  label: 'Normalized' | 'Needs review' | 'No software';
  className: string;
};

type HostOverviewRecord = {
  asset: Asset;
  detail: HostAssetDetail;
  operatingSystem: string;
  deployedSoftwareCount: number;
  normalizedSoftwareCount: number;
  notNormalizedSoftwareCount: number;
  normalization: NormalizationState;
  openFindingCount: number;
  applicableCveCount: number;
  lastSeenAt?: string;
  freshness: FreshnessState;
  eolSoftwareCount: number;
  unknownLifecycleCount: number;
  reviewGapCount: number;
  attentionScore: number;
};

type AssetOverviewRecord = {
  asset: Asset;
  assetType: SupportedAssetType;
  operatingSystem?: string;
  deployedSoftwareCount: number;
  normalizedSoftwareCount: number;
  notNormalizedSoftwareCount: number;
  normalization: NormalizationState;
  openFindingCount: number;
  applicableCveCount: number;
  lastSeenAt?: string;
  freshness: FreshnessState;
  eolSoftwareCount: number;
  unknownLifecycleCount: number;
  reviewGapCount: number;
  attentionScore: number;
};

type AssetNormalizationSummary = {
  trackedAssetCount: number;
  normalizedAssetCount: number;
  notNormalizedAssetCount: number;
  normalizedComponentCount: number;
  notNormalizedComponentCount: number;
  normalizedAssetCoveragePercent: number;
};

type AssetTypePortfolioSummary = {
  type: SupportedAssetType;
  label: string;
  totalAssetCount: number;
  trackedAssetCount: number;
  normalizedAssetCount: number;
  notNormalizedAssetCount: number;
  componentCount: number;
};

type OverviewFocusTab = 'assets' | 'software';
type OverviewAssetFocus = 'all' | 'exposed' | 'stale';
type QualityInventoryWorkspaceTab = 'quality-normalization' | 'quality-correlation' | 'quality-eol' | 'quality-vex';
type InventoryWorkspaceTab = 'overview' | QualityInventoryWorkspaceTab;

const SUPPORTED_ASSET_TYPES: SupportedAssetType[] = ['APPLICATION', 'HOST', 'CONTAINER_IMAGE'];
const INVENTORY_TABS_PARAM = 'inventoryTabs';
const INVENTORY_ACTIVE_TAB_PARAM = 'inventoryActiveTab';
const INVENTORY_NORMALIZATION_TAB = 'quality-normalization';
const INVENTORY_CORRELATION_TAB = 'quality-correlation';
const INVENTORY_EOL_TAB = 'quality-eol';
const INVENTORY_VEX_TAB = 'quality-vex';
const QUALITY_INVENTORY_WORKSPACE_TABS: QualityInventoryWorkspaceTab[] = [
  INVENTORY_NORMALIZATION_TAB,
  INVENTORY_CORRELATION_TAB,
  INVENTORY_EOL_TAB,
  INVENTORY_VEX_TAB
];
const INVENTORY_WORKSPACE_TAB_CONFIG: Record<QualityInventoryWorkspaceTab, {
  label: string;
  domain: 'NORMALIZATION' | 'CORRELATION' | 'EOL' | 'VEX';
}> = {
  [INVENTORY_NORMALIZATION_TAB]: { label: 'Quality / Normalization', domain: 'NORMALIZATION' },
  [INVENTORY_CORRELATION_TAB]: { label: 'Quality / Correlation', domain: 'CORRELATION' },
  [INVENTORY_EOL_TAB]: { label: 'Quality / EOL', domain: 'EOL' },
  [INVENTORY_VEX_TAB]: { label: 'Quality / VEX', domain: 'VEX' }
};

function hasValue(value?: string | null): boolean {
  return Boolean(value && value.trim().length > 0);
}

function formatRefetchedAt(value?: number): string {
  if (!value) {
    return 'Refreshing when data arrives';
  }
  return `Last refreshed ${new Date(value).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`;
}

function normalizeAssetType(value?: string | null): SupportedAssetType | null {
  const normalized = value?.trim().toUpperCase();
  if (normalized === 'APPLICATION' || normalized === 'HOST' || normalized === 'CONTAINER_IMAGE') {
    return normalized;
  }
  return null;
}

function formatAssetTypeLabel(value: SupportedAssetType): string {
  if (value === 'APPLICATION') {
    return 'Applications';
  }
  if (value === 'CONTAINER_IMAGE') {
    return 'Container Images';
  }
  return 'Hosts';
}

function formatAssetTypeSingleLabel(value: SupportedAssetType): string {
  if (value === 'APPLICATION') {
    return 'Application';
  }
  if (value === 'CONTAINER_IMAGE') {
    return 'Container image';
  }
  return 'Host';
}

function inventoryViewForAssetType(value: SupportedAssetType): InventoryViewKey {
  if (value === 'APPLICATION') {
    return 'sbom';
  }
  if (value === 'CONTAINER_IMAGE') {
    return 'container-images';
  }
  return 'hosts';
}

function daysSince(value?: string): number | null {
  if (!value) {
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  const diffMs = Date.now() - parsed.getTime();
  return Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
}

function freshnessStateFor(value?: string): FreshnessState {
  const age = daysSince(value);
  if (age == null) {
    return { label: 'Unknown', className: 'status-pill status-unknown' };
  }
  if (age >= HOST_STALE_DAYS) {
    return { label: 'Stale', className: 'status-pill status-inactive' };
  }
  if (age >= HOST_AGING_DAYS) {
    return { label: 'Aging', className: 'status-pill status-warning' };
  }
  return { label: 'Fresh', className: 'status-pill status-success' };
}

function summarizeAge(value?: string): string {
  const age = daysSince(value);
  if (age == null) {
    return 'Waiting for inventory signal';
  }
  if (age === 0) {
    return 'Updated today';
  }
  if (age === 1) {
    return 'Updated 1 day ago';
  }
  return `Updated ${age} days ago`;
}

function inferOperatingSystem(detail: HostAssetDetail): string {
  const candidates = detail.software.flatMap((software) => [
    software.displayName,
    software.publisher,
    software.normalizedProduct,
    software.normalizedPublisher
  ]);

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    const normalized = candidate.trim().toLowerCase();
    const match = OS_MATCHERS.find((matcher) => matcher.test(normalized));
    if (match) {
      return match.label;
    }
  }

  return 'Unknown';
}

function hostLastSeen(asset: Asset, detail: HostAssetDetail): string | undefined {
  return detail.host.lastInventoryAt ?? detail.host.lastCmdbSyncAt ?? asset.lastInventoryAt ?? asset.lastCmdbSyncAt;
}

function assetLastSeen(asset: Asset): string | undefined {
  return asset.lastInventoryAt ?? asset.lastCmdbSyncAt;
}

function softwareNeedsReview(software: HostSoftwareInstanceRecord): boolean {
  return software.needsVersionReview || software.needsIdentityReview || software.needsDiscoveryModelReview;
}

function hostSoftwareIsNormalized(software: HostSoftwareInstanceRecord): boolean {
  return hasValue(software.normalizedPublisher)
    && hasValue(software.normalizedProduct)
    && hasValue(software.normalizedVersion)
    && hasValue(software.softwareIdentity)
    && !softwareNeedsReview(software);
}

function hostNormalizationStateFor(totalRows: number, notNormalizedRows: number): NormalizationState {
  if (totalRows === 0) {
    return { label: 'No software', className: 'status-pill status-unknown' };
  }
  if (notNormalizedRows === 0) {
    return { label: 'Normalized', className: 'status-pill status-success' };
  }
  return { label: 'Needs review', className: 'status-pill status-warning' };
}

function inventoryComponentIsNormalized(component: InventoryComponentRecord): boolean {
  return hasValue(component.normalizedName)
    && hasValue(component.normalizedVersion)
    && hasValue(component.softwareIdentity)
    && !component.needsReview;
}

async function loadAllActiveInventoryComponents(): Promise<InventoryComponentRecord[]> {
  const items: InventoryComponentRecord[] = [];
  let page = 0;

  while (true) {
    const response = await api.listInventoryComponents({
      componentStatus: ['ACTIVE'],
      page,
      size: INVENTORY_COMPONENT_PAGE_SIZE
    });
    items.push(...response.items);
    page += 1;
    if (page >= response.totalPages) {
      break;
    }
  }

  return items;
}

async function loadAllApplicableSoftware(): Promise<ApplicableSoftwareRecord[]> {
  const items: ApplicableSoftwareRecord[] = [];
  let page = 0;

  while (true) {
    const response = await api.listApplicableSoftware({
      page,
      size: INVENTORY_COMPONENT_PAGE_SIZE
    });
    items.push(...response.items);
    page += 1;
    if (page >= response.totalPages) {
      break;
    }
  }

  return items;
}

function buildAssetNormalizationSummary(components: InventoryComponentRecord[]): AssetNormalizationSummary {
  const assets = new Map<string, { componentCount: number; normalizedComponentCount: number }>();

  components.forEach((component) => {
    const current = assets.get(component.assetId) ?? { componentCount: 0, normalizedComponentCount: 0 };
    current.componentCount += 1;
    if (inventoryComponentIsNormalized(component)) {
      current.normalizedComponentCount += 1;
    }
    assets.set(component.assetId, current);
  });

  let normalizedAssetCount = 0;
  let normalizedComponentCount = 0;
  let notNormalizedComponentCount = 0;

  assets.forEach((asset) => {
    normalizedComponentCount += asset.normalizedComponentCount;
    notNormalizedComponentCount += asset.componentCount - asset.normalizedComponentCount;
    if (asset.componentCount > 0 && asset.componentCount === asset.normalizedComponentCount) {
      normalizedAssetCount += 1;
    }
  });

  const trackedAssetCount = assets.size;
  const notNormalizedAssetCount = trackedAssetCount - normalizedAssetCount;

  return {
    trackedAssetCount,
    normalizedAssetCount,
    notNormalizedAssetCount,
    normalizedComponentCount,
    notNormalizedComponentCount,
    normalizedAssetCoveragePercent: trackedAssetCount === 0 ? 0 : (normalizedAssetCount / trackedAssetCount) * 100
  };
}

function buildAssetTypePortfolioSummaries(
  assets: Asset[],
  components: InventoryComponentRecord[]
): AssetTypePortfolioSummary[] {
  const totalAssetIds = new Map<SupportedAssetType, Set<string>>();
  const trackedAssetIds = new Map<SupportedAssetType, Set<string>>();
  const normalizedAssetIds = new Map<SupportedAssetType, Set<string>>();
  const componentCountByType = new Map<SupportedAssetType, number>();
  const assetComponentStats = new Map<string, {
    type: SupportedAssetType;
    componentCount: number;
    normalizedComponentCount: number;
  }>();

  SUPPORTED_ASSET_TYPES.forEach((type) => {
    totalAssetIds.set(type, new Set());
    trackedAssetIds.set(type, new Set());
    normalizedAssetIds.set(type, new Set());
    componentCountByType.set(type, 0);
  });

  assets.forEach((asset) => {
    const assetType = normalizeAssetType(asset.type);
    if (!assetType) {
      return;
    }
    totalAssetIds.get(assetType)?.add(asset.id);
  });

  components.forEach((component) => {
    const assetType = normalizeAssetType(component.assetType);
    if (!assetType) {
      return;
    }
    const current = assetComponentStats.get(component.assetId) ?? {
      type: assetType,
      componentCount: 0,
      normalizedComponentCount: 0
    };
    current.componentCount += 1;
    if (inventoryComponentIsNormalized(component)) {
      current.normalizedComponentCount += 1;
    }
    assetComponentStats.set(component.assetId, current);
  });

  assetComponentStats.forEach((assetStats, assetId) => {
    trackedAssetIds.get(assetStats.type)?.add(assetId);
    componentCountByType.set(
      assetStats.type,
      (componentCountByType.get(assetStats.type) ?? 0) + assetStats.componentCount
    );
    if (assetStats.componentCount > 0 && assetStats.componentCount === assetStats.normalizedComponentCount) {
      normalizedAssetIds.get(assetStats.type)?.add(assetId);
    }
  });

  return SUPPORTED_ASSET_TYPES.map((type) => {
    const totalAssetCount = totalAssetIds.get(type)?.size ?? 0;
    const trackedAssetCount = trackedAssetIds.get(type)?.size ?? 0;
    const normalizedAssetCount = normalizedAssetIds.get(type)?.size ?? 0;
    return {
      type,
      label: formatAssetTypeLabel(type),
      totalAssetCount,
      trackedAssetCount,
      normalizedAssetCount,
      notNormalizedAssetCount: Math.max(0, trackedAssetCount - normalizedAssetCount),
      componentCount: componentCountByType.get(type) ?? 0
    };
  });
}

function emptyAssetTypeSummary(type: SupportedAssetType): AssetTypePortfolioSummary {
  return {
    type,
    label: formatAssetTypeLabel(type),
    totalAssetCount: 0,
    trackedAssetCount: 0,
    normalizedAssetCount: 0,
    notNormalizedAssetCount: 0,
    componentCount: 0
  };
}

function toHostOverviewRecord(asset: Asset, detail: HostAssetDetail): HostOverviewRecord {
  const lastSeenAt = hostLastSeen(asset, detail);
  const freshness = freshnessStateFor(lastSeenAt);
  const openFindingCount = detail.findings.filter((finding) => (finding.status ?? '').toUpperCase() !== 'RESOLVED').length;
  const eolSoftwareCount = detail.software.filter((software) => software.isEol === true).length;
  const unknownLifecycleCount = detail.software.filter((software) => !software.eolSlug).length;
  const reviewGapCount = detail.software.filter(softwareNeedsReview).length;
  const applicableCveCount = detail.applicableCves.length;
  const deployedSoftwareCount = detail.software.length;
  const normalizedSoftwareCount = detail.software.filter(hostSoftwareIsNormalized).length;
  const notNormalizedSoftwareCount = Math.max(0, deployedSoftwareCount - normalizedSoftwareCount);
  const normalization = hostNormalizationStateFor(deployedSoftwareCount, notNormalizedSoftwareCount);
  const freshnessWeight = freshness.label === 'Stale' ? 8 : freshness.label === 'Aging' ? 4 : 0;
  const attentionScore = (openFindingCount * 5)
    + (applicableCveCount * 2)
    + (eolSoftwareCount * 4)
    + (unknownLifecycleCount * 2)
    + (reviewGapCount * 3)
    + (notNormalizedSoftwareCount * 2)
    + freshnessWeight;

  return {
    asset,
    detail,
    operatingSystem: inferOperatingSystem(detail),
    deployedSoftwareCount,
    normalizedSoftwareCount,
    notNormalizedSoftwareCount,
    normalization,
    openFindingCount,
    applicableCveCount,
    lastSeenAt,
    freshness,
    eolSoftwareCount,
    unknownLifecycleCount,
    reviewGapCount,
    attentionScore
  };
}

function assetDrilldownPath(record: AssetOverviewRecord, returnTo: string): string {
  if (record.assetType === 'HOST') {
    return pathForInventoryHostAsset(record.asset.id, returnTo);
  }
  return pathForInventoryViewWithSearch(inventoryViewForAssetType(record.assetType), {
    query: record.asset.identifier || record.asset.name,
    groupBy: ['sourceSystem', 'ecosystem']
  });
}

function softwareLifecycleSummary(identity: SoftwareIdentitySummary): { label: string; className: string } {
  if (identity.eolComponentCount > 0) {
    return { label: `${identity.eolComponentCount} EOL`, className: 'status-pill status-failure' };
  }
  if (identity.nearEolComponentCount > 0) {
    return { label: `${identity.nearEolComponentCount} near EOL`, className: 'status-pill status-warning' };
  }
  if (identity.unknownEolComponentCount > 0) {
    return { label: `${identity.unknownEolComponentCount} unknown`, className: 'status-pill status-unknown' };
  }
  return { label: 'Supported', className: 'status-pill status-success' };
}

function firstErrorMessage(errors: Array<unknown>): string | null {
  for (const error of errors) {
    if (error instanceof Error) {
      return error.message;
    }
  }
  return null;
}

function softwareIdentityDetailPath(identityId: string): string {
  const searchParams = new URLSearchParams();
  searchParams.set('softwareIdentityId', identityId);
  return `${pathForInventoryView('software-identities')}?${searchParams.toString()}`;
}

function qualityDomainCount(summary: OperationalQualitySummary | null, domain: string): number {
  if (!summary) {
    return 0;
  }
  return summary.domainCounts.find((entry) => entry.domain === domain)?.issueCount ?? 0;
}

function parseInventoryWorkspaceTabs(value: string | null): QualityInventoryWorkspaceTab[] {
  if (!value) {
    return [];
  }

  const seen = new Set<QualityInventoryWorkspaceTab>();
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry): entry is QualityInventoryWorkspaceTab =>
      QUALITY_INVENTORY_WORKSPACE_TABS.includes(entry as QualityInventoryWorkspaceTab))
    .filter((entry) => {
      if (seen.has(entry)) {
        return false;
      }
      seen.add(entry);
      return true;
    });
}

function OverviewMetricCard({
  label,
  value,
  onClick,
  active = false
}: {
  label: string;
  value: string;
  onClick: () => void;
  active?: boolean;
}) {
  return (
    <article className={`inventory-overview-metric-card${active ? ' active' : ''}`}>
      <span className="inventory-overview-card-label">{label}</span>
      <button
        type="button"
        className="inventory-overview-card-value-button"
        onClick={onClick}
        aria-label={`Open ${label}`}
      >
        <strong className="inventory-overview-card-value">{value}</strong>
      </button>
    </article>
  );
}

export function InventoryOverviewPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [focusTab, setFocusTab] = React.useState<OverviewFocusTab>('assets');
  const [assetFocus, setAssetFocus] = React.useState<OverviewAssetFocus>('all');
  const focusWidgetRef = React.useRef<HTMLElement | null>(null);

  const dashboardQuery = useDashboardSummaryQuery();
  const softwareQuery = useSoftwareIdentitiesQuery({ page: 0, size: SOFTWARE_PAGE_SIZE });
  const eolSummaryQuery = useEolSummaryQuery();
  const unresolvedMappingsQuery = useEolUnresolvedMappingsQuery({ page: 0, size: 1 });
  const qualitySummaryQuery = useOperationalQualitySummaryQuery();
  const inventoryComponentsQuery = useQuery({
    queryKey: ['inventory-overview-active-components'],
    queryFn: loadAllActiveInventoryComponents
  });
  const applicableSoftwareQuery = useQuery({
    queryKey: ['inventory-overview-applicable-software'],
    queryFn: loadAllApplicableSoftware
  });

  const assetsQuery = useQuery({
    queryKey: ['inventory-overview-assets'],
    queryFn: api.listAssets
  });

  const hostAssets = React.useMemo(
    () => (assetsQuery.data ?? []).filter((asset) => asset.type.toUpperCase() === 'HOST'),
    [assetsQuery.data]
  );

  const hostDetailsQuery = useQuery({
    queryKey: ['inventory-overview-host-detail', hostAssets.map((asset) => asset.id)],
    queryFn: async () => Promise.all(
      hostAssets.map(async (asset) => ({
        asset,
        detail: await api.getHostAssetDetail(asset.id)
      }))
    ),
    enabled: hostAssets.length > 0
  });

  const dashboard = dashboardQuery.data ?? null;
  const softwarePage = softwareQuery.data ?? null;
  const qualitySummary = qualitySummaryQuery.data ?? null;
  const locationSearchParams = React.useMemo(
    () => new URLSearchParams(location.search),
    [location.search]
  );
  const openWorkspaceTabs = React.useMemo(
    () => parseInventoryWorkspaceTabs(locationSearchParams.get(INVENTORY_TABS_PARAM)),
    [locationSearchParams]
  );
  const activeWorkspaceTab = React.useMemo<InventoryWorkspaceTab>(() => {
    const requested = locationSearchParams.get(INVENTORY_ACTIVE_TAB_PARAM);
    if (requested && openWorkspaceTabs.includes(requested as QualityInventoryWorkspaceTab)) {
      return requested as QualityInventoryWorkspaceTab;
    }
    return 'overview';
  }, [locationSearchParams, openWorkspaceTabs]);
  const updateOverviewSearch = React.useCallback((updates: Record<string, string | null>) => {
    const next = new URLSearchParams(location.search);
    Object.entries(updates).forEach(([key, value]) => {
      if (!value) {
        next.delete(key);
      } else {
        next.set(key, value);
      }
    });
    navigate(
      {
        pathname: location.pathname,
        search: next.toString() ? `?${next.toString()}` : ''
      },
      { replace: true }
    );
  }, [location.pathname, location.search, navigate]);
  const writeWorkspaceTabs = React.useCallback((
    tabs: QualityInventoryWorkspaceTab[],
    activeTab: InventoryWorkspaceTab
  ) => {
    updateOverviewSearch({
      [INVENTORY_TABS_PARAM]: tabs.length > 0 ? tabs.join(',') : null,
      [INVENTORY_ACTIVE_TAB_PARAM]: activeTab === 'overview' ? null : activeTab
    });
  }, [updateOverviewSearch]);
  const openWorkspaceTab = React.useCallback((tab: QualityInventoryWorkspaceTab) => {
    const nextTabs = openWorkspaceTabs.includes(tab) ? openWorkspaceTabs : [...openWorkspaceTabs, tab];
    writeWorkspaceTabs(nextTabs, tab);
  }, [openWorkspaceTabs, writeWorkspaceTabs]);
  const activateOverviewTab = React.useCallback(() => {
    writeWorkspaceTabs(openWorkspaceTabs, 'overview');
  }, [openWorkspaceTabs, writeWorkspaceTabs]);
  const activateWorkspaceTab = React.useCallback((tab: QualityInventoryWorkspaceTab) => {
    writeWorkspaceTabs(openWorkspaceTabs, tab);
  }, [openWorkspaceTabs, writeWorkspaceTabs]);
  const closeWorkspaceTab = React.useCallback((tab: QualityInventoryWorkspaceTab) => {
    const nextTabs = openWorkspaceTabs.filter((entry) => entry !== tab);
    const nextActive = activeWorkspaceTab === tab ? (nextTabs[nextTabs.length - 1] ?? 'overview') : activeWorkspaceTab;
    writeWorkspaceTabs(nextTabs, nextActive);
  }, [activeWorkspaceTab, openWorkspaceTabs, writeWorkspaceTabs]);
  const allAssets = React.useMemo(
    () => assetsQuery.data ?? [],
    [assetsQuery.data]
  );

  const softwareRows = React.useMemo(
    () => softwarePage?.content ?? [],
    [softwarePage?.content]
  );
  const _assetNormalizationSummary = React.useMemo(
    () => buildAssetNormalizationSummary(inventoryComponentsQuery.data ?? []),
    [inventoryComponentsQuery.data]
  );
  const componentStatsByAssetId = React.useMemo(() => {
    const stats = new Map<string, {
      componentCount: number;
      normalizedComponentCount: number;
      reviewGapCount: number;
      eolComponentCount: number;
      unknownLifecycleCount: number;
    }>();

    (inventoryComponentsQuery.data ?? []).forEach((component) => {
      const current = stats.get(component.assetId) ?? {
        componentCount: 0,
        normalizedComponentCount: 0,
        reviewGapCount: 0,
        eolComponentCount: 0,
        unknownLifecycleCount: 0
      };
      current.componentCount += 1;
      if (inventoryComponentIsNormalized(component)) {
        current.normalizedComponentCount += 1;
      }
      if (component.needsReview) {
        current.reviewGapCount += 1;
      }
      if (component.isEol) {
        current.eolComponentCount += 1;
      }
      if (!component.eolSlug) {
        current.unknownLifecycleCount += 1;
      }
      stats.set(component.assetId, current);
    });

    return stats;
  }, [inventoryComponentsQuery.data]);
  const applicableCvesByAssetId = React.useMemo(() => {
    const stats = new Map<string, number>();
    (applicableSoftwareQuery.data ?? []).forEach((record) => {
      stats.set(record.assetId, (stats.get(record.assetId) ?? 0) + record.applicableCveCount);
    });
    return stats;
  }, [applicableSoftwareQuery.data]);
  const assetTypeSummaries = React.useMemo(
    () => buildAssetTypePortfolioSummaries(allAssets, inventoryComponentsQuery.data ?? []),
    [allAssets, inventoryComponentsQuery.data]
  );
  const topSoftwareByDeployment = React.useMemo(
    () => softwareRows.slice(0, SOFTWARE_TABLE_ROWS),
    [softwareRows]
  );
  const hostRecords = React.useMemo<HostOverviewRecord[]>(() => (
    (hostDetailsQuery.data ?? [])
      .map(({ asset, detail }) => toHostOverviewRecord(asset, detail))
      .sort((left, right) => right.attentionScore - left.attentionScore || left.asset.name.localeCompare(right.asset.name))
  ), [hostDetailsQuery.data]);
  const hostSignalsByAssetId = React.useMemo(() => {
    const stats = new Map<string, { openFindingCount: number; operatingSystem: string; lastSeenAt?: string }>();
    hostRecords.forEach((record) => {
      stats.set(record.asset.id, {
        openFindingCount: record.openFindingCount,
        operatingSystem: record.operatingSystem,
        lastSeenAt: record.lastSeenAt
      });
    });
    return stats;
  }, [hostRecords]);
  const assetRecords = React.useMemo<AssetOverviewRecord[]>(() => (
    allAssets
      .flatMap((asset) => {
        const assetType = normalizeAssetType(asset.type);
        if (!assetType) {
          return [];
        }
        const componentStats = componentStatsByAssetId.get(asset.id) ?? {
          componentCount: 0,
          normalizedComponentCount: 0,
          reviewGapCount: 0,
          eolComponentCount: 0,
          unknownLifecycleCount: 0
        };
        const applicableCveCount = applicableCvesByAssetId.get(asset.id) ?? 0;
        const hostSignals = hostSignalsByAssetId.get(asset.id);
        const lastSeenAt = hostSignals?.lastSeenAt ?? assetLastSeen(asset);
        const freshness = freshnessStateFor(lastSeenAt);
        const notNormalizedSoftwareCount = Math.max(0, componentStats.componentCount - componentStats.normalizedComponentCount);
        const freshnessWeight = freshness.label === 'Stale' ? 8 : freshness.label === 'Aging' ? 4 : 0;
        const openFindingCount = hostSignals?.openFindingCount ?? 0;
        return [{
          asset,
          assetType,
          operatingSystem: hostSignals?.operatingSystem,
          deployedSoftwareCount: componentStats.componentCount,
          normalizedSoftwareCount: componentStats.normalizedComponentCount,
          notNormalizedSoftwareCount,
          normalization: hostNormalizationStateFor(componentStats.componentCount, notNormalizedSoftwareCount),
          openFindingCount,
          applicableCveCount,
          lastSeenAt,
          freshness,
          eolSoftwareCount: componentStats.eolComponentCount,
          unknownLifecycleCount: componentStats.unknownLifecycleCount,
          reviewGapCount: componentStats.reviewGapCount,
          attentionScore: (openFindingCount * 5)
            + (applicableCveCount * 3)
            + (componentStats.eolComponentCount * 4)
            + (componentStats.unknownLifecycleCount * 2)
            + (componentStats.reviewGapCount * 3)
            + (notNormalizedSoftwareCount * 2)
            + freshnessWeight
        }];
      })
      .sort((left, right) => right.attentionScore - left.attentionScore || left.asset.name.localeCompare(right.asset.name))
  ), [allAssets, applicableCvesByAssetId, componentStatsByAssetId, hostSignalsByAssetId]);

  const staleAssets = React.useMemo(
    () => assetRecords.filter((record) => record.freshness.label === 'Stale').length,
    [assetRecords]
  );
  const assetsWithExposure = React.useMemo(
    () => assetRecords.filter((record) => record.openFindingCount > 0 || record.applicableCveCount > 0).length,
    [assetRecords]
  );

  const filteredAssetRecords = React.useMemo(() => {
    if (assetFocus === 'exposed') {
      return assetRecords.filter((record) => record.openFindingCount > 0 || record.applicableCveCount > 0);
    }
    if (assetFocus === 'stale') {
      return assetRecords.filter((record) => record.freshness.label === 'Stale');
    }
    return assetRecords;
  }, [assetFocus, assetRecords]);

  const topAssets = React.useMemo(
    () => filteredAssetRecords.slice(0, HOST_TABLE_ROWS),
    [filteredAssetRecords]
  );

  const softwareLoading = dashboardQuery.isPending
    || softwareQuery.isPending
    || eolSummaryQuery.isPending
    || unresolvedMappingsQuery.isPending
    || qualitySummaryQuery.isPending
    || applicableSoftwareQuery.isPending
    || inventoryComponentsQuery.isPending;
  const assetLoading = assetsQuery.isPending
    || hostDetailsQuery.isPending
    || applicableSoftwareQuery.isPending
    || inventoryComponentsQuery.isPending;
  const softwareError = firstErrorMessage([
    dashboardQuery.error,
    softwareQuery.error,
    eolSummaryQuery.error,
    unresolvedMappingsQuery.error,
    qualitySummaryQuery.error,
    applicableSoftwareQuery.error,
    inventoryComponentsQuery.error
  ]);
  const assetError = firstErrorMessage([
    assetsQuery.error,
    hostDetailsQuery.error,
    applicableSoftwareQuery.error,
    inventoryComponentsQuery.error
  ]);

  const lastUpdated = Math.max(
    dashboardQuery.dataUpdatedAt || 0,
    softwareQuery.dataUpdatedAt || 0,
    eolSummaryQuery.dataUpdatedAt || 0,
    unresolvedMappingsQuery.dataUpdatedAt || 0,
    qualitySummaryQuery.dataUpdatedAt || 0,
    applicableSoftwareQuery.dataUpdatedAt || 0,
    inventoryComponentsQuery.dataUpdatedAt || 0,
    assetsQuery.dataUpdatedAt || 0,
    hostDetailsQuery.dataUpdatedAt || 0
  );

  const applicationsSummary = assetTypeSummaries.find((summary) => summary.type === 'APPLICATION') ?? emptyAssetTypeSummary('APPLICATION');
  const hostsSummary = assetTypeSummaries.find((summary) => summary.type === 'HOST') ?? emptyAssetTypeSummary('HOST');
  const containerImagesSummary = assetTypeSummaries.find((summary) => summary.type === 'CONTAINER_IMAGE') ?? emptyAssetTypeSummary('CONTAINER_IMAGE');
  const totalKnownAssets = assetTypeSummaries.reduce((sum, summary) => sum + summary.totalAssetCount, 0);
  const activeComponentCount = inventoryComponentsQuery.data?.length ?? dashboard?.components ?? 0;
  const overviewLoading = softwareLoading || assetLoading;
  const overviewHasData = totalKnownAssets > 0 || activeComponentCount > 0 || softwareRows.length > 0 || assetRecords.length > 0;
  const normalizationIssueCount = qualityDomainCount(qualitySummary, 'NORMALIZATION');
  const correlationIssueCount = qualityDomainCount(qualitySummary, 'CORRELATION');
  const unmatchedEolCount = qualityDomainCount(qualitySummary, 'EOL');
  const vexIssueCount = qualityDomainCount(qualitySummary, 'VEX');
  const openAssetFocus = React.useCallback((focus: OverviewAssetFocus) => {
    setAssetFocus(focus);
    setFocusTab('assets');
    requestAnimationFrame(() => {
      focusWidgetRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }, []);
  const focusWidgetRowCount = focusTab === 'assets'
    ? topAssets.length
    : topSoftwareByDeployment.length;

  return (
    <section className="inventory-overview-shell">
      <header className="inventory-overview-hero">
        <div className="inventory-overview-hero-copy">
          <h1>Inventory Overview</h1>
        </div>
      </header>

      <div className="inventory-overview-status-row">
        <span className="panel-caption">{formatRefetchedAt(lastUpdated || undefined)}</span>
      </div>

      <div className="inventory-workspace-tabs" role="tablist" aria-label="Inventory workspace tabs">
        <button
          type="button"
          className={`inventory-workspace-tab${activeWorkspaceTab === 'overview' ? ' active' : ''}`}
          onClick={activateOverviewTab}
          role="tab"
          aria-selected={activeWorkspaceTab === 'overview'}
        >
          Overview
        </button>
        {openWorkspaceTabs.map((tab) => (
          <div key={tab} className={`inventory-workspace-tab-shell${activeWorkspaceTab === tab ? ' active' : ''}`}>
            <button
              type="button"
              className={`inventory-workspace-tab${activeWorkspaceTab === tab ? ' active' : ''}`}
              onClick={() => activateWorkspaceTab(tab)}
              role="tab"
              aria-selected={activeWorkspaceTab === tab}
            >
              {INVENTORY_WORKSPACE_TAB_CONFIG[tab].label}
            </button>
            <button
              type="button"
              className="inventory-workspace-tab-close"
              onClick={() => closeWorkspaceTab(tab)}
              aria-label={`Close ${INVENTORY_WORKSPACE_TAB_CONFIG[tab].label} tab`}
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <section className="inventory-overview-section">
        {activeWorkspaceTab !== 'overview' ? (
          <InventoryQualityWorkspace
            embedded
            forcedDomain={INVENTORY_WORKSPACE_TAB_CONFIG[activeWorkspaceTab].domain}
            showPanelHeader={false}
            storageKeyPrefix={`inventory-${activeWorkspaceTab}`}
          />
        ) : (
          <>
            {softwareError ? (
              <div className="inventory-error-banner">Failed to load software summary: {softwareError}</div>
            ) : null}
            {assetError ? (
              <div className="inventory-error-banner">Failed to load asset summary: {assetError}</div>
            ) : null}

            {overviewLoading && !overviewHasData ? (
              <div className="empty-state"><p>Loading combined inventory overview…</p></div>
            ) : (
              <>
            <div className="inventory-overview-stack">
              <article className="inventory-section-card">
                <div className="inventory-section-header">
                  <div>
                    <h3>Asset Inventory</h3>
                  </div>
                </div>
                <div className="inventory-overview-metrics">
                  <OverviewMetricCard
                    label="Applications tracked"
                    value={applicationsSummary.trackedAssetCount.toLocaleString()}
                    onClick={() => navigate(pathForInventoryViewWithSearch('sbom', {
                      groupBy: ['sourceSystem', 'ecosystem']
                    }))}
                  />
                  <OverviewMetricCard
                    label="Hosts tracked"
                    value={hostsSummary.trackedAssetCount.toLocaleString()}
                    onClick={() => navigate(pathForInventoryViewWithSearch('hosts', {
                      groupBy: ['operatingSystem', 'environment']
                    }))}
                  />
                  <OverviewMetricCard
                    label="Container images"
                    value={containerImagesSummary.trackedAssetCount.toLocaleString()}
                    onClick={() => navigate(pathForInventoryViewWithSearch('container-images', {
                      groupBy: ['sourceSystem', 'ecosystem']
                    }))}
                  />
                  <OverviewMetricCard
                    label="Assets with exposure"
                    value={assetsWithExposure.toLocaleString()}
                    onClick={() => openAssetFocus('exposed')}
                  />
                  <OverviewMetricCard
                    label="Stale assets"
                    value={staleAssets.toLocaleString()}
                    onClick={() => openAssetFocus('stale')}
                  />
                </div>
              </article>

              <article className="inventory-section-card">
                <div className="inventory-section-header">
                  <div>
                    <h3>Software inventory</h3>
                  </div>
                </div>
                <div className="inventory-overview-metrics">
                  <OverviewMetricCard
                    label="Software identities"
                    value={(softwarePage?.totalElements ?? 0).toLocaleString()}
                    onClick={() => navigate(pathForInventoryViewWithSearch('software-identities', {
                      groupBy: ['sourceSystem', 'ecosystem']
                    }))}
                  />
                  <OverviewMetricCard
                    label="Non Normalised software"
                    value={normalizationIssueCount.toLocaleString()}
                    onClick={() => openWorkspaceTab(INVENTORY_NORMALIZATION_TAB)}
                  />
                  <OverviewMetricCard
                    label="Non corelated software"
                    value={correlationIssueCount.toLocaleString()}
                    onClick={() => openWorkspaceTab(INVENTORY_CORRELATION_TAB)}
                  />
                  <OverviewMetricCard
                    label="Unmatched EOL software"
                    value={unmatchedEolCount.toLocaleString()}
                    onClick={() => openWorkspaceTab(INVENTORY_EOL_TAB)}
                  />
                  <OverviewMetricCard
                    label="VEX"
                    value={vexIssueCount.toLocaleString()}
                    onClick={() => openWorkspaceTab(INVENTORY_VEX_TAB)}
                  />
                </div>
              </article>
            </div>

            <article className="inventory-section-card" ref={focusWidgetRef}>
              <div className="inventory-section-header">
                <div>
                  <h3>Most exposed</h3>
                </div>
                <span className="panel-caption">{focusWidgetRowCount} rows</span>
              </div>

              <div className="inventory-tab-row inventory-overview-focus-tabs">
                <button
                  type="button"
                  className={`inventory-tab-button ${focusTab === 'assets' ? 'active' : ''}`}
                  onClick={() => setFocusTab('assets')}
                >
                  Assets
                </button>
                <button
                  type="button"
                  className={`inventory-tab-button ${focusTab === 'software' ? 'active' : ''}`}
                  onClick={() => setFocusTab('software')}
                >
                  Software
                </button>
              </div>

              {focusTab === 'assets' ? (
                <div className="inventory-chip-row inventory-overview-focus-filters">
                  {([
                    ['all', 'All assets'],
                    ['exposed', 'With exposure'],
                    ['stale', 'Stale']
                  ] as const).map(([value, label]) => (
                    <button
                      key={value}
                      type="button"
                      className={`inventory-chip ${assetFocus === value ? 'active' : ''}`}
                      onClick={() => setAssetFocus(value)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              ) : null}

              {focusTab === 'assets' ? (
                <div className="inventory-table-shell">
                  <table className="inventory-table inventory-overview-table">
                    <thead>
                      <tr>
                        <th>Asset</th>
                        <th>Freshness</th>
                        <th>Software</th>
                        <th>Normalization</th>
                        <th>Exposure</th>
                        <th>Lifecycle</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topAssets.length === 0 ? (
                        <tr>
                          <td colSpan={7}>
                            <div className="empty-state">
                              <p>
                                {assetFocus === 'exposed'
                                  ? 'No exposed assets matched the current view.'
                                  : assetFocus === 'stale'
                                    ? 'No stale assets matched the current view.'
                                    : 'No assets are available yet.'}
                              </p>
                            </div>
                          </td>
                        </tr>
                      ) : topAssets.map((record) => (
                        <tr key={record.asset.id}>
                          <td>
                            <button
                              type="button"
                              className="inventory-link-button inventory-link-button-primary"
                              onClick={() => navigate(assetDrilldownPath(record, `${location.pathname}${location.search}`))}
                            >
                              {record.asset.name}
                            </button>
                            <div className="panel-caption">
                              {[
                                formatAssetTypeSingleLabel(record.assetType),
                                record.asset.environment || 'Unspecified environment',
                                record.operatingSystem
                              ].filter(Boolean).join(' · ')}
                            </div>
                          </td>
                          <td>
                            <span className={record.freshness.className}>{record.freshness.label}</span>
                            <div className="panel-caption">{summarizeAge(record.lastSeenAt)}</div>
                          </td>
                          <td>
                            <div className="inventory-primary-text">{record.deployedSoftwareCount.toLocaleString()} rows</div>
                            <div className="panel-caption">{record.reviewGapCount.toLocaleString()} review gaps</div>
                          </td>
                          <td>
                            <span className={record.normalization.className}>{record.normalization.label}</span>
                            <div className="panel-caption">
                              {record.deployedSoftwareCount === 0
                                ? 'Waiting for software inventory'
                                : `${record.normalizedSoftwareCount.toLocaleString()} of ${record.deployedSoftwareCount.toLocaleString()} rows fully normalized`}
                            </div>
                          </td>
                          <td>
                            <div className="inventory-primary-text">{record.openFindingCount.toLocaleString()} findings</div>
                            <div className="panel-caption">{record.applicableCveCount.toLocaleString()} applicable CVEs</div>
                          </td>
                          <td>
                            <div className="inventory-primary-text">{record.eolSoftwareCount.toLocaleString()} EOL</div>
                            <div className="panel-caption">{record.unknownLifecycleCount.toLocaleString()} unknown lifecycle</div>
                          </td>
                          <td>
                            <button
                              type="button"
                              className="inventory-link-button inventory-link-button-primary"
                              onClick={() => navigate(assetDrilldownPath(record, `${location.pathname}${location.search}`))}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="inventory-table-shell">
                  <table className="inventory-table inventory-overview-table">
                    <thead>
                      <tr>
                        <th>Software</th>
                        <th>Footprint</th>
                        <th>Lifecycle</th>
                        <th>Exposure</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topSoftwareByDeployment.length === 0 ? (
                        <tr>
                          <td colSpan={5}>
                            <div className="empty-state"><p>No software inventory is available yet.</p></div>
                          </td>
                        </tr>
                      ) : topSoftwareByDeployment.map((identity) => {
                        const lifecycle = softwareLifecycleSummary(identity);
                        return (
                          <tr key={identity.id}>
                            <td>
                              <button
                                type="button"
                                className="inventory-link-button inventory-link-button-primary"
                                onClick={() => navigate(softwareIdentityDetailPath(identity.id))}
                              >
                                {identity.displayName}
                              </button>
                              <div className="panel-caption">{identity.vendor || 'Unknown vendor'} / {identity.product || 'Unknown product'}</div>
                            </td>
                            <td>
                              <div className="inventory-primary-text">{identity.assetCount.toLocaleString()} assets</div>
                              <div className="panel-caption">{identity.componentCount.toLocaleString()} components · {identity.versionCount.toLocaleString()} versions</div>
                            </td>
                            <td>
                              <span className={lifecycle.className}>{lifecycle.label}</span>
                              <div className="panel-caption">{identity.eolSlug || 'No mapped lifecycle slug'}</div>
                            </td>
                            <td>
                              <div className="inventory-primary-text">{identity.openVulnerabilityCount.toLocaleString()} open CVEs</div>
                              <div className="panel-caption">{identity.openFindingCount.toLocaleString()} open findings</div>
                            </td>
                            <td>
                              <button
                                type="button"
                                className="inventory-link-button inventory-link-button-primary"
                                onClick={() => navigate(softwareIdentityDetailPath(identity.id))}
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </article>
              </>
            )}
          </>
        )}
      </section>
    </section>
  );
}
