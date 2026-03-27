import React from 'react';
import type {
  InventoryComponentFilterValues,
  InventoryComponentRecord
} from './api-types';
import type {
  VulnerabilityIntelDetail,
  VulnerabilityIntelFilterValues,
  VulnerabilityIntelRecord
} from '../vulnerability-intel/types';
import {
  DEFAULT_COMPONENT_FILTERS,
  DEFAULT_VULNERABILITY_INTEL_FILTERS
} from './config';
import {
  useInventoryComponentFiltersQuery,
  useInventoryComponentsQuery,
  useVulnerabilityIntelligenceDetailQuery,
  useVulnerabilityIntelligenceFiltersQuery,
  useVulnerabilityIntelligenceQuery
} from './queries';

type UseInventoryDataArgs = {
  selectedView: string;
  scopedAssetType: 'ALL' | InventoryComponentRecord['assetType'];
  componentActiveFilters: string[];
  componentAssetTypes: string[];
  componentStatuses: string[];
  componentSourceSystems: string[];
  componentEcosystems: string[];
  componentReviewCategories: string[];
  componentPage: number;
  debouncedComponentQuery: string;
  vulnerabilityIntelPage: number;
  debouncedVulnerabilityIntelQuery: string;
  debouncedVulnerabilityIntelAffectedPackageQuery: string;
  vulnerabilityIntelSeverities: string[];
  vulnerabilityIntelSources: string[];
  vulnerabilityIntelStatuses: string[];
  vulnerabilityIntelInKevFilter: boolean | undefined;
  normalizeVulnerabilitySource: (value: string) => string;
  expandVulnerabilitySourceFilters: (values: string[]) => string[];
};

type UseInventoryDataResult = {
  rows: InventoryComponentRecord[];
  componentTotalItems: number;
  componentTotalPages: number;
  componentFilterValues: InventoryComponentFilterValues;
  vulnerabilityIntelRows: VulnerabilityIntelRecord[];
  vulnerabilityIntelTotalItems: number;
  vulnerabilityIntelTotalPages: number;
  vulnerabilityIntelFilterValues: VulnerabilityIntelFilterValues;
  loading: boolean;
  error: string;
  refreshInventory: () => Promise<void>;
};

type UseVulnerabilityIntelDetailArgs = {
  selectedView: string;
  selectedVulnerabilityIntelId: string | null;
};

type UseVulnerabilityIntelDetailResult = {
  selectedVulnerabilityIntelDetail: VulnerabilityIntelDetail | null;
  vulnerabilityIntelDetailLoading: boolean;
};

export function useInventoryData({
  selectedView,
  scopedAssetType,
  componentActiveFilters,
  componentAssetTypes,
  componentStatuses,
  componentSourceSystems,
  componentEcosystems,
  componentReviewCategories,
  componentPage,
  debouncedComponentQuery,
  vulnerabilityIntelPage,
  debouncedVulnerabilityIntelQuery,
  debouncedVulnerabilityIntelAffectedPackageQuery,
  vulnerabilityIntelSeverities,
  vulnerabilityIntelSources,
  vulnerabilityIntelStatuses,
  vulnerabilityIntelInKevFilter,
  normalizeVulnerabilitySource,
  expandVulnerabilitySourceFilters
}: UseInventoryDataArgs): UseInventoryDataResult {
  const showingVulnerabilityIntel = selectedView === 'vulnerability-intelligence';
  const assetTypeParam = scopedAssetType === 'ALL'
    ? (
      componentActiveFilters.includes('assetType') && componentAssetTypes.length > 0
        ? componentAssetTypes.filter((value): value is InventoryComponentRecord['assetType'] => (
          value === 'APPLICATION' || value === 'HOST' || value === 'CONTAINER_IMAGE'
        ))
        : undefined
    )
    : [scopedAssetType as InventoryComponentRecord['assetType']];
  const componentStatusParam = componentActiveFilters.includes('componentStatus') && componentStatuses.length > 0
    ? componentStatuses.filter((value): value is InventoryComponentRecord['componentStatus'] => (
      value === 'ACTIVE' || value === 'RETIRED'
    ))
    : undefined;
  const inventoryQuery = useInventoryComponentsQuery({
    assetType: assetTypeParam,
    componentStatus: componentStatusParam,
    sourceSystem: componentActiveFilters.includes('sourceSystem') && componentSourceSystems.length > 0
      ? componentSourceSystems
      : undefined,
    ecosystem: componentActiveFilters.includes('ecosystem') && componentEcosystems.length > 0
      ? componentEcosystems
      : undefined,
    reviewCategory: selectedView === 'hosts'
      && componentActiveFilters.includes('reviewCategory')
      && componentReviewCategories.length > 0
      ? componentReviewCategories
      : undefined,
    query: componentActiveFilters.includes('query') ? debouncedComponentQuery.trim() : undefined,
    page: componentPage,
    size: 25
  }, !showingVulnerabilityIntel);
  const componentFiltersQuery = useInventoryComponentFiltersQuery(!showingVulnerabilityIntel);
  const vulnerabilityIntelQuery = useVulnerabilityIntelligenceQuery({
    page: vulnerabilityIntelPage,
    size: 25,
    query: debouncedVulnerabilityIntelQuery.trim() || undefined,
    affectedPackage: debouncedVulnerabilityIntelAffectedPackageQuery.trim() || undefined,
    severity: vulnerabilityIntelSeverities.length > 0 ? vulnerabilityIntelSeverities : undefined,
    source: vulnerabilityIntelSources.length > 0 ? expandVulnerabilitySourceFilters(vulnerabilityIntelSources) : undefined,
    vulnStatus: vulnerabilityIntelStatuses.length > 0 ? vulnerabilityIntelStatuses : undefined,
    inKev: vulnerabilityIntelInKevFilter
  }, showingVulnerabilityIntel);
  const vulnerabilityIntelFiltersQuery = useVulnerabilityIntelligenceFiltersQuery(showingVulnerabilityIntel);

  const normalizedVulnerabilityIntelRows = React.useMemo<VulnerabilityIntelRecord[]>(() => (
    (vulnerabilityIntelQuery.data?.items ?? []).map((record) => ({
      ...record,
      sources: Array.from(
        new Set(
          (record.sources || [])
            .filter((source) => source && source.trim().length > 0)
            .map((source) => normalizeVulnerabilitySource(source))
        )
      )
    }))
  ), [normalizeVulnerabilitySource, vulnerabilityIntelQuery.data?.items]);

  const componentFilterValues: InventoryComponentFilterValues = React.useMemo(() => {
    const availableFilters = componentFiltersQuery.data;
    if (!availableFilters) {
      return DEFAULT_COMPONENT_FILTERS;
    }
    return {
      assetTypes: Array.from(new Set(
        (availableFilters.assetTypes || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toUpperCase())
      )),
      componentStatuses: Array.from(new Set(
        (availableFilters.componentStatuses || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toUpperCase())
      )),
      sourceSystems: Array.from(new Set(
        (availableFilters.sourceSystems || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toLowerCase())
      )),
      ecosystems: Array.from(new Set(
        (availableFilters.ecosystems || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toLowerCase())
      ))
    };
  }, [componentFiltersQuery.data]);

  const vulnerabilityIntelFilterValues: VulnerabilityIntelFilterValues = React.useMemo(() => {
    const availableFilters = vulnerabilityIntelFiltersQuery.data;
    if (!availableFilters) {
      return DEFAULT_VULNERABILITY_INTEL_FILTERS;
    }
    return {
      severities: Array.from(new Set(
        (availableFilters.severities || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toUpperCase())
      )),
      sources: Array.from(new Set(
        (availableFilters.sources || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => normalizeVulnerabilitySource(value))
      )),
      vulnStatuses: Array.from(new Set(
        (availableFilters.vulnStatuses || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toUpperCase())
      )),
      inKevValues: Array.from(new Set(
        (availableFilters.inKevValues || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toLowerCase())
      ))
    };
  }, [normalizeVulnerabilitySource, vulnerabilityIntelFiltersQuery.data]);

  const refreshInventory = React.useCallback(async () => {
    if (showingVulnerabilityIntel) {
      await Promise.all([
        vulnerabilityIntelQuery.refetch(),
        vulnerabilityIntelFiltersQuery.refetch()
      ]);
      return;
    }
    await Promise.all([
      inventoryQuery.refetch(),
      componentFiltersQuery.refetch()
    ]);
  }, [
    componentFiltersQuery,
    inventoryQuery,
    showingVulnerabilityIntel,
    vulnerabilityIntelFiltersQuery,
    vulnerabilityIntelQuery
  ]);

  return {
    rows: showingVulnerabilityIntel ? [] : (inventoryQuery.data?.items ?? []),
    componentTotalItems: showingVulnerabilityIntel ? 0 : (inventoryQuery.data?.totalItems ?? 0),
    componentTotalPages: showingVulnerabilityIntel ? 0 : (inventoryQuery.data?.totalPages ?? 0),
    componentFilterValues,
    vulnerabilityIntelRows: showingVulnerabilityIntel ? normalizedVulnerabilityIntelRows : [],
    vulnerabilityIntelTotalItems: showingVulnerabilityIntel ? (vulnerabilityIntelQuery.data?.totalItems ?? 0) : 0,
    vulnerabilityIntelTotalPages: showingVulnerabilityIntel ? (vulnerabilityIntelQuery.data?.totalPages ?? 0) : 0,
    vulnerabilityIntelFilterValues,
    loading: showingVulnerabilityIntel
      ? vulnerabilityIntelQuery.isLoading || vulnerabilityIntelQuery.isFetching || vulnerabilityIntelFiltersQuery.isLoading
      : inventoryQuery.isLoading || inventoryQuery.isFetching || componentFiltersQuery.isLoading,
    error: (
      showingVulnerabilityIntel ? vulnerabilityIntelQuery.error : inventoryQuery.error
    ) instanceof Error
      ? String((showingVulnerabilityIntel ? vulnerabilityIntelQuery.error : inventoryQuery.error) as Error)
      : '',
    refreshInventory
  };
}

export function useVulnerabilityIntelDetail({
  selectedView,
  selectedVulnerabilityIntelId
}: UseVulnerabilityIntelDetailArgs): UseVulnerabilityIntelDetailResult {
  const detailQuery = useVulnerabilityIntelligenceDetailQuery(
    selectedVulnerabilityIntelId,
    selectedView === 'vulnerability-intelligence'
  );

  return {
    selectedVulnerabilityIntelDetail: detailQuery.data ?? null,
    vulnerabilityIntelDetailLoading: detailQuery.isLoading || detailQuery.isFetching
  };
}
