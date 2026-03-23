import React from 'react';
import { api } from '../../api/client';
import type {
  InventoryComponentFilterValues,
  InventoryComponentRecord,
  VulnerabilityIntelDetail,
  VulnerabilityIntelFilterValues,
  VulnerabilityIntelRecord
} from '../../types';
import {
  DEFAULT_COMPONENT_FILTERS,
  DEFAULT_VULNERABILITY_INTEL_FILTERS
} from './config';

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
  vulnerabilityIntelSeverities,
  vulnerabilityIntelSources,
  vulnerabilityIntelStatuses,
  vulnerabilityIntelInKevFilter,
  normalizeVulnerabilitySource,
  expandVulnerabilitySourceFilters
}: UseInventoryDataArgs): UseInventoryDataResult {
  const [rows, setRows] = React.useState<InventoryComponentRecord[]>([]);
  const [componentTotalItems, setComponentTotalItems] = React.useState(0);
  const [componentTotalPages, setComponentTotalPages] = React.useState(0);
  const [vulnerabilityIntelRows, setVulnerabilityIntelRows] = React.useState<VulnerabilityIntelRecord[]>([]);
  const [vulnerabilityIntelTotalItems, setVulnerabilityIntelTotalItems] = React.useState(0);
  const [vulnerabilityIntelTotalPages, setVulnerabilityIntelTotalPages] = React.useState(0);
  const [vulnerabilityIntelFilterValues, setVulnerabilityIntelFilterValues] = React.useState<VulnerabilityIntelFilterValues>(
    DEFAULT_VULNERABILITY_INTEL_FILTERS
  );
  const [componentFilterValues, setComponentFilterValues] = React.useState<InventoryComponentFilterValues>(
    DEFAULT_COMPONENT_FILTERS
  );
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');
  const loadRequestIdRef = React.useRef(0);

  const refreshInventory = React.useCallback(async () => {
    const requestId = loadRequestIdRef.current + 1;
    loadRequestIdRef.current = requestId;
    setLoading(true);
    setError('');

    try {
      if (selectedView === 'vulnerability-intelligence') {
        const response = await api.listVulnerabilityIntelligence({
          page: vulnerabilityIntelPage,
          size: 25,
          query: debouncedVulnerabilityIntelQuery.trim() || undefined,
          severity: vulnerabilityIntelSeverities.length > 0 ? vulnerabilityIntelSeverities : undefined,
          source: vulnerabilityIntelSources.length > 0 ? expandVulnerabilitySourceFilters(vulnerabilityIntelSources) : undefined,
          vulnStatus: vulnerabilityIntelStatuses.length > 0 ? vulnerabilityIntelStatuses : undefined,
          inKev: vulnerabilityIntelInKevFilter
        });
        if (requestId !== loadRequestIdRef.current) {
          return;
        }

        const normalizedRows = response.items.map((record) => ({
          ...record,
          sources: Array.from(
            new Set(
              (record.sources || [])
                .filter((source) => source && source.trim().length > 0)
                .map((source) => normalizeVulnerabilitySource(source))
            )
          )
        }));

        setVulnerabilityIntelRows(normalizedRows);
        setVulnerabilityIntelTotalItems(response.totalItems);
        setVulnerabilityIntelTotalPages(response.totalPages);
        setRows([]);
        setComponentTotalItems(0);
        setComponentTotalPages(0);

        void api.listVulnerabilityIntelligenceFilters()
          .then((availableFilters) => {
            if (requestId !== loadRequestIdRef.current) {
              return;
            }
            setVulnerabilityIntelFilterValues({
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
            });
          })
          .catch(() => {
            if (requestId !== loadRequestIdRef.current) {
              return;
            }
            setVulnerabilityIntelFilterValues(DEFAULT_VULNERABILITY_INTEL_FILTERS);
          });

        return;
      }

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

      const [data, availableFilters] = await Promise.all([
        api.listInventoryComponents({
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
        }),
        api.listInventoryComponentFilters().catch(() => DEFAULT_COMPONENT_FILTERS)
      ]);
      if (requestId !== loadRequestIdRef.current) {
        return;
      }

      setComponentFilterValues({
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
      });
      setRows(data.items);
      setComponentTotalItems(data.totalItems);
      setComponentTotalPages(data.totalPages);
      setVulnerabilityIntelRows([]);
      setVulnerabilityIntelTotalItems(0);
      setVulnerabilityIntelTotalPages(0);
    } catch (requestError) {
      if (requestId !== loadRequestIdRef.current) {
        return;
      }
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      if (requestId === loadRequestIdRef.current) {
        setLoading(false);
      }
    }
  }, [
    componentActiveFilters,
    componentAssetTypes,
    componentEcosystems,
    componentPage,
    componentReviewCategories,
    componentSourceSystems,
    componentStatuses,
    debouncedComponentQuery,
    debouncedVulnerabilityIntelQuery,
    expandVulnerabilitySourceFilters,
    normalizeVulnerabilitySource,
    scopedAssetType,
    selectedView,
    vulnerabilityIntelInKevFilter,
    vulnerabilityIntelPage,
    vulnerabilityIntelSeverities,
    vulnerabilityIntelSources,
    vulnerabilityIntelStatuses
  ]);

  React.useEffect(() => {
    void refreshInventory();
  }, [refreshInventory]);

  return {
    rows,
    componentTotalItems,
    componentTotalPages,
    componentFilterValues,
    vulnerabilityIntelRows,
    vulnerabilityIntelTotalItems,
    vulnerabilityIntelTotalPages,
    vulnerabilityIntelFilterValues,
    loading,
    error,
    refreshInventory
  };
}

export function useVulnerabilityIntelDetail({
  selectedView,
  selectedVulnerabilityIntelId
}: UseVulnerabilityIntelDetailArgs): UseVulnerabilityIntelDetailResult {
  const [selectedVulnerabilityIntelDetail, setSelectedVulnerabilityIntelDetail] = React.useState<VulnerabilityIntelDetail | null>(null);
  const [vulnerabilityIntelDetailLoading, setVulnerabilityIntelDetailLoading] = React.useState(false);

  React.useEffect(() => {
    if (selectedView !== 'vulnerability-intelligence' || !selectedVulnerabilityIntelId) {
      setSelectedVulnerabilityIntelDetail(null);
      setVulnerabilityIntelDetailLoading(false);
      return;
    }

    let cancelled = false;
    setVulnerabilityIntelDetailLoading(true);

    api.getVulnerabilityIntelligenceDetail(selectedVulnerabilityIntelId)
      .then((detail) => {
        if (!cancelled) {
          setSelectedVulnerabilityIntelDetail(detail);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedVulnerabilityIntelDetail(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setVulnerabilityIntelDetailLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedView, selectedVulnerabilityIntelId]);

  return {
    selectedVulnerabilityIntelDetail,
    vulnerabilityIntelDetailLoading
  };
}
