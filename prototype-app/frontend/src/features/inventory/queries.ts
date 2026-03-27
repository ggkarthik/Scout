import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';

export type InventoryComponentsQueryParams = Parameters<typeof api.listInventoryComponents>[0];
export type VulnerabilityIntelQueryParams = Parameters<typeof api.listVulnerabilityIntelligence>[0];

export function useInventoryComponentsQuery(params: InventoryComponentsQueryParams, enabled = true) {
  return useQuery({
    queryKey: ['inventory-components', params],
    queryFn: () => api.listInventoryComponents(params),
    enabled,
    placeholderData: keepPreviousData
  });
}

export function useInventoryComponentFiltersQuery(enabled = true) {
  return useQuery({
    queryKey: ['inventory-component-filters'],
    queryFn: api.listInventoryComponentFilters,
    enabled
  });
}

export function useVulnerabilityIntelligenceQuery(params: VulnerabilityIntelQueryParams, enabled = true) {
  return useQuery({
    queryKey: ['vulnerability-intelligence', params],
    queryFn: () => api.listVulnerabilityIntelligence(params),
    enabled,
    placeholderData: keepPreviousData
  });
}

export function useVulnerabilityIntelligenceFiltersQuery(enabled = true) {
  return useQuery({
    queryKey: ['vulnerability-intelligence-filters'],
    queryFn: api.listVulnerabilityIntelligenceFilters,
    enabled
  });
}

export function useVulnerabilityIntelligenceDetailQuery(externalId: string | null, enabled = true) {
  return useQuery({
    queryKey: ['vulnerability-intelligence-detail', externalId],
    queryFn: () => api.getVulnerabilityIntelligenceDetail(externalId ?? ''),
    enabled: enabled && Boolean(externalId)
  });
}

export function useHostAssetDetailQuery(assetId: string | null, sourceSystem?: string) {
  return useQuery({
    queryKey: ['host-asset-detail', assetId, sourceSystem],
    queryFn: () => api.getHostAssetDetail(assetId ?? '', sourceSystem ? { sourceSystem } : undefined),
    enabled: Boolean(assetId)
  });
}
