import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';

export type EolComponentStatusesQueryParams = Parameters<typeof api.getEolComponentStatuses>[0];

export function useEolSummaryQuery(enabled = true) {
  return useQuery({
    queryKey: ['eol-summary'],
    queryFn: api.getEolSummary,
    enabled
  });
}

export function useEolComponentStatusesQuery(params: EolComponentStatusesQueryParams, enabled = true) {
  return useQuery({
    queryKey: ['eol-component-statuses', params],
    queryFn: () => api.getEolComponentStatuses(params),
    enabled,
    placeholderData: keepPreviousData
  });
}

export function useEolProductsQuery(enabled = true) {
  return useQuery({
    queryKey: ['eol-products'],
    queryFn: api.listEolProducts,
    enabled
  });
}

export function useEolReleasesQuery(slug: string | null, enabled = true) {
  return useQuery({
    queryKey: ['eol-releases', slug],
    queryFn: () => api.listEolProductReleases(slug ?? ''),
    enabled: enabled && Boolean(slug)
  });
}

export function useEolUnresolvedMappingsQuery(enabled = true) {
  return useQuery({
    queryKey: ['eol-unresolved-mappings'],
    queryFn: api.listEolUnresolvedMappings,
    enabled
  });
}
