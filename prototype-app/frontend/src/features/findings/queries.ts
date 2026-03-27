import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';

export type FindingsQueryParams = Parameters<typeof api.listFindings>[0];

export function useFindingFiltersQuery() {
  return useQuery({
    queryKey: ['finding-filters'],
    queryFn: api.listFindingFilters
  });
}

export function useFindingsQuery(params: FindingsQueryParams) {
  return useQuery({
    queryKey: ['findings', params],
    queryFn: () => api.listFindings(params),
    placeholderData: keepPreviousData
  });
}
