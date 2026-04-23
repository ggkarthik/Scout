import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../../lib/polling';
import type { SyncRun } from './types';

export type SyncRunsQueryParams = Parameters<typeof api.listSyncRuns>[0];
type QueryPollingOption = number | false | undefined;

function shouldPollRuns(runs: SyncRun[] | undefined): boolean {
  return (runs ?? []).some((run) => {
    const status = run.status.trim().toUpperCase();
    return status === 'RUNNING' || status === 'STARTED' || status === 'QUEUED';
  });
}

export function useSyncRunsQuery(params: SyncRunsQueryParams, enabled = true, refetchInterval?: QueryPollingOption) {
  return useQuery({
    queryKey: ['sync-runs', params],
    queryFn: () => api.listSyncRuns(params),
    enabled,
    placeholderData: keepPreviousData,
    refetchInterval: refetchInterval ?? ((query) => (
      shouldPollRuns(query.state.data as SyncRun[] | undefined) ? RUN_QUEUE_REFRESH_INTERVAL_MS : false
    )),
    refetchIntervalInBackground: false
  });
}

export function useVexAssertionRepairSummaryQuery(enabled = true, refetchInterval?: QueryPollingOption) {
  return useQuery({
    queryKey: ['vex-assertion-repair-summary'],
    queryFn: api.getVexAssertionRepairSummary,
    enabled,
    refetchInterval
  });
}

export function useSourceFilterConfigQuery(sourceSystem: 'nvd' | 'kev' | 'ghsa' | 'redhat' | null, enabled = true) {
  return useQuery({
    queryKey: ['source-filter-config', sourceSystem],
    queryFn: () => api.getVulnerabilitySourceFilterConfig(sourceSystem ?? 'nvd'),
    enabled: enabled && sourceSystem != null
  });
}

export function useGithubSbomSourcesQuery() {
  return useQuery({
    queryKey: ['github-sbom-sources'],
    queryFn: api.listGithubSbomSources
  });
}

export function useServiceNowCmdbConfigQuery() {
  return useQuery({
    queryKey: ['service-now-cmdb-config'],
    queryFn: api.getServiceNowCmdbConfig
  });
}

export function useSccmCmdbConfigQuery() {
  return useQuery({
    queryKey: ['sccm-cmdb-config'],
    queryFn: api.getSccmCmdbConfig
  });
}
