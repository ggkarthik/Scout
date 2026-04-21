import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { DASHBOARD_REFRESH_INTERVAL_MS, OPERATIONS_REFRESH_INTERVAL_MS } from '../../lib/polling';
import type {
  OperationalApiReadPath,
  OperationalCorrelationEffectiveness,
  OperationalExecutiveHealth,
  OperationalFreshnessDrift,
  OperationalIngestionEfficiency,
  OperationalMetricDefinition,
  OperationalNoiseLifecycle,
  OperationalNormalizationQuality,
  OperationalSectionResponse,
  SloStatus
} from './types';
import type { Dashboard } from '../dashboard/types';

export type OperationsDashboardViewKey = 'quality' | 'pipeline' | 'platform-health';

export type PipelinePayload = {
  overview: OperationalSectionResponse<OperationalExecutiveHealth>;
  ingestion: OperationalSectionResponse<OperationalIngestionEfficiency>;
  normalization: OperationalSectionResponse<OperationalNormalizationQuality>;
  correlation: OperationalSectionResponse<OperationalCorrelationEffectiveness>;
  lifecycle: OperationalSectionResponse<OperationalNoiseLifecycle>;
  freshness: OperationalSectionResponse<OperationalFreshnessDrift>;
  dashboard: Dashboard | null;
};

export type PlatformHealthPayload = {
  readPath: OperationalSectionResponse<OperationalApiReadPath>;
  slo: SloStatus;
  catalog: OperationalSectionResponse<OperationalMetricDefinition[]>;
};

async function loadOperationsView(selectedView: OperationsDashboardViewKey): Promise<PipelinePayload | PlatformHealthPayload | null> {
  switch (selectedView) {
    case 'quality':
      return null;
    case 'pipeline': {
      const [overview, ingestion, normalization, correlation, lifecycle, freshness, dashboard] = await Promise.all([
        api.getOperationalOverview(),
        api.getOperationalIngestionEfficiency(),
        api.getOperationalNormalizationQuality(),
        api.getOperationalCorrelationEffectiveness(),
        api.getOperationalNoiseLifecycle(),
        api.getOperationalFreshnessDrift(),
        api.getDashboard().catch(() => null)
      ]);
      return {
        overview,
        ingestion,
        normalization,
        correlation,
        lifecycle,
        freshness,
        dashboard
      };
    }
    case 'platform-health': {
      const [readPath, slo, catalog] = await Promise.all([
        api.getOperationalApiReadPath(),
        api.getSloStatus(),
        api.getOperationalMetricCatalog()
      ]);
      return {
        readPath,
        slo,
        catalog
      };
    }
    default:
      return loadOperationsView('pipeline');
  }
}

export function useOperationsViewQuery(selectedView: OperationsDashboardViewKey) {
  return useQuery({
    queryKey: ['operations-view', selectedView],
    queryFn: () => loadOperationsView(selectedView),
    enabled: selectedView !== 'quality',
    refetchInterval: OPERATIONS_REFRESH_INTERVAL_MS
  });
}

export type OperationalQualityIssuesQueryParams = Parameters<typeof api.listOperationalQualityIssues>[0];

export function useOperationalQualitySummaryQuery() {
  return useQuery({
    queryKey: ['operational-quality-summary'],
    queryFn: api.getOperationalQualitySummary,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useOperationalQualityFiltersQuery() {
  return useQuery({
    queryKey: ['operational-quality-filters'],
    queryFn: api.getOperationalQualityFilters
  });
}

export function useOperationalQualityIssuesQuery(params: OperationalQualityIssuesQueryParams) {
  return useQuery({
    queryKey: ['operational-quality-issues', params],
    queryFn: () => api.listOperationalQualityIssues(params),
    placeholderData: keepPreviousData,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useOperationalQualityIssueDetailQuery(issueId: string | null) {
  return useQuery({
    queryKey: ['operational-quality-issue-detail', issueId],
    queryFn: () => api.getOperationalQualityIssue(issueId ?? ''),
    enabled: Boolean(issueId)
  });
}
