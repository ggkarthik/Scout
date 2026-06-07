import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type {
  Finding,
  FindingBacklogHealth,
  FindingDistributions,
  FindingFilterValues,
  FindingProjectionStatus,
  FindingQueueAnalytics,
  FindingQueueAnalyticsTrendPoint,
  FindingQueueDefinition,
  FindingPage,
  FindingPortfolioRollup,
  FindingSummary
} from '../features/findings/types';
import type { RiskPolicy } from '../features/configurations/types';
import { renderWithProviders } from '../test/test-utils';
import { FindingsPage } from './FindingsPage';

function buildFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    displayId: 'F-001',
    componentId: 'cmp-1',
    assetName: 'web-prod-01',
    assetIdentifier: 'web-prod-01.example.com',
    assetType: 'HOST',
    packageName: 'openssl',
    packageVersion: '1.1.1k',
    vulnerabilityId: 'CVE-2026-1234',
    source: 'NVD',
    creationSource: 'AUTOMATIC',
    severity: 'CRITICAL',
    inKev: true,
    epss: 0.42,
    riskScore: 9.1,
    confidenceScore: 0.95,
    matchedBy: 'CPE',
    assignedTo: 'analyst@example.com',
    dueAt: '2026-05-15T00:00:00Z',
    evidence: '{}',
    firstObservedAt: '2026-04-01T00:00:00Z',
    lastObservedAt: '2026-04-25T00:00:00Z',
    decisionState: 'AFFECTED',
    status: 'OPEN',
    updatedAt: '2026-04-25T00:00:00Z',
    ...overrides,
  };
}

const FILTER_VALUES: FindingFilterValues = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'],
  statuses: ['OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'],
  decisionStates: ['AFFECTED', 'NOT_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'NEEDS_REVIEW'],
  matchMethods: ['CPE', 'PURL'],
  vexStatuses: [],
  vexFreshness: [],
  vexProviders: [],
  owners: [],
  supportGroups: [],
  assignedTo: [],
  ownershipSources: [],
};

const RISK_POLICY: RiskPolicy = {
  criticalThreshold: 9, highThreshold: 7,
  criticalSlaDays: 7, highSlaDays: 14, mediumSlaDays: 30, lowSlaDays: 60,
  assetCriticalSlaMultiplier: 0.5, assetHighSlaMultiplier: 0.75,
  assetMediumSlaMultiplier: 1, assetLowSlaMultiplier: 1.25,
  autoCloseEnabled: false, autoCloseAfterDays: 30, findingGenerationMode: 'AUTO',
  triageExploitabilityWeight: 1, triageBlastRadiusWeight: 1, triageEolRiskWeight: 1,
  triageSlaBreachWeight: 1, triageMissingOwnerBoost: 1, triagePatchGapBoost: 1,
};

function pageOf(items: Finding[]): FindingPage {
  return { items, page: 0, size: 25, totalItems: items.length, totalPages: 1, nextCursor: null };
}

const FINDING_SUMMARY: FindingSummary = {
  openCount: 1,
  criticalOpenCount: 1,
  withIncidentCount: 0,
  unassignedOpenCount: 0,
  overdueOpenCount: 1,
  noSlaOpenCount: 0,
};

const FINDING_DISTRIBUTIONS: FindingDistributions = {
  severityCounts: [{ key: 'CRITICAL', count: 1 }],
  statusCounts: [{ key: 'OPEN', count: 1 }],
  topAssets: [{ assetName: 'web-prod-01', count: 1 }],
};

const FINDING_BACKLOG_HEALTH: FindingBacklogHealth = {
  overdue: 1,
  dueSoon: 0,
  onTrack: 0,
  noSla: 0,
};

const FINDING_QUEUE_ANALYTICS: FindingQueueAnalytics = {
  agingBuckets: [
    { key: '0-7d', count: 1 },
    { key: '8-30d', count: 0 },
    { key: '31-90d', count: 0 },
    { key: '90d+', count: 0 },
  ],
  reopenRatePercent: 12.5,
  reopenedCountLast30Days: 1,
  assignedOpenCount: 1,
  unassignedOpenCount: 0,
  withIncidentCount: 0,
  withoutIncidentCount: 1,
  oldestOpenAgeDays: 24,
  medianOpenAgeDays: 24,
  topOwners: [{ label: 'analyst@example.com', count: 1 }],
  topSupportGroups: [{ label: 'Platform Ops', count: 1 }],
};

const FINDING_QUEUE_TREND: FindingQueueAnalyticsTrendPoint[] = [
  { date: '2026-05-29', openedCount: 1, resolvedCount: 0, reopenedCount: 0 },
  { date: '2026-05-30', openedCount: 0, resolvedCount: 1, reopenedCount: 0 },
  { date: '2026-05-31', openedCount: 0, resolvedCount: 0, reopenedCount: 1 },
];

const FINDING_PORTFOLIO_ROLLUP: FindingPortfolioRollup = {
  totalOpenCount: 12,
  totalCriticalOpenCount: 3,
  totalOverdueOpenCount: 2,
  queueRollups: [
    {
      queueKey: 'all-findings',
      title: 'All Findings',
      matchingCount: 12,
      openCount: 12,
      criticalOpenCount: 3,
      overdueOpenCount: 2,
      unassignedOpenCount: 1,
      withIncidentCount: 4,
    },
    {
      queueKey: 'critical-open',
      title: 'Critical Open',
      matchingCount: 3,
      openCount: 3,
      criticalOpenCount: 3,
      overdueOpenCount: 1,
      unassignedOpenCount: 0,
      withIncidentCount: 1,
    },
  ],
  topOwnerGroups: [{ label: 'Platform', count: 5 }],
  topSupportGroups: [{ label: 'Ops', count: 6 }],
};

const FINDING_PROJECTION_STATUS: FindingProjectionStatus = {
  lastComputedAt: '2026-06-05T10:15:30Z',
  findingCount: 12,
  sourceFindingCount: 12,
  stale: false,
  driftCount: 0,
  lastRebuildDurationMs: 241,
};

const FINDING_QUEUES: FindingQueueDefinition[] = [
  {
    id: null,
    key: 'all-findings',
    title: 'All Findings',
    description: 'Full findings backlog across the active tenant.',
    kind: 'BUILT_IN',
    ownerType: 'SYSTEM',
    editable: false,
    isDefault: false,
    matchingCount: 1,
    filter: {},
    summary: FINDING_SUMMARY,
  },
  {
    id: null,
    key: 'critical-open',
    title: 'Critical Open',
    description: 'Open findings currently scored at critical severity.',
    kind: 'BUILT_IN',
    ownerType: 'SYSTEM',
    editable: false,
    isDefault: false,
    matchingCount: 1,
    filter: { severity: ['CRITICAL'], status: ['OPEN'] },
    summary: FINDING_SUMMARY,
  },
  {
    id: 'queue-1',
    key: 'personal:queue-1',
    title: 'My Queue',
    description: 'Saved personal queue',
    kind: 'PERSONAL',
    ownerType: 'USER',
    editable: true,
    isDefault: true,
    matchingCount: 1,
    filter: { severity: ['CRITICAL'], status: ['OPEN'], assignedTo: 'analyst@example.com' },
    summary: FINDING_SUMMARY,
  },
];

describe('FindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders the findings table with mocked data', async () => {
    const listFindingsSpy = vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingQueueAnalytics').mockResolvedValue(FINDING_QUEUE_ANALYTICS);
    vi.spyOn(api, 'getFindingQueueAnalyticsTrend').mockResolvedValue(FINDING_QUEUE_TREND);
    vi.spyOn(api, 'getFindingPortfolioRollups').mockResolvedValue(FINDING_PORTFOLIO_ROLLUP);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument();
    // Asset name appears in both the row and the "Top Assets at Risk" widget
    expect(screen.getAllByText('web-prod-01').length).toBeGreaterThan(0);
    expect(screen.getByRole('columnheader', { name: /Finding ID/ })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /CVE ID/ })).toBeInTheDocument();
    expect(listFindingsSpy).toHaveBeenCalled();
  });

  it('shows the empty state when there are no findings and no active filter chips beyond defaults', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue({ ...FINDING_SUMMARY, openCount: 0, criticalOpenCount: 0, overdueOpenCount: 0 });
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue({ severityCounts: [], statusCounts: [], topAssets: [] });
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue({ overdue: 0, dueSoon: 0, onTrack: 0, noSla: 0 });
    vi.spyOn(api, 'getFindingQueueAnalytics').mockResolvedValue({ ...FINDING_QUEUE_ANALYTICS, agingBuckets: [], topOwners: [], topSupportGroups: [] });
    vi.spyOn(api, 'getFindingQueueAnalyticsTrend').mockResolvedValue([]);
    vi.spyOn(api, 'getFindingPortfolioRollups').mockResolvedValue({ ...FINDING_PORTFOLIO_ROLLUP, queueRollups: [], topOwnerGroups: [], topSupportGroups: [] });
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    // No findings and no active chips → "No findings yet" onboarding state.
    await waitFor(() => {
      expect(screen.getByText(/No findings yet/i)).toBeInTheDocument();
    });
  });

  it('renders the SLA & Due Date widget header from the dashboard widgets row', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingQueueAnalytics').mockResolvedValue(FINDING_QUEUE_ANALYTICS);
    vi.spyOn(api, 'getFindingQueueAnalyticsTrend').mockResolvedValue(FINDING_QUEUE_TREND);
    vi.spyOn(api, 'getFindingPortfolioRollups').mockResolvedValue(FINDING_PORTFOLIO_ROLLUP);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    expect(screen.getByText('Exposure by Severity')).toBeInTheDocument();
    expect(screen.getByText('Findings by Status')).toBeInTheDocument();
    expect(screen.getByText('SLA & Due Date')).toBeInTheDocument();
  });

  it('switches queues and passes queueKey through the findings queries', async () => {
    const listFindingsSpy = vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    const queueAnalyticsSpy = vi.spyOn(api, 'getFindingQueueAnalytics').mockResolvedValue(FINDING_QUEUE_ANALYTICS);
    const queueTrendSpy = vi.spyOn(api, 'getFindingQueueAnalyticsTrend').mockResolvedValue(FINDING_QUEUE_TREND);
    vi.spyOn(api, 'getFindingPortfolioRollups').mockResolvedValue(FINDING_PORTFOLIO_ROLLUP);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: /Critical Open \(1\)/i }));

    await waitFor(() => {
      expect(listFindingsSpy).toHaveBeenLastCalledWith(expect.objectContaining({ queueKey: 'critical-open' }));
      expect(queueAnalyticsSpy).toHaveBeenLastCalledWith(expect.objectContaining({ queueKey: 'critical-open' }));
      expect(queueTrendSpy).toHaveBeenLastCalledWith(expect.objectContaining({ queueKey: 'critical-open' }), 30);
    });
  });

  it('saves the current view as a personal queue', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingQueueAnalytics').mockResolvedValue(FINDING_QUEUE_ANALYTICS);
    vi.spyOn(api, 'getFindingQueueAnalyticsTrend').mockResolvedValue(FINDING_QUEUE_TREND);
    vi.spyOn(api, 'getFindingPortfolioRollups').mockResolvedValue(FINDING_PORTFOLIO_ROLLUP);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const createQueueSpy = vi.spyOn(api, 'createFindingQueue').mockResolvedValue(FINDING_QUEUES[2]!);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getAllByRole('button', { name: /Save Current View/i })[0]!);
    fireEvent.change(screen.getByPlaceholderText(/Queue title/i), { target: { value: 'Ops Queue' } });
    fireEvent.click(screen.getByRole('button', { name: /Save Queue/i }));

    await waitFor(() => {
      expect(createQueueSpy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Ops Queue' }));
    });
  });

  it('shows a local queue analytics error without breaking the findings grid', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingQueueAnalytics').mockRejectedValue(new Error('Queue analytics unavailable'));
    vi.spyOn(api, 'getFindingQueueAnalyticsTrend').mockResolvedValue(FINDING_QUEUE_TREND);
    vi.spyOn(api, 'getFindingPortfolioRollups').mockResolvedValue(FINDING_PORTFOLIO_ROLLUP);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    await waitFor(() => {
      expect(screen.getByText(/Queue analytics unavailable/i)).toBeInTheDocument();
    });
    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument();
  });

  it('renders tenant-wide portfolio rollups alongside the queue workspace', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingQueueAnalytics').mockResolvedValue(FINDING_QUEUE_ANALYTICS);
    vi.spyOn(api, 'getFindingQueueAnalyticsTrend').mockResolvedValue(FINDING_QUEUE_TREND);
    vi.spyOn(api, 'getFindingPortfolioRollups').mockResolvedValue(FINDING_PORTFOLIO_ROLLUP);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('Portfolio Rollups');
    await screen.findByText('Queue Portfolio Snapshot');
    expect(screen.getByText('Total Open')).toBeInTheDocument();
    expect(screen.getByText('Platform')).toBeInTheDocument();
    expect(screen.getByText('Ops')).toBeInTheDocument();
  });
});
