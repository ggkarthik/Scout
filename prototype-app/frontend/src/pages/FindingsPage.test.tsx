import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { Finding, FindingFilterValues, FindingPage } from '../features/findings/types';
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
  cvssWeight: 1, kevBoost: 2, epssWeight: 1,
  vexNotAffectedFreshnessDays: 30, vexFixedFreshnessDays: 30,
  vexKnownAffectedBoost: 0.4, vexUnderInvestigationPenalty: 0.2,
  vexNotAffectedReduction: 0.8, vexStalePenalty: 0.5,
  criticalThreshold: 9, highThreshold: 7,
  assetCriticalRiskBoost: 1.5, assetHighRiskBoost: 1,
  assetMediumRiskBoost: 0.5, assetLowRiskBoost: 0,
  criticalSlaDays: 7, highSlaDays: 14, mediumSlaDays: 30, lowSlaDays: 60,
  assetCriticalSlaMultiplier: 0.5, assetHighSlaMultiplier: 0.75,
  assetMediumSlaMultiplier: 1, assetLowSlaMultiplier: 1.25,
  autoCloseEnabled: false, autoCloseAfterDays: 30, findingGenerationMode: 'AUTO',
  triageExploitabilityWeight: 1, triageBlastRadiusWeight: 1, triageEolRiskWeight: 1,
  triageSlaBreachWeight: 1, triageMissingOwnerBoost: 1, triagePatchGapBoost: 1,
};

function pageOf(items: Finding[]): FindingPage {
  return { items, page: 0, size: 25, totalItems: items.length, totalPages: 1 };
}

describe('FindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders the findings table with mocked data', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument();
    // Asset name appears in both the row and the "Top Assets at Risk" widget
    expect(screen.getAllByText('web-prod-01').length).toBeGreaterThan(0);
    expect(screen.getByRole('columnheader', { name: /Finding ID/ })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /CVE ID/ })).toBeInTheDocument();
  });

  it('shows the empty state when there are no findings and no active filter chips beyond defaults', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([]));
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    // Default filters (severity CRITICAL+HIGH, status OPEN) produce active chips,
    // so empty state shows the "no findings matched" branch.
    await waitFor(() => {
      expect(screen.getByText(/No findings matched/i)).toBeInTheDocument();
    });
  });

  it('renders the SLA & Due Date widget header from the dashboard widgets row', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    expect(screen.getByText('Exposure by Severity')).toBeInTheDocument();
    expect(screen.getByText('Findings by Status')).toBeInTheDocument();
    expect(screen.getByText('SLA & Due Date')).toBeInTheDocument();
  });
});
