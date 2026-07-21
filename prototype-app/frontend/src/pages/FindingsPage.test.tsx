import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type {
  Finding,
  FindingBacklogHealth,
  FindingDistributions,
  FindingFilterValues,
  FindingProjectionStatus,
  FindingQueueDefinition,
  FindingPage,
  FindingSummary
} from '../features/findings/types';
import type { RiskPolicy } from '../features/configurations/types';
import { renderWithProviders } from '../test/test-utils';
import { FindingsPage } from './FindingsPage';

const ACTOR: ActorContext = {
  creator: false,
  principal: 'analyst@example.com',
  userId: 'user-1',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_SECURITY_ANALYST'],
};

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
  autoCloseRequiredConsecutiveMisses: 2,
  autoCloseNotObservedEnabled: true,
  autoCloseComponentRemovedEnabled: true,
  autoCloseAssetRetiredEnabled: true,
  autoCloseSourceDisabledEnabled: false,
  autoCloseDuplicateEnabled: true,
  autoCloseRunIntervalDays: 1,
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
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
    expect(screen.getByText(/Projection healthy/i)).toBeInTheDocument();
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
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

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
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    expect(screen.getByText('Exposure by Severity')).toBeInTheDocument();
    expect(screen.getByText('Findings by Status')).toBeInTheDocument();
    expect(screen.getByText('SLA & Due Date')).toBeInTheDocument();
  });

  it('passes the default queueKey through the findings queries', async () => {
    const listFindingsSpy = vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');

    await waitFor(() => {
      expect(listFindingsSpy).toHaveBeenCalledWith(expect.objectContaining({ queueKey: expect.any(String) }));
    });
  });

  it('saves the current view as a personal queue', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
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

  it('edits an existing personal queue', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const updateQueueSpy = vi.spyOn(api, 'updateFindingQueue').mockResolvedValue({
      ...FINDING_QUEUES[2]!,
      title: 'Ops Escalations',
      description: 'Updated queue scope',
      isDefault: false,
    });

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: /Edit Queue/i }));
    fireEvent.change(screen.getByPlaceholderText(/Queue title/i), { target: { value: 'Ops Escalations' } });
    fireEvent.change(screen.getByPlaceholderText(/Optional description/i), { target: { value: 'Updated queue scope' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /Set as my default queue/i }));
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }));

    await waitFor(() => {
      expect(updateQueueSpy).toHaveBeenCalledWith('personal:queue-1', expect.objectContaining({
        title: 'Ops Escalations',
        description: 'Updated queue scope',
        setAsDefault: false,
      }));
    });
  });

  it('duplicates and sets a personal queue as default from the findings toolbar', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue([
      FINDING_QUEUES[0]!,
      FINDING_QUEUES[1]!,
      { ...FINDING_QUEUES[2]!, isDefault: false },
    ]);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const duplicateQueueSpy = vi.spyOn(api, 'duplicateFindingQueue').mockResolvedValue({
      ...FINDING_QUEUES[2]!,
      id: 'queue-2',
      key: 'personal:queue-2',
      title: 'My Queue Copy',
      isDefault: false,
    });
    const setDefaultQueueSpy = vi.spyOn(api, 'setDefaultFindingQueue').mockResolvedValue();

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: /Duplicate Queue/i }));
    fireEvent.click(screen.getByRole('button', { name: /Set Default/i }));

    await waitFor(() => {
      expect(duplicateQueueSpy).toHaveBeenCalledWith('personal:queue-1');
      expect(setDefaultQueueSpy).toHaveBeenCalledWith('personal:queue-1');
    });
  });

  it('deletes an existing personal queue after confirmation', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const deleteQueueSpy = vi.spyOn(api, 'deleteFindingQueue').mockResolvedValue();

    renderWithProviders(<FindingsPage />);

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('button', { name: /Delete Queue/i }));

    await waitFor(() => {
      expect(deleteQueueSpy).toHaveBeenCalledWith('personal:queue-1');
    });
  });

  it('defers and deletes selected findings through the bulk action flows', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const bulkUpdateSpy = vi.spyOn(api, 'bulkUpdateFindingWorkflow').mockResolvedValue({
      targeted: 1,
      updated: 1,
      failed: 0,
      message: 'Updated 1 finding',
    });
    const bulkDeleteSpy = vi.spyOn(api, 'bulkDeleteFindings').mockResolvedValue({
      deleted: 1,
      message: 'Deleted 1 finding',
    });

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('checkbox', { name: /Select row/i }));
    fireEvent.click(screen.getByTitle(/More actions/i));
    fireEvent.click(screen.getByRole('button', { name: /Defer/i }));
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'PENDING_PATCH' } });
    fireEvent.change(document.querySelector('.fd3-modal input[type="date"]') as HTMLInputElement, { target: { value: '2026-06-30' } });
    fireEvent.click(document.querySelector('.fd3-modal .btn-primary') as HTMLButtonElement);

    await waitFor(() => {
      expect(bulkUpdateSpy).toHaveBeenLastCalledWith(expect.objectContaining({
        findingIds: ['finding-1'],
        workflowStatus: 'SUPPRESSED',
        suppressionReason: 'PENDING_PATCH',
        suppressedUntil: '2026-06-30T00:00:00.000Z',
        actor: 'analyst@example.com',
      }));
    });

    fireEvent.click(screen.getByRole('checkbox', { name: /Select row/i }));
    fireEvent.click(screen.getByTitle(/More actions/i));
    fireEvent.click(screen.getByRole('button', { name: /^Delete$/i }));
    fireEvent.click(document.querySelector('.fd3-modal .btn-danger') as HTMLButtonElement);

    await waitFor(() => {
      expect(bulkDeleteSpy).toHaveBeenCalledWith(['finding-1']);
    });
  });

  it('creates a ServiceNow incident for the selected finding', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(pageOf([buildFinding()]));
    vi.spyOn(api, 'getFindingSummary').mockResolvedValue(FINDING_SUMMARY);
    vi.spyOn(api, 'getFindingDistributions').mockResolvedValue(FINDING_DISTRIBUTIONS);
    vi.spyOn(api, 'getFindingBacklogHealth').mockResolvedValue(FINDING_BACKLOG_HEALTH);
    vi.spyOn(api, 'getFindingProjectionStatus').mockResolvedValue(FINDING_PROJECTION_STATUS);
    vi.spyOn(api, 'listFindingQueues').mockResolvedValue(FINDING_QUEUES);
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(FILTER_VALUES);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(RISK_POLICY);
    const createIncidentSpy = vi.spyOn(cveWorkbenchApi, 'createServiceNowIncident').mockResolvedValue([{
      incidentNumber: 'INC000200',
      sysId: 'sys-200',
      url: 'https://example.service-now.com/nav_to.do?uri=incident.do?sys_id=sys-200',
      status: 'created',
      message: 'Incident created successfully',
    }]);

    renderWithProviders(
      <ActorContextState.Provider value={ACTOR}>
        <FindingsPage />
      </ActorContextState.Provider>
    );

    await screen.findByText('F-001');
    fireEvent.click(screen.getByRole('checkbox', { name: /Select row/i }));
    fireEvent.click(screen.getByTitle(/More actions/i));
    fireEvent.click(screen.getByRole('button', { name: /\+ Create Incident/i }));
    fireEvent.change(screen.getByPlaceholderText(/username or email/i), { target: { value: 'resolver@example.com' } });
    fireEvent.change(screen.getByPlaceholderText(/Security Operations/i), { target: { value: 'Security Operations' } });
    fireEvent.change(screen.getByPlaceholderText(/Remediation context/i), { target: { value: 'Escalate to resolver team.' } });
    fireEvent.click(screen.getByRole('button', { name: /Create Incident/i }));

    await waitFor(() => {
      expect(createIncidentSpy).toHaveBeenCalledWith('CVE-2026-1234', expect.objectContaining({
        findingTitle: 'CVE-2026-1234 — Vulnerability Remediation',
        severity: 'CRITICAL',
        priority: '3',
        assignedTo: 'resolver@example.com',
        notes: 'Escalate to resolver team.',
        affectedAssets: [expect.objectContaining({
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assignmentGroup: 'Security Operations',
        })],
      }));
    });

    await waitFor(() => {
      expect(screen.getByText(/ServiceNow incident creation completed/i)).toBeInTheDocument();
    });
  });

});
