import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AiInventoryPage } from './AiInventoryPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

describe('AiInventoryPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('opens with all discovered AI assets instead of hiding non-agent artifacts', async () => {
    const listArtifacts = vi.spyOn(api, 'listAiSecurityArtifacts').mockResolvedValue({
      items: [{
        id: 'artifact-1',
        provider: 'AWS',
        providerResourceId: 'arn:aws:bedrock:us-east-1:123456789012:guardrail/example',
        artifactType: 'AI_GUARDRAIL',
        nativeKind: 'AWS_BEDROCK_GUARDRAIL',
        name: 'Production Guardrail',
        accountId: '123456789012',
        region: 'us-east-1',
        active: true,
        attributes: {},
        ownerName: null,
        ownerState: 'UNOWNED',
        ownerSource: null,
        ownerConfidence: null,
        ownerConfidenceMethod: null,
        ownerConfidenceMethodVersion: null,
        businessCriticality: null,
        environment: null,
        firstObservedAt: '2026-07-29T09:00:00Z',
        lastObservedAt: '2026-07-29T09:05:00Z',
      }],
      page: 0,
      size: 100,
      total: 1,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      artifactCounts: { AI_GUARDRAIL: 1 },
      openFindings: 0,
      incompleteScopes: 0,
      lastCompleteSnapshotAt: '2026-07-29T09:05:00Z',
    });
    vi.spyOn(api, 'getAiGridCoverage').mockResolvedValue(emptyCoverage());

    renderWithProviders(<AiInventoryPage />);

    expect(await screen.findByText('Production Guardrail')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /All AI Assets/ })).toHaveAttribute('aria-selected', 'true');
    await waitFor(() => expect(listArtifacts).toHaveBeenCalledWith(
      undefined,
      0,
      100,
      undefined,
      undefined,
    ));
  });

  it('navigates to the AI asset detail page when a row is clicked', async () => {
    vi.spyOn(api, 'listAiSecurityArtifacts').mockResolvedValue({
      items: [{
        id: 'artifact-1',
        provider: 'AWS',
        providerResourceId: 'arn:aws:bedrock:us-east-1:123456789012:guardrail/example',
        artifactType: 'AI_GUARDRAIL',
        nativeKind: 'AWS_BEDROCK_GUARDRAIL',
        name: 'Production Guardrail',
        accountId: '123456789012',
        region: 'us-east-1',
        active: true,
        attributes: {},
        ownerName: null,
        ownerState: 'UNOWNED',
        ownerSource: null,
        ownerConfidence: null,
        ownerConfidenceMethod: null,
        ownerConfidenceMethodVersion: null,
        businessCriticality: null,
        environment: null,
        firstObservedAt: '2026-07-29T09:00:00Z',
        lastObservedAt: '2026-07-29T09:05:00Z',
      }],
      page: 0,
      size: 100,
      total: 1,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      artifactCounts: { AI_GUARDRAIL: 1 },
      openFindings: 0,
      incompleteScopes: 0,
      lastCompleteSnapshotAt: '2026-07-29T09:05:00Z',
    });
    vi.spyOn(api, 'getAiGridCoverage').mockResolvedValue(emptyCoverage());

    renderWithProviders(<AiInventoryPage />, { route: '/inventory/ai' });

    fireEvent.click(await screen.findByText('Production Guardrail'));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith('/inventory/ai/artifact-1?returnTo=%2Finventory%2Fai'));
  });

  it('routes empty inventory CTA to the connectors landing page', async () => {
    vi.spyOn(api, 'listAiSecurityArtifacts').mockResolvedValue({
      items: [],
      page: 0,
      size: 100,
      total: 0,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      artifactCounts: {},
      openFindings: 0,
      incompleteScopes: 0,
      lastCompleteSnapshotAt: null,
    });
    vi.spyOn(api, 'getAiGridCoverage').mockResolvedValue(emptyCoverage());

    renderWithProviders(<AiInventoryPage />, { route: '/inventory/ai' });

    expect(await screen.findByText('No AI assets discovered')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Configure AI connector' }));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith('/connect/connectors'));
  });

  it('makes incomplete and unsupported inventory evidence explicit', async () => {
    vi.spyOn(api, 'listAiSecurityArtifacts').mockResolvedValue({ items: [], page: 0, size: 100, total: 0 });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      artifactCounts: {}, openFindings: 0, incompleteScopes: 2, lastCompleteSnapshotAt: null,
    });
    vi.spyOn(api, 'getAiGridCoverage').mockResolvedValue({ ...emptyCoverage(), unsupported: 3 });

    renderWithProviders(<AiInventoryPage />);

    expect(await screen.findByText('Inventory coverage is incomplete.')).toBeInTheDocument();
    expect(screen.getByText(/2 discovery scopes need attention; 3 policy evidence items remain unsupported/)).toBeInTheDocument();
  });
});

function emptyCoverage() {
  return {
    runId: null,
    coverageEpochId: null,
    authoritativeScopeHeads: 0,
    currentArtifacts: 0,
    applicablePublished: 0,
    required: 0,
    tenantEnabled: 0,
    preview: 0,
    tenantDisabled: 0,
    evidenceReady: 0,
    evaluatedPass: 0,
    evaluatedFail: 0,
    noDecision: 0,
    notApplicable: 0,
    stale: 0,
    unsupported: 0,
  };
}
