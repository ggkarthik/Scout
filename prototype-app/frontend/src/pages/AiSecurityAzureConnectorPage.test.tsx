import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AiSecurityAzureConnectorPage } from './AiSecurityAzureConnectorPage';

describe('AiSecurityAzureConnectorPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('runs the authenticated Azure target and renders sanitized scope health', async () => {
    vi.spyOn(api, 'listAzureDiscoveryTargets').mockResolvedValue([{
      id: 'target-1',
      subscriptionId: 'sub-1',
      subscriptionName: 'Production',
      enabled: true,
      regionsJson: '["eastus"]',
      hostCount: 0,
    }]);
    vi.spyOn(api, 'listAiSecurityAzureCredentials').mockResolvedValue([{
      id: 'profile-1',
      name: 'Pilot',
      authType: 'CLIENT_SECRET',
      azureTenantId: 'tenant-1',
      clientId: 'client-1',
      status: 'ACTIVE',
      expiresAt: '2026-12-01T00:00:00Z',
      lastVerifiedAt: '2026-07-01T00:00:00Z',
      lastVerificationStatus: 'SUCCESS',
      createdAt: '2026-07-01T00:00:00Z',
      updatedAt: '2026-07-01T00:00:00Z',
    }]);
    vi.spyOn(api, 'listAiSecurityAzureConnectors').mockResolvedValue([{
      id: 'connector-1',
      subscriptionId: 'sub-1',
      azureTenantId: 'tenant-1',
      credentialProfileId: 'profile-1',
      sourceConfigId: 'config-1',
      sourceTargetId: 'target-1',
      regions: ['eastus'],
      resourceFamilies: ['AZURE_AI_ACCOUNTS'],
      enabled: true,
      createdAt: '2026-07-01T00:00:00Z',
      updatedAt: '2026-07-01T00:00:00Z',
    }]);
    vi.spyOn(api, 'getAiSecurityAzureRequirements').mockResolvedValue({
      matrixVersion: 1,
      provider: 'AZURE',
      resourceFamilies: [],
      policies: [],
      prohibitedActions: [],
      roleTemplate: {
        name: 'NoScan AI Security Discovery',
        isCustom: true,
        description: 'Read-only',
        actions: [],
        notActions: [],
        dataActions: [],
        notDataActions: [],
        assignableScopes: [],
      },
    });
    vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([{
      id: 'run-1',
      status: 'COMPLETED',
      recordsFetched: 12,
      recordsFailed: 1,
      startedAt: '2026-07-01T00:00:00Z',
      completedAt: '2026-07-01T00:02:00Z',
      errorMessage: null,
    }]);
    vi.spyOn(api, 'listAiSecurityRunScopes').mockResolvedValue([{
      id: 'scope-1',
      runId: 'run-1',
      accountId: 'sub-1',
      region: 'eastus',
      resourceFamily: 'AZURE_AI_ACCOUNTS',
      scopeKey: 'AZURE_AI_ACCOUNTS:eastus',
      status: 'PARTIAL',
      expectedChunks: 1,
      acceptedChunks: 1,
      diagnostics: {
        items: [{
          code: 'ACCESS_DENIED',
          message: 'Azure permissions are insufficient',
          retryable: false,
          missingPermissions: ['Microsoft.CognitiveServices/accounts/read'],
          correlationId: 'correlation-1',
        }],
      },
      diagnosticCode: 'ACCESS_DENIED',
      startedAt: '2026-07-01T00:00:00Z',
      completedAt: '2026-07-01T00:02:00Z',
    }]);
    const run = vi.spyOn(api, 'runAiSecurityAzureTarget').mockResolvedValue({
      jobId: 'job-1',
      status: 'QUEUED',
      message: 'Queued',
    });

    renderWithProviders(<AiSecurityAzureConnectorPage />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run discovery' }));
    await waitFor(() => expect(run).toHaveBeenCalledWith('target-1'));
    expect(await screen.findByText('Latest scope completeness')).toBeInTheDocument();
    expect(screen.getByText('ACCESS_DENIED')).toBeInTheDocument();
    expect(screen.getByText(/correlation-1/)).toBeInTheDocument();
  });
});
