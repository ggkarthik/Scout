import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import type { AzureDiscoveryConfig, AzureDiscoveryTarget } from '../features/connect/types';
import { renderWithProviders } from '../test/test-utils';
import { AzureDiscoveryConnectorPage } from './AzureDiscoveryConnectorPage';

const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'tenant.admin@example.test',
  userId: 'tenant-admin',
  tenantId: 'tenant-1',
  tenantName: 'Customer One',
  roles: ['TENANT_ADMIN']
};

function renderPage(actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <AzureDiscoveryConnectorPage />
    </ActorContextState.Provider>
  );
}

function config(overrides: Partial<AzureDiscoveryConfig> = {}): AzureDiscoveryConfig {
  return {
    sourceSystem: 'azure',
    configured: false,
    authType: 'CLIENT_SECRET',
    azureTenantId: '',
    clientId: '',
    hasCredential: false,
    subscriptionIdsJson: '[]',
    regionsJson: '["eastus2"]',
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440,
    ...overrides
  };
}

function target(overrides: Partial<AzureDiscoveryTarget> = {}): AzureDiscoveryTarget {
  return {
    id: 'target-1',
    subscriptionId: 'sub-1',
    subscriptionName: 'Production',
    enabled: true,
    regionsJson: '["eastus2"]',
    hostCount: 3,
    ...overrides
  };
}

describe('AzureDiscoveryConnectorPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders the Connection tab and lets a tenant admin save the connector', async () => {
    vi.spyOn(api, 'getAzureDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listAzureDiscoveryTargets').mockResolvedValue([]);
    const saveSpy = vi.spyOn(api, 'saveAzureDiscoveryConfig').mockResolvedValue(config({ configured: true }));

    renderPage();

    expect(await screen.findByText('Connection')).toBeInTheDocument();
    expect(screen.getByText('Multi-Subscription')).toBeInTheDocument();

    const saveButton = screen.getByRole('button', { name: /Save Connector/i });
    fireEvent.click(saveButton);

    await waitFor(() => expect(saveSpy).toHaveBeenCalled());
  });

  it('calls testAzureDiscoveryConnection when Test Connection is clicked', async () => {
    vi.spyOn(api, 'getAzureDiscoveryConfig').mockResolvedValue(config({ configured: true }));
    vi.spyOn(api, 'listAzureDiscoveryTargets').mockResolvedValue([]);
    vi.spyOn(api, 'saveAzureDiscoveryConfig').mockResolvedValue(config({ configured: true }));
    const testSpy = vi.spyOn(api, 'testAzureDiscoveryConnection').mockResolvedValue({
      status: 'SUCCESS',
      message: 'Connected',
      reachableSubscriptions: ['sub-1'],
      warnings: [],
      subscriptionErrors: {},
      testedAt: '2026-07-01T00:00:00Z'
    });

    renderPage();

    const testButton = await screen.findByRole('button', { name: /Test Connection/i });
    fireEvent.click(testButton);

    await waitFor(() => expect(testSpy).toHaveBeenCalled());
    expect(await screen.findByText(/Connection successful/i)).toBeInTheDocument();
  });

  it('calls triggerAzureDiscoverySync when Run Integration Now is clicked', async () => {
    vi.spyOn(api, 'getAzureDiscoveryConfig').mockResolvedValue(config({ configured: true }));
    vi.spyOn(api, 'listAzureDiscoveryTargets').mockResolvedValue([]);
    vi.spyOn(api, 'saveAzureDiscoveryConfig').mockResolvedValue(config({ configured: true }));
    const syncSpy = vi.spyOn(api, 'triggerAzureDiscoverySync').mockResolvedValue({
      runId: 'run-1',
      status: 'QUEUED',
      message: 'Sync queued'
    });

    renderPage();

    const syncButton = await screen.findByRole('button', { name: /Run Integration Now/i });
    fireEvent.click(syncButton);

    await waitFor(() => expect(syncSpy).toHaveBeenCalled());
  });

  it('renders subscription targets on the Multi-Subscription tab', async () => {
    vi.spyOn(api, 'getAzureDiscoveryConfig').mockResolvedValue(config({ configured: true }));
    vi.spyOn(api, 'listAzureDiscoveryTargets').mockResolvedValue([target()]);
    vi.spyOn(api, 'saveAzureDiscoveryConfig').mockResolvedValue(config({ configured: true }));

    renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Multi-Subscription' }));

    expect(await screen.findByText('Production')).toBeInTheDocument();
    expect(screen.getByText('sub-1')).toBeInTheDocument();
  });
});
