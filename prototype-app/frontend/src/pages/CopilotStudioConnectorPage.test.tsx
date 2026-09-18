import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { CopilotStudioConnectorPage } from './CopilotStudioConnectorPage';

describe('CopilotStudioConnectorPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('loads an existing connector for editing and persists schedule and host policy', async () => {
    vi.spyOn(api, 'listAiSecurityConnectorFeatureFlags').mockResolvedValue([]);
    vi.spyOn(api, 'listCopilotStudioConnectors').mockResolvedValue([{
      id: 'connector-1', organizationUrl: 'https://org.crm.dynamics.com', credentialProfileId: 'profile-1',
      discoveryEnabled: true, executionEnabled: false, killSwitch: false, scheduleCron: '0 15 * * * *',
      allowedDataverseHosts: ['org.crm.dynamics.com'], createdAt: '2026-09-17T00:00:00Z', updatedAt: '2026-09-17T00:00:00Z',
    }]);
    const save = vi.spyOn(api, 'saveCopilotStudioConnector').mockImplementation(async payload => ({
      id: 'connector-1', ...payload, scheduleCron: payload.scheduleCron ?? '0 0 * * * *',
      allowedDataverseHosts: payload.allowedDataverseHosts ?? [], createdAt: '2026-09-17T00:00:00Z', updatedAt: '2026-09-17T00:00:00Z',
    }));

    renderWithProviders(<CopilotStudioConnectorPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    expect(screen.getByLabelText('Schedule (six-field cron)')).toHaveValue('0 15 * * * *');
    fireEvent.change(screen.getByLabelText('Schedule (six-field cron)'), { target: { value: '0 30 2 * * *' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save connector' }));

    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({
      scheduleCron: '0 30 2 * * *', allowedDataverseHosts: ['org.crm.dynamics.com'],
      discoveryEnabled: true, executionEnabled: false,
    }), expect.anything()));
  });

  it('renders discovery and runtime permission results independently', async () => {
    vi.spyOn(api, 'listAiSecurityConnectorFeatureFlags').mockResolvedValue([]);
    vi.spyOn(api, 'listCopilotStudioConnectors').mockResolvedValue([{
      id: 'connector-1', organizationUrl: 'https://org.crm.dynamics.com', credentialProfileId: 'profile-1',
      discoveryEnabled: true, executionEnabled: true, killSwitch: false, scheduleCron: '0 0 * * * *',
      allowedDataverseHosts: ['org.crm.dynamics.com'], createdAt: '2026-09-17T00:00:00Z', updatedAt: '2026-09-17T00:00:00Z',
    }]);
    vi.spyOn(api, 'testCopilotStudioConnector').mockResolvedValue({
      bots: { ready: true, status: 200, state: 'READY' },
      components: { ready: true, status: 200, state: 'READY' },
      executions: { ready: false, status: 403, state: 'DENIED' },
    });
    renderWithProviders(<CopilotStudioConnectorPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Test permissions' }));
    expect(await screen.findByText(/Discovery — bots: READY; components: READY/)).toBeInTheDocument();
    expect(screen.getByText(/Runtime — executions: DENIED/)).toBeInTheDocument();
  });

  it('reports completed inventory and policy processing after discovery', async () => {
    vi.spyOn(api, 'listAiSecurityConnectorFeatureFlags').mockResolvedValue([]);
    vi.spyOn(api, 'listCopilotStudioConnectors').mockResolvedValue([{
      id: 'connector-1', organizationUrl: 'https://org.crm.dynamics.com', credentialProfileId: 'profile-1',
      discoveryEnabled: true, executionEnabled: false, killSwitch: false, scheduleCron: '0 0 * * * *',
      allowedDataverseHosts: ['org.crm.dynamics.com'], createdAt: '2026-09-17T00:00:00Z', updatedAt: '2026-09-17T00:00:00Z',
    }]);
    const run = vi.spyOn(api, 'runCopilotStudioDiscovery').mockResolvedValue({
      runId: 'run-1', artifacts: 5, incompleteScopes: 0, status: 'COMPLETE',
    });

    renderWithProviders(<CopilotStudioConnectorPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Run discovery' }));

    await waitFor(() => expect(run).toHaveBeenCalledWith('connector-1', expect.anything()));
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Discovery completed: 5 inventory artifacts, 0 incomplete scopes. Policy validation ran for every complete scope.'
    );
  });
});
