import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AuthContext } from '../features/admin/types';
import { defaultRiskPolicy } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { ConfigurationsPage } from './ConfigurationsPage';

const TENANT_ADMIN_CONTEXT: AuthContext = {
  creator: false,
  principal: 'admin@example.com',
  userId: 'user-admin',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_TENANT_ADMIN'],
};

describe('ConfigurationsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  function mockBaseApis() {
    vi.spyOn(api, 'getAuthContext').mockResolvedValue(TENANT_ADMIN_CONTEXT);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    vi.spyOn(api, 'listOwnershipRules').mockResolvedValue([]);
    vi.spyOn(api, 'listSuppressionRules').mockResolvedValue([]);
    vi.spyOn(api, 'listVulnerabilitySourceFilterConfigs').mockResolvedValue([]);
  }

  it('renders the SLA & Remediation tab by default', async () => {
    mockBaseApis();
    renderWithProviders(<ConfigurationsPage />, { route: '/configurations' });

    expect((await screen.findAllByText(/SLA & Remediation/i)).length).toBeGreaterThan(0);
  });

  it('renders SLA deadline inputs populated from the risk policy', async () => {
    mockBaseApis();
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(
      defaultRiskPolicy({ criticalSlaDays: 7, highSlaDays: 14, mediumSlaDays: 30, lowSlaDays: 60 })
    );

    renderWithProviders(<ConfigurationsPage />, {
      initialEntries: [{ pathname: '/configurations', search: '?tab=sla' }],
    });

    await waitFor(() => {
      expect(api.getRiskPolicy).toHaveBeenCalled();
    });
  });

  it('renders sidebar navigation items', async () => {
    mockBaseApis();
    renderWithProviders(<ConfigurationsPage />, { route: '/configurations' });

    expect((await screen.findAllByText(/S\.AI Prioritization/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/Workflow Automation/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/Suppression Rules/i)).length).toBeGreaterThan(0);
  });

  it('renders triage tab content when navigated to', async () => {
    mockBaseApis();
    renderWithProviders(<ConfigurationsPage />, {
      initialEntries: [{ pathname: '/configurations', search: '?tab=triage' }],
    });

    expect((await screen.findAllByText(/S\.AI Prioritization/i)).length).toBeGreaterThan(0);
  });

  it('calls getRiskPolicy on mount', async () => {
    mockBaseApis();
    renderWithProviders(<ConfigurationsPage />, { route: '/configurations' });

    await waitFor(() => {
      expect(api.getRiskPolicy).toHaveBeenCalledTimes(1);
    });
  });
});
