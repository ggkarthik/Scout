import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ActorContext } from './features/auth/types';
import { renderWithProviders } from './test/test-utils';

const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'admin-a@example.test',
  userId: 'admin-a',
  tenantId: 'tenant-a',
  tenantName: 'Customer A',
  roles: ['TENANT_ADMIN']
};

describe('App test persona switcher', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.resetModules();
    window.localStorage.clear();
  });

  it('shows non-production personas from the gear menu and supports UI preview mode', async () => {
    vi.stubEnv('VITE_ENABLE_TEST_PERSONAS', 'true');
    const client = await import('./api/client');
    vi.spyOn(client.api, 'getAuthContext').mockResolvedValue(TENANT_ADMIN);
    vi.spyOn(client.api, 'listTestPersonas').mockResolvedValue([
      {
        key: 'tenant-a-admin',
        label: 'Tenant A Admin',
        subject: 'persona-tenant-a-admin',
        tenantSlug: 'customer-a',
        tenantName: 'Customer A',
        roles: ['TENANT_ADMIN']
      }
    ]);

    const { default: App } = await import('./App');
    renderWithProviders(<App />);

    fireEvent.click(await screen.findByLabelText('Open settings menu'));
    expect(screen.getByText('Impersonate User')).toBeInTheDocument();
    expect(screen.queryByText(/Refresh personas/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Load personas/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('menuitem', { name: /Impersonate User/i }));
    expect(await screen.findByRole('dialog', { name: /Non-production test personas/i })).toBeInTheDocument();
    expect(await screen.findByText('Tenant A Admin')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));

    await waitFor(() => {
      expect(screen.getByText('Impersonating: Tenant A Admin')).toBeInTheDocument();
    });
    expect(screen.getAllByText('UI preview only')[0]).toBeInTheDocument();
    expect(screen.getByText(/backend authorization still uses the current real session/i)).toBeInTheDocument();
  });

  it('hides the gear-menu persona option unless explicitly enabled', async () => {
    vi.stubEnv('VITE_ENABLE_TEST_PERSONAS', 'false');
    const client = await import('./api/client');
    vi.spyOn(client.api, 'getAuthContext').mockResolvedValue(TENANT_ADMIN);

    const { default: App } = await import('./App');
    renderWithProviders(<App />);

    fireEvent.click(await screen.findByLabelText('Open settings menu'));

    expect(screen.queryByText('Impersonate User')).not.toBeInTheDocument();
  });
});
