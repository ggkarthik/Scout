import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api, clearStoredAuthToken } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { DemoInvitePage, DemoRequestPage, LoginPage } from './DemoPublicPages';

describe('Demo public pages', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    clearStoredAuthToken();
  });

  it('submits a demo request with customer details', async () => {
    const createDemoRequest = vi.spyOn(api, 'createDemoRequest').mockResolvedValue({
      id: 'request-1',
      email: 'alex@example.com',
      fullName: 'Alex Rivera',
      company: 'Example Co',
      roleTitle: 'Security Lead',
      companySize: '101-1000',
      useCase: 'SBOM validation',
      notes: '',
      status: 'PENDING',
      requestedAt: new Date().toISOString(),
      decidedAt: null,
      decidedBy: null,
      rejectionReason: null,
      tenantId: null,
      latestInvite: null
    });

    renderWithProviders(<DemoRequestPage />, { route: '/demo/request' });

    fireEvent.change(screen.getByLabelText(/Full name/i), { target: { value: 'Alex Rivera' } });
    fireEvent.change(screen.getByLabelText(/Work email/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Company$/i), { target: { value: 'Example Co' } });
    fireEvent.change(screen.getByLabelText(/Role/i), { target: { value: 'Security Lead' } });
    fireEvent.change(screen.getByLabelText(/Company size/i), { target: { value: '101-1000' } });
    fireEvent.change(screen.getByLabelText(/Primary use case/i), { target: { value: 'SBOM validation' } });
    fireEvent.click(screen.getByLabelText(/I understand/i));
    fireEvent.click(screen.getByRole('button', { name: /Submit request/i }));

    await waitFor(() => {
      expect(createDemoRequest).toHaveBeenCalledWith(expect.objectContaining({
        fullName: 'Alex Rivera',
        email: 'alex@example.com',
        company: 'Example Co',
        acceptedTerms: true
      }), expect.anything());
    });
  });

  it('renders invite validation details', async () => {
    vi.spyOn(api, 'validateDemoInvite').mockResolvedValue({
      valid: true,
      status: 'VALID',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Invite is ready'
    });

    renderWithProviders(
      <Routes>
        <Route path="/invite/:token" element={<DemoInvitePage />} />
      </Routes>,
      { route: '/invite/demo-token' }
    );

    expect(await screen.findByText('Example Co')).toBeInTheDocument();
    expect(screen.getByText('alex@example.com')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Accept invite/i })).toBeEnabled();
  });

  it('routes tenant owners to exposure after credential login', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      token: 'tenant-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });
    vi.spyOn(api, 'getAuthContext').mockResolvedValue({
      creator: false,
      principal: 'alex@example.com',
      userId: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      roles: ['TENANT_ADMIN'],
      platformScope: false
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/exposure" element={<div>Exposure Home</div>} />
        <Route path="/platform/tenants" element={<div>Platform Tenants</div>} />
      </Routes>,
      { route: '/login' }
    );

    fireEvent.change(screen.getByLabelText(/Work email/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('Exposure Home');
    expect(api.login).toHaveBeenCalledWith('alex@example.com', 'password-123');
  });

  it('routes platform owners to platform tenants after credential login', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      token: 'platform-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });
    vi.spyOn(api, 'getAuthContext').mockResolvedValue({
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER'],
      platformScope: true
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/exposure" element={<div>Exposure Home</div>} />
        <Route path="/platform/tenants" element={<div>Platform Tenants</div>} />
      </Routes>,
      { route: '/login' }
    );

    fireEvent.change(screen.getByLabelText(/Work email/i), { target: { value: 'owner@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('Platform Tenants');
    expect(api.login).toHaveBeenCalledWith('owner@example.com', 'password-123');
  });

  it('sends invite accept flows to password setup login', async () => {
    vi.spyOn(api, 'validateDemoInvite').mockResolvedValue({
      valid: true,
      status: 'VALID',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Invite is ready'
    });
    vi.spyOn(api, 'acceptDemoInvite').mockResolvedValue({
      valid: true,
      status: 'ACCEPTED',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Invite accepted',
      setupToken: 'setup-token-123'
    });

    renderWithProviders(
      <Routes>
        <Route path="/invite/:token" element={<DemoInvitePage />} />
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/invite/demo-token' }
    );

    fireEvent.click(await screen.findByRole('button', { name: /Accept invite/i }));

    expect(await screen.findByText(/Set a password for your tenant workspace/i)).toBeInTheDocument();
  });

  it('completes password setup and routes to the tenant workspace', async () => {
    vi.spyOn(api, 'setupPassword').mockResolvedValue({
      token: 'tenant-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });
    vi.spyOn(api, 'getAuthContext').mockResolvedValue({
      creator: false,
      principal: 'alex@example.com',
      userId: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      roles: ['TENANT_ADMIN'],
      platformScope: false
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/exposure" element={<div>Exposure Home</div>} />
      </Routes>,
      { route: '/login?setup=setup-token-123' }
    );

    fireEvent.change(screen.getByLabelText(/New password/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Set password/i }));

    await screen.findByText('Exposure Home');
    expect(api.setupPassword).toHaveBeenCalledWith('setup-token-123', 'password-123');
  });
});
