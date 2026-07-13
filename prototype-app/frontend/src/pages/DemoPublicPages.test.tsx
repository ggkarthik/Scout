import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken } from '../api/client';
import { authApi } from '../features/auth/api';
import { useActorQuery } from '../features/auth/queries';
import { createTestQueryClient, renderWithProviders } from '../test/test-utils';
import { DemoInvitePage, DemoLandingPage, DemoRequestPage, LoginPage } from './DemoPublicPages';

function ExposureActorProbe() {
  const actorQuery = useActorQuery();
  return <div>{actorQuery.data?.principal ?? 'missing actor'}</div>;
}

describe('Demo public pages', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    clearStoredAuthToken();
  });

  it('renders the landing screen at the index route with login and request-demo access', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/" element={<DemoLandingPage />} />
      </Routes>,
      { route: '/' }
    );

    expect(screen.getByRole('heading', { name: /See every threat\. Secure every surface\./i })).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: /Request demo/i })[0]).toHaveAttribute('href', '/demo/request');
    expect(screen.getAllByRole('link', { name: /Log in/i })[0]).toHaveAttribute('href', '/login');
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
      bootstrapStatus: null,
      tenantId: null,
      provisionedPlanCode: 'ENTERPRISE',
      latestInvite: null
    });

    renderWithProviders(<DemoRequestPage />, { route: '/demo/request' });

    expect(screen.getByRole('link', { name: /Back to overview/i })).toHaveAttribute('href', '/demo');
    expect(screen.getByRole('link', { name: /Already have access\? Log in/i })).toHaveAttribute('href', '/login');

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
    expect(screen.getByRole('button', { name: /Activate your workspace/i })).toBeEnabled();
    expect(screen.queryByRole('link', { name: /Continue to login/i })).not.toBeInTheDocument();
  });

  it('renders delivery failure invites as manual setup fallback', async () => {
    vi.spyOn(api, 'validateDemoInvite').mockResolvedValue({
      valid: true,
      status: 'DELIVERY_ERROR',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Email delivery failed, but this invite link is still valid. Continue here to set the tenant password manually.'
    });

    renderWithProviders(
      <Routes>
        <Route path="/invite/:token" element={<DemoInvitePage />} />
      </Routes>,
      { route: '/invite/demo-token' }
    );

    expect(await screen.findByText(/Email delivery failed/i)).toBeInTheDocument();
    expect(screen.getByText(/could not deliver the email automatically/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Activate your workspace/i })).toBeEnabled();
  });

  it('routes tenant admins to configurations after credential login', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      token: 'tenant-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });
    const actor = {
      creator: false,
      principal: 'alex@example.com',
      userId: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      planCode: 'ENTERPRISE',
      demo: true,
      roles: ['TENANT_ADMIN'],
      platformScope: false
    };
    const getAuthContextSpy = vi.spyOn(api, 'getAuthContext').mockResolvedValue(actor);
    const getActorContextSpy = vi.spyOn(authApi, 'getActorContext').mockResolvedValue(actor);
    const queryClient = createTestQueryClient();

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/configurations" element={<ExposureActorProbe />} />
        <Route path="/platform/tenants" element={<div>Platform Tenants</div>} />
      </Routes>,
      { queryClient, route: '/login' }
    );

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('alex@example.com');
    expect(api.login).toHaveBeenCalledWith('alex@example.com', 'password-123');
    expect(getAuthContextSpy).toHaveBeenCalledTimes(1);
    expect(getActorContextSpy).not.toHaveBeenCalled();
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

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'owner@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('Platform Tenants');
    expect(api.login).toHaveBeenCalledWith('owner@example.com', 'password-123');
  });

  it('sends invite activation flows to password setup login', async () => {
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

    fireEvent.click(await screen.findByRole('button', { name: /Activate your workspace/i }));

    expect(await screen.findByText(/Set a password for your tenant workspace/i)).toBeInTheDocument();
  });

  it('completes password setup and returns to login with a success message', async () => {
    vi.spyOn(api, 'setupPassword').mockResolvedValue({
      token: 'tenant-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/login?setup=setup-token-123&email=alex%40example.com' }
    );

    fireEvent.change(screen.getByLabelText(/New password/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Set password/i }));

    expect(await screen.findByText(/Password created successfully/i)).toBeInTheDocument();
    expect(screen.getByDisplayValue('alex@example.com')).toBeInTheDocument();
    expect(api.setupPassword).toHaveBeenCalledWith('setup-token-123', 'password-123');
  });

  it('allows tenant login with the request email and new password after activation reset', async () => {
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
      planCode: 'ENTERPRISE',
      demo: true,
      roles: ['TENANT_ADMIN'],
      platformScope: false
    });
    const loginSpy = vi.spyOn(api, 'login').mockResolvedValue({
      token: 'tenant-token-2',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/configurations" element={<div>Configurations</div>} />
      </Routes>,
      { route: '/login?setup=setup-token-123&email=alex%40example.com' }
    );

    fireEvent.change(screen.getByLabelText(/New password/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Set password/i }));
    await screen.findByText(/Password created successfully/i);

    clearStoredAuthToken();
    cleanup();

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/configurations" element={<div>Configurations</div>} />
      </Routes>,
      { route: '/login' }
    );

    expect(screen.getByRole('link', { name: /Need access\? Request a demo/i })).toHaveAttribute('href', '/demo/request');

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('Configurations');
    expect(loginSpy).toHaveBeenCalledWith('alex@example.com', 'password-123');
  });

  it('lets users clear a saved session from the login shell', async () => {
    setStoredAuthToken('saved-token');

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/login' }
    );

    fireEvent.click(screen.getByRole('button', { name: /Log out/i }));

    await waitFor(() => {
      expect(getStoredAuthToken()).toBe('');
    });
    expect(screen.getByRole('heading', { name: /Log in to securityGrid/i })).toBeInTheDocument();
  });
});
