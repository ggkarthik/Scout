import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { DemoInvitePage, DemoRequestPage, LoginPage } from './DemoPublicPages';

describe('Demo public pages', () => {
  afterEach(() => {
    vi.restoreAllMocks();
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
    expect(screen.getByRole('button', { name: /Activate workspace/i })).toBeEnabled();
  });

  it('renders password login form', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/login' }
    );

    expect(await screen.findByRole('button', { name: /Sign in/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Email/i)).toBeInTheDocument();
  });

  it('routes platform owners to demo requests after login', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      token: 'session-token',
      tokenType: 'Bearer',
      expiresAt: new Date().toISOString()
    });
    vi.spyOn(api, 'getActorContext').mockResolvedValue({
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER'],
      planCode: null,
      demoExpiresAt: null,
      demoDaysRemaining: null,
      demoCapabilities: null,
      demoUsage: null
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/platform/demo-requests" element={<div>Platform queue</div>} />
      </Routes>,
      { route: '/login' }
    );

    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'owner@example.com' } });
    fireEvent.change(screen.getByLabelText(/Password/i), { target: { value: 'hunter2hunter2' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    expect(await screen.findByText('Platform queue')).toBeInTheDocument();
  });
});
