import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { PlatformRouteView } from '../app/routes';
import { pathForPlatformView } from '../app/routes';
import { VulnIntelConfigPage } from './VulnIntelConfigPage';
import { IntegrationRunQueuePage } from './IntegrationRunQueuePage';
import type { DemoInvite, DemoRequest } from '../features/admin/types';

const PLATFORM_TABS: Array<{ key: PlatformRouteView; label: string; helper: string }> = [
  { key: 'tenants', label: 'Tenants', helper: 'Lifecycle and plan metadata' },
  { key: 'demo-requests', label: 'Demo Requests', helper: 'Review, provision, and invite customer demo tenants' },
  { key: 'feeds', label: 'Central Repository', helper: 'Global CVE and advisory feed sync' },
  { key: 'runs', label: 'Run History', helper: 'Feed, inventory, and processing runs' },
  { key: 'support', label: 'Support', helper: 'Audited support access workspace' }
];

type PlatformConsolePageProps = {
  selectedView: PlatformRouteView;
};

export function PlatformConsolePage({ selectedView }: PlatformConsolePageProps) {
  const navigate = useNavigate();

  return (
    <div className="page-grid platform-console-page">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>Platform Console</h3>
            <div className="panel-caption">
              Platform-owner controls for tenant lifecycle and the central vulnerability repository.
            </div>
          </div>
        </div>
        <div className="connect-filter-bar connect-filter-bar--standalone">
          {PLATFORM_TABS.map((tab) => (
            <button
              key={tab.key}
              type="button"
              className={`connect-filter-btn${selectedView === tab.key ? ' active' : ''}`}
              onClick={() => navigate(pathForPlatformView(tab.key))}
              title={tab.helper}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {selectedView === 'tenants' && <TenantLifecyclePanel />}
        {selectedView === 'demo-requests' && <DemoRequestsPanel />}
        {selectedView === 'feeds' && <PlatformFeedsPanel />}
        {selectedView === 'runs' && <PlatformRunsPanel />}
        {selectedView === 'support' && <PlatformSupportPanel />}
      </section>
    </div>
  );
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function deliveryHeadline(invite: DemoInvite | null): string {
  if (!invite) {
    return 'Invite pending';
  }
  return invite.deliveryStatus === 'EMAIL_SENT' ? 'Email sent' : 'Pending delivery';
}

function deliveryDetail(invite: DemoInvite | null): string {
  if (!invite) {
    return 'Invite email will be generated after approval.';
  }
  if (invite.deliveryMessage?.trim()) {
    return invite.deliveryMessage.trim();
  }
  return invite.deliveryStatus === 'EMAIL_SENT'
    ? 'The latest invite email was sent successfully.'
    : 'Invite delivery is still pending.';
}

function inviteNoticeMessage(invite: DemoInvite): string {
  return invite.deliveryStatus === 'EMAIL_SENT'
    ? 'Invite email sent successfully.'
    : 'Invite updated.';
}

function TenantLifecyclePanel() {
  const queryClient = useQueryClient();
  const tenantsQuery = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: api.listTenants
  });
  const createTenant = useMutation({
    mutationFn: api.createTenant,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
    }
  });

  const tenants = tenantsQuery.data ?? [];

  const handleCreateTenant = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const name = String(formData.get('name') ?? '').trim();
    const slug = String(formData.get('slug') ?? '').trim();
    const planCode = String(formData.get('planCode') ?? '').trim();
    const billingRef = String(formData.get('billingRef') ?? '').trim();
    if (!name || !slug) {
      return;
    }
    createTenant.mutate({ name, slug, planCode, billingRef });
    event.currentTarget.reset();
  };

  return (
    <div className="section-block">
      <div className="section-title-row">
        <h4 className="section-title">Tenant Lifecycle</h4>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => void tenantsQuery.refetch()}>
          Refresh
        </button>
      </div>
      <form className="platform-create-tenant-form" onSubmit={handleCreateTenant}>
        <input name="name" placeholder="Tenant name" aria-label="Tenant name" />
        <input name="slug" placeholder="tenant-slug" aria-label="Tenant slug" />
        <input name="planCode" placeholder="Plan code" aria-label="Plan code" />
        <input name="billingRef" placeholder="Billing reference" aria-label="Billing reference" />
        <button type="submit" className="btn btn-primary" disabled={createTenant.isPending}>
          {createTenant.isPending ? 'Creating...' : 'Create Tenant'}
        </button>
      </form>
      {createTenant.isError && (
        <div className="notice error" role="alert">
          {createTenant.error instanceof Error ? createTenant.error.message : 'Tenant creation failed'}
        </div>
      )}
      {tenantsQuery.isError ? (
        <div className="notice error" role="alert">
          {tenantsQuery.error instanceof Error ? tenantsQuery.error.message : 'Failed to load tenants'}
        </div>
      ) : tenantsQuery.isLoading ? (
        <div className="empty-state"><p>Loading tenants...</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Tenant</th>
                <th>Slug</th>
                <th>Status</th>
                <th>Plan</th>
                <th>Daily Exposure Refreshes</th>
                <th>Demo Expires</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((tenant) => (
                <tr key={tenant.id}>
                  <td>{tenant.name}</td>
                  <td><code>{tenant.slug}</code></td>
                  <td>{tenant.status}</td>
                  <td>{tenant.planCode ?? 'manual'}</td>
                  <td>{tenant.maxDailyExposureRefreshes ?? '-'}</td>
                  <td>{tenant.demoExpiresAt ? new Date(tenant.demoExpiresAt).toLocaleDateString() : '-'}</td>
                  <td>{new Date(tenant.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DemoRequestsPanel() {
  const queryClient = useQueryClient();
  const [notice, setNotice] = React.useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [rejectDraft, setRejectDraft] = React.useState<{ request: DemoRequest; reason: string } | null>(null);
  const requestsQuery = useQuery({
    queryKey: ['platform-demo-requests'],
    queryFn: api.listDemoRequests
  });
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['platform-demo-requests'] });
    await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
  };
  const approve = useMutation({
    mutationFn: api.approveDemoRequest,
    onSuccess: async (request) => {
      await refresh();
      setNotice({
        type: 'success',
        message: request.latestInvite ? inviteNoticeMessage(request.latestInvite) : 'Demo request approved.'
      });
    },
    onError: (error) => {
      setNotice({ type: 'error', message: error instanceof Error ? error.message : 'Failed to approve demo request' });
    }
  });
  const reject = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) => api.rejectDemoRequest(id, reason),
    onSuccess: async (request) => {
      await refresh();
      setNotice({
        type: 'success',
        message: request.rejectionReason?.trim()
          ? `Demo request rejected. Reason saved: ${request.rejectionReason}`
          : 'Demo request rejected.'
      });
      setRejectDraft(null);
    },
    onError: (error) => {
      setNotice({ type: 'error', message: error instanceof Error ? error.message : 'Failed to reject demo request' });
    }
  });
  const resend = useMutation({
    mutationFn: api.resendDemoInvite,
    onSuccess: async (invite) => {
      await refresh();
      setNotice({ type: 'success', message: inviteNoticeMessage(invite) });
    },
    onError: (error) => {
      setNotice({ type: 'error', message: error instanceof Error ? error.message : 'Failed to resend invite' });
    }
  });
  const requests = requestsQuery.data ?? [];

  return (
    <div className="section-block">
      <div className="section-title-row">
        <h4 className="section-title">Demo Request Queue</h4>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => void requestsQuery.refetch()}>
          Refresh
        </button>
      </div>
      {notice && (
        <div className={`notice ${notice.type === 'success' ? 'success' : 'error'}`} role="status">
          {notice.message}
        </div>
      )}
      {requestsQuery.isError ? (
        <div className="notice error">{requestsQuery.error instanceof Error ? requestsQuery.error.message : 'Failed to load demo requests'}</div>
      ) : requestsQuery.isLoading ? (
        <div className="empty-state"><p>Loading demo requests...</p></div>
      ) : requests.length === 0 ? (
        <div className="empty-state"><p>No demo requests yet.</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Requester</th>
                <th>Company</th>
                <th>Requested</th>
                <th>Use Case</th>
                <th>Status</th>
                <th>Invite Delivery</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((request) => (
                <tr key={request.id}>
                  <td>
                    <strong>{request.fullName}</strong>
                    <div className="muted-small">{request.email}</div>
                    {request.roleTitle && <div className="muted-small">{request.roleTitle}</div>}
                  </td>
                  <td>{request.company}</td>
                  <td>
                    <div>{formatTimestamp(request.requestedAt)}</div>
                    {request.companySize && <div className="muted-small">{request.companySize}</div>}
                  </td>
                  <td>{request.useCase ?? '-'}</td>
                  <td>{request.status}</td>
                  <td>
                    <strong>{deliveryHeadline(request.latestInvite)}</strong>
                    <div className="muted-small">{deliveryDetail(request.latestInvite)}</div>
                    {request.latestInvite && (
                      <div className="muted-small">
                        Invite {request.latestInvite.status.toLowerCase()} · Last send {formatTimestamp(request.latestInvite.deliveryAttemptedAt ?? request.latestInvite.lastSentAt)}
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="button-row compact">
                      <button className="btn btn-secondary btn-sm" disabled={approve.isPending || request.status === 'PROVISIONED'} onClick={() => approve.mutate(request.id)}>
                        Approve
                      </button>
                      <button className="btn btn-secondary btn-sm" disabled={resend.isPending || !request.tenantId} onClick={() => resend.mutate(request.id)}>
                        Resend
                      </button>
                      <button className="btn btn-secondary btn-sm" disabled={reject.isPending || request.status === 'REJECTED'} onClick={() => setRejectDraft({ request, reason: request.rejectionReason ?? '' })}>
                        Reject
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rejectDraft && (
        <div className="modal-backdrop" role="presentation" onClick={() => setRejectDraft(null)}>
          <section
            className="panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="reject-demo-request-title"
            style={{ width: 'min(34rem, calc(100vw - 2rem))' }}
            onClick={(event) => event.stopPropagation()}
          >
            <div className="panel-header">
              <div>
                <h4 id="reject-demo-request-title">Reject Demo Request</h4>
                <div className="panel-caption">
                  Save an optional reason for {rejectDraft.request.fullName} at {rejectDraft.request.company}.
                </div>
              </div>
            </div>
            <label className="full-width">
              Reason
              <textarea
                rows={4}
                value={rejectDraft.reason}
                onChange={(event) => setRejectDraft((current) => current ? { ...current, reason: event.target.value } : current)}
                placeholder="Optional rejection reason"
              />
            </label>
            <div className="button-row" style={{ marginTop: '1rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setRejectDraft(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={reject.isPending}
                onClick={() => reject.mutate({ id: rejectDraft.request.id, reason: rejectDraft.reason.trim() || undefined })}
              >
                {reject.isPending ? 'Rejecting...' : 'Save Rejection'}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function PlatformFeedsPanel() {
  const summaryQuery = useQuery({
    queryKey: ['vuln-intel-sources-summary'],
    queryFn: api.getVulnIntelSourcesSummary
  });
  return (
    <div className="section-block">
      <VulnIntelConfigPage vulnSummary={summaryQuery.data ?? null} />
    </div>
  );
}

function PlatformRunsPanel() {
  return (
    <div className="section-block">
      <IntegrationRunQueuePage />
    </div>
  );
}

function PlatformSupportPanel() {
  return (
    <div className="section-block">
      <h4 className="section-title">Support Access</h4>
      <div className="notice" role="note">
        Support access must remain audited and approval-backed. Use tenant audit exports and support bundles from
        tenant administration until impersonation approval APIs are available.
      </div>
    </div>
  );
}
