import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { PlatformRouteView } from '../app/routes';
import { pathForPlatformView } from '../app/routes';
import { ConfirmDialog } from '../components/ConfirmDialog';

const PLATFORM_TABS: Array<{ key: PlatformRouteView; label: string; helper: string }> = [
  { key: 'tenants', label: 'Tenants', helper: 'Lifecycle and plan metadata' },
  { key: 'users', label: 'Users', helper: 'Provision and manage platform-owner identities' },
  { key: 'demo-requests', label: 'Demo Requests', helper: 'Review, provision, and invite customer demo tenants' }
];

type PlatformConsolePageProps = {
  selectedView: PlatformRouteView;
};

export function PlatformConsolePage({ selectedView }: PlatformConsolePageProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const platformMessage = typeof location.state === 'object' && location.state && 'platformMessage' in location.state
    ? String((location.state as { platformMessage?: string }).platformMessage ?? '')
    : '';

  return (
    <div className="page-grid platform-console-page">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>Platform Console</h3>
            <div className="panel-caption">
              Platform-owner controls for tenant lifecycle, demo provisioning, and platform-owned operations.
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
        {platformMessage && (
          <div className="notice" role="status">
            {platformMessage}
          </div>
        )}

        {selectedView === 'tenants' && <TenantLifecyclePanel />}
        {selectedView === 'users' && <PlatformUsersPanel />}
        {selectedView === 'demo-requests' && <DemoRequestsPanel />}
      </section>
    </div>
  );
}

function PlatformUsersPanel() {
  const queryClient = useQueryClient();
  const usersQuery = useQuery({
    queryKey: ['platform-users'],
    queryFn: api.listPlatformUsers
  });
  const upsertPlatformUser = useMutation({
    mutationFn: api.upsertPlatformUser,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['platform-users'] });
    }
  });
  const revokeRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: string }) => api.revokePlatformUserRole(userId, role),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['platform-users'] });
    }
  });

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const externalSubject = String(formData.get('externalSubject') ?? '').trim();
    const email = String(formData.get('email') ?? '').trim();
    const displayName = String(formData.get('displayName') ?? '').trim();
    const role = String(formData.get('role') ?? 'PLATFORM_OWNER').trim();
    if (!externalSubject || !role) {
      return;
    }
    upsertPlatformUser.mutate(
      {
        externalSubject,
        email: email || undefined,
        displayName: displayName || undefined,
        role
      },
      {
        onSuccess: () => event.currentTarget.reset()
      }
    );
  };

  const users = usersQuery.data ?? [];

  return (
    <div className="section-block">
      <div className="section-title-row">
        <h4 className="section-title">Platform Users</h4>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => void usersQuery.refetch()}>
          Refresh
        </button>
      </div>
      <p className="panel-caption">
        Provision platform access with the external subject emitted by your configured identity provider subject claim.
      </p>
      <form className="platform-create-tenant-form" onSubmit={handleSubmit}>
        <input name="externalSubject" placeholder="External subject" aria-label="External subject" />
        <input name="email" placeholder="Email" aria-label="Email" />
        <input name="displayName" placeholder="Display name" aria-label="Display name" />
        <input name="role" placeholder="PLATFORM_OWNER" aria-label="Role" defaultValue="PLATFORM_OWNER" />
        <button type="submit" className="btn btn-primary" disabled={upsertPlatformUser.isPending}>
          {upsertPlatformUser.isPending ? 'Saving...' : 'Grant Role'}
        </button>
      </form>
      {upsertPlatformUser.isError && (
        <div className="notice error" role="alert">
          {upsertPlatformUser.error instanceof Error ? upsertPlatformUser.error.message : 'Failed to save platform user'}
        </div>
      )}
      {usersQuery.isError ? (
        <div className="notice error" role="alert">
          {usersQuery.error instanceof Error ? usersQuery.error.message : 'Failed to load platform users'}
        </div>
      ) : usersQuery.isLoading ? (
        <div className="empty-state"><p>Loading platform users...</p></div>
      ) : users.length === 0 ? (
        <div className="empty-state"><p>No platform users provisioned yet.</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Display Name</th>
                <th>Subject</th>
                <th>Email</th>
                <th>Roles</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.userId}>
                  <td>{user.displayName ?? 'Unassigned'}</td>
                  <td><code>{user.externalSubject}</code></td>
                  <td>{user.email ?? '-'}</td>
                  <td>{user.globalRoles.join(', ') || '-'}</td>
                  <td>{user.status}</td>
                  <td>{user.lastSeenAt ? new Date(user.lastSeenAt).toLocaleString() : '-'}</td>
                  <td>
                    {user.globalRoles.length === 0 ? '-' : user.globalRoles.map((role) => (
                      <button
                        key={`${user.userId}-${role}`}
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => revokeRole.mutate({ userId: user.userId, role })}
                        disabled={revokeRole.isPending}
                      >
                        Revoke {role}
                      </button>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {revokeRole.isError && (
        <div className="notice error" role="alert">
          {revokeRole.error instanceof Error ? revokeRole.error.message : 'Failed to revoke role'}
        </div>
      )}
    </div>
  );
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
                <th>Owner Email</th>
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
                  <td>{tenant.demoOwnerEmail ?? '-'}</td>
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
  const [requestPendingDelete, setRequestPendingDelete] = React.useState<{
    id: string;
    company: string;
    fullName: string;
    tenantId: string | null;
  } | null>(null);
  const requestsQuery = useQuery({
    queryKey: ['platform-demo-requests'],
    queryFn: api.listDemoRequests
  });
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['platform-demo-requests'] });
    await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
  };
  const approve = useMutation({ mutationFn: api.approveDemoRequest, onSuccess: refresh });
  const reject = useMutation({ mutationFn: ({ id, reason }: { id: string; reason?: string }) => api.rejectDemoRequest(id, reason), onSuccess: refresh });
  const resend = useMutation({ mutationFn: api.resendDemoInvite, onSuccess: refresh });
  const issueSetup = useMutation({
    mutationFn: api.issueDemoSetupLink,
    onSuccess: (response) => {
      window.location.href = response.setupUrl;
    }
  });
  const deleteRequest = useMutation({
    mutationFn: api.deleteDemoRequest,
    onSuccess: async () => {
      setRequestPendingDelete(null);
      await refresh();
    },
    onError: async (error) => {
      if (error instanceof Error && error.message.includes('[NOT_FOUND]')) {
        setRequestPendingDelete(null);
        await refresh();
      }
    }
  });
  const requests = requestsQuery.data ?? [];
  const isApprovalComplete = (status: string, tenantId: string | null) =>
    tenantId != null || ['SENT', 'ERROR', 'REJECTED'].includes(status.toUpperCase());
  const deleteNotFound =
    deleteRequest.error instanceof Error && deleteRequest.error.message.includes('[NOT_FOUND]');

  React.useEffect(() => {
    if (requestPendingDelete == null && deleteRequest.isError && deleteNotFound) {
      deleteRequest.reset();
    }
  }, [deleteNotFound, deleteRequest, requestPendingDelete]);

  return (
    <div className="section-block">
      <div className="section-title-row">
        <h4 className="section-title">Demo Request Queue</h4>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => void requestsQuery.refetch()}>
          Refresh
        </button>
      </div>
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
                <th>Use Case</th>
                <th>Status</th>
                <th>Invite</th>
                <th>Requested</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((request) => (
                <tr key={request.id}>
                  <td>
                    <strong>{request.fullName}</strong>
                    <div className="muted-small">{request.email}</div>
                  </td>
                  <td>{request.company}</td>
                  <td>{request.useCase ?? '-'}</td>
                  <td>{request.status}</td>
                  <td>
                    {request.latestInvite ? (
                      <a href={request.latestInvite.inviteUrl}>{request.latestInvite.status}</a>
                    ) : '-'}
                  </td>
                  <td>{new Date(request.requestedAt).toLocaleDateString()}</td>
                  <td>
                    <div className="button-row compact">
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={approve.isPending || isApprovalComplete(request.status, request.tenantId)}
                        onClick={() => approve.mutate(request.id)}
                      >
                        Approve
                      </button>
                      <button className="btn btn-secondary btn-sm" disabled={resend.isPending || !request.tenantId} onClick={() => resend.mutate(request.id)}>
                        Resend
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={issueSetup.isPending || !request.tenantId}
                        onClick={() => issueSetup.mutate(request.id)}
                        title={request.tenantId ? 'Open password setup for the tenant owner' : 'Provision the request first'}
                      >
                        Set Password
                      </button>
                      <button className="btn btn-secondary btn-sm" disabled={reject.isPending || request.status === 'REJECTED'} onClick={() => reject.mutate({ id: request.id, reason: 'Not a fit for current validation wave' })}>
                        Reject
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={deleteRequest.isPending}
                        onClick={() => setRequestPendingDelete({
                          id: request.id,
                          company: request.company,
                          fullName: request.fullName,
                          tenantId: request.tenantId
                        })}
                        title="Delete this request from the queue"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(approve.isError || reject.isError || resend.isError || issueSetup.isError || (deleteRequest.isError && !deleteNotFound)) && (
        <div className="notice error" role="alert">
          {[approve.error, reject.error, resend.error, issueSetup.error, deleteNotFound ? null : deleteRequest.error].find(Boolean) instanceof Error
            ? ([approve.error, reject.error, resend.error, issueSetup.error, deleteNotFound ? null : deleteRequest.error].find(Boolean) as Error).message
            : 'Demo request action failed'}
        </div>
      )}
      <ConfirmDialog
        isOpen={requestPendingDelete != null}
        title="Delete demo request?"
        message={
          requestPendingDelete == null
            ? ''
            : requestPendingDelete.tenantId
              ? `Delete the demo request for ${requestPendingDelete.fullName} at ${requestPendingDelete.company} from the queue? The tenant workspace will remain provisioned.`
              : `Delete the demo request for ${requestPendingDelete.fullName} at ${requestPendingDelete.company} from the queue?`
        }
        confirmLabel={deleteRequest.isPending ? 'Deleting...' : 'Delete'}
        cancelLabel="Cancel"
        onCancel={() => {
          if (!deleteRequest.isPending) {
            setRequestPendingDelete(null);
          }
        }}
        onConfirm={() => {
          if (requestPendingDelete != null && !deleteRequest.isPending) {
            deleteRequest.mutate(requestPendingDelete.id);
          }
        }}
      />
    </div>
  );
}
