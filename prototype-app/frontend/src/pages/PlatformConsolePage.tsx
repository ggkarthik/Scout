import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getStoredAuthToken } from '../api/client';
import type { PlatformRouteView } from '../app/routes';
import { pathForPlatformView } from '../app/routes';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { getAuthContextQueryKey } from '../features/auth/queries';
import { EolPage } from './EolPage';

const PLATFORM_TABS: Array<{ key: PlatformRouteView; label: string; helper: string }> = [
  { key: 'tenants', label: 'Tenants', helper: 'Lifecycle and plan metadata' },
  { key: 'users', label: 'Users', helper: 'Provision and manage platform-owner identities' },
  { key: 'demo-requests', label: 'Demo Requests', helper: 'Review, provision, and invite customer demo tenants' },
  { key: 'eol', label: 'EOL', helper: 'Platform-owned end-of-life catalog and lifecycle coverage' }
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
        {selectedView === 'eol' && <EolPage />}
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
  const authToken = getStoredAuthToken().trim() || 'anonymous';
  const [tenantPendingDelete, setTenantPendingDelete] = React.useState<{
    id: string;
    name: string;
    slug: string;
    status: string;
    demoExpiresAt?: string | null;
  } | null>(null);
  const [selectedTenantId, setSelectedTenantId] = React.useState('');
  const [overrideReasonDrafts, setOverrideReasonDrafts] = React.useState<Record<string, string>>({});
  const [overrideExpiryDrafts, setOverrideExpiryDrafts] = React.useState<Record<string, string>>({});
  const tenantsQuery = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: api.listTenants
  });
  const entitlementSnapshotQuery = useQuery({
    queryKey: ['platform-tenant-entitlements', selectedTenantId],
    queryFn: () => api.getTenantEntitlements(selectedTenantId),
    enabled: selectedTenantId.length > 0
  });
  const inventoryConnectorHealthQuery = useQuery({
    queryKey: ['platform-inventory-connector-health'],
    queryFn: api.listInventoryConnectorHealth
  });
  const refreshTenantEntitlements = async () => {
    if (selectedTenantId) {
      await queryClient.invalidateQueries({ queryKey: ['platform-tenant-entitlements', selectedTenantId] });
    }
    await queryClient.invalidateQueries({ queryKey: getAuthContextQueryKey(authToken) });
  };
  const createTenant = useMutation({
    mutationFn: api.createTenant,
    onSuccess: async (tenant) => {
      if (!selectedTenantId) {
        setSelectedTenantId(tenant.id);
      }
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
      await queryClient.invalidateQueries({ queryKey: ['platform-inventory-connector-health'] });
    }
  });
  const deleteTenant = useMutation({
    mutationFn: api.deleteTenant,
    onSuccess: async () => {
      setTenantPendingDelete(null);
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
      await queryClient.invalidateQueries({ queryKey: ['platform-inventory-connector-health'] });
    }
  });
  const upsertEntitlementOverride = useMutation({
    mutationFn: ({
      tenantId,
      entitlementKey,
      enabled,
      reason,
      expiresAt,
    }: {
      tenantId: string;
      entitlementKey: string;
      enabled: boolean;
      reason?: string;
      expiresAt?: string;
    }) => api.upsertTenantEntitlementOverride(tenantId, entitlementKey, {
      enabled,
      reason: reason?.trim() || undefined,
      expiresAt: expiresAt?.trim() ? new Date(expiresAt).toISOString() : null,
    }),
    onSuccess: async (_, variables) => {
      setOverrideReasonDrafts((current) => ({ ...current, [variables.entitlementKey]: '' }));
      setOverrideExpiryDrafts((current) => ({ ...current, [variables.entitlementKey]: '' }));
      await refreshTenantEntitlements();
    }
  });
  const deleteEntitlementOverride = useMutation({
    mutationFn: ({ tenantId, entitlementKey }: { tenantId: string; entitlementKey: string }) =>
      api.deleteTenantEntitlementOverride(tenantId, entitlementKey),
    onSuccess: refreshTenantEntitlements
  });

  const tenants = React.useMemo(() => tenantsQuery.data ?? [], [tenantsQuery.data]);
  const entitlementSnapshot = entitlementSnapshotQuery.data ?? null;
  const inventoryConnectorHealth = inventoryConnectorHealthQuery.data ?? [];

  React.useEffect(() => {
    if (!selectedTenantId && tenants.length > 0) {
      setSelectedTenantId(tenants[0].id);
      return;
    }
    if (selectedTenantId && tenants.every((tenant) => tenant.id !== selectedTenantId)) {
      setSelectedTenantId(tenants[0]?.id ?? '');
    }
  }, [selectedTenantId, tenants]);

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
                <th>Actions</th>
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
                  <td>
                    {tenant.slug === 'default-workspace' ? (
                      '-'
                    ) : (
                      <button
                        type="button"
                        className="btn btn-danger btn-sm"
                        disabled={deleteTenant.isPending || tenant.status.toUpperCase() === 'PURGING' || tenant.status.toUpperCase() === 'DELETED'}
                        onClick={() => setTenantPendingDelete({
                          id: tenant.id,
                          name: tenant.name,
                          slug: tenant.slug,
                          status: tenant.status,
                          demoExpiresAt: tenant.demoExpiresAt ?? null
                        })}
                        title="Delete the tenant and purge its tenant schema"
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {deleteTenant.isError && (
        <div className="notice error" role="alert">
          {deleteTenant.error instanceof Error ? deleteTenant.error.message : 'Failed to delete tenant'}
        </div>
      )}
      <div className="section-title-row" style={{ marginTop: 24 }}>
        <h4 className="section-title">Plan Entitlements</h4>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => void entitlementSnapshotQuery.refetch()}
          disabled={!selectedTenantId}
        >
          Refresh
        </button>
      </div>
      <p className="panel-caption">
        Effective access comes from the commercial plan plus optional tenant overrides. Mutations here invalidate auth context so the tenant sees changes without re-login.
      </p>
      <div className="platform-create-tenant-form" style={{ gridTemplateColumns: 'minmax(260px, 360px)' }}>
        <select
          aria-label="Select tenant for entitlements"
          value={selectedTenantId}
          onChange={(event) => setSelectedTenantId(event.target.value)}
        >
          <option value="" disabled>Select tenant</option>
          {tenants.map((tenant) => (
            <option key={tenant.id} value={tenant.id}>
              {tenant.name} ({tenant.planCode ?? 'manual'})
            </option>
          ))}
        </select>
      </div>
      {entitlementSnapshotQuery.isError ? (
        <div className="notice error" role="alert">
          {entitlementSnapshotQuery.error instanceof Error
            ? entitlementSnapshotQuery.error.message
            : 'Failed to load tenant entitlements'}
        </div>
      ) : entitlementSnapshotQuery.isLoading ? (
        <div className="empty-state"><p>Loading entitlements...</p></div>
      ) : entitlementSnapshot ? (
        <>
          <div className="panel-caption" style={{ marginTop: 12 }}>
            Current plan: <strong>{entitlementSnapshot.planCode ?? 'PRO'}</strong>
          </div>
          <div className="table-scroll" style={{ marginTop: 12 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Entitlement</th>
                  <th>Category</th>
                  <th>Enabled</th>
                  <th>Source</th>
                  <th>Override</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {entitlementSnapshot.entitlements.map((entitlement) => {
                  const override = entitlementSnapshot.overrides.find((item) => item.entitlementKey === entitlement.key) ?? null;
                  const reasonDraft = overrideReasonDrafts[entitlement.key] ?? override?.reason ?? '';
                  const expiryDraft = overrideExpiryDrafts[entitlement.key] ?? (override?.expiresAt ? override.expiresAt.slice(0, 10) : '');
                  return (
                    <tr key={entitlement.key}>
                      <td><code>{entitlement.key}</code></td>
                      <td>{entitlement.category}</td>
                      <td>{entitlement.enabled ? 'Enabled' : 'Disabled'}</td>
                      <td>{entitlement.source}</td>
                      <td>
                        {override ? (
                          <div>
                            <div>{override.enabled ? 'Forced on' : 'Forced off'}</div>
                            <div className="muted-small">
                              {override.reason ?? 'No reason'}
                              {override.expiresAt ? ` · Expires ${new Date(override.expiresAt).toLocaleDateString()}` : ''}
                            </div>
                          </div>
                        ) : (
                          <span className="muted-small">No override</span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'grid', gap: 8, minWidth: 280 }}>
                          <input
                            aria-label={`Reason for ${entitlement.key}`}
                            placeholder="Override reason"
                            value={reasonDraft}
                            onChange={(event) => setOverrideReasonDrafts((current) => ({
                              ...current,
                              [entitlement.key]: event.target.value,
                            }))}
                          />
                          <input
                            aria-label={`Expiry for ${entitlement.key}`}
                            type="date"
                            value={expiryDraft}
                            onChange={(event) => setOverrideExpiryDrafts((current) => ({
                              ...current,
                              [entitlement.key]: event.target.value,
                            }))}
                          />
                          <div className="button-row compact">
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={upsertEntitlementOverride.isPending || !selectedTenantId}
                              onClick={() => upsertEntitlementOverride.mutate({
                                tenantId: selectedTenantId,
                                entitlementKey: entitlement.key,
                                enabled: true,
                                reason: reasonDraft,
                                expiresAt: expiryDraft,
                              })}
                            >
                              Force Enable
                            </button>
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={upsertEntitlementOverride.isPending || !selectedTenantId}
                              onClick={() => upsertEntitlementOverride.mutate({
                                tenantId: selectedTenantId,
                                entitlementKey: entitlement.key,
                                enabled: false,
                                reason: reasonDraft,
                                expiresAt: expiryDraft,
                              })}
                            >
                              Force Disable
                            </button>
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={deleteEntitlementOverride.isPending || !override || !selectedTenantId}
                              onClick={() => deleteEntitlementOverride.mutate({
                                tenantId: selectedTenantId,
                                entitlementKey: entitlement.key,
                              })}
                            >
                              Clear Override
                            </button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="empty-state"><p>Select a tenant to inspect entitlements.</p></div>
      )}
      {(upsertEntitlementOverride.isError || deleteEntitlementOverride.isError) && (
        <div className="notice error" role="alert">
          {(upsertEntitlementOverride.error instanceof Error && upsertEntitlementOverride.error.message)
            || (deleteEntitlementOverride.error instanceof Error && deleteEntitlementOverride.error.message)
            || 'Failed to update entitlement override'}
        </div>
      )}
      <ConfirmDialog
        isOpen={tenantPendingDelete != null}
        title="Delete tenant?"
        message={
          tenantPendingDelete == null
            ? ''
            : tenantPendingDelete.demoExpiresAt
              ? `Delete ${tenantPendingDelete.name} and purge all tenant-scoped tables now? This will immediately remove tenant access, clear memberships, and reset the tenant schema.`
              : `Delete ${tenantPendingDelete.name} and purge all tenant-scoped tables now? This action is irreversible for this tenant workspace.`
        }
        confirmLabel={deleteTenant.isPending ? 'Deleting...' : 'Delete Tenant'}
        cancelLabel="Cancel"
        onCancel={() => {
          if (!deleteTenant.isPending) {
            setTenantPendingDelete(null);
          }
        }}
        onConfirm={() => {
          if (tenantPendingDelete != null && !deleteTenant.isPending) {
            deleteTenant.mutate(tenantPendingDelete.id);
          }
        }}
      />

      <div className="section-title-row" style={{ marginTop: 24 }}>
        <h4 className="section-title">Inventory Connector Health</h4>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => void inventoryConnectorHealthQuery.refetch()}
        >
          Refresh
        </button>
      </div>
      <p className="panel-caption">
        Read-only oversight of tenant-managed inventory connectors across customer workspaces.
      </p>
      {inventoryConnectorHealthQuery.isError ? (
        <div className="notice error" role="alert">
          {inventoryConnectorHealthQuery.error instanceof Error
            ? inventoryConnectorHealthQuery.error.message
            : 'Failed to load inventory connector health'}
        </div>
      ) : inventoryConnectorHealthQuery.isLoading ? (
        <div className="empty-state"><p>Loading inventory connector health...</p></div>
      ) : inventoryConnectorHealth.length === 0 ? (
        <div className="empty-state"><p>No tenant inventory connectors configured yet.</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Tenant</th>
                <th>Connector</th>
                <th>Health</th>
                <th>Enabled</th>
                <th>Auto Sync</th>
                <th>Last Test</th>
                <th>Last Sync</th>
              </tr>
            </thead>
            <tbody>
              {inventoryConnectorHealth.map((row) => (
                <tr key={`${row.tenantId}-${row.connectorKey}`}>
                  <td>{row.tenantName}</td>
                  <td><code>{row.connectorKey}</code></td>
                  <td>{row.healthState}</td>
                  <td>{row.enabled ? 'Yes' : 'No'}</td>
                  <td>{row.autoSyncEnabled ? 'Yes' : 'No'}</td>
                  <td title={row.lastTestMessage ?? undefined}>
                    {row.lastTestStatus ?? '-'}
                    {row.lastTestedAt ? ` · ${new Date(row.lastTestedAt).toLocaleString()}` : ''}
                  </td>
                  <td>{row.lastSyncAt ? new Date(row.lastSyncAt).toLocaleString() : '-'}</td>
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
      <p className="panel-caption">
        Approved requests provision Enterprise-equivalent demo tenants by default while retaining demo expiry, invite, and quota controls.
      </p>
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
