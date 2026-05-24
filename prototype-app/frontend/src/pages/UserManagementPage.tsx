import React from 'react';
import { Navigate, useNavigate, useParams } from 'react-router-dom';
import {
  type AdminRouteView,
  normalizeAdminRouteView,
  pathForAdminView,
} from '../app/routes';
import {
  useAddTenantMemberMutation,
  useAuditEventsQuery,
  useAuthContextQuery,
  useCreateTenantSupportGrantMutation,
  useCreateServiceAccountMutation,
  useRevokeTenantSupportGrantMutation,
  useServiceAccountsQuery,
  useTenantSupportGrantsQuery,
  useTenantMembersQuery,
} from '../features/admin/queries';
import { api } from '../api/client';
import type { AuditEvent, ServiceAccount, TenantMember, TenantSupportGrant } from '../features/admin/types';
import { canExportAudit, canManageServiceAccounts, canManageTenant, canManageUsers } from '../features/auth/roles';

type RoleKey = 'Owner' | 'Admin' | 'Security Lead' | 'Analyst' | 'Viewer';

const ROLE_KEYS: RoleKey[] = ['Owner', 'Admin', 'Security Lead', 'Analyst', 'Viewer'];

const ROLE_DESCRIPTIONS: Record<RoleKey, string> = {
  Owner: 'Tenant lifecycle, billing controls, identity policy, and emergency access.',
  Admin: 'Operational administration across users, integrations, inventory, and findings.',
  'Security Lead': 'Triage ownership, risk acceptance, VEX decisions, and remediation governance.',
  Analyst: 'Investigation workflow, comments, evidence review, and finding disposition.',
  Viewer: 'Read-only access for engineering leaders, auditors, and partner teams.',
};

const ROLE_MATRIX = [
  { capability: 'Invite and remove users', owner: true, admin: true, lead: false, analyst: false, viewer: false },
  { capability: 'Change roles and scopes', owner: true, admin: true, lead: false, analyst: false, viewer: false },
  { capability: 'Approve VEX and risk acceptance', owner: true, admin: true, lead: true, analyst: false, viewer: false },
  { capability: 'Manage service accounts', owner: true, admin: true, lead: false, analyst: false, viewer: false },
  { capability: 'Suppress findings / risk acceptance', owner: true, admin: true, lead: true, analyst: false, viewer: false },
  { capability: 'Edit risk policy and SLA', owner: true, admin: true, lead: false, analyst: false, viewer: false },
  { capability: 'Trigger ingestion and connectors', owner: true, admin: true, lead: false, analyst: false, viewer: false },
  { capability: 'Investigate findings', owner: true, admin: true, lead: true, analyst: true, viewer: false },
  { capability: 'Export audit log', owner: true, admin: true, lead: true, analyst: false, viewer: false },
  { capability: 'View dashboards and reports', owner: true, admin: true, lead: true, analyst: true, viewer: true },
];

const ADMIN_TABS: Array<{ key: AdminRouteView; label: string; helper: string }> = [
  { key: 'users', label: 'Users', helper: 'Members and access scope' },
  { key: 'invites', label: 'Invites', helper: 'Pending access requests' },
  { key: 'support', label: 'Support Access', helper: 'Tenant-approved platform access' },
  { key: 'roles', label: 'Roles & Permissions', helper: 'Role model and grants' },
  { key: 'service-accounts', label: 'Service Accounts', helper: 'Machine identities' },
  { key: 'audit', label: 'Audit', helper: 'Identity event trail' },
];

const STATUS_PILL_BY_API: Record<string, string> = {
  ACTIVE: 'status-pill status-open',
  INVITED: 'status-pill status-investigating',
  SUSPENDED: 'status-pill status-suppressed',
  PAUSED: 'status-pill status-suppressed',
};

function statusPillClass(status: string): string {
  return STATUS_PILL_BY_API[status.toUpperCase()] ?? 'status-pill';
}

function formatStatus(status: string): string {
  if (!status) return '—';
  const upper = status.toUpperCase();
  return upper.charAt(0) + upper.slice(1).toLowerCase();
}

function formatRole(role: string | null | undefined): string {
  if (!role) return 'Unassigned';
  return role
    .split('_')
    .map((part) => (part.length === 0 ? '' : part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()))
    .filter((part) => part.length > 0)
    .join(' ');
}

function formatAccessMode(mode: string | null | undefined): string {
  if (!mode) return 'Read only';
  return mode
    .split('_')
    .map((part) => part.charAt(0) + part.slice(1).toLowerCase())
    .join(' ');
}

function roleBucket(role: string | null | undefined): RoleKey {
  const normalized = formatRole(role);
  if (ROLE_KEYS.includes(normalized as RoleKey)) {
    return normalized as RoleKey;
  }
  if (normalized === 'Platform Owner') return 'Owner';
  if (normalized === 'Tenant Admin') return 'Admin';
  if (normalized === 'Inventory Admin') return 'Admin';
  if (normalized === 'Creator') return 'Admin';
  return 'Viewer';
}

function privilegedRoleBucket(role: string | null | undefined): boolean {
  const bucket = roleBucket(role);
  return bucket === 'Owner' || bucket === 'Admin' || bucket === 'Security Lead';
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
  });
}

function formatRelative(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return formatTimestamp(value);
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? '' : 's'} ago`;
  return formatTimestamp(value);
}

function avatarInitials(member: TenantMember): string {
  const source = (member.displayName || member.email || member.subject || '').trim();
  if (!source) return '?';
  const parts = source.split(/\s+/).filter(Boolean);
  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase();
  }
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function memberDisplayName(member: TenantMember): string {
  return member.displayName?.trim() || member.email?.trim() || member.subject || 'Unknown member';
}

function memberSearchHaystack(member: TenantMember): string {
  return [member.displayName, member.email, member.subject, member.role, member.status]
    .filter(Boolean)
    .join(' ');
}

function serviceSearchHaystack(account: ServiceAccount): string {
  return [account.name, account.role, account.status, account.keyId].filter(Boolean).join(' ');
}

function auditSearchHaystack(event: AuditEvent): string {
  return [event.actorSubject, event.action, event.targetType, event.targetId, event.outcome]
    .filter(Boolean)
    .join(' ');
}

function matchesQuery(haystack: string, needle: string): boolean {
  const term = needle.trim().toLowerCase();
  if (!term) return true;
  return haystack.toLowerCase().includes(term);
}

function deriveAuditRisk(event: AuditEvent): 'Low' | 'Medium' | 'High' {
  const outcome = (event.outcome ?? '').toLowerCase();
  const action = (event.action ?? '').toLowerCase();
  if (outcome === 'failure' || outcome === 'denied' || outcome === 'blocked') return 'High';
  if (action.includes('delete') || action.includes('suspend') || action.includes('rotate')) return 'High';
  if (action.includes('update') || action.includes('change') || action.includes('invite') || action.includes('add')) return 'Medium';
  return 'Low';
}

const AUDIT_RISK_PILL: Record<'Low' | 'Medium' | 'High', string> = {
  Low: 'severity-pill severity-low',
  Medium: 'severity-pill severity-medium',
  High: 'severity-pill severity-high',
};

function CheckMark({ enabled }: { enabled: boolean }) {
  return (
    <span className={enabled ? 'um-check enabled' : 'um-check'} aria-label={enabled ? 'allowed' : 'not allowed'}>
      {enabled ? 'Yes' : 'No'}
    </span>
  );
}

type IconName = 'plus' | 'mail' | 'key' | 'clock' | 'search' | 'more' | 'close' | 'rotate' | 'play' | 'pause' | 'download';

function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    plus: <path d="M12 5v14M5 12h14" />,
    mail: <path d="M4 6h16v12H4zM4 7l8 6 8-6" />,
    key: <path d="M14.5 9.5a4 4 0 1 1-2.1 3.5L21 4.5M18 7.5l2 2" />,
    clock: <path d="M12 6v6l4 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />,
    search: <path d="m21 21-4.2-4.2M10.8 18a7.2 7.2 0 1 1 0-14.4 7.2 7.2 0 0 1 0 14.4Z" />,
    more: <path d="M5 12h.01M12 12h.01M19 12h.01" />,
    close: <path d="M6 6l12 12M6 18 18 6" />,
    rotate: <path d="M4 12a8 8 0 0 1 14-5.3M20 4v4h-4M20 12a8 8 0 0 1-14 5.3M4 20v-4h4" />,
    play: <path d="M7 5v14l12-7z" />,
    pause: <path d="M8 5v14M16 5v14" />,
    download: <path d="M12 4v12m0 0-4-4m4 4 4-4M4 20h16" />,
  };
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="um-icon">
      {paths[name]}
    </svg>
  );
}

function subjectFromEmail(email: string): string {
  const trimmed = email.trim().toLowerCase();
  if (!trimmed) return '';
  const [local] = trimmed.split('@');
  return (local || trimmed).replace(/[^a-z0-9._-]+/g, '-');
}

export function UserManagementPage() {
  const params = useParams<{ adminView?: string }>();
  const navigate = useNavigate();
  const activeView = normalizeAdminRouteView(params.adminView);

  const authQuery = useAuthContextQuery();
  const actor = authQuery.data ?? null;
  const tenantId = authQuery.data?.tenantId ?? null;
  const mayAccessTenantAdministration = canManageTenant(actor);
  const mayManageUsers = canManageUsers(actor);
  const mayManageServiceAccounts = canManageServiceAccounts(actor);
  const mayExportAudit = canExportAudit(actor);

  const membersQuery = useTenantMembersQuery(tenantId);
  const serviceAccountsQuery = useServiceAccountsQuery();
  const supportGrantsQuery = useTenantSupportGrantsQuery(tenantId);
  const auditEventsQuery = useAuditEventsQuery();
  const addMember = useAddTenantMemberMutation(tenantId);
  const createServiceAccount = useCreateServiceAccountMutation();
  const createSupportGrant = useCreateTenantSupportGrantMutation(tenantId);
  const revokeSupportGrant = useRevokeTenantSupportGrantMutation(tenantId);

  const members = React.useMemo(() => membersQuery.data ?? [], [membersQuery.data]);
  const serviceAccounts = React.useMemo(() => serviceAccountsQuery.data ?? [], [serviceAccountsQuery.data]);
  const supportGrants = React.useMemo(() => supportGrantsQuery.data ?? [], [supportGrantsQuery.data]);
  const auditEvents = React.useMemo(() => auditEventsQuery.data ?? [], [auditEventsQuery.data]);

  const [selectedRole, setSelectedRole] = React.useState<RoleKey>('Security Lead');
  const [inviteOpen, setInviteOpen] = React.useState(false);
  const [serviceOpen, setServiceOpen] = React.useState(false);
  const [memberQuery, setMemberQuery] = React.useState('');
  const [inviteQuery, setInviteQuery] = React.useState('');
  const [serviceQuery, setServiceQuery] = React.useState('');
  const [supportQuery, setSupportQuery] = React.useState('');
  const [auditQuery, setAuditQuery] = React.useState('');
  const [exportError, setExportError] = React.useState<string | null>(null);
  const [isExporting, setIsExporting] = React.useState(false);

  const inviteEmailRef = React.useRef<HTMLInputElement | null>(null);
  const inviteRoleRef = React.useRef<HTMLSelectElement | null>(null);
  const inviteOpenerRef = React.useRef<HTMLButtonElement | null>(null);

  const serviceNameRef = React.useRef<HTMLInputElement | null>(null);
  const serviceOpenerRef = React.useRef<HTMLButtonElement | null>(null);

  const setActiveView = React.useCallback(
    (next: AdminRouteView) => {
      if (next !== activeView) {
        navigate(pathForAdminView(next));
      }
    },
    [activeView, navigate]
  );

  const activeMembers = React.useMemo(
    () => members.filter((m) => m.status.toUpperCase() !== 'INVITED'),
    [members]
  );
  const invitedMembers = React.useMemo(
    () => members.filter((m) => m.status.toUpperCase() === 'INVITED'),
    [members]
  );

  const visibleMembers = activeMembers.filter((m) => matchesQuery(memberSearchHaystack(m), memberQuery));
  const visibleInvites = invitedMembers.filter((m) => matchesQuery(memberSearchHaystack(m), inviteQuery));
  const visibleServiceAccounts = serviceAccounts.filter((a) => matchesQuery(serviceSearchHaystack(a), serviceQuery));
  const visibleSupportGrants = supportGrants.filter((grant) =>
    matchesQuery([grant.tenantName, grant.invitedPlatformSubject, grant.reason, grant.status, grant.accessMode].join(' '), supportQuery));
  const visibleAuditEvents = auditEvents.filter((e) => matchesQuery(auditSearchHaystack(e), auditQuery));

  const memberCountByRole = React.useMemo(() => {
    const counts: Record<RoleKey, number> = { Owner: 0, Admin: 0, 'Security Lead': 0, Analyst: 0, Viewer: 0 };
    members.forEach((m) => { counts[roleBucket(m.role)] += 1; });
    return counts;
  }, [members]);

  const privilegedCount = members.filter((m) => privilegedRoleBucket(m.role)).length;
  const tenantName = authQuery.data?.tenantName ?? '—';

  const captionParts: string[] = [];
  if (authQuery.data?.tenantName) captionParts.push(authQuery.data.tenantName);
  captionParts.push(`${members.length} member${members.length === 1 ? '' : 's'}`);
  captionParts.push(`${privilegedCount} privileged`);
  captionParts.push(`${serviceAccounts.length} service account${serviceAccounts.length === 1 ? '' : 's'}`);
  captionParts.push(`${supportGrants.length} support grant${supportGrants.length === 1 ? '' : 's'}`);
  captionParts.push(`${auditEvents.length} event${auditEvents.length === 1 ? '' : 's'}`);

  const openInvite = React.useCallback(() => {
    if (!mayManageUsers) return;
    addMember.reset();
    setInviteOpen(true);
  }, [addMember, mayManageUsers]);
  const closeInvite = React.useCallback(() => {
    setInviteOpen(false);
  }, []);
  const openService = React.useCallback(() => {
    if (!mayManageServiceAccounts) return;
    createServiceAccount.reset();
    setServiceOpen(true);
  }, [createServiceAccount, mayManageServiceAccounts]);
  const closeService = React.useCallback(() => {
    setServiceOpen(false);
  }, []);

  React.useEffect(() => {
    if (!inviteOpen) {
      inviteOpenerRef.current?.focus();
      return;
    }
    inviteEmailRef.current?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        closeInvite();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [inviteOpen, closeInvite]);

  React.useEffect(() => {
    if (!serviceOpen) {
      serviceOpenerRef.current?.focus();
      return;
    }
    serviceNameRef.current?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        closeService();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [serviceOpen, closeService]);

  if (!authQuery.isLoading && !mayAccessTenantAdministration) {
    return <Navigate to="/exposure" replace />;
  }

  const handleInviteSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!mayManageUsers) return;
    const formData = new FormData(event.currentTarget);
    const email = String(formData.get('email') ?? '').trim();
    const role = String(formData.get('role') ?? '').trim();
    const displayName = String(formData.get('displayName') ?? '').trim() || email;
    const subject = subjectFromEmail(email);
    if (!email || !role || !subject) return;
    addMember.mutate(
      { subject, email, displayName, role },
      {
        onSuccess: () => {
          closeInvite();
        },
      }
    );
  };

  const handleServiceSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!mayManageServiceAccounts) return;
    const formData = new FormData(event.currentTarget);
    const name = String(formData.get('name') ?? '').trim();
    const keyId = String(formData.get('keyId') ?? '').trim();
    const role = String(formData.get('role') ?? '').trim();
    if (!name || !keyId || !role) return;
    createServiceAccount.mutate(
      { name, keyId, role },
      {
        onSuccess: () => {
          closeService();
        },
      }
    );
  };

  const handleSupportGrantSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!mayManageUsers || !tenantId) return;
    const formData = new FormData(event.currentTarget);
    const invitedPlatformSubject = String(formData.get('invitedPlatformSubject') ?? '').trim();
    const reason = String(formData.get('reason') ?? '').trim();
    const expiresInHours = Number(String(formData.get('expiresInHours') ?? '24').trim());
  const scope = String(formData.get('scope') ?? '').trim();
  const accessMode = String(formData.get('accessMode') ?? 'READ_ONLY').trim() || 'READ_ONLY';
  if (!invitedPlatformSubject || !reason || !Number.isFinite(expiresInHours) || expiresInHours <= 0) {
    return;
  }
    const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000).toISOString();
    createSupportGrant.mutate(
      {
        invitedPlatformSubject,
        reason,
        scope,
        accessMode,
        expiresAt,
      },
      {
        onSuccess: () => {
          event.currentTarget.reset();
        },
      }
    );
  };

  const handleExportAudit = async () => {
    if (!mayExportAudit) return;
    setExportError(null);
    setIsExporting(true);
    try {
      const { filename, csv } = await api.exportAuditEventsCsv();
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : 'Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  const membersLoading = membersQuery.isLoading || (!membersQuery.data && membersQuery.isFetching);
  const serviceAccountsLoading = serviceAccountsQuery.isLoading || (!serviceAccountsQuery.data && serviceAccountsQuery.isFetching);
  const auditLoading = auditEventsQuery.isLoading || (!auditEventsQuery.data && auditEventsQuery.isFetching);

  const tenantBlocked = !authQuery.isLoading && !tenantId;

  return (
    <div className="page-grid user-management-page">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>User Management</h3>
            <div className="panel-caption">{captionParts.join(' · ')}</div>
          </div>
          <div className="topbar-actions">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setActiveView('audit')}
            >
              <Icon name="clock" />
              Audit log
            </button>
            <button
              ref={inviteOpenerRef}
              type="button"
              className="btn btn-primary btn-sm"
              onClick={openInvite}
              disabled={!tenantId}
              hidden={!mayManageUsers}
            >
              <Icon name="plus" />
              Invite user
            </button>
          </div>
        </div>

        {tenantBlocked && (
          <div className="notice error" role="alert">
            <strong>Workspace unavailable.</strong> Could not resolve a tenant from the current session. The
            <code>X-API-Key</code> / <code>X-Tenant-ID</code> credentials may be missing or unauthorized.
          </div>
        )}

        <div className="um-layout">
          <nav className="um-side-nav" aria-label="User management sections">
            <div className="um-side-nav-title">Settings</div>
            {ADMIN_TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={activeView === tab.key ? 'um-side-tab active' : 'um-side-tab'}
                aria-current={activeView === tab.key ? 'page' : undefined}
                onClick={() => setActiveView(tab.key)}
              >
                <span>{tab.label}</span>
                <small>{tab.helper}</small>
              </button>
            ))}
          </nav>

          <div className="um-content">
            {activeView === 'users' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Members</h3>
                    <p>Tenant membership with role, status, and external subject identity.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={memberQuery}
                        onChange={(event) => setMemberQuery(event.target.value)}
                        placeholder="Search users"
                        aria-label="Search users"
                      />
                    </label>
                  </div>
                </div>

                {membersQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load members.</strong> {membersQuery.error instanceof Error ? membersQuery.error.message : 'Unknown error'}
                  </div>
                ) : (
                  <div className="um-table-scroll">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>User</th>
                          <th>Status</th>
                          <th>Role</th>
                          <th>Subject</th>
                          <th>Member since</th>
                          <th aria-label="Actions" />
                        </tr>
                      </thead>
                      <tbody>
                        {membersLoading ? (
                          <tr><td colSpan={6} className="um-empty-cell">Loading members…</td></tr>
                        ) : visibleMembers.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="um-empty-cell">
                              {memberQuery
                                ? <>No members match &ldquo;{memberQuery}&rdquo;.</>
                                : 'No active members yet. Invite a user to get started.'}
                            </td>
                          </tr>
                        ) : (
                          visibleMembers.map((member) => (
                            <tr key={member.id}>
                              <td>
                                <div className="um-person">
                                  <span className="um-avatar" aria-hidden="true">{avatarInitials(member)}</span>
                                  <div className="um-person-text">
                                    <strong>{memberDisplayName(member)}</strong>
                                    <small>{member.email ?? '—'}</small>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <span className={statusPillClass(member.status)}>{formatStatus(member.status)}</span>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="um-role-button"
                                  onClick={() => {
                                    setSelectedRole(roleBucket(member.role));
                                    setActiveView('roles');
                                  }}
                                  title={`View ${formatRole(member.role)} role detail`}
                                >
                                  {formatRole(member.role)}
                                </button>
                              </td>
                              <td><code>{member.subject}</code></td>
                              <td>{formatTimestamp(member.createdAt)}</td>
                              <td>
                                <button
                                  type="button"
                                  className="um-icon-button"
                                  aria-label={`More actions for ${memberDisplayName(member)}`}
                                  disabled
                                  title="Member mutations land in a follow-up"
                                >
                                  <Icon name="more" />
                                </button>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeView === 'invites' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Pending Invitations</h3>
                    <p>Memberships in <code>INVITED</code> state awaiting first sign-in.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={inviteQuery}
                        onChange={(event) => setInviteQuery(event.target.value)}
                        placeholder="Search invites"
                        aria-label="Search invites"
                      />
                    </label>
                    <button type="button" className="btn btn-primary btn-sm" onClick={openInvite} disabled={!tenantId || !mayManageUsers} hidden={!mayManageUsers}>
                      <Icon name="mail" />
                      New invite
                    </button>
                    {!mayManageUsers && (
                      <span className="panel-caption">Invitations are read-only for your role.</span>
                    )}
                  </div>
                </div>

                {membersQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load invites.</strong> {membersQuery.error instanceof Error ? membersQuery.error.message : 'Unknown error'}
                  </div>
                ) : membersLoading ? (
                  <div className="um-empty-block">Loading invites…</div>
                ) : visibleInvites.length === 0 ? (
                  <div className="um-empty-block">
                    {inviteQuery
                      ? <>No invites match &ldquo;{inviteQuery}&rdquo;.</>
                      : 'No pending invitations. New invites appear here until the user signs in.'}
                  </div>
                ) : (
                  <div className="um-card-grid">
                    {visibleInvites.map((invite) => (
                      <article key={invite.id} className="um-card">
                        <div className="um-card-title">
                          <span className="um-card-icon"><Icon name="mail" /></span>
                          <div style={{ minWidth: 0 }}>
                            <h4>{invite.email ?? memberDisplayName(invite)}</h4>
                            <p><code>{invite.subject}</code></p>
                          </div>
                        </div>
                        <div className="um-card-row"><span>Role</span><strong>{formatRole(invite.role)}</strong></div>
                        <div className="um-card-row">
                          <span>Status</span>
                          <strong><span className={statusPillClass(invite.status)}>{formatStatus(invite.status)}</span></strong>
                        </div>
                        <div className="um-card-row"><span>Invited</span><strong>{formatRelative(invite.createdAt)}</strong></div>
                        <div className="um-card-actions">
                          <button type="button" className="btn btn-secondary btn-sm" disabled title="Resend lands in a follow-up">Resend</button>
                          <button type="button" className="btn btn-ghost btn-sm" disabled title="Revoke lands in a follow-up">Revoke</button>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </>
            )}

            {activeView === 'roles' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Role Model</h3>
                    <p>Permission clarity for least-privilege review. Member counts are live.</p>
                  </div>
                </div>

                <div className="notice" role="note">
                  <strong>Illustrative.</strong> The capability matrix is a design draft, not the authoritative permission spec.
                  Final mapping will follow the backend role authorities (<code>ROLE_PLATFORM_OWNER</code>,
                  <code>ROLE_TENANT_ADMIN</code>, <code>ROLE_INVENTORY_ADMIN</code>,
                  <code>ROLE_SECURITY_ANALYST</code>, <code>ROLE_READ_ONLY_AUDITOR</code>).
                </div>

                <div className="um-role-grid">
                  {ROLE_KEYS.map((roleKey) => (
                    <button
                      key={roleKey}
                      type="button"
                      className={selectedRole === roleKey ? 'um-role-card active' : 'um-role-card'}
                      aria-pressed={selectedRole === roleKey}
                      onClick={() => setSelectedRole(roleKey)}
                    >
                      <strong>{roleKey}</strong>
                      <span>{memberCountByRole[roleKey]} members</span>
                      <small>{ROLE_DESCRIPTIONS[roleKey]}</small>
                    </button>
                  ))}
                </div>

                <div className="um-table-scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Capability</th>
                        <th>Owner</th>
                        <th>Admin</th>
                        <th>Security Lead</th>
                        <th>Analyst</th>
                        <th>Viewer</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ROLE_MATRIX.map((row) => (
                        <tr key={row.capability}>
                          <td>{row.capability}</td>
                          <td><CheckMark enabled={row.owner} /></td>
                          <td><CheckMark enabled={row.admin} /></td>
                          <td><CheckMark enabled={row.lead} /></td>
                          <td><CheckMark enabled={row.analyst} /></td>
                          <td><CheckMark enabled={row.viewer} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {activeView === 'support' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Support Access</h3>
                    <p>Issue audited, time-bound platform support access to this tenant. Access stays read-only by default.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={supportQuery}
                        onChange={(event) => setSupportQuery(event.target.value)}
                        placeholder="Search support grants"
                        aria-label="Search support grants"
                      />
                    </label>
                  </div>
                </div>

                <form className="platform-create-tenant-form" onSubmit={handleSupportGrantSubmit}>
                  <div>
                    <input name="invitedPlatformSubject" placeholder="owner-subject-123" aria-label="Platform owner subject" style={{ width: '100%' }} />
                    <p className="panel-caption" style={{ marginTop: 4 }}>
                      Subject ID from the configured identity provider (<code>sub</code> claim) of the platform owner.
                    </p>
                  </div>
                  <input name="reason" placeholder="Why platform access is needed" aria-label="Support reason" />
                  <input name="scope" placeholder="Scope (optional)" aria-label="Support scope" />
                  <select name="accessMode" defaultValue="READ_ONLY" aria-label="Support access mode">
                    <option value="READ_ONLY">Read only</option>
                    <option value="WRITE_ENABLED">Write enabled</option>
                  </select>
                  <input name="expiresInHours" type="number" min="1" defaultValue="24" placeholder="Expires in hours" aria-label="Expires in hours" />
                  <button type="submit" className="btn btn-primary" disabled={!tenantId || !mayManageUsers || createSupportGrant.isPending}>
                    {createSupportGrant.isPending ? 'Issuing...' : 'Issue support grant'}
                  </button>
                </form>
                {createSupportGrant.isError && (
                  <div className="notice error" role="alert">
                    {createSupportGrant.error instanceof Error ? createSupportGrant.error.message : 'Failed to issue support grant'}
                  </div>
                )}

                {supportGrantsQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load support grants.</strong> {supportGrantsQuery.error instanceof Error ? supportGrantsQuery.error.message : 'Unknown error'}
                  </div>
                ) : supportGrantsQuery.isLoading ? (
                  <div className="um-empty-block">Loading support grants…</div>
                ) : visibleSupportGrants.length === 0 ? (
                  <div className="um-empty-block">
                    {supportQuery ? <>No support grants match &ldquo;{supportQuery}&rdquo;.</> : 'No support grants have been issued for this tenant.'}
                  </div>
                ) : (
                  <div className="um-card-grid">
                    {visibleSupportGrants.map((grant: TenantSupportGrant) => (
                      <article key={grant.id} className="um-card">
                        <div className="um-card-title">
                          <span className="um-card-icon"><Icon name="key" /></span>
                          <div style={{ minWidth: 0 }}>
                            <h4>{grant.invitedPlatformSubject}</h4>
                            <p>{grant.reason}</p>
                          </div>
                        </div>
                        <div className="um-card-row"><span>Status</span><strong><span className={statusPillClass(grant.status)}>{formatStatus(grant.status)}</span></strong></div>
                        <div className="um-card-row"><span>Mode</span><strong>{formatAccessMode(grant.accessMode)}</strong></div>
                        <div className="um-card-row"><span>Requested</span><strong>{formatRelative(grant.requestedAt)}</strong></div>
                        <div className="um-card-row"><span>Expires</span><strong>{formatTimestamp(grant.expiresAt)}</strong></div>
                        <div className="um-card-row"><span>Accepted</span><strong>{grant.acceptedAt ? formatTimestamp(grant.acceptedAt) : 'Pending acceptance'}</strong></div>
                        <div className="um-card-actions">
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            disabled={!mayManageUsers || revokeSupportGrant.isPending || ['REVOKED', 'EXPIRED'].includes(grant.status.toUpperCase())}
                            onClick={() => revokeSupportGrant.mutate(grant.id)}
                          >
                            Revoke
                          </button>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </>
            )}

            {activeView === 'service-accounts' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Service Accounts</h3>
                    <p>Machine identities with role, key id, status, and last-used timestamp.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={serviceQuery}
                        onChange={(event) => setServiceQuery(event.target.value)}
                        placeholder="Search service accounts"
                        aria-label="Search service accounts"
                      />
                    </label>
                    <button
                      ref={serviceOpenerRef}
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={openService}
                      disabled={!mayManageServiceAccounts}
                      hidden={!mayManageServiceAccounts}
                    >
                      <Icon name="key" />
                      Create account
                    </button>
                  </div>
                </div>

                {serviceAccountsQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load service accounts.</strong> {serviceAccountsQuery.error instanceof Error ? serviceAccountsQuery.error.message : 'Unknown error'}
                  </div>
                ) : serviceAccountsLoading ? (
                  <div className="um-empty-block">Loading service accounts…</div>
                ) : visibleServiceAccounts.length === 0 ? (
                  <div className="um-empty-block">
                    {serviceQuery
                      ? <>No service accounts match &ldquo;{serviceQuery}&rdquo;.</>
                      : 'No service accounts yet. Create one to issue a machine identity.'}
                  </div>
                ) : (
                  <div className="um-card-grid">
                    {visibleServiceAccounts.map((account) => (
                      <article key={account.id} className="um-card">
                        <div className="um-card-title">
                          <span className="um-card-icon"><Icon name="key" /></span>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <h4>{account.name}</h4>
                            <p><code>{account.keyId}</code></p>
                          </div>
                          <span className={statusPillClass(account.status)}>{formatStatus(account.status)}</span>
                        </div>
                        <div className="um-card-row"><span>Role</span><strong>{formatRole(account.role)}</strong></div>
                        <div className="um-card-row"><span>Created</span><strong>{formatRelative(account.createdAt)}</strong></div>
                        <div className="um-card-row"><span>Last used</span><strong>{account.lastUsedAt ? formatRelative(account.lastUsedAt) : 'Never'}</strong></div>
                        <div className="um-card-actions">
                          <button type="button" className="btn btn-secondary btn-sm" disabled title="Token rotation lands in a follow-up">
                            <Icon name="rotate" />
                            Rotate
                          </button>
                          {account.status.toUpperCase() === 'PAUSED' ? (
                            <button type="button" className="btn btn-ghost btn-sm" disabled title="Resume lands in a follow-up">
                              <Icon name="play" />
                              Resume
                            </button>
                          ) : (
                            <button type="button" className="btn btn-ghost btn-sm" disabled title="Pause lands in a follow-up">
                              <Icon name="pause" />
                              Pause
                            </button>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </>
            )}

            {activeView === 'audit' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Audit Events</h3>
                    <p>Latest 100 identity and access events from the tenant audit stream.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={auditQuery}
                        onChange={(event) => setAuditQuery(event.target.value)}
                        placeholder="Search events"
                        aria-label="Search audit events"
                      />
                    </label>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={handleExportAudit} disabled={isExporting || !mayExportAudit}>
                      <Icon name="download" />
                      {isExporting ? 'Exporting…' : 'Export CSV'}
                    </button>
                  </div>
                </div>

                {exportError && (
                  <div className="notice error" role="alert">
                    <strong>Export failed.</strong> {exportError}
                  </div>
                )}

                {auditEventsQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load audit events.</strong> {auditEventsQuery.error instanceof Error ? auditEventsQuery.error.message : 'Unknown error'}
                  </div>
                ) : auditLoading ? (
                  <div className="um-empty-block">Loading events…</div>
                ) : visibleAuditEvents.length === 0 ? (
                  <div className="um-empty-block">
                    {auditQuery
                      ? <>No events match &ldquo;{auditQuery}&rdquo;.</>
                      : 'No audit events recorded yet.'}
                  </div>
                ) : (
                  <div className="um-timeline">
                    {visibleAuditEvents.map((event) => {
                      const risk = deriveAuditRisk(event);
                      return (
                        <article key={event.id} className="um-audit-row">
                          <span className={AUDIT_RISK_PILL[risk]}>{risk}</span>
                          <div className="um-audit-meta">
                            <strong>{event.action}</strong>
                            <span>
                              {event.actorSubject ?? 'system'}
                              {event.targetType && ` · ${event.targetType}${event.targetId ? `:${event.targetId.slice(0, 8)}` : ''}`}
                              {event.outcome && ` · ${event.outcome}`}
                            </span>
                          </div>
                          <time dateTime={event.occurredAt}>{formatRelative(event.occurredAt)}</time>
                        </article>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </section>

      {inviteOpen && (
        <div className="um-modal-backdrop" role="presentation" onClick={closeInvite}>
          <section
            className="um-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="invite-user-title"
            onClick={(event) => event.stopPropagation()}
          >
            <form onSubmit={handleInviteSubmit} style={{ display: 'contents' }}>
              <div className="um-modal-head">
                <div>
                  <h3 id="invite-user-title">Invite User</h3>
                  <p>Creates a tenant membership for the resolved subject. The user appears under Members with role and status.</p>
                </div>
                <button
                  type="button"
                  className="um-icon-button"
                  aria-label="Close invite dialog"
                  onClick={closeInvite}
                >
                  <Icon name="close" />
                </button>
              </div>
              {addMember.isError && (
                <div className="notice error" role="alert">
                  <strong>Could not add member.</strong> {addMember.error instanceof Error ? addMember.error.message : 'Unknown error'}
                </div>
              )}
              <div className="um-form-grid">
                <label>
                  Email
                  <input
                    ref={inviteEmailRef}
                    name="email"
                    type="email"
                    placeholder="name@example.com"
                    required
                    autoComplete="email"
                  />
                </label>
                <label>
                  Display name
                  <input
                    name="displayName"
                    type="text"
                    placeholder="Name (optional)"
                    autoComplete="name"
                  />
                </label>
                <label>
                  Role
                  <select ref={inviteRoleRef} name="role" defaultValue="ANALYST" required>
                    {ROLE_KEYS.map((roleKey) => (
                      <option key={roleKey} value={roleKey.toUpperCase().replace(/\s+/g, '_')}>
                        {roleKey}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Tenant
                  <input value={tenantName} disabled readOnly />
                </label>
              </div>
              <div className="um-modal-actions">
                <button type="button" className="btn btn-secondary btn-sm" onClick={closeInvite}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={addMember.isPending || !tenantId}>
                  {addMember.isPending ? 'Sending…' : 'Send invite'}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}

      {serviceOpen && (
        <div className="um-modal-backdrop" role="presentation" onClick={closeService}>
          <section
            className="um-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="service-account-title"
            onClick={(event) => event.stopPropagation()}
          >
            <form onSubmit={handleServiceSubmit} style={{ display: 'contents' }}>
              <div className="um-modal-head">
                <div>
                  <h3 id="service-account-title">Create Service Account</h3>
                  <p>Issues a machine identity scoped to the current tenant. The Key ID is the credential the integration presents.</p>
                </div>
                <button
                  type="button"
                  className="um-icon-button"
                  aria-label="Close service account dialog"
                  onClick={closeService}
                >
                  <Icon name="close" />
                </button>
              </div>
              {createServiceAccount.isError && (
                <div className="notice error" role="alert">
                  <strong>Could not create service account.</strong> {createServiceAccount.error instanceof Error ? createServiceAccount.error.message : 'Unknown error'}
                </div>
              )}
              <div className="um-form-grid">
                <label>
                  Name
                  <input
                    ref={serviceNameRef}
                    name="name"
                    type="text"
                    placeholder="github-sbom-ingest"
                    required
                  />
                </label>
                <label>
                  Key ID
                  <input
                    name="keyId"
                    type="text"
                    placeholder="key-abc123"
                    required
                  />
                </label>
                <label>
                  Role
                  <select name="role" defaultValue="INTEGRATION_WRITER" required>
                    <option value="INTEGRATION_WRITER">Integration Writer</option>
                    <option value="WORKFLOW_WRITER">Workflow Writer</option>
                    <option value="AUDIT_EXPORTER">Audit Exporter</option>
                    <option value="VIEWER">Viewer</option>
                  </select>
                </label>
                <label>
                  Tenant
                  <input value={tenantName} disabled readOnly />
                </label>
              </div>
              <div className="um-modal-actions">
                <button type="button" className="btn btn-secondary btn-sm" onClick={closeService}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={createServiceAccount.isPending}>
                  {createServiceAccount.isPending ? 'Creating…' : 'Create account'}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}
