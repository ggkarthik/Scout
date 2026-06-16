export type TenantMember = {
  id: string;
  userId: string;
  subject: string;
  email: string | null;
  displayName: string | null;
  role: string;
  status: string;
  createdAt: string;
};

export type TenantMemberUpdateRequest = {
  role?: string;
  status?: string;
};

export type TenantInvite = {
  id: string;
  tenantId: string;
  email: string;
  displayName: string | null;
  subject: string;
  role: string;
  status: string;
  createdAt: string;
  expiresAt: string;
  acceptedAt: string | null;
  lastSentAt: string | null;
  invitedBySubject: string | null;
  invitedByDisplayName: string | null;
  deliveryDetail: string | null;
};

export type TenantInviteRequest = {
  email: string;
  displayName: string;
  role: string;
};

export type TenantBulkInviteRequest = {
  invites: TenantInviteRequest[];
};

export type TenantBulkInviteItemResult = {
  email: string;
  displayName: string | null;
  role: string | null;
  status: string;
  message: string;
  invite: TenantInvite | null;
};

export type TenantBulkInviteResponse = {
  requestedCount: number;
  invitedCount: number;
  failedCount: number;
  results: TenantBulkInviteItemResult[];
};

export type TenantInviteValidationResponse = {
  valid: boolean;
  status: string;
  email: string;
  tenantId: string;
  tenantName: string;
  inviteeName: string | null;
  role: string;
  inviteExpiresAt: string;
  message: string;
  setupToken?: string | null;
};

export type PlatformUser = {
  userId: string;
  externalSubject: string;
  email: string | null;
  displayName: string | null;
  status: string;
  globalRoles: string[];
  lastSeenAt: string | null;
  createdAt: string;
};

export type PlatformUserRequest = {
  externalSubject: string;
  email?: string;
  displayName?: string;
  role: string;
};

export type TenantMemberRequest = {
  subject: string;
  email: string;
  displayName: string;
  role: string;
};

export type Tenant = {
  id: string;
  name: string;
  slug: string;
  status: string;
  planCode: string | null;
  billingRef: string | null;
  maxConnectorCount: number | null;
  maxServiceAccountCount: number | null;
  maxDailySbomUploads: number | null;
  maxExportRows: number | null;
  maxDailyExposureRefreshes: number | null;
  expiredAt?: string | null;
  purgeStartedAt?: string | null;
  purgedAt?: string | null;
  purgeStatus?: string | null;
  purgeError?: string | null;
  demoExpiresAt?: string | null;
  demoCreatedBy?: string | null;
  demoSource?: string | null;
  demoOwnerEmail?: string | null;
  createdAt: string;
  updatedAt: string | null;
};

export type TenantCreateRequest = {
  name: string;
  slug: string;
  planCode?: string;
  billingRef?: string;
};

export type TenantEntitlement = {
  key: string;
  category: string;
  enabled: boolean;
  source: string;
  planCode: string | null;
  config: Record<string, unknown> | null;
};

export type TenantEntitlementOverride = {
  id: string;
  tenantId: string;
  entitlementKey: string;
  enabled: boolean;
  config: Record<string, unknown> | null;
  reason: string | null;
  expiresAt: string | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string | null;
};

export type TenantEntitlementSnapshot = {
  tenantId: string;
  planCode: string | null;
  entitlements: TenantEntitlement[];
  overrides: TenantEntitlementOverride[];
};

export type TenantEntitlementOverrideRequest = {
  enabled: boolean;
  config?: Record<string, unknown> | null;
  reason?: string;
  expiresAt?: string | null;
};

export type ServiceAccount = {
  id: string;
  tenantId: string | null;
  name: string;
  keyId: string;
  role: string;
  status: string;
  createdAt: string;
  lastUsedAt: string | null;
};

export type ServiceAccountRequest = {
  tenantId?: string;
  name: string;
  keyId: string;
  role: string;
};

export type AuditEvent = {
  id: string;
  occurredAt: string;
  tenantId: string | null;
  actorSubject: string | null;
  actorRole: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  outcome: string | null;
  detailsJson: string | null;
};

export type AllowedTenant = {
  id: string;
  name: string;
  slug: string | null;
  role: string;
  accessMode?: string | null;
  expiresAt?: string | null;
};

export type AuthContext = {
  creator: boolean;
  principal: string;
  userId: string;
  tenantId: string | null;
  tenantName: string | null;
  roles: string[];
  allowedTenants?: AllowedTenant[];
  platformScope?: boolean;
  actingAsPlatformOwner?: boolean;
  sensitiveActionConfirmationRequired?: boolean;
  supportAccessMode?: string | null;
  supportGrantExpiresAt?: string | null;
  planCode?: string | null;
  entitlements?: Record<string, boolean> | null;
  demo?: boolean | null;
  demoExpiresAt?: string | null;
  demoDaysRemaining?: number | null;
  demoCapabilities?: Record<string, boolean> | null;
  demoUsage?: Record<string, number> | null;
};

export type DemoInvite = {
  id: string;
  requestId: string | null;
  tenantId: string;
  tenantName: string;
  email: string;
  status: string;
  expiresAt: string;
  acceptedAt: string | null;
  lastSentAt: string | null;
  inviteUrl: string;
};

export type DemoSetupLink = {
  requestId: string;
  inviteId: string;
  tenantId: string;
  tenantName: string;
  email: string;
  inviteStatus: string;
  inviteExpiresAt: string;
  inviteUrl: string;
  setupUrl: string;
};

export type DemoRequest = {
  id: string;
  email: string;
  fullName: string;
  company: string;
  roleTitle: string | null;
  companySize: string | null;
  useCase: string | null;
  notes: string | null;
  status: string;
  requestedAt: string;
  decidedAt: string | null;
  decidedBy: string | null;
  rejectionReason: string | null;
  tenantId: string | null;
  provisionedPlanCode: string | null;
  latestInvite: DemoInvite | null;
};

export type DemoRequestCreateRequest = {
  fullName: string;
  email: string;
  company: string;
  roleTitle?: string;
  companySize?: string;
  useCase?: string;
  notes?: string;
  acceptedTerms: boolean;
};

export type DemoInviteValidationResponse = {
  valid: boolean;
  status: string;
  email: string;
  tenantId: string;
  tenantName: string;
  demoExpiresAt: string;
  inviteExpiresAt: string;
  loginUrl: string;
  message: string;
  setupToken?: string | null;
};

export type AuthTokenResponse = {
  token: string;
  tokenType: 'Bearer';
  expiresAt: string;
};

export type DemoStatus = {
  demo: boolean;
  planCode: string | null;
  demoExpiresAt: string | null;
  demoDaysRemaining: number | null;
  demoCapabilities: Record<string, boolean>;
  demoUsage: Record<string, number>;
};

export type TenantSupportGrant = {
  id: string;
  tenantId: string;
  tenantName: string;
  invitedPlatformSubject: string;
  reason: string;
  scope: string | null;
  accessMode: string;
  status: string;
  grantedBySubject: string | null;
  acceptedBySubject: string | null;
  revokedBySubject: string | null;
  requestedAt: string;
  acceptedAt: string | null;
  expiresAt: string;
  revokedAt: string | null;
};

export type TenantSupportGrantRequest = {
  invitedPlatformSubject: string;
  reason: string;
  scope?: string;
  accessMode?: string;
  expiresAt: string;
};

export type InventoryConnectorHealth = {
  tenantId: string;
  tenantName: string;
  connectorKey: string;
  enabled: boolean;
  autoSyncEnabled: boolean;
  lastTestStatus: string | null;
  lastTestMessage: string | null;
  lastTestedAt: string | null;
  lastSyncAt: string | null;
  healthState: string;
};
