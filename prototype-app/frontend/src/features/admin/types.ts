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
  demoExpiresAt?: string | null;
  demoCreatedBy?: string | null;
  demoSource?: string | null;
  createdAt: string;
  updatedAt: string | null;
};

export type TenantCreateRequest = {
  name: string;
  slug: string;
  planCode?: string;
  billingRef?: string;
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
  planCode?: string | null;
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
