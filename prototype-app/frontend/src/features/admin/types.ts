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

export type AuthContext = {
  creator: boolean;
  principal: string;
  userId: string;
  tenantId: string | null;
  tenantName: string | null;
  roles: string[];
};
