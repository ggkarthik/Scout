export type AllowedTenant = {
  id: string;
  name: string;
  slug: string | null;
  role: string;
};

export type ActorContext = {
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
