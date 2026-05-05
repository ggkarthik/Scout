export type ActorContext = {
  creator: boolean;
  principal: string;
  userId: string;
  tenantId: string | null;
  tenantName: string | null;
  roles: string[];
  planCode?: string | null;
  demoExpiresAt?: string | null;
  demoDaysRemaining?: number | null;
  demoCapabilities?: Record<string, boolean> | null;
  demoUsage?: Record<string, number> | null;
};
