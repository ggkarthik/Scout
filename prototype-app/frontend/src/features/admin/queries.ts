import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getStoredAuthToken } from '../../api/client';
import { getAuthContextQueryKey } from '../auth/queries';
import type { ServiceAccountRequest, TenantMemberRequest, TenantSupportGrantRequest } from './types';

const SERVICE_ACCOUNTS_KEY = ['service-accounts'] as const;
const AUDIT_EVENTS_KEY = ['audit-events'] as const;
const PLATFORM_SUPPORT_GRANTS_KEY = ['platform-support-grants'] as const;
const PLATFORM_INVENTORY_CONNECTOR_HEALTH_KEY = ['platform-inventory-connector-health'] as const;

function membersKey(tenantId: string | null | undefined) {
  return ['tenant-members', tenantId ?? 'unknown'] as const;
}

function supportGrantsKey(tenantId: string | null | undefined) {
  return ['tenant-support-grants', tenantId ?? 'unknown'] as const;
}

export function useAuthContextQuery() {
  const authToken = getStoredAuthToken().trim() || 'anonymous';
  return useQuery({
    queryKey: getAuthContextQueryKey(authToken),
    queryFn: api.getAuthContext,
    staleTime: 5 * 60 * 1000
  });
}

export function useTenantMembersQuery(tenantId: string | null | undefined) {
  return useQuery({
    queryKey: membersKey(tenantId),
    queryFn: () => api.listTenantMembers(tenantId as string),
    enabled: !!tenantId
  });
}

export function useAddTenantMemberMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: TenantMemberRequest) => api.addTenantMember(tenantId as string, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: membersKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useTenantSupportGrantsQuery(tenantId: string | null | undefined) {
  return useQuery({
    queryKey: supportGrantsKey(tenantId),
    queryFn: () => api.listTenantSupportGrants(tenantId as string),
    enabled: !!tenantId
  });
}

export function useCreateTenantSupportGrantMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: TenantSupportGrantRequest) => api.createTenantSupportGrant(tenantId as string, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: supportGrantsKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: PLATFORM_SUPPORT_GRANTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
      queryClient.invalidateQueries({ queryKey: getAuthContextQueryKey(getStoredAuthToken().trim() || 'anonymous') });
    }
  });
}

export function useRevokeTenantSupportGrantMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (grantId: string) => api.revokeTenantSupportGrant(tenantId as string, grantId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: supportGrantsKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: PLATFORM_SUPPORT_GRANTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
      queryClient.invalidateQueries({ queryKey: getAuthContextQueryKey(getStoredAuthToken().trim() || 'anonymous') });
    }
  });
}

export function useServiceAccountsQuery() {
  return useQuery({
    queryKey: SERVICE_ACCOUNTS_KEY,
    queryFn: api.listServiceAccounts
  });
}

export function useCreateServiceAccountMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ServiceAccountRequest) => api.createServiceAccount(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: SERVICE_ACCOUNTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useAuditEventsQuery() {
  return useQuery({
    queryKey: AUDIT_EVENTS_KEY,
    queryFn: api.listAuditEvents
  });
}

export function usePlatformSupportGrantsQuery() {
  return useQuery({
    queryKey: PLATFORM_SUPPORT_GRANTS_KEY,
    queryFn: api.listPlatformSupportGrants
  });
}

export function useAcceptPlatformSupportGrantMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (grantId: string) => api.acceptPlatformSupportGrant(grantId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: PLATFORM_SUPPORT_GRANTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
      queryClient.invalidateQueries({ queryKey: getAuthContextQueryKey(getStoredAuthToken().trim() || 'anonymous') });
    }
  });
}

export function usePlatformInventoryConnectorHealthQuery() {
  return useQuery({
    queryKey: PLATFORM_INVENTORY_CONNECTOR_HEALTH_KEY,
    queryFn: api.listPlatformInventoryConnectorHealth
  });
}
