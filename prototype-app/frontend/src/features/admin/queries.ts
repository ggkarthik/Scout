import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getStoredAuthToken } from '../../api/client';
import { getAuthContextQueryKey } from '../auth/queries';
import type { ServiceAccountRequest, TenantMemberRequest } from './types';

const SERVICE_ACCOUNTS_KEY = ['service-accounts'] as const;
const AUDIT_EVENTS_KEY = ['audit-events'] as const;

function membersKey(tenantId: string | null | undefined) {
  return ['tenant-members', tenantId ?? 'unknown'] as const;
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
