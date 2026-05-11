import { useQuery } from '@tanstack/react-query';
import { getStoredAuthToken } from '../../api/client';
import { authApi } from './api';

export function useActorQuery() {
  const authToken = getStoredAuthToken().trim() || 'anonymous';
  return useQuery({
    queryKey: ['actor-context', authToken],
    queryFn: authApi.getActorContext
  });
}
