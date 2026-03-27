import { useQuery } from '@tanstack/react-query';
import { authApi } from './api';

const ACTOR_CONTEXT_QUERY_KEY = ['actor-context'] as const;

export function useActorQuery() {
  return useQuery({
    queryKey: ACTOR_CONTEXT_QUERY_KEY,
    queryFn: authApi.getActorContext
  });
}
