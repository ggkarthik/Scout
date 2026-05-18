import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';

export function useVulnRepoDashboardQuery(platformScope = false) {
  return useQuery({
    queryKey: ['vuln-repo-dashboard', platformScope ? 'platform' : 'tenant'],
    queryFn: () => platformScope ? api.getPlatformVulnRepoDashboard() : api.getVulnRepoDashboard(),
  });
}
