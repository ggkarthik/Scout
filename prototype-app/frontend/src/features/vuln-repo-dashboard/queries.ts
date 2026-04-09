import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';

export function useVulnRepoDashboardQuery() {
  return useQuery({
    queryKey: ['vuln-repo-dashboard'],
    queryFn: () => api.getVulnRepoDashboard(),
  });
}
