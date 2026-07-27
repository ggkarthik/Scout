import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';

export function AiPoliciesPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const policiesQuery = useQuery({
    queryKey: ['ai-security-policies'],
    queryFn: api.listAiSecurityPolicies,
  });
  const mutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.updateAiSecurityPolicy(id, enabled),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-policies'] }),
  });
  const canManage = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'PLATFORM_OWNER');

  return (
    <div className="ai-security-page">
      <section className="ai-security-hero policies">
        <div>
          <span className="ai-security-kicker">Built-in, versioned controls</span>
          <h2>Policies</h2>
          <p>Platform-shipped AI configuration checks with tenant-level enablement and quality coverage.</p>
        </div>
      </section>

      {policiesQuery.isLoading ? (
        <section className="panel"><div className="empty-state"><p>Loading policies…</p></div></section>
      ) : policiesQuery.isError ? (
        <section className="panel"><div className="notice error">AI Security policies could not be loaded.</div></section>
      ) : (
        <div className="ai-policy-grid">
          {(policiesQuery.data ?? []).map((policy) => (
            <article className="panel ai-policy-card" key={policy.id}>
              <div className="ai-policy-card-head">
                <span className={`severity-badge ${policy.severity.toLowerCase()}`}>{policy.severity}</span>
                <label className="ai-policy-switch">
                  <input
                    type="checkbox"
                    checked={policy.enabled}
                    disabled={!canManage || mutation.isPending}
                    onChange={(event) => mutation.mutate({ id: policy.id, enabled: event.target.checked })}
                  />
                  <span>{policy.enabled ? 'Enabled' : 'Disabled'}</span>
                </label>
              </div>
              <h3>{policy.name}</h3>
              <p>{policy.description}</p>
              <div className="ai-policy-stats">
                <button type="button" onClick={() => navigate(`/findings/ai?policyId=${encodeURIComponent(policy.id)}`)}>
                  <strong>{policy.openFindings}</strong><span>Open findings</span>
                </button>
                <div><strong>{policy.lifetimeFindings}</strong><span>Lifetime findings</span></div>
                <div><strong>{Math.round(policy.decisionCoverage * 100)}%</strong><span>Decision coverage</span></div>
              </div>
              <div className={`ai-policy-coverage-gate ${policy.decisionCoverageStatus.toLowerCase()}`}>
                <strong>
                  {policy.decisionCoverageStatus === 'NO_DATA'
                    ? 'Coverage not measured'
                    : policy.decisionCoverageStatus === 'PASS'
                      ? 'Pilot coverage gate passed'
                      : 'Pilot coverage gate blocked'}
                </strong>
                <span>
                  {policy.evaluatedArtifacts} evaluated · {policy.noDecisionCount} no decision ·{' '}
                  {Math.round(policy.decisionCoverageThreshold * 100)}% required
                </span>
              </div>
              <div className="ai-policy-evidence">
                <span>Required evidence</span>
                <p>{policy.requiredResourceFamilies.join(' · ')}</p>
              </div>
              <div className="ai-policy-remediation"><strong>Remediation</strong><p>{policy.remediation}</p></div>
              <small>{policy.id} · v{policy.version}</small>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
