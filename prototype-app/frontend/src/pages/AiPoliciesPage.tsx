import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForPolicyDetail } from '../app/routes';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import type { AiGridPolicySelection } from '../features/ai-security/types';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export function AiPoliciesPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = React.useState<string | null>(null);
  const [search, setSearch] = React.useState('');
  const policiesQuery = useQuery({
    queryKey: ['ai-security-policies'],
    queryFn: api.listAiSecurityPolicies,
  });
  const governedPoliciesQuery = useQuery({
    queryKey: ['ai-grid-policies'],
    queryFn: api.listAiGridPolicies,
  });
  const canManage = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'PLATFORM_OWNER');
  const selectionMutation = useMutation({
    mutationFn: ({ id, selection }: { id: string; selection: AiGridPolicySelection }) =>
      api.updateAiGridPolicySelection(id, selection, 'Updated from governed policy catalog'),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-grid-policies'] }),
  });
  const governedSelection = React.useMemo(() => new Map(
    (governedPoliciesQuery.data ?? []).map((policy) => [policy.policyId, policy.selection]),
  ), [governedPoliciesQuery.data]);

  const policies = React.useMemo(() => policiesQuery.data ?? [], [policiesQuery.data]);
  const severityOptions = React.useMemo(() => (
    Array.from(new Set(policies.map((policy) => policy.severity.toUpperCase())))
      .sort((left, right) => (SEVERITY_RANK[left] ?? 99) - (SEVERITY_RANK[right] ?? 99))
  ), [policies]);
  const trimmedSearch = search.trim().toLowerCase();
  const visiblePolicies = React.useMemo(() => policies.filter((policy) => {
    if (severityFilter && policy.severity.toUpperCase() !== severityFilter) return false;
    if (trimmedSearch && !policy.name.toLowerCase().includes(trimmedSearch) && !policy.id.toLowerCase().includes(trimmedSearch)) return false;
    return true;
  }), [policies, severityFilter, trimmedSearch]);

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
        <>
          <div className="ai-policy-toolbar">
            <div className="ai-policy-severity-pills">
              <span className="ai-policy-severity-pills-label">Severity</span>
              <div className="ai-policy-severity-pills-row">
                <button
                  type="button"
                  className={`ai-policy-severity-pill${severityFilter === null ? ' is-active' : ''}`}
                  onClick={() => setSeverityFilter(null)}
                >
                  All
                </button>
                {severityOptions.map((severity) => (
                  <button
                    key={severity}
                    type="button"
                    className={`ai-policy-severity-pill${severityFilter === severity ? ' is-active' : ''}`}
                    onClick={() => setSeverityFilter((current) => (current === severity ? null : severity))}
                  >
                    {formatLabel(severity)}
                  </button>
                ))}
              </div>
            </div>
            <div className="ai-policy-search">
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search policies"
                aria-label="Search policies"
              />
            </div>
          </div>
          <div className="panel ai-security-table-panel">
            {visiblePolicies.length === 0 ? (
              <div className="empty-state"><p>No policies match the current filters.</p></div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Policy</th>
                    <th>Severity</th>
                    <th>Required evidence</th>
                    <th>Coverage</th>
                    <th>Findings</th>
                    <th>Selection</th>
                  </tr>
                </thead>
                <tbody>
                  {visiblePolicies.map((policy) => (
                    <tr key={policy.id} onClick={() => navigate(pathForPolicyDetail(policy.id))}>
                      <td><strong>{policy.name}</strong></td>
                      <td><span className={severityClassName(policy.severity)}>{policy.severity}</span></td>
                      <td><small>{policy.requiredResourceFamilies.join(' · ')}</small></td>
                      <td>
                        <strong>{Math.round(policy.decisionCoverage * 100)}%</strong>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="ai-policy-findings-link"
                          onClick={(event) => {
                            event.stopPropagation();
                            navigate(`/findings/ai?policyId=${encodeURIComponent(policy.id)}`);
                          }}
                        >
                          <strong>{policy.openFindings}</strong><span> open</span>
                        </button>
                      </td>
                      <td>
                        <select
                          value={governedSelection.get(policy.id) ?? (policy.enabled ? 'ENABLED' : 'DISABLED')}
                          disabled={!canManage || (selectionMutation.isPending && selectionMutation.variables?.id === policy.id)}
                          onClick={(event) => event.stopPropagation()}
                          onChange={(event) => selectionMutation.mutate({
                            id: policy.id,
                            selection: event.target.value as AiGridPolicySelection,
                          })}
                          aria-label={`${policy.name} selection`}
                        >
                          <option value="REQUIRED">Required</option>
                          <option value="ENABLED">Enabled</option>
                          <option value="PREVIEW">Preview</option>
                          <option value="DISABLED">Disabled</option>
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}
