import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForPolicyDetail } from '../app/routes';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import type { AiGridPolicy, AiGridPolicySelection } from '../features/ai-security/types';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const PROVIDER_ORDER = ['AWS', 'AZURE', 'MULTI_CLOUD'];

type FrameworkMapping = { framework?: string; frameworkVersion?: string; controlId?: string; mappingType?: string; rationale?: string };

function parseStringArray(json: string): string[] {
  try { const value = JSON.parse(json || '[]'); return Array.isArray(value) ? value.map(String) : []; } catch { return []; }
}
function parseFrameworkMappings(json: string): FrameworkMapping[] {
  try { const value = JSON.parse(json || '[]'); return Array.isArray(value) ? (value as FrameworkMapping[]) : []; } catch { return []; }
}

export function AiPoliciesPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = React.useState<string | null>(null);
  const [search, setSearch] = React.useState('');
  const [expanded, setExpanded] = React.useState<Set<string>>(() => new Set());
  const policiesQuery = useQuery({
    queryKey: ['ai-grid-policies'],
    queryFn: api.listAiGridPolicies,
  });
  const mutation = useMutation({
    mutationFn: ({ id, selection }: { id: string; selection: AiGridPolicySelection }) =>
      api.updateAiGridPolicySelection(id, selection),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['ai-grid-policies'] });
      void queryClient.invalidateQueries({ queryKey: ['ai-security-policies'] });
    },
  });
  const canManage = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'PLATFORM_OWNER');

  const policies = React.useMemo(() => policiesQuery.data ?? [], [policiesQuery.data]);
  const severityOptions = React.useMemo(() => (
    Array.from(new Set(policies.map((policy) => policy.severity.toUpperCase())))
      .sort((left, right) => (SEVERITY_RANK[left] ?? 99) - (SEVERITY_RANK[right] ?? 99))
  ), [policies]);
  const trimmedSearch = search.trim().toLowerCase();
  const visiblePolicies = React.useMemo(() => policies.filter((policy) => {
    if (severityFilter && policy.severity.toUpperCase() !== severityFilter) return false;
    if (trimmedSearch && !policy.name.toLowerCase().includes(trimmedSearch) && !policy.policyId.toLowerCase().includes(trimmedSearch)) return false;
    return true;
  }), [policies, severityFilter, trimmedSearch]);
  const groupedPolicies = React.useMemo(() => {
    const groups = new Map<string, AiGridPolicy[]>();
    for (const policy of visiblePolicies) {
      const key = (policy.provider || 'OTHER').toUpperCase();
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(policy);
    }
    return Array.from(groups.entries()).sort(([left], [right]) => {
      const li = PROVIDER_ORDER.indexOf(left); const ri = PROVIDER_ORDER.indexOf(right);
      return (li === -1 ? 99 : li) - (ri === -1 ? 99 : ri) || left.localeCompare(right);
    });
  }, [visiblePolicies]);
  const toggleExpanded = React.useCallback((policyId: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(policyId)) next.delete(policyId); else next.add(policyId);
      return next;
    });
  }, []);

  return (
    <div className="ai-security-page">
      <section className="ai-security-hero policies">
        <div>
          <span className="ai-security-kicker">Built-in, versioned controls</span>
          <h2>Policies</h2>
          <p>Governed AI security controls, with tenant selection and evidence readiness shown independently.</p>
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
              groupedPolicies.map(([provider, group]) => (
                <div key={provider} className="ai-policy-group">
                  <h3 className="ai-policy-group-heading">{formatLabel(provider)} <small>({group.length})</small></h3>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th aria-label="Expand" />
                        <th>Policy</th>
                        <th>Severity</th>
                        <th>Objective</th>
                        <th>Evaluation</th>
                        <th>Readiness</th>
                        <th>Selection</th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.map((policy) => (
                        <PolicyRows
                          key={policy.policyId}
                          policy={policy}
                          expanded={expanded.has(policy.policyId)}
                          canManage={canManage}
                          saving={mutation.isPending && mutation.variables?.id === policy.policyId}
                          onToggle={() => toggleExpanded(policy.policyId)}
                          onOpen={() => navigate(pathForPolicyDetail(policy.policyId))}
                          onSelect={(checked) => mutation.mutate({ id: policy.policyId, selection: checked ? 'ENABLED' : 'DISABLED' })}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}

function PolicyRows({ policy, expanded, canManage, saving, onToggle, onOpen, onSelect }: {
  policy: AiGridPolicy;
  expanded: boolean;
  canManage: boolean;
  saving: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onSelect: (checked: boolean) => void;
}) {
  const conditionalCapabilities = parseStringArray(policy.conditionalCapabilitiesJson);
  const evidenceTiers = parseStringArray(policy.baseEvidenceTiersJson);
  const mappings = parseFrameworkMappings(policy.frameworkMappingsJson);
  return (
    <>
      <tr onClick={onOpen}>
        <td>
          <button
            type="button"
            className="ai-policy-expand"
            aria-label={expanded ? `Collapse ${policy.name}` : `Expand ${policy.name}`}
            aria-expanded={expanded}
            onClick={(event) => { event.stopPropagation(); onToggle(); }}
          >
            {expanded ? '▾' : '▸'}
          </button>
        </td>
        <td>
          <strong>{policy.name}</strong>
          {conditionalCapabilities.length > 0 ? (
            <span className="ai-policy-capability-flag" title="Requires an optional connector capability"> · needs capability</span>
          ) : null}
        </td>
        <td><span className={severityClassName(policy.severity)}>{policy.severity}</span></td>
        <td><small>{policy.controlObjectiveId}</small></td>
        <td>{formatLabel(policy.evaluationMode)}</td>
        <td><span className={`ai-policy-readiness ai-policy-readiness-${policy.readiness.toLowerCase()}`}>{formatLabel(policy.readiness)}</span></td>
        <td>
          <label className="ai-policy-switch" onClick={(event) => event.stopPropagation()}>
            <input
              type="checkbox"
              checked={policy.selection === 'REQUIRED' || policy.selection === 'ENABLED'}
              disabled={!canManage || saving}
              onChange={(event) => onSelect(event.target.checked)}
              aria-label={policy.selection}
            />
            <span>{formatLabel(policy.selection)}</span>
          </label>
        </td>
      </tr>
      {expanded ? (
        <tr className="ai-policy-detail-row">
          <td />
          <td colSpan={6}>
            <div className="ai-policy-detail">
              <p className="ai-policy-detail-evidence">
                <strong>Evidence tiers:</strong> {evidenceTiers.length > 0 ? evidenceTiers.join(', ') : '—'}
              </p>
              <div className="ai-policy-detail-block">
                <strong>Required connector capabilities</strong>
                {conditionalCapabilities.length === 0 ? (
                  <p>None — decides from base connector evidence.</p>
                ) : (
                  <ul className="ai-policy-setup-list">
                    {conditionalCapabilities.map((capability) => (
                      <li key={capability}>
                        Enable <code>{formatLabel(capability)}</code> in the connector to make this policy decision-capable; without it the policy reports <em>NO_DECISION</em>.
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="ai-policy-detail-block">
                <strong>Framework mappings</strong>
                {mappings.length === 0 ? (
                  <p>No structured framework mappings.</p>
                ) : (
                  <ul className="ai-policy-mapping-list">
                    {mappings.map((mapping, index) => (
                      <li key={`${mapping.framework}-${mapping.controlId}-${index}`}>
                        <strong>{mapping.framework} {mapping.frameworkVersion}</strong> · {mapping.controlId} <span className="ai-policy-mapping-type">{mapping.mappingType}</span>
                        {mapping.rationale ? <><br /><small>{mapping.rationale}</small></> : null}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}
