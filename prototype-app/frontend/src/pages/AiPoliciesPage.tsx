import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForPolicyDetail } from '../app/routes';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { ProviderLogo } from '../features/ai-security/ProviderLogo';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import type { AiGridPolicy, AiGridPolicySelection } from '../features/ai-security/types';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const PROVIDER_ORDER = ['AWS', 'AZURE', 'MULTI_CLOUD'];

function parseStringArray(json: string): string[] {
  try { const value = JSON.parse(json || '[]'); return Array.isArray(value) ? value.map(String) : []; } catch { return []; }
}

function parseFrameworks(json: string): string[] {
  try {
    const value = JSON.parse(json || '[]');
    if (!Array.isArray(value)) return [];
    return value.map((mapping) => {
      if (typeof mapping === 'string') return mapping;
      if (!mapping || typeof mapping !== 'object') return '';
      const item = mapping as { framework?: unknown; frameworkVersion?: unknown };
      return [item.framework, item.frameworkVersion].filter(Boolean).join(' ');
    }).filter(Boolean);
  } catch { return []; }
}

function providerNames(provider: string): string[] {
  const normalized = provider.toUpperCase();
  if (normalized === 'MULTI_CLOUD' || normalized === 'MULTI-CLOUD') return ['AWS', 'AZURE'];
  return normalized.split(/[,/ ]+/).filter((name) => name === 'AWS' || name === 'AZURE');
}

export function AiPoliciesPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = React.useState<string | null>(null);
  const [search, setSearch] = React.useState('');
  const [selectedPolicyIds, setSelectedPolicyIds] = React.useState<Set<string>>(new Set());
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
  const canExecute = canManage || hasRole(actor, 'SECURITY_ANALYST');
  const executeMutation = useMutation({
    mutationFn: () => api.executeAiGridPolicies(Array.from(selectedPolicyIds)),
    onSuccess: () => {
      setSelectedPolicyIds(new Set());
      void queryClient.invalidateQueries({ queryKey: ['ai-grid-policies'] });
      void queryClient.invalidateQueries({ queryKey: ['ai-security-policies'] });
    },
  });

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
  const policyInsights = React.useMemo(() => buildPolicyInsights(policies), [policies]);
  return (
    <div className="ai-security-page">
      <section className="ai-security-hero policies">
        <div>
          <span className="ai-security-kicker">Built-in, versioned controls</span>
          <h2>Policies</h2>
          <p>Governed AI security controls, with tenant selection and evidence readiness shown independently.</p>
        </div>
      </section>

      {!policiesQuery.isError ? <PolicyInsights insights={policyInsights} loading={policiesQuery.isLoading} /> : null}

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
            <button
              type="button"
              className="btn btn-primary ai-policy-execute-button"
              disabled={!canExecute || selectedPolicyIds.size === 0 || executeMutation.isPending}
              onClick={() => executeMutation.mutate()}
            >
              {executeMutation.isPending ? 'Assessing…' : 'Execute now'}
            </button>
          </div>
          {executeMutation.isError ? <div className="notice error">Selected policies could not be assessed. Please try again.</div> : null}
          {executeMutation.data ? <div className="notice success">Assessment completed for {executeMutation.data.evaluatedPolicies} selected {executeMutation.data.evaluatedPolicies === 1 ? 'policy' : 'policies'}.</div> : null}
          {selectedPolicyIds.size > 0 ? <div className="ai-policy-selection-status">{selectedPolicyIds.size} {selectedPolicyIds.size === 1 ? 'policy' : 'policies'} selected for assessment.</div> : null}
          <div className="panel ai-security-table-panel">
            {visiblePolicies.length === 0 ? (
              <div className="empty-state"><p>No policies match the current filters.</p></div>
            ) : (
              <table className="data-table">
                    <thead>
                      <tr>
                        <th>Select</th>
                        <th>Policy</th>
                        <th>Severity</th>
                        <th>Framework</th>
                        <th>Failed artefacts</th>
                        <th>Provide</th>
                        <th>Artefact types</th>
                        <th>Enabled/disabled</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visiblePolicies.map((policy) => (
                        <PolicyRows
                          key={policy.policyId}
                          policy={policy}
                          canManage={canManage}
                          saving={mutation.isPending && mutation.variables?.id === policy.policyId}
                          onOpen={() => navigate(pathForPolicyDetail(policy.policyId))}
                          onSelect={(checked) => mutation.mutate({ id: policy.policyId, selection: checked ? 'ENABLED' : 'DISABLED' })}
                          selected={selectedPolicyIds.has(policy.policyId)}
                          onToggleSelected={(checked) => setSelectedPolicyIds((current) => {
                            const next = new Set(current);
                            if (checked) next.add(policy.policyId); else next.delete(policy.policyId);
                            return next;
                          })}
                        />
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

type PolicyInsights = ReturnType<typeof buildPolicyInsights>;

function buildPolicyInsights(policies: AiGridPolicy[]) {
  const required = policies.filter((policy) => policy.selection === 'REQUIRED').length;
  const enabled = policies.filter((policy) => policy.selection === 'ENABLED').length;
  const critical = policies.filter((policy) => policy.severity.toUpperCase() === 'CRITICAL').length;
  const high = policies.filter((policy) => policy.severity.toUpperCase() === 'HIGH').length;
  const ready = policies.filter((policy) => policy.readiness.toUpperCase() === 'READY').length;
  const partial = policies.filter((policy) => policy.readiness.toUpperCase() === 'PARTIAL').length;
  const blocked = policies.filter((policy) => policy.readiness.toUpperCase() === 'BLOCKED').length;
  const noResources = policies.filter((policy) => policy.readiness.toUpperCase() === 'NO_RESOURCES').length;
  const notEvaluated = policies.filter((policy) => policy.readiness.toUpperCase() === 'NOT_EVALUATED').length;
  const providers = PROVIDER_ORDER.map((provider) => ({
    label: formatLabel(provider),
    count: policies.filter((policy) => policy.provider.toUpperCase() === provider).length,
  }));
  const readinessPercent = policies.length === 0 ? 0 : Math.round((ready / policies.length) * 100);
  return {
    required, enabled, critical, high, ready, partial, blocked, noResources, notEvaluated,
    providers, readinessPercent, total: policies.length, enforced: required + enabled,
    gaps: policies.length - ready,
  };
}

function PolicyInsights({ insights, loading }: { insights: PolicyInsights; loading: boolean }) {
  const value = (number: number) => loading ? '—' : number.toLocaleString();
  return (
    <section className="ai-policy-insight-grid" aria-label="Policy organization insights">
      <PolicyInsightCard
        tone="accent"
        label="Policy estate"
        value={value(insights.total)}
        detail={loading ? 'Loading catalog' : `${value(insights.providers[0].count)} AWS · ${value(insights.providers[1].count)} Azure · ${value(insights.providers[2].count)} multi-cloud`}
      />
      <PolicyInsightCard
        tone="accent"
        label="Enforcement posture"
        value={value(insights.enforced)}
        detail={loading ? 'Loading selections' : `${value(insights.required)} required · ${value(insights.enabled)} enabled`}
      />
      <PolicyInsightCard
        tone={insights.critical > 0 ? 'critical' : 'accent'}
        label="High-priority controls"
        value={value(insights.critical + insights.high)}
        detail={loading ? 'Loading severity mix' : `${value(insights.critical)} critical · ${value(insights.high)} high`}
      />
      <PolicyInsightCard
        tone={insights.readinessPercent >= 80 ? 'positive' : 'warn'}
        label="Evidence ready"
        value={loading ? '—' : `${insights.readinessPercent}%`}
        detail={loading ? 'Loading readiness' : `${value(insights.ready)} of ${value(insights.total)} controls ready`}
      />
      <PolicyInsightCard
        tone={insights.gaps > 0 ? 'warn' : 'positive'}
        label="Coverage gaps"
        value={value(insights.gaps)}
        detail={loading ? 'Loading gaps' : `${value(insights.partial)} partial · ${value(insights.blocked)} blocked`}
      />
      <PolicyInsightCard
        tone={insights.noResources + insights.notEvaluated > 0 ? 'warn' : 'positive'}
        label="Organization blind spots"
        value={value(insights.noResources + insights.notEvaluated)}
        detail={loading ? 'Loading evaluation state' : `${value(insights.noResources)} no resources · ${value(insights.notEvaluated)} not evaluated`}
      />
    </section>
  );
}

function PolicyInsightCard({ label, value, detail, tone }: {
  label: string;
  value: string;
  detail: string;
  tone: 'accent' | 'positive' | 'warn' | 'critical';
}) {
  return (
    <article className={`ai-policy-insight-card ai-policy-insight-card-${tone}`}>
      <span className="ai-policy-insight-label">{label}</span>
      <strong className="ai-policy-insight-value">{value}</strong>
      <span className="ai-policy-insight-detail">{detail}</span>
    </article>
  );
}

function PolicyRows({ policy, canManage, saving, onOpen, onSelect, selected, onToggleSelected }: {
  policy: AiGridPolicy;
  canManage: boolean;
  saving: boolean;
  onOpen: () => void;
  onSelect: (checked: boolean) => void;
  selected: boolean;
  onToggleSelected: (checked: boolean) => void;
}) {
  const conditionalCapabilities = parseStringArray(policy.conditionalCapabilitiesJson);
  const frameworks = parseFrameworks(policy.frameworkMappingsJson);
  const artifactTypes = parseStringArray(policy.artifactTypesJson);
  const resourceFamilies = parseStringArray(policy.requiredResourceFamiliesJson);
  const providers = providerNames(policy.provider);
  return (
    <>
      <tr onClick={onOpen}>
        <td onClick={(event) => event.stopPropagation()}>
          <input
            className="ai-policy-select-checkbox"
            type="checkbox"
            checked={selected}
            onChange={(event) => onToggleSelected(event.target.checked)}
            aria-label={`Select ${policy.name}`}
          />
        </td>
        <td>
          <strong>{policy.name}</strong>
          {conditionalCapabilities.length > 0 ? (
            <span className="ai-policy-capability-flag" title="Requires an optional connector capability"> · needs capability</span>
          ) : null}
        </td>
        <td><span className={severityClassName(policy.severity)}>{policy.severity}</span></td>
        <td>
          <div className="ai-policy-framework-list">
            {frameworks.length > 0 ? frameworks.map((framework) => <span key={framework}>{formatLabel(framework)}</span>) : <small>—</small>}
          </div>
        </td>
        <td><strong>{policy.failedArtifacts} / {policy.totalArtifacts}</strong></td>
        <td>
          <div className="ai-policy-provider-logos" aria-label={`Applicable providers: ${providers.join(', ')}`}>
            {providers.length > 0 ? providers.map((provider) => <span key={provider} className="ai-policy-provider-logo"><ProviderLogo provider={provider} /></span>) : <small>—</small>}
          </div>
        </td>
        <td>
          <div className="ai-policy-artifact-list">
            {artifactTypes.map((type) => <span key={type}>{formatLabel(type)}</span>)}
            {resourceFamilies.map((family) => <small key={family}>{formatLabel(family)}</small>)}
            {artifactTypes.length === 0 && resourceFamilies.length === 0 ? <small>—</small> : null}
          </div>
        </td>
        <td>
          <label className="ai-policy-toggle" onClick={(event) => event.stopPropagation()}>
            <input
              type="checkbox"
              checked={policy.selection === 'REQUIRED' || policy.selection === 'ENABLED'}
              disabled={!canManage || saving}
              onChange={(event) => onSelect(event.target.checked)}
              aria-label={`${policy.name} enabled`}
            />
            <span className="ai-policy-toggle-track" aria-hidden="true"><span className="ai-policy-toggle-thumb" /></span>
          </label>
        </td>
      </tr>
    </>
  );
}
