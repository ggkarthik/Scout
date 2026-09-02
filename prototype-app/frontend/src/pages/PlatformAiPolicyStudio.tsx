import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { AiGridPolicyDistribution, AiGridPolicySelection } from '../features/ai-security/types';

const DEFAULTS: AiGridPolicySelection[] = ['REQUIRED', 'ENABLED', 'DISABLED'];
const ROLLOUTS: AiGridPolicyDistribution['rolloutStage'][] = ['GENERAL_AVAILABILITY', 'CANARY', 'PAUSED', 'RETIRED'];

function owaspMappings(value?: string): string {
  try {
    return (JSON.parse(value ?? '[]') as Array<{ framework?: string; controlId?: string; mappingType?: string }>)
      .filter((mapping) => mapping.framework === 'OWASP_GENAI_LLM_TOP_10' && /^LLM\d{2}$/.test(mapping.controlId ?? ''))
      .map((mapping) => `${mapping.controlId} (${mapping.mappingType})`).join(', ') || '—';
  } catch { return '—'; }
}

function rolloutLabel(stage: AiGridPolicyDistribution['rolloutStage']): string {
  return stage === 'GENERAL_AVAILABILITY' ? 'General availability' : stage.charAt(0) + stage.slice(1).toLowerCase();
}

function statusClass(value: string): string {
  return `policy-status policy-status--${value.toLowerCase().replace(/_/g, '-')}`;
}

export function PlatformAiPolicyStudio() {
  const client = useQueryClient();
  const [provider, setProvider] = React.useState('ALL');
  const [rollout, setRollout] = React.useState('ALL');
  const [selection, setSelection] = React.useState('ALL');
  const [owasp, setOwasp] = React.useState('ALL');
  const [query, setQuery] = React.useState('');
  const [activePolicyId, setActivePolicyId] = React.useState<string | null>(null);
  const catalog = useQuery({ queryKey: ['platform-ai-grid-policies'], queryFn: () => api.listPlatformAiGridPolicies() });
  const shipping = useQuery({ queryKey: ['platform-ai-grid-shipping-status'], queryFn: api.getPlatformAiGridShippingStatus });
  const tenants = useQuery({ queryKey: ['platform-ai-grid-active-tenants'], queryFn: api.listTenants });
  const rollouts = useQuery({ queryKey: ['platform-ai-grid-policy-rollouts'], queryFn: api.listPlatformAiGridPolicyRollouts });
  const invalidateLifecycle = () => void Promise.all([
    client.invalidateQueries({ queryKey: ['platform-ai-grid-policies'] }),
    client.invalidateQueries({ queryKey: ['platform-ai-grid-shipping-status'] }),
    client.invalidateQueries({ queryKey: ['platform-ai-grid-policy-rollouts'] }),
  ]);
  const approve = useMutation({
    mutationFn: api.approvePlatformAiGridPolicy,
    onSuccess: () => void Promise.all([
      client.invalidateQueries({ queryKey: ['platform-ai-grid-policies'] }),
      client.invalidateQueries({ queryKey: ['platform-ai-grid-shipping-status'] }),
    ]),
  });
  const publish = useMutation({
    mutationFn: ({ policyId, targetTenantIds }: { policyId: string; targetTenantIds: string[] }) => api.publishPlatformAiGridPolicy(policyId, targetTenantIds),
    onSuccess: invalidateLifecycle,
  });
  const deprecate = useMutation({
    mutationFn: ({ policyId, reason }: { policyId: string; reason: string }) => api.deprecatePlatformAiGridPolicy(policyId, reason),
    onSuccess: invalidateLifecycle,
  });
  const retry = useMutation({
    mutationFn: api.retryPlatformAiGridPolicyRollout,
    onSuccess: () => void client.invalidateQueries({ queryKey: ['platform-ai-grid-policy-rollouts'] }),
  });
  const policies = React.useMemo(() => (catalog.data ?? []).filter((item) => {
    const searchable = `${item.name} ${item.policyId} ${item.provider} ${owaspMappings(item.frameworkMappingsJson)}`.toLowerCase();
    return (provider === 'ALL' || item.provider === provider)
      && (rollout === 'ALL' || item.rolloutStage === rollout)
      && (selection === 'ALL' || item.defaultSelection === selection)
      && (owasp === 'ALL' || owaspMappings(item.frameworkMappingsJson).includes(owasp))
      && (query.trim() === '' || searchable.includes(query.trim().toLowerCase()));
  }), [catalog.data, owasp, provider, query, rollout, selection]);
  const activePolicy = (catalog.data ?? []).find((policy) => policy.policyId === activePolicyId) ?? null;
  const activeTenantIds = (tenants.data ?? []).filter((tenant) => tenant.status === 'ACTIVE').map((tenant) => tenant.id);
  const hasFilters = provider !== 'ALL' || rollout !== 'ALL' || selection !== 'ALL' || owasp !== 'ALL' || query.trim() !== '';

  return <section className="platform-ai-policy-studio">
      <header className="ai-security-hero policies policy-studio-hero"><div>
      <span className="ai-security-kicker">Tenant Management / Policies</span><h2>Policy distribution</h2>
      <p>Ship a governed catalog, make tenant defaults clear, and stage rollout changes from one workspace.</p>
    </div><div className={shipping.data?.blockers.length ? 'policy-shipping-state policy-shipping-state--blocked' : 'policy-shipping-state'}>
      <span>{shipping.data?.blockers.length ? 'Action needed' : 'Catalog healthy'}</span>
      <strong>{shipping.data?.blockers.length ? `${shipping.data.blockers.length} blocker${shipping.data.blockers.length === 1 ? '' : 's'}` : 'Ready to ship'}</strong>
    </div></header>
    <ShippingSummary status={shipping.data} />
    {shipping.data?.blockers.length ? <p className="notice error">{shipping.data.blockers.join(' · ')}</p> : null}

    <section className="panel policy-catalog-panel">
      <div className="panel-header policy-catalog-header"><div><h3>Policy catalog</h3><p className="panel-caption">Approve a validated policy, publish it to an explicit tenant canary cohort, or deprecate it through its policy-ID lifecycle.</p></div>
        <span className="policy-results-count">{policies.length} of {catalog.data?.length ?? 0} policies</span></div>
      <div className="policy-filter-bar" aria-label="Policy catalog filters">
        <label className="policy-search"><span>Find policy</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name, ID, provider, or OWASP mapping" /></label>
        <label>Provider <select value={provider} onChange={(event) => setProvider(event.target.value)}><option value="ALL">All providers</option><option value="AWS">AWS</option><option value="AZURE">Azure</option><option value="MULTI_CLOUD">Multi-cloud</option></select></label>
        <label>Rollout <select value={rollout} onChange={(event) => setRollout(event.target.value)}><option value="ALL">All stages</option>{ROLLOUTS.map((value) => <option key={value} value={value}>{rolloutLabel(value)}</option>)}</select></label>
        <label>Default <select value={selection} onChange={(event) => setSelection(event.target.value)}><option value="ALL">All defaults</option>{DEFAULTS.map((value) => <option key={value}>{value}</option>)}</select></label>
        <label>OWASP <select value={owasp} onChange={(event) => setOwasp(event.target.value)}><option value="ALL">All mappings</option>{Array.from({ length: 10 }, (_, index) => `LLM${String(index + 1).padStart(2, '0')}`).map((value) => <option key={value}>{value}</option>)}</select></label>
        {hasFilters ? <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setProvider('ALL'); setRollout('ALL'); setSelection('ALL'); setOwasp('ALL'); setQuery(''); }}>Clear filters</button> : null}
      </div>
      {catalog.isLoading ? <p role="status">Loading shipped policies…</p> : null}
      {catalog.isError ? <p className="notice error">The policy catalog could not be loaded.</p> : null}
      <div className="policy-management-layout">
        <div className="table-scroll policy-catalog-table"><table className="data-table"><thead><tr><th>Policy</th><th>Framework mapping</th><th>Availability</th><th>Tenant default</th><th>Rollout</th><th aria-label="Actions" /></tr></thead>
          <tbody>{policies.length === 0 ? <tr><td colSpan={6} className="policy-empty-cell">No policies match the selected filters.</td></tr> : policies.map((policy) => <tr key={policy.policyId} className={activePolicyId === policy.policyId ? 'policy-catalog-row active' : 'policy-catalog-row'}>
            <td><strong>{policy.name}</strong><br /><small>{policy.policyId} · {policy.provider} · {policy.severity}</small></td>
            <td>{owaspMappings(policy.frameworkMappingsJson)}</td><td><span className={statusClass(policy.available ? 'available' : 'unavailable')}>{policy.available ? 'Available' : 'Unavailable'}</span></td>
            <td><span className={statusClass(policy.defaultSelection)}>{policy.defaultSelection}</span></td><td><span className={statusClass(policy.rolloutStage)}>{rolloutLabel(policy.rolloutStage)}</span></td>
            <td><button type="button" className="btn btn-secondary btn-sm" aria-label={`Manage ${policy.name}`} onClick={() => setActivePolicyId(policy.policyId)}>Manage</button></td>
          </tr>)}</tbody></table></div>
        <PolicyConfigurationPanel key={activePolicy?.policyId ?? 'empty'} policy={activePolicy} tenantIds={activeTenantIds}
          saving={approve.isPending || publish.isPending || deprecate.isPending}
          onClose={() => setActivePolicyId(null)} onApprove={(policy) => approve.mutate(policy.policyId)}
          onPublish={(policy, targetTenantIds) => publish.mutate({ policyId: policy.policyId, targetTenantIds })}
          onDeprecate={(policy, reason) => deprecate.mutate({ policyId: policy.policyId, reason })} />
      </div>
    </section>

    <section className="panel policy-rollout-panel"><div className="panel-header"><div><h3>Canary rollout queue</h3><p className="panel-caption">Each canary rollout is created by one policy approval and carries its exact digest and release-decision binding.</p></div><span className="policy-results-count">{rollouts.data?.filter((item) => item.status !== 'COMPLETED' && item.status !== 'CANCELED').length ?? 0} active</span></div>
      <div className="table-scroll"><table className="data-table"><thead><tr><th>Policy</th><th>Approved digest</th><th>Decision</th><th>State</th><th>Created</th><th>Action</th></tr></thead><tbody>
        {rollouts.isLoading ? <tr><td colSpan={6}>Loading rollout jobs…</td></tr> : (rollouts.data ?? []).length === 0 ? <tr><td colSpan={6}>No rollout jobs are waiting.</td></tr> : (rollouts.data ?? []).map((item) => <tr key={item.id}><td><strong>{item.policyId}</strong></td><td className="mono">{item.approvedDigest ?? '—'}</td><td className="mono">{item.releaseDecisionId ?? '—'}</td><td><span className={statusClass(item.status)}>{item.status}</span></td><td>{new Date(item.createdAt).toLocaleString()}</td><td><button type="button" className="btn btn-secondary btn-sm" onClick={() => retry.mutate(item.id)} disabled={retry.isPending || item.status === 'COMPLETED' || item.status === 'CANCELED'}>{item.status === 'COMPLETED' ? 'Complete' : item.status === 'CANCELED' ? 'Canceled' : 'Retry'}</button></td></tr>)}
      </tbody></table></div>
    </section>
  </section>;
}

function ShippingSummary({ status }: { status?: { expectedPolicies: number; installedPolicies: number; publishedPolicies: number; distributedPolicies: number; digestMatchedPolicies: number; rolloutPendingTenants: number } }) {
  const value = (key: keyof NonNullable<typeof status>) => status ? status[key] : '—';
  return <section className="summary-strip policy-shipping-summary" aria-label="Shipping summary"><span><strong>{value('expectedPolicies')}</strong> catalog packages</span><span><strong>{value('installedPolicies')}</strong> installed</span><span><strong>{value('publishedPolicies')}</strong> published</span><span><strong>{value('distributedPolicies')}</strong> distributed</span><span><strong>{value('digestMatchedPolicies')}</strong> digest verified</span><span><strong>{value('rolloutPendingTenants')}</strong> tenant jobs pending</span></section>;
}

function PolicyConfigurationPanel({ policy, tenantIds, saving, onClose, onApprove, onPublish, onDeprecate }: { policy: AiGridPolicyDistribution | null; tenantIds: string[]; saving: boolean; onClose: () => void; onApprove: (policy: AiGridPolicyDistribution) => void; onPublish: (policy: AiGridPolicyDistribution, targetTenantIds: string[]) => void; onDeprecate: (policy: AiGridPolicyDistribution, reason: string) => void }) {
  const [cohort, setCohort] = React.useState<string[]>([]);
  const [deprecationReason, setDeprecationReason] = React.useState('');
  const detail = useQuery({ queryKey: ['platform-ai-grid-policy-detail', policy?.policyId, policy?.version], queryFn: () => api.getPlatformAiGridPolicyDetail(policy!.policyId, policy!.version), enabled: policy != null });
  if (!policy) return <aside className="policy-configuration-empty"><span className="ai-security-kicker">Lifecycle</span><h4>Select a policy</h4><p>Choose <strong>Manage</strong> beside a policy to approve, publish to a canary cohort, or deprecate it.</p></aside>;
  return <aside className="policy-configuration-panel" aria-label={`${policy.name} configuration`}><div className="policy-configuration-heading"><div><span className="ai-security-kicker">Configuration</span><h4>{policy.name}</h4><p>{policy.policyId}</p></div><button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>Close</button></div>
    <div className="policy-detail-summary"><span className={statusClass(policy.severity)}>{policy.severity}</span><span>{detail.data?.description ?? 'Loading policy intent…'}</span></div>
    <div className="policy-config-fields"><label>Canary tenants<select multiple value={cohort} aria-label={`${policy.policyId} canary tenants`} onChange={(event) => setCohort(Array.from(event.target.selectedOptions, (option) => option.value))}>{tenantIds.map((id) => <option key={id} value={id}>{id}</option>)}</select><small>Choose one or more active tenants. Publishing never targets only the Default Workspace unless a caller intentionally uses the no-body API fallback.</small></label>
      <label>Deprecation reason<input value={deprecationReason} onChange={(event) => setDeprecationReason(event.target.value)} placeholder="Why this policy is being retired" /></label>
    </div>
    {cohort.length === 0 ? <p className="notice error">Choose at least one tenant before publishing a canary.</p> : null}
    <div className="button-row"><button type="button" className="btn btn-secondary" disabled={saving || policy.lifecycle !== 'VALIDATED'} onClick={() => onApprove(policy)}>{saving ? 'Working…' : 'Approve policy'}</button><button type="button" className="btn btn-primary" disabled={saving || policy.lifecycle !== 'APPROVED' || cohort.length === 0} onClick={() => onPublish(policy, cohort)}>{saving ? 'Working…' : 'Publish canary'}</button><button type="button" className="btn btn-secondary" disabled={saving || policy.lifecycle === 'DEPRECATED' || deprecationReason.trim() === ''} onClick={() => onDeprecate(policy, deprecationReason.trim())}>{saving ? 'Working…' : 'Deprecate policy'}</button></div>
    <details className="policy-technical-details"><summary>Policy implementation details</summary><dl><dt>Control objective</dt><dd>{detail.data?.controlObjectiveId ?? policy.controlObjectiveId ?? '—'}</dd><dt>Evaluation mode</dt><dd>{detail.data?.evaluationMode ?? policy.evaluationMode ?? '—'}</dd><dt>Source</dt><dd>{detail.data?.packageSourceRef ?? 'Loading…'}</dd></dl></details>
  </aside>;
}
