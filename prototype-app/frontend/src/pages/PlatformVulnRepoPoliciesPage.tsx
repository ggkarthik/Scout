import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Navigate } from 'react-router-dom';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import { canAccessPlatformConsole } from '../features/auth/roles';
import type { AiGridPlatformPolicyDetail, AiGridPolicyDistribution } from '../features/ai-security/types';

const PROVIDERS = ['ALL', 'AWS', 'AZURE', 'MULTI_CLOUD'];
const LIFECYCLES = ['ALL', 'VALIDATED', 'PUBLISHED', 'RETIRED'];

export function PlatformVulnRepoPoliciesPage() {
  const actor = useActor();
  const [provider, setProvider] = React.useState('ALL');
  const [lifecycle, setLifecycle] = React.useState('ALL');
  const [search, setSearch] = React.useState('');
  const [expanded, setExpanded] = React.useState<Set<string>>(() => new Set());
  const catalogQuery = useQuery({
    queryKey: ['platform-vuln-repo-ai-policies'],
    // The platform catalog is the source of truth. Do not filter by release family here:
    // platform owners must see the complete governed catalog, including legacy and retired
    // definitions that remain relevant for migration/audit review.
    queryFn: () => api.listPlatformAiGridPolicies(),
    enabled: Boolean(actor?.platformScope && canAccessPlatformConsole(actor)),
  });

  if (!actor?.platformScope || !canAccessPlatformConsole(actor)) {
    return <Navigate to="/vuln-repo" replace />;
  }

  const policies = (catalogQuery.data ?? []).filter((policy) => {
    const query = search.trim().toLowerCase();
    return (provider === 'ALL' || policy.provider === provider)
      && (lifecycle === 'ALL' || policy.lifecycle === lifecycle)
      && (!query || policy.policyId.toLowerCase().includes(query) || policy.name.toLowerCase().includes(query));
  });

  const toggleExpanded = (policy: AiGridPolicyDistribution) => {
    const key = `${policy.policyId}@${policy.version}`;
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  return (
    <div className="ai-security-page platform-vuln-repo-policies-page">
      <section className="ai-security-hero policies">
        <div>
          <span className="ai-security-kicker">Platform-owned catalog · tenant data excluded</span>
          <h2>AI Policies</h2>
          <p>Governed policy definitions and release metadata visible to Platform Owners. This view does not load tenant findings, assets, coverage, or tenant policy selections.</p>
        </div>
      </section>

      <section className="panel" aria-label="Platform policy catalog summary">
        <div className="summary-strip">
          <span><strong>{catalogQuery.data?.length ?? 0}</strong> policies</span>
          <span><strong>{catalogQuery.data?.filter((policy) => policy.provider === 'AWS').length ?? 0}</strong> AWS</span>
          <span><strong>{catalogQuery.data?.filter((policy) => policy.provider === 'AZURE').length ?? 0}</strong> Azure</span>
          <span><strong>{catalogQuery.data?.filter((policy) => policy.provider === 'MULTI_CLOUD').length ?? 0}</strong> multi-resource</span>
        </div>
      </section>

      <div className="connect-filter-bar connect-filter-bar--standalone" aria-label="Platform policy filters">
        <label htmlFor="platform-policy-provider">Provider</label>
        <select id="platform-policy-provider" value={provider} onChange={(event) => setProvider(event.target.value)}>
          {PROVIDERS.map((option) => <option key={option} value={option}>{option === 'ALL' ? 'All providers' : option === 'MULTI_CLOUD' ? 'Multi-resource' : option}</option>)}
        </select>
        <label htmlFor="platform-policy-lifecycle">Lifecycle</label>
        <select id="platform-policy-lifecycle" value={lifecycle} onChange={(event) => setLifecycle(event.target.value)}>
          {LIFECYCLES.map((option) => <option key={option} value={option}>{option === 'ALL' ? 'All lifecycles' : option}</option>)}
        </select>
        <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search policy ID or name" aria-label="Search platform policies" />
      </div>

      {catalogQuery.isLoading ? <section className="panel"><div className="empty-state"><p>Loading platform policy catalog…</p></div></section> : null}
      {catalogQuery.isError ? <section className="panel"><div className="notice error">The platform-owned AI policy catalog could not be loaded.</div></section> : null}
      {!catalogQuery.isLoading && !catalogQuery.isError ? (
        <section className="panel ai-security-table-panel" aria-label="Platform-owned AI policy catalog">
          <table className="data-table">
            <thead><tr><th aria-label="Expand" /><th>Policy</th><th>Provider</th><th>Version</th><th>Severity</th><th>Lifecycle</th><th>Control objective</th><th>Default</th><th>Rollout</th><th>Availability</th></tr></thead>
            <tbody>
              {policies.map((policy) => <PlatformPolicyRow key={`${policy.policyId}@${policy.version}`} policy={policy} expanded={expanded.has(`${policy.policyId}@${policy.version}`)} onToggle={() => toggleExpanded(policy)} />)}
            </tbody>
          </table>
          {policies.length === 0 ? <div className="empty-state"><p>No platform policies match the current filters.</p></div> : null}
        </section>
      ) : null}
    </div>
  );
}

function PlatformPolicyRow({ policy, expanded, onToggle }: { policy: AiGridPolicyDistribution; expanded: boolean; onToggle: () => void }) {
  const detailQuery = useQuery({
    queryKey: ['platform-vuln-repo-ai-policy-detail', policy.policyId, policy.version],
    queryFn: () => api.getPlatformAiGridPolicyDetail(policy.policyId, policy.version),
    enabled: expanded,
  });
  return <>
    <tr>
      <td><button type="button" className="ai-policy-expand" aria-label={`${expanded ? 'Collapse' : 'Expand'} ${policy.name}`} aria-expanded={expanded} onClick={onToggle}>{expanded ? '▾' : '▸'}</button></td>
      <td><strong>{policy.name}</strong><br /><small>{policy.policyId}</small></td>
      <td>{policy.provider === 'MULTI_CLOUD' ? 'Multi-resource' : policy.provider}</td>
      <td>{policy.version}</td>
      <td>{policy.severity}</td>
      <td>{policy.lifecycle}</td>
      <td>{policy.controlObjectiveId ?? '—'}</td>
      <td>{policy.defaultSelection}</td>
      <td>{policy.rolloutStage}</td>
      <td>{policy.available ? 'Available' : 'Unavailable'}</td>
    </tr>
    {expanded ? <tr className="ai-policy-detail-row"><td /><td colSpan={9}><PlatformPolicyMetadata detail={detailQuery.data} loading={detailQuery.isLoading} failed={detailQuery.isError} /></td></tr> : null}
  </>;
}

function PlatformPolicyMetadata({ detail, loading, failed }: { detail?: AiGridPlatformPolicyDetail; loading: boolean; failed: boolean }) {
  if (loading) return <p>Loading policy metadata…</p>;
  if (failed || !detail) return <p className="notice error">Policy metadata could not be loaded.</p>;
  return <section aria-label={`${detail.policyId} metadata`}>
    <p><strong>{detail.controlObjectiveId}</strong>{detail.objectiveName ? ` · ${detail.objectiveName}` : ''}</p>
    <p>{detail.description}</p>
    <dl className="ai-policy-detail-grid">
      <div><dt>Security intent</dt><dd>{detail.securityIntent ?? '—'}</dd></div>
      <div><dt>Remediation intent</dt><dd>{detail.remediationIntent ?? '—'}</dd></div>
      <div><dt>Evaluation mode</dt><dd>{detail.evaluationMode}</dd></div>
      <div><dt>Release</dt><dd>{detail.releaseFamily} · {detail.releaseWave}</dd></div>
      <div><dt>Evidence tiers</dt><dd>{jsonLabel(detail.baseEvidenceTiers)}</dd></div>
      <div><dt>Capabilities</dt><dd>{jsonLabel(detail.requiredCapabilities)}</dd></div>
      <div><dt>Conditional capabilities</dt><dd>{jsonLabel(detail.conditionalCapabilities)}</dd></div>
      <div><dt>Resource families</dt><dd>{jsonLabel(detail.requiredResourceFamilies)}</dd></div>
      <div><dt>Native kinds</dt><dd>{jsonLabel(detail.nativeKinds)}</dd></div>
      <div><dt>Package digest</dt><dd><code>{detail.packageDigest}</code></dd></div>
      <div><dt>Package source</dt><dd><code>{detail.packageSourceRef}</code></dd></div>
      <div><dt>Certification profile</dt><dd>{jsonLabel(detail.certificationParameterProfile)}</dd></div>
    </dl>
    <details><summary>View evidence, evaluation, relationships, and framework metadata</summary><pre>{JSON.stringify({ requiredFacts: detail.requiredFacts, requiredRelationships: detail.requiredRelationships, evaluationDefinition: detail.evaluationDefinition, frameworkMappings: detail.frameworkMappings }, null, 2)}</pre></details>
  </section>;
}

function jsonLabel(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (Array.isArray(value) && value.length === 0) return '—';
  return typeof value === 'string' ? value : JSON.stringify(value);
}
