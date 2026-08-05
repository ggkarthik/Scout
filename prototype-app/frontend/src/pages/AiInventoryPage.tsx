import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForInventoryAiAsset } from '../app/routes';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../lib/polling';
import { timeAgo } from '../lib/time';

type InventoryPill = 'ALL' | 'AI_AGENT' | 'AI_MODEL' | 'OTHER_AI_ARTIFACT';

const PILLS: Array<{ key: InventoryPill; label: string }> = [
  { key: 'ALL', label: 'All AI Assets' },
  { key: 'AI_AGENT', label: 'AI Agents' },
  { key: 'AI_MODEL', label: 'AI Models' },
  { key: 'OTHER_AI_ARTIFACT', label: 'Other AI Artifacts' },
];

function emptyStateTitle(activePill: InventoryPill): string {
  if (activePill === 'ALL') {
    return 'No AI assets discovered';
  }
  return `No ${PILLS.find((pill) => pill.key === activePill)?.label.toLowerCase()} discovered`;
}

export function AiInventoryPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [activePill, setActivePill] = React.useState<InventoryPill>('ALL');
  const [provider, setProvider] = React.useState<'' | 'AWS' | 'AZURE'>('');
  const [subscription, setSubscription] = React.useState('');
  const deferredSubscription = React.useDeferredValue(subscription.trim());
  const runsQuery = useQuery({
    queryKey: ['ai-security-runs'],
    queryFn: () => api.listAiSecurityRuns(),
    refetchInterval: (query) => shouldPollAiRuns(query.state.data as Array<{ status: string }> | undefined)
      ? RUN_QUEUE_REFRESH_INTERVAL_MS
      : false,
  });
  const artifactsQuery = useQuery({
    queryKey: ['ai-security-artifacts', activePill, provider, deferredSubscription],
    queryFn: () => api.listAiSecurityArtifacts(
      activePill === 'ALL' ? undefined : activePill,
      0,
      100,
      provider || undefined,
      deferredSubscription || undefined,
    ),
    refetchInterval: shouldPollAiRuns(runsQuery.data) ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const summaryQuery = useQuery({
    queryKey: ['ai-security-summary'],
    queryFn: api.getAiSecuritySummary,
    refetchInterval: shouldPollAiRuns(runsQuery.data) ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const systemsQuery = useQuery({
    queryKey: ['ai-grid-systems'],
    queryFn: api.listAiGridSystems,
    refetchInterval: shouldPollAiRuns(runsQuery.data) ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const coverageQuery = useQuery({
    queryKey: ['ai-grid-coverage'],
    queryFn: api.getAiGridCoverage,
    refetchInterval: shouldPollAiRuns(runsQuery.data) ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });

  const items = artifactsQuery.data?.items ?? [];
  const totalArtifacts = Object.values(summaryQuery.data?.artifactCounts ?? {})
    .reduce((total, count) => total + count, 0);

  return (
    <div className="ai-security-page">
      <section className="ai-security-hero">
        <div>
          <span className="ai-security-kicker">AWS and Azure AI estate</span>
          <h2>AI Inventory</h2>
          <p>Tenant-scoped agents, referenced models, and supporting AI-native resources.</p>
        </div>
        <div className="ai-security-hero-metrics">
          <Metric label="Open AI findings" value={summaryQuery.data?.openFindings ?? 0} tone="danger" />
          <Metric label="AI systems" value={systemsQuery.data?.length ?? 0} tone="success" />
          <Metric label="Coverage gaps" value={coverageQuery.data?.noDecision ?? summaryQuery.data?.incompleteScopes ?? 0} tone="warning" />
        </div>
        <select value={provider} onChange={(event) => setProvider(event.target.value as '' | 'AWS' | 'AZURE')} aria-label="Cloud provider">
          <option value="">All providers</option>
          <option value="AWS">AWS</option>
          <option value="AZURE">Azure</option>
        </select>
        <label>
          <span className="sr-only">Azure subscription</span>
          <input
            type="search"
            value={subscription}
            placeholder="Filter subscription ID"
            aria-label="Azure subscription"
            onChange={(event) => setSubscription(event.target.value)}
          />
        </label>
      </section>

      {(systemsQuery.data?.length ?? 0) > 0 && (
        <section className="panel ai-security-table-panel">
          <div className="panel-header">
            <div><h3>AI systems</h3><p className="panel-caption">Stable systems derived from evidence-backed artifact relationships.</p></div>
          </div>
          <table className="data-table">
            <thead><tr><th>System</th><th>Members</th><th>Revision</th><th>State</th><th>Updated</th></tr></thead>
            <tbody>{systemsQuery.data?.map((system) => (
              <tr key={system.id}>
                <td><strong>{system.name}</strong><small>{system.id}</small></td>
                <td>{system.memberCount}</td>
                <td>v{system.revision}</td>
                <td><span className="status-pill success">{system.status}</span></td>
                <td>{timeAgo(system.updatedAt) ?? 'Unknown'}</td>
              </tr>
            ))}</tbody>
          </table>
        </section>
      )}

      <div className="ai-security-pill-row" role="tablist" aria-label="AI inventory artifact types">
        {PILLS.map((pill) => (
          <button
            key={pill.key}
            type="button"
            role="tab"
            aria-selected={activePill === pill.key}
            className={`ai-security-pill${activePill === pill.key ? ' active' : ''}`}
            onClick={() => setActivePill(pill.key)}
          >
            {pill.label}
            <span>
              {pill.key === 'ALL'
                ? totalArtifacts
                : summaryQuery.data?.artifactCounts[pill.key]
                  ?? (pill.key === 'OTHER_AI_ARTIFACT' ? items.length : 0)}
            </span>
          </button>
        ))}
      </div>

      {artifactsQuery.isLoading ? (
        <section className="panel"><div className="empty-state"><p>Loading AI inventory…</p></div></section>
      ) : artifactsQuery.isError ? (
        <section className="panel"><div className="notice error">AI inventory could not be loaded.</div></section>
      ) : items.length === 0 ? (
        <section className="ai-security-empty">
          <div className="ai-security-empty-mark">AI</div>
          <h3>{emptyStateTitle(activePill)}</h3>
          <p>Connect an AWS or Azure account and run AI discovery. Empty inventory never hides this workspace.</p>
          <button className="btn btn-primary" type="button" onClick={() => navigate('/connect/connectors')}>
            Configure AI connector
          </button>
        </section>
      ) : (
        <section className="panel ai-security-table-panel">
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Native type</th><th>Owner</th><th>Account / Region</th><th>Last observed</th><th>State</th></tr>
            </thead>
            <tbody>
              {items.map((artifact) => (
                <tr
                  key={artifact.id}
                  onClick={() => navigate(pathForInventoryAiAsset(artifact.id, `${location.pathname}${location.search}`))}
                >
                  <td><strong>{artifact.name}</strong><small>{artifact.providerResourceId}</small></td>
                  <td>{artifact.nativeKind.replace(/_/g, ' ')}</td>
                  <td>{artifact.ownerName ?? 'Unowned'}<small>{artifact.ownerState ?? 'UNOWNED'}</small></td>
                  <td>{artifact.accountId}<small>{artifact.region}</small></td>
                  <td>{timeAgo(artifact.lastObservedAt) ?? 'Unknown'}</td>
                  <td><span className={`status-pill ${artifact.active ? 'success' : 'muted'}`}>{artifact.active ? 'Active' : 'Inactive'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className={`ai-security-metric ${tone}`}><strong>{value.toLocaleString()}</strong><span>{label}</span></div>;
}

function shouldPollAiRuns(runs: Array<{ status: string }> | undefined): boolean {
  return (runs ?? []).some((run) => {
    const status = run.status.trim().toUpperCase();
    return status === 'RUNNING' || status === 'STARTED' || status === 'QUEUED';
  });
}
