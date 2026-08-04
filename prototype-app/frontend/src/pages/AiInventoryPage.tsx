import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import type { AiSecurityArtifact } from '../features/ai-security/types';
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
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activePill, setActivePill] = React.useState<InventoryPill>('ALL');
  const [provider, setProvider] = React.useState<'' | 'AWS' | 'AZURE'>('');
  const [subscription, setSubscription] = React.useState('');
  const deferredSubscription = React.useDeferredValue(subscription.trim());
  const [selected, setSelected] = React.useState<AiSecurityArtifact | null>(null);
  const [ownerDraft, setOwnerDraft] = React.useState('');
  const canConfirmOwner = hasRole(actor, 'PLATFORM_OWNER') || hasRole(actor, 'TENANT_ADMIN')
    || hasRole(actor, 'SECURITY_ANALYST');
  React.useEffect(() => setOwnerDraft(selected?.ownerName ?? ''), [selected?.id, selected?.ownerName]);
  const ownerMutation = useMutation({
    mutationFn: () => api.confirmAiGridArtifactOwner(
      selected?.id ?? '',
      ownerDraft,
      'Confirmed from AI inventory',
    ),
    onSuccess: (owner) => {
      setSelected((current) => current?.id === owner.artifactId ? {
        ...current,
        ownerName: owner.ownerName,
        ownerState: owner.ownerState,
        ownerSource: owner.ownerSource,
        ownerConfidence: owner.confidence,
        ownerConfidenceMethod: owner.confidenceMethod,
        ownerConfidenceMethodVersion: owner.confidenceMethodVersion,
      } : current);
      void queryClient.invalidateQueries({ queryKey: ['ai-security-artifacts'] });
      void queryClient.invalidateQueries({ queryKey: ['ai-grid-coverage'] });
    },
  });
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
  const graphQuery = useQuery({
    queryKey: ['ai-security-graph', selected?.id],
    queryFn: () => api.getAiSecurityGraph(selected?.id),
    enabled: selected != null,
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
        <select value={provider} onChange={(event) => { setProvider(event.target.value as '' | 'AWS' | 'AZURE'); setSelected(null); }} aria-label="Cloud provider">
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
            onChange={(event) => {
              setSubscription(event.target.value);
              setSelected(null);
            }}
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
            onClick={() => {
              setActivePill(pill.key);
              setSelected(null);
            }}
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
        <section className="ai-security-split">
          <div className="panel ai-security-table-panel">
            <table className="data-table">
              <thead>
                <tr><th>Name</th><th>Native type</th><th>Owner</th><th>Account / Region</th><th>Last observed</th><th>State</th></tr>
              </thead>
              <tbody>
                {items.map((artifact) => (
                  <tr
                    key={artifact.id}
                    className={selected?.id === artifact.id ? 'selected' : ''}
                    onClick={() => setSelected(artifact)}
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
          </div>
          {selected && (
            <aside className="panel ai-security-detail">
              <span className="ai-security-kicker">{selected.nativeKind.replace(/_/g, ' ')}</span>
              <h3>{selected.name}</h3>
              <dl>
                <dt>Provider ID</dt><dd>{selected.providerResourceId}</dd>
                <dt>Account</dt><dd>{selected.accountId}</dd>
                <dt>Region</dt><dd>{selected.region}</dd>
                <dt>Owner state</dt><dd>{selected.ownerState ?? 'UNOWNED'}</dd>
                <dt>Owner source</dt><dd>{selected.ownerSource ?? 'No owner signal'}</dd>
              </dl>
              {canConfirmOwner && (
                <div className="ai-security-owner-confirmation">
                  <label>
                    <span>Accountable owner</span>
                    <input
                      value={ownerDraft}
                      onChange={(event) => setOwnerDraft(event.target.value)}
                      placeholder="Team or owner"
                      aria-label="Accountable owner"
                    />
                  </label>
                  <button
                    className="btn btn-secondary"
                    type="button"
                    disabled={!ownerDraft.trim() || ownerMutation.isPending}
                    onClick={() => ownerMutation.mutate()}
                  >
                    {ownerMutation.isPending ? 'Confirming…' : 'Confirm owner'}
                  </button>
                  {ownerMutation.isError && <div className="notice error">Owner could not be confirmed.</div>}
                </div>
              )}
              <h4>Observed facts</h4>
              <div className="ai-security-facts">
                {Object.entries(selected.attributes).map(([key, value]) => (
                  <div key={key}><span>{key.replace(/([A-Z_])/g, ' $1')}</span><strong>{formatValue(value)}</strong></div>
                ))}
              </div>
              <h4>Relationships</h4>
              {graphQuery.isLoading ? (
                <p className="panel-caption">Loading connected resources…</p>
              ) : (graphQuery.data?.edges.length ?? 0) === 0 ? (
                <p className="panel-caption">No active relationships observed.</p>
              ) : (
                <div className="ai-security-graph" aria-label="AI artifact relationship graph">
                  {graphQuery.data?.edges.slice(0, 12).map((edge) => (
                    <div className="ai-security-graph-edge" key={edge.id}>
                      <span>{edge.sourceName}</span>
                      <strong>{edge.relationshipType.replace(/_/g, ' ')}</strong>
                      <span>{edge.targetName}</span>
                    </div>
                  ))}
                  {graphQuery.data?.truncated && <small>Graph capped for safe rendering.</small>}
                </div>
              )}
            </aside>
          )}
        </section>
      )}
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className={`ai-security-metric ${tone}`}><strong>{value.toLocaleString()}</strong><span>{label}</span></div>;
}

function formatValue(value: unknown): string {
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`;
  if (typeof value === 'object' && value != null) return JSON.stringify(value);
  return String(value ?? 'Not observed');
}

function shouldPollAiRuns(runs: Array<{ status: string }> | undefined): boolean {
  return (runs ?? []).some((run) => {
    const status = run.status.trim().toUpperCase();
    return status === 'RUNNING' || status === 'STARTED' || status === 'QUEUED';
  });
}
