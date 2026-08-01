import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForInventoryAiAsset } from '../app/routes';
import { timeAgo } from '../lib/time';

type InventoryPill = 'AI_AGENT' | 'AI_MODEL' | 'OTHER_AI_ARTIFACT';

const PILLS: Array<{ key: InventoryPill; label: string }> = [
  { key: 'AI_AGENT', label: 'AI Agents' },
  { key: 'AI_MODEL', label: 'AI Models' },
  { key: 'OTHER_AI_ARTIFACT', label: 'Other AI Artifacts' },
];

export function AiInventoryPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [activePill, setActivePill] = React.useState<InventoryPill>('AI_AGENT');
  const [provider, setProvider] = React.useState<'' | 'AWS' | 'AZURE'>('');
  const [subscription, setSubscription] = React.useState('');
  const deferredSubscription = React.useDeferredValue(subscription.trim());
  const artifactsQuery = useQuery({
    queryKey: ['ai-security-artifacts', activePill, provider, deferredSubscription],
    queryFn: () => api.listAiSecurityArtifacts(
      activePill,
      0,
      100,
      provider || undefined,
      deferredSubscription || undefined,
    ),
  });
  const summaryQuery = useQuery({
    queryKey: ['ai-security-summary'],
    queryFn: api.getAiSecuritySummary,
  });

  const items = artifactsQuery.data?.items ?? [];
  const returnTo = location.pathname + location.search;

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
          <Metric label="Incomplete scopes" value={summaryQuery.data?.incompleteScopes ?? 0} tone="warning" />
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
            <span>{summaryQuery.data?.artifactCounts[pill.key] ?? (pill.key === 'OTHER_AI_ARTIFACT' ? items.length : 0)}</span>
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
          <h3>No {PILLS.find((pill) => pill.key === activePill)?.label.toLowerCase()} discovered</h3>
          <p>Connect an AWS or Azure account and run AI discovery. Empty inventory never hides this workspace.</p>
          <button className="btn btn-primary" type="button" onClick={() => navigate(`/connect/sources?connectSource=${provider === 'AZURE' ? 'ai-security-azure' : 'ai-security-aws'}`)}>
            Configure AI connector
          </button>
        </section>
      ) : (
        <section className="panel ai-security-table-panel">
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Native type</th><th>Account / Region</th><th>Last observed</th><th>State</th><th aria-hidden="true" /></tr>
            </thead>
            <tbody>
              {items.map((artifact) => (
                <tr
                  key={artifact.id}
                  className="ai-security-row-link"
                  tabIndex={0}
                  role="link"
                  onClick={() => navigate(pathForInventoryAiAsset(artifact.id, returnTo))}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      navigate(pathForInventoryAiAsset(artifact.id, returnTo));
                    }
                  }}
                >
                  <td><strong>{artifact.name}</strong><small>{artifact.providerResourceId}</small></td>
                  <td>{artifact.nativeKind.replace(/_/g, ' ')}</td>
                  <td>{artifact.accountId}<small>{artifact.region}</small></td>
                  <td>{timeAgo(artifact.lastObservedAt) ?? 'Unknown'}</td>
                  <td><span className={`status-pill ${artifact.active ? 'success' : 'muted'}`}>{artifact.active ? 'Active' : 'Inactive'}</span></td>
                  <td className="ai-security-row-chevron" aria-hidden="true">→</td>
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
