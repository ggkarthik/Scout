import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { PageFreshnessStatus } from '../components/PageFreshnessStatus';
import { AI_ARTIFACT_CATEGORIES, combinedNativeKindFilterValue, stripProviderPrefix } from '../features/ai-security/categories';
import { ProviderLogo } from '../features/ai-security/ProviderLogo';
import { FindingSeverityChips } from '../features/findings/components/FindingSeverityChips';
import { InventoryShell } from '../features/inventory/InventoryShell';
import { pathForInventoryAiAsset, pathForInventoryView } from '../app/routes';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../lib/polling';

const ALL_KIND = 'ALL';
const CATEGORIZED_NATIVE_KINDS = new Set(AI_ARTIFACT_CATEGORIES.flatMap((category) => category.nativeKinds));

function shouldPollAiRuns(runs: Array<{ status: string }> | undefined): boolean {
  return (runs ?? []).some((run) => {
    const status = run.status.trim().toUpperCase();
    return status === 'RUNNING' || status === 'STARTED' || status === 'QUEUED';
  });
}

export function AiInventoryAssetsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const [nativeKind, setNativeKind] = React.useState<string>(searchParams.get('nativeKind') ?? ALL_KIND);
  const [severity, setSeverity] = React.useState<string | undefined>(searchParams.get('severity') ?? undefined);
  const [provider, setProvider] = React.useState<'' | 'AWS' | 'AZURE'>(
    searchParams.get('provider') === 'AWS' || searchParams.get('provider') === 'AZURE'
      ? (searchParams.get('provider') as 'AWS' | 'AZURE')
      : '',
  );
  const [subscription, setSubscription] = React.useState('');
  const deferredSubscription = React.useDeferredValue(subscription.trim());

  const runsQuery = useQuery({
    queryKey: ['ai-security-runs'],
    queryFn: () => api.listAiSecurityRuns(),
    refetchInterval: (query) => shouldPollAiRuns(query.state.data as Array<{ status: string }> | undefined)
      ? RUN_QUEUE_REFRESH_INTERVAL_MS
      : false,
  });
  const shouldPoll = shouldPollAiRuns(runsQuery.data);
  const artifactsQuery = useQuery({
    queryKey: ['ai-artifact-summaries', nativeKind, provider, deferredSubscription, severity],
    queryFn: () => api.listAiArtifactSummaries(
      undefined,
      0,
      100,
      provider || undefined,
      deferredSubscription || undefined,
      nativeKind === ALL_KIND ? undefined : nativeKind,
      severity,
    ),
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const summaryQuery = useQuery({
    queryKey: ['ai-security-summary'],
    queryFn: api.getAiSecuritySummary,
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });

  const items = artifactsQuery.data?.items ?? [];
  const summary = summaryQuery.data;
  const totalArtifacts = Object.values(summary?.artifactCounts ?? {}).reduce((total, count) => total + count, 0);
  const nativeKindCounts = summary?.nativeKindCounts ?? {};
  const categoryOptions = AI_ARTIFACT_CATEGORIES.map((category) => ({
    key: combinedNativeKindFilterValue(category.nativeKinds),
    label: category.label,
    count: category.nativeKinds.reduce((total, kind) => total + (nativeKindCounts[kind] ?? 0), 0),
  }));
  const remainingKindOptions = Object.entries(nativeKindCounts)
    .filter(([kind]) => !CATEGORIZED_NATIVE_KINDS.has(kind))
    .sort(([, a], [, b]) => b - a)
    .map(([kind, count]) => ({ key: kind, label: stripProviderPrefix(kind), count }));

  return (
    <InventoryShell
      eyebrow="AWS and Azure AI estate"
      title="AI Asset Inventory"
      description="Every discovered AI artifact across AWS and Azure, filterable by kind, provider, and severity."
      legacyClassName="ai-security-page"
      actions={(
        <button type="button" className="btn btn-secondary" onClick={() => navigate(pathForInventoryView('ai'))}>
          View dashboard
        </button>
      )}
    >
      <PageFreshnessStatus updatedAt={summary?.lastCompleteSnapshotAt} />

      <div className="inventory-fpl-toolbar">
        <label className="findings-filter-chip">
          <span className="panel-caption">Artifact kind</span>
          <select value={nativeKind} onChange={(event) => setNativeKind(event.target.value)} aria-label="Artifact kind">
            <option value={ALL_KIND}>All AI Assets ({totalArtifacts.toLocaleString()})</option>
            {categoryOptions.map((option) => (
              <option key={option.key} value={option.key}>{option.label} ({option.count.toLocaleString()})</option>
            ))}
            {remainingKindOptions.map((option) => (
              <option key={option.key} value={option.key}>{option.label} ({option.count.toLocaleString()})</option>
            ))}
          </select>
        </label>
        <label className="findings-filter-chip">
          <span className="panel-caption">Provider</span>
          <select value={provider} onChange={(event) => setProvider(event.target.value as '' | 'AWS' | 'AZURE')} aria-label="Cloud provider">
            <option value="">All providers</option>
            <option value="AWS">AWS</option>
            <option value="AZURE">Azure</option>
          </select>
        </label>
        <label className="findings-filter-chip inventory-fpl-search">
          <span className="panel-caption">Azure subscription</span>
          <input
            type="search"
            value={subscription}
            placeholder="Filter subscription ID"
            aria-label="Azure subscription"
            onChange={(event) => setSubscription(event.target.value)}
          />
        </label>
        {severity ? (
          <div className="fpl-active-chips">
            <span className="fpl-chip">
              Severity: {severity}
              <button type="button" onClick={() => setSeverity(undefined)} aria-label="Clear severity filter">×</button>
            </span>
          </div>
        ) : null}
        <button
          type="button"
          className="btn btn-secondary inventory-refresh-btn"
          onClick={() => {
            void artifactsQuery.refetch();
            void summaryQuery.refetch();
          }}
        >
          Refresh
        </button>
      </div>

      {artifactsQuery.isLoading ? (
        <section className="panel"><div className="empty-state"><p>Loading AI inventory…</p></div></section>
      ) : artifactsQuery.isError ? (
        <section className="panel"><div className="notice error">AI inventory could not be loaded.</div></section>
      ) : items.length === 0 ? (
        <section className="ai-security-empty">
          <div className="ai-security-empty-mark">AI</div>
          <h3>No AI assets discovered</h3>
          <p>Connect an AWS or Azure account and run AI discovery. Empty inventory never hides this workspace.</p>
          <button className="btn btn-primary" type="button" onClick={() => navigate('/connect/connectors')}>
            Configure AI connector
          </button>
        </section>
      ) : (
        <section className="panel ai-security-table-panel">
          <div className="panel-header">
            <div><h3>AI asset inventory</h3><p className="panel-caption">{items.length.toLocaleString()} of {totalArtifacts.toLocaleString()} assets shown</p></div>
          </div>
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Native type</th><th>Provider</th><th>Account / Region</th><th>Findings</th><th>Policies (Failed/Total)</th></tr>
            </thead>
            <tbody>
              {items.map((artifact) => {
                const otherFindings = Math.max(0, artifact.totalFindings - artifact.criticalFindings - artifact.highFindings);
                return (
                  <tr
                    key={artifact.id}
                    onClick={() => navigate(pathForInventoryAiAsset(artifact.id, `${location.pathname}${location.search}`))}
                  >
                    <td><strong>{artifact.name}</strong></td>
                    <td>{stripProviderPrefix(artifact.nativeKind)}</td>
                    <td><ProviderLogo provider={artifact.provider} /></td>
                    <td>{artifact.accountId}<small>{artifact.region}</small></td>
                    <td>
                      <FindingSeverityChips critical={artifact.criticalFindings} high={artifact.highFindings} other={otherFindings} />
                    </td>
                    <td><strong>{artifact.policiesFailed.toLocaleString()}/{artifact.policiesTotal.toLocaleString()}</strong></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}
    </InventoryShell>
  );
}
