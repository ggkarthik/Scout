import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { pathForAiFindingDetail } from '../app/routes';
import { timeAgo } from '../lib/time';

export function AiFindingsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const policyId = searchParams.get('policyId') ?? undefined;
  const [status, setStatus] = React.useState('OPEN');
  const [provider, setProvider] = React.useState<'' | 'AWS' | 'AZURE'>('');
  const [subscription, setSubscription] = React.useState('');
  const deferredSubscription = React.useDeferredValue(subscription.trim());
  const findingsQuery = useQuery({
    queryKey: ['ai-security-findings', policyId, status, provider, deferredSubscription],
    queryFn: () => api.listAiSecurityFindings(
      policyId,
      status || undefined,
      0,
      100,
      provider || undefined,
      deferredSubscription || undefined,
    ),
  });

  const items = findingsQuery.data?.items ?? [];
  return (
    <div className="ai-security-page">
      <section className="ai-security-hero findings">
        <div>
          <span className="ai-security-kicker">Configuration evidence, separate from CVEs</span>
          <h2>AI Findings</h2>
          <p>Deterministic policy failures from complete AWS and Azure evidence scopes.</p>
          <Link className="btn btn-secondary" to="/findings/ai/exposures">View AI exposure paths</Link>
        </div>
        <select value={provider} onChange={(event) => setProvider(event.target.value as '' | 'AWS' | 'AZURE')} aria-label="Cloud provider">
          <option value="">All providers</option>
          <option value="AWS">AWS</option>
          <option value="AZURE">Azure</option>
        </select>
        <select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Finding status">
          <option value="OPEN">Open</option>
          <option value="RESOLVED">Resolved</option>
          <option value="SUPPRESSED_BY_POLICY">Suppressed by policy</option>
          <option value="">All states</option>
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

      {findingsQuery.isLoading ? (
        <section className="panel"><div className="empty-state"><p>Loading AI findings…</p></div></section>
      ) : findingsQuery.isError ? (
        <section className="panel"><div className="notice error">AI findings could not be loaded.</div></section>
      ) : items.length === 0 ? (
        <section className="ai-security-empty">
          <div className="ai-security-empty-mark clean">0</div>
          <h3>No matching AI findings</h3>
          <p>Findings appear only when a policy has complete evidence and returns a deterministic failure.</p>
        </section>
      ) : (
        <section className="panel ai-security-table-panel">
          <table className="data-table">
            <thead><tr><th>Finding</th><th>Policy</th><th>Artifact</th><th>State</th><th>Observed</th></tr></thead>
            <tbody>
              {items.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => navigate(pathForAiFindingDetail(finding.id, `${location.pathname}${location.search}`))}
                >
                  <td><span className={`severity-badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span><strong>{finding.displayId}</strong></td>
                  <td>{finding.title}<small>v{finding.policyVersion}</small></td>
                  <td>{finding.artifactName}</td>
                  <td><span className="status-pill">{finding.status.replace(/_/g, ' ')}</span></td>
                  <td>{timeAgo(finding.lastObservedAt) ?? 'Unknown'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
