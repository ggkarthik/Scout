import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import type { AiSecurityFinding } from '../features/ai-security/types';
import { timeAgo } from '../lib/time';

export function AiFindingsPage() {
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const policyId = searchParams.get('policyId') ?? undefined;
  const [status, setStatus] = React.useState('OPEN');
  const [selected, setSelected] = React.useState<AiSecurityFinding | null>(null);
  const findingsQuery = useQuery({
    queryKey: ['ai-security-findings', policyId, status],
    queryFn: () => api.listAiSecurityFindings(policyId, status || undefined, 0, 100),
  });
  const reviewMutation = useMutation({
    mutationFn: (disposition: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NEEDS_INVESTIGATION') => {
      if (!selected) throw new Error('Select a finding first');
      return api.reviewAiSecurityFinding(selected.id, disposition);
    },
    onSuccess: (finding) => {
      setSelected(finding);
      void queryClient.invalidateQueries({ queryKey: ['ai-security-findings'] });
    },
  });

  const items = findingsQuery.data?.items ?? [];
  return (
    <div className="ai-security-page">
      <section className="ai-security-hero findings">
        <div>
          <span className="ai-security-kicker">Configuration evidence, separate from CVEs</span>
          <h2>AI Findings</h2>
          <p>Deterministic policy failures from complete AWS evidence scopes.</p>
        </div>
        <select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Finding status">
          <option value="OPEN">Open</option>
          <option value="RESOLVED">Resolved</option>
          <option value="SUPPRESSED_BY_POLICY">Suppressed by policy</option>
          <option value="">All states</option>
        </select>
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
        <section className="ai-security-split">
          <div className="panel ai-security-table-panel">
            <table className="data-table">
              <thead><tr><th>Finding</th><th>Policy</th><th>Artifact</th><th>State</th><th>Observed</th></tr></thead>
              <tbody>
                {items.map((finding) => (
                  <tr key={finding.id} onClick={() => setSelected(finding)} className={selected?.id === finding.id ? 'selected' : ''}>
                    <td><span className={`severity-badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span><strong>{finding.displayId}</strong></td>
                    <td>{finding.title}<small>v{finding.policyVersion}</small></td>
                    <td>{finding.artifactName}</td>
                    <td><span className="status-pill">{finding.status.replace(/_/g, ' ')}</span></td>
                    <td>{timeAgo(finding.lastObservedAt) ?? 'Unknown'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {selected && (
            <aside className="panel ai-security-detail">
              <span className={`severity-badge ${selected.severity.toLowerCase()}`}>{selected.severity}</span>
              <h3>{selected.title}</h3>
              <p>{selected.artifactName}</p>
              <h4>Evidence</h4>
              <pre>{JSON.stringify(selected.evidence, null, 2)}</pre>
              <h4>Analyst review</h4>
              <p>Current: <strong>{selected.reviewDisposition.replace(/_/g, ' ')}</strong></p>
              <div className="ai-security-review-actions">
                <button className="btn btn-secondary" onClick={() => reviewMutation.mutate('CONFIRMED')}>Confirm</button>
                <button className="btn btn-secondary" onClick={() => reviewMutation.mutate('NEEDS_INVESTIGATION')}>Investigate</button>
                <button className="btn btn-secondary" onClick={() => reviewMutation.mutate('FALSE_POSITIVE')}>False positive</button>
              </div>
            </aside>
          )}
        </section>
      )}
    </div>
  );
}
