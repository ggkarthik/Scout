import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { GithubAdvisoryResponse, GithubAdvisorySyncStatusResponse } from '../connect/types';
import './github-advisory-status.css';

type Props = {
  sourceId?: string;
};

export function GithubAdvisoryStatus({ sourceId }: Props) {
  const syncStatusQuery = useQuery({
    queryKey: ['github-advisory-sync-status'],
    queryFn: () => api.getGithubAdvisorySyncStatus(),
    refetchInterval: 60000
  });

  const advisoriesQuery = useQuery({
    queryKey: ['github-advisories-for-source', sourceId],
    queryFn: () => sourceId ? api.getAdvisoriesForSource(sourceId, true) : Promise.resolve([]),
    enabled: !!sourceId,
    refetchInterval: 300000
  });

  if (syncStatusQuery.isPending) {
    return <div className="advisory-status advisory-status--loading">Loading GHSA status...</div>;
  }

  if (syncStatusQuery.isError) {
    return <div className="advisory-status advisory-status--error">Failed to load advisory status</div>;
  }

  const syncStatus = syncStatusQuery.data;
  const advisories = advisoriesQuery.data ?? [];

  return (
    <div className="advisory-status">
      <div className="advisory-status__header">
        <h3>GitHub Security Advisories</h3>
        <div className={`status-badge status-badge--${syncStatus.status.toLowerCase()}`}>
          {syncStatus.status}
        </div>
      </div>

      <div className="advisory-status__stats">
        <div className="stat">
          <span className="stat__label">Cached:</span>
          <span className="stat__value">{syncStatus.advisoriesCached.toLocaleString()}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Affected Repos:</span>
          <span className="stat__value">{syncStatus.affectedRepositories}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Last Sync:</span>
          <span className="stat__value">{formatTime(syncStatus.lastSyncAt)}</span>
        </div>
      </div>

      {advisories.length > 0 && (
        <div className="advisory-status__findings">
          <h4>{advisories.length} Security Advisories Found</h4>
          <ul className="advisory-list">
            {advisories.map((advisory) => (
              <li key={advisory.ghsaId} className={`advisory-item advisory-item--${advisory.severity.toLowerCase()}`}>
                <div className="advisory-item__header">
                  <code className="advisory-id">{advisory.ghsaId}</code>
                  {advisory.cveId && <code className="advisory-cve">{advisory.cveId}</code>}
                  <span className={`severity-badge severity-badge--${advisory.severity.toLowerCase()}`}>
                    {advisory.severity}
                  </span>
                </div>
                <div className="advisory-item__title">{advisory.title}</div>
                <div className="advisory-item__package">
                  {advisory.packageName}@{advisory.affectedVersionsStart}
                </div>
                {advisory.upgradeAvailable && advisory.recommendedFixedVersion && (
                  <div className="advisory-item__fix">
                    ✓ Upgrade to {advisory.recommendedFixedVersion}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {!advisories.length && sourceId && (
        <div className="advisory-status__empty">
          No vulnerabilities found in this repository's components.
        </div>
      )}

      {syncStatus.lastError && (
        <div className="advisory-status__error">
          ⚠ Last error: {syncStatus.lastError}
        </div>
      )}
    </div>
  );
}

function formatTime(instant: string): string {
  const date = new Date(instant);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 365) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}
