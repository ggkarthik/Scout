import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { pathForInventoryView, pathForVulnRepoHostAsset, pathForVulnRepoSoftwareAssets, pathForVulnRepoView } from '../app/routes';
import { StatCard } from '../components/StatCard';
import { useVulnRepoDashboardQuery } from '../features/vuln-repo-dashboard/queries';
import type {
  VulnRepoDashboardCriticalUnresolvedItem,
  VulnRepoDashboardSeverityBreakdownItem,
} from '../features/vuln-repo-dashboard/types';

function formatNumber(value: number): string {
  return value.toLocaleString();
}

function formatSeverity(value: string): string {
  return value.toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
}

function severityClassName(value: string): string {
  switch (value.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'severity-pill severity-critical';
    case 'HIGH':
      return 'severity-pill severity-high';
    case 'MEDIUM':
      return 'severity-pill severity-medium';
    case 'LOW':
      return 'severity-pill severity-low';
    default:
      return 'severity-pill';
  }
}

function severityBarClassName(value: string): string {
  switch (value.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--critical';
    case 'HIGH':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--high';
    case 'MEDIUM':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--medium';
    case 'LOW':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--low';
    default:
      return 'vuln-repo-inline-bar';
  }
}

function statusClassName(value: string): string {
  const normalized = value.trim().toUpperCase().replace(/[\s-]+/g, '_');
  switch (normalized) {
    case 'OPEN':
    case 'UNRESOLVED':
      return 'status-pill status-open';
    case 'IN_PROGRESS':
      return 'status-pill status-in-progress';
    case 'RESOLVED':
      return 'status-pill status-resolved';
    case 'ACCEPTED_RISK':
      return 'status-pill status-warning';
    default:
      return 'status-pill status-unknown';
  }
}

function relativeTime(value?: string): string {
  if (!value) {
    return 'Recently';
  }
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    return 'Recently';
  }
  const deltaMs = Date.now() - timestamp;
  const days = Math.max(0, Math.floor(deltaMs / (24 * 60 * 60 * 1000)));
  if (days <= 0) {
    return 'Today';
  }
  if (days === 1) {
    return '1 day ago';
  }
  if (days < 7) {
    return `${days} days ago`;
  }
  const weeks = Math.floor(days / 7);
  return `${weeks} week${weeks === 1 ? '' : 's'} ago`;
}

function topCount(items: VulnRepoDashboardSeverityBreakdownItem[]): number {
  return items.reduce((max, item) => Math.max(max, item.count), 0);
}

function renderCriticalUnresolvedTags(item: VulnRepoDashboardCriticalUnresolvedItem) {
  return (
    <div className="vuln-repo-dashboard-item-tags">
      <span className={severityClassName(item.severity)}>{formatSeverity(item.severity)}</span>
      <span className={statusClassName(item.statusLabel)}>{item.statusLabel}</span>
      {item.exploitKnown ? <span className="status-pill status-warning">Exploit</span> : null}
    </div>
  );
}

function advisoryRelativeTimeLabel(value?: string): string {
  return value ? relativeTime(value) : 'Recently';
}

function formatGeneratedAt(value?: string): string | null {
  if (!value) {
    return null;
  }
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    return null;
  }
  return `Last updated ${new Date(timestamp).toLocaleString()}`;
}

function vulnRepoVulnerabilityPath(filters?: Record<string, string | number | boolean | undefined>) {
  const searchParams = new URLSearchParams();
  Object.entries(filters ?? {}).forEach(([key, value]) => {
    if (value == null || value === '') {
      return;
    }
    searchParams.set(key, String(value));
  });
  const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
  return `${pathForVulnRepoView('vulnerabilities')}${suffix}`;
}

function findingsPath(filters?: Record<string, string | number | boolean | undefined>) {
  const searchParams = new URLSearchParams();
  Object.entries(filters ?? {}).forEach(([key, value]) => {
    if (value == null || value === '') {
      return;
    }
    searchParams.set(key, String(value));
  });
  const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
  return `/findings${suffix}`;
}

function vulnRepoTrackedVulnerabilityPath(filters?: Record<string, string | number | boolean | undefined>) {
  return vulnRepoVulnerabilityPath({ includeAll: true, ...(filters ?? {}) });
}

export function VulnRepoDashboardPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const dashboardQuery = useVulnRepoDashboardQuery();
  const [searchValue, setSearchValue] = React.useState('');

  const dashboard = dashboardQuery.data;
  const loading = dashboardQuery.isPending && !dashboard;
  const refreshing = dashboardQuery.isFetching && !!dashboard;
  const error = dashboardQuery.error instanceof Error ? dashboardQuery.error.message : '';
  const severityMax = React.useMemo(
    () => topCount(dashboard?.severityBreakdown ?? []),
    [dashboard?.severityBreakdown]
  );
  const topAffectedSoftware = React.useMemo(
    () =>
      [...(dashboard?.topAffectedSoftware ?? [])]
        .sort(
          (left, right) =>
            right.cveCount - left.cveCount ||
            right.criticalCount - left.criticalCount ||
            right.highCount - left.highCount ||
            left.software.localeCompare(right.software)
        )
        .slice(0, 5),
    [dashboard?.topAffectedSoftware]
  );
  const generatedAtLabel = React.useMemo(
    () => formatGeneratedAt(dashboard?.generatedAt),
    [dashboard?.generatedAt]
  );
  const summaryCards = dashboard ? [
    {
      key: 'tracked',
      title: 'Tracked CVEs',
      value: dashboard.summaryCards.trackedCount,
      caption: 'Repository coverage',
      tone: 'neutral' as const,
      onClick: () => navigate(vulnRepoTrackedVulnerabilityPath()),
    },
    {
      key: 'recent',
      title: 'Added This Week',
      value: dashboard.summaryCards.trackedAddedLastWeek,
      caption: 'New in the last 7 days',
      tone: 'neutral' as const,
      onClick: () => navigate(vulnRepoTrackedVulnerabilityPath({ createdSinceDays: 7 })),
    },
    {
      key: 'critical',
      title: 'Critical Severity',
      value: dashboard.summaryCards.criticalCount,
      caption: 'Immediate action required',
      tone: 'critical' as const,
      onClick: () => navigate(vulnRepoTrackedVulnerabilityPath({ severity: 'CRITICAL' })),
    },
    {
      key: 'exploit',
      title: 'Exploits Available',
      value: dashboard.summaryCards.exploitCount,
      caption: `${dashboard.summaryCards.exploitCoveragePercent}% of tracked CVEs`,
      tone: 'warn' as const,
      onClick: () => navigate(vulnRepoTrackedVulnerabilityPath({ exploitOnly: true })),
    },
  ] : [];

  const handleSearchSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const query = searchValue.trim();
    if (!query) {
      navigate(pathForVulnRepoView('vulnerabilities'));
      return;
    }
    navigate(vulnRepoVulnerabilityPath({ query }));
  };

  return (
    <div className="page-grid vuln-repo-dashboard-page">
      <section className="panel vuln-repo-dashboard-header-panel">
        <div className="panel-header vuln-repo-dashboard-header">
          <div className="vuln-repo-dashboard-header-copy">
            <div>
              <h3>Vulnerability Repository</h3>
              <div className="panel-caption">
                Track repository coverage, review active risk, and jump directly into affected software, advisories, and assets.
              </div>
            </div>
            {generatedAtLabel ? (
              <div className="panel-caption vuln-repo-dashboard-generated-at">
                {refreshing ? 'Refreshing dashboard...' : generatedAtLabel}
              </div>
            ) : null}
          </div>
          <form className="findings-filter-chip vuln-repo-dashboard-search" onSubmit={handleSearchSubmit}>
            <label htmlFor="vuln-repo-dashboard-search-input">Search CVEs</label>
            <input
              id="vuln-repo-dashboard-search-input"
              type="search"
              value={searchValue}
              onChange={(event) => setSearchValue(event.target.value)}
              placeholder="CVE-2024-21762, FortiOS, critical"
            />
          </form>
        </div>
      </section>

      {loading ? <div className="panel"><div className="panel-caption">Loading dashboard...</div></div> : null}
      {!dashboard && !loading && error ? <div className="panel"><div className="notice error">Failed to load dashboard: {error}</div></div> : null}

      {dashboard ? (
        <>
          {error ? <div className="notice error">Using cached dashboard data while refresh failed: {error}</div> : null}

          <div className="stats-grid vuln-repo-dashboard-stats-grid">
            {summaryCards.map((card) => (
              <button
                key={card.key}
                type="button"
                className="vuln-repo-dashboard-stat-button"
                onClick={card.onClick}
              >
                <StatCard title={card.title} value={card.value} tone={card.tone} caption={card.caption} />
              </button>
            ))}
          </div>

          <div className="dashboard-grid vuln-repo-dashboard-main-grid">
            <section className="panel vuln-repo-dashboard-panel">
              <div className="panel-header">
                <div className="vuln-repo-dashboard-section-copy">
                  <h3>Critical unresolved</h3>
                  <div className="panel-caption">Requires immediate attention</div>
                </div>
                <button type="button" className="btn-link" onClick={() => navigate(findingsPath({ status: 'OPEN' }))}>View all</button>
              </div>
              <div className="vuln-repo-dashboard-unresolved-list">
                {dashboard.criticalUnresolved.length === 0 ? (
                  <div className="empty-state">No unresolved CVEs with created findings are available right now.</div>
                ) : (
                  dashboard.criticalUnresolved.map((item) => (
                    <article
                      key={item.externalId}
                      className="vuln-repo-dashboard-unresolved-item"
                    >
                      <div className="vuln-repo-dashboard-unresolved-copy">
                        <button
                          type="button"
                          className="btn-link vuln-repo-dashboard-cve-link mono"
                          onClick={() => navigate(pathForVulnRepoView('org-cves', item.externalId))}
                        >
                          {item.externalId}
                        </button>
                        {renderCriticalUnresolvedTags(item)}
                        <p>{item.title}</p>
                      </div>
                      <button
                        type="button"
                        className="vuln-repo-dashboard-findings-count btn-link"
                        onClick={(event) => {
                          event.stopPropagation();
                          navigate(findingsPath({ vulnerabilityId: item.externalId, status: 'OPEN' }));
                        }}
                      >
                        <strong>{formatNumber(item.findingCount)}</strong>
                        <span>findings</span>
                      </button>
                    </article>
                  ))
                )}
              </div>
            </section>

            <section className="panel vuln-repo-dashboard-panel">
              <div className="panel-header">
                <div className="vuln-repo-dashboard-section-copy">
                  <h3>Risk overview</h3>
                  <div className="panel-caption">Severity distribution and current disposition across tracked CVEs</div>
                </div>
              </div>
              <div className="vuln-repo-dashboard-overview-stack">
                <div className="vuln-repo-dashboard-panel-block">
                  <div className="vuln-repo-dashboard-panel-block-header">
                    <h4>Severity breakdown</h4>
                    <span className="panel-caption">Current tracked vulnerability mix</span>
                  </div>
                  <div className="vuln-repo-dashboard-breakdown-list">
                    {dashboard.severityBreakdown.map((item) => (
                      <div key={item.severity} className="vuln-repo-dashboard-breakdown-row">
                        <span>{formatSeverity(item.severity)}</span>
                        <div className="vuln-repo-dashboard-breakdown-bar">
                          <span
                            className={severityBarClassName(item.severity)}
                            style={{ width: `${severityMax > 0 ? (item.count / severityMax) * 100 : 0}%` }}
                          />
                        </div>
                        <button
                          type="button"
                          className="btn-link vuln-repo-dashboard-count-link"
                          onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({ severity: item.severity }))}
                        >
                          {formatNumber(item.count)}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="vuln-repo-dashboard-panel-block">
                  <div className="vuln-repo-dashboard-panel-block-header">
                    <h4>Resolution status</h4>
                    <span className="panel-caption">Disposition across tracked CVEs</span>
                  </div>
                  <div className="vuln-repo-dashboard-resolution-grid">
                    <div className="vuln-repo-dashboard-resolution-card">
                      <strong>{formatNumber(dashboard.resolutionStatus.unresolvedCount)}</strong>
                      <span>Unresolved</span>
                    </div>
                    <div className="vuln-repo-dashboard-resolution-card vuln-repo-dashboard-resolution-card--success">
                      <strong>{formatNumber(dashboard.resolutionStatus.resolvedCount)}</strong>
                      <span>Resolved</span>
                    </div>
                    <div className="vuln-repo-dashboard-resolution-card vuln-repo-dashboard-resolution-card--info">
                      <strong>{formatNumber(dashboard.resolutionStatus.inProgressCount)}</strong>
                      <span>In progress</span>
                    </div>
                    <div className="vuln-repo-dashboard-resolution-card">
                      <strong>{formatNumber(dashboard.resolutionStatus.acceptedRiskCount)}</strong>
                      <span>Accepted risk</span>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          </div>

          <section className="panel vuln-repo-dashboard-panel">
            <div className="panel-header">
              <div className="vuln-repo-dashboard-section-copy">
                <h3>Repository context</h3>
                <div className="panel-caption">Explore concentration in affected software and the latest advisory movement.</div>
              </div>
            </div>
            <div className="vuln-repo-dashboard-context-grid">
              <div className="vuln-repo-dashboard-context-section">
                <div className="vuln-repo-dashboard-panel-block-header">
                  <h4>Top affected software</h4>
                  <div className="panel-caption">Sorted by tracked CVE count</div>
                </div>
                <button type="button" className="btn-link vuln-repo-dashboard-inline-link" onClick={() => navigate(pathForInventoryView('software-identities'))}>Show all</button>
                <div className="vuln-repo-dashboard-software-list">
                  {topAffectedSoftware.length === 0 ? (
                    <div className="empty-state">No software exposure data is available yet.</div>
                  ) : (
                    topAffectedSoftware.map((item) => (
                      <div key={`${item.software}-${item.vendor}`} className="vuln-repo-dashboard-software-row">
                        <div className="vuln-repo-dashboard-software-copy">
                          <strong>{item.software}</strong>
                          <span>{item.vendor}</span>
                        </div>
                        <div className="vuln-repo-dashboard-software-metrics">
                          <div className="vuln-repo-dashboard-breakdown-bar">
                            <span className={severityBarClassName(item.highestSeverity)} style={{ width: '100%' }} />
                          </div>
                          <button
                            type="button"
                            className="btn-link vuln-repo-dashboard-count-link"
                            onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({
                              software: item.software,
                              softwareScope: 'broad',
                              softwareIdentityId: item.softwareIdentityId,
                            }))}
                          >
                            {formatNumber(item.cveCount)}
                          </button>
                          <button
                            type="button"
                            className="btn-link vuln-repo-dashboard-count-link vuln-repo-dashboard-asset-link"
                            onClick={() => navigate(pathForVulnRepoSoftwareAssets(item.softwareIdentityId, item.software))}
                          >
                            {formatNumber(item.impactedAssetCount)} assets
                          </button>
                          <span className={severityClassName(item.highestSeverity)}>{formatSeverity(item.highestSeverity)}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="vuln-repo-dashboard-context-section">
                <div className="vuln-repo-dashboard-panel-block-header">
                  <h4>Recent advisories</h4>
                  <div className="panel-caption">CISA KEV, NVD, and vendor updates</div>
                </div>
                <button type="button" className="btn-link vuln-repo-dashboard-inline-link" onClick={() => navigate(pathForVulnRepoView('vulnerabilities'))}>View all</button>
                <div className="vuln-repo-dashboard-advisory-list">
                  {dashboard.recentAdvisories.map((item) => (
                    <button
                      key={`${item.externalId}-${item.lastModifiedAt ?? item.publishedAt ?? ''}`}
                      type="button"
                      className="vuln-repo-dashboard-advisory-item"
                      onClick={() => navigate(pathForVulnRepoView('org-cves', item.externalId))}
                    >
                      <div className="vuln-repo-dashboard-advisory-copy">
                        <strong>{item.externalId}</strong>
                        <p>{item.descriptionSnippet}</p>
                        <div className="vuln-repo-dashboard-item-tags">
                          <span className={severityClassName(item.severity)}>{formatSeverity(item.severity)}</span>
                          <span className="panel-caption">{item.source} · {advisoryRelativeTimeLabel(item.lastModifiedAt ?? item.publishedAt)}</span>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </section>

          <section className="panel vuln-repo-dashboard-panel">
            <div className="panel-header">
              <div className="vuln-repo-dashboard-section-copy">
                <h3>Impacted assets</h3>
                <div className="panel-caption">Hosts with unresolved critical CVEs</div>
              </div>
              <button
                type="button"
                className="btn-link"
                onClick={() => navigate(pathForInventoryView('hosts'))}
              >
                View all
              </button>
            </div>
            <div className="vuln-repo-dashboard-assets-grid">
              {dashboard.impactedAssets.map((asset) => (
                <button
                  key={asset.assetId}
                  type="button"
                  className="vuln-repo-dashboard-asset-card"
                  onClick={() => navigate(pathForVulnRepoHostAsset(asset.assetId, `${location.pathname}${location.search}${location.hash}`))}
                >
                  <div className="vuln-repo-dashboard-asset-copy">
                    <strong>{asset.assetName}</strong>
                    <span>{asset.assetType.toLowerCase()} · {asset.identifier}</span>
                    {asset.environment ? <span>{asset.environment}</span> : null}
                  </div>
                  <span className="vuln-repo-dashboard-asset-count">{formatNumber(asset.cveCount)} CVEs</span>
                </button>
              ))}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
