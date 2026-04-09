import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { pathForInventoryView, pathForVulnRepoHostAsset, pathForVulnRepoSoftwareAssets, pathForVulnRepoView } from '../app/routes';
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
      return 'vuln-repo-severity-pill vuln-repo-severity-pill--critical';
    case 'HIGH':
      return 'vuln-repo-severity-pill vuln-repo-severity-pill--high';
    case 'MEDIUM':
      return 'vuln-repo-severity-pill vuln-repo-severity-pill--medium';
    case 'LOW':
      return 'vuln-repo-severity-pill vuln-repo-severity-pill--low';
    default:
      return 'vuln-repo-severity-pill';
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
      <span className="vuln-repo-dashboard-tag">{item.statusLabel}</span>
      {item.exploitKnown ? <span className="vuln-repo-dashboard-tag vuln-repo-dashboard-tag--warn">Exploit</span> : null}
    </div>
  );
}

function advisoryRelativeTimeLabel(value?: string): string {
  return value ? relativeTime(value) : 'Recently';
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
  const loading = dashboardQuery.isPending || dashboardQuery.isFetching;
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
    <section className="vuln-repo-page vuln-repo-dashboard-page">
      <div className="vuln-repo-dashboard-shell">
        <div className="vuln-repo-dashboard-topbar">
          <div>
            <h1 className="page-title">Vulnerability Repository</h1>
          </div>
          <form className="vuln-repo-dashboard-search" onSubmit={handleSearchSubmit}>
            <label className="sr-only" htmlFor="vuln-repo-dashboard-search-input">Search CVEs</label>
            <input
              id="vuln-repo-dashboard-search-input"
              className="text-input"
              type="search"
              value={searchValue}
              onChange={(event) => setSearchValue(event.target.value)}
              placeholder="Search CVEs..."
            />
          </form>
        </div>

        {loading ? <div className="panel-card">Loading dashboard…</div> : null}
        {!loading && error ? <div className="empty-state">{error}</div> : null}

        {!loading && !error && dashboard ? (
          <>
            <div className="vuln-repo-dashboard-metric-grid">
              <article className="vuln-repo-dashboard-metric-card">
                <div className="vuln-repo-dashboard-metric-icon vuln-repo-dashboard-metric-icon--tracked" />
                <div>
                  <button
                    type="button"
                    className="btn-link vuln-repo-dashboard-metric-link"
                    onClick={() => navigate(vulnRepoTrackedVulnerabilityPath())}
                  >
                    {formatNumber(dashboard.summaryCards.trackedCount)}
                  </button>
                  <div className="vuln-repo-dashboard-metric-title">Total CVEs Tracked</div>
                  <button
                    type="button"
                    className="btn-link vuln-repo-dashboard-metric-caption-link"
                    onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({ createdSinceDays: 7 }))}
                  >
                    +{formatNumber(dashboard.summaryCards.trackedAddedLastWeek)} this week
                  </button>
                </div>
              </article>
              <article className="vuln-repo-dashboard-metric-card">
                <div className="vuln-repo-dashboard-metric-icon vuln-repo-dashboard-metric-icon--critical" />
                <div>
                  <button
                    type="button"
                    className="btn-link vuln-repo-dashboard-metric-link vuln-repo-dashboard-metric-value vuln-repo-dashboard-metric-value--critical"
                    onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({ severity: 'CRITICAL' }))}
                  >
                    {formatNumber(dashboard.summaryCards.criticalCount)}
                  </button>
                  <div className="vuln-repo-dashboard-metric-title">Critical Severity</div>
                  <div className="vuln-repo-dashboard-metric-caption">Immediate action required</div>
                </div>
              </article>
              <article className="vuln-repo-dashboard-metric-card">
                <div className="vuln-repo-dashboard-metric-icon vuln-repo-dashboard-metric-icon--exploit" />
                <div>
                  <button
                    type="button"
                    className="btn-link vuln-repo-dashboard-metric-link vuln-repo-dashboard-metric-value vuln-repo-dashboard-metric-value--warn"
                    onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({ exploitOnly: true }))}
                  >
                    {formatNumber(dashboard.summaryCards.exploitCount)}
                  </button>
                  <div className="vuln-repo-dashboard-metric-title">Exploits Available</div>
                  <div className="vuln-repo-dashboard-metric-caption">{dashboard.summaryCards.exploitCoveragePercent}% of tracked CVEs</div>
                </div>
              </article>
            </div>

            <div className="vuln-repo-dashboard-main-grid">
              <section className="panel-card vuln-repo-dashboard-panel">
                <div className="vuln-repo-dashboard-panel-header">
                  <div>
                    <h2>Critical unresolved</h2>
                    <p>Requires immediate attention</p>
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

              <div className="vuln-repo-dashboard-side-stack">
                <section className="panel-card vuln-repo-dashboard-panel">
                  <div className="vuln-repo-dashboard-panel-header">
                    <div>
                      <h2>Severity breakdown</h2>
                    </div>
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
                </section>

                <section className="panel-card vuln-repo-dashboard-panel">
                  <div className="vuln-repo-dashboard-panel-header">
                    <div>
                      <h2>Resolution status</h2>
                    </div>
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
                </section>
              </div>
            </div>

            <div className="vuln-repo-dashboard-lower-grid">
              <section className="panel-card vuln-repo-dashboard-panel">
                <div className="vuln-repo-dashboard-panel-header">
                  <div>
                    <h2>Top affected software</h2>
                    <p>By CVE count</p>
                  </div>
                  <button type="button" className="btn-link" onClick={() => navigate(pathForInventoryView('software-identities'))}>Show all</button>
                </div>
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
              </section>

              <section className="panel-card vuln-repo-dashboard-panel">
                <div className="vuln-repo-dashboard-panel-header">
                  <div>
                    <h2>Recent advisories</h2>
                    <p>CISA KEV · NVD · Vendor</p>
                  </div>
                  <button type="button" className="btn-link" onClick={() => navigate(pathForVulnRepoView('vulnerabilities'))}>View all</button>
                </div>
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
              </section>
            </div>

            <section className="panel-card vuln-repo-dashboard-panel">
              <div className="vuln-repo-dashboard-panel-header">
                <div>
                  <h2>Impacted assets</h2>
                  <p>Hosts with unresolved critical CVEs</p>
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
    </section>
  );
}
