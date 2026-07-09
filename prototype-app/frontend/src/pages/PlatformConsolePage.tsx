import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, setStoredAuthToken } from '../api/client';
import type { PlatformRouteView } from '../app/routes';
import { pathForPlatformView, pathForTab } from '../app/routes';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { MetricInfoIcon } from '../components/MetricInfoIcon';
import { useActor } from '../features/auth/context';
import { EolPage } from './EolPage';

const PLATFORM_TABS: Array<{ key: PlatformRouteView; label: string; helper: string }> = [
  { key: 'tenants', label: 'Tenants', helper: 'Lifecycle and workspace metadata' },
  { key: 'operations', label: 'Operations', helper: 'Tenant experience operations ownerspace and frustration signals' },
  { key: 'users', label: 'Users', helper: 'Provision and manage platform-owner identities' },
  { key: 'demo-requests', label: 'Demo Requests', helper: 'Review, provision, and invite customer demo tenants' },
  { key: 'eol', label: 'EOL', helper: 'Platform-owned end-of-life catalog and lifecycle coverage' }
];

const PLATFORM_TAB_GROUPS: Array<{
  key: 'tenant-management';
  title: string;
  tabs: PlatformRouteView[];
}> = [
  {
    key: 'tenant-management',
    title: 'Tenant Management',
    tabs: ['tenants', 'users', 'demo-requests']
  }
];

type PlatformOperationsSubView =
  | 'overview'
  | 'tenant-health'
  | 'reliability';

const PLATFORM_OPERATIONS_SUBNAV: Array<{ key: PlatformOperationsSubView; label: string; helper: string }> = [
  { key: 'overview', label: 'Overview', helper: 'Top tenant frustration signals and immediate action queue' },
  { key: 'tenant-health', label: 'Freshness & Access', helper: 'Connector health, stale data, and onboarding blockers' },
  { key: 'reliability', label: 'Trust & Reliability', helper: 'Accuracy and stability signals tenants will notice' }
];

function normalizeOperationsSubView(value: string | null): PlatformOperationsSubView {
  if (!value) {
    return 'overview';
  }
  return PLATFORM_OPERATIONS_SUBNAV.some((item) => item.key === value)
    ? value as PlatformOperationsSubView
    : 'overview';
}

function formatWorkspaceProfile(planCode: string | null | undefined): string {
  const normalized = String(planCode ?? '').trim().toUpperCase();
  if (normalized === '' || normalized === 'PRO' || normalized === 'ENTERPRISE' || normalized === 'DEMO' || normalized === 'PILOT') {
    return 'Standard workspace';
  }
  return normalized;
}

type PlatformConsolePageProps = {
  selectedView: PlatformRouteView;
};

export function PlatformConsolePage({ selectedView }: PlatformConsolePageProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const platformMessage = typeof location.state === 'object' && location.state && 'platformMessage' in location.state
    ? String((location.state as { platformMessage?: string }).platformMessage ?? '')
    : '';
  const hideSidebar = selectedView === 'eol' || selectedView === 'operations';
  const visibleTabGroups = PLATFORM_TAB_GROUPS.map((group) => ({
    ...group,
    tabs: group.tabs
      .map((key) => PLATFORM_TABS.find((tab) => tab.key === key))
      .filter((tab): tab is NonNullable<typeof tab> => tab != null)
  }));
  const operationsSubView = normalizeOperationsSubView(searchParams.get('ops'));

  const setOperationsSubView = (nextView: PlatformOperationsSubView) => {
    const nextParams = new URLSearchParams(searchParams);
    nextParams.set('ops', nextView);
    setSearchParams(nextParams, { replace: true });
  };

  return (
    <div className="page-grid platform-console-page">
      <section className={`panel platform-console-shell${hideSidebar ? ' platform-console-shell--no-sidebar' : ''}`}>
        {!hideSidebar && (
          <aside className="platform-console-sidebar" aria-label="Platform views">
            <div className="platform-console-sidebar-header">
              <h3>Tenant Management</h3>
            </div>
            <div className="platform-console-nav-groups">
              {visibleTabGroups.map((group) => (
                <section key={group.key} className="platform-console-nav-group" aria-label={group.title}>
                  <div className="platform-console-nav-group-title">{group.title}</div>
                  <div className="platform-console-nav">
                    {group.tabs.map((tab) => (
                      <button
                        key={tab.key}
                        type="button"
                        className={`platform-console-nav-btn${selectedView === tab.key ? ' active' : ''}`}
                        onClick={() => navigate(pathForPlatformView(tab.key))}
                        title={tab.helper}
                      >
                        <span>{tab.label}</span>
                        <small>{tab.helper}</small>
                      </button>
                    ))}
                  </div>
                </section>
              ))}
            </div>
          </aside>
        )}

        <div className="platform-console-content">
          {platformMessage && (
            <div className="notice" role="status">
              {platformMessage}
            </div>
          )}

          <div className="platform-console-section">
            {selectedView === 'tenants' && <TenantLifecyclePanel />}
            {selectedView === 'operations' && (
              <PlatformOperationsOwnerspace
                selectedSubView={operationsSubView}
                onSelectSubView={setOperationsSubView}
              />
            )}
            {selectedView === 'users' && <PlatformUsersPanel />}
            {selectedView === 'demo-requests' && <DemoRequestsPanel />}
            {selectedView === 'eol' && <EolPage embedded mode="platform" />}
          </div>
        </div>
      </section>
    </div>
  );
}

function formatPercent(value: number | null | undefined): string {
  return `${(value ?? 0).toFixed(1)}%`;
}

function formatInteger(value: number | null | undefined): string {
  return (value ?? 0).toLocaleString();
}

function formatRelativeHours(value: number | null | undefined): string {
  if (value == null) {
    return '-';
  }
  return `${value.toFixed(1)}h`;
}

function formatDateTime(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : 'Never';
}

function formatPerformanceValue(value: number | null | undefined, unit: string | null | undefined): string {
  if (value == null) {
    return '-';
  }
  if (unit === '%') {
    return `${value.toFixed(1)}%`;
  }
  if (unit === 'ms') {
    return `${value.toFixed(1)} ms`;
  }
  if (unit === 'threads') {
    return `${Math.round(value).toLocaleString()} threads`;
  }
  return `${value.toLocaleString()}${unit ? ` ${unit}` : ''}`;
}

function reliabilityStateLabel(state: 'PASS' | 'FAIL' | 'NO_DATA' | string): string {
  switch (state) {
    case 'PASS':
      return 'Healthy';
    case 'NO_DATA':
      return 'Awaiting telemetry';
    default:
      return 'Needs attention';
  }
}

function reliabilityStateClass(state: 'PASS' | 'FAIL' | 'NO_DATA' | string): string {
  return state === 'PASS' ? '' : 'table-critical';
}

function formatAttentionReason(reason: string): string {
  switch (reason) {
    case 'TENANT_SUSPENDED':
      return 'Tenant suspended';
    case 'TENANT_EXPIRED':
      return 'Tenant expired';
    case 'CONNECTOR_ERROR':
      return 'Connector error';
    case 'CONNECTOR_PENDING':
      return 'Connector pending';
    default:
      return reason
        .toLowerCase()
        .split('_')
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ');
  }
}

type MetricScope = 'all-tenants' | 'platform-wide' | 'default-workspace' | 'mock';

function scopeLabel(scope: MetricScope): string {
  switch (scope) {
    case 'all-tenants':
      return 'All tenants';
    case 'platform-wide':
      return 'Platform-wide';
    case 'default-workspace':
      return 'Default workspace';
    case 'mock':
      return 'Mock';
  }
}

function ScopeBadge({ scope }: { scope: MetricScope }) {
  return <span className={`platform-ops-scope-badge platform-ops-scope-badge--${scope}`}>{scopeLabel(scope)}</span>;
}

function MetricScopeNote({
  scope,
  text
}: {
  scope: MetricScope;
  text?: string;
}) {
  return (
    <div className="platform-ops-scope-note">
      <ScopeBadge scope={scope} />
      {text ? <span>{text}</span> : null}
    </div>
  );
}

const TENANT_EXPERIENCE_METRIC_HELP: Record<string, string> = {
  'Sync Success (24h)': 'Percentage of recent ingestion and sync jobs that completed successfully. Low values usually surface to tenants as missing or outdated data.',
  'Tenants With Connector Issues': 'Number of distinct tenants that currently have at least one unhealthy connector. These tenants are most likely blocked from getting fresh data.',
  'Stale Sources': 'Number of shared data sources whose most recent successful run is older than the allowed freshness threshold.',
  'Failing SLOs': 'Count of service objectives currently failing. These are platform reliability conditions that can degrade tenant experience.',
  'Lifecycle Attention': 'Number of tenants currently suspended or expired and therefore likely to be frustrated by access or continuity issues.',
  'Trust-Critical Quality Issues': 'Count of severe quality issues in the current quality workspace that could make tenants doubt the accuracy of the product.',
  'Inventory Normalization Trust': 'Placeholder signal for how consistently software and version data is normalized. Poor normalization usually means confusing or incomplete tenant results.',
  'False Noise Reduction': 'Placeholder signal for how much irrelevant or non-actionable noise is filtered out before it reaches tenants.',
  'Refresh Responsiveness P95': '95th percentile time for background refresh or recompute work. Higher values typically mean slower tenant-visible updates.',
  'SBOM Runs (24h)': 'Total SBOM ingestion runs processed in the last 24 hours.',
  'SBOM Success Rate': 'Share of SBOM ingestion runs that completed successfully in the last 24 hours.',
  'Sync Success Rate': 'Share of source and connector sync runs that completed successfully in the last 24 hours.',
  'Staleness Threshold': 'Configured age limit before a source is considered stale.',
  'Total Tenants': 'Total number of tenant workspaces on the platform.',
  'Active / Trial': 'Breakdown of active customer tenants and tenants still in trial or evaluation mode.',
  'Suspended / Expired': 'Breakdown of tenants that are currently blocked or have lapsed.',
  'Demo Workspaces': 'Number of demo or temporary workspaces currently present.',
  'Healthy Connectors': 'Connectors currently reporting a healthy state and unlikely to block tenant workflows.',
  'Failing Connectors': 'Connectors currently unhealthy or failing checks and likely to create tenant frustration.',
  'Total Issues': 'Total open quality issues in the current quality workspace.',
  'Critical Issues': 'Highest-severity quality issues that are most likely to affect tenant trust.',
  'Affecting Active Findings': 'Quality issues that currently impact live findings instead of only background data.',
  'New in Last 24h': 'Quality issues newly detected during the last day.',
  'Summary Coverage': 'Percentage of canonical source records represented in the main summary read model.',
  'Read Model Readiness': 'Whether the main summary model is ready to serve tenant-facing reads.',
  'Read Performance Cache Hit Ratio': 'Percentage of eligible reads served from cache instead of being recomputed.',
  'Overall Reliability State': 'High-level pass/fail signal for the current reliability objective set.',
  'Route Budget Failures': 'Interactive routes currently failing enterprise latency targets.',
  'Freshness Guardrail Failures': 'Freshness or mixed-load guardrails currently outside their target envelope.',
  'Resource Ceiling Failures': 'Runtime capacity signals currently breaching their measured ceilings.',
  'Enterprise Guardrails': 'Condensed view of the performance guardrails most likely to turn into tenant-visible degradation.',
  'Guardrail Signal': 'Specific performance budget or runtime ceiling being monitored.',
  State: 'Current pass/fail or no-data state for the guardrail.',
  Detail: 'Supporting context for why this guardrail is currently healthy or at risk.',
  Source: 'The upstream source or connector being monitored for freshness.',
  'Last Healthy Run': 'The last time this source completed successfully.',
  'Data Age': 'How long it has been since the last successful run for this source.',
  'Tenant Impact': 'What this freshness state is likely to mean for tenant-visible data.',
  Tenant: 'The tenant workspace affected by the connector state shown in this row.',
  Connector: 'The integration or connector that may be blocking tenant value.',
  Health: 'Current connector health state.',
  'Last Sync': 'Most recent sync time recorded for the connector.',
  'Why Attention': 'The specific reasons this tenant has been surfaced in the attention queue.',
  'Affected Connectors': 'The connectors currently contributing to this tenant needing attention.',
  'Affected Tenants': 'The tenants currently impacted by this connector problem.',
  'Tenant Count': 'How many tenants are currently affected by the listed issue.',
  Domain: 'The quality domain where issues are currently being observed.',
  'Issue Count': 'Number of open issues in this quality domain.',
  'Tenant Experience Risk': 'How likely this quality issue category is to reduce tenant confidence or usability.',
  'Suggested Owner Action': 'Recommended next move for a platform owner reviewing the issue.',
  'Reliability Signal': 'Specific platform reliability indicator being tracked.',
  Window: 'Time window over which the reliability signal is being evaluated.',
  Target: 'Expected threshold for the reliability signal.',
  Current: 'Current measured value for the reliability signal.',
  'Tenant Risk': 'How likely this reliability state is to be noticeable to tenants.'
};

function MetricLabel({
  label,
  description
}: {
  label: string;
  description?: string;
}) {
  return (
    <div className="metric-label-row">
      <span>{label}</span>
      {description ? <MetricInfoIcon label={label} description={description} /> : null}
    </div>
  );
}


function PlatformOperationsOwnerspace({
  selectedSubView,
  onSelectSubView
}: {
  selectedSubView: PlatformOperationsSubView;
  onSelectSubView: (nextView: PlatformOperationsSubView) => void;
}) {
  const overviewQuery = useQuery({
    queryKey: ['platform-operations-overview'],
    queryFn: api.getOperationalOverview
  });
  const ingestionQuery = useQuery({
    queryKey: ['platform-operations-ingestion'],
    queryFn: api.getOperationalIngestionEfficiency
  });
  const freshnessQuery = useQuery({
    queryKey: ['platform-operations-freshness'],
    queryFn: api.getOperationalFreshnessDrift
  });
  const qualityQuery = useQuery({
    queryKey: ['platform-operations-quality-summary'],
    queryFn: api.getOperationalQualitySummary
  });
  const readPathQuery = useQuery({
    queryKey: ['platform-operations-read-path'],
    queryFn: api.getOperationalApiReadPath
  });
  const performanceScorecardQuery = useQuery({
    queryKey: ['platform-operations-performance-scorecard'],
    queryFn: api.getOperationalPerformanceScorecard
  });
  const tenantsQuery = useQuery({
    queryKey: ['platform-operations-tenants'],
    queryFn: api.listTenants
  });
  const connectorHealthQuery = useQuery({
    queryKey: ['platform-operations-connectors'],
    queryFn: api.listInventoryConnectorHealth
  });
  const tenantAttentionQuery = useQuery({
    queryKey: ['platform-operations-tenant-attention'],
    queryFn: api.getOperationalTenantAttention
  });
  const connectorIssuesQuery = useQuery({
    queryKey: ['platform-operations-connector-issues'],
    queryFn: api.getOperationalConnectorIssues
  });

  const overview = overviewQuery.data?.data;
  const freshness = freshnessQuery.data?.data;
  const quality = qualityQuery.data;
  const readPath = readPathQuery.data?.data;
  const performanceScorecard = performanceScorecardQuery.data;
  const tenants = React.useMemo(() => tenantsQuery.data ?? [], [tenantsQuery.data]);
  const connectorHealth = React.useMemo(() => connectorHealthQuery.data ?? [], [connectorHealthQuery.data]);
  const tenantAttentionRows = tenantAttentionQuery.data ?? [];
  const connectorIssueGroups = React.useMemo(() => connectorIssuesQuery.data ?? [], [connectorIssuesQuery.data]);
  const latestOwnerspaceUpdate = React.useMemo(() => latestFreshnessValue([
    overviewQuery.data?.generatedAt,
    ingestionQuery.data?.generatedAt,
    freshnessQuery.data?.generatedAt,
    qualityQuery.data?.generatedAt,
    readPathQuery.data?.generatedAt,
    performanceScorecardQuery.data?.generatedAt,
    tenantsQuery.dataUpdatedAt,
    connectorHealthQuery.dataUpdatedAt,
    tenantAttentionQuery.dataUpdatedAt,
    connectorIssuesQuery.dataUpdatedAt,
  ]), [
    connectorHealthQuery.dataUpdatedAt,
    connectorIssuesQuery.dataUpdatedAt,
    freshnessQuery.data?.generatedAt,
    ingestionQuery.data?.generatedAt,
    overviewQuery.data?.generatedAt,
    performanceScorecardQuery.data?.generatedAt,
    qualityQuery.data?.generatedAt,
    readPathQuery.data?.generatedAt,
    tenantAttentionQuery.dataUpdatedAt,
    tenantsQuery.dataUpdatedAt,
  ]);
  const ownerspaceRefreshing = [
    overviewQuery,
    ingestionQuery,
    freshnessQuery,
    qualityQuery,
    readPathQuery,
    performanceScorecardQuery,
    tenantsQuery,
    connectorHealthQuery,
    tenantAttentionQuery,
    connectorIssuesQuery
  ].some((query) => query.isFetching);
  const ownerspaceDelayMessage = (freshness?.staleSourceCount ?? 0) > 0
    ? 'Some shared sources are stale, so tenant-facing dashboards may reflect older data until refresh catches up.'
    : (performanceScorecard?.freshnessFailureCount ?? 0) > 0
      ? 'Some freshness guardrails are outside target, so platform health signals may lag behind recent activity.'
      : null;

  const tenantStats = React.useMemo(() => {
    const active = tenants.filter((tenant) => tenant.status === 'ACTIVE').length;
    const trial = tenants.filter((tenant) => tenant.status === 'TRIAL').length;
    const suspended = tenants.filter((tenant) => tenant.status === 'SUSPENDED').length;
    const expired = tenants.filter((tenant) => tenant.status === 'EXPIRED').length;
    const demo = tenants.filter((tenant) => tenant.status === 'DEMO' || tenant.demoExpiresAt).length;
    return {
      total: tenants.length,
      active,
      trial,
      suspended,
      expired,
      demo
    };
  }, [tenants]);

  const connectorStats = React.useMemo(() => {
    const total = connectorHealth.length;
    const healthy = connectorHealth.filter((item) => {
      const status = String(item.healthState ?? item.lastTestStatus ?? '').toUpperCase();
      return status === 'HEALTHY' || status === 'ACTIVE' || status === 'CONNECTED';
    }).length;
    const failing = total - healthy;
    return { total, healthy, failing };
  }, [connectorHealth]);

  const tenantsWithConnectorIssues = React.useMemo(() => {
    return Array.from(new Set(connectorIssueGroups.flatMap((group) => group.affectedTenants))).length;
  }, [connectorIssueGroups]);

  const guardrailRows = React.useMemo(() => {
    if (!performanceScorecard) {
      return [];
    }

    const rows: Array<{
      key: string;
      signal: string;
      state: string;
      detail: string;
      risk: string;
    }> = [];

    performanceScorecard.freshnessItems
      .filter((item) => !item.compliant)
      .forEach((item) => {
        rows.push({
          key: `freshness-${item.key}`,
          signal: item.label,
          state: 'FAIL',
          detail: `${formatPerformanceValue(item.currentValue, item.unit)} vs target ${formatPerformanceValue(item.targetValue, item.unit)} (${item.window})`,
          risk: 'Fresh data may arrive later than tenants expect'
        });
      });

    performanceScorecard.resourceItems
      .filter((item) => item.status !== 'PASS')
      .forEach((item) => {
        rows.push({
          key: `resource-${item.key}`,
          signal: item.label,
          state: item.status,
          detail: item.note,
          risk: item.status === 'NO_DATA'
            ? 'Capacity blind spots reduce confidence in tenant stability'
            : 'Runtime saturation may slow or stall tenant-visible work'
        });
      });

    performanceScorecard.routeItems
      .filter((item) => item.status !== 'PASS')
      .slice(0, 6)
      .forEach((item) => {
        rows.push({
          key: `route-${item.key}`,
          signal: item.label,
          state: item.status,
          detail: item.note,
          risk: item.status === 'NO_DATA'
            ? 'Missing route telemetry weakens performance certification confidence'
            : 'Tenants may feel slower reads or investigation workflows'
        });
      });

    return rows;
  }, [performanceScorecard]);

  const loading = [
    overviewQuery,
    ingestionQuery,
    freshnessQuery,
    qualityQuery,
    readPathQuery,
    performanceScorecardQuery,
    tenantsQuery,
    connectorHealthQuery,
    tenantAttentionQuery,
    connectorIssuesQuery
  ].every((query) => query.isLoading);

  if (loading) {
    return (
      <section className="panel">
        <div className="notice">Loading platform owner operations ownerspace...</div>
      </section>
    );
  }

  return (
    <div className="platform-ops-space">
      <section className="panel platform-ops-hero">
        <div className="panel-header">
          <div>
            <h3>Tenant Experience Operations</h3>
            <div className="panel-caption">
              A platform-owner view of what tenants are most likely to feel as friction: stale data, broken connectors, trust gaps, and reliability issues.
            </div>
          </div>
          <div className="platform-ops-hero-tag">Platform owner</div>
        </div>
        <MetricScopeNote
          scope="all-tenants"
          text="This view stays intentionally narrow: only the few tenant-facing signals most likely to require platform-owner action."
        />
        <PageFreshnessStatus
          updatedAt={latestOwnerspaceUpdate}
          isRefreshing={ownerspaceRefreshing}
          delayedMessage={ownerspaceDelayMessage}
          refreshLabel="Refreshing tenant experience signals…"
        />
        <div className="stats-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label"><MetricLabel label="Tenants With Connector Issues" description={TENANT_EXPERIENCE_METRIC_HELP['Tenants With Connector Issues']} /></div>
            <div className="noise-summary-value">{formatInteger(tenantsWithConnectorIssues)}</div>
            <div className="platform-ops-metric-scope">All tenants</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label"><MetricLabel label="Stale Sources" description={TENANT_EXPERIENCE_METRIC_HELP['Stale Sources']} /></div>
            <div className="noise-summary-value">{formatInteger(freshness?.staleSourceCount)}</div>
            <div className="platform-ops-metric-scope">Platform-wide</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label"><MetricLabel label="Failing SLOs" description={TENANT_EXPERIENCE_METRIC_HELP['Failing SLOs']} /></div>
            <div className="noise-summary-value">{formatInteger(performanceScorecard?.freshnessFailureCount)}</div>
            <div className="platform-ops-metric-scope">All tenants</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label"><MetricLabel label="Trust-Critical Quality Issues" description={TENANT_EXPERIENCE_METRIC_HELP['Trust-Critical Quality Issues']} /></div>
            <div className="noise-summary-value">{formatInteger(quality?.criticalIssues)}</div>
            <div className="platform-ops-metric-scope">Default workspace</div>
          </div>
        </div>
      </section>

      <div className="section-tab-row platform-ops-subnav" role="tablist" aria-label="Operations ownerspace sections">
        {PLATFORM_OPERATIONS_SUBNAV.map((item) => (
          <button
            key={item.key}
            type="button"
            className={selectedSubView === item.key ? 'section-tab-btn active' : 'section-tab-btn'}
            title={item.helper}
            onClick={() => onSelectSubView(item.key)}
          >
            {item.label}
          </button>
        ))}
      </div>

      {selectedSubView === 'overview' && (
        <div className="page-grid">
          <section className="panel">
            <div className="panel-header">
              <h3>Tenant Attention Queue</h3>
              <span className="panel-caption">Every tenant currently needing platform-owner attention, with the reason surfaced inline.</span>
            </div>
            <div className="ops-table">
              <div className="ops-table-header">
                <span><MetricLabel label="Tenant" description={TENANT_EXPERIENCE_METRIC_HELP.Tenant} /></span>
                <span>Status</span>
                <span><MetricLabel label="Why Attention" description={TENANT_EXPERIENCE_METRIC_HELP['Why Attention']} /></span>
                <span><MetricLabel label="Affected Connectors" description={TENANT_EXPERIENCE_METRIC_HELP['Affected Connectors']} /></span>
                <span><MetricLabel label="Last Sync" description={TENANT_EXPERIENCE_METRIC_HELP['Last Sync']} /></span>
              </div>
              {tenantAttentionRows.length === 0 ? (
                <div className="ops-table-row">
                  <span>No tenant</span>
                  <span>-</span>
                  <span>No tenant currently requires attention</span>
                  <span>-</span>
                  <span>-</span>
                </div>
              ) : tenantAttentionRows.map((row) => (
                <div key={row.tenantId} className="ops-table-row ops-table-row-wide">
                  <span>{row.tenantName}</span>
                  <span>{row.tenantStatus}</span>
                  <span>{row.reasons.map(formatAttentionReason).join(', ')}</span>
                  <span>{row.affectedConnectors.length > 0 ? row.affectedConnectors.join(', ') : '-'}</span>
                  <span>{formatDateTime(row.latestRelevantSyncAt)}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h3>Connector Issues</h3>
              <span className="panel-caption">If a specific connector breaks, see exactly which tenants are affected.</span>
            </div>
            <div className="ops-table">
              <div className="ops-table-header">
                <span><MetricLabel label="Connector" description={TENANT_EXPERIENCE_METRIC_HELP.Connector} /></span>
                <span><MetricLabel label="Tenant Count" description={TENANT_EXPERIENCE_METRIC_HELP['Tenant Count']} /></span>
                <span><MetricLabel label="Affected Tenants" description={TENANT_EXPERIENCE_METRIC_HELP['Affected Tenants']} /></span>
              </div>
              {connectorIssueGroups.length === 0 ? (
                <div className="ops-table-row">
                  <span>No connector</span>
                  <span>0</span>
                  <span>No tenants currently impacted</span>
                </div>
              ) : connectorIssueGroups.map((group) => (
                <div key={group.connectorKey} className="ops-table-row ops-table-row-wide">
                  <span>{group.connectorKey}</span>
                  <span>{formatInteger(group.affectedTenantCount)}</span>
                  <span>{group.affectedTenants.join(', ')}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}

      {selectedSubView === 'tenant-health' && (
        <div className="page-grid">
          <section className="panel">
            <div className="panel-header">
              <h3>Freshness & Access</h3>
              <span className="panel-caption">The two biggest early frustrations: stale data and broken setup.</span>
            </div>
            <MetricScopeNote
              scope="all-tenants"
              text="Focused on the few operational signals most likely to block tenant value quickly."
            />
            <div className="noise-summary-grid">
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Sync Success (24h)" description={TENANT_EXPERIENCE_METRIC_HELP['Sync Success (24h)']} /></div>
                <div className="noise-summary-value">{formatPercent(overview?.ingestionSuccessRateLast24h)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Stale Sources" description={TENANT_EXPERIENCE_METRIC_HELP['Stale Sources']} /></div>
                <div className="noise-summary-value">{formatInteger(freshness?.staleSourceCount)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Suspended / Expired" description={TENANT_EXPERIENCE_METRIC_HELP['Suspended / Expired']} /></div>
                <div className="noise-summary-value">{formatInteger(tenantStats.suspended)} / {formatInteger(tenantStats.expired)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Failing Connectors" description={TENANT_EXPERIENCE_METRIC_HELP['Failing Connectors']} /></div>
                <div className="noise-summary-value">{formatInteger(connectorStats.failing)}</div>
              </div>
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h3>Stale Source Watchlist</h3>
              <span className="panel-caption">Data lag tenants are likely to notice in dashboards and findings.</span>
            </div>
            <div className="ops-table">
              <div className="ops-table-header">
                <span><MetricLabel label="Source" description={TENANT_EXPERIENCE_METRIC_HELP.Source} /></span>
                <span><MetricLabel label="Last Healthy Run" description={TENANT_EXPERIENCE_METRIC_HELP['Last Healthy Run']} /></span>
                <span><MetricLabel label="Data Age" description={TENANT_EXPERIENCE_METRIC_HELP['Data Age']} /></span>
                <span><MetricLabel label="Tenant Impact" description={TENANT_EXPERIENCE_METRIC_HELP['Tenant Impact']} /></span>
              </div>
              {(freshness?.sourceFreshness ?? []).filter((row) => row.stale).length === 0 ? (
                <div className="ops-table-row">
                  <span>No stale source</span>
                  <span>-</span>
                  <span>-</span>
                  <span>All tracked sources are fresh enough for tenant workflows</span>
                </div>
              ) : (freshness?.sourceFreshness ?? []).filter((row) => row.stale).map((row) => (
                <div key={row.source} className="ops-table-row">
                  <span>{row.source}</span>
                  <span>{formatDateTime(row.lastSuccessfulAt)}</span>
                  <span>{formatRelativeHours(row.ageHours)}</span>
                  <span>Tenants likely seeing stale data</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}

      {selectedSubView === 'reliability' && (
        <div className="page-grid">
          <section className="panel">
            <div className="panel-header">
              <h3>Trust & Reliability</h3>
              <span className="panel-caption">The quality and stability signals most likely to affect tenant confidence.</span>
            </div>
            <div className="noise-summary-grid">
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Critical Issues" description={TENANT_EXPERIENCE_METRIC_HELP['Critical Issues']} /></div>
                <div className="noise-summary-value">{formatInteger(quality?.criticalIssues)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Affecting Active Findings" description={TENANT_EXPERIENCE_METRIC_HELP['Affecting Active Findings']} /></div>
                <div className="noise-summary-value">{formatInteger(quality?.affectsActiveFindingsCount)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Overall Reliability State" description={TENANT_EXPERIENCE_METRIC_HELP['Overall Reliability State']} /></div>
                <div className="noise-summary-value">{performanceScorecard?.overallCompliant ? 'Healthy' : 'Needs attention'}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Read Model Readiness" description={TENANT_EXPERIENCE_METRIC_HELP['Read Model Readiness']} /></div>
                <div className="noise-summary-value">{readPath?.summaryReadModelReady ? 'Ready' : 'Rebuilding'}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Route Budget Failures" description={TENANT_EXPERIENCE_METRIC_HELP['Route Budget Failures']} /></div>
                <div className="noise-summary-value">{formatInteger(performanceScorecard?.routeFailureCount)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Resource Ceiling Failures" description={TENANT_EXPERIENCE_METRIC_HELP['Resource Ceiling Failures']} /></div>
                <div className="noise-summary-value">{formatInteger(performanceScorecard?.resourceFailureCount)}</div>
              </div>
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h3>Quality Signals</h3>
              <span className="panel-caption">Where tenant trust is most likely to erode.</span>
            </div>
            <div className="ops-table">
              <div className="ops-table-header">
                <span><MetricLabel label="Domain" description={TENANT_EXPERIENCE_METRIC_HELP.Domain} /></span>
                <span><MetricLabel label="Issue Count" description={TENANT_EXPERIENCE_METRIC_HELP['Issue Count']} /></span>
                <span><MetricLabel label="Tenant Experience Risk" description={TENANT_EXPERIENCE_METRIC_HELP['Tenant Experience Risk']} /></span>
                <span><MetricLabel label="Suggested Owner Action" description={TENANT_EXPERIENCE_METRIC_HELP['Suggested Owner Action']} /></span>
              </div>
              {(quality?.domainCounts ?? []).map((row) => (
                <div key={row.domain} className="ops-table-row">
                  <span>{row.domain}</span>
                  <span>{formatInteger(row.issueCount)}</span>
                  <span>{row.issueCount > 0 ? 'Tenants may distrust results' : 'Low visible trust risk'}</span>
                  <span>{row.issueCount > 0 ? 'Review drilldown and remediate source quality' : 'No action'}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h3>Reliability Signals</h3>
              <span className="panel-caption">Stability issues most likely to become tenant-visible.</span>
            </div>
            <div className="ops-table">
              <div className="ops-table-header">
                <span><MetricLabel label="Reliability Signal" description={TENANT_EXPERIENCE_METRIC_HELP['Reliability Signal']} /></span>
                <span><MetricLabel label="Window" description={TENANT_EXPERIENCE_METRIC_HELP.Window} /></span>
                <span><MetricLabel label="Target" description={TENANT_EXPERIENCE_METRIC_HELP.Target} /></span>
                <span><MetricLabel label="Current" description={TENANT_EXPERIENCE_METRIC_HELP.Current} /></span>
                <span><MetricLabel label="Tenant Risk" description={TENANT_EXPERIENCE_METRIC_HELP['Tenant Risk']} /></span>
              </div>
              {(performanceScorecard?.freshnessItems ?? []).map((row) => (
                <div key={row.key} className="ops-table-row">
                  <span>{row.label}</span>
                  <span>{row.window}</span>
                  <span>{formatPerformanceValue(row.targetValue, row.unit)}</span>
                  <span>{formatPerformanceValue(row.currentValue, row.unit)}</span>
                  <span className={row.compliant ? '' : 'table-critical'}>{row.compliant ? 'Healthy' : 'Needs attention'}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h3>Enterprise Performance Guardrails</h3>
              <span className="panel-caption">A compact watchlist of the failing or unmeasured performance budgets most likely to become tenant-visible.</span>
            </div>
            <MetricScopeNote
              scope="platform-wide"
              text={performanceScorecard?.scaleProfile
                ? `Validated against ${performanceScorecard.scaleProfile}.`
                : 'Guardrails unavailable until the performance scorecard is sampled.'}
            />
            <div className="noise-summary-grid">
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Freshness Guardrail Failures" description={TENANT_EXPERIENCE_METRIC_HELP['Freshness Guardrail Failures']} /></div>
                <div className="noise-summary-value">{formatInteger(performanceScorecard?.freshnessFailureCount)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Route Budget Failures" description={TENANT_EXPERIENCE_METRIC_HELP['Route Budget Failures']} /></div>
                <div className="noise-summary-value">{formatInteger(performanceScorecard?.routeFailureCount)}</div>
              </div>
              <div className="noise-summary-item">
                <div className="noise-summary-label"><MetricLabel label="Resource Ceiling Failures" description={TENANT_EXPERIENCE_METRIC_HELP['Resource Ceiling Failures']} /></div>
                <div className="noise-summary-value">{formatInteger(performanceScorecard?.resourceFailureCount)}</div>
              </div>
            </div>
            <div className="ops-table">
              <div className="ops-table-header">
                <span><MetricLabel label="Guardrail Signal" description={TENANT_EXPERIENCE_METRIC_HELP['Guardrail Signal']} /></span>
                <span><MetricLabel label="State" description={TENANT_EXPERIENCE_METRIC_HELP.State} /></span>
                <span><MetricLabel label="Tenant Risk" description={TENANT_EXPERIENCE_METRIC_HELP['Tenant Risk']} /></span>
                <span><MetricLabel label="Detail" description={TENANT_EXPERIENCE_METRIC_HELP.Detail} /></span>
              </div>
              {guardrailRows.length === 0 ? (
                <div className="ops-table-row">
                  <span>No active guardrail</span>
                  <span>Healthy</span>
                  <span>Low visible risk</span>
                  <span>All measured route, freshness, and resource guardrails are currently passing.</span>
                </div>
              ) : guardrailRows.map((row) => (
                <div key={row.key} className="ops-table-row ops-table-row-wide">
                  <span>{row.signal}</span>
                  <span className={reliabilityStateClass(row.state)}>{reliabilityStateLabel(row.state)}</span>
                  <span className={reliabilityStateClass(row.state)}>{row.risk}</span>
                  <span>{row.detail}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function PlatformUsersPanel() {
  const queryClient = useQueryClient();
  const usersQuery = useQuery({
    queryKey: ['platform-users'],
    queryFn: api.listPlatformUsers
  });
  const upsertPlatformUser = useMutation({
    mutationFn: api.upsertPlatformUser,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['platform-users'] });
    }
  });
  const revokeRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: string }) => api.revokePlatformUserRole(userId, role),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['platform-users'] });
    }
  });

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const externalSubject = String(formData.get('externalSubject') ?? '').trim();
    const email = String(formData.get('email') ?? '').trim();
    const displayName = String(formData.get('displayName') ?? '').trim();
    const role = String(formData.get('role') ?? 'PLATFORM_OWNER').trim();
    if (!externalSubject || !role) {
      return;
    }
    upsertPlatformUser.mutate(
      {
        externalSubject,
        email: email || undefined,
        displayName: displayName || undefined,
        role
      },
      {
        onSuccess: () => event.currentTarget.reset()
      }
    );
  };

  const users = usersQuery.data ?? [];

  return (
    <div className="section-block">
      <div className="section-title-row">
        <h4 className="section-title">Platform Users</h4>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => void usersQuery.refetch()}>
          Refresh
        </button>
      </div>
      <p className="panel-caption">
        Provision platform access with the external subject emitted by your configured identity provider subject claim.
      </p>
      <form className="platform-create-tenant-form" onSubmit={handleSubmit}>
        <input name="externalSubject" placeholder="External subject" aria-label="External subject" />
        <input name="email" placeholder="Email" aria-label="Email" />
        <input name="displayName" placeholder="Display name" aria-label="Display name" />
        <input name="role" placeholder="PLATFORM_OWNER" aria-label="Role" defaultValue="PLATFORM_OWNER" />
        <button type="submit" className="btn btn-primary" disabled={upsertPlatformUser.isPending}>
          {upsertPlatformUser.isPending ? 'Saving...' : 'Grant Role'}
        </button>
      </form>
      {upsertPlatformUser.isError && (
        <div className="notice error" role="alert">
          {upsertPlatformUser.error instanceof Error ? upsertPlatformUser.error.message : 'Failed to save platform user'}
        </div>
      )}
      {usersQuery.isError ? (
        <div className="notice error" role="alert">
          {usersQuery.error instanceof Error ? usersQuery.error.message : 'Failed to load platform users'}
        </div>
      ) : usersQuery.isLoading ? (
        <div className="empty-state"><p>Loading platform users...</p></div>
      ) : users.length === 0 ? (
        <div className="empty-state"><p>No platform users provisioned yet.</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Display Name</th>
                <th>Subject</th>
                <th>Email</th>
                <th>Roles</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.userId}>
                  <td>{user.displayName ?? 'Unassigned'}</td>
                  <td><code>{user.externalSubject}</code></td>
                  <td>{user.email ?? '-'}</td>
                  <td>{user.globalRoles.join(', ') || '-'}</td>
                  <td>{user.status}</td>
                  <td>{user.lastSeenAt ? new Date(user.lastSeenAt).toLocaleString() : '-'}</td>
                  <td>
                    {user.globalRoles.length === 0 ? '-' : user.globalRoles.map((role) => (
                      <button
                        key={`${user.userId}-${role}`}
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => revokeRole.mutate({ userId: user.userId, role })}
                        disabled={revokeRole.isPending}
                      >
                        Revoke {role}
                      </button>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {revokeRole.isError && (
        <div className="notice error" role="alert">
          {revokeRole.error instanceof Error ? revokeRole.error.message : 'Failed to revoke role'}
        </div>
      )}
    </div>
  );
}

function TenantLifecyclePanel() {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tenantPendingDelete, setTenantPendingDelete] = React.useState<{
    id: string;
    name: string;
    slug: string;
    status: string;
    demoExpiresAt?: string | null;
  } | null>(null);
  const tenantsQuery = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: api.listTenants
  });
  const inventoryConnectorHealthQuery = useQuery({
    queryKey: ['platform-inventory-connector-health'],
    queryFn: api.listInventoryConnectorHealth
  });
  const createTenant = useMutation({
    mutationFn: api.createTenant,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
      await queryClient.invalidateQueries({ queryKey: ['platform-inventory-connector-health'] });
    }
  });
  const deleteTenant = useMutation({
    mutationFn: api.deleteTenant,
    onSuccess: async () => {
      setTenantPendingDelete(null);
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
      await queryClient.invalidateQueries({ queryKey: ['platform-inventory-connector-health'] });
    }
  });
  const switchTenantContext = useMutation({
    mutationFn: api.selectTenantContext,
    onSuccess: async (response, tenantId) => {
      setStoredAuthToken(response.token);
      queryClient.clear();
      navigate(pathForTab('dashboard'), {
        replace: true,
        state: { platformMessage: `Entered tenant workspace ${tenantId}.` }
      });
    }
  });
  const clearTenantContext = useMutation({
    mutationFn: api.clearTenantContext,
    onSuccess: async (response) => {
      setStoredAuthToken(response.token);
      queryClient.clear();
      navigate(pathForPlatformView('tenants'), {
        replace: true,
        state: { platformMessage: 'Returned to platform scope.' }
      });
    }
  });

  const tenants = React.useMemo(() => tenantsQuery.data ?? [], [tenantsQuery.data]);
  const inventoryConnectorHealth = inventoryConnectorHealthQuery.data ?? [];
  const accessibleTenantIds = React.useMemo(
    () => new Set((actor?.allowedTenants ?? []).map((tenant) => tenant.id)),
    [actor?.allowedTenants]
  );
  const actingTenantId = actor?.actingAsPlatformOwner ? actor.tenantId : null;
  const switchingTenantId = switchTenantContext.variables ?? null;

  const handleCreateTenant = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const name = String(formData.get('name') ?? '').trim();
    const slug = String(formData.get('slug') ?? '').trim();
    const billingRef = String(formData.get('billingRef') ?? '').trim();
    if (!name || !slug) {
      return;
    }
    createTenant.mutate({ name, slug, billingRef });
    event.currentTarget.reset();
  };

  return (
    <div className="section-block">
      <div className="section-title-row">
        <h4 className="section-title">Tenant Lifecycle</h4>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => void tenantsQuery.refetch()}>
          Refresh
        </button>
      </div>
      {actor?.platformScope ? (
        <div className="notice" role="status">
          Enter a tenant workspace only through an active support grant. Platform-scope access no longer inherits a default tenant.
        </div>
      ) : null}
      {actor?.actingAsPlatformOwner ? (
        <div className="notice" role="status">
          You are acting inside <strong>{actor.tenantName ?? 'the selected tenant'}</strong>.
          {' '}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => clearTenantContext.mutate()}
            disabled={clearTenantContext.isPending}
          >
            {clearTenantContext.isPending ? 'Returning...' : 'Return to platform scope'}
          </button>
        </div>
      ) : null}
      <form className="platform-create-tenant-form" onSubmit={handleCreateTenant}>
        <input name="name" placeholder="Tenant name" aria-label="Tenant name" />
        <input name="slug" placeholder="tenant-slug" aria-label="Tenant slug" />
        <input name="billingRef" placeholder="Billing reference" aria-label="Billing reference" />
        <button type="submit" className="btn btn-primary" disabled={createTenant.isPending}>
          {createTenant.isPending ? 'Creating...' : 'Create Tenant'}
        </button>
      </form>
      {createTenant.isError && (
        <div className="notice error" role="alert">
          {createTenant.error instanceof Error ? createTenant.error.message : 'Tenant creation failed'}
        </div>
      )}
      {tenantsQuery.isError ? (
        <div className="notice error" role="alert">
          {tenantsQuery.error instanceof Error ? tenantsQuery.error.message : 'Failed to load tenants'}
        </div>
      ) : tenantsQuery.isLoading ? (
        <div className="empty-state"><p>Loading tenants...</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Tenant</th>
                <th>Owner Email</th>
                <th>Slug</th>
                <th>Status</th>
                <th>Workspace</th>
                <th>Daily Exposure Refreshes</th>
                <th>Demo Expires</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((tenant) => (
                <tr key={tenant.id}>
                  <td>{tenant.name}</td>
                  <td>{tenant.demoOwnerEmail ?? '-'}</td>
                  <td><code>{tenant.slug}</code></td>
                  <td>{tenant.status}</td>
                  <td>{formatWorkspaceProfile(tenant.planCode)}</td>
                  <td>{tenant.maxDailyExposureRefreshes ?? '-'}</td>
                  <td>{tenant.demoExpiresAt ? new Date(tenant.demoExpiresAt).toLocaleDateString() : '-'}</td>
                  <td>{new Date(tenant.createdAt).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {actor?.roles.includes('PLATFORM_OWNER') ? (
                        actingTenantId === tenant.id ? (
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => clearTenantContext.mutate()}
                            disabled={clearTenantContext.isPending}
                          >
                            {clearTenantContext.isPending ? 'Returning...' : 'Exit workspace'}
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            disabled={
                              switchTenantContext.isPending
                              || !accessibleTenantIds.has(tenant.id)
                              || tenant.status.toUpperCase() === 'PURGING'
                              || tenant.status.toUpperCase() === 'DELETED'
                            }
                            onClick={() => switchTenantContext.mutate(tenant.id)}
                            title={accessibleTenantIds.has(tenant.id)
                              ? 'Switch into tenant workspace context'
                              : 'Active support grant required'}
                          >
                            {switchingTenantId === tenant.id && switchTenantContext.isPending ? 'Entering...' : 'Enter workspace'}
                          </button>
                        )
                      ) : null}
                      {tenant.slug === 'default-workspace' ? null : (
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          disabled={deleteTenant.isPending || tenant.status.toUpperCase() === 'PURGING' || tenant.status.toUpperCase() === 'DELETED'}
                          onClick={() => setTenantPendingDelete({
                            id: tenant.id,
                            name: tenant.name,
                            slug: tenant.slug,
                            status: tenant.status,
                            demoExpiresAt: tenant.demoExpiresAt ?? null
                          })}
                          title="Delete the tenant and purge its tenant schema"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {switchTenantContext.isError && (
        <div className="notice error" role="alert">
          {switchTenantContext.error instanceof Error ? switchTenantContext.error.message : 'Failed to enter tenant workspace'}
        </div>
      )}
      {clearTenantContext.isError && (
        <div className="notice error" role="alert">
          {clearTenantContext.error instanceof Error ? clearTenantContext.error.message : 'Failed to return to platform scope'}
        </div>
      )}
      {deleteTenant.isError && (
        <div className="notice error" role="alert">
          {deleteTenant.error instanceof Error ? deleteTenant.error.message : 'Failed to delete tenant'}
        </div>
      )}
      <ConfirmDialog
        isOpen={tenantPendingDelete != null}
        title="Delete tenant?"
        message={
          tenantPendingDelete == null
            ? ''
            : tenantPendingDelete.demoExpiresAt
              ? `Delete ${tenantPendingDelete.name} and purge all tenant-scoped tables now? This will immediately remove tenant access, clear memberships, and reset the tenant schema.`
              : `Delete ${tenantPendingDelete.name} and purge all tenant-scoped tables now? This action is irreversible for this tenant workspace.`
        }
        confirmLabel={deleteTenant.isPending ? 'Deleting...' : 'Delete Tenant'}
        cancelLabel="Cancel"
        onCancel={() => {
          if (!deleteTenant.isPending) {
            setTenantPendingDelete(null);
          }
        }}
        onConfirm={() => {
          if (tenantPendingDelete != null && !deleteTenant.isPending) {
            deleteTenant.mutate(tenantPendingDelete.id);
          }
        }}
      />

      <div className="section-title-row" style={{ marginTop: 24 }}>
        <h4 className="section-title">Inventory Connector Health</h4>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => void inventoryConnectorHealthQuery.refetch()}
        >
          Refresh
        </button>
      </div>
      <p className="panel-caption">
        Read-only oversight of tenant-managed inventory connectors across customer workspaces.
      </p>
      {inventoryConnectorHealthQuery.isError ? (
        <div className="notice error" role="alert">
          {inventoryConnectorHealthQuery.error instanceof Error
            ? inventoryConnectorHealthQuery.error.message
            : 'Failed to load inventory connector health'}
        </div>
      ) : inventoryConnectorHealthQuery.isLoading ? (
        <div className="empty-state"><p>Loading inventory connector health...</p></div>
      ) : inventoryConnectorHealth.length === 0 ? (
        <div className="empty-state"><p>No tenant inventory connectors configured yet.</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Tenant</th>
                <th>Connector</th>
                <th>Health</th>
                <th>Enabled</th>
                <th>Auto Sync</th>
                <th>Last Test</th>
                <th>Last Sync</th>
              </tr>
            </thead>
            <tbody>
              {inventoryConnectorHealth.map((row) => (
                <tr key={`${row.tenantId}-${row.connectorKey}`}>
                  <td>{row.tenantName}</td>
                  <td><code>{row.connectorKey}</code></td>
                  <td>{row.healthState}</td>
                  <td>{row.enabled ? 'Yes' : 'No'}</td>
                  <td>{row.autoSyncEnabled ? 'Yes' : 'No'}</td>
                  <td title={row.lastTestMessage ?? undefined}>
                    {row.lastTestStatus ?? '-'}
                    {row.lastTestedAt ? ` · ${new Date(row.lastTestedAt).toLocaleString()}` : ''}
                  </td>
                  <td>{row.lastSyncAt ? new Date(row.lastSyncAt).toLocaleString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DemoRequestsPanel() {
  const queryClient = useQueryClient();
  const [requestPendingDelete, setRequestPendingDelete] = React.useState<{
    id: string;
    company: string;
    fullName: string;
    tenantId: string | null;
  } | null>(null);
  const requestsQuery = useQuery({
    queryKey: ['platform-demo-requests'],
    queryFn: api.listDemoRequests
  });
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['platform-demo-requests'] });
    await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
  };
  const approve = useMutation({ mutationFn: api.approveDemoRequest, onSuccess: refresh });
  const reject = useMutation({ mutationFn: ({ id, reason }: { id: string; reason?: string }) => api.rejectDemoRequest(id, reason), onSuccess: refresh });
  const resend = useMutation({ mutationFn: api.resendDemoInvite, onSuccess: refresh });
  const issueSetup = useMutation({
    mutationFn: api.issueDemoSetupLink,
    onSuccess: (response) => {
      window.location.href = response.setupUrl;
    }
  });
  const deleteRequest = useMutation({
    mutationFn: api.deleteDemoRequest,
    onSuccess: async () => {
      setRequestPendingDelete(null);
      await refresh();
    },
    onError: async (error) => {
      if (error instanceof Error && error.message.includes('[NOT_FOUND]')) {
        setRequestPendingDelete(null);
        await refresh();
      }
    }
  });
  const requests = requestsQuery.data ?? [];
  const isApprovalComplete = (status: string, tenantId: string | null) =>
    tenantId != null || ['SENT', 'ERROR', 'REJECTED'].includes(status.toUpperCase());
  const deleteNotFound =
    deleteRequest.error instanceof Error && deleteRequest.error.message.includes('[NOT_FOUND]');

  React.useEffect(() => {
    if (requestPendingDelete == null && deleteRequest.isError && deleteNotFound) {
      deleteRequest.reset();
    }
  }, [deleteNotFound, deleteRequest, requestPendingDelete]);

  return (
    <div className="section-block">
      <div className="section-title-row">
        <h4 className="section-title">Demo Request Queue</h4>
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => void requestsQuery.refetch()}>
          Refresh
        </button>
      </div>
      <p className="panel-caption">
        Approved requests provision demo tenants with the standard access profile while retaining demo expiry, invite, and quota controls.
      </p>
      {requestsQuery.isError ? (
        <div className="notice error">{requestsQuery.error instanceof Error ? requestsQuery.error.message : 'Failed to load demo requests'}</div>
      ) : requestsQuery.isLoading ? (
        <div className="empty-state"><p>Loading demo requests...</p></div>
      ) : requests.length === 0 ? (
        <div className="empty-state"><p>No demo requests yet.</p></div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Requester</th>
                <th>Company</th>
                <th>Access Profile</th>
                <th>Use Case</th>
                <th>Status</th>
                <th>Invite</th>
                <th>Requested</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((request) => (
                <tr key={request.id}>
                  <td>
                    <strong>{request.fullName}</strong>
                    <div className="muted-small">{request.email}</div>
                  </td>
                  <td>{request.company}</td>
                  <td>{formatWorkspaceProfile(request.provisionedPlanCode)}</td>
                  <td>{request.useCase ?? '-'}</td>
                  <td>{request.status}</td>
                  <td>
                    {request.latestInvite ? (
                      <a href={request.latestInvite.inviteUrl}>{request.latestInvite.status}</a>
                    ) : '-'}
                  </td>
                  <td>{new Date(request.requestedAt).toLocaleDateString()}</td>
                  <td>
                    <div className="button-row compact">
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={approve.isPending || isApprovalComplete(request.status, request.tenantId)}
                        onClick={() => approve.mutate(request.id)}
                      >
                        Approve
                      </button>
                      <button className="btn btn-secondary btn-sm" disabled={resend.isPending || !request.tenantId} onClick={() => resend.mutate(request.id)}>
                        Resend
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={issueSetup.isPending || !request.tenantId}
                        onClick={() => issueSetup.mutate(request.id)}
                        title={request.tenantId ? 'Open password setup for the tenant owner' : 'Provision the request first'}
                      >
                        Set Password
                      </button>
                      <button className="btn btn-secondary btn-sm" disabled={reject.isPending || request.status === 'REJECTED'} onClick={() => reject.mutate({ id: request.id, reason: 'Not a fit for current validation wave' })}>
                        Reject
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={deleteRequest.isPending}
                        onClick={() => setRequestPendingDelete({
                          id: request.id,
                          company: request.company,
                          fullName: request.fullName,
                          tenantId: request.tenantId
                        })}
                        title="Delete this request from the queue"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(approve.isError || reject.isError || resend.isError || issueSetup.isError || (deleteRequest.isError && !deleteNotFound)) && (
        <div className="notice error" role="alert">
          {[approve.error, reject.error, resend.error, issueSetup.error, deleteNotFound ? null : deleteRequest.error].find(Boolean) instanceof Error
            ? ([approve.error, reject.error, resend.error, issueSetup.error, deleteNotFound ? null : deleteRequest.error].find(Boolean) as Error).message
            : 'Demo request action failed'}
        </div>
      )}
      <ConfirmDialog
        isOpen={requestPendingDelete != null}
        title="Delete demo request?"
        message={
          requestPendingDelete == null
            ? ''
            : requestPendingDelete.tenantId
              ? `Delete the demo request for ${requestPendingDelete.fullName} at ${requestPendingDelete.company} from the queue? The tenant workspace will remain provisioned.`
              : `Delete the demo request for ${requestPendingDelete.fullName} at ${requestPendingDelete.company} from the queue?`
        }
        confirmLabel={deleteRequest.isPending ? 'Deleting...' : 'Delete'}
        cancelLabel="Cancel"
        onCancel={() => {
          if (!deleteRequest.isPending) {
            setRequestPendingDelete(null);
          }
        }}
        onConfirm={() => {
          if (requestPendingDelete != null && !deleteRequest.isPending) {
            deleteRequest.mutate(requestPendingDelete.id);
          }
        }}
      />
    </div>
  );
}
