import React from 'react';
import { Navigate } from 'react-router-dom';

type ErrorBoundaryState = { error: Error | null };

class OperationsSectionErrorBoundary extends React.Component<
  { children: React.ReactNode; viewKey: string },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode; viewKey: string }) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidUpdate(prevProps: { viewKey: string }) {
    if (prevProps.viewKey !== this.props.viewKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="panel">
          <div className="panel-header">
            <h3>Failed to render section</h3>
          </div>
          <div className="notice">{this.state.error.message}</div>
        </div>
      );
    }
    return this.props.children;
  }
}
import {
  OperationalApiReadPath,
  OperationalCorrelationEffectiveness,
  OperationalEndpointMetric,
  OperationalFreshnessDrift,
  OperationalIngestionEfficiency,
  OperationalIngestionSourceMetric,
  OperationalMetricDefinition,
  OperationalNoiseLifecycle,
  OperationalNormalizationQuality,
  OperationalSectionResponse,
  OperationalSourceFreshness,
  SloStatus
} from '../features/operations/types';
import type { Dashboard, TopFindingMetric } from '../features/dashboard/types';
import { MetricInfoIcon } from '../components/MetricInfoIcon';
import { StatCard } from '../components/StatCard';
import {
  type PipelinePayload,
  type PlatformHealthPayload,
  useOperationsViewQuery
} from '../features/operations/queries';

export type OperationsViewKey =
  | 'quality'
  | 'pipeline'
  | 'platform-health';

const OPERATIONS_NAV_ITEMS: Array<{ key: OperationsViewKey; label: string }> = [
  { key: 'pipeline', label: 'Pipeline' },
  { key: 'platform-health', label: 'Platform Health' }
];

const LEGACY_VIEW_ALIASES: Record<string, OperationsViewKey> = {
  dashboard: 'pipeline',
  overview: 'pipeline',
  quality: 'quality',
  pipeline: 'pipeline',
  'ingestion-efficiency': 'pipeline',
  ingestion: 'pipeline',
  'normalization-quality': 'pipeline',
  normalization: 'pipeline',
  'correlation-effectiveness': 'pipeline',
  correlation: 'pipeline',
  'noise-lifecycle': 'pipeline',
  noise: 'pipeline',
  lifecycle: 'pipeline',
  freshness: 'pipeline',
  'freshness-drift': 'pipeline',
  'platform-health': 'platform-health',
  'api-read-path': 'platform-health',
  readPath: 'platform-health',
  'metric-catalog': 'platform-health',
  catalog: 'platform-health',
  slo: 'platform-health'
};

function normalizeOperationsView(value: string | null | undefined): OperationsViewKey {
  if (!value) {
    return 'pipeline';
  }
  if (OPERATIONS_NAV_ITEMS.some((item) => item.key === value)) {
    return value as OperationsViewKey;
  }
  return LEGACY_VIEW_ALIASES[value] ?? 'pipeline';
}

type OperationalDashboardPageProps = {
  selectedView: OperationsViewKey;
  redirectSearch?: string;
};

const METRIC_HELP: Record<string, string> = {
  'Ingestion Success (24h)': 'Percent of SBOM ingestions and source sync runs that completed successfully in the last 24 hours.',
  'Projection Refresh P95 (ms)': 'P95 processing time for the background projection refresh worker.',
  'Normalization Coverage': 'Share of active components with enough normalized identity and version data for reliable matching.',
  'Noise Reduction': 'Percent of potential findings filtered out before they became analyst backlog.',
  'Open Critical': 'Count of currently critical findings that need attention.',
  'Open Findings': 'Count of findings that are currently unresolved.',
  'Stale Sources': 'Count of sources that are older than the configured freshness threshold.',
  'SBOM Ingestions (24h)': 'Total SBOM ingestion runs processed in the last 24 hours.',
  'SBOM / Hour': 'Average SBOM ingestion rate over the last 24 hours.',
  'SBOM Success Rate': 'Percent of SBOM ingestions that completed successfully.',
  'Sync Success Rate': 'Percent of source and connector sync runs that completed successfully.',
  'Queued/Running Sync Jobs': 'Current number of sync jobs that are queued or still running.',
  'Records Fetched': 'Total source records fetched during the last 24 hours.',
  'Records Inserted': 'Total new records inserted during the last 24 hours.',
  'Records Updated': 'Total existing records updated during the last 24 hours.',
  'Active Components': 'Count of active inventory components currently in scope for matching.',
  'Name Coverage': 'Share of active components with normalized product naming.',
  'Version Coverage': 'Share of active components with usable version information.',
  'Identity Coverage': 'Share of active components linked to a software identity.',
  'CPE Coverage (Active Components)': 'Share of active components that have at least one CPE identifier available for highest-confidence correlation.',
  'CPE Eligible Components': 'Active components with at least one CPE identifier and therefore eligible for direct CPE-based matching.',
  'CPE Ineligible Components': 'Active components with no CPE identifier and therefore limited to lower-confidence fallback matching methods.',
  'Open Findings via CPE': 'Open findings currently backed by CPE-based correlation methods.',
  'Direct vs Fallback': 'How many CPE-backed open findings used precise direct matching versus broader fallback matching.',
  'Direct Share': 'Percent of CPE-backed open findings using direct CPE matching rather than fallback methods.',
  'Fallback Share': 'Percent of CPE-backed open findings using fallback CPE matching methods.',
  'Average Open CPE Confidence': 'Average confidence score for currently open findings that were matched through CPE-based correlation.',
  'CPE Created (24h)': 'New findings created in the last 24 hours through CPE-based correlation.',
  'Other Methods Created (24h)': 'New findings created in the last 24 hours through non-CPE correlation methods.',
  'High Confidence Affected': 'Share of open affected findings backed by high-confidence matching evidence.',
  'Unknown Decision Rate': 'Share of open findings still stuck in an unknown or under-investigation state.',
  'Filtered Not Applicable': 'Total exposures filtered out as not applicable before or after finding creation.',
  'Never Opened': 'Filtered exposures that never became findings in the first place.',
  'Auto Resolved': 'Findings automatically resolved because the underlying evidence no longer supports them.',
  Deferred: 'Applicable matches deferred because the vendor is still under investigation.',
  'Filtered Rate': 'Share of potential findings that were filtered out as noise.',
  'Reopen Rate': 'Share of previously auto-resolved findings that later reopened.',
  'Summary Coverage': 'Percent of canonical CVEs represented in the summary read model.',
  'Summary Model': 'Whether the summary read model is ready to serve the UI.',
  'Cache Hit Ratio': 'Percent of eligible read-path requests served from cache.',
  'Failing SLOs': 'Count of tracked service-level objectives that are currently failing.',
  'Canonical CVEs': 'Count of canonical CVEs in the source-of-truth dataset.',
  'Summary CVEs': 'Count of CVEs currently materialized in the serving summary model.',
  'Noise Projection': 'Whether the noise-reduction projection is ready to serve dashboard reads.',
  'Projection Age': 'How long it has been since the noise-reduction projection was last recomputed.',
  'Projection Last Computed': 'Timestamp of the last completed noise-reduction projection refresh.',
  'Projection Refresh P95': 'P95 processing time for the background projection refresh worker.',
  'Projection Refresh Failures': 'Number of failed projection refresh attempts in the current metrics sample.',
  'Filter Cache State': 'Whether the read-path filter cache is warm and serving requests.',
  'Filter Cache Hit Ratio': 'Percent of filter-cache eligible requests served from cache.',
  'Stale Threshold (h)': 'Configured freshness threshold, in hours, before a source is treated as stale.',
  'Stale Source Count': 'Count of sources that are currently beyond the freshness threshold.',
  'Normalization Drift (7d)': 'Seven-day change in normalization coverage.',
  'CPE Fallback Drift (7d)': 'Seven-day change in the share of findings relying on fallback CPE matching.',
  'SLOs Defined': 'Total number of tracked service-level objectives.',
  'SLOs Passing': 'Number of tracked service-level objectives currently meeting target.',
  'SLOs Failing': 'Number of tracked service-level objectives currently breaching target.'
};

function formatPercent(value: number): string {
  return `${(value ?? 0).toFixed(1)}%`;
}

function formatAgeSeconds(value?: number): string {
  if (value == null || value < 0) {
    return '-';
  }
  if (value < 60) {
    return `${Math.round(value)}s`;
  }
  if (value < 3600) {
    return `${Math.round(value / 60)}m`;
  }
  return `${(value / 3600).toFixed(1)}h`;
}

function isCreatorAccessError(error: string): boolean {
  const normalized = error.toLowerCase();
  return normalized.includes('403') || normalized.includes('forbidden');
}

function formatGeneratedAt(generatedAt: string): string {
  return `Last updated ${new Date(generatedAt).toLocaleString()}`;
}

function MetricDistribution({ title, items = [], emptyLabel }: { title: string; items?: TopFindingMetric[]; emptyLabel: string }) {
  return (
    <div>
      <div className="noise-subtitle">{title}</div>
      {items.length === 0 ? (
        <div className="panel-caption">{emptyLabel}</div>
      ) : (
        <div className="noise-category-list">
          {items.map((entry) => (
            <div key={`${title}-${entry.key}`} className="noise-category-row">
              <div className="noise-category-key">{entry.key}</div>
              <div className="noise-category-count">{entry.count.toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryMetricCard({ label, value }: { label: string; value: React.ReactNode }) {
  const description = METRIC_HELP[label];
  return (
    <div className="noise-summary-item">
      <div className="metric-label-row">
        <div className="noise-summary-label">{label}</div>
        {description ? <MetricInfoIcon label={label} description={description} /> : null}
      </div>
      <div className="noise-summary-value">{value}</div>
    </div>
  );
}

function IngestionSourceTable({ rows = [] }: { rows?: OperationalIngestionSourceMetric[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No ingestion runs observed in the last 24 hours.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Source</span>
        <span>Runs</span>
        <span>Success %</span>
        <span>Fetched</span>
        <span>Inserted</span>
        <span>Updated</span>
      </div>
      {rows.map((row) => (
        <div key={row.source} className="ops-table-row">
          <span>{row.source}</span>
          <span>{row.runs.toLocaleString()}</span>
          <span>{formatPercent(row.successRatePercent)}</span>
          <span>{row.fetched.toLocaleString()}</span>
          <span>{row.inserted.toLocaleString()}</span>
          <span>{row.updated.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

function FreshnessTable({ rows = [] }: { rows?: OperationalSourceFreshness[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No source freshness records yet.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Source</span>
        <span>Last Success</span>
        <span>Age (h)</span>
        <span>State</span>
      </div>
      {rows.map((row) => (
        <div key={row.source} className="ops-table-row">
          <span>{row.source}</span>
          <span>{row.lastSuccessfulAt ? new Date(row.lastSuccessfulAt).toLocaleString() : 'Never'}</span>
          <span>{row.ageHours >= 0 ? row.ageHours.toLocaleString() : '-'}</span>
          <span>{row.stale ? 'Stale' : 'Fresh'}</span>
        </div>
      ))}
    </div>
  );
}

function EndpointMetricsTable({ rows = [] }: { rows?: OperationalEndpointMetric[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No API endpoint metrics observed yet.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Endpoint</span>
        <span>Requests</span>
        <span>Errors</span>
        <span>Avg ms</span>
        <span>P95 ms</span>
        <span>P99 ms</span>
      </div>
      {rows.map((row) => (
        <div key={row.key} className="ops-table-row">
          <span>{row.label}</span>
          <span>{row.requestCount.toLocaleString()}</span>
          <span>{row.errorCount.toLocaleString()}</span>
          <span>{row.averageMs.toFixed(1)}</span>
          <span>{row.p95Ms.toFixed(1)}</span>
          <span>{row.p99Ms.toFixed(1)}</span>
        </div>
      ))}
    </div>
  );
}

function renderIngestion(payload: OperationalSectionResponse<OperationalIngestionEfficiency>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Ingestion Efficiency</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Ingestion Efficiency</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="SBOM Ingestions (24h)" value={(data.sbomIngestionsLast24h ?? 0).toLocaleString()} />
          <SummaryMetricCard label="SBOM / Hour" value={(data.sbomIngestionsPerHour ?? 0).toFixed(2)} />
          <SummaryMetricCard label="SBOM Success Rate" value={formatPercent(data.sbomSuccessRatePercent ?? 0)} />
          <SummaryMetricCard label="Sync Success Rate" value={formatPercent(data.syncSuccessRatePercent ?? 0)} />
          <SummaryMetricCard label="Queued/Running Sync Jobs" value={(data.queueBacklog ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Records Fetched" value={(data.recordsFetchedLast24h ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Records Inserted" value={(data.recordsInsertedLast24h ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Records Updated" value={(data.recordsUpdatedLast24h ?? 0).toLocaleString()} />
        </div>
        <IngestionSourceTable rows={data.sourceBreakdown} />
      </section>
    </div>
  );
}

function renderNormalization(payload: OperationalSectionResponse<OperationalNormalizationQuality>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Normalization Quality</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Normalization Quality</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Active Components" value={(data.activeComponents ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Name Coverage" value={formatPercent(data.normalizedNameCoveragePercent)} />
          <SummaryMetricCard label="Version Coverage" value={formatPercent(data.normalizedVersionCoveragePercent)} />
          <SummaryMetricCard label="Identity Coverage" value={formatPercent(data.softwareIdentityCoveragePercent)} />
        </div>
      </section>
    </div>
  );
}

function renderCorrelation(payload: OperationalSectionResponse<OperationalCorrelationEffectiveness>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Correlation Effectiveness</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Correlation Effectiveness</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Open Findings" value={(data.openFindings ?? 0).toLocaleString()} />
          <SummaryMetricCard label="High Confidence Affected" value={formatPercent(data.highConfidenceAffectedRatePercent)} />
          <SummaryMetricCard label="Unknown Decision Rate" value={formatPercent(data.unknownDecisionRatePercent)} />
        </div>
        <div className="noise-panel-grid">
          <MetricDistribution
            title="Selected Method Distribution"
            items={data.selectedMethodDistribution ?? []}
            emptyLabel="No selected method samples yet."
          />
          <MetricDistribution
            title="Decision State Distribution"
            items={data.decisionStateDistribution ?? []}
            emptyLabel="No decision states observed yet."
          />
          <MetricDistribution
            title="Workflow Status Distribution"
            items={data.workflowStatusDistribution ?? []}
            emptyLabel="No workflow states observed yet."
          />
        </div>
      </section>
    </div>
  );
}

function renderCorrelationEfficiency(payload: OperationalSectionResponse<OperationalCorrelationEffectiveness>, dashboard: Dashboard | null) {
  const data = dashboard?.correlationEfficiency;
  if (!data) {
    return null;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Correlation Efficiency</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Active Components" value={data.activeComponents.toLocaleString()} />
          <SummaryMetricCard label="CPE Coverage (Active Components)" value={formatPercent(data.cpeCoveragePercent)} />
          <SummaryMetricCard label="CPE Eligible Components" value={data.cpeEligibleActiveComponents.toLocaleString()} />
          <SummaryMetricCard label="CPE Ineligible Components" value={data.cpeIneligibleActiveComponents.toLocaleString()} />
          <SummaryMetricCard label="Open Findings via CPE" value={data.openFindingsMatchedByCpe.toLocaleString()} />
          <SummaryMetricCard
            label="Direct vs Fallback"
            value={`${data.openFindingsCpeDirect.toLocaleString()} / ${data.openFindingsCpeFallback.toLocaleString()}`}
          />
          <SummaryMetricCard label="Direct Share" value={formatPercent(data.cpeDirectSharePercent)} />
          <SummaryMetricCard label="Fallback Share" value={formatPercent(data.cpeFallbackSharePercent)} />
          <SummaryMetricCard label="Average Open CPE Confidence" value={`${(data.averageOpenCpeConfidenceScore * 100).toFixed(1)}%`} />
          <SummaryMetricCard label="CPE Created (24h)" value={data.cpeFindingsCreatedLast24Hours.toLocaleString()} />
          <SummaryMetricCard label="Other Methods Created (24h)" value={data.nonCpeFindingsCreatedLast24Hours.toLocaleString()} />
        </div>
      </section>
    </div>
  );
}

function renderCsafVexAnalytics(payload: OperationalSectionResponse<OperationalIngestionEfficiency>, dashboard: Dashboard | null) {
  const data = dashboard?.csafVexAnalytics;
  if (!data) {
    return null;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>CSAF/VEX Quality Analytics</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>

        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">Active VEX Coverage</div>
            <div className="noise-summary-value">{data.activeVexCoveragePercent.toFixed(1)}%</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">VEX Matched States</div>
            <div className="noise-summary-value">{data.activeVexMatchedStateCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Awaiting Exact VEX</div>
            <div className="noise-summary-value">{data.activeApplicableAwaitingVexCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Confirmed Impacted</div>
            <div className="noise-summary-value">{data.activeVexConfirmedImpactedCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Confirmed Not Affected</div>
            <div className="noise-summary-value">{data.activeVexConfirmedNotAffectedCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">No Patch</div>
            <div className="noise-summary-value">{data.activeVexNoPatchCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CSAF Normalization Success</div>
            <div className="noise-summary-value">{data.csafNormalizationSuccessRate.toFixed(1)}%</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CSAF Partial Failure</div>
            <div className="noise-summary-value">{data.csafPartialFailureRate.toFixed(1)}%</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Suppressed by VEX</div>
            <div className="noise-summary-value">{data.findingsSuppressedByVex.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Suppressed by Stale VEX</div>
            <div className="noise-summary-value">{data.suppressedByStaleVex.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Under Investigation Aging</div>
            <div className="noise-summary-value">{data.underInvestigationAging.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CSAF Runs (30d)</div>
            <div className="noise-summary-value">{data.csafRunsLast30Days.toLocaleString()}</div>
          </div>
        </div>

        <div className="noise-panel-grid">
          <div className="noise-categories">
            <div className="noise-subtitle">VEX Coverage by Provider</div>
            {data.vexCoverageByProvider.length === 0 ? (
              <div className="panel-caption">No provider-tagged VEX evidence in current exposure set.</div>
            ) : (
              <div className="noise-category-list">
                {data.vexCoverageByProvider.map((entry) => (
                  <div key={entry.key} className="noise-category-row">
                    <div className="noise-category-key">{entry.key}</div>
                    <div className="noise-category-count">{entry.count.toLocaleString()}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

function renderLifecycle(payload: OperationalSectionResponse<OperationalNoiseLifecycle>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Noise and Lifecycle</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Noise and Lifecycle</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Filtered Not Applicable" value={(data.totalFilteredNotApplicable ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Never Opened" value={(data.neverOpenedNotApplicable ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Auto Resolved" value={(data.autoResolvedNotApplicable ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Deferred" value={(data.deferredUnderInvestigation ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Filtered Rate" value={formatPercent(data.filteredPercentOfPotential)} />
          <SummaryMetricCard label="Reopen Rate" value={formatPercent(data.reopenRatePercent)} />
        </div>
        <div className="noise-panel-grid">
          <MetricDistribution
            title="Not Applicable Categories"
            items={data.notApplicableCategories ?? []}
            emptyLabel="No categories observed yet."
          />
        </div>
      </section>
    </div>
  );
}

function renderReadPath(payload: OperationalSectionResponse<OperationalApiReadPath>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>API and Read-Path Performance</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  const noiseProjectionState = typeof data.noiseProjectionReady === 'boolean'
    ? (data.noiseProjectionReady ? 'Ready' : 'Refreshing')
    : 'Unavailable';
  const noiseProjectionRefreshP95 = data.noiseProjectionRefreshP95Ms ?? 0;
  const noiseProjectionRefreshFailures = data.noiseProjectionRefreshFailures ?? 0;
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>API and Read-Path Performance</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Canonical CVEs" value={(data.canonicalCveCount ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Summary CVEs" value={(data.summaryCveCount ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Summary Coverage" value={formatPercent(data.summaryCoveragePercent)} />
          <SummaryMetricCard label="Noise Projection" value={noiseProjectionState} />
          <SummaryMetricCard label="Projection Age" value={formatAgeSeconds(data.noiseProjectionAgeSeconds)} />
          <SummaryMetricCard
            label="Projection Last Computed"
            value={data.noiseProjectionLastComputedAt ? new Date(data.noiseProjectionLastComputedAt).toLocaleString() : 'Never'}
          />
          <SummaryMetricCard label="Projection Refresh P95" value={`${noiseProjectionRefreshP95.toFixed(1)} ms`} />
          <SummaryMetricCard label="Projection Refresh Failures" value={noiseProjectionRefreshFailures.toLocaleString()} />
          <SummaryMetricCard label="Summary Model" value={data.summaryReadModelReady ? 'Ready' : 'Rebuilding'} />
          <SummaryMetricCard label="Filter Cache State" value={data.filterCacheActive ? 'Warm' : 'Cold'} />
          <SummaryMetricCard label="Filter Cache Hit Ratio" value={formatPercent(data.filterCacheHitRatioPercent)} />
        </div>
        <EndpointMetricsTable rows={data.endpointMetrics ?? []} />
      </section>
    </div>
  );
}

function renderFreshness(payload: OperationalSectionResponse<OperationalFreshnessDrift>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Data Freshness and Drift</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Data Freshness and Drift</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Stale Threshold (h)" value={(data.staleThresholdHours ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Stale Source Count" value={(data.staleSourceCount ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Normalization Drift (7d)" value={formatPercent(data.normalizationCoverageDrift7d)} />
          <SummaryMetricCard label="CPE Fallback Drift (7d)" value={formatPercent(data.cpeFallbackShareDrift7d)} />
        </div>
        <FreshnessTable rows={data.sourceFreshness ?? []} />
      </section>
    </div>
  );
}

function renderCatalog(payload: OperationalSectionResponse<OperationalMetricDefinition[]>) {
  const data = Array.isArray(payload.data) ? payload.data : [];
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Metric Catalog</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="ops-table">
          <div className="ops-table-header">
            <span>Section</span>
            <span>Key</span>
            <span>Label</span>
            <span>Description</span>
          </div>
          {data.map((metric) => (
            <div key={metric.key} className="ops-table-row ops-table-row-wide">
              <span>{metric.section}</span>
              <span>{metric.key}</span>
              <span>{metric.label}</span>
              <span>{metric.description}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function renderSlo(data: SloStatus) {
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>SLO Status</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  const slos = data.slos ?? [];
  return (
    <div className="page-grid">
      <div className="stats-grid">
        <StatCard title="SLOs Defined" value={slos.length} description={METRIC_HELP['SLOs Defined']} />
        <StatCard title="SLOs Passing" value={slos.filter((s) => s.compliant).length} description={METRIC_HELP['SLOs Passing']} />
        <StatCard title="SLOs Failing" value={slos.filter((s) => !s.compliant).length} tone={slos.some((s) => !s.compliant) ? 'critical' : undefined} description={METRIC_HELP['SLOs Failing']} />
      </div>

      <section className="panel">
        <div className="panel-header">
          <h3>SLO Status <span className={data.overallCompliant ? 'slo-pass' : 'slo-fail'}>{data.overallCompliant ? 'COMPLIANT' : 'NON-COMPLIANT'}</span></h3>
          <span className="panel-caption">Evaluated {new Date(data.evaluatedAt).toLocaleString()}</span>
        </div>
        <div className="ops-table">
          <div className="ops-table-header">
            <span>SLO</span>
            <span>Description</span>
            <span>Window</span>
            <span>Target</span>
            <span>Current</span>
            <span>Status</span>
          </div>
          {slos.map((slo) => (
            <div key={slo.name} className="ops-table-row ops-table-row-wide">
              <span>{slo.name}</span>
              <span>{slo.description}</span>
              <span>{slo.window}</span>
              <span>{slo.target}{slo.unit ? ` ${slo.unit}` : ''}</span>
              <span>{slo.current}{slo.unit ? ` ${slo.unit}` : ''}</span>
              <span className={slo.compliant ? 'slo-pass' : 'slo-fail'}>{slo.compliant ? 'PASS' : 'FAIL'}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function renderPipeline(payload: PipelinePayload) {
  const overview = payload.overview.data;
  const correlation = payload.correlation.data;
  const freshness = payload.freshness.data;

  return (
    <div className="page-grid">
      {overview ? (
        <div className="stats-grid">
          <StatCard title="Ingestion Success (24h)" value={Math.round(overview.ingestionSuccessRateLast24h)} caption="Percent" description={METRIC_HELP['Ingestion Success (24h)']} />
          <StatCard title="Normalization Coverage" value={Math.round(overview.normalizationCoveragePercent)} caption="Percent" description={METRIC_HELP['Normalization Coverage']} />
          <StatCard title="Noise Reduction" value={Math.round(overview.correlationNoiseReductionPercent)} caption="Percent filtered" description={METRIC_HELP['Noise Reduction']} />
          <StatCard title="Open Findings" value={correlation?.openFindings ?? 0} description={METRIC_HELP['Open Findings']} />
          <StatCard title="Stale Sources" value={freshness?.staleSourceCount ?? 0} tone={(freshness?.staleSourceCount ?? 0) > 0 ? 'critical' : undefined} description={METRIC_HELP['Stale Sources']} />
        </div>
      ) : null}

      {renderIngestion(payload.ingestion)}
      {renderCsafVexAnalytics(payload.ingestion, payload.dashboard)}
      {renderNormalization(payload.normalization)}
      {renderCorrelation(payload.correlation)}
      {renderCorrelationEfficiency(payload.correlation, payload.dashboard)}
      {renderLifecycle(payload.lifecycle)}
      {renderFreshness(payload.freshness)}
    </div>
  );
}

function renderPlatformHealth(payload: PlatformHealthPayload) {
  const readPath = payload.readPath.data;
  const sloItems = payload.slo?.slos ?? [];

  return (
    <div className="page-grid">
      {readPath ? (
        <div className="stats-grid">
          <StatCard title="Summary Coverage" value={Math.round(readPath.summaryCoveragePercent)} caption="Percent" description={METRIC_HELP['Summary Coverage']} />
          <StatCard
            title="Summary Model"
            value={readPath.summaryReadModelReady ? 1 : 0}
            caption={readPath.summaryReadModelReady ? 'Ready' : 'Rebuilding'}
            tone={readPath.summaryReadModelReady ? undefined : 'critical'}
            description={METRIC_HELP['Summary Model']}
          />
          <StatCard title="Cache Hit Ratio" value={Math.round(readPath.filterCacheHitRatioPercent)} caption="Percent" description={METRIC_HELP['Cache Hit Ratio']} />
          <StatCard title="Failing SLOs" value={sloItems.filter((item) => !item.compliant).length} tone={sloItems.some((item) => !item.compliant) ? 'critical' : undefined} description={METRIC_HELP['Failing SLOs']} />
        </div>
      ) : null}

      {renderReadPath(payload.readPath)}
      {renderSlo(payload.slo)}
      {renderCatalog(payload.catalog)}
    </div>
  );
}

export function OperationalDashboardPage({ selectedView, redirectSearch = '' }: OperationalDashboardPageProps) {
  const normalizedView = normalizeOperationsView(selectedView);
  const operationsViewQuery = useOperationsViewQuery(normalizedView);
  const payload = operationsViewQuery.data ?? null;
  const error = operationsViewQuery.error instanceof Error ? operationsViewQuery.error.message : null;

  if (normalizedView === 'quality') {
    return <Navigate to={`/inventory/manage-software${redirectSearch}`} replace />;
  }

  if (error) {
    if (payload) {
      let content: React.ReactNode;
      switch (normalizedView) {
        case 'pipeline':
          content = renderPipeline(payload as PipelinePayload);
          break;
        case 'platform-health':
          content = renderPlatformHealth(payload as PlatformHealthPayload);
          break;
        default:
          content = renderPipeline(payload as PipelinePayload);
      }

      return (
        <OperationsSectionErrorBoundary viewKey={normalizedView}>
          <div className="page-grid">
            <div className="panel">Operational data may be stale: {error}</div>
            {content}
          </div>
        </OperationsSectionErrorBoundary>
      );
    }

    if (isCreatorAccessError(error)) {
      return (
        <section className="panel">
          <div className="panel-header">
            <h3>Operations Workspace Access Required</h3>
            <span className="panel-caption">Creator mode is enabled on backend</span>
          </div>
          <div className="noise-summary-grid">
            <div className="noise-summary-item">
              <div className="noise-summary-label">Step 1</div>
              <div className="noise-summary-value">
                Use backend env <code>APP_CREATOR_KEY</code>.
              </div>
            </div>
            <div className="noise-summary-item">
              <div className="noise-summary-label">Step 2</div>
              <div className="noise-summary-value">
                Set frontend <code>VITE_CREATOR_KEY</code> to the same value.
              </div>
            </div>
            <div className="noise-summary-item">
              <div className="noise-summary-label">Step 3</div>
              <div className="noise-summary-value">Restart backend and frontend.</div>
            </div>
          </div>
        </section>
      );
    }
    return <div className="panel">Failed to load operational section: {error}</div>;
  }

  if (!payload) {
    return <div className="panel">Loading operational section...</div>;
  }

  let content: React.ReactNode;
  switch (normalizedView) {
    case 'pipeline':
      content = renderPipeline(payload as PipelinePayload);
      break;
    case 'platform-health':
      content = renderPlatformHealth(payload as PlatformHealthPayload);
      break;
    default:
      content = renderPipeline(payload as PipelinePayload);
  }

  return (
    <OperationsSectionErrorBoundary viewKey={normalizedView}>
      <div className="ops-context-bar">
        <span className="ops-context-label">Operations</span>
        <span className="ops-context-view">{normalizedView === 'pipeline' ? 'Pipeline Analytics' : 'Platform Health'}</span>
      </div>
      {content}
    </OperationsSectionErrorBoundary>
  );
}
