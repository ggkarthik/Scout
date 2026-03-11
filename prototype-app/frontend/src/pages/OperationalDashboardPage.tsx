import React from 'react';
import { api } from '../api/client';

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
  OperationalExecutiveHealth,
  OperationalFreshnessDrift,
  OperationalIngestionEfficiency,
  OperationalIngestionSourceMetric,
  OperationalMetricDefinition,
  OperationalNoiseLifecycle,
  OperationalNormalizationQuality,
  OperationalSectionResponse,
  OperationalSourceFreshness,
  SloStatus,
  TopFindingMetric
} from '../types';
import { StatCard } from '../components/StatCard';

export type OperationsViewKey =
  | 'overview'
  | 'ingestion'
  | 'normalization'
  | 'correlation'
  | 'lifecycle'
  | 'read-path'
  | 'freshness'
  | 'catalog'
  | 'slo';

export const OPERATIONS_NAV_ITEMS: Array<{ key: OperationsViewKey; label: string }> = [
  { key: 'overview', label: 'Dashboard' },
  { key: 'ingestion', label: 'Ingestion' },
  { key: 'normalization', label: 'Normalization' },
  { key: 'correlation', label: 'Correlation' },
  { key: 'lifecycle', label: 'Noise & Lifecycle' },
  { key: 'read-path', label: 'API Read-Path' },
  { key: 'freshness', label: 'Freshness & Drift' },
  { key: 'catalog', label: 'Metric Catalog' },
  { key: 'slo', label: 'SLO Status' }
];

const LEGACY_VIEW_ALIASES: Record<string, OperationsViewKey> = {
  dashboard: 'overview',
  'ingestion-efficiency': 'ingestion',
  'normalization-quality': 'normalization',
  'correlation-effectiveness': 'correlation',
  'noise-lifecycle': 'lifecycle',
  noise: 'lifecycle',
  'api-read-path': 'read-path',
  readPath: 'read-path',
  'freshness-drift': 'freshness',
  'metric-catalog': 'catalog'
};

export function normalizeOperationsView(value: string | null | undefined): OperationsViewKey {
  if (!value) {
    return 'overview';
  }
  if (OPERATIONS_NAV_ITEMS.some((item) => item.key === value)) {
    return value as OperationsViewKey;
  }
  return LEGACY_VIEW_ALIASES[value] ?? 'overview';
}

type OperationalDashboardPageProps = {
  selectedView: OperationsViewKey;
};

const SECTION_DESCRIPTIONS: Record<Exclude<OperationsViewKey, 'overview'>, string> = {
  ingestion: 'SBOM and sync throughput, success rates, and source-by-source run volume.',
  normalization: 'Coverage of normalized names, versions, identities, and model resolution.',
  correlation: 'Finding confidence, selected match methods, and workflow mix.',
  lifecycle: 'False-positive filtering, lifecycle behavior, and reopen patterns.',
  'read-path': 'API latency, summary-read-model health, and cache behavior.',
  freshness: 'Source staleness, normalization drift, and fallback drift over time.',
  catalog: 'Metric definitions tracked by the operations workspace.',
  slo: 'Service level objective compliance for ingestion, queue depth, and queue staleness.'
};

function formatPercent(value: number): string {
  return `${(value ?? 0).toFixed(1)}%`;
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

function renderOverview(payload: OperationalSectionResponse<OperationalExecutiveHealth>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Operations Overview</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <div className="stats-grid">
        <StatCard title="Ingestion Success (24h)" value={Math.round(data.ingestionSuccessRateLast24h)} caption="Percent" />
        <StatCard title="Recompute P95 (ms)" value={Math.round(data.recomputeP95Ms)} />
        <StatCard title="Normalization Coverage" value={Math.round(data.normalizationCoveragePercent)} caption="Percent" />
        <StatCard title="Noise Reduction" value={Math.round(data.correlationNoiseReductionPercent)} caption="Percent filtered" />
        <StatCard title="Open Critical" value={data.openCriticalFindings} tone="critical" />
      </div>

      <section className="panel">
        <div className="panel-header">
          <h3>Operations Overview</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          {Object.entries(SECTION_DESCRIPTIONS).map(([key, description]) => (
            <div key={key} className="noise-summary-item">
              <div className="noise-summary-label">{key.split('-').join(' ')}</div>
              <div className="noise-summary-value">{description}</div>
            </div>
          ))}
        </div>
      </section>
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
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM Ingestions (24h)</div>
            <div className="noise-summary-value">{(data.sbomIngestionsLast24h ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM / Hour</div>
            <div className="noise-summary-value">{(data.sbomIngestionsPerHour ?? 0).toFixed(2)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM Success Rate</div>
            <div className="noise-summary-value">{formatPercent(data.sbomSuccessRatePercent ?? 0)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Sync Success Rate</div>
            <div className="noise-summary-value">{formatPercent(data.syncSuccessRatePercent ?? 0)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Pending Delta Events</div>
            <div className="noise-summary-value">{(data.queueBacklog ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Fetched</div>
            <div className="noise-summary-value">{(data.recordsFetchedLast24h ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Inserted</div>
            <div className="noise-summary-value">{(data.recordsInsertedLast24h ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Updated</div>
            <div className="noise-summary-value">{(data.recordsUpdatedLast24h ?? 0).toLocaleString()}</div>
          </div>
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
          <div className="noise-summary-item">
            <div className="noise-summary-label">Active Components</div>
            <div className="noise-summary-value">{(data.activeComponents ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Name Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.normalizedNameCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Version Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.normalizedVersionCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Identity Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.softwareIdentityCoveragePercent)}</div>
          </div>
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
          <div className="noise-summary-item">
            <div className="noise-summary-label">Open Findings</div>
            <div className="noise-summary-value">{(data.openFindings ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">High Confidence Affected</div>
            <div className="noise-summary-value">{formatPercent(data.highConfidenceAffectedRatePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Unknown Decision Rate</div>
            <div className="noise-summary-value">{formatPercent(data.unknownDecisionRatePercent)}</div>
          </div>
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
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filtered Not Applicable</div>
            <div className="noise-summary-value">{(data.totalFilteredNotApplicable ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Never Opened</div>
            <div className="noise-summary-value">{(data.neverOpenedNotApplicable ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Auto Resolved</div>
            <div className="noise-summary-value">{(data.autoResolvedNotApplicable ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Deferred</div>
            <div className="noise-summary-value">{(data.deferredUnderInvestigation ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filtered Rate</div>
            <div className="noise-summary-value">{formatPercent(data.filteredPercentOfPotential)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Reopen Rate</div>
            <div className="noise-summary-value">{formatPercent(data.reopenRatePercent)}</div>
          </div>
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
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>API and Read-Path Performance</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">Canonical CVEs</div>
            <div className="noise-summary-value">{(data.canonicalCveCount ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Summary CVEs</div>
            <div className="noise-summary-value">{(data.summaryCveCount ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Summary Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.summaryCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Summary Model</div>
            <div className="noise-summary-value">{data.summaryReadModelReady ? 'Ready' : 'Rebuilding'}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filter Cache State</div>
            <div className="noise-summary-value">{data.filterCacheActive ? 'Warm' : 'Cold'}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filter Cache Hit Ratio</div>
            <div className="noise-summary-value">{formatPercent(data.filterCacheHitRatioPercent)}</div>
          </div>
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
          <div className="noise-summary-item">
            <div className="noise-summary-label">Stale Threshold (h)</div>
            <div className="noise-summary-value">{(data.staleThresholdHours ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Stale Source Count</div>
            <div className="noise-summary-value">{(data.staleSourceCount ?? 0).toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Normalization Drift (7d)</div>
            <div className="noise-summary-value">{formatPercent(data.normalizationCoverageDrift7d)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CPE Fallback Drift (7d)</div>
            <div className="noise-summary-value">{formatPercent(data.cpeFallbackShareDrift7d)}</div>
          </div>
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
        <StatCard title="SLOs Defined" value={slos.length} />
        <StatCard title="SLOs Passing" value={slos.filter((s) => s.compliant).length} />
        <StatCard title="SLOs Failing" value={slos.filter((s) => !s.compliant).length} tone={slos.some((s) => !s.compliant) ? 'critical' : undefined} />
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

async function loadOperationsView(selectedView: OperationsViewKey): Promise<unknown> {
  switch (selectedView) {
    case 'overview':
      return api.getOperationalOverview();
    case 'ingestion':
      return api.getOperationalIngestionEfficiency();
    case 'normalization':
      return api.getOperationalNormalizationQuality();
    case 'correlation':
      return api.getOperationalCorrelationEffectiveness();
    case 'lifecycle':
      return api.getOperationalNoiseLifecycle();
    case 'read-path':
      return api.getOperationalApiReadPath();
    case 'freshness':
      return api.getOperationalFreshnessDrift();
    case 'catalog':
      return api.getOperationalMetricCatalog();
    case 'slo':
      return api.getSloStatus();
    default:
      return api.getOperationalOverview();
  }
}

export function OperationalDashboardPage({ selectedView }: OperationalDashboardPageProps) {
  const normalizedView = normalizeOperationsView(selectedView);
  const [payload, setPayload] = React.useState<unknown>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    setPayload(null);
    setError(null);

    const load = async (): Promise<void> => {
      try {
        const response = await loadOperationsView(normalizedView);
        if (!cancelled) {
          setPayload(response);
          setError(null);
        }
      } catch (requestError) {
        if (!cancelled) {
          setError(requestError instanceof Error ? requestError.message : String(requestError));
        }
      }
    };

    void load();
    const intervalId = window.setInterval(() => {
      void load();
    }, 15000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [normalizedView]);

  if (error) {
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
    case 'overview':
      content = renderOverview(payload as OperationalSectionResponse<OperationalExecutiveHealth>);
      break;
    case 'ingestion':
      content = renderIngestion(payload as OperationalSectionResponse<OperationalIngestionEfficiency>);
      break;
    case 'normalization':
      content = renderNormalization(payload as OperationalSectionResponse<OperationalNormalizationQuality>);
      break;
    case 'correlation':
      content = renderCorrelation(payload as OperationalSectionResponse<OperationalCorrelationEffectiveness>);
      break;
    case 'lifecycle':
      content = renderLifecycle(payload as OperationalSectionResponse<OperationalNoiseLifecycle>);
      break;
    case 'read-path':
      content = renderReadPath(payload as OperationalSectionResponse<OperationalApiReadPath>);
      break;
    case 'freshness':
      content = renderFreshness(payload as OperationalSectionResponse<OperationalFreshnessDrift>);
      break;
    case 'catalog':
      content = renderCatalog(payload as OperationalSectionResponse<OperationalMetricDefinition[]>);
      break;
    case 'slo':
      content = renderSlo(payload as SloStatus);
      break;
    default:
      content = renderOverview(payload as OperationalSectionResponse<OperationalExecutiveHealth>);
  }

  return (
    <OperationsSectionErrorBoundary viewKey={normalizedView}>
      {content}
    </OperationsSectionErrorBoundary>
  );
}
