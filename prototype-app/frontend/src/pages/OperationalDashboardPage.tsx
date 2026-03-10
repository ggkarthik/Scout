import React from 'react';
import { api } from '../api/client';
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
  | 'catalog';

export const OPERATIONS_NAV_ITEMS: Array<{ key: OperationsViewKey; label: string }> = [
  { key: 'overview', label: 'Dashboard' },
  { key: 'ingestion', label: 'Ingestion' },
  { key: 'normalization', label: 'Normalization' },
  { key: 'correlation', label: 'Correlation' },
  { key: 'lifecycle', label: 'Noise & Lifecycle' },
  { key: 'read-path', label: 'API Read-Path' },
  { key: 'freshness', label: 'Freshness & Drift' },
  { key: 'catalog', label: 'Metric Catalog' }
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
  catalog: 'Metric definitions tracked by the operations workspace.'
};

function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
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
              <div className="noise-summary-label">{key.replace('-', ' ')}</div>
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
            <div className="noise-summary-value">{data.sbomIngestionsLast24h.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM / Hour</div>
            <div className="noise-summary-value">{data.sbomIngestionsPerHour.toFixed(2)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM Success Rate</div>
            <div className="noise-summary-value">{formatPercent(data.sbomSuccessRatePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Sync Success Rate</div>
            <div className="noise-summary-value">{formatPercent(data.syncSuccessRatePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Queue Backlog</div>
            <div className="noise-summary-value">{data.queueBacklog.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Fetched</div>
            <div className="noise-summary-value">{data.recordsFetchedLast24h.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Inserted</div>
            <div className="noise-summary-value">{data.recordsInsertedLast24h.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Updated</div>
            <div className="noise-summary-value">{data.recordsUpdatedLast24h.toLocaleString()}</div>
          </div>
        </div>
        <IngestionSourceTable rows={data.sourceBreakdown} />
      </section>
    </div>
  );
}

function renderNormalization(payload: OperationalSectionResponse<OperationalNormalizationQuality>) {
  const data = payload.data;
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
            <div className="noise-summary-value">{data.activeComponents.toLocaleString()}</div>
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
          <div className="noise-summary-item">
            <div className="noise-summary-label">Model Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.softwareModelCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Unresolved Models</div>
            <div className="noise-summary-value">{data.unresolvedModelCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Unresolved Rate</div>
            <div className="noise-summary-value">{formatPercent(data.unresolvedModelRatePercent)}</div>
          </div>
        </div>
      </section>
    </div>
  );
}

function renderCorrelation(payload: OperationalSectionResponse<OperationalCorrelationEffectiveness>) {
  const data = payload.data;
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
            <div className="noise-summary-value">{data.openFindings.toLocaleString()}</div>
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
            items={data.selectedMethodDistribution}
            emptyLabel="No selected method samples yet."
          />
          <MetricDistribution
            title="Decision State Distribution"
            items={data.decisionStateDistribution}
            emptyLabel="No decision states observed yet."
          />
          <MetricDistribution
            title="Workflow Status Distribution"
            items={data.workflowStatusDistribution}
            emptyLabel="No workflow states observed yet."
          />
        </div>
      </section>
    </div>
  );
}

function renderLifecycle(payload: OperationalSectionResponse<OperationalNoiseLifecycle>) {
  const data = payload.data;
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
            <div className="noise-summary-value">{data.totalFilteredNotApplicable.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Never Opened</div>
            <div className="noise-summary-value">{data.neverOpenedNotApplicable.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Auto Resolved</div>
            <div className="noise-summary-value">{data.autoResolvedNotApplicable.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Deferred</div>
            <div className="noise-summary-value">{data.deferredUnderInvestigation.toLocaleString()}</div>
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
            items={data.notApplicableCategories}
            emptyLabel="No categories observed yet."
          />
        </div>
      </section>
    </div>
  );
}

function renderReadPath(payload: OperationalSectionResponse<OperationalApiReadPath>) {
  const data = payload.data;
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
            <div className="noise-summary-value">{data.canonicalCveCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Summary CVEs</div>
            <div className="noise-summary-value">{data.summaryCveCount.toLocaleString()}</div>
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
        <EndpointMetricsTable rows={data.endpointMetrics} />
      </section>
    </div>
  );
}

function renderFreshness(payload: OperationalSectionResponse<OperationalFreshnessDrift>) {
  const data = payload.data;
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
            <div className="noise-summary-value">{data.staleThresholdHours.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Stale Source Count</div>
            <div className="noise-summary-value">{data.staleSourceCount.toLocaleString()}</div>
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
        <FreshnessTable rows={data.sourceFreshness} />
      </section>
    </div>
  );
}

function renderCatalog(payload: OperationalSectionResponse<OperationalMetricDefinition[]>) {
  const data = payload.data ?? [];
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

  switch (normalizedView) {
    case 'overview':
      return renderOverview(payload as OperationalSectionResponse<OperationalExecutiveHealth>);
    case 'ingestion':
      return renderIngestion(payload as OperationalSectionResponse<OperationalIngestionEfficiency>);
    case 'normalization':
      return renderNormalization(payload as OperationalSectionResponse<OperationalNormalizationQuality>);
    case 'correlation':
      return renderCorrelation(payload as OperationalSectionResponse<OperationalCorrelationEffectiveness>);
    case 'lifecycle':
      return renderLifecycle(payload as OperationalSectionResponse<OperationalNoiseLifecycle>);
    case 'read-path':
      return renderReadPath(payload as OperationalSectionResponse<OperationalApiReadPath>);
    case 'freshness':
      return renderFreshness(payload as OperationalSectionResponse<OperationalFreshnessDrift>);
    case 'catalog':
      return renderCatalog(payload as OperationalSectionResponse<OperationalMetricDefinition[]>);
    default:
      return renderOverview(payload as OperationalSectionResponse<OperationalExecutiveHealth>);
  }
}
