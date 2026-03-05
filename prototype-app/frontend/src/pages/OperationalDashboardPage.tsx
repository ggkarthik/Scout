import React from 'react';
import { api } from '../api/client';
import {
  OperationalDashboard,
  OperationalEndpointMetric,
  OperationalIngestionSourceMetric,
  OperationalSourceFreshness,
  TopFindingMetric
} from '../types';
import { StatCard } from '../components/StatCard';

function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
}

function isCreatorAccessError(error: string): boolean {
  const normalized = error.toLowerCase();
  return normalized.includes("403") || normalized.includes("forbidden");
}

function MetricDistribution({ title, items, emptyLabel }: { title: string; items: TopFindingMetric[]; emptyLabel: string }) {
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

function IngestionSourceTable({ rows }: { rows: OperationalIngestionSourceMetric[] }) {
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

function FreshnessTable({ rows }: { rows: OperationalSourceFreshness[] }) {
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

function EndpointMetricsTable({ rows }: { rows: OperationalEndpointMetric[] }) {
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

export function OperationalDashboardPage() {
  const [data, setData] = React.useState<OperationalDashboard | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const response = await api.getOperationalDashboard();
        if (!cancelled) {
          setData(response);
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
  }, []);

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
    return <div className="panel">Failed to load operational dashboard: {error}</div>;
  }
  if (!data) {
    return <div className="panel">Loading operational dashboard...</div>;
  }

  return (
    <div className="page-grid">
      <div className="stats-grid">
        <StatCard title="Ingestion Success (24h)" value={Math.round(data.executiveHealth.ingestionSuccessRateLast24h)} caption="Percent" />
        <StatCard title="Recompute P95 (ms)" value={Math.round(data.executiveHealth.recomputeP95Ms)} />
        <StatCard title="Normalization Coverage" value={Math.round(data.executiveHealth.normalizationCoveragePercent)} caption="Percent" />
        <StatCard title="Noise Reduction" value={Math.round(data.executiveHealth.correlationNoiseReductionPercent)} caption="Percent filtered" />
        <StatCard title="Open Critical" value={data.executiveHealth.openCriticalFindings} tone="critical" />
        <StatCard title="Stale Sources" value={data.freshnessDrift.staleSourceCount} tone="warn" />
      </div>

      <section className="panel">
        <div className="panel-header">
          <h3>Ingestion Efficiency</h3>
          <span className="panel-caption">Last updated {new Date(data.generatedAt).toLocaleString()}</span>
        </div>
        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM Ingestions (24h)</div>
            <div className="noise-summary-value">{data.ingestionEfficiency.sbomIngestionsLast24h.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM / Hour</div>
            <div className="noise-summary-value">{data.ingestionEfficiency.sbomIngestionsPerHour.toFixed(2)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">SBOM Success Rate</div>
            <div className="noise-summary-value">{formatPercent(data.ingestionEfficiency.sbomSuccessRatePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Sync Success Rate</div>
            <div className="noise-summary-value">{formatPercent(data.ingestionEfficiency.syncSuccessRatePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Queue Backlog</div>
            <div className="noise-summary-value">{data.ingestionEfficiency.queueBacklog.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Fetched</div>
            <div className="noise-summary-value">{data.ingestionEfficiency.recordsFetchedLast24h.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Inserted</div>
            <div className="noise-summary-value">{data.ingestionEfficiency.recordsInsertedLast24h.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Records Updated</div>
            <div className="noise-summary-value">{data.ingestionEfficiency.recordsUpdatedLast24h.toLocaleString()}</div>
          </div>
        </div>
        <IngestionSourceTable rows={data.ingestionEfficiency.sourceBreakdown} />
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Normalization Quality</h3>
          <span className="panel-caption">Coverage on active inventory components</span>
        </div>
        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">Active Components</div>
            <div className="noise-summary-value">{data.normalizationQuality.activeComponents.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Name Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.normalizationQuality.normalizedNameCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Version Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.normalizationQuality.normalizedVersionCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Identity Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.normalizationQuality.softwareIdentityCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Model Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.normalizationQuality.softwareModelCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Unresolved Models</div>
            <div className="noise-summary-value">{data.normalizationQuality.unresolvedModelCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Unresolved Rate</div>
            <div className="noise-summary-value">{formatPercent(data.normalizationQuality.unresolvedModelRatePercent)}</div>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Correlation Effectiveness</h3>
          <span className="panel-caption">Method mix and decision confidence for current findings</span>
        </div>
        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">Open Findings</div>
            <div className="noise-summary-value">{data.correlationEffectiveness.openFindings.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">High Confidence Affected</div>
            <div className="noise-summary-value">{formatPercent(data.correlationEffectiveness.highConfidenceAffectedRatePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Unknown Decision Rate</div>
            <div className="noise-summary-value">{formatPercent(data.correlationEffectiveness.unknownDecisionRatePercent)}</div>
          </div>
        </div>
        <div className="noise-panel-grid">
          <MetricDistribution
            title="Selected Method Distribution"
            items={data.correlationEffectiveness.selectedMethodDistribution}
            emptyLabel="No selected method samples yet."
          />
          <MetricDistribution
            title="Decision State Distribution"
            items={data.correlationEffectiveness.decisionStateDistribution}
            emptyLabel="No decision states observed yet."
          />
          <MetricDistribution
            title="Workflow Status Distribution"
            items={data.correlationEffectiveness.workflowStatusDistribution}
            emptyLabel="No workflow states observed yet."
          />
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Noise and Lifecycle</h3>
          <span className="panel-caption">Correlation-filtered findings and lifecycle behavior</span>
        </div>
        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filtered Not Applicable</div>
            <div className="noise-summary-value">{data.noiseLifecycle.totalFilteredNotApplicable.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Never Opened</div>
            <div className="noise-summary-value">{data.noiseLifecycle.neverOpenedNotApplicable.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Auto Resolved</div>
            <div className="noise-summary-value">{data.noiseLifecycle.autoResolvedNotApplicable.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Deferred</div>
            <div className="noise-summary-value">{data.noiseLifecycle.deferredUnderInvestigation.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filtered Rate</div>
            <div className="noise-summary-value">{formatPercent(data.noiseLifecycle.filteredPercentOfPotential)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Reopen Rate</div>
            <div className="noise-summary-value">{formatPercent(data.noiseLifecycle.reopenRatePercent)}</div>
          </div>
        </div>
        <div className="noise-panel-grid">
          <MetricDistribution
            title="Not Applicable Categories"
            items={data.noiseLifecycle.notApplicableCategories}
            emptyLabel="No categories observed yet."
          />
          <MetricDistribution
            title="Auto Resolved Trend (30d)"
            items={data.noiseLifecycle.autoResolvedTrendLast30Days}
            emptyLabel="No trend points yet."
          />
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>API and Read-Path Performance</h3>
          <span className="panel-caption">Operational endpoint behavior and summary-read-model health</span>
        </div>
        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">Canonical CVEs</div>
            <div className="noise-summary-value">{data.apiReadPath.canonicalCveCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Summary CVEs</div>
            <div className="noise-summary-value">{data.apiReadPath.summaryCveCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Summary Coverage</div>
            <div className="noise-summary-value">{formatPercent(data.apiReadPath.summaryCoveragePercent)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Summary Model</div>
            <div className="noise-summary-value">{data.apiReadPath.summaryReadModelReady ? 'Ready' : 'Rebuilding'}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filter Cache State</div>
            <div className="noise-summary-value">{data.apiReadPath.filterCacheActive ? 'Warm' : 'Cold'}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Filter Cache Hit Ratio</div>
            <div className="noise-summary-value">{formatPercent(data.apiReadPath.filterCacheHitRatioPercent)}</div>
          </div>
        </div>
        <EndpointMetricsTable rows={data.apiReadPath.endpointMetrics} />
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Data Freshness and Drift</h3>
          <span className="panel-caption">Drift vs baseline and source staleness threshold tracking</span>
        </div>
        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">Stale Threshold (h)</div>
            <div className="noise-summary-value">{data.freshnessDrift.staleThresholdHours.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Stale Source Count</div>
            <div className="noise-summary-value">{data.freshnessDrift.staleSourceCount.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Normalization Drift (7d)</div>
            <div className="noise-summary-value">{formatPercent(data.freshnessDrift.normalizationCoverageDrift7d)}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CPE Fallback Drift (7d)</div>
            <div className="noise-summary-value">{formatPercent(data.freshnessDrift.cpeFallbackShareDrift7d)}</div>
          </div>
        </div>
        <FreshnessTable rows={data.freshnessDrift.sourceFreshness} />
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Metric Catalog</h3>
          <span className="panel-caption">Temporary developer metric definitions tracked by this workspace</span>
        </div>
        <div className="ops-table">
          <div className="ops-table-header">
            <span>Section</span>
            <span>Key</span>
            <span>Label</span>
            <span>Description</span>
          </div>
          {data.metricCatalog.map((metric) => (
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
