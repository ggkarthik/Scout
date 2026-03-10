import React from 'react';
import { api } from '../api/client';
import {
  ApplicableSoftwarePage,
  Dashboard,
  DashboardCveInventoryMap,
  ImpactedCvePage
} from '../types';
import { StatCard } from '../components/StatCard';

function formatDateTime(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '-';
  }
  return parsed.toLocaleString();
}

function summarizeList(values: string[], maxItems = 3): string {
  if (!values || values.length === 0) {
    return '-';
  }
  if (values.length <= maxItems) {
    return values.join(', ');
  }
  return `${values.slice(0, maxItems).join(', ')} +${values.length - maxItems} more`;
}

function severityClassName(severity?: string): string {
  const normalized = (severity ?? '').trim().toLowerCase();
  if (normalized === 'critical') {
    return 'severity-pill severity-critical';
  }
  if (normalized === 'high') {
    return 'severity-pill severity-high';
  }
  if (normalized === 'medium') {
    return 'severity-pill severity-medium';
  }
  return 'severity-pill severity-low';
}

function formatEpss(value?: number): string {
  if (value == null) {
    return '-';
  }
  if (value <= 1) {
    return `${(value * 100).toFixed(2)}%`;
  }
  return `${value.toFixed(2)}%`;
}

export function DashboardPage() {
  const [data, setData] = React.useState<Dashboard | null>(null);
  const [applicableSoftware, setApplicableSoftware] = React.useState<ApplicableSoftwarePage | null>(null);
  const [impactedCves, setImpactedCves] = React.useState<ImpactedCvePage | null>(null);
  const [cveInventoryMap, setCveInventoryMap] = React.useState<DashboardCveInventoryMap | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let active = true;

    api.getDashboard()
      .then(d => { if (active) setData(d); })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : String(e)); });

    api.listApplicableSoftware({ page: 0, size: 10 })
      .then(p => { if (active) setApplicableSoftware(p); })
      .catch(() => {});

    api.listImpactedCves({ page: 0, size: 10 })
      .then(p => { if (active) setImpactedCves(p); })
      .catch(() => {});

    api.getCveInventoryMap(5)
      .then(m => { if (active) setCveInventoryMap(m); })
      .catch(() => {});

    return () => {
      active = false;
    };
  }, []);

  if (error) {
    return <div className="panel">Failed to load dashboard: {error}</div>;
  }
  if (!data) {
    return <div className="panel">Loading dashboard...</div>;
  }

  const critical = data.openCritical;
  const high = data.openHigh;
  const medium = data.openMedium;
  const low = data.openLow;
  const maxSeverityCount = Math.max(critical, high, medium, low, 1);
  const avgRisk = data.averageOpenRiskScore;
  const avgConfidence = data.averageOpenConfidenceScore;
  const highConfidenceExposures = data.highConfidenceOpenFindings;
  const securityScore = Math.round(Math.max(0, 100 - (avgRisk / 10) * 100));
  const analytics = data.csafVexAnalytics;
  const correlation = data.correlationEfficiency;
  const staleTrend = analytics?.staleSuppressionsTrendLast30Days ?? [];
  const staleTrendMax = Math.max(1, ...staleTrend.map((point) => point.count));
  const topHighRiskMap = cveInventoryMap?.topHighRisk ?? [];
  const latestMap = cveInventoryMap?.latest ?? [];

  return (
    <div className="page-grid">
      <div className="stats-grid">
        <StatCard title="Assets" value={data.assets} />
        <StatCard title="Installed Components" value={data.components} />
        <StatCard title="Open Exposures" value={data.openFindings} tone="warn" />
        <StatCard title="Critical Exposures" value={data.criticalFindings} tone="critical" />
        <StatCard title="High Confidence" value={highConfidenceExposures} caption="Confidence >= 0.80" />
        <StatCard title="Avg Confidence" value={Math.round(avgConfidence * 100)} caption="Percent confidence" />
      </div>

      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-header">
            <h3>Exposure Severity</h3>
            <span className="panel-caption">Open exposures only</span>
          </div>
          <div className="severity-meter">
            {[
              { label: 'Critical', value: critical, className: 'critical' },
              { label: 'High', value: high, className: 'high' },
              { label: 'Medium', value: medium, className: 'medium' },
              { label: 'Low', value: low, className: 'low' }
            ].map((entry) => (
              <div key={entry.label} className="severity-row">
                <div className="severity-label">{entry.label}</div>
                <div className="severity-bar-track">
                  <div
                    className={`severity-bar severity-bar-${entry.className}`}
                    style={{ width: `${(entry.value / maxSeverityCount) * 100}%` }}
                  />
                </div>
                <div className="severity-value">{entry.value.toLocaleString()}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="panel security-score-panel">
          <div className="panel-header">
            <h3>Security Score</h3>
            <span className="panel-caption">Derived from open exposure risk</span>
          </div>
          <div className="score-gauge-wrap">
            <div className="score-gauge" style={{ ['--score' as string]: `${securityScore}` }}>
              <div className="score-inner">
                <div className="score-value">{securityScore}</div>
                <div className="score-unit">/ 100</div>
              </div>
            </div>
            <div className="score-note">
              Avg risk: {avgRisk.toFixed(2)} | Avg confidence: {(avgConfidence * 100).toFixed(1)}%
            </div>
          </div>
        </section>
      </div>

      <section className="panel csaf-vex-analytics-panel">
        <div className="panel-header">
          <h3>Correlation Efficiency</h3>
          <span className="panel-caption">Coverage, match quality, and finding generation across correlation methods</span>
        </div>

        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">CPE Coverage (Active Components)</div>
            <div className="noise-summary-value">{correlation.cpeCoveragePercent.toFixed(1)}%</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CPE Eligible Components</div>
            <div className="noise-summary-value">{correlation.cpeEligibleActiveComponents.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Open Findings via CPE</div>
            <div className="noise-summary-value">{correlation.openFindingsMatchedByCpe.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Direct vs Fallback</div>
            <div className="noise-summary-value">
              {correlation.openFindingsCpeDirect.toLocaleString()} / {correlation.openFindingsCpeFallback.toLocaleString()}
            </div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Direct Share</div>
            <div className="noise-summary-value">{correlation.cpeDirectSharePercent.toFixed(1)}%</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CPE Created (24h)</div>
            <div className="noise-summary-value">{correlation.cpeFindingsCreatedLast24Hours.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Other Methods Created (24h)</div>
            <div className="noise-summary-value">{correlation.nonCpeFindingsCreatedLast24Hours.toLocaleString()}</div>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Applicable Software</h3>
          <span className="panel-caption">
            {applicableSoftware ? `${applicableSoftware.totalItems.toLocaleString()} components with at least one applicable CVE` : 'Loading...'}
          </span>
        </div>
        {!applicableSoftware ? (
          <div className="panel-caption">Loading...</div>
        ) : applicableSoftware.items.length === 0 ? (
          <div className="panel-caption">No applicable software components found.</div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Software</th>
                  <th>Asset</th>
                  <th>Applicable</th>
                  <th>Impacted</th>
                  <th>No Patch</th>
                  <th>Last Evaluated</th>
                </tr>
              </thead>
              <tbody>
                {applicableSoftware.items.map((row) => (
                  <tr key={row.componentId}>
                    <td>
                      <span className="mono">
                        {row.ecosystem}:{row.packageName}@{row.version}
                      </span>
                    </td>
                    <td>
                      {row.assetName}
                      <div className="panel-caption mono">{row.assetIdentifier}</div>
                    </td>
                    <td>{row.applicableCveCount.toLocaleString()}</td>
                    <td>{row.impactedCveCount.toLocaleString()}</td>
                    <td>{row.noPatchCveCount.toLocaleString()}</td>
                    <td>{formatDateTime(row.lastEvaluatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Impacted CVEs</h3>
          <span className="panel-caption">
            {impactedCves ? `${impactedCves.totalItems.toLocaleString()} CVEs impacted by current inventory and VEX status` : 'Loading...'}
          </span>
        </div>
        {!impactedCves ? (
          <div className="panel-caption">Loading...</div>
        ) : impactedCves.items.length === 0 ? (
          <div className="panel-caption">No impacted CVEs found.</div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>EPSS</th>
                  <th>KEV</th>
                  <th>Impacted Components</th>
                  <th>Impacted Assets</th>
                  <th>No Patch</th>
                  <th>Last Modified</th>
                </tr>
              </thead>
              <tbody>
                {impactedCves.items.map((row) => (
                  <tr key={row.vulnerabilityId}>
                    <td className="mono">{row.externalId}</td>
                    <td>
                      <span className={severityClassName(row.severity)}>{row.severity || 'UNKNOWN'}</span>
                    </td>
                    <td>{row.cvssScore == null ? '-' : row.cvssScore.toFixed(1)}</td>
                    <td>{formatEpss(row.epssScore)}</td>
                    <td>{row.inKev ? 'Yes' : 'No'}</td>
                    <td>{row.impactedComponentCount.toLocaleString()}</td>
                    <td>{row.impactedAssetCount.toLocaleString()}</td>
                    <td>{row.noPatchComponentCount.toLocaleString()}</td>
                    <td>{formatDateTime(row.lastModifiedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Top CVE Inventory Mapping</h3>
          <span className="panel-caption">Identifier-level mapping for top high risk and latest impacted CVEs</span>
        </div>
        {!cveInventoryMap ? (
          <div className="panel-caption">Loading...</div>
        ) : (<div className="noise-panel-grid">
          <div>
            <div className="noise-subtitle">Top 5 High Risk CVEs</div>
            {topHighRiskMap.length === 0 ? (
              <div className="panel-caption">No high-risk impacted CVEs available.</div>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Severity</th>
                      <th>CVSS</th>
                      <th>Matched Identifiers</th>
                      <th>Mapped Software</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topHighRiskMap.map((row) => (
                      <tr key={row.vulnerabilityId}>
                        <td className="mono">{row.externalId}</td>
                        <td>
                          <span className={severityClassName(row.severity)}>{row.severity || 'UNKNOWN'}</span>
                        </td>
                        <td>{row.cvssScore == null ? '-' : row.cvssScore.toFixed(1)}</td>
                        <td className="mono">{summarizeList(row.matchedIdentifiers)}</td>
                        <td title={row.mappedSoftware.join(', ')}>
                          {row.mappedSoftwareCount.toLocaleString()} ({summarizeList(row.mappedSoftware, 2)})
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div>
            <div className="noise-subtitle">Latest 5 Impacted CVEs</div>
            {latestMap.length === 0 ? (
              <div className="panel-caption">No recent impacted CVEs available.</div>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Severity</th>
                      <th>CVSS</th>
                      <th>Matched Identifiers</th>
                      <th>Mapped Software</th>
                    </tr>
                  </thead>
                  <tbody>
                    {latestMap.map((row) => (
                      <tr key={row.vulnerabilityId}>
                        <td className="mono">{row.externalId}</td>
                        <td>
                          <span className={severityClassName(row.severity)}>{row.severity || 'UNKNOWN'}</span>
                        </td>
                        <td>{row.cvssScore == null ? '-' : row.cvssScore.toFixed(1)}</td>
                        <td className="mono">{summarizeList(row.matchedIdentifiers)}</td>
                        <td title={row.mappedSoftware.join(', ')}>
                          {row.mappedSoftwareCount.toLocaleString()} ({summarizeList(row.mappedSoftware, 2)})
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>)}
      </section>

      <section className="panel csaf-vex-analytics-panel">
        <div className="panel-header">
          <h3>CSAF/VEX Quality Analytics</h3>
          <span className="panel-caption">30-day risk exposure and ingestion quality indicators</span>
        </div>

        <div className="noise-summary-grid">
          <div className="noise-summary-item">
            <div className="noise-summary-label">CSAF Normalization Success</div>
            <div className="noise-summary-value">{analytics.csafNormalizationSuccessRate.toFixed(1)}%</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CSAF Partial Failure</div>
            <div className="noise-summary-value">{analytics.csafPartialFailureRate.toFixed(1)}%</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Suppressed by VEX</div>
            <div className="noise-summary-value">{analytics.findingsSuppressedByVex.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Suppressed by Stale VEX</div>
            <div className="noise-summary-value">{analytics.suppressedByStaleVex.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">Under Investigation Aging</div>
            <div className="noise-summary-value">{analytics.underInvestigationAging.toLocaleString()}</div>
          </div>
          <div className="noise-summary-item">
            <div className="noise-summary-label">CSAF Runs (30d)</div>
            <div className="noise-summary-value">{analytics.csafRunsLast30Days.toLocaleString()}</div>
          </div>
        </div>

        <div className="noise-panel-grid">
          <div className="noise-categories">
            <div className="noise-subtitle">VEX Coverage by Provider</div>
            {analytics.vexCoverageByProvider.length === 0 ? (
              <div className="panel-caption">No provider-tagged VEX evidence in current exposure set.</div>
            ) : (
              <div className="noise-category-list">
                {analytics.vexCoverageByProvider.map((entry) => (
                  <div key={entry.key} className="noise-category-row">
                    <div className="noise-category-key">{entry.key}</div>
                    <div className="noise-category-count">{entry.count.toLocaleString()}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="noise-trend">
            <div className="noise-subtitle">30-Day Stale Suppression Trend</div>
            <div className="noise-trend-bars" aria-label="30-day stale suppression trend">
              {staleTrend.map((point) => (
                <div
                  key={point.key}
                  className="noise-trend-bar noise-trend-bar-stale"
                  title={`${point.key}: ${point.count}`}
                  style={{ height: `${Math.max(6, (point.count / staleTrendMax) * 100)}%` }}
                />
              ))}
            </div>
            <div className="noise-trend-footer">
              <span>{staleTrend[0]?.key ?? '-'}</span>
              <span>{staleTrend[staleTrend.length - 1]?.key ?? '-'}</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
