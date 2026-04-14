import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { EolMappingReviewPanel } from '../components/EolMappingReviewPanel';
import type {
  OperationalQualityIssue
} from '../features/operations/types';
import {
  useOperationalQualityFiltersQuery,
  useOperationalQualityIssueDetailQuery,
  useOperationalQualityIssuesQuery,
  useOperationalQualitySummaryQuery
} from '../features/operations/queries';

const PAGE_SIZE = 25;

const DOMAIN_LABELS: Record<string, string> = {
  INGESTION: 'Ingestion',
  NORMALIZATION: 'Normalization',
  CORRELATION: 'Correlation',
  VEX: 'VEX',
  EOL: 'EOL',
  PROJECTION_FRESHNESS: 'Projection/Freshness'
};

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'quality-severity quality-severity-critical',
  HIGH: 'quality-severity quality-severity-high',
  MEDIUM: 'quality-severity quality-severity-medium',
  LOW: 'quality-severity quality-severity-low'
};

function formatLabel(value: string): string {
  return value
    .trim()
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatDomain(value: string): string {
  return DOMAIN_LABELS[value] ?? formatLabel(value);
}

function formatInstant(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function ownerDestination(issue: OperationalQualityIssue): string {
  if (issue.domain === 'INGESTION') return 'Connect';
  if (issue.domain === 'PROJECTION_FRESHNESS') return 'Operations';
  if (issue.domain === 'VEX') return 'CVE Workbench';
  if (issue.domain === 'EOL') {
    return issue.issueType === 'SOFTWARE_IDENTITY_NEEDS_EOL_MAPPING'
      ? 'Operations Quality'
      : issue.primaryLabel
        ? 'Software Identities'
        : 'EOL';
  }
  if (issue.assetType === 'HOST') return 'Hosts';
  return issue.sourceObjectType === 'SOFTWARE_IDENTITY' ? 'Software Identities' : 'Inventory';
}

function scopeLabel(issue: OperationalQualityIssue): string {
  return `${issue.affectedComponentCount} components · ${issue.affectedAssetCount} assets`;
}

function exposureLabel(issue: OperationalQualityIssue): string {
  return `${issue.openFindingCount} findings · ${issue.openVulnerabilityCount} vulns`;
}

function DetailDrawer({
  issueId,
  onClose
}: {
  issueId: string;
  onClose: () => void;
}) {
  const detailQuery = useOperationalQualityIssueDetailQuery(issueId);
  const detail = detailQuery.data ?? null;
  const error = detailQuery.error instanceof Error ? detailQuery.error.message : null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel modal-panel-wide quality-issue-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="panel-header">
          <div>
            <h3>Quality Issue Detail</h3>
            {detail && (
              <>
                <div>{detail.title}</div>
                <div className="panel-caption">
                  {formatDomain(detail.domain)} · {formatLabel(detail.issueType)} · {detail.reasonCode}
                </div>
              </>
            )}
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close quality issue detail">
            x
          </button>
        </div>

        {error && <div className="notice error">Unable to load quality issue detail: {error}</div>}
        {!detail && !error && <div className="notice">Loading quality issue detail...</div>}

        {detail && (
          <div className="quality-drawer-body">
            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">What failed</div>
              <div className="quality-drawer-card-grid">
                <div className="summary-card">
                  <strong>Issue</strong>
                  <span>{detail.title}</span>
                  <span className="panel-caption">{detail.primaryLabel || detail.sourceObjectType}</span>
                </div>
                <div className="summary-card">
                  <strong>Severity</strong>
                  <span className={SEVERITY_CLASS[detail.severity] ?? 'quality-severity'}>{detail.severity}</span>
                  <span className="panel-caption">{detail.affectsActiveFindings ? 'Affects active findings' : 'No active finding impact'}</span>
                </div>
                <div className="summary-card">
                  <strong>Affected scope</strong>
                  <span>{scopeLabel(detail)}</span>
                  <span className="panel-caption">{exposureLabel(detail)}</span>
                </div>
              </div>
            </section>

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">Why it matters</div>
              <p className="quality-drawer-text">{detail.whyThisMatters}</p>
            </section>

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">Affected scope</div>
              <div className="quality-sample-list">
                {detail.sampleRecords.map((sample) => (
                  <div key={`${sample.label}-${sample.primaryValue}`} className="quality-sample-row">
                    <div className="quality-sample-label">{sample.label}</div>
                    <div className="quality-sample-value">{sample.primaryValue}</div>
                    {sample.secondaryValue && <div className="quality-sample-secondary">{sample.secondaryValue}</div>}
                  </div>
                ))}
              </div>
            </section>

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">Evidence</div>
              <pre className="quality-evidence-block">{detail.evidenceJson}</pre>
            </section>

            <section className="quality-drawer-section">
              <div className="quality-drawer-section-title">Go fix it</div>
              <p className="quality-drawer-text">{detail.recommendedAction}</p>
              <div className="button-row quality-drawer-links">
                {detail.drilldownTargets.map((target) => (
                  <a key={`${target.label}-${target.href}`} className="btn btn-secondary" href={target.href}>
                    {target.label}
                  </a>
                ))}
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}

export function OperationsQualityPage() {
  const [searchParams] = useSearchParams();
  const requestedDomainParam = (searchParams.get('domain') ?? '').trim().toUpperCase();
  const requestedDomain = requestedDomainParam in DOMAIN_LABELS ? requestedDomainParam : '';
  const [queryInput, setQueryInput] = React.useState('');
  const [domain, setDomain] = React.useState(requestedDomain);
  const [issueType, setIssueType] = React.useState('');
  const [severity, setSeverity] = React.useState('');
  const [affectsActiveFindings, setAffectsActiveFindings] = React.useState<'all' | 'yes' | 'no'>('all');
  const [assetType, setAssetType] = React.useState('');
  const [sourceSystem, setSourceSystem] = React.useState('');
  const [ecosystem, setEcosystem] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [selectedIssueId, setSelectedIssueId] = React.useState<string | null>(null);
  const query = useDebouncedValue(queryInput.trim());
  const summaryQuery = useOperationalQualitySummaryQuery();
  const filtersQuery = useOperationalQualityFiltersQuery();
  const issuesQuery = useOperationalQualityIssuesQuery({
    domain: domain || undefined,
    issueType: issueType || undefined,
    severity: severity || undefined,
    affectsActiveFindings: affectsActiveFindings === 'all'
      ? undefined
      : affectsActiveFindings === 'yes',
    assetType: assetType ? [assetType as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'] : undefined,
    sourceSystem: sourceSystem ? [sourceSystem] : undefined,
    ecosystem: ecosystem ? [ecosystem] : undefined,
    query: query || undefined,
    page,
    size: PAGE_SIZE
  });
  const summary = summaryQuery.data ?? null;
  const filters = filtersQuery.data ?? null;
  const pageData = issuesQuery.data ?? null;
  const loading = summaryQuery.isLoading || filtersQuery.isLoading || issuesQuery.isLoading || issuesQuery.isFetching;
  const error = issuesQuery.error instanceof Error
    ? issuesQuery.error.message
    : summaryQuery.error instanceof Error
      ? summaryQuery.error.message
      : filtersQuery.error instanceof Error
        ? filtersQuery.error.message
        : null;

  React.useEffect(() => {
    setDomain(requestedDomain);
  }, [requestedDomain]);

  React.useEffect(() => {
    setPage(0);
  }, [domain, issueType, severity, affectsActiveFindings, assetType, sourceSystem, ecosystem, query]);

  const issues = React.useMemo(() => pageData?.items ?? [], [pageData?.items]);
  const eolReviewFilters = React.useMemo(() => ({
    issueType: issueType || undefined,
    severity: severity || undefined,
    affectsActiveFindings: affectsActiveFindings === 'all'
      ? undefined
      : affectsActiveFindings === 'yes',
    assetType: assetType ? [assetType as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'] : undefined,
    sourceSystem: sourceSystem ? [sourceSystem] : undefined,
    ecosystem: ecosystem ? [ecosystem] : undefined,
    query: query || undefined
  }), [affectsActiveFindings, assetType, ecosystem, issueType, query, severity, sourceSystem]);
  const issueColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'issue', label: 'Issue', header: 'Issue', initialSize: 240 },
    { id: 'domain', label: 'Domain', header: 'Domain', initialSize: 140 },
    { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
    { id: 'source', label: 'Source / Object', header: 'Source / Object', initialSize: 220 },
    { id: 'scope', label: 'Affected Scope', header: 'Affected Scope', initialSize: 180 },
    { id: 'exposure', label: 'Open Findings / Vulns', header: 'Open Findings / Vulns', initialSize: 180 },
    { id: 'lastSeen', label: 'Last Seen', header: 'Last Seen', initialSize: 180 },
    { id: 'owner', label: 'Owner', header: 'Owner', initialSize: 140 }
  ], []);
  const issueRows = React.useMemo<DataTableRow[]>(() => (
    issues.map((issue) => ({
      id: issue.id,
      rowProps: {
        className: 'quality-table-row',
        onClick: () => setSelectedIssueId(issue.id)
      },
      cells: {
        issue: {
          content: (
            <button type="button" className="quality-row-button" onClick={() => setSelectedIssueId(issue.id)}>
              <span>{issue.title}</span>
              <span className="panel-caption">{issue.primaryLabel || issue.reasonCode}</span>
            </button>
          )
        },
        domain: { content: formatDomain(issue.domain) },
        severity: {
          content: <span className={SEVERITY_CLASS[issue.severity] ?? 'quality-severity'}>{issue.severity}</span>
        },
        source: {
          content: (
            <div className="software-identity-row-stack">
              <span>{issue.sourceSystem ? formatLabel(issue.sourceSystem) : issue.sourceObjectType}</span>
              <span className="panel-caption">{issue.secondaryLabel || issue.sourceObjectId || '-'}</span>
            </div>
          )
        },
        scope: { content: scopeLabel(issue) },
        exposure: { content: exposureLabel(issue) },
        lastSeen: { content: formatInstant(issue.lastSeenAt) },
        owner: { content: ownerDestination(issue) }
      }
    }))
  ), [issues]);

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>Quality</h3>
          </div>
          {summary && <span className="panel-caption">Last updated {formatInstant(summary.generatedAt)}</span>}
        </div>

        {summary && (
          <>
            <div className="stats-grid quality-stats-grid">
              <div className="summary-card">
                <strong>Total Issues</strong>
                <span>{summary.totalIssues.toLocaleString()}</span>
              </div>
              <div className="summary-card">
                <strong>Critical</strong>
                <span>{summary.criticalIssues.toLocaleString()}</span>
              </div>
              <div className="summary-card">
                <strong>Affecting Findings</strong>
                <span>{summary.affectsActiveFindingsCount.toLocaleString()}</span>
              </div>
              <div className="summary-card">
                <strong>New in 24h</strong>
                <span>{summary.newIssuesLast24h.toLocaleString()}</span>
              </div>
            </div>

            <div className="quality-domain-strip">
              <button
                type="button"
                className={domain === '' ? 'quality-domain-tab active' : 'quality-domain-tab'}
                onClick={() => setDomain('')}
              >
                All
              </button>
              {summary.domainCounts.map((entry) => (
                <button
                  key={entry.domain}
                  type="button"
                  className={domain === entry.domain ? 'quality-domain-tab active' : 'quality-domain-tab'}
                  onClick={() => setDomain(entry.domain)}
                >
                  {formatDomain(entry.domain)} <span>{entry.issueCount}</span>
                </button>
              ))}
            </div>
          </>
        )}

        <div className="toolbar quality-filter-toolbar">
          <label className="software-identity-filter software-identity-filter--search">
            <span className="panel-caption">Search issues</span>
            <input
              value={queryInput}
              onChange={(event) => setQueryInput(event.target.value)}
              placeholder="Title, reason code, label, source"
            />
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Issue Type</span>
            <select value={issueType} onChange={(event) => setIssueType(event.target.value)}>
              <option value="">All Issue Types</option>
              {filters?.issueTypes.map((value) => (
                <option key={value} value={value}>{formatLabel(value)}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Severity</span>
            <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">All Severities</option>
              {filters?.severities.map((value) => (
                <option key={value} value={value}>{formatLabel(value)}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Active Findings</span>
            <select value={affectsActiveFindings} onChange={(event) => setAffectsActiveFindings(event.target.value as 'all' | 'yes' | 'no')}>
              <option value="all">All</option>
              <option value="yes">Affects findings</option>
              <option value="no">No finding impact</option>
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Asset Type</span>
            <select value={assetType} onChange={(event) => setAssetType(event.target.value)}>
              <option value="">All Asset Types</option>
              {filters?.assetTypes.map((value) => (
                <option key={value} value={value}>{formatLabel(value)}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Source</span>
            <select value={sourceSystem} onChange={(event) => setSourceSystem(event.target.value)}>
              <option value="">All Sources</option>
              {filters?.sourceSystems.map((value) => (
                <option key={value} value={value}>{formatLabel(value)}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Ecosystem</span>
            <select value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}>
              <option value="">All Ecosystems</option>
              {filters?.ecosystems.map((value) => (
                <option key={value} value={value}>{formatLabel(value)}</option>
              ))}
            </select>
          </label>
        </div>

        {domain === 'EOL' ? (
          <EolMappingReviewPanel qualityFilters={eolReviewFilters} />
        ) : (
          <>
            {error && <div className="notice error">Failed to load quality issues: {error}</div>}
            {loading && !pageData && <div className="notice">Loading quality issues...</div>}

            {!loading && issues.length === 0 && !error && (
              <div className="empty-state">
                <p>No quality issues match the current filters.</p>
              </div>
            )}

            {issues.length > 0 && (
              <>
                <div className="table-scroll">
                  <DataTable
                    storageKey="operations-quality-issues"
                    columns={issueColumns}
                    rows={issueRows}
                  />
                </div>

                <div className="pagination quality-pagination">
                  <button type="button" onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={page === 0}>
                    Previous
                  </button>
                  <span>
                    Page {(pageData?.page ?? 0) + 1} of {Math.max(1, pageData?.totalPages ?? 1)}
                  </span>
                  <button
                    type="button"
                    onClick={() => setPage((current) => (pageData && current + 1 < pageData.totalPages ? current + 1 : current))}
                    disabled={!pageData || page + 1 >= pageData.totalPages}
                  >
                    Next
                  </button>
                </div>
              </>
            )}
          </>
        )}
      </section>

      {selectedIssueId && <DetailDrawer issueId={selectedIssueId} onClose={() => setSelectedIssueId(null)} />}
    </div>
  );
}
