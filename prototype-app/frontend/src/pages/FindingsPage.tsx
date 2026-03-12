import React from 'react';
import { api } from '../api/client';
import { Finding, FindingFilterValues } from '../types';
import { FilterBuilder, FilterBuilderCategory, FilterBuilderField } from '../components/FilterBuilder';
import { FilterValueOption, FilterValueSelectCard } from '../components/FilterValueSelectCard';
import { MultiGroupBy, MultiGroupByOption } from '../components/MultiGroupBy';
import { ResizableTable } from '../components/ResizableTable';
import { StatCard } from '../components/StatCard';

const PAGE_SIZE = 25;
const DEFAULT_MATCH_METHODS: string[] = [];
const DEFAULT_ACTIVE_FILTERS: FindingFilterKey[] = [];
const DEFAULT_MIN_CONFIDENCE = 0.7;

type FindingFilterKey =
  | 'severity'
  | 'status'
  | 'decisionState'
  | 'matchMethod'
  | 'vexStatus'
  | 'vexFreshness'
  | 'vexProvider'
  | 'minConfidence'
  | 'vulnerabilityId'
  | 'packageName'
  | 'ecosystem';

const FINDING_FILTER_CATEGORIES: FilterBuilderCategory[] = [
  { key: 'finding', label: 'Finding' },
  { key: 'correlation', label: 'Correlation' },
  { key: 'vex', label: 'VEX' }
];

const FINDING_FILTER_FIELDS: FilterBuilderField[] = [
  {
    key: 'severity',
    label: 'Severity',
    categoryKey: 'finding',
    description: 'Filter by vulnerability severity.',
    typeLabel: 'Enum property'
  },
  {
    key: 'status',
    label: 'Workflow Status',
    categoryKey: 'finding',
    description: 'Filter by finding workflow state.',
    typeLabel: 'Enum property'
  },
  {
    key: 'decisionState',
    label: 'Decision State',
    categoryKey: 'finding',
    description: 'Filter by applicability outcome.',
    typeLabel: 'Enum property'
  },
  {
    key: 'matchMethod',
    label: 'Match Method',
    categoryKey: 'correlation',
    description: 'Limit results by the correlation method used to create the finding.',
    typeLabel: 'Enum property'
  },
  {
    key: 'minConfidence',
    label: 'Min Confidence',
    categoryKey: 'correlation',
    description: 'Show findings with confidence at or above threshold.',
    typeLabel: 'Number property'
  },
  {
    key: 'vulnerabilityId',
    label: 'Vulnerability ID',
    categoryKey: 'finding',
    description: 'Search exact vulnerability id (for example CVE-2025-1234).',
    typeLabel: 'String property'
  },
  {
    key: 'packageName',
    label: 'Package Name',
    categoryKey: 'finding',
    description: 'Filter by package name.',
    typeLabel: 'String property'
  },
  {
    key: 'ecosystem',
    label: 'Ecosystem',
    categoryKey: 'finding',
    description: 'Filter by package ecosystem.',
    typeLabel: 'String property'
  },
  {
    key: 'vexStatus',
    label: 'VEX Status',
    categoryKey: 'vex',
    description: 'Filter by parsed VEX statement status.',
    typeLabel: 'Enum property'
  },
  {
    key: 'vexFreshness',
    label: 'VEX Freshness',
    categoryKey: 'vex',
    description: 'Filter by VEX freshness classification.',
    typeLabel: 'Enum property'
  },
  {
    key: 'vexProvider',
    label: 'VEX Provider',
    categoryKey: 'vex',
    description: 'Filter by VEX provider/source.',
    typeLabel: 'Enum property'
  }
];

const GROUP_BY_OPTIONS: MultiGroupByOption[] = [
  { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Workflow Status' },
  { key: 'decisionState', label: 'Decision State' },
  { key: 'assetType', label: 'Asset Type' },
  { key: 'assetName', label: 'Asset Name' },
  { key: 'packageName', label: 'Package Name' },
  { key: 'vulnerabilityId', label: 'Vulnerability ID' },
  { key: 'matchedBy', label: 'Match Method' },
  { key: 'inKev', label: 'KEV' }
];

const DEFAULT_FILTER_VALUES: FindingFilterValues = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'],
  statuses: ['OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'],
  decisionStates: ['AFFECTED', 'NOT_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'NEEDS_REVIEW'],
  matchMethods: DEFAULT_MATCH_METHODS,
  vexStatuses: ['AFFECTED', 'NOT_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'UNKNOWN'],
  vexFreshness: ['FRESH', 'STALE', 'UNKNOWN'],
  vexProviders: ['unknown']
};

function formatLabel(value: string): string {
  const normalized = value.trim().replace(/[_-]+/g, ' ').toLowerCase();
  return normalized.replace(/\b\w/g, (ch) => ch.toUpperCase());
}

function severityTone(value: string): FilterValueOption['tone'] {
  if (value === 'CRITICAL') return 'critical';
  if (value === 'HIGH') return 'high';
  if (value === 'MEDIUM') return 'medium';
  if (value === 'LOW') return 'low';
  return 'neutral';
}

function matchMethodLabel(value: string): string {
  if (value.startsWith('cpe-indexed-direct')) return 'CPE Direct + Version';
  if (value.startsWith('cpe-indexed-fallback')) return 'CPE Fallback + Version';
  if (value.startsWith('cpe-direct')) return 'CPE Direct + Version';
  if (value.startsWith('cpe-fallback')) return 'CPE Fallback + Version';
  if (value.startsWith('purl-indexed-exact')) return 'PURL Exact + Version';
  if (value.startsWith('coord-indexed-exact')) return 'Package Coordinate Exact + Version';
  if (value.startsWith('advisory-pkg-indexed-exact')) return 'Advisory Package Exact + Version';
  if (value.startsWith('manual-org-cve-review')) return 'Manual Org CVE Review';
  return formatLabel(value);
}

function statusClass(status: Finding['status']): string {
  return `status-${status.toLowerCase()}`;
}

function groupValue(row: Finding, key: string): string {
  if (key === 'severity') return row.severity || 'UNKNOWN';
  if (key === 'status') return row.status;
  if (key === 'decisionState') return row.decisionState;
  if (key === 'assetType') return row.assetType;
  if (key === 'assetName') return row.assetName;
  if (key === 'packageName') return row.packageName;
  if (key === 'vulnerabilityId') return row.vulnerabilityId;
  if (key === 'matchedBy') return row.matchedBy || 'unknown';
  if (key === 'inKev') return row.inKev ? 'true' : 'false';
  return 'unknown';
}

export function FindingsPage() {
  const [rows, setRows] = React.useState<Finding[]>([]);
  const [page, setPage] = React.useState(0);
  const [totalItems, setTotalItems] = React.useState(0);
  const [totalPages, setTotalPages] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');

  const [filterValues, setFilterValues] = React.useState<FindingFilterValues>(DEFAULT_FILTER_VALUES);
  const [activeFilters, setActiveFilters] = React.useState<FindingFilterKey[]>(DEFAULT_ACTIVE_FILTERS);
  const [severities, setSeverities] = React.useState<string[]>([]);
  const [statuses, setStatuses] = React.useState<string[]>([]);
  const [decisionStates, setDecisionStates] = React.useState<string[]>([]);
  const [matchMethods, setMatchMethods] = React.useState<string[]>(DEFAULT_MATCH_METHODS);
  const [vexStatuses, setVexStatuses] = React.useState<string[]>([]);
  const [vexFreshness, setVexFreshness] = React.useState<string[]>([]);
  const [vexProviders, setVexProviders] = React.useState<string[]>([]);
  const [minConfidence, setMinConfidence] = React.useState(DEFAULT_MIN_CONFIDENCE);
  const [vulnerabilityId, setVulnerabilityId] = React.useState('');
  const [packageName, setPackageName] = React.useState('');
  const [ecosystem, setEcosystem] = React.useState('');
  const [groupBy, setGroupBy] = React.useState<string[]>([]);
  const loadRequestIdRef = React.useRef(0);

  const severityOptions = React.useMemo<FilterValueOption[]>(
    () => filterValues.severities.map((value) => ({ value, label: formatLabel(value), tone: severityTone(value) })),
    [filterValues.severities]
  );
  const statusOptions = React.useMemo<FilterValueOption[]>(
    () => filterValues.statuses.map((value) => ({ value, label: formatLabel(value) })),
    [filterValues.statuses]
  );
  const decisionStateOptions = React.useMemo<FilterValueOption[]>(
    () => filterValues.decisionStates.map((value) => ({ value, label: formatLabel(value) })),
    [filterValues.decisionStates]
  );
  const matchMethodOptions = React.useMemo<FilterValueOption[]>(
    () => filterValues.matchMethods.map((value) => ({ value, label: matchMethodLabel(value) })),
    [filterValues.matchMethods]
  );
  const vexStatusOptions = React.useMemo<FilterValueOption[]>(
    () => filterValues.vexStatuses.map((value) => ({ value, label: formatLabel(value) })),
    [filterValues.vexStatuses]
  );
  const vexFreshnessOptions = React.useMemo<FilterValueOption[]>(
    () => filterValues.vexFreshness.map((value) => ({ value, label: formatLabel(value) })),
    [filterValues.vexFreshness]
  );
  const vexProviderOptions = React.useMemo<FilterValueOption[]>(
    () => filterValues.vexProviders.map((value) => ({ value, label: value })),
    [filterValues.vexProviders]
  );

  const addFilter = React.useCallback((key: FindingFilterKey) => {
    setActiveFilters((current) => (current.includes(key) ? current : [...current, key]));
  }, []);

  const removeFilter = React.useCallback((key: FindingFilterKey) => {
    setActiveFilters((current) => current.filter((item) => item !== key));
    if (key === 'severity') setSeverities([]);
    if (key === 'status') setStatuses([]);
    if (key === 'decisionState') setDecisionStates([]);
    if (key === 'matchMethod') setMatchMethods(DEFAULT_MATCH_METHODS);
    if (key === 'vexStatus') setVexStatuses([]);
    if (key === 'vexFreshness') setVexFreshness([]);
    if (key === 'vexProvider') setVexProviders([]);
    if (key === 'minConfidence') setMinConfidence(DEFAULT_MIN_CONFIDENCE);
    if (key === 'vulnerabilityId') setVulnerabilityId('');
    if (key === 'packageName') setPackageName('');
    if (key === 'ecosystem') setEcosystem('');
    setPage(0);
  }, [filterValues.matchMethods]);

  const clearFilters = React.useCallback(() => {
    setActiveFilters(DEFAULT_ACTIVE_FILTERS);
    setSeverities([]);
    setStatuses([]);
    setDecisionStates([]);
    setMatchMethods(DEFAULT_MATCH_METHODS);
    setVexStatuses([]);
    setVexFreshness([]);
    setVexProviders([]);
    setMinConfidence(DEFAULT_MIN_CONFIDENCE);
    setVulnerabilityId('');
    setPackageName('');
    setEcosystem('');
    setPage(0);
  }, []);

  const loadFindings = React.useCallback(() => {
    const requestId = loadRequestIdRef.current + 1;
    loadRequestIdRef.current = requestId;
    setLoading(true);
    setError('');

    api.listFindings({
      page,
      size: PAGE_SIZE,
      severity: activeFilters.includes('severity') && severities.length > 0 ? severities : undefined,
      status: activeFilters.includes('status') && statuses.length > 0 ? statuses : undefined,
      decisionState: activeFilters.includes('decisionState') && decisionStates.length > 0 ? decisionStates : undefined,
      matchMethod: activeFilters.includes('matchMethod') && matchMethods.length > 0 ? matchMethods : undefined,
      vexStatus: activeFilters.includes('vexStatus') && vexStatuses.length > 0 ? vexStatuses : undefined,
      vexFreshness: activeFilters.includes('vexFreshness') && vexFreshness.length > 0 ? vexFreshness : undefined,
      vexProvider: activeFilters.includes('vexProvider') && vexProviders.length > 0 ? vexProviders : undefined,
      minConfidence: activeFilters.includes('minConfidence') ? minConfidence : undefined,
      vulnerabilityId: activeFilters.includes('vulnerabilityId') ? vulnerabilityId : undefined,
      packageName: activeFilters.includes('packageName') ? packageName : undefined,
      ecosystem: activeFilters.includes('ecosystem') ? ecosystem : undefined
    })
      .then((response) => {
        if (loadRequestIdRef.current !== requestId) return;
        setRows(response.items);
        setTotalItems(response.totalItems);
        setTotalPages(response.totalPages);
      })
      .catch((requestError) => {
        if (loadRequestIdRef.current !== requestId) return;
        setRows([]);
        setTotalItems(0);
        setTotalPages(0);
        setError(requestError instanceof Error ? requestError.message : String(requestError));
      })
      .finally(() => {
        if (loadRequestIdRef.current === requestId) {
          setLoading(false);
        }
      });
  }, [
    page,
    activeFilters,
    severities,
    statuses,
    decisionStates,
    matchMethods,
    vexStatuses,
    vexFreshness,
    vexProviders,
    minConfidence,
    vulnerabilityId,
    packageName,
    ecosystem
  ]);

  React.useEffect(() => {
    api.listFindingFilters()
      .then((values) => {
        setFilterValues({
          severities: values.severities,
          statuses: values.statuses,
          decisionStates: values.decisionStates,
          matchMethods: values.matchMethods,
          vexStatuses: values.vexStatuses,
          vexFreshness: values.vexFreshness,
          vexProviders: values.vexProviders
        });
      })
      .catch(() => {
        setFilterValues(DEFAULT_FILTER_VALUES);
        setMatchMethods(DEFAULT_MATCH_METHODS);
      });
  }, []);

  React.useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  const groupedCards = React.useMemo(() => {
    return groupBy
      .map((key) => {
        const option = GROUP_BY_OPTIONS.find((entry) => entry.key === key);
        if (!option) return null;
        const counts = new Map<string, number>();
        rows.forEach((row) => {
          const value = groupValue(row, key);
          counts.set(value, (counts.get(value) ?? 0) + 1);
        });
        const items = Array.from(counts.entries())
          .sort((left, right) => right[1] - left[1])
          .slice(0, 5);
        return { key, label: option.label, items };
      })
      .filter((entry): entry is { key: string; label: string; items: Array<[string, number]> } => entry != null);
  }, [groupBy, rows]);

  return (
    <div className="page-grid">
      <section className="panel panel-findings-filters">
        <div className="findings-filter-shell">
          <div className="findings-filter-builder-row">
            <FilterBuilder
              categories={FINDING_FILTER_CATEGORIES}
              fields={FINDING_FILTER_FIELDS}
              activeKeys={activeFilters}
              onAddFilter={(key) => addFilter(key as FindingFilterKey)}
            />
            <div className="findings-filter-active-chips">
              {activeFilters.map((key) => {
                let label: string = key;
                if (key === 'severity') label = `Severity${severities.length > 0 ? ` (${severities.length})` : ''}`;
                if (key === 'status') label = `Status${statuses.length > 0 ? ` (${statuses.length})` : ''}`;
                if (key === 'decisionState') label = `Decision${decisionStates.length > 0 ? ` (${decisionStates.length})` : ''}`;
                if (key === 'matchMethod') label = `Match Method${matchMethods.length > 0 ? ` (${matchMethods.length})` : ''}`;
                if (key === 'vexStatus') label = `VEX Status${vexStatuses.length > 0 ? ` (${vexStatuses.length})` : ''}`;
                if (key === 'vexFreshness') label = `VEX Freshness${vexFreshness.length > 0 ? ` (${vexFreshness.length})` : ''}`;
                if (key === 'vexProvider') label = `VEX Provider${vexProviders.length > 0 ? ` (${vexProviders.length})` : ''}`;
                if (key === 'minConfidence') label = `Min Confidence (${Math.round(minConfidence * 100)}%)`;
                if (key === 'vulnerabilityId') label = `Vulnerability ID${vulnerabilityId.trim() ? ' (1)' : ''}`;
                if (key === 'packageName') label = `Package${packageName.trim() ? ' (1)' : ''}`;
                if (key === 'ecosystem') label = `Ecosystem${ecosystem.trim() ? ' (1)' : ''}`;
                return (
                  <button
                    key={key}
                    type="button"
                    className="findings-filter-chip-tag"
                    onClick={() => removeFilter(key)}
                    title="Remove filter"
                  >
                    <span>{label}</span>
                    <span aria-hidden="true">x</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="findings-active-filter-grid">
            {activeFilters.includes('severity') && (
              <FilterValueSelectCard
                label="Severity"
                selectedValues={severities}
                options={severityOptions}
                onChange={(values) => {
                  setSeverities(values);
                  setPage(0);
                }}
                onRemove={() => removeFilter('severity')}
              />
            )}
            {activeFilters.includes('status') && (
              <FilterValueSelectCard
                label="Workflow Status"
                selectedValues={statuses}
                options={statusOptions}
                onChange={(values) => {
                  setStatuses(values);
                  setPage(0);
                }}
                onRemove={() => removeFilter('status')}
              />
            )}
            {activeFilters.includes('decisionState') && (
              <FilterValueSelectCard
                label="Decision State"
                selectedValues={decisionStates}
                options={decisionStateOptions}
                onChange={(values) => {
                  setDecisionStates(values);
                  setPage(0);
                }}
                onRemove={() => removeFilter('decisionState')}
              />
            )}
            {activeFilters.includes('matchMethod') && (
              <FilterValueSelectCard
                label="Match Method"
                selectedValues={matchMethods}
                options={matchMethodOptions}
                onChange={(values) => {
                  setMatchMethods(values);
                  setPage(0);
                }}
                onRemove={() => removeFilter('matchMethod')}
              />
            )}
            {activeFilters.includes('vexStatus') && (
              <FilterValueSelectCard
                label="VEX Status"
                selectedValues={vexStatuses}
                options={vexStatusOptions}
                onChange={(values) => {
                  setVexStatuses(values);
                  setPage(0);
                }}
                onRemove={() => removeFilter('vexStatus')}
              />
            )}
            {activeFilters.includes('vexFreshness') && (
              <FilterValueSelectCard
                label="VEX Freshness"
                selectedValues={vexFreshness}
                options={vexFreshnessOptions}
                onChange={(values) => {
                  setVexFreshness(values);
                  setPage(0);
                }}
                onRemove={() => removeFilter('vexFreshness')}
              />
            )}
            {activeFilters.includes('vexProvider') && (
              <FilterValueSelectCard
                label="VEX Provider"
                selectedValues={vexProviders}
                options={vexProviderOptions}
                onChange={(values) => {
                  setVexProviders(values);
                  setPage(0);
                }}
                onRemove={() => removeFilter('vexProvider')}
              />
            )}
            {activeFilters.includes('minConfidence') && (
              <label className="findings-filter-chip findings-confidence-chip">
                Min Confidence: <strong>{Math.round(minConfidence * 100)}%</strong>
                <button
                  type="button"
                  className="findings-filter-chip-remove"
                  onClick={() => removeFilter('minConfidence')}
                  aria-label="Remove minimum confidence filter"
                >
                  x
                </button>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={minConfidence}
                  onChange={(event) => {
                    setMinConfidence(Number(event.target.value));
                    setPage(0);
                  }}
                />
              </label>
            )}
            {activeFilters.includes('vulnerabilityId') && (
              <label className="findings-filter-chip findings-filter-text-card">Vulnerability ID
                <button
                  type="button"
                  className="findings-filter-chip-remove"
                  onClick={() => removeFilter('vulnerabilityId')}
                  aria-label="Remove vulnerability id filter"
                >
                  x
                </button>
                <input
                  value={vulnerabilityId}
                  onChange={(event) => {
                    setVulnerabilityId(event.target.value);
                    setPage(0);
                  }}
                  placeholder="CVE-2025-1234"
                  className="mono"
                />
              </label>
            )}
            {activeFilters.includes('packageName') && (
              <label className="findings-filter-chip findings-filter-text-card">Package Name
                <button
                  type="button"
                  className="findings-filter-chip-remove"
                  onClick={() => removeFilter('packageName')}
                  aria-label="Remove package filter"
                >
                  x
                </button>
                <input
                  value={packageName}
                  onChange={(event) => {
                    setPackageName(event.target.value);
                    setPage(0);
                  }}
                  placeholder="log4j-core"
                  className="mono"
                />
              </label>
            )}
            {activeFilters.includes('ecosystem') && (
              <label className="findings-filter-chip findings-filter-text-card">Ecosystem
                <button
                  type="button"
                  className="findings-filter-chip-remove"
                  onClick={() => removeFilter('ecosystem')}
                  aria-label="Remove ecosystem filter"
                >
                  x
                </button>
                <input
                  value={ecosystem}
                  onChange={(event) => {
                    setEcosystem(event.target.value);
                    setPage(0);
                  }}
                  placeholder="maven"
                  className="mono"
                />
              </label>
            )}
          </div>

          <div className="findings-groupby-shell">
            <MultiGroupBy
              options={GROUP_BY_OPTIONS}
              value={groupBy}
              onChange={setGroupBy}
              label="GROUP BY"
              placeholder="No secondary grouping"
              allowEmptyPrimary
              emptyPrimaryLabel="Select..."
              showSelectorsByDefault={false}
            />
          </div>

          <div className="findings-filter-row">
            <div className="findings-filter-actions">
              <button className="btn btn-secondary btn-inline" type="button" onClick={clearFilters}>
                Clear Filters
              </button>
              <button className="btn btn-secondary btn-inline" type="button" onClick={loadFindings} disabled={loading}>
                {loading ? 'Refreshing...' : 'Refresh Findings'}
              </button>
            </div>
          </div>
        </div>
      </section>

      <div className="stats-grid">
        <StatCard title="Total Findings" value={totalItems} caption="Across all pages matching current filters" />
        <StatCard title="This Page" value={rows.length} caption={`Page ${totalPages === 0 ? 0 : page + 1} of ${Math.max(totalPages, 1)}`} />
      </div>

      {groupedCards.length > 0 && (
        <section className="panel">
          <div className="panel-header findings-title-row">
            <h3>Group Breakdown</h3>
            <span className="panel-caption">Top values on current page</span>
          </div>
          <div className="findings-widget-grid">
            {groupedCards.map((group) => (
              <div className="findings-widget-card" key={group.key}>
                <div className="findings-widget-title">{group.label}</div>
                <div className="findings-widget-list">
                  {group.items.length === 0 ? (
                    <div className="panel-caption">No rows in current result set.</div>
                  ) : (
                    group.items.map(([value, count]) => (
                      <div className="findings-widget-row" key={`${group.key}:${value}`}>
                        <span>{group.key === 'matchedBy' ? matchMethodLabel(value) : value}</span>
                        <strong>{count.toLocaleString()}</strong>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="panel">
        <div className="panel-header">
          <h3>Correlated Findings</h3>
          <span className="panel-caption">
            Showing {totalItems.toLocaleString()} total findings for the current filter set.
          </span>
        </div>

        {error && <div className="notice error">Failed to load findings: {error}</div>}

        {loading && rows.length === 0 ? (
          <div className="notice">Loading findings...</div>
        ) : rows.length === 0 ? (
          <div className="empty-state">
            <p>No findings matched the current filter set.</p>
          </div>
        ) : (
          <>
            <div className="table-scroll">
              <ResizableTable storageKey="findings-table-widths">
                <thead>
                  <tr>
                    <th>Vulnerability</th>
                    <th>Asset</th>
                    <th>Package</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Decision</th>
                    <th>VEX</th>
                    <th>Impact Reason</th>
                    <th>Risk</th>
                    <th>Confidence</th>
                    <th>Match Method</th>
                    <th>KEV</th>
                    <th>First Observed</th>
                    <th>Last Observed</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.id}>
                      <td className="mono">{row.vulnerabilityId}</td>
                      <td>
                        <div>{row.assetName}</div>
                        <div className="panel-caption">{formatLabel(row.assetType)}</div>
                      </td>
                      <td>
                        <div>{row.packageName}</div>
                        <div className="panel-caption mono">{row.packageVersion}</div>
                      </td>
                      <td>
                        <span className={`severity-pill severity-${row.severity.toLowerCase()}`}>
                          {row.severity}
                        </span>
                      </td>
                      <td>
                        <span className={`status-pill ${statusClass(row.status)}`}>
                          {row.status}
                        </span>
                      </td>
                      <td>
                        <span className="match-pill">{row.decisionState}</span>
                      </td>
                      <td>
                        <div>{row.vexStatus ? formatLabel(row.vexStatus) : '-'}</div>
                        <div className="panel-caption">
                          {row.vexProvider ? formatLabel(row.vexProvider) : row.vexFreshness ? formatLabel(row.vexFreshness) : '-'}
                        </div>
                      </td>
                      <td>{row.impactReason ? formatLabel(row.impactReason) : '-'}</td>
                      <td className="confidence-cell">{row.riskScore.toFixed(2)}</td>
                      <td className="confidence-cell">{(row.confidenceScore * 100).toFixed(1)}%</td>
                      <td>
                        <span className="match-pill">{matchMethodLabel(row.matchedBy)}</span>
                        {row.matchedVexAssertionId && (
                          <div className="panel-caption mono">{row.matchedVexAssertionId}</div>
                        )}
                      </td>
                      <td>{row.inKev ? 'Yes' : 'No'}</td>
                      <td>{row.firstObservedAt ? new Date(row.firstObservedAt).toLocaleString() : '-'}</td>
                      <td>{row.lastObservedAt ? new Date(row.lastObservedAt).toLocaleString() : '-'}</td>
                      <td>
                        {row.evidence ? (
                          <details className="evidence-details">
                            <summary>View</summary>
                            <pre>{row.evidence}</pre>
                          </details>
                        ) : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </ResizableTable>
            </div>
            <div className="pagination-row">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setPage((current) => Math.max(0, current - 1))}
                disabled={page <= 0 || loading}
              >
                Previous
              </button>
              <span className="panel-caption pagination-caption">
                Page {totalPages === 0 ? 0 : page + 1} of {Math.max(totalPages, 1)}
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setPage((current) => (current + 1 < totalPages ? current + 1 : current))}
                disabled={loading || totalPages === 0 || page + 1 >= totalPages}
              >
                Next
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
