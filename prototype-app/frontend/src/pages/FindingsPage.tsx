import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { pathForFindingDetail } from '../app/routes';
import type { Finding, FindingFilterValues } from '../features/findings/types';
import { FilterBuilder, FilterBuilderCategory, FilterBuilderField } from '../components/FilterBuilder';
import { FilterValueOption, FilterValueSelectCard } from '../components/FilterValueSelectCard';
import { MultiGroupBy, MultiGroupByOption } from '../components/MultiGroupBy';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { StatCard } from '../components/StatCard';
import { ColumnVisibilityToggle, ColumnDef } from '../components/ColumnVisibilityToggle';
import { EolBadge } from '../components/EolBadge';
import { useFindingFiltersQuery, useFindingsQuery } from '../features/findings/queries';

const PAGE_SIZE = 25;
const DEFAULT_MATCH_METHODS: string[] = [];
const DEFAULT_ACTIVE_FILTERS: FindingFilterKey[] = [];

const FINDINGS_COLUMNS: ColumnDef[] = [
  { key: 'vulnerability', label: 'Vulnerability', defaultVisible: true },
  { key: 'asset', label: 'Asset', defaultVisible: true },
  { key: 'package', label: 'Package', defaultVisible: true },
  { key: 'severity', label: 'Severity', defaultVisible: true },
  { key: 'status', label: 'Status', defaultVisible: true },
  { key: 'decision', label: 'Decision', defaultVisible: true },
  { key: 'vex', label: 'VEX', defaultVisible: true },
  { key: 'impact-reason', label: 'Impact Reason', defaultVisible: true },
  { key: 'risk', label: 'Risk', defaultVisible: true },
  { key: 'confidence', label: 'Confidence', defaultVisible: true },
  { key: 'match-method', label: 'Match Method', defaultVisible: true },
  { key: 'kev', label: 'KEV', defaultVisible: true },
  { key: 'eol-status', label: 'EOL Status', defaultVisible: true },
  { key: 'first-observed', label: 'First Observed', defaultVisible: false },
  { key: 'last-observed', label: 'Last Observed', defaultVisible: false },
  { key: 'evidence', label: 'Evidence', defaultVisible: false },
  { key: 'incident-id', label: 'Incident ID', defaultVisible: true },
  { key: 'incident-status', label: 'Incident Status', defaultVisible: true },
];

const COL_VIS_STORAGE_KEY = 'findings-column-visibility';

function loadColumnVisibility(): Set<string> {
  try {
    const raw = localStorage.getItem(COL_VIS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) return new Set(parsed as string[]);
    }
  } catch {
    // ignore
  }
  return new Set(FINDINGS_COLUMNS.filter((c) => c.defaultVisible).map((c) => c.key));
}

type FindingsPageProps = {
  onOpenCveWorkbench?: (vulnerabilityId: string) => void;
};
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

function incidentStatusClass(status: string): string {
  const s = status.toLowerCase();
  if (s === 'resolved' || s === 'closed') return 'severity-low';
  if (s === 'in progress') return 'severity-medium';
  if (s === 'new') return 'severity-info';
  if (s === 'on hold') return 'severity-high';
  if (s === 'canceled') return 'severity-none';
  return 'severity-none';
}

export function FindingsPage({ onOpenCveWorkbench }: FindingsPageProps = {}) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialVulnerabilityId = React.useMemo(() => searchParams.get('vulnerabilityId')?.trim() ?? '', [searchParams]);
  const initialPackageName = React.useMemo(() => searchParams.get('packageName')?.trim() ?? '', [searchParams]);
  const initialStatuses = React.useMemo(
    () => searchParams.getAll('status').map((value) => value.trim()).filter((value) => value.length > 0),
    [searchParams]
  );
  const initialSeverities = React.useMemo(
    () => searchParams.getAll('severity').map((value) => value.trim()).filter((value) => value.length > 0),
    [searchParams]
  );
  const [page, setPage] = React.useState(0);
  const [activeFilters, setActiveFilters] = React.useState<FindingFilterKey[]>(() => {
    const filters = new Set<FindingFilterKey>(DEFAULT_ACTIVE_FILTERS);
    if (initialVulnerabilityId) filters.add('vulnerabilityId');
    if (initialPackageName) filters.add('packageName');
    if (initialStatuses.length > 0) filters.add('status');
    if (initialSeverities.length > 0) filters.add('severity');
    return Array.from(filters);
  });
  const [severities, setSeverities] = React.useState<string[]>(initialSeverities);
  const [statuses, setStatuses] = React.useState<string[]>(initialStatuses);
  const [decisionStates, setDecisionStates] = React.useState<string[]>([]);
  const [matchMethods, setMatchMethods] = React.useState<string[]>(DEFAULT_MATCH_METHODS);
  const [vexStatuses, setVexStatuses] = React.useState<string[]>([]);
  const [vexFreshness, setVexFreshness] = React.useState<string[]>([]);
  const [vexProviders, setVexProviders] = React.useState<string[]>([]);
  const [minConfidence, setMinConfidence] = React.useState(DEFAULT_MIN_CONFIDENCE);
  const [vulnerabilityId, setVulnerabilityId] = React.useState(initialVulnerabilityId);
  const [packageName, setPackageName] = React.useState(initialPackageName);
  const [ecosystem, setEcosystem] = React.useState('');
  const [groupBy, setGroupBy] = React.useState<string[]>([]);
  const [visibleColumns, setVisibleColumns] = React.useState<Set<string>>(loadColumnVisibility);
  const findingFiltersQuery = useFindingFiltersQuery();
  const filterValues: FindingFilterValues = findingFiltersQuery.data ?? DEFAULT_FILTER_VALUES;
  const findingsQuery = useFindingsQuery({
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
  });
  const rows = React.useMemo(() => findingsQuery.data?.items ?? [], [findingsQuery.data?.items]);
  const totalItems = findingsQuery.data?.totalItems ?? 0;
  const totalPages = findingsQuery.data?.totalPages ?? 0;
  const loading = findingsQuery.isLoading || findingsQuery.isFetching;
  const error = findingsQuery.error instanceof Error ? findingsQuery.error.message : '';
  const tableColumns = React.useMemo<DataTableColumn[]>(() => {
    const columns: DataTableColumn[] = [];
    if (visibleColumns.has('vulnerability')) columns.push({ id: 'vulnerability', label: 'Finding ID', header: 'Finding ID', initialSize: 180 });
    if (visibleColumns.has('asset')) columns.push({ id: 'asset', label: 'Asset', header: 'Asset', initialSize: 180 });
    if (visibleColumns.has('package')) columns.push({ id: 'package', label: 'Package', header: 'Package', initialSize: 180 });
    if (visibleColumns.has('severity')) columns.push({ id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 });
    if (visibleColumns.has('status')) columns.push({ id: 'status', label: 'Status', header: 'Status', initialSize: 140 });
    if (visibleColumns.has('decision')) columns.push({ id: 'decision', label: 'Decision', header: 'Decision', initialSize: 140 });
    if (visibleColumns.has('vex')) columns.push({ id: 'vex', label: 'VEX', header: 'VEX', initialSize: 180 });
    if (visibleColumns.has('impact-reason')) columns.push({ id: 'impactReason', label: 'Impact Reason', header: 'Impact Reason', initialSize: 160 });
    if (visibleColumns.has('risk')) columns.push({ id: 'risk', label: 'Risk', header: 'Risk', initialSize: 100 });
    if (visibleColumns.has('confidence')) columns.push({ id: 'confidence', label: 'Confidence', header: 'Confidence', initialSize: 120 });
    if (visibleColumns.has('match-method')) columns.push({ id: 'matchMethod', label: 'Match Method', header: 'Match Method', initialSize: 180 });
    if (visibleColumns.has('kev')) columns.push({ id: 'kev', label: 'KEV', header: 'KEV', initialSize: 80 });
    if (visibleColumns.has('eol-status')) columns.push({ id: 'eolStatus', label: 'EOL Status', header: 'EOL Status', initialSize: 160 });
    if (visibleColumns.has('first-observed')) columns.push({ id: 'firstObserved', label: 'First Observed', header: 'First Observed', initialSize: 180 });
    if (visibleColumns.has('last-observed')) columns.push({ id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 });
    if (visibleColumns.has('evidence')) columns.push({ id: 'evidence', label: 'Evidence', header: 'Evidence', initialSize: 220 });
    if (visibleColumns.has('incident-id')) columns.push({ id: 'incidentId', label: 'Incident ID', header: 'Incident ID', initialSize: 140 });
    if (visibleColumns.has('incident-status')) columns.push({ id: 'incidentStatus', label: 'Incident Status', header: 'Incident Status', initialSize: 140 });
    return columns;
  }, [visibleColumns]);
  const tableRows = React.useMemo<DataTableRow[]>(() => (
    rows.map((row) => ({
      id: row.id,
      cells: {
        vulnerability: {
          content: (
            <>
              <button
                type="button"
                className="finding-id-link mono"
                onClick={() => navigate(pathForFindingDetail(row.displayId || row.id), { state: { finding: row } })}
              >
                {row.displayId || row.id}
              </button>
              {onOpenCveWorkbench ? (
                <button
                  type="button"
                  className="findings-vuln-link-btn"
                  onClick={() => onOpenCveWorkbench(row.vulnerabilityId)}
                >
                  {row.vulnerabilityId}
                </button>
              ) : (
                <div>{row.vulnerabilityId}</div>
              )}
            </>
          ),
          props: { className: 'mono' }
        },
        asset: {
          content: (
            <>
              <div>{row.assetName}</div>
              <div className="panel-caption">{formatLabel(row.assetType)}</div>
            </>
          )
        },
        package: {
          content: (
            <>
              <div>{row.packageName}</div>
              <div className="panel-caption mono">{row.packageVersion}</div>
            </>
          )
        },
        severity: {
          content: (
            <span className={`severity-pill severity-${row.severity.toLowerCase()}`}>
              {row.severity}
            </span>
          )
        },
        status: {
          content: (
            <span className={`status-pill ${statusClass(row.status)}`}>
              {row.status}
            </span>
          )
        },
        decision: { content: <span className="match-pill">{row.decisionState}</span> },
        vex: {
          content: (
            <>
              <div>{row.vexStatus ? formatLabel(row.vexStatus) : '-'}</div>
              <div className="panel-caption">
                {row.vexProvider ? formatLabel(row.vexProvider) : row.vexFreshness ? formatLabel(row.vexFreshness) : '-'}
              </div>
            </>
          )
        },
        impactReason: { content: row.impactReason ? formatLabel(row.impactReason) : '-' },
        risk: { content: row.riskScore.toFixed(2), props: { className: 'confidence-cell' } },
        confidence: { content: `${(row.confidenceScore * 100).toFixed(1)}%`, props: { className: 'confidence-cell' } },
        matchMethod: {
          content: (
            <>
              <span className="match-pill">{matchMethodLabel(row.matchedBy)}</span>
              {row.matchedVexAssertionId && (
                <div className="panel-caption mono">{row.matchedVexAssertionId}</div>
              )}
            </>
          )
        },
        kev: { content: row.inKev ? 'Yes' : 'No' },
        eolStatus: {
          content: (
            <EolBadge
              isEol={row.isEol}
              daysRemaining={row.eolDaysRemaining}
              eolDate={row.eolDate}
            />
          )
        },
        firstObserved: { content: row.firstObservedAt ? new Date(row.firstObservedAt).toLocaleString() : '-' },
        lastObserved: { content: row.lastObservedAt ? new Date(row.lastObservedAt).toLocaleString() : '-' },
        evidence: {
          content: row.evidence ? (
            <details className="evidence-details">
              <summary>View</summary>
              <pre>{row.evidence}</pre>
            </details>
          ) : '-'
        },
        incidentId: {
          content: row.incidentId
            ? <span className="mono" style={{ fontSize: 12 }}>{row.incidentId}</span>
            : <span style={{ color: 'var(--text-muted, #9ca3af)', fontSize: 12 }}>—</span>
        },
        incidentStatus: {
          content: row.incidentStatus
            ? <span className={`severity-pill ${incidentStatusClass(row.incidentStatus)}`}>{row.incidentStatus}</span>
            : <span style={{ color: 'var(--text-muted, #9ca3af)', fontSize: 12 }}>—</span>
        }
      }
    }))
  ), [navigate, onOpenCveWorkbench, rows]);

  function handleColumnVisibilityChange(next: Set<string>): void {
    setVisibleColumns(next);
    localStorage.setItem(COL_VIS_STORAGE_KEY, JSON.stringify(Array.from(next)));
  }

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
  }, []);

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
                    <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M1.5 1.5l7 7M8.5 1.5l-7 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
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
                  <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M1.5 1.5l7 7M8.5 1.5l-7 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
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
                  <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M1.5 1.5l7 7M8.5 1.5l-7 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
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
                  <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M1.5 1.5l7 7M8.5 1.5l-7 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
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
                  <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M1.5 1.5l7 7M8.5 1.5l-7 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
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
              <button className="btn btn-secondary btn-inline" type="button" onClick={() => void findingsQuery.refetch()} disabled={loading}>
                {loading ? 'Refreshing...' : 'Refresh Findings'}
              </button>
            </div>
          </div>
        </div>
      </section>

      <div className="stats-grid">
        <StatCard title="Total Findings" value={totalItems} caption="Across all pages matching current filters" />
        <StatCard title="This Page" value={rows.length} caption={totalItems === 0 ? 'No results' : `Page ${page + 1} of ${totalPages}`} />
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
          <div className="panel-header-actions">
            <span className="panel-caption">
              Showing {totalItems.toLocaleString()} total findings for the current filter set.
            </span>
            <ColumnVisibilityToggle
              columns={FINDINGS_COLUMNS}
              visible={visibleColumns}
              onChange={handleColumnVisibilityChange}
            />
          </div>
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
              <DataTable
                storageKey="findings-table-widths"
                columns={tableColumns}
                rows={tableRows}
                showColumnControls={false}
              />
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
                {totalItems === 0 ? 'No results' : `Page ${page + 1} of ${totalPages}`}
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
