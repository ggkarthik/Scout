import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CVEInvestigationSummary, type InvestigationSummaryInput } from '../components/CVEInvestigationSummary';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoView } from '../app/routes';
import type { CveDetail, CveMatchedSoftware, OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { useCveDetailQuery, useRiskPolicyQuery, useSavedAiSolutionQuery, useSavedInvestigationSummaryQuery, useVulnRepoVulnerabilitiesQuery } from '../features/cve-workbench/queries';
import type { AiSolutionData } from '../features/cve-workbench/api';
import { computeCveRiskScore, computeOrgImpact, riskScoreLabel } from '../lib/riskScoring';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';

const PAGE_SIZE = 25;

const RUNBOOK_TASK_IDS = ['review-asset-inventory', 'find-false-positive', 'end-of-life-analysis', 'solutions', 'installed-patch-info'];
const SEVERITY_FILTER_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const STATUS_FILTER_OPTIONS = ['OPEN', 'IN_PROGRESS', 'NOT_STARTED', 'DONE'];
const RISK_TIER_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Column-level filter types
type IntelColKey = 'cve' | 'severity' | 'cvss' | 'epss' | 'cveRisk' | 'applicable' | 'investigationStatus';
type IntelColFilters = {
  cve: string;
  severity: string[];
  cvss: string;
  epss: string;
  cveRisk: string[];
  applicable: string;
  investigationStatus: string[];
};
const DEFAULT_INTEL_COL_FILTERS: IntelColFilters = {
  cve: '', severity: [], cvss: '', epss: '', cveRisk: [], applicable: '', investigationStatus: [],
};

// Funnel SVG icon used in column headers
const FunnelIcon = ({ active }: { active: boolean }) => (
  <svg viewBox="0 0 12 12" width="11" height="11"
    fill={active ? 'var(--accent,#3b82f6)' : 'currentColor'} aria-hidden="true">
    <path d="M1 2h10l-4 5v3l-2-1V7z" />
  </svg>
);

function getInvestigationStatus(cveId: string): 'not-started' | 'in-progress' | 'done' {
  try {
    const raw = window.localStorage.getItem(`vulnrepo:${cveId}:investigation-runbook`);
    if (!raw) return 'not-started';
    const state = JSON.parse(raw) as { doneTaskIds?: string[] };
    const done = new Set(state.doneTaskIds ?? []);
    if (done.size === 0) return 'not-started';
    if (RUNBOOK_TASK_IDS.every((id) => done.has(id))) return 'done';
    return 'in-progress';
  } catch {
    return 'not-started';
  }
}

function getLocalSummaryMode(cveId: string): 'ai' | 'deterministic' | null {
  try {
    const raw = window.localStorage.getItem(`vulnrepo:${cveId}:ai-summary`);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { mode?: string };
    return parsed.mode === 'ai' ? 'ai' : 'deterministic';
  } catch {
    return null;
  }
}

function parseCsvParam(value: string | null): string[] {
  if (!value) {
    return [];
  }
  return value
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);
}

function serializeCsvParam(values: string[]): string {
  return values.map((value) => value.trim().toUpperCase()).filter(Boolean).join(',');
}

type SoftwareDrawerRow = {
  id: string;
  software: string;
  vendor: string;
  version: string;
};

type DrawerMode = 'metadata' | 'software' | 'summary' | 'ai-solution';

function parseCombinedSearchInput(value: string): { query?: string; software?: string } {
  const normalized = value.trim();
  if (!normalized) {
    return {};
  }
  const parts = normalized
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length >= 2) {
    return {
      query: parts[0] || undefined,
      software: parts.slice(1).join(', ') || undefined,
    };
  }
  return { query: normalized };
}

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

function isApplicableByInventory(record: OrgSpecificCveExposureRecord): boolean {
  return record.matchedSoftwareCount > 0;
}

function cveDisplayStatus(record: OrgSpecificCveExposureRecord): 'NOT_APPLICABLE' | 'NO_IMPACT' | 'REVIEWED' | 'APPLICABLE' {
  if (record.applicability === 'NOT_APPLICABLE' || (record.matchedAssetCount === 0 && record.applicableComponentCount === 0)) {
    return 'NOT_APPLICABLE';
  }
  // No Impact: all findings closed and no remaining open exposure
  if (record.openFindings === 0 && record.impactedComponentCount === 0 && record.underInvestigationComponentCount === 0) {
    return 'NO_IMPACT';
  }
  // Reviewed: investigation workflow marked done (mirrors workbench invDone logic)
  const investigationStatus = getInvestigationStatus(record.externalId);
  if (investigationStatus === 'done') {
    return 'REVIEWED';
  }
  return 'APPLICABLE';
}

function statusForRecord(record: OrgSpecificCveExposureRecord): string {
  return cveDisplayStatus(record);
}

function dashboardFilterLabel(key: string, value: string): string {
  if (key === 'severity') {
    return `Severity: ${value.split(',').map((item) => formatLabel(item)).join(', ')}`;
  }
  if (key === 'exploitOnly' && value === 'true') {
    return 'Exploit: Available';
  }
  if (key === 'inKev' && value === 'true') {
    return 'CISA KEV: Yes';
  }
  if (key === 'createdSinceDays') {
    return `Added: Last ${value} days`;
  }
  if (key === 'software') {
    return `Software: ${value}`;
  }
  if (key === 'softwareScope') {
    return `Software scope: ${formatLabel(value)}`;
  }
  if (key === 'includeAll' && value === 'true') {
    return 'Scope: All tracked CVEs';
  }
  if (key === 'impactedOnly' && value === 'true') {
    return 'Impact: High / Medium / Low';
  }
  if (key === 'hasFindings' && value === 'true') {
    return 'Open Findings: Yes';
  }
  return `${formatLabel(key)}: ${value}`;
}

function buildSoftwareDrawerRows(detail: CveDetail | null): SoftwareDrawerRow[] {
  if (!detail) {
    return [];
  }

  const vendorByPackage = new Map<string, string>();
  (detail.vendorIntelligence ?? []).forEach((entry) => {
    const key = entry.packageName?.trim().toLowerCase();
    if (!key || vendorByPackage.has(key)) {
      return;
    }
    vendorByPackage.set(key, entry.source?.trim() || entry.ecosystem?.trim() || 'Unknown');
  });

  const unique = new Map<string, SoftwareDrawerRow>();
  detail.matchedSoftware.forEach((software: CveMatchedSoftware) => {
    const pkg = software.packageName?.trim() || 'Unknown';
    const version = software.version?.trim() || '-';
    const vendor = software.vexSource?.trim()
      || vendorByPackage.get(pkg.toLowerCase())
      || software.ecosystem?.trim()
      || detail.summary.source?.trim()
      || 'Unknown';
    const key = `${pkg.toLowerCase()}|${version.toLowerCase()}|${vendor.toLowerCase()}`;
    if (!unique.has(key)) {
      unique.set(key, {
        id: key,
        software: pkg,
        vendor,
        version,
      });
    }
  });

  return Array.from(unique.values()).sort((left, right) => (
    left.software.localeCompare(right.software)
    || left.version.localeCompare(right.version)
    || left.vendor.localeCompare(right.vendor)
  ));
}

export function VulnRepoVulnerabilitiesPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = React.useMemo(() => searchParams.get('query')?.trim() ?? '', [searchParams]);
  const initialSeverity = React.useMemo(() => searchParams.get('severity')?.trim() ?? '', [searchParams]);
  const initialStatuses = React.useMemo(() => parseCsvParam(searchParams.get('status')), [searchParams]);
  const initialExploitOnly = React.useMemo(() => searchParams.get('exploitOnly') === 'true', [searchParams]);
  const initialInKev = React.useMemo(() => searchParams.get('inKev') === 'true', [searchParams]);
  const initialCreatedSinceDays = React.useMemo(() => {
    const raw = searchParams.get('createdSinceDays');
    if (!raw) {
      return undefined;
    }
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
  }, [searchParams]);
  const initialSoftware = React.useMemo(() => searchParams.get('software')?.trim() ?? '', [searchParams]);
  const initialSoftwareScope = React.useMemo(() => searchParams.get('softwareScope')?.trim() ?? '', [searchParams]);
  const initialSoftwareIdentityId = React.useMemo(() => searchParams.get('softwareIdentityId')?.trim() ?? '', [searchParams]);
  const initialIncludeAll = React.useMemo(() => searchParams.get('includeAll') === 'true', [searchParams]);
  const initialApplicable = React.useMemo(() => searchParams.get('applicable') === 'true', [searchParams]);
  const initialImpactedOnly = React.useMemo(() => searchParams.get('impactedOnly') === 'true', [searchParams]);
  const initialHasFindings = React.useMemo(() => searchParams.get('hasFindings') === 'true', [searchParams]);
  const [page, setPage] = React.useState(0);
  const [queryInput, setQueryInput] = React.useState(initialQuery);
  const [query, setQuery] = React.useState(initialQuery);
  const [severityFilters, setSeverityFilters] = React.useState<string[]>(parseCsvParam(initialSeverity));
  const [statusFilters, setStatusFilters] = React.useState<string[]>(initialStatuses);
  const [sourceFilter, setSourceFilter] = React.useState<string>('');
  const [selectedSoftwareRecord, setSelectedSoftwareRecord] = React.useState<OrgSpecificCveExposureRecord | null>(null);
  const [drawerMode, setDrawerMode] = React.useState<DrawerMode>('software');
  const [colFilters, setColFilters] = React.useState<IntelColFilters>(DEFAULT_INTEL_COL_FILTERS);
  const [openColFilter, setOpenColFilter] = React.useState<IntelColKey | null>(null);
  const colFilterRef = React.useRef<HTMLDivElement | null>(null);
  const serverSeverityFilter = severityFilters.length === 1 ? severityFilters[0] : undefined;
  const vulnRepoQuery = useVulnRepoVulnerabilitiesQuery({
    page,
    size: PAGE_SIZE,
    query: query || undefined,
    severity: serverSeverityFilter,
    exploitOnly: initialExploitOnly || undefined,
    inKev: initialInKev || undefined,
    createdSinceDays: initialCreatedSinceDays,
    software: initialSoftware || undefined,
    softwareScope: initialSoftwareScope || undefined,
    softwareIdentityId: initialSoftwareIdentityId || undefined,
    // Omit includeAll when applicable filter is active (URL, column filter, or legacy status filter)
    // so the server returns only applicabilityState=APPLICABLE rows
    includeAll: (initialApplicable || initialImpactedOnly || colFilters.applicable === 'YES' || statusFilters.includes('APPLICABLE'))
      ? undefined
      : (initialIncludeAll || undefined),
    impactedOnly: initialImpactedOnly || undefined,
    source: sourceFilter || undefined,
  });
  const policyQuery = useRiskPolicyQuery();
  const items = React.useMemo(() => vulnRepoQuery.data?.items ?? [], [vulnRepoQuery.data?.items]);
  const totalItems = vulnRepoQuery.data?.totalItems ?? 0;
  const totalPages = vulnRepoQuery.data?.totalPages ?? 0;
  const loading = vulnRepoQuery.isLoading || vulnRepoQuery.isFetching;
  const error = vulnRepoQuery.error instanceof Error ? vulnRepoQuery.error.message : '';
  const softwareDetailQuery = useCveDetailQuery(selectedSoftwareRecord?.externalId ?? null);
  const savedSummaryQuery = useSavedInvestigationSummaryQuery(
    drawerMode === 'summary' ? selectedSoftwareRecord?.externalId ?? null : null,
    drawerMode === 'summary'
  );
  const savedAiSolutionQuery = useSavedAiSolutionQuery(
    drawerMode === 'ai-solution' ? selectedSoftwareRecord?.externalId ?? null : null,
    drawerMode === 'ai-solution'
  );
  const softwareRows = React.useMemo(
    () => buildSoftwareDrawerRows(softwareDetailQuery.data ?? null),
    [softwareDetailQuery.data]
  );
  const savedSummaryInput = React.useMemo(
    () => (savedSummaryQuery.data?.input ?? null) as InvestigationSummaryInput | null,
    [savedSummaryQuery.data?.input]
  );

  React.useEffect(() => {
    setQueryInput(initialQuery);
    setQuery(initialQuery);
    setSeverityFilters(parseCsvParam(initialSeverity));
    setStatusFilters(initialStatuses);
    setPage(0);
  }, [initialApplicable, initialImpactedOnly, initialInKev, initialCreatedSinceDays, initialExploitOnly, initialIncludeAll, initialQuery, initialSeverity, initialSoftware, initialSoftwareIdentityId, initialSoftwareScope, initialStatuses]);

  // Reset to page 0 when applicable column filter changes (server query changes)
  React.useEffect(() => {
    setPage(0);
  }, [colFilters.applicable]);

  // Close column filter popover on outside click
  React.useEffect(() => {
    if (!openColFilter) return;
    function handleClick(e: MouseEvent) {
      if (colFilterRef.current && !colFilterRef.current.contains(e.target as Node)) {
        setOpenColFilter(null);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [openColFilter]);

  function hasColFilter(key: IntelColKey): boolean {
    const f = colFilters;
    if (key === 'cve') return f.cve !== '';
    if (key === 'severity') return f.severity.length > 0;
    if (key === 'cvss') return f.cvss !== '';
    if (key === 'epss') return f.epss !== '';
    if (key === 'cveRisk') return f.cveRisk.length > 0;
    if (key === 'applicable') return f.applicable !== '';
    if (key === 'investigationStatus') return f.investigationStatus.length > 0;
    return false;
  }

  function clearColFilter(key: IntelColKey) {
    const empty = ['severity', 'cveRisk', 'investigationStatus'].includes(key) ? [] : '';
    setColFilters((f) => ({ ...f, [key]: empty }));
    setOpenColFilter(null);
  }

  function toggleColArr(key: 'severity' | 'cveRisk' | 'investigationStatus', value: string) {
    setColFilters((f) => {
      const arr = f[key] as string[];
      return { ...f, [key]: arr.includes(value) ? arr.filter((x) => x !== value) : [...arr, value] };
    });
    setPage(0);
  }

  function renderColFilterPopover(colKey: IntelColKey): React.ReactNode {
    if (openColFilter !== colKey) return null;
    const colLabel: Record<IntelColKey, string> = {
      cve: 'Vulnerability ID', severity: 'Severity', cvss: 'CVSS',
      epss: 'EPSS', cveRisk: 'S.AI Risk', applicable: 'Applicable',
      investigationStatus: 'Investigation Status',
    };
    return (
      <div className="fpl-col-filter-popover" ref={colFilterRef}>
        <div className="fpl-col-filter-header">
          <span>{colLabel[colKey]}</span>
          {hasColFilter(colKey) && (
            <button type="button" className="fpl-col-filter-clear" onClick={() => clearColFilter(colKey)}>Clear</button>
          )}
        </div>
        {colKey === 'cve' && (
          <input autoFocus className="fpl-col-filter-input" placeholder="Search CVE ID…"
            value={colFilters.cve}
            onChange={(e) => { setColFilters((f) => ({ ...f, cve: e.target.value })); setPage(0); }} />
        )}
        {colKey === 'severity' && (
          <div className="fpl-col-filter-checks">
            {SEVERITY_FILTER_OPTIONS.map((v) => (
              <label key={v} className="fpl-col-filter-check">
                <input type="checkbox" checked={colFilters.severity.includes(v)} onChange={() => toggleColArr('severity', v)} />
                <span className={severityClassName(v)} style={{ fontSize: 11 }}>{formatLabel(v)}</span>
              </label>
            ))}
          </div>
        )}
        {colKey === 'cvss' && (
          <input autoFocus type="number" min={0} max={10} step={0.1} className="fpl-col-filter-input"
            placeholder="Min CVSS score (0–10)" value={colFilters.cvss}
            onChange={(e) => { setColFilters((f) => ({ ...f, cvss: e.target.value })); setPage(0); }} />
        )}
        {colKey === 'epss' && (
          <input autoFocus type="number" min={0} max={100} step={0.1} className="fpl-col-filter-input"
            placeholder="Min EPSS % (0–100)" value={colFilters.epss}
            onChange={(e) => { setColFilters((f) => ({ ...f, epss: e.target.value })); setPage(0); }} />
        )}
        {colKey === 'cveRisk' && (
          <div className="fpl-col-filter-checks">
            {RISK_TIER_OPTIONS.map((tier) => (
              <label key={tier} className="fpl-col-filter-check">
                <input type="checkbox" checked={colFilters.cveRisk.includes(tier)} onChange={() => toggleColArr('cveRisk', tier)} />
                <span>{formatLabel(tier)}</span>
              </label>
            ))}
          </div>
        )}
        {colKey === 'applicable' && (
          <div className="fpl-col-filter-checks">
            {(['YES', 'NO'] as const).map((v) => (
              <label key={v} className="fpl-col-filter-check">
                <input type="radio" name="intel-applicable-filter"
                  checked={colFilters.applicable === v}
                  onChange={() => { setColFilters((f) => ({ ...f, applicable: f.applicable === v ? '' : v })); setPage(0); }} />
                <span>{v === 'YES' ? 'Applicable (inventory matched)' : 'Not Applicable'}</span>
              </label>
            ))}
          </div>
        )}
        {colKey === 'investigationStatus' && (
          <div className="fpl-col-filter-checks">
            {STATUS_FILTER_OPTIONS.map((v) => (
              <label key={v} className="fpl-col-filter-check">
                <input type="checkbox" checked={colFilters.investigationStatus.includes(v)} onChange={() => toggleColArr('investigationStatus', v)} />
                <span>{formatLabel(v)}</span>
              </label>
            ))}
          </div>
        )}
      </div>
    );
  }

  const filteredItems = React.useMemo(() => (
    items.filter((item) => {
      if (severityFilters.length > 0 && !severityFilters.includes((item.severity || 'UNKNOWN').toUpperCase())) {
        return false;
      }
      // APPLICABLE/NOT_APPLICABLE are not in STATUS_FILTER_OPTIONS; skip them to avoid empty results
      const clientStatusFilters = statusFilters.filter((s) => s !== 'APPLICABLE' && s !== 'NOT_APPLICABLE');
      if (clientStatusFilters.length > 0 && !clientStatusFilters.includes(statusForRecord(item))) {
        return false;
      }
      // Guard: applicable filter is server-side but add client-side guard for items that slip through
      if (initialApplicable && !isApplicableByInventory(item)) {
        return false;
      }
      if (initialHasFindings && item.openFindings === 0) {
        return false;
      }
      // Column-level filters
      if (colFilters.cve && !item.externalId.toLowerCase().includes(colFilters.cve.toLowerCase())) {
        return false;
      }
      if (colFilters.severity.length > 0 && !colFilters.severity.includes((item.severity || 'UNKNOWN').toUpperCase())) {
        return false;
      }
      if (colFilters.cvss !== '') {
        const min = parseFloat(colFilters.cvss);
        if (!Number.isNaN(min) && (item.cvssScore ?? 0) < min) return false;
      }
      if (colFilters.epss !== '') {
        const min = parseFloat(colFilters.epss);
        if (!Number.isNaN(min) && (item.epssScore ?? 0) * 100 < min) return false;
      }
      if (colFilters.cveRisk.length > 0) {
        const r = computeCveRiskScore(item, policyQuery.data);
        if (!colFilters.cveRisk.includes(riskScoreLabel(r.score).toUpperCase())) return false;
      }
      if (colFilters.applicable === 'YES' && !isApplicableByInventory(item)) return false;
      if (colFilters.applicable === 'NO' && isApplicableByInventory(item)) return false;
      if (colFilters.investigationStatus.length > 0 && !colFilters.investigationStatus.includes(statusForRecord(item))) {
        return false;
      }
      return true;
    })
  ), [items, severityFilters, statusFilters, initialApplicable, initialHasFindings, colFilters, policyQuery.data]);

  const writeFilterParams = React.useCallback((updates: {
    severity?: string[];
    status?: string[];
  }) => {
    const nextParams = new URLSearchParams(searchParams);
    const nextSeverity = updates.severity ?? severityFilters;
    const nextStatus = updates.status ?? statusFilters;
    if (nextSeverity.length > 0) {
      nextParams.set('severity', serializeCsvParam(nextSeverity));
    } else {
      nextParams.delete('severity');
    }
    if (nextStatus.length > 0) {
      nextParams.set('status', serializeCsvParam(nextStatus));
    } else {
      nextParams.delete('status');
    }
    setPage(0);
    setSearchParams(nextParams);
  }, [searchParams, setSearchParams, severityFilters, statusFilters]);

  const updateSeverityFilters = React.useCallback((next: string[]) => {
    setSeverityFilters(next);
    writeFilterParams({ severity: next });
  }, [writeFilterParams]);

  const updateStatusFilters = React.useCallback((next: string[]) => {
    setStatusFilters(next);
    writeFilterParams({ status: next });
  }, [writeFilterParams]);

  const tableRows = React.useMemo<DataTableRow[]>(() => (
    filteredItems.map((item) => {
      const applicable = isApplicableByInventory(item);
      return {
        id: item.recordId,
        cells: {
          cve: {
            content: (
              <button
                type="button"
                className="btn-link vuln-repo-cve-link"
                onClick={() => {
                  const base = pathForVulnRepoView('org-cves', item.externalId);
                  const dest = sourceFilter === 'euvd' && item.euvdId
                    ? `${base}?euvdId=${encodeURIComponent(item.euvdId)}`
                    : sourceFilter === 'japan-vulndb' && item.jvndbId
                    ? `${base}?jvndbId=${encodeURIComponent(item.jvndbId)}`
                    : base;
                  navigate(dest);
                }}
              >
                {sourceFilter === 'euvd' && item.euvdId ? (
                  <span className="mono">{item.euvdId}</span>
                ) : sourceFilter === 'japan-vulndb' && item.jvndbId ? (
                  <span className="mono">{item.jvndbId}</span>
                ) : (
                  <>
                    <span className="mono">{item.externalId}</span>
                    {item.euvdId && (
                      <span className="mono euvd-id-badge" title={`EUVD ID: ${item.euvdId}`}>
                        {item.euvdId}
                      </span>
                    )}
                    {item.jvndbId && (
                      <span className="mono euvd-id-badge" title={`JVNDB ID: ${item.jvndbId}`}>
                        {item.jvndbId}
                      </span>
                    )}
                  </>
                )}
              </button>
            ),
          },
          title: {
            content: <div className="org-cve-title-cell">{item.descriptionSnippet?.trim() || item.title}</div>,
          },
          severity: {
            content: <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span>,
          },
          cvss: {
            content: item.cvssScore?.toFixed(1) ?? '-',
          },
          epss: {
            content: item.epssScore != null ? `${(item.epssScore * 100).toFixed(1)}%` : '-',
          },
          ...(() => {
            const r = computeCveRiskScore(item, policyQuery.data);
            const orgImpact = computeOrgImpact(item, r.score, 0);
            const orgImpactStyle: React.CSSProperties =
              orgImpact === 'HIGH'
                ? { background: '#9b233522', color: '#9b2335', border: '1px solid #9b233544' }
                : orgImpact === 'MEDIUM'
                  ? { background: '#b7791f22', color: '#b7791f', border: '1px solid #b7791f44' }
                  : orgImpact === 'LOW'
                    ? { background: '#2d6a4f22', color: '#2d6a4f', border: '1px solid #2d6a4f44' }
                    : { background: 'var(--panel-muted)', color: 'var(--muted)', border: '1px solid var(--border)' };
            const orgImpactLabel = orgImpact === 'NONE' ? 'No' : orgImpact.charAt(0) + orgImpact.slice(1).toLowerCase();
            const cls = `risk-score-badge risk-score-badge--${riskScoreLabel(r.score).toLowerCase()}`;
            return {
              cveRisk: {
                content: (
                  <span className={cls} title={r.topReasons.join(' · ')}>
                    {r.score.toFixed(1)}
                  </span>
                ),
              },
              orgImpact: {
                content: (
                  <span style={{ display: 'inline-block', padding: '2px 10px', borderRadius: 12, fontSize: 11, fontWeight: 700, letterSpacing: '0.04em', ...orgImpactStyle }}>
                    {orgImpactLabel}
                  </span>
                ),
              },
            };
          })(),
          applicable: {
            content: applicable
              ? <span className="status-pill status-open">Yes</span>
              : <span className="status-pill status-suppressed">No</span>,
          },
          investigationStatus: {
            content: (() => {
              const s = cveDisplayStatus(item);
              if (s === 'NOT_APPLICABLE') return <span className="inv-status-badge inv-status-not-started">Not Applicable</span>;
              if (s === 'NO_IMPACT') return <span className="inv-status-badge inv-status-done">No Impact</span>;
              if (s === 'REVIEWED') return <span className="inv-status-badge inv-status-in-progress">Reviewed</span>;
              return <span className="inv-status-badge inv-status-applicable">Applicable</span>;
            })(),
          },
          sources: {
            content: (() => {
              const baseSources = item.sources ?? [];
              const allSources = baseSources.some(s => s.toLowerCase() === 'nvd')
                ? baseSources
                : ['nvd', ...baseSources];
              return (
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {allSources.map((s) => {
                    const label = { nvd: 'NVD', euvd: 'EUVD', ghsa: 'GHSA', kev: 'KEV', 'csaf-redhat': 'Red Hat', 'vex-microsoft': 'Microsoft', advisory: 'Advisory', 'japan-vulndb': 'JVNDB' }[s.toLowerCase()] ?? s;
                    const src = s.toLowerCase();
                    const isEuvd = src === 'euvd';
                    const isJvn = src === 'japan-vulndb';
                    return (
                      <span key={s} style={{
                        display: 'inline-block', padding: '1px 7px', borderRadius: 10, fontSize: 10, fontWeight: 700,
                        background: isEuvd ? '#dbeafe' : isJvn ? '#fef3c7' : '#f1f5f9',
                        color: isEuvd ? '#1d4ed8' : isJvn ? '#92400e' : '#475569',
                        border: isEuvd ? '1px solid #93c5fd' : isJvn ? '1px solid #fcd34d' : '1px solid #e2e8f0',
                      }}>{label}</span>
                    );
                  })}
                </div>
              );
            })(),
          },
          impactedSoftware: {
            content: applicable ? (
              <button
                type="button"
                className="btn-link vuln-repo-software-link"
                onClick={() => {
                  setSelectedSoftwareRecord(item);
                  setDrawerMode('software');
                }}
              >
                {item.matchedSoftwareCount.toLocaleString()}
              </button>
            ) : (
              '0'
            ),
          },
          investigationSummary: {
            content: (() => {
              const localMode = getLocalSummaryMode(item.externalId);
              const hasSummary = item.hasInvestigationSummary || localMode !== null;
              return (hasSummary || item.hasAiSolution) ? (
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                {(item.hasInvestigationSummary || localMode !== null) && (
                  <button
                    type="button"
                    className="btn-link vuln-repo-summary-link"
                    aria-label={`Open investigation summary for ${item.externalId}`}
                    title={`Investigation Summary — ${item.externalId}`}
                    onClick={() => { setSelectedSoftwareRecord(item); setDrawerMode('summary'); }}
                  >
                    {/* Investigation: clipboard/document icon */}
                    <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                      <path
                        d="M7 4h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Zm6 1.5V10h4.5"
                        fill="none" stroke="currentColor" strokeWidth="1.8"
                        strokeLinecap="round" strokeLinejoin="round"
                      />
                      <path d="M9 13h6M9 16h6M9 19h4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                    </svg>
                  </button>
                )}
                {item.hasAiSolution && (
                  <button
                    type="button"
                    className="btn-link vuln-repo-ai-solution-link"
                    aria-label={`Open AI solution for ${item.externalId}`}
                    title={`AI Remediation Solution — ${item.externalId}`}
                    onClick={() => { setSelectedSoftwareRecord(item); setDrawerMode('ai-solution'); }}
                  >
                    {/* AI Solution: sparkle/lightning icon */}
                    <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                      <path
                        d="M13 2L4.5 13.5H11L10 22L19.5 10H13L13 2Z"
                        fill="none" stroke="currentColor" strokeWidth="1.8"
                        strokeLinecap="round" strokeLinejoin="round"
                      />
                    </svg>
                  </button>
                )}
              </div>
              ) : null;
            })(),
          },
          openFindings: {
            content: item.openFindings.toLocaleString(),
          },
          lastEvaluated: {
            content: formatDateTime(item.lastEvaluatedAt),
          },
        },
      };
    })
  ), [filteredItems, navigate, policyQuery.data]);

  const activeChips = React.useMemo<Array<{ label: string; onRemove: () => void }>>(() => {
    const chips: Array<{ label: string; onRemove: () => void }> = [];
    if (initialApplicable) {
      chips.push({
        label: 'Applicable: Yes',
        onRemove: () => {
          const nextParams = new URLSearchParams(searchParams);
          nextParams.delete('applicable');
          setPage(0);
          setSearchParams(nextParams);
        },
      });
    }
    severityFilters.forEach((s) => {
      chips.push({
        label: `Severity: ${formatLabel(s)}`,
        onRemove: () => updateSeverityFilters(severityFilters.filter((x) => x !== s)),
      });
    });
    statusFilters.forEach((s) => {
      chips.push({
        label: `Status: ${formatLabel(s)}`,
        onRemove: () => updateStatusFilters(statusFilters.filter((x) => x !== s)),
      });
    });
    // Column-level filter chips
    if (colFilters.cve) {
      chips.push({ label: `CVE ID: ${colFilters.cve}`, onRemove: () => { setColFilters((f) => ({ ...f, cve: '' })); setPage(0); } });
    }
    colFilters.severity.forEach((s) => {
      chips.push({ label: `Severity: ${formatLabel(s)}`, onRemove: () => { setColFilters((f) => ({ ...f, severity: f.severity.filter((x) => x !== s) })); setPage(0); } });
    });
    if (colFilters.cvss) {
      chips.push({ label: `CVSS ≥ ${colFilters.cvss}`, onRemove: () => { setColFilters((f) => ({ ...f, cvss: '' })); setPage(0); } });
    }
    if (colFilters.epss) {
      chips.push({ label: `EPSS ≥ ${colFilters.epss}%`, onRemove: () => { setColFilters((f) => ({ ...f, epss: '' })); setPage(0); } });
    }
    colFilters.cveRisk.forEach((tier) => {
      chips.push({ label: `S.AI Risk: ${formatLabel(tier)}`, onRemove: () => { setColFilters((f) => ({ ...f, cveRisk: f.cveRisk.filter((x) => x !== tier) })); setPage(0); } });
    });
    if (colFilters.applicable) {
      chips.push({ label: `Applicable: ${colFilters.applicable === 'YES' ? 'Yes' : 'No'}`, onRemove: () => { setColFilters((f) => ({ ...f, applicable: '' })); setPage(0); } });
    }
    colFilters.investigationStatus.forEach((s) => {
      chips.push({ label: `Inv. Status: ${formatLabel(s)}`, onRemove: () => { setColFilters((f) => ({ ...f, investigationStatus: f.investigationStatus.filter((x) => x !== s) })); setPage(0); } });
    });
    if (sourceFilter) {
      chips.push({ label: `Source: ${{ nvd: 'NVD', euvd: 'EUVD', ghsa: 'GHSA', kev: 'KEV', 'csaf-redhat': 'Red Hat', 'vex-microsoft': 'Microsoft', advisory: 'Advisory', 'japan-vulndb': 'JVNDB' }[sourceFilter] ?? sourceFilter}`, onRemove: () => { setSourceFilter(''); setPage(0); } });
    }
    return chips;
  }, [initialApplicable, initialImpactedOnly, initialHasFindings, severityFilters, statusFilters, sourceFilter, colFilters, searchParams, setSearchParams, updateSeverityFilters, updateStatusFilters]);

  const dashboardFilterChips = React.useMemo(() => {
    const keys = ['exploitOnly', 'inKev', 'createdSinceDays', 'software', 'softwareScope', 'includeAll', 'impactedOnly', 'hasFindings'];
    return keys
      .map((key) => {
        const value = searchParams.get(key);
        return value ? { key, label: dashboardFilterLabel(key, value) } : null;
      })
      .filter((item): item is { key: string; label: string } => item != null);
  }, [searchParams]);

  const clearAllFilters = React.useCallback(() => {
    setSeverityFilters([]);
    setStatusFilters([]);
    setColFilters(DEFAULT_INTEL_COL_FILTERS);
    setOpenColFilter(null);
    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete('severity');
    nextParams.delete('status');
    nextParams.delete('applicable');
    nextParams.delete('impactedOnly');
    nextParams.delete('hasFindings');
    setPage(0);
    setSearchParams(nextParams);
  }, [searchParams, setSearchParams]);

  // Column defs with inline filter headers — recreated when filter state changes
  const vuln_repo_columns = React.useMemo<DataTableColumn[]>(() => {
    const filterable = (colKey: IntelColKey, label: string): React.ReactNode => {
      const active = hasColFilter(colKey);
      return (
        <span className="intel-col-header-inner">
          <span className="intel-col-label">{label}</span>
          <button
            type="button"
            className={`fpl-filter-btn${active ? ' fpl-filter-btn--active' : ''}`}
            title={`Filter ${label}`}
            onClick={(e) => { e.stopPropagation(); setOpenColFilter((p) => (p === colKey ? null : colKey)); }}
          >
            <FunnelIcon active={active} />
          </button>
          {openColFilter === colKey && renderColFilterPopover(colKey)}
        </span>
      );
    };
    const relStyle: React.CSSProperties = { position: 'relative' };
    return [
      { id: 'cve', label: 'Vulnerability ID', initialSize: 200, headerProps: { style: relStyle }, header: filterable('cve', 'Vulnerability ID') },
      { id: 'title', label: 'Description', header: 'Description', initialSize: 360 },
      { id: 'severity', label: 'Severity', initialSize: 120, headerProps: { style: relStyle }, header: filterable('severity', 'Severity') },
      { id: 'cvss', label: 'CVSS', initialSize: 90, headerProps: { style: relStyle }, header: filterable('cvss', 'CVSS') },
      { id: 'epss', label: 'EPSS', initialSize: 90, headerProps: { style: relStyle }, header: filterable('epss', 'EPSS') },
      { id: 'cveRisk', label: 'S.AI Risk', initialSize: 100, headerProps: { style: relStyle }, header: filterable('cveRisk', 'S.AI Risk') },
      { id: 'orgImpact', label: 'Impact', header: 'Impact', initialSize: 110 },
      { id: 'applicable', label: 'Applicable', initialSize: 110, headerProps: { style: relStyle }, header: filterable('applicable', 'Applicable') },
      { id: 'investigationStatus', label: 'Investigation Status', initialSize: 170, headerProps: { style: relStyle }, header: filterable('investigationStatus', 'Investigation Status') },
      { id: 'sources', label: 'Source', header: 'Source', initialSize: 160 },
      { id: 'impactedSoftware', label: 'Impacted Software', header: 'Impacted Software', initialSize: 180 },
      { id: 'investigationSummary', label: 'AI Summaries', header: 'AI Summaries', initialSize: 140 },
      { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 120 },
      { id: 'lastEvaluated', label: 'Last Evaluated', header: 'Last Evaluated', initialSize: 180 },
    ];
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openColFilter, colFilters]);

  const updateSearchFilter = React.useCallback((value: string) => {
    setQueryInput(value);
    const parsed = parseCombinedSearchInput(value);
    const nextParams = new URLSearchParams(searchParams);
    if (parsed.query) {
      nextParams.set('query', parsed.query);
    } else {
      nextParams.delete('query');
    }
    if (parsed.software) {
      nextParams.set('software', parsed.software);
    }
    setPage(0);
    setQuery(parsed.query ?? '');
    setSelectedSoftwareRecord(null);
    setDrawerMode('software');
    setSearchParams(nextParams);
  }, [searchParams, setSearchParams]);

  return (
    <section className="panel vuln-repo-vulnerabilities-shell">
      {error && <div className="notice error">Failed to load vuln repo vulnerabilities: {error}</div>}

      <div className="fpl-toolbar vuln-repo-intel-toolbar">
        <div className="fpl-toolbar-left">
          {/* Column-level inline filter: Severity */}
          <label className="vuln-repo-filter-select">
            <span>Severity</span>
            <select
              value=""
              onChange={(event) => {
                const next = event.target.value;
                if (next && !severityFilters.includes(next)) {
                  updateSeverityFilters([...severityFilters, next]);
                }
              }}
            >
              <option value="">Add severity...</option>
              {SEVERITY_FILTER_OPTIONS.map((option) => (
                <option key={option} value={option} disabled={severityFilters.includes(option)}>
                  {formatLabel(option)}
                </option>
              ))}
            </select>
          </label>

          {/* Column-level inline filter: Status */}
          <label className="vuln-repo-filter-select">
            <span>Status</span>
            <select
              value=""
              onChange={(event) => {
                const next = event.target.value;
                if (next && !statusFilters.includes(next)) {
                  updateStatusFilters([...statusFilters, next]);
                }
              }}
            >
              <option value="">Add status...</option>
              {STATUS_FILTER_OPTIONS.map((option) => (
                <option key={option} value={option} disabled={statusFilters.includes(option)}>
                  {formatLabel(option)}
                </option>
              ))}
            </select>
          </label>

          {/* Source filter */}
          <label className="vuln-repo-filter-select">
            <span>Source</span>
            <select
              value={sourceFilter}
              onChange={(e) => { setSourceFilter(e.target.value); setPage(0); }}
            >
              <option value="">All sources</option>
              <option value="nvd">NVD</option>
              <option value="euvd">EUVD</option>
              <option value="japan-vulndb">JVNDB</option>
              <option value="ghsa">GHSA</option>
              <option value="kev">KEV</option>
              <option value="csaf-redhat">Red Hat</option>
              <option value="vex-microsoft">Microsoft</option>
              <option value="advisory">Advisory</option>
            </select>
          </label>

          {/* Active filter chips — one chip per selected value */}
          {(activeChips.length > 0 || dashboardFilterChips.length > 0) && (
            <div className="vuln-repo-intel-chips-row">
              {activeChips.map((chip) => (
                <span key={chip.label} className="fpl-chip">
                  {chip.label}
                  <button type="button" onClick={chip.onRemove} aria-label={`Remove ${chip.label} filter`}>×</button>
                </span>
              ))}
              {dashboardFilterChips.map((chip) => (
                <span key={`${chip.key}:${chip.label}`} className="fpl-chip">
                  {chip.label}
                  <button
                    type="button"
                    onClick={() => {
                      const nextParams = new URLSearchParams(searchParams);
                      nextParams.delete(chip.key);
                      setPage(0);
                      setSearchParams(nextParams);
                    }}
                    aria-label={`Remove ${chip.label} filter`}
                  >
                    ×
                  </button>
                </span>
              ))}
              {activeChips.length + dashboardFilterChips.length > 1 && (
                <button type="button" className="fpl-chip-clear" onClick={clearAllFilters}>Clear all</button>
              )}
            </div>
          )}

          {/* Search — pushed to far right */}
          <div className="vuln-repo-intel-search">
            <label htmlFor="vuln-repo-vuln-search">Search CVE / Description</label>
            <input
              id="vuln-repo-vuln-search"
              value={queryInput}
              onChange={(event) => updateSearchFilter(event.target.value)}
              placeholder="CVE-2026-1526"
            />
          </div>
        </div>
      </div>

      <div className={`vuln-repo-vulnerabilities-layout${selectedSoftwareRecord ? ' is-drawer-open' : ''}`}>
        <div className="table-scroll">
          <DataTable
            storageKey="vuln-repo-vulnerabilities-table-v2"
            columns={vuln_repo_columns}
            rows={tableRows}
          />
        </div>

        {selectedSoftwareRecord ? (
          <aside className="panel detail-panel vuln-repo-software-drawer">
            <div className="panel-header org-cve-drawer-header">
              <div>
                <div className="org-cve-back-link">
                  {drawerMode === 'summary'
                    ? 'Investigation Summary'
                    : drawerMode === 'ai-solution'
                      ? 'AI Remediation Solution'
                      : drawerMode === 'metadata'
                        ? 'CVE Metadata'
                        : 'Impacted Software'}
                </div>
                <h3>{selectedSoftwareRecord.externalId}</h3>
                <span className="panel-caption">
                  {drawerMode === 'summary'
                    ? 'Saved investigation summary for this CVE.'
                    : drawerMode === 'ai-solution'
                    ? 'AI-generated remediation recommendation.'
                    : drawerMode === 'metadata'
                    ? 'Summary and metadata for the selected CVE.'
                    : 'Matched software inventory for this CVE.'}
                </span>
              </div>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setSelectedSoftwareRecord(null)}
                aria-label="Close details panel"
              >
                x
              </button>
            </div>

            {drawerMode === 'summary' ? (
              savedSummaryQuery.isLoading || savedSummaryQuery.isFetching ? (
                <div className="empty-state"><p>Loading saved summary...</p></div>
              ) : savedSummaryQuery.error instanceof Error ? (
                <div className="notice error">{savedSummaryQuery.error.message}</div>
              ) : savedSummaryInput && savedSummaryQuery.data?.summary ? (
                <div className="vuln-repo-summary-shell">
                  <CVEInvestigationSummary
                    visible
                    input={savedSummaryInput}
                    initialSummary={savedSummaryQuery.data.summary}
                    initialMode={savedSummaryQuery.data.mode === 'ai' ? 'ai' : 'deterministic'}
                    autoGenerate={false}
                    readOnly
                  />
                </div>
              ) : (
                <div className="empty-state"><p>No saved investigation summary was found for this CVE.</p></div>
              )
            ) : drawerMode === 'ai-solution' ? (
              savedAiSolutionQuery.isLoading || savedAiSolutionQuery.isFetching ? (
                <div className="empty-state"><p>Loading AI solution...</p></div>
              ) : !savedAiSolutionQuery.data?.success || !savedAiSolutionQuery.data?.data ? (
                <div className="empty-state"><p>No AI solution has been generated yet for this CVE. Open the CVE detail and click Generate AI Recommendation.</p></div>
              ) : (
                <AiSolutionPanel data={savedAiSolutionQuery.data.data} generatedAt={savedAiSolutionQuery.data.generatedAt} />
              )
            ) : softwareDetailQuery.isLoading || softwareDetailQuery.isFetching ? (
              <div className="empty-state"><p>Loading CVE details...</p></div>
            ) : softwareDetailQuery.error instanceof Error ? (
              <div className="notice error">{softwareDetailQuery.error.message}</div>
            ) : drawerMode === 'metadata' ? (
              <div className="vuln-repo-cve-metadata">
                <div className="button-row">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => navigate(pathForVulnRepoView('org-cves', selectedSoftwareRecord.externalId))}
                  >
                    Investigate
                  </button>
                </div>
                <div className="details-grid">
                  <div>
                    <div className="section-subtitle">Title</div>
                    <div>{softwareDetailQuery.data?.summary.title || selectedSoftwareRecord.title}</div>
                  </div>
                  <div>
                    <div className="section-subtitle">Severity</div>
                    <div>{formatLabel(softwareDetailQuery.data?.summary.severity || selectedSoftwareRecord.severity)}</div>
                  </div>
                  <div>
                    <div className="section-subtitle">CVSS</div>
                    <div>{softwareDetailQuery.data?.summary.cvssScore?.toFixed(1) ?? selectedSoftwareRecord.cvssScore?.toFixed(1) ?? '-'}</div>
                  </div>
                  <div>
                    <div className="section-subtitle">EPSS</div>
                    <div>{softwareDetailQuery.data?.summary.epssScore != null ? `${(softwareDetailQuery.data.summary.epssScore * 100).toFixed(2)}%` : '-'}</div>
                  </div>
                  <div>
                    <div className="section-subtitle">Source</div>
                    <div>{softwareDetailQuery.data?.summary.source || '-'}</div>
                  </div>
                  <div>
                    <div className="section-subtitle">Applicable</div>
                    <div>{isApplicableByInventory(selectedSoftwareRecord) ? 'Yes' : 'No'}</div>
                  </div>
                </div>
                <div className="section-subtitle">Description</div>
                <p className="vuln-repo-cve-description">
                  {softwareDetailQuery.data?.summary.description
                    || selectedSoftwareRecord.descriptionSnippet
                    || selectedSoftwareRecord.title}
                </p>
              </div>
            ) : softwareRows.length === 0 ? (
              <div className="empty-state"><p>No matched software was found for this CVE.</p></div>
            ) : (
              <div className="table-scroll">
                <table className="vuln-repo-software-table">
                  <thead>
                    <tr>
                      <th>Software</th>
                      <th>Vendor</th>
                      <th>Version</th>
                    </tr>
                  </thead>
                  <tbody>
                    {softwareRows.map((row) => (
                      <tr key={row.id}>
                        <td>{row.software}</td>
                        <td>{row.vendor}</td>
                        <td className="mono">{row.version}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </aside>
        ) : null}
      </div>

      <div className="pagination-bar">
        <span className="panel-caption">
          {totalItems.toLocaleString()} CVEs
        </span>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={page <= 0 || loading}
            onClick={() => setPage((current) => Math.max(0, current - 1))}
          >
            Previous
          </button>
          <span className="panel-caption">
            Page {totalPages === 0 ? 0 : page + 1} of {totalPages}
          </span>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={loading || totalPages === 0 || page >= totalPages - 1}
            onClick={() => setPage((current) => current + 1)}
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}

function AiSolutionPanel({ data, generatedAt }: { data: AiSolutionData; generatedAt?: string }) {
  const val = (v: string | null | undefined) => (!v || v === 'null' || v === 'N/A') ? null : v;
  const phaseColor = (c: string) => c === 'red' ? '#e53e3e' : c === 'amber' ? '#d97706' : '#16a34a';

  return (
    <div className="ai-sol-panel">
      {generatedAt && (
        <p className="ai-sol-ts">Generated {new Date(generatedAt).toLocaleString()}</p>
      )}
      {data.affected_scope && <p className="ai-sol-scope">{data.affected_scope}</p>}

      {data.bottom_line && (
        <div className="ai-sol-section">
          <p className="ai-sol-section-hdr">The Bottom Line</p>
          <div className="ai-sol-badges">
            {data.bottom_line.severity && (
              <span className={`severity-pill severity-${data.bottom_line.severity.toLowerCase()}`}>{data.bottom_line.severity}</span>
            )}
            {data.bottom_line.cvss && <span className="ai-sol-badge">CVSS {data.bottom_line.cvss}</span>}
            {data.bottom_line.kev_status && <span className="ai-sol-badge">{data.bottom_line.kev_status}</span>}
          </div>
          {data.bottom_line.summary && <p className="ai-sol-text">{data.bottom_line.summary}</p>}
        </div>
      )}

      {data.primary_fix && (() => {
        const patchId = val(data.primary_fix!.patch_id);
        const targetVer = val(data.primary_fix!.target_version);
        return (
          <div className="ai-sol-section">
            <p className="ai-sol-section-hdr">Primary Fix</p>
            <p className="ai-sol-fix-title">
              {val(data.primary_fix.action) ?? 'Apply'}{patchId ? ` — ${patchId}` : ''}
            </p>
            {targetVer && <p className="ai-sol-text"><code>{targetVer}</code></p>}
            {val(data.primary_fix.verification) && (
              <p className="ai-sol-verify">{val(data.primary_fix.verification)}</p>
            )}
          </div>
        );
      })()}

      {data.timeline && data.timeline.length > 0 && (
        <div className="ai-sol-section">
          <p className="ai-sol-section-hdr">Timeline</p>
          {data.timeline.map((t, i) => (
            <div key={i} className="ai-sol-timeline-row">
              <div className="ai-sol-timeline-dot" style={{ background: phaseColor(t.color) }} />
              <div>
                <p className="ai-sol-timeline-hdr" style={{ color: phaseColor(t.color) }}>
                  {t.window} — {t.label}
                </p>
                {t.actions && (
                  <ul className="ai-sol-list">
                    {t.actions.map((a, j) => <li key={j}>{a}</li>)}
                  </ul>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {data.compensating_controls && data.compensating_controls.length > 0 && (
        <div className="ai-sol-section">
          <p className="ai-sol-section-hdr">Compensating Controls</p>
          {data.compensating_controls.map((c, i) => (
            <div key={i} className="ai-sol-ctrl-row">
              <span className="ai-sol-text">{c.control}</span>
              <span className="ai-sol-badge">{c.effort}</span>
            </div>
          ))}
        </div>
      )}

      {data.lifecycle_warning?.upgrade_recommendation && (
        <div className="ai-sol-lifecycle">
          <span style={{ color: '#d97706' }}>⚠</span>
          <p className="ai-sol-text">{data.lifecycle_warning.upgrade_recommendation}</p>
        </div>
      )}

      {data.confidence_score != null && (
        <div className="ai-sol-confidence">
          <span className="ai-sol-section-hdr">Confidence</span>
          <span className="ai-sol-conf-score">{data.confidence_score}%</span>
          {data.confidence_rationale && <span className="ai-sol-text">{data.confidence_rationale}</span>}
        </div>
      )}
    </div>
  );
}
