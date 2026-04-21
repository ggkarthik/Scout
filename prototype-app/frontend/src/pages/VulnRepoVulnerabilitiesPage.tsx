import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CVEInvestigationSummary, type InvestigationSummaryInput } from '../components/CVEInvestigationSummary';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoView } from '../app/routes';
import type { CveDetail, CveMatchedSoftware, OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { useCveDetailQuery, useSavedAiSolutionQuery, useSavedInvestigationSummaryQuery, useVulnRepoVulnerabilitiesQuery } from '../features/cve-workbench/queries';
import type { AiSolutionData } from '../features/cve-workbench/api';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';

const PAGE_SIZE = 25;

const VULN_REPO_COLUMNS: DataTableColumn[] = [
  { id: 'cve', label: 'Vulnerability ID', header: 'Vulnerability ID', initialSize: 200 },
  { id: 'title', label: 'Description', header: 'Description', initialSize: 360 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'cvss', label: 'CVSS', header: 'CVSS', initialSize: 100 },
  { id: 'applicable', label: 'Applicable', header: 'Applicable', initialSize: 110 },
  { id: 'investigationStatus', label: 'Investigation Status', header: 'Investigation Status', initialSize: 170 },
  { id: 'impactedSoftware', label: 'Impacted Software', header: 'Impacted Software', initialSize: 180 },
  { id: 'investigationSummary', label: 'AI Summaries', header: 'AI Summaries', initialSize: 140 },
  { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 120 },
  { id: 'lastEvaluated', label: 'Last Evaluated', header: 'Last Evaluated', initialSize: 180 },
];

const RUNBOOK_TASK_IDS = ['review-asset-inventory', 'find-false-positive', 'end-of-life-analysis', 'solutions', 'installed-patch-info'];

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
  const initialExploitOnly = React.useMemo(() => searchParams.get('exploitOnly') === 'true', [searchParams]);
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
  const [page, setPage] = React.useState(0);
  const [queryInput, setQueryInput] = React.useState(initialQuery);
  const [query, setQuery] = React.useState(initialQuery);
  const [selectedSoftwareRecord, setSelectedSoftwareRecord] = React.useState<OrgSpecificCveExposureRecord | null>(null);
  const [drawerMode, setDrawerMode] = React.useState<DrawerMode>('software');
  const vulnRepoQuery = useVulnRepoVulnerabilitiesQuery({
    page,
    size: PAGE_SIZE,
    query: query || undefined,
    severity: initialSeverity || undefined,
    exploitOnly: initialExploitOnly || undefined,
    createdSinceDays: initialCreatedSinceDays,
    software: initialSoftware || undefined,
    softwareScope: initialSoftwareScope || undefined,
    softwareIdentityId: initialSoftwareIdentityId || undefined,
    includeAll: initialIncludeAll || undefined,
  });
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
    setPage(0);
  }, [initialCreatedSinceDays, initialExploitOnly, initialIncludeAll, initialQuery, initialSeverity, initialSoftware, initialSoftwareIdentityId, initialSoftwareScope]);

  const tableRows = React.useMemo<DataTableRow[]>(() => (
    items.map((item) => {
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
                  navigate(pathForVulnRepoView('org-cves', item.externalId));
                }}
              >
                <span className="mono">{item.externalId}</span>
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
          applicable: {
            content: applicable
              ? <span className="status-pill status-open">Yes</span>
              : <span className="status-pill status-suppressed">No</span>,
          },
          investigationStatus: {
            content: (() => {
              const status = getInvestigationStatus(item.externalId);
              if (status === 'done') return <span className="inv-status-badge inv-status-done">Done</span>;
              if (status === 'in-progress') return <span className="inv-status-badge inv-status-in-progress">In Progress</span>;
              return <span className="inv-status-badge inv-status-not-started">Not Started</span>;
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
  ), [items, navigate]);

  const applySearch = React.useCallback(() => {
    const parsed = parseCombinedSearchInput(queryInput);
    const nextParams = new URLSearchParams();
    if (parsed.query) {
      nextParams.set('query', parsed.query);
    }
    if (parsed.software) {
      nextParams.set('software', parsed.software);
    } else if (initialSoftware) {
      nextParams.set('software', initialSoftware);
    }
    if (initialSoftwareIdentityId) {
      nextParams.set('softwareIdentityId', initialSoftwareIdentityId);
    }
    if (initialSoftwareScope) {
      nextParams.set('softwareScope', initialSoftwareScope);
    }
    if (initialIncludeAll) {
      nextParams.set('includeAll', 'true');
    }
    if (initialSeverity) {
      nextParams.set('severity', initialSeverity);
    }
    if (initialExploitOnly) {
      nextParams.set('exploitOnly', 'true');
    }
    if (initialCreatedSinceDays) {
      nextParams.set('createdSinceDays', String(initialCreatedSinceDays));
    }
    setPage(0);
    setQuery(parsed.query ?? '');
    setSelectedSoftwareRecord(null);
    setDrawerMode('software');
    setSearchParams(nextParams);
  }, [
    initialCreatedSinceDays,
    initialExploitOnly,
    initialIncludeAll,
    initialSeverity,
    initialSoftware,
    initialSoftwareIdentityId,
    initialSoftwareScope,
    queryInput,
    setSearchParams,
  ]);

  const clearSearch = React.useCallback(() => {
    const nextParams = new URLSearchParams();
    if (initialSeverity) {
      nextParams.set('severity', initialSeverity);
    }
    if (initialExploitOnly) {
      nextParams.set('exploitOnly', 'true');
    }
    if (initialCreatedSinceDays) {
      nextParams.set('createdSinceDays', String(initialCreatedSinceDays));
    }
    if (initialSoftwareIdentityId) {
      nextParams.set('softwareIdentityId', initialSoftwareIdentityId);
    }
    if (initialSoftwareScope) {
      nextParams.set('softwareScope', initialSoftwareScope);
    }
    if (initialIncludeAll) {
      nextParams.set('includeAll', 'true');
    }
    setPage(0);
    setQueryInput('');
    setQuery('');
    setSelectedSoftwareRecord(null);
    setDrawerMode('software');
    setSearchParams(nextParams);
  }, [initialCreatedSinceDays, initialExploitOnly, initialIncludeAll, initialSeverity, initialSoftwareIdentityId, initialSoftwareScope, setSearchParams]);

  return (
    <section className="panel vuln-repo-vulnerabilities-shell">
      <div className="panel-header">
        <div>
          <h3>Unified Vulnerability Records</h3>
          <span className="panel-caption">
            Applicable CVEs are flagged when any CVE CPE is matched to software inventory. Impacted software shows matched software only, not assets.
          </span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => void vulnRepoQuery.refetch()}
            disabled={loading}
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="org-cve-filter-row">
        <div className="findings-filter-chip org-cve-filter-chip">
          <label htmlFor="vuln-repo-vuln-search">Search CVE / Description</label>
          <input
            id="vuln-repo-vuln-search"
            value={queryInput}
            onChange={(event) => setQueryInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                applySearch();
              }
            }}
            placeholder="CVE-2026-1526, internet_explorer"
          />
        </div>
        <div className="button-row org-cve-filter-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={applySearch}
            disabled={loading}
          >
            Apply
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={clearSearch}
            disabled={loading && !query}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className="notice error">Failed to load vuln repo vulnerabilities: {error}</div>}

      <div className={`vuln-repo-vulnerabilities-layout${selectedSoftwareRecord ? ' is-drawer-open' : ''}`}>
        <div className="table-scroll">
          <DataTable
            storageKey="vuln-repo-vulnerabilities-table-widths"
            columns={VULN_REPO_COLUMNS}
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
