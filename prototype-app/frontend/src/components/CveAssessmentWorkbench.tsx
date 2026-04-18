import React from 'react';
import { EolDetailDrawer } from './EolDetailDrawer';
import { ConfirmDialog } from './ConfirmDialog';
import {
  type CveMatchedSoftware,
  type CveDetail,
  type OrgSpecificCveExposureRecord,
} from '../features/cve-workbench/types';
import {
  formatDate,
  formatLabel,
  severityClassName,
  statusClassName,
} from '../features/cve-workbench/formatting';
import { InvestigationContent } from '../features/cve-workbench/components/InvestigationContent';
import {
  ApplicabilityTable,
  DecisionSummary,
} from '../features/cve-workbench/components/ApplicabilityPanel';
import {
  FindingConfigSidebar,
  FindingsContent,
} from '../features/cve-workbench/components/FindingsPanel';
import { useCveWorkbenchAssessment } from '../features/cve-workbench/hooks/useCveWorkbenchAssessment';
import { useCveWorkbenchFindings } from '../features/cve-workbench/hooks/useCveWorkbenchFindings';
import { usePendingNavigationGuard } from '../features/cve-workbench/hooks/usePendingNavigationGuard';
import type { RiskPolicy } from '../features/configurations/types';

type WorkflowPanel = 1 | 2 | 3;

const CVSS_DIMS: { key: string; label: string; values: Record<string, string> }[] = [
  { key: 'AV', label: 'Attack vector',       values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' } },
  { key: 'AC', label: 'Attack complexity',   values: { L: 'Low', H: 'High' } },
  { key: 'PR', label: 'Privileges required', values: { N: 'None', L: 'Low', H: 'High' } },
  { key: 'UI', label: 'User interaction',    values: { N: 'None', R: 'Required' } },
  { key: 'S',  label: 'Scope',               values: { U: 'Unchanged', C: 'Changed' } },
  { key: 'C',  label: 'Confidentiality',     values: { N: 'None', L: 'Low', H: 'High' } },
  { key: 'I',  label: 'Integrity',           values: { N: 'None', L: 'Low', H: 'High' } },
  { key: 'A',  label: 'Availability',        values: { N: 'None', L: 'Low', H: 'High' } },
];

type Props = {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail | null;
  loading: boolean;
  error: string | null;
  findingGenerationMode: RiskPolicy['findingGenerationMode'];
  analystId?: string;
  onBack: () => void;
  onRefreshDetail: (options?: { includeList?: boolean }) => Promise<void>;
};

export function CveAssessmentWorkbench({
  item,
  detail,
  loading,
  error,
  findingGenerationMode,
  analystId,
  onBack,
  onRefreshDetail,
}: Props) {
  const [activePanel, setActivePanel] = React.useState<WorkflowPanel | null>(null);
  const [actionNotice, setActionNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const [eolDrawer, setEolDrawer] = React.useState<CveMatchedSoftware | null>(null);
  const [pendingFindingAction, setPendingFindingAction] = React.useState<(() => Promise<void>) | null>(null);
  const [activeTab, setActiveTab] = React.useState<'assets' | 'refs'>('assets');

  const assessment = useCveWorkbenchAssessment({
    item, detail, onRefreshDetail, setActionNotice, setActionError,
  });
  const findings = useCveWorkbenchFindings({
    item,
    detail,
    currentApplicableSoftware: assessment.currentApplicableSoftware,
    applicabilityDecisions: assessment.applicabilityDecisions,
    impactDecisions: assessment.impactDecisions,
    onRefreshDetail,
    setActionNotice,
    setActionError,
  });
  const navigationGuard = usePendingNavigationGuard(assessment.isDirty);

  const severity = item.severity;
  const cvssScore = item.cvssScore ?? detail?.summary.cvssScore;
  const epssScore = detail?.summary.epssScore ?? item.epssScore;
  const exploitActive = detail?.signals.exploitAvailable ?? false;
  const patchAvailable = detail?.signals.patchAvailable ?? false;
  const patchVersions = detail?.signals.patchVersions;

  const recommendedAction = React.useMemo(() => {
    const sev = severity?.toLowerCase();
    if (item.inKev && exploitActive) {
      return 'Investigate and patch immediately — CISA KEV confirmed with active exploitation.';
    }
    if (sev === 'critical' || sev === 'high') {
      return `${formatLabel(severity)} severity${exploitActive ? ' with active exploitation' : ''}. Review affected assets and apply available patches.`;
    }
    return 'Review exposure and apply mitigations per your remediation SLA.';
  }, [severity, item.inKev, exploitActive]);

  const vendorTargets = React.useMemo(() => {
    if (!detail) return [];
    const seen = new Set<string>();
    return (detail.vendorIntelligence ?? []).filter(vi => {
      if (!vi.packageName) return false;
      if (seen.has(vi.packageName)) return false;
      seen.add(vi.packageName);
      return true;
    });
  }, [detail]);

  const cweList = React.useMemo(() => {
    if (!detail?.summary.cweIds) return [];
    return detail.summary.cweIds.split(',').map(s => s.trim()).filter(Boolean);
  }, [detail]);

  const applicabilityStepStatus = React.useMemo(() => {
    if (item.applicableComponentCount > 0) {
      return `Applicable · ${item.applicableComponentCount} of ${item.matchedComponentCount} confirmed.`;
    }
    if (item.applicability === 'NOT_APPLICABLE') return 'Not applicable.';
    return 'Pending review.';
  }, [item]);

  const investigationStepStatus = React.useMemo(() => {
    if (item.hasInvestigationSummary) return 'Summary generated.';
    if (item.impactState === 'UNDER_INVESTIGATION') return 'Under investigation.';
    return 'Open the runbook and gather evidence.';
  }, [item]);

  const togglePanel = (panel: WorkflowPanel) => {
    setActivePanel(prev => prev === panel ? null : panel);
  };

  return (
    <div className="cve-detail-page">

      {/* Breadcrumb */}
      <div className="cve-assessment-breadcrumb">
        <button type="button" onClick={() => navigationGuard.guardedNav(onBack)}>Vulnerabilities</button>
        <span aria-hidden="true">›</span>
        <button type="button" onClick={() => navigationGuard.guardedNav(onBack)}>Org CVEs</button>
        <span aria-hidden="true">›</span>
        <span>{item.externalId}</span>
      </div>

      {/* Header */}
      <div className="cvd-header">
        <div className="cvd-header-left">
          <div className="cvd-header-title-row">
            <h1 className="cvd-id">{item.externalId}</h1>
            <span className={severityClassName(severity)}>{formatLabel(severity)}</span>
            {item.inKev && (
              <span className="cvd-flag-chip cvd-flag-critical">
                <span className="cvd-flag-dot" />CISA KEV
              </span>
            )}
            {exploitActive && (
              <span className="cvd-flag-chip cvd-flag-high">
                <span className="cvd-flag-dot" />Exploited in wild
              </span>
            )}
            {item.eolComponentCount > 0 && (
              <span className="cvd-flag-chip cvd-flag-medium">
                <span className="cvd-flag-dot" />{item.eolComponentCount} EOL
              </span>
            )}
          </div>
          <p className="cvd-tagline">{detail?.summary.title ?? item.title}</p>
        </div>
        <div className="cvd-header-actions">
          <button type="button" className="btn btn-secondary" onClick={() => navigationGuard.guardedNav(onBack)}>← Back</button>
          <button type="button" className="btn btn-secondary">Export evidence</button>
        </div>
      </div>

      {actionNotice && <div className="notice">{actionNotice}</div>}
      {actionError && <div className="notice error">{actionError}</div>}

      {loading ? (
        <div className="notice">Loading CVE details...</div>
      ) : error ? (
        <div className="notice error">{error}</div>
      ) : !detail ? (
        <div className="notice error">No detail available for this CVE.</div>
      ) : (
        <>
          {/* ── Decision Panel ──────────────────────────────── */}
          <div className="cvd-decision-panel">
            <div className="cvd-decision-top">
              <span className="cvd-section-label">Decision panel · should you act?</span>
              <span className="cvd-muted-sm">
                Last evaluated {item.lastEvaluatedAt ? formatDate(item.lastEvaluatedAt) : '—'}
              </span>
            </div>
            <div className="cvd-kv-row">
              <div className="cvd-kv">
                <span className="cvd-kv-label">Severity</span>
                <div className="cvd-kv-score-wrap">
                  <span className={`cvd-kv-big cvd-sev-${severity?.toLowerCase()}`}>
                    {cvssScore != null ? cvssScore.toFixed(1) : formatLabel(severity)}
                  </span>
                  {cvssScore != null && <span className="cvd-kv-denom">/10</span>}
                </div>
                <span className="cvd-kv-sub">{formatLabel(severity)}</span>
              </div>

              <div className="cvd-kv">
                <span className="cvd-kv-label">Exploit status</span>
                <div className="cvd-kv-status-wrap">
                  <span className={`cvd-dot ${exploitActive ? 'cvd-dot-danger' : 'cvd-dot-none'}`} />
                  <span className={exploitActive ? 'cvd-kv-danger' : 'cvd-kv-muted'}>
                    {exploitActive ? (detail.signals.exploitReason || 'Active') : 'None known'}
                  </span>
                </div>
                {epssScore != null && (
                  <span className="cvd-kv-sub">EPSS {(epssScore * 100).toFixed(1)}%</span>
                )}
              </div>

              <div className="cvd-kv">
                <span className="cvd-kv-label">Your exposure</span>
                <div className="cvd-kv-score-wrap">
                  <span className="cvd-kv-big">{item.matchedAssetCount}</span>
                  <span className="cvd-kv-denom">assets</span>
                </div>
                <span className="cvd-kv-sub">{item.matchedSoftwareCount} software · {item.matchedComponentCount} components</span>
              </div>

              <div className="cvd-kv">
                <span className="cvd-kv-label">Patch available</span>
                <div className="cvd-kv-status-wrap">
                  <span className={`cvd-dot ${patchAvailable ? 'cvd-dot-ok' : 'cvd-dot-none'}`} />
                  <span className={patchAvailable ? 'cvd-kv-ok' : 'cvd-kv-muted'}>
                    {patchAvailable ? 'Yes' : 'No'}
                  </span>
                </div>
                {patchVersions && <span className="cvd-kv-sub">{patchVersions}</span>}
              </div>

              <div className="cvd-kv">
                <span className="cvd-kv-label">Open findings</span>
                <div className="cvd-kv-score-wrap">
                  <span className="cvd-kv-big">{item.openFindings}</span>
                </div>
                <span className="cvd-kv-sub">{item.applicableComponentCount} applicable</span>
              </div>
            </div>

            <div className="cvd-recommend-banner">
              <div className="cvd-recommend-icon">!</div>
              <div>
                <strong>Recommended action: </strong>
                <span>{recommendedAction}</span>
              </div>
            </div>
          </div>

          {/* ── Workflow Panel ───────────────────────────────── */}
          <div className="cvd-workflow-panel">
            <div className="cvd-workflow-header">
              <div>
                <span className="cvd-section-label">Workflow</span>
                <p className="cvd-workflow-sub">Move from investigation to assessment and finding creation.</p>
              </div>
              <div className="cvd-workflow-secondary">
                <span className="cvd-section-label" style={{ marginRight: 8 }}>Secondary actions</span>
                <button type="button" className="btn btn-secondary" onClick={() => navigationGuard.guardedNav(onBack)}>Mark deferred</button>
                <button type="button" className="btn btn-secondary">Export evidence</button>
              </div>
            </div>

            <div className="cvd-wf-steps">
              {([
                { panel: 1 as WorkflowPanel, title: 'Investigation',  sub: investigationStepStatus },
                { panel: 2 as WorkflowPanel, title: 'Applicability',  sub: applicabilityStepStatus },
                { panel: 3 as WorkflowPanel, title: 'Create finding', sub: 'Add impacted assets to the backlog.' },
              ] as const).map(({ panel, title, sub }) => (
                <button
                  key={panel}
                  type="button"
                  className={`cvd-wf-step ${activePanel === panel ? 'active' : ''}`}
                  onClick={() => togglePanel(panel)}
                >
                  <div className="cvd-wf-num">{panel}</div>
                  <div className="cvd-wf-body">
                    <p className="cvd-wf-title">{title}</p>
                    <p className="cvd-wf-sub">{sub}</p>
                  </div>
                </button>
              ))}
            </div>

            {/* ── Investigation panel ── */}
            {activePanel === 1 && (
              <div className="cvd-inline-panel">
                <div className="cve-assessment-layout">
                  <div className="cve-investigation-main">
                    <InvestigationContent
                      item={item}
                      detail={detail}
                      softwareGroups={assessment.softwareGroups}
                      vendorRows={assessment.vendorRows}
                      overallConfidence={assessment.overallConfidence}
                      investigationNotes={assessment.investigationNotes}
                      autoNote={assessment.autoNote}
                      onNotesChange={assessment.setInvestigationNotes}
                      onEolClick={setEolDrawer}
                    />
                  </div>
                </div>
                <div className="cvd-inline-footer">
                  <button type="button" className="btn btn-secondary" onClick={() => setActivePanel(null)}>Close</button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={assessment.investigationBusy}
                    onClick={() => {
                      void assessment.saveInvestigation().then(saved => {
                        if (saved) setActivePanel(2);
                      });
                    }}
                  >
                    {assessment.investigationBusy ? 'Saving...' : 'Save & Continue to Applicability'}
                  </button>
                </div>
              </div>
            )}

            {/* ── Applicability panel ── */}
            {activePanel === 2 && (
              <div className="cvd-inline-panel">
                <div className="cve-applicability-layout">
                  <div className="cve-applicability-main">
                    <ApplicabilityTable
                      matchedSoftware={detail.matchedSoftware}
                      applicabilityDecisions={assessment.applicabilityDecisions}
                      impactDecisions={assessment.impactDecisions}
                      expandedEvidenceComponentId={assessment.expandedEvidenceComponentId}
                      vexEvidenceByComponent={assessment.vexEvidenceByComponent}
                      vexEvidenceErrors={assessment.vexEvidenceErrors}
                      vexEvidenceLoadingComponentId={assessment.vexEvidenceLoadingComponentId}
                      onApplicabilityDecision={assessment.setApplicabilityDecision}
                      onBulkApplicabilityDecision={assessment.applyBulkApplicabilityDecision}
                      onImpactDecision={assessment.setImpactDecision}
                      onToggleVexEvidence={assessment.toggleVexEvidence}
                      onEolClick={setEolDrawer}
                    />
                  </div>
                  <DecisionSummary
                    matchedSoftware={detail.matchedSoftware}
                    applicabilityDecisions={assessment.applicabilityDecisions}
                    impactDecisions={assessment.impactDecisions}
                    analystRationale={assessment.analystRationale}
                    onAnalystRationaleChange={assessment.setAnalystRationale}
                    latestAssessment={assessment.latestAssessment}
                    saveBusy={assessment.assessmentBusy}
                    analystId={analystId}
                    onSave={() => { void assessment.saveAssessment(); }}
                    onProceed={() => {
                      void assessment.saveAssessment({ showSuccessNotice: false }).then(saved => {
                        if (saved) setActivePanel(3);
                      });
                    }}
                    onBack={() => navigationGuard.guardedNav(() => setActivePanel(1))}
                  />
                </div>
              </div>
            )}

            {/* ── Create findings panel ── */}
            {activePanel === 3 && (
              <div className="cvd-inline-panel">
                <div className="cve-applicability-layout">
                  <FindingsContent
                    filteredSoftware={findings.filteredFindingSoftware}
                    selectedIds={findings.selectedFindingIds}
                    groupBy={findings.findingGroupBy}
                    showFilter={findings.findingShowFilter}
                    severity={item.severity}
                    onToggleRow={findings.toggleFindingRow}
                    onSelectAll={findings.selectAllFindings}
                    onClearAll={findings.clearAllFindings}
                    onGroupByChange={findings.setFindingGroupBy}
                    onShowFilterChange={findings.setFindingShowFilter}
                    onEolClick={setEolDrawer}
                  />
                  <FindingConfigSidebar
                    filteredSoftware={findings.filteredFindingSoftware}
                    selectedIds={findings.selectedFindingIds}
                    findingGenerationMode={findingGenerationMode}
                    findingTitle={findings.findingTitle}
                    findingPriority={findings.findingPriority}
                    assignmentGroup={findings.assignmentGroup}
                    ticketTarget={findings.ticketTarget}
                    dueDate={findings.dueDate}
                    findingNotes={findings.findingNotes}
                    findingBusy={findings.findingBusy}
                    onFindingTitleChange={findings.setFindingTitle}
                    onFindingPriorityChange={findings.setFindingPriority}
                    onAssignmentGroupChange={findings.setAssignmentGroup}
                    onTicketTargetChange={findings.setTicketTarget}
                    onDueDateChange={findings.setDueDate}
                    onFindingNotesChange={findings.setFindingNotes}
                    onRequestCreateFindings={() => setPendingFindingAction(() => findings.createFindings)}
                    onRequestCreateGrouped={() => setPendingFindingAction(() => findings.createFindings)}
                    onSaveAssessment={() => { void assessment.saveAssessment(); }}
                    onBack={() => setActivePanel(2)}
                  />
                </div>
              </div>
            )}
          </div>

          {/* ── CVE Detail Content ───────────────────────────── */}
          <div className="cvd-content">

            {/* Description */}
            <div className="cvd-card">
              <p className="cvd-section-label">Description</p>
              <p className="cvd-description">{detail.summary.description}</p>
            </div>

            {/* Technical details / CVSS */}
            {detail.summary.cvssVector && (
              <div className="cvd-card">
                <div className="cvd-technical-hdr">
                  <p className="cvd-section-label">Technical details · CVSS v3.1 vector</p>
                  {detail.summary.source && (
                    <div style={{ display: 'flex', gap: 6 }}>
                      <span className="cvd-src-tag">{detail.summary.source}</span>
                    </div>
                  )}
                </div>
                <div className="cvd-vector-bar">
                  <code className="cvd-vector-code">{detail.summary.cvssVector}</code>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ padding: '4px 10px', fontSize: '11px' }}
                    onClick={() => void navigator.clipboard.writeText(detail.summary.cvssVector ?? '')}
                  >
                    Copy
                  </button>
                </div>
                <div className="cvd-cvss-grid">
                  {CVSS_DIMS.map(({ key, label, values }) => {
                    const raw = assessment.cvssFields[key];
                    if (!raw) return null;
                    return (
                      <div key={key} className="cvd-cvss-cell">
                        <p className="cvd-cvss-cell-label">{label}</p>
                        <p className="cvd-cvss-cell-val">{values[raw] ?? raw}</p>
                        <span className="cvd-cvss-cell-code">{key}:{raw}</span>
                      </div>
                    );
                  })}
                </div>
                <div className="cvd-cvss-meta">
                  {detail.summary.publishedAt && (
                    <div>
                      <p className="cvd-meta-label">Published</p>
                      <p className="cvd-meta-val">{formatDate(detail.summary.publishedAt)}</p>
                    </div>
                  )}
                  {detail.summary.modifiedAt && (
                    <div>
                      <p className="cvd-meta-label">Last modified</p>
                      <p className="cvd-meta-val">{formatDate(detail.summary.modifiedAt)}</p>
                    </div>
                  )}
                  {detail.summary.epssScore != null && (
                    <div>
                      <p className="cvd-meta-label">EPSS score</p>
                      <p className="cvd-meta-val cvd-meta-warn">{(detail.summary.epssScore * 100).toFixed(1)}%</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Affected entities + Weaknesses */}
            {(vendorTargets.length > 0 || cweList.length > 0) && (
              <div className="cvd-two-col">
                {vendorTargets.length > 0 && (
                  <div className="cvd-card cvd-card-flush">
                    <div className="cvd-card-inset-hdr">
                      <p className="cvd-section-label">Affected entities</p>
                      <span className="cvd-count-badge">{vendorTargets.length} entries</span>
                    </div>
                    <div>
                      {vendorTargets.slice(0, 4).map((vi, i) => (
                        <div key={i} className="cvd-entity-row">
                          <div className="cvd-entity-row-top">
                            <span className="cvd-entity-name">{vi.packageName}</span>
                            <span className="cvd-src-tag">{vi.source}</span>
                          </div>
                          {vi.cpe && <code className="cvd-entity-cpe">{vi.cpe}</code>}
                          {vi.affectedVersions && (
                            <span className="cvd-entity-versions">{vi.affectedVersions}</span>
                          )}
                        </div>
                      ))}
                      {vendorTargets.length > 4 && (
                        <div className="cvd-entity-more">Show all {vendorTargets.length} entries →</div>
                      )}
                    </div>
                  </div>
                )}
                {cweList.length > 0 && (
                  <div className="cvd-card cvd-card-flush">
                    <div className="cvd-card-inset-hdr">
                      <p className="cvd-section-label">Weaknesses</p>
                      <span className="cvd-count-badge">{cweList.length} CWEs</span>
                    </div>
                    <div>
                      {cweList.map(cwe => (
                        <div key={cwe} className="cvd-entity-row">
                          <span className="cvd-entity-name">{cwe}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Solution */}
            {patchAvailable && (
              <div className="cvd-card">
                <div className="cvd-solution-hdr">
                  <p className="cvd-section-label">Solution</p>
                  <span className="severity-pill severity-low">✓ Available</span>
                </div>
                <div className="cvd-sol-card">
                  <div className="cvd-sol-top">
                    <span className="cvd-sol-title">
                      {patchVersions ? `Upgrade to ${patchVersions}` : 'Apply latest security patch'}
                    </span>
                    {detail.summary.source && <span className="cvd-src-tag">{detail.summary.source}</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                    <span className="severity-pill severity-low">Recommended</span>
                    <span className="cvd-pill-neutral">Full fix</span>
                  </div>
                </div>
              </div>
            )}

            {/* Tabs: Affected assets / References */}
            <div className="cvd-card" style={{ padding: 0 }}>
              <div className="cvd-tab-bar">
                <button
                  type="button"
                  className={`cvd-tab-btn ${activeTab === 'assets' ? 'active' : ''}`}
                  onClick={() => setActiveTab('assets')}
                >
                  Affected assets · {item.matchedAssetCount}
                </button>
                <button
                  type="button"
                  className={`cvd-tab-btn ${activeTab === 'refs' ? 'active' : ''}`}
                  onClick={() => setActiveTab('refs')}
                >
                  References
                </button>
              </div>

              {activeTab === 'assets' && (
                detail.matchedSoftware.length === 0 ? (
                  <p className="cvd-tab-empty">No matched assets.</p>
                ) : (
                  <>
                    <div className="table-scroll">
                      <table className="data-table cvd-assets-table">
                        <thead>
                          <tr>
                            <th>Asset</th>
                            <th>Ecosystem</th>
                            <th>Package</th>
                            <th>Version</th>
                            <th>Applicability</th>
                            <th>Impact</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detail.matchedSoftware.slice(0, 10).map(sw => (
                            <tr key={sw.componentId}>
                              <td>{sw.assetName ?? sw.assetIdentifier ?? sw.assetId ?? '—'}</td>
                              <td><span className="cvd-src-tag">{sw.ecosystem}</span></td>
                              <td>{sw.packageName}</td>
                              <td className="mono">{sw.version ?? '—'}</td>
                              <td>
                                <span className={statusClassName(sw.applicabilityState)}>
                                  {formatLabel(sw.applicabilityState)}
                                </span>
                              </td>
                              <td>
                                <span className={statusClassName(sw.impactState)}>
                                  {formatLabel(sw.impactState)}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {detail.matchedSoftware.length > 10 && (
                      <div className="cvd-tab-footer">
                        Showing 10 of {detail.matchedSoftware.length} ·{' '}
                        <button type="button" className="cvd-link-btn" onClick={() => togglePanel(2)}>
                          View all in Applicability →
                        </button>
                      </div>
                    )}
                  </>
                )
              )}

              {activeTab === 'refs' && (
                <div className="cvd-refs-list">
                  {detail.summary.sourceUrl ? (
                    <div className="cvd-ref-row">
                      <span className="cvd-src-tag">{detail.summary.source ?? 'Source'}</span>
                      <a href={detail.summary.sourceUrl} target="_blank" rel="noreferrer" className="cvd-ref-link">
                        {detail.summary.sourceUrl}
                      </a>
                    </div>
                  ) : (
                    <p className="cvd-tab-empty">No references available.</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* Navigation guard dialog */}
      <ConfirmDialog
        isOpen={navigationGuard.pendingNavAction !== null}
        title="Unsaved Changes"
        message="You have unsaved notes or rationale. Navigating away will discard them. Continue?"
        confirmLabel="Discard & Leave"
        cancelLabel="Stay"
        onConfirm={navigationGuard.confirmPendingNavigation}
        onCancel={navigationGuard.cancelPendingNavigation}
      />

      {/* Finding creation confirmation */}
      <ConfirmDialog
        isOpen={pendingFindingAction !== null}
        title={`Create ${findings.selectedFindingIds.size} Finding${findings.selectedFindingIds.size === 1 ? '' : 's'}?`}
        message="This will immediately create findings for the selected assets. Existing open findings for the same components will be reopened rather than duplicated."
        confirmLabel="Create Findings"
        cancelLabel="Cancel"
        onConfirm={() => {
          const action = pendingFindingAction;
          setPendingFindingAction(null);
          if (action) void action();
        }}
        onCancel={() => setPendingFindingAction(null)}
      />

      {/* EOL detail drawer */}
      {eolDrawer?.eolSlug && (
        <EolDetailDrawer
          slug={eolDrawer.eolSlug}
          cycle={eolDrawer.eolCycle ?? undefined}
          packageName={eolDrawer.packageName}
          version={eolDrawer.version ?? undefined}
          isEol={eolDrawer.isEol ?? undefined}
          eolDate={eolDrawer.eolDate ?? undefined}
          daysRemaining={eolDrawer.eolDaysRemaining ?? undefined}
          onClose={() => setEolDrawer(null)}
        />
      )}
    </div>
  );
}
