import React from 'react';
import { ConfirmDialog } from './ConfirmDialog';
import { SegmentedControl } from './SegmentedControl';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import {
  applicableSoftwareRows,
  buildFindingDisplayRows,
  buildSoftwareGroups,
  computedImpactStateOf,
  confidenceFromApplicability,
  deriveAssessmentResult,
  exactMatchMeta,
  explainApplicability,
  explainImpact,
  hasPersistedVexEvidence,
  impactBadgeClass,
  impactLabel,
  initialApplicabilityDecision,
  latestByDate,
  matchBasisLabel,
  parseCvssVector,
  priorityFromSeverityAndImpact,
  type ApplicabilityDecision,
  type FindingDisplayRow,
  type ImpactDecision,
  type SoftwareGroup,
  vendorStatementFor,
} from '../features/cve-workbench/assessment-helpers';
import {
  formatDate,
  formatLabel,
  severityClassName,
  softwareLabel,
} from '../features/cve-workbench/formatting';
import {
  CveApplicabilityAssessment,
  CveDetail,
  CveInvestigation,
  CveMatchedSoftware,
  CveVexEvidence,
  OrgSpecificCveExposureRecord,
} from '../features/cve-workbench/types';
import {
  InvestigationPriority,
  InvestigationStatus,
} from '../features/cve-workbench/workflow';
import type { VendorIntelligence } from '../features/cve-workbench/types';
import type { RiskPolicy } from '../types';

type WorkflowStep = 1 | 2 | 3;

type Props = {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail | null;
  loading: boolean;
  error: string | null;
  findingGenerationMode: RiskPolicy['findingGenerationMode'];
  analystId?: string;
  onBack: () => void;
  onRefreshDetail: () => Promise<void>;
};

const AV_LABELS: Record<string, string> = { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' };
const PR_LABELS: Record<string, string> = { N: 'None', L: 'Low', H: 'High' };
const UI_LABELS: Record<string, string> = { N: 'None', R: 'Required' };

// --- CVE Summary Sidebar (step 1) ---

type SidebarProps = {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail;
  cvssFields: Record<string, string>;
  softwareGroups: SoftwareGroup[];
};

function CveSummarySidebar({ item, detail, cvssFields, softwareGroups }: SidebarProps) {
  // Deduplicate affected products and enrich with version ranges from vendor intelligence
  const affectedProductMap = new Map<string, { ecosystem?: string; versions: string[] }>();
  for (const vi of (detail.vendorIntelligence ?? [])) {
    if (!vi.packageName) continue;
    const key = vi.packageName;
    const existing = affectedProductMap.get(key);
    if (existing) {
      if (vi.affectedVersions && !existing.versions.includes(vi.affectedVersions)) {
        existing.versions.push(vi.affectedVersions);
      }
    } else {
      affectedProductMap.set(key, {
        ecosystem: vi.ecosystem ?? undefined,
        versions: vi.affectedVersions ? [vi.affectedVersions] : [],
      });
    }
  }
  // Fall back to matched software names if no vendor intelligence
  if (affectedProductMap.size === 0) {
    for (const g of softwareGroups.slice(0, 5)) {
      const key = g.software.packageName;
      if (!affectedProductMap.has(key)) {
        affectedProductMap.set(key, { ecosystem: g.software.ecosystem ?? undefined, versions: [] });
      }
    }
  }

  // Unique CPEs from vendor intelligence
  const cpes = [...new Set((detail.vendorIntelligence ?? []).map((vi) => vi.cpe).filter(Boolean))] as string[];

  const epssScore = detail.summary.epssScore ?? null;
  const epssUpdatedAt = detail.summary.epssUpdatedAt ?? null;
  const cweIds = detail.summary.cweIds;

  return (
    <aside className="cve-summary-sidebar">

      {/* Header: ID + severity + score */}
      <div className="cve-sidebar-header">
        <h4>CVE Summary</h4>
        <div className="cve-sidebar-scores">
          {epssScore != null && (
            <span
              className={`cve-score-chip ${epssScore >= 0.5 ? 'cve-score-chip-warn' : ''}`}
              title={epssUpdatedAt
                ? `Probability of exploitation in the next 30 days — score refreshed ${new Date(epssUpdatedAt).toLocaleDateString()}`
                : 'Probability of exploitation in the next 30 days'}
            >
              EPSS {(epssScore * 100).toFixed(1)}%
            </span>
          )}
        </div>
      </div>

      {/* KEV warning — exploitability signal only, not an applicability determination */}
      {item.inKev && (
        <div className="cve-kev-banner">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" width="14" height="14">
            <path d="M12 3L2 21h20L12 3z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
            <path d="M12 9v5M12 17h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          In CISA KEV — actively exploited in the wild. Prioritize review; applicability must still be verified against your inventory.
        </div>
      )}

      {/* Description */}
      <div>
        <h5>Description</h5>
        <p className="cve-summary-description">
          {detail.summary.description || detail.summary.title || 'No description available.'}
        </p>
      </div>

      {/* CWE */}
      {cweIds && (
        <>
          <hr className="cve-summary-divider" />
          <div>
            <h5>Weakness (CWE)</h5>
            <p className="cve-summary-cwe">{cweIds}</p>
          </div>
        </>
      )}

      {/* Dates */}
      {(detail.summary.publishedAt || detail.summary.modifiedAt) && (
        <>
          <hr className="cve-summary-divider" />
          <div className="cve-summary-meta-grid">
            {detail.summary.publishedAt && (
              <div className="cve-summary-meta-item">
                <label>Published</label>
                <span>{formatDate(detail.summary.publishedAt)}</span>
              </div>
            )}
            {detail.summary.modifiedAt && (
              <div className="cve-summary-meta-item">
                <label>Updated</label>
                <span>{formatDate(detail.summary.modifiedAt)}</span>
              </div>
            )}
          </div>
        </>
      )}

      {/* CVSS breakdown — only when vector present */}
      {(cvssFields['AV'] || cvssFields['PR'] || cvssFields['UI']) && (
        <>
          <hr className="cve-summary-divider" />
          <div>
            <h5>CVSS Details</h5>
            {cvssFields['AV'] && (
              <div className="cve-cvss-row">
                <span>Attack Vector</span>
                <span>{AV_LABELS[cvssFields['AV']] ?? cvssFields['AV']}</span>
              </div>
            )}
            {cvssFields['PR'] && (
              <div className="cve-cvss-row">
                <span>Privileges Required</span>
                <span>{PR_LABELS[cvssFields['PR']] ?? cvssFields['PR']}</span>
              </div>
            )}
            {cvssFields['UI'] && (
              <div className="cve-cvss-row">
                <span>User Interaction</span>
                <span>{UI_LABELS[cvssFields['UI']] ?? cvssFields['UI']}</span>
              </div>
            )}
            {detail.summary.cvssVector && (
              <div className="cve-cvss-row cve-cvss-vector-row">
                <span>Vector</span>
                <span className="mono cve-cvss-vector-val" title={detail.summary.cvssVector}>
                  {detail.summary.cvssVector}
                </span>
              </div>
            )}
          </div>
        </>
      )}

      {/* Affected Products */}
      {affectedProductMap.size > 0 && (
        <>
          <hr className="cve-summary-divider" />
          <div>
            <h5>Affected Products</h5>
            <ul className="cve-affected-products">
              {Array.from(affectedProductMap.entries()).map(([name, { ecosystem, versions }]) => (
                <li key={name} className="cve-affected-product-item">
                  <div className="cve-affected-product-name">
                    {ecosystem && <span className="cve-ecosystem-tag">{ecosystem}</span>}
                    <strong>{name}</strong>
                  </div>
                  {versions.length > 0 && (
                    <div className="cve-affected-product-range mono">{versions.join(', ')}</div>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </>
      )}

      {/* CPE Identifiers */}
      {cpes.length > 0 && (
        <>
          <hr className="cve-summary-divider" />
          <div>
            <h5>CPE Identifiers</h5>
            <div className="cve-cpe-list">
              {cpes.map((cpe) => (
                <div key={cpe} className="cve-cpe-entry" title={cpe}>{cpe}</div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* Sources */}
      <hr className="cve-summary-divider" />
      <div>
        <h5>Sources</h5>
        <div className="cve-source-badges">
          {detail.summary.source && (
            detail.summary.sourceUrl
              ? <a href={detail.summary.sourceUrl} target="_blank" rel="noreferrer" className="cve-source-badge cve-source-badge-link">{detail.summary.source}</a>
              : <span className="cve-source-badge">{detail.summary.source}</span>
          )}
          {item.inKev && <span className="cve-source-badge kev">KEV</span>}
          {hasPersistedVexEvidence(detail) && <span className="cve-source-badge csaf">VEX</span>}
          {detail.summary.cvssVector && <span className="cve-source-badge">CVSS</span>}
        </div>
      </div>

    </aside>
  );
}

// --- Investigation Content (step 1) ---

type VendorRow = {
  source: string;
  statement: string;
  statementClass: string;
  affectedVersions: string;
  fixedVersion: string;
  ecosystem?: string;
  packageName?: string;
  cpe?: string;
  vexStatus?: string;
};

type InvestigationContentProps = {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail;
  softwareGroups: SoftwareGroup[];
  vendorRows: VendorRow[];
  overallConfidence: { label: string; cls: string; pct: number };
  investigationNotes: string;
  autoNote: string;
  onNotesChange: (v: string) => void;
};

function InvestigationContent({
  item, detail, softwareGroups, vendorRows, overallConfidence, investigationNotes, autoNote, onNotesChange,
}: InvestigationContentProps) {
  const [expandedRows, setExpandedRows] = React.useState<Set<string>>(new Set());

  function toggleRow(key: string): void {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  return (
    <>
      <div className="cve-stat-cards">
        <div className="cve-stat-card">
          <div className="cve-stat-card-label">Matching Software</div>
          <div className="cve-stat-card-value">{softwareGroups.length}</div>
          <div className="cve-stat-card-sub">{softwareGroups.length > 0 ? 'Correlated to inventory' : 'None detected'}</div>
        </div>
        <div className="cve-stat-card">
          <div className="cve-stat-card-label">Candidate Assets</div>
          <div className="cve-stat-card-value">{detail.signals.assetCount}</div>
          <div className="cve-stat-card-sub">{detail.signals.assetCount > 0 ? 'Assets with matched software' : 'None impacted'}</div>
        </div>
        <div className="cve-stat-card">
          <div className="cve-stat-card-label">Open Findings</div>
          <div className="cve-stat-card-value">{item.openFindings}</div>
          <div className="cve-stat-card-sub">{formatLabel(item.impactState)}</div>
        </div>
        <div className="cve-stat-card">
          <div className="cve-stat-card-label">Confidence</div>
          <div className={`cve-stat-card-value cve-stat-card-value-composite ${overallConfidence.cls}`}>
            <span className="cve-confidence-main">{overallConfidence.label}</span>
            {overallConfidence.pct > 0 && <span className="cve-confidence-pct">{overallConfidence.pct}%</span>}
          </div>
          <div className="cve-stat-card-sub">Match confidence</div>
        </div>
        <div className="cve-stat-card">
          <div className="cve-stat-card-label">CVSS Score</div>
          <div className={`cve-stat-card-value cve-cvss-score-value cve-cvss-score-${item.severity.toLowerCase()}`}>
            {detail.summary.cvssScore != null ? detail.summary.cvssScore.toFixed(1) : item.cvssScore != null ? item.cvssScore.toFixed(1) : 'N/A'}
          </div>
          <div className="cve-stat-card-sub">{formatLabel(item.severity)} severity</div>
        </div>
      </div>

      <div className="cve-intel-section">
        <div className="cve-intel-section-header">
          <h4>Matched Software</h4>
          <p>Software identified in your environment that may be affected</p>
        </div>
        {softwareGroups.length === 0 ? (
          <div className="cve-intel-empty">No software inventory is currently correlated to this CVE.</div>
        ) : (
          <table className="cve-intel-table">
            <thead>
              <tr>
                <th>Software</th>
                <th>Version</th>
                <th>Assets</th>
                <th>Match Basis</th>
                <th>Confidence</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {softwareGroups.map(({ software, assets }) => {
                const conf = confidenceFromApplicability(software.applicabilityState);
                const groupKey = software.version ? `${software.packageName}@${software.version}` : software.packageName;
                const isExpanded = expandedRows.has(groupKey);
                return (
                  <React.Fragment key={groupKey}>
                    <tr>
                      <td>
                        <div className="cve-sw-name-cell">
                          {software.ecosystem && (
                            <span className="cve-ecosystem-tag">{software.ecosystem}</span>
                          )}
                          <strong>{software.packageName}</strong>
                        </div>
                      </td>
                      <td className="mono">{software.version}</td>
                      <td>{assets.length}</td>
                      <td>{matchBasisLabel(software.matchedBy)}</td>
                      <td><span className={`cve-confidence-badge ${conf}`}>{formatLabel(conf)}</span></td>
                      <td>
                        <button
                          type="button"
                          className={`cve-view-assets-btn${isExpanded ? ' active' : ''}`}
                          onClick={() => toggleRow(groupKey)}
                          aria-expanded={isExpanded}
                        >
                          {isExpanded ? 'Hide Assets ›' : `View Assets (${assets.length}) ›`}
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="cve-assets-expansion-row">
                        <td colSpan={6}>
                          <div className="cve-assets-expansion">
                            <table className="cve-assets-mini-table">
                              <thead>
                                <tr>
                                  <th>Asset</th>
                                  <th>Identifier</th>
                                  <th>Finding</th>
                                </tr>
                              </thead>
                              <tbody>
                                {assets.map((asset) => (
                                  <tr key={asset.componentId}>
                                    <td>{asset.assetName ?? <span className="cve-muted">—</span>}</td>
                                    <td className="mono">{asset.assetIdentifier ?? <span className="cve-muted">—</span>}</td>
                                    <td>
                                      {asset.eligibleForFinding
                                        ? <span className="cve-finding-eligible-tag">Finding eligible</span>
                                        : <span className="cve-muted">—</span>}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="cve-intel-section">
        <div className="cve-intel-section-header">
          <h4>Vendor Intelligence</h4>
          <p>Official statements and patch information</p>
        </div>
        {vendorRows.length === 0 ? (
          <div className="cve-intel-empty">No vendor intelligence data available.</div>
        ) : (
          <table className="cve-intel-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Statement</th>
                <th>Package</th>
                <th>Affected Versions</th>
                <th>Fixed In</th>
                <th>CPE</th>
              </tr>
            </thead>
            <tbody>
              {vendorRows.map((row, i) => (
                <tr key={`${row.source}-${i}`}>
                  <td><strong>{row.source}</strong></td>
                  <td><span className={`cve-statement-badge ${row.statementClass}`}>{row.statement}</span></td>
                  <td className="mono">
                    {row.packageName
                      ? <>{row.ecosystem ? <span className="cve-ecosystem-tag">{row.ecosystem}</span> : null}{row.packageName}</>
                      : <span className="cve-muted">—</span>}
                  </td>
                  <td className="mono">{row.affectedVersions}</td>
                  <td className="mono">
                    {row.fixedVersion && row.fixedVersion !== '—'
                      ? <span className="cve-patch-version">{row.fixedVersion}</span>
                      : <span className="cve-muted">—</span>}
                  </td>
                  <td className="mono">
                    {row.cpe
                      ? <span className="cve-cpe-cell" title={row.cpe}>{row.cpe.length > 40 ? row.cpe.substring(0, 40) + '…' : row.cpe}</span>
                      : <span className="cve-muted">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="cve-notes-section">
        <div className="cve-notes-header"><h4>Investigation Notes</h4></div>
        <div className="cve-notes-body">
          {autoNote && (
            <div className="cve-notes-auto-banner">
              <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle cx="12" cy="12" r="9.5" stroke="currentColor" strokeWidth="1.5" />
                <path d="M12 8v4M12 16h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
              <span>{autoNote}</span>
            </div>
          )}
          <textarea
            className="cve-notes-textarea"
            value={investigationNotes}
            onChange={(e) => onNotesChange(e.target.value)}
            placeholder="Add analyst notes..."
            rows={4}
          />
        </div>
      </div>
    </>
  );
}

// --- VEX Evidence Mini-Card ---

function VexEvidenceCard({ evidence }: { evidence: CveVexEvidence }) {
  const rows: Array<{ key: string; value: React.ReactNode }> = [
    { key: 'Asset', value: evidence.assetName ?? evidence.assetIdentifier ?? '—' },
    {
      key: 'Software',
      value: [evidence.packageName, evidence.installedVersion].filter(Boolean).join(' ') || '—',
    },
    {
      key: 'Provider',
      value: `${formatLabel(evidence.provider)} / ${formatLabel(evidence.status)}`,
    },
    {
      key: 'Trust',
      value: `${formatLabel(evidence.trustTier)} trust · ${formatLabel(evidence.freshness)}`,
    },
  ];
  if (evidence.documentId) {
    rows.push({ key: 'Document', value: <span className="mono">{evidence.documentId}</span> });
  }
  if (evidence.evidenceUrl) {
    rows.push({
      key: 'Source',
      value: (
        <a href={evidence.evidenceUrl} target="_blank" rel="noreferrer">
          {evidence.evidenceUrl}
        </a>
      ),
    });
  }
  return (
    <div className="vex-evidence-card">
      <div className="vex-evidence-grid">
        {rows.map(({ key, value }) => (
          <React.Fragment key={key}>
            <span className="vex-evidence-key">{key}</span>
            <span className="vex-evidence-val">{value}</span>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

// --- Applicability Decision Table (step 2, left panel) ---

type ApplicabilityTableProps = {
  matchedSoftware: CveMatchedSoftware[];
  applicabilityDecisions: Map<string, ApplicabilityDecision>;
  impactDecisions: Map<string, ImpactDecision>;
  expandedEvidenceComponentId: string | null;
  vexEvidenceByComponent: Record<string, CveVexEvidence | null>;
  vexEvidenceErrors: Record<string, string | null>;
  vexEvidenceLoadingComponentId: string | null;
  onApplicabilityDecision: (componentId: string, decision: ApplicabilityDecision) => void;
  onBulkApplicabilityDecision: (decision: ApplicabilityDecision) => void;
  onImpactDecision: (componentId: string, decision: ImpactDecision) => void;
  onToggleVexEvidence: (componentId: string) => void | Promise<void>;
};

function ApplicabilityTable({
  matchedSoftware,
  applicabilityDecisions,
  impactDecisions,
  expandedEvidenceComponentId,
  vexEvidenceByComponent,
  vexEvidenceErrors,
  vexEvidenceLoadingComponentId,
  onApplicabilityDecision,
  onBulkApplicabilityDecision,
  onImpactDecision,
  onToggleVexEvidence,
}: ApplicabilityTableProps) {
  const applicableSoftware = matchedSoftware.filter(
    (s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE'
  );

  return (
    <>
      {/* Applicability Assessment */}
      <div className="cve-decision-section">
        <div className="cve-decision-section-header">
          <h4>Applicability Assessment</h4>
          <p>Determine if the matched software is truly relevant to your environment</p>
        </div>
        {matchedSoftware.length === 0 ? (
          <div className="cve-intel-empty">No matched software to assess.</div>
        ) : (
          <>
            <div className="cve-bulk-actions">
              <span className="cve-bulk-actions-label">Mark all:</span>
              <button type="button" className="btn btn-secondary btn-inline" onClick={() => onBulkApplicabilityDecision('APPLICABLE')}>
                Applicable
              </button>
              <button type="button" className="btn btn-secondary btn-inline" onClick={() => onBulkApplicabilityDecision('NOT_APPLICABLE')}>
                Not Applicable
              </button>
              <button type="button" className="btn btn-secondary btn-inline" onClick={() => onBulkApplicabilityDecision('NEEDS_REVIEW')}>
                Needs Review
              </button>
            </div>
            <table className="cve-decision-table">
              <thead>
                <tr>
                  <th>Software</th>
                  <th>Asset</th>
                  <th>Match Basis</th>
                  <th>Confidence</th>
                  <th>Decision</th>
                </tr>
              </thead>
              <tbody>
                {matchedSoftware.map((sw) => {
                  const conf = confidenceFromApplicability(sw.applicabilityState);
                  const decision = applicabilityDecisions.get(sw.componentId) ?? 'NEEDS_REVIEW';
                  return (
                    <tr key={sw.componentId}>
                      <td>
                        <strong>{sw.packageName}</strong> <span className="cve-decision-table-muted">{sw.version}</span>
                        <div className="panel-caption">{explainApplicability(sw)}</div>
                      </td>
                      <td className="cve-decision-table-muted mono">{sw.assetName ?? sw.assetIdentifier ?? '—'}</td>
                      <td className="cve-decision-table-muted">{matchBasisLabel(sw.matchedBy)}</td>
                      <td><span className={`cve-confidence-badge ${conf}`}>{formatLabel(conf)}</span></td>
                      <td>
                        <SegmentedControl
                          ariaLabel={`Applicability for ${sw.packageName}`}
                          value={decision}
                          onChange={(v) => onApplicabilityDecision(sw.componentId, v as ApplicabilityDecision)}
                          options={[
                            { value: 'APPLICABLE', label: 'Applicable', activeClass: 'seg-applicable' },
                            { value: 'NOT_APPLICABLE', label: 'Not Applicable', activeClass: 'seg-not-applicable' },
                            { value: 'NEEDS_REVIEW', label: 'Review', activeClass: 'seg-needs-review' },
                          ]}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>

      {/* Impact Assessment */}
      <div className="cve-decision-section cve-impact-section">
        <div className="cve-decision-section-header cve-impact-section-header">
          <div className="cve-impact-title-row">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className="cve-impact-warn-icon">
              <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
              <path d="M12 9v4M12 17h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <h4>Impact Assessment</h4>
          </div>
          <p>Only applicable software shown. Analyst disposition is captured here, but computed impact stays server-driven from exact VEX evidence.</p>
        </div>
        {applicableSoftware.length === 0 ? (
          <div className="cve-intel-empty">Mark software as Applicable above to assess impact.</div>
        ) : (
          <table className="cve-decision-table">
            <thead>
              <tr>
                <th>Applicable Software</th>
                <th>Asset</th>
                <th>Exact Match</th>
                <th>Analyst Disposition</th>
              </tr>
            </thead>
            <tbody>
              {applicableSoftware.map((sw) => {
                const impact = impactDecisions.get(sw.componentId) ?? 'UNKNOWN';
                const exactMatchMetaLine = exactMatchMeta(sw);
                return (
                  <tr key={sw.componentId}>
                    <td>
                      <strong>{sw.packageName}</strong> <span className="cve-decision-table-muted">{sw.version}</span>
                      <div className="panel-caption">{explainApplicability(sw)}</div>
                    </td>
                    <td className="cve-decision-table-muted mono">{sw.assetName ?? sw.assetIdentifier ?? '—'}</td>
                    <td className="cve-decision-table-muted">
                      <div>{vendorStatementFor(sw)}</div>
                      {exactMatchMetaLine && (
                        <div className="panel-caption">{exactMatchMetaLine}</div>
                      )}
                      {sw.matchedVexAssertionId && (
                        <div className="panel-caption">
                          <button
                            type="button"
                            className="btn-link"
                            onClick={() => void onToggleVexEvidence(sw.componentId)}
                          >
                            {expandedEvidenceComponentId === sw.componentId ? 'Hide VEX evidence' : 'View VEX evidence'}
                          </button>
                        </div>
                      )}
                      {expandedEvidenceComponentId === sw.componentId && (
                        <div>
                          {vexEvidenceLoadingComponentId === sw.componentId && (
                            <div className="panel-caption">Loading VEX evidence...</div>
                          )}
                          {vexEvidenceErrors[sw.componentId] && (
                            <div className="panel-caption">{vexEvidenceErrors[sw.componentId]}</div>
                          )}
                          {vexEvidenceByComponent[sw.componentId] && (
                            <VexEvidenceCard evidence={vexEvidenceByComponent[sw.componentId]!} />
                          )}
                        </div>
                      )}
                    </td>
                    <td>
                      <SegmentedControl
                        ariaLabel={`Impact disposition for ${sw.packageName}`}
                        value={impact}
                        onChange={(v) => onImpactDecision(sw.componentId, v as ImpactDecision)}
                        options={[
                          { value: 'IMPACTED', label: 'Impacted', activeClass: 'seg-impacted' },
                          { value: 'NOT_IMPACTED', label: 'Not Impacted', activeClass: 'seg-not-impacted' },
                          { value: 'UNKNOWN', label: 'Unknown' },
                        ]}
                      />
                      {sw.analystReason && (
                        <div className="panel-caption">{sw.analystReason}</div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// --- Decision Summary Sidebar (step 2, right panel) ---

type DecisionSummaryProps = {
  matchedSoftware: CveMatchedSoftware[];
  applicabilityDecisions: Map<string, ApplicabilityDecision>;
  impactDecisions: Map<string, ImpactDecision>;
  analystRationale: string;
  onAnalystRationaleChange: (v: string) => void;
  latestAssessment: CveApplicabilityAssessment | null;
  saveBusy: boolean;
  analystId?: string;
  onSave: () => void;
  onProceed: () => void;
  onBack: () => void;
};

type CountBadgeProps = { count: number; variant?: 'green' | 'red' | 'orange' | 'grey' };

function CountBadge({ count, variant = 'grey' }: CountBadgeProps) {
  return <span className={`cve-count-badge cve-count-badge-${variant}`}>{count}</span>;
}

function DecisionSummary({
  matchedSoftware, applicabilityDecisions, impactDecisions, analystRationale, onAnalystRationaleChange,
  latestAssessment, saveBusy, analystId, onSave, onProceed, onBack,
}: DecisionSummaryProps) {
  const applicableCount = matchedSoftware.filter((s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE').length;
  const notApplicableCount = matchedSoftware.filter((s) => applicabilityDecisions.get(s.componentId) === 'NOT_APPLICABLE').length;
  const needsReviewCount = matchedSoftware.filter((s) => (applicabilityDecisions.get(s.componentId) ?? 'NEEDS_REVIEW') === 'NEEDS_REVIEW').length;

  const applicableSoftware = matchedSoftware.filter((s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE');
  const computedImpactedCount = applicableSoftware.filter((s) => {
    const state = computedImpactStateOf(s);
    return state === 'IMPACTED' || state === 'NO_PATCH';
  }).length;
  const computedNotImpactedCount = applicableSoftware.filter((s) => {
    const state = computedImpactStateOf(s);
    return state === 'NOT_IMPACTED' || state === 'FIXED';
  }).length;
  const computedUnknownCount = applicableSoftware.filter((s) => {
    const state = computedImpactStateOf(s);
    return state === 'UNKNOWN' || state === 'UNDER_INVESTIGATION';
  }).length;
  const findingEligibleCount = applicableSoftware.filter((s) => s.eligibleForFinding).length;
  const analystImpactedCount = applicableSoftware.filter((s) => impactDecisions.get(s.componentId) === 'IMPACTED').length;
  const analystNotImpactedCount = applicableSoftware.filter((s) => impactDecisions.get(s.componentId) === 'NOT_IMPACTED').length;
  const analystUnknownCount = applicableSoftware.filter((s) => (impactDecisions.get(s.componentId) ?? 'UNKNOWN') === 'UNKNOWN').length;

  const reviewedAt = latestAssessment?.completedAt ?? latestAssessment?.createdAt;
  const assessmentResult = deriveAssessmentResult(matchedSoftware, applicabilityDecisions, impactDecisions);

  const assessmentResultClass: Record<string, string> = {
    AFFECTED: 'assessment-result-affected',
    NOT_AFFECTED: 'assessment-result-not-affected',
    UNDER_INVESTIGATION: 'assessment-result-under-investigation',
    INCONCLUSIVE: 'assessment-result-inconclusive',
  };

  const assessmentResultLabel: Record<string, string> = {
    AFFECTED: 'Affected',
    NOT_AFFECTED: 'Not Affected',
    UNDER_INVESTIGATION: 'Under Investigation',
    INCONCLUSIVE: 'Inconclusive',
  };

  return (
    <aside className="cve-decision-summary-sidebar">
      <div className="cve-decision-summary-card">
        <h4>Decision Summary</h4>

        <div className="assessment-result-banner">
          <span className="assessment-result-label">Assessment Result</span>
          <span className={`assessment-result-badge ${assessmentResultClass[assessmentResult] ?? ''}`}>
            {assessmentResultLabel[assessmentResult] ?? assessmentResult}
          </span>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Applicability</div>
          <div className="cve-decision-summary-row">
            <span>Applicable</span>
            <CountBadge count={applicableCount} variant={applicableCount > 0 ? 'green' : 'grey'} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Not Applicable</span>
            <CountBadge count={notApplicableCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Needs Review</span>
            <CountBadge count={needsReviewCount} variant={needsReviewCount > 0 ? 'orange' : 'grey'} />
          </div>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Computed Impact</div>
          <div className="cve-decision-summary-row">
            <span>Impacted</span>
            <CountBadge count={computedImpactedCount} variant={computedImpactedCount > 0 ? 'red' : 'grey'} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Not Impacted</span>
            <CountBadge count={computedNotImpactedCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Unknown</span>
            <CountBadge count={computedUnknownCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Finding Eligible</span>
            <CountBadge count={findingEligibleCount} variant={findingEligibleCount > 0 ? 'green' : 'grey'} />
          </div>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Analyst Disposition</div>
          <div className="cve-decision-summary-row">
            <span>Impacted</span>
            <CountBadge count={analystImpactedCount} variant={analystImpactedCount > 0 ? 'red' : 'grey'} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Not Impacted</span>
            <CountBadge count={analystNotImpactedCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Unknown</span>
            <CountBadge count={analystUnknownCount} />
          </div>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Analyst Rationale</div>
          <textarea
            className="cve-notes-textarea"
            value={analystRationale}
            onChange={(e) => onAnalystRationaleChange(e.target.value)}
            placeholder="Document your assessment rationale..."
            rows={4}
          />
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Audit Metadata</div>
          <div className="cve-audit-row">
            <span>Reviewed by</span>
            <span>{analystId ?? 'Current User'}</span>
          </div>
          <div className="cve-audit-row">
            <span>Reviewed at</span>
            <span>{reviewedAt ? new Date(reviewedAt).toLocaleString() : new Date().toLocaleString()}</span>
          </div>
          <div className="cve-audit-row">
            <span>Assessment Type</span>
            <span>Manual</span>
          </div>
        </div>

        <div className="cve-decision-summary-actions">
          <button type="button" className="btn btn-secondary" onClick={onSave} disabled={saveBusy}>
            {saveBusy ? 'Saving...' : 'Save Assessment'}
          </button>
          <button type="button" className="btn btn-primary" onClick={onProceed} disabled={saveBusy}>
            {saveBusy ? 'Saving...' : 'Proceed to Findings'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={onBack}>Back</button>
        </div>
      </div>
    </aside>
  );
}

// --- Findings Content (step 3) ---

type FindingsContentProps = {
  filteredSoftware: FindingDisplayRow[];
  selectedIds: Set<string>;
  groupBy: 'ASSET' | 'SOFTWARE';
  showFilter: 'ALL' | 'IMPACTED_ONLY';
  severity: string;
  onToggleRow: (id: string) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
  onGroupByChange: (v: 'ASSET' | 'SOFTWARE') => void;
  onShowFilterChange: (v: 'ALL' | 'IMPACTED_ONLY') => void;
};

function FindingsContent({
  filteredSoftware, selectedIds, groupBy, showFilter, severity,
  onToggleRow, onSelectAll, onClearAll, onGroupByChange, onShowFilterChange,
}: FindingsContentProps) {
  const selectableRows = filteredSoftware.filter((row) => row.selectable);
  const allSelected = selectableRows.length > 0 && selectableRows.every((row) => selectedIds.has(row.software.componentId));
  const someSelected = selectableRows.some((row) => selectedIds.has(row.software.componentId));

  return (
    <div className="cve-findings-selection-panel">
      <div className="cve-findings-filter-bar">
        <div className="cve-findings-filter-item">
          <label htmlFor="findings-group-by">Group by:</label>
          <select id="findings-group-by" value={groupBy} onChange={(e) => onGroupByChange(e.target.value as 'ASSET' | 'SOFTWARE')}>
            <option value="ASSET">Asset</option>
            <option value="SOFTWARE">Software</option>
          </select>
        </div>
        <div className="cve-findings-filter-item">
          <label htmlFor="findings-show">Show:</label>
          <select id="findings-show" value={showFilter} onChange={(e) => onShowFilterChange(e.target.value as 'ALL' | 'IMPACTED_ONLY')}>
            <option value="IMPACTED_ONLY">Finding eligible only</option>
            <option value="ALL">Show excluded rows</option>
          </select>
        </div>
        <div className="cve-findings-filter-links">
          <button type="button" className="cve-findings-link-btn" onClick={onSelectAll}>Select All</button>
          <button type="button" className="cve-findings-link-btn secondary" onClick={onClearAll}>Clear Selection</button>
        </div>
      </div>

      <div className="cve-findings-asset-section">
        <div className="cve-findings-asset-section-header">
          <h4>Select Assets for Finding Creation</h4>
          <p className="panel-caption">Choose which applicable assets should have findings created, including analyst-confirmed impacted overrides.</p>
        </div>

        <table className="cve-findings-asset-table">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={(el) => { if (el) el.indeterminate = someSelected && !allSelected; }}
                  onChange={() => { if (allSelected) onClearAll(); else onSelectAll(); }}
                  disabled={selectableRows.length === 0}
                />
              </th>
              <th>ASSET / CI</th>
              <th>SOFTWARE</th>
              <th>APPLICABILITY</th>
              <th>IMPACT</th>
              <th>ELIGIBILITY REASON</th>
              <th>PRIORITY</th>
            </tr>
          </thead>
          <tbody>
            {filteredSoftware.map((row) => {
              const sw = row.software;
              const checked = selectedIds.has(sw.componentId);
              const computedImpactState = computedImpactStateOf(sw);
              const pri = priorityFromSeverityAndImpact(severity, computedImpactState);
              return (
                <tr
                  key={sw.componentId}
                  className={`cve-findings-asset-row ${checked ? 'selected' : ''}${row.selectable ? '' : ' is-disabled'}`}
                  onClick={() => { if (row.selectable) onToggleRow(sw.componentId); }}
                >
                  <td onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={!row.selectable}
                      onChange={() => { if (row.selectable) onToggleRow(sw.componentId); }}
                    />
                  </td>
                  <td>
                    <div className="cve-findings-asset-name">
                      <svg className="cve-findings-asset-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                        <rect x="1" y="2" width="14" height="10" rx="1.5" stroke="currentColor" strokeWidth="1.2" />
                        <path d="M4 12v2M12 12v2M3 14h10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                      </svg>
                      <span className="mono">{sw.assetName ?? sw.assetIdentifier ?? sw.componentId}</span>
                    </div>
                  </td>
                  <td>{sw.packageName} {sw.version}</td>
                  <td>
                    <span className={`cve-applicability-tag ${row.displayApplicability === 'APPLICABLE' ? 'applicable' : row.displayApplicability === 'NOT_APPLICABLE' ? 'not-applicable' : 'unknown'}`}>
                      {row.displayApplicability === 'APPLICABLE' ? 'Applicable' : row.displayApplicability === 'NOT_APPLICABLE' ? 'Not Applicable' : 'Unknown'}
                    </span>
                  </td>
                  <td>
                    <span className={`cve-impact-badge ${impactBadgeClass(row.displayImpact)}`}>
                      {impactLabel(row.displayImpact)}
                    </span>
                  </td>
                  <td>
                    <strong>{row.eligibilityLabel}</strong>
                    <div className="panel-caption">{row.eligibilityDetail}</div>
                  </td>
                  <td><span className={severityClassName(pri)}>{formatLabel(pri)}</span></td>
                </tr>
              );
            })}
            {filteredSoftware.length === 0 && (
              <tr>
                <td colSpan={7} className="cve-findings-empty-row">
                  No finding rows are available. Mark software as Applicable and Impacted, or use exact impacted/no-patch rows, to create findings.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

type FindingConfigSidebarProps = {
  filteredSoftware: FindingDisplayRow[];
  selectedIds: Set<string>;
  findingTitle: string;
  findingPriority: string;
  assignmentGroup: string;
  ticketTarget: 'SERVICENOW' | 'JIRA';
  dueDate: string;
  findingNotes: string;
  findingBusy: boolean;
  onFindingTitleChange: (v: string) => void;
  onFindingPriorityChange: (v: string) => void;
  onAssignmentGroupChange: (v: string) => void;
  onTicketTargetChange: (v: 'SERVICENOW' | 'JIRA') => void;
  onDueDateChange: (v: string) => void;
  onFindingNotesChange: (v: string) => void;
  onRequestCreateFindings: () => void;
  onRequestCreateGrouped: () => void;
  onSaveAssessment: () => void;
  onBack: () => void;
};

function FindingConfigSidebar({
  filteredSoftware, selectedIds,
  findingTitle, findingPriority, assignmentGroup, ticketTarget, dueDate, findingNotes, findingBusy,
  onFindingTitleChange, onFindingPriorityChange, onAssignmentGroupChange, onTicketTargetChange,
  onDueDateChange, onFindingNotesChange, onRequestCreateFindings, onRequestCreateGrouped, onSaveAssessment, onBack,
}: FindingConfigSidebarProps) {
  const selectedSoftware = filteredSoftware
    .map((row) => row.software)
    .filter((software) => selectedIds.has(software.componentId));
  const selectedCount = selectedSoftware.length;
  const softwareFamilies = new Set(selectedSoftware.map((s) => s.packageName)).size;

  return (
    <aside className="cve-decision-summary-sidebar">
      <div className="cve-decision-summary-card">
        <h4>Finding Configuration</h4>

        <div className="cve-form-field">
          <label htmlFor="finding-title">Finding Title</label>
          <input id="finding-title" type="text" value={findingTitle} onChange={(e) => onFindingTitleChange(e.target.value)} />
        </div>

        <div className="cve-form-field">
          <label htmlFor="finding-priority">Priority</label>
          <select id="finding-priority" value={findingPriority} onChange={(e) => onFindingPriorityChange(e.target.value)}>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <div className="cve-form-field">
          <label htmlFor="assignment-group">Assignment Group</label>
          <input
            id="assignment-group"
            type="text"
            value={assignmentGroup}
            onChange={(e) => onAssignmentGroupChange(e.target.value)}
            placeholder="e.g. IT Infrastructure"
          />
        </div>

        <div className="cve-form-field">
          <label>Ticket Target</label>
          <div className="cve-findings-ticket-target">
            <button
              type="button"
              className={`cve-findings-ticket-btn ${ticketTarget === 'SERVICENOW' ? 'selected' : ''}`}
              onClick={() => onTicketTargetChange('SERVICENOW')}
            >
              ServiceNow
            </button>
            <button
              type="button"
              className={`cve-findings-ticket-btn ${ticketTarget === 'JIRA' ? 'selected' : ''}`}
              onClick={() => onTicketTargetChange('JIRA')}
            >
              Jira
            </button>
          </div>
        </div>

        <div className="cve-form-field">
          <label htmlFor="finding-due-date">Due Date</label>
          <input id="finding-due-date" type="date" value={dueDate} onChange={(e) => onDueDateChange(e.target.value)} />
        </div>

        <div className="cve-form-field">
          <label htmlFor="finding-notes">Notes</label>
          <textarea
            id="finding-notes"
            rows={3}
            value={findingNotes}
            onChange={(e) => onFindingNotesChange(e.target.value)}
            placeholder="Describe the remediation approach..."
          />
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Summary</div>
          <div className="cve-decision-summary-row">
            <span className="panel-caption">Selected Assets</span>
            <span>{selectedCount}</span>
          </div>
          <div className="cve-decision-summary-row">
            <span className="panel-caption">Software Families</span>
            <span>{softwareFamilies}</span>
          </div>
          <div className="cve-decision-summary-row">
            <span className="panel-caption">Estimated Tickets</span>
            <span>{selectedCount}</span>
          </div>
        </div>

        <div className="cve-decision-summary-actions">
          <button
            type="button"
            className="btn btn-primary"
            onClick={onRequestCreateFindings}
            disabled={findingBusy || selectedCount === 0}
          >
            {findingBusy ? 'Creating...' : `Create Findings (${selectedCount})`}
          </button>
          <button type="button" className="btn btn-secondary" onClick={onRequestCreateGrouped} disabled={findingBusy || selectedCount === 0}>
            Create One Grouped Finding
          </button>
          <button type="button" className="btn btn-secondary" onClick={onSaveAssessment} disabled={findingBusy}>
            Save Assessment
          </button>
          <button type="button" className="btn btn-secondary" onClick={onBack}>
            Back
          </button>
        </div>
      </div>
    </aside>
  );
}

// --- Main Component ---

export function CveAssessmentWorkbench({ item, detail, loading, error, findingGenerationMode, analystId, onBack, onRefreshDetail }: Props) {
  const [activeStep, setActiveStep] = React.useState<WorkflowStep>(1);
  const [actionNotice, setActionNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const latestInvestigation = React.useMemo(() => latestByDate(detail?.investigations ?? []), [detail]);
  const latestAssessment = React.useMemo(() => latestByDate(detail?.assessments ?? []), [detail]);

  // Investigation state
  const [investigationId, setInvestigationId] = React.useState<number | null>(null);
  const investigationStatus: InvestigationStatus = 'IN_PROGRESS';
  const investigationPriority: InvestigationPriority = 'MEDIUM';
  const assignedTo = '';
  const [investigationNotes, setInvestigationNotes] = React.useState('');
  const [investigationBusy, setInvestigationBusy] = React.useState(false);

  // Applicability state
  const [assessmentId, setAssessmentId] = React.useState<number | null>(null);
  const [applicabilityDecisions, setApplicabilityDecisions] = React.useState<Map<string, ApplicabilityDecision>>(new Map());
  const [impactDecisions, setImpactDecisions] = React.useState<Map<string, ImpactDecision>>(new Map());
  const [analystRationale, setAnalystRationale] = React.useState('');
  const [assessmentBusy, setAssessmentBusy] = React.useState(false);
  const [expandedEvidenceComponentId, setExpandedEvidenceComponentId] = React.useState<string | null>(null);
  const [vexEvidenceByComponent, setVexEvidenceByComponent] = React.useState<Record<string, CveVexEvidence | null>>({});
  const [vexEvidenceErrors, setVexEvidenceErrors] = React.useState<Record<string, string | null>>({});
  const [vexEvidenceLoadingComponentId, setVexEvidenceLoadingComponentId] = React.useState<string | null>(null);

  // Findings state
  const [findingTitle, setFindingTitle] = React.useState(() => `${item.externalId} - ${item.title}`);
  const [findingPriority, setFindingPriority] = React.useState(() => item.severity?.toUpperCase() ?? 'MEDIUM');
  const [assignmentGroup, setAssignmentGroup] = React.useState('');
  const [ticketTarget, setTicketTarget] = React.useState<'SERVICENOW' | 'JIRA'>('SERVICENOW');
  const [dueDate, setDueDate] = React.useState('');
  const [findingNotes, setFindingNotes] = React.useState('');
  const [selectedFindingIds, setSelectedFindingIds] = React.useState<Set<string>>(new Set());
  const [findingGroupBy, setFindingGroupBy] = React.useState<'ASSET' | 'SOFTWARE'>('ASSET');
  const [findingShowFilter, setFindingShowFilter] = React.useState<'ALL' | 'IMPACTED_ONLY'>('IMPACTED_ONLY');
  const [findingBusy, setFindingBusy] = React.useState(false);

  // Unsaved-changes guard
  const seedNotesRef = React.useRef('');
  const seedRationaleRef = React.useRef('');
  const [pendingNavAction, setPendingNavAction] = React.useState<(() => void) | null>(null);

  // Finding creation confirmation
  const [pendingFindingAction, setPendingFindingAction] = React.useState<(() => Promise<void>) | null>(null);

  const isDirty = investigationNotes !== seedNotesRef.current || analystRationale !== seedRationaleRef.current;

  function guardedNav(action: () => void): void {
    if (isDirty) {
      setPendingNavAction(() => action);
    } else {
      action();
    }
  }

  // Guard: track which CVE has been initialized so detail refreshes don't overwrite in-flight decisions
  const lastInitializedCveRef = React.useRef<string | null>(null);

  React.useEffect(() => {
    if (!detail) return;
    // Only reinitialize when opening a different CVE, not when detail refreshes mid-session
    if (lastInitializedCveRef.current === item.externalId) return;
    lastInitializedCveRef.current = item.externalId;

    const inv = latestInvestigation as CveInvestigation | null;
    setInvestigationId(inv?.id ?? null);
    const seedNotes = inv?.notes ?? '';
    setInvestigationNotes(seedNotes);
    seedNotesRef.current = seedNotes;

    const assess = latestAssessment as CveApplicabilityAssessment | null;
    setAssessmentId(assess?.id ?? null);
    const seedRationale = assess?.justification ?? '';
    setAnalystRationale(seedRationale);
    seedRationaleRef.current = seedRationale;

    // Initialize per-row applicability decisions from existing state
    const initialApplicability = new Map<string, ApplicabilityDecision>();
    for (const sw of detail.matchedSoftware) {
      initialApplicability.set(sw.componentId, initialApplicabilityDecision(sw.applicabilityState));
    }
    setApplicabilityDecisions(initialApplicability);

    // Initialize impact decisions — default UNKNOWN
    const initialImpact = new Map<string, ImpactDecision>();
    for (const sw of detail.matchedSoftware) {
      if (sw.applicabilityState === 'APPLICABLE') {
        const seededDecision = sw.analystDisposition
          ?? (computedImpactStateOf(sw) === 'IMPACTED' || computedImpactStateOf(sw) === 'NO_PATCH'
            ? 'IMPACTED'
            : computedImpactStateOf(sw) === 'NOT_IMPACTED' || computedImpactStateOf(sw) === 'FIXED'
              ? 'NOT_IMPACTED'
              : 'UNKNOWN');
        initialImpact.set(sw.componentId, seededDecision);
      }
    }
    setImpactDecisions(initialImpact);

    // Pre-select all eligible software for finding creation
    const eligible = detail.matchedSoftware.filter((s) => s.eligibleForFinding && s.analystDisposition !== 'NOT_IMPACTED');
    setSelectedFindingIds(new Set(eligible.map((s) => s.componentId)));
    setExpandedEvidenceComponentId(null);
    setVexEvidenceByComponent({});
    setVexEvidenceErrors({});
    setVexEvidenceLoadingComponentId(null);
  }, [detail, item.externalId, latestAssessment, latestInvestigation]);

  const toggleVexEvidence = React.useCallback(async (componentId: string) => {
    if (expandedEvidenceComponentId === componentId) {
      setExpandedEvidenceComponentId(null);
      return;
    }
    setExpandedEvidenceComponentId(componentId);
    if (vexEvidenceByComponent[componentId] || vexEvidenceLoadingComponentId === componentId) {
      return;
    }
    setVexEvidenceLoadingComponentId(componentId);
    setVexEvidenceErrors((current) => ({ ...current, [componentId]: null }));
    try {
      const evidence = await cveWorkbenchApi.getCveVexEvidence(item.externalId, componentId);
      setVexEvidenceByComponent((current) => ({ ...current, [componentId]: evidence }));
    } catch (requestError) {
      const rawMessage = requestError instanceof Error ? requestError.message : String(requestError);
      const message = rawMessage.includes('(404)') || rawMessage.includes('[NOT_FOUND]')
        ? 'No persisted VEX evidence is currently linked to this component.'
        : rawMessage;
      setVexEvidenceErrors((current) => ({ ...current, [componentId]: message }));
    } finally {
      setVexEvidenceLoadingComponentId((current) => (current === componentId ? null : current));
    }
  }, [expandedEvidenceComponentId, item.externalId, vexEvidenceByComponent, vexEvidenceLoadingComponentId]);

  const softwareGroups = React.useMemo(
    () => buildSoftwareGroups(detail?.matchedSoftware ?? []),
    [detail]
  );

  const currentApplicableSoftware = React.useMemo(
    () => applicableSoftwareRows(detail?.matchedSoftware ?? [], applicabilityDecisions),
    [detail, applicabilityDecisions]
  );

  const filteredFindingSoftware = React.useMemo<FindingDisplayRow[]>(() => {
    return buildFindingDisplayRows(
      currentApplicableSoftware,
      applicabilityDecisions,
      impactDecisions,
      findingShowFilter
    );
  }, [currentApplicableSoftware, applicabilityDecisions, impactDecisions, findingShowFilter]);

  const cvssFields = React.useMemo(() => parseCvssVector(detail?.summary.cvssVector), [detail]);

  const autoNote = React.useMemo(() => {
    if (!detail || !item) return '';
    const parts: string[] = [];
    const topProducts = softwareGroups.slice(0, 2).map((g) => g.software.packageName).join(', ');
    if (topProducts) {
      parts.push(`${detail.signals.softwareCount > 0 ? 'High confidence match' : 'No direct software match'}. ${topProducts} detected with potentially vulnerable versions.`);
    }
    if (detail.signals.patchAvailable && detail.signals.patchVersions) {
      parts.push(`Patch available: ${detail.signals.patchVersions}.`);
    } else if (!detail.signals.patchAvailable) {
      parts.push('No patch currently available.');
    }
    if (item.inKev) parts.push('This CVE is in the CISA KEV catalog — active exploitation confirmed.');
    return parts.join(' ');
  }, [detail, item, softwareGroups]);

  const vendorRows = React.useMemo((): VendorRow[] => {
    if (!detail) return [];
    const rows: VendorRow[] = [];

    const intel: VendorIntelligence[] = detail.vendorIntelligence ?? [];
    if (intel.length > 0) {
      for (const vi of intel) {
        const vexNormalized = vi.vexStatus?.toUpperCase();
        const statementClass =
          vexNormalized === 'NOT_AFFECTED' || vexNormalized === 'FIXED' ? 'resolved'
          : vexNormalized === 'UNDER_INVESTIGATION' ? 'under-investigation'
          : 'affected';
        const statement =
          vi.vexStatus ? formatLabel(vi.vexStatus)
          : 'Affected';
        rows.push({
          source: vi.source,
          statement,
          statementClass,
          affectedVersions: vi.affectedVersions,
          fixedVersion: vi.fixedVersion ?? '—',
          ecosystem: vi.ecosystem ?? undefined,
          packageName: vi.packageName ?? undefined,
          cpe: vi.cpe ?? undefined,
          vexStatus: vi.vexStatus ?? undefined,
        });
      }
    } else {
      // Fallback when backend returns no vendor intelligence records
      rows.push({
        source: detail.summary.source ?? 'ADVISORY',
        statement: 'Affected',
        statementClass: 'affected',
        affectedVersions: detail.signals.patchVersions ? `< ${detail.signals.patchVersions}` : 'See advisory',
        fixedVersion: detail.signals.patchVersions ?? '—',
      });
    }

    if (item.inKev) {
      // BLG-004: KEV signals exploitability, not product applicability. It is NOT an
      // authoritative source for determining whether your specific version is affected.
      // Rendered with a distinct style so analysts don't conflate it with NVD/VEX/advisory rows.
      rows.push({
        source: 'CISA KEV (exploitability context)',
        statement: 'Actively Exploited — not an applicability source',
        statementClass: 'exploited kev-context',
        affectedVersions: '— (no version data)',
        fixedVersion: '—',
      });
    }
    return rows;
  }, [detail, item]);

  const overallConfidence = React.useMemo(() => {
    if (!detail) return { label: 'Unknown', cls: '', pct: 0 };
    const applicable = detail.matchedSoftware.filter((s) => s.applicabilityState === 'APPLICABLE').length;
    const total = detail.matchedSoftware.length;
    if (total === 0) return { label: 'Unknown', cls: '', pct: 0 };
    const pct = Math.round((applicable / total) * 100);
    if (pct >= 70) return { label: 'High', cls: 'is-high', pct };
    if (pct >= 40) return { label: 'Medium', cls: 'is-medium', pct };
    return { label: 'Low', cls: 'is-low', pct };
  }, [detail]);

  function setApplicabilityDecision(componentId: string, decision: ApplicabilityDecision): void {
    setApplicabilityDecisions((prev) => new Map(prev).set(componentId, decision));
    // If changing to non-applicable, clear impact decision
    if (decision !== 'APPLICABLE') {
      setImpactDecisions((prev) => { const next = new Map(prev); next.delete(componentId); return next; });
    } else {
      // Default to UNKNOWN when marked applicable
      setImpactDecisions((prev) => { const next = new Map(prev); if (!next.has(componentId)) next.set(componentId, 'UNKNOWN'); return next; });
    }
  }

  function setImpactDecision(componentId: string, decision: ImpactDecision): void {
    setImpactDecisions((prev) => new Map(prev).set(componentId, decision));
  }

  const currentBreadcrumbStep = activeStep === 1 ? null : activeStep === 2 ? 'Applicability' : 'Create Findings';

  async function saveInvestigationAndContinue(): Promise<void> {
    setInvestigationBusy(true);
    setActionError(null);
    try {
      const saved = await cveWorkbenchApi.submitCveInvestigation(item.externalId, {
        priority: investigationPriority,
        assignedTo: assignedTo.trim() || undefined,
        notes: investigationNotes.trim() || undefined,
      });
      setInvestigationId(saved.id);
      setActiveStep(2);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setInvestigationBusy(false);
    }
  }

  async function saveAssessment(proceed: boolean): Promise<void> {
    if (!detail) return;
    setAssessmentBusy(true);
    setActionError(null);
    try {
      const matchedSoftwareList = detail.matchedSoftware;
      const applicableComponents = matchedSoftwareList
        .filter((s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE')
        .map((s) => softwareLabel(s));

      const finalResult = deriveAssessmentResult(matchedSoftwareList, applicabilityDecisions, impactDecisions);
      const hasImpacted = Array.from(impactDecisions.values()).some((d) => d === 'IMPACTED');

      const componentImpactDecisions: Record<string, 'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN'> = {};
      impactDecisions.forEach((decision, componentId) => {
        componentImpactDecisions[componentId] = decision;
      });

      const saved = await cveWorkbenchApi.submitCveAssessment(item.externalId, {
        softwareDetected: applicableComponents.length > 0,
        detectionMethod: 'SOFTWARE_INVENTORY',
        affectedComponents: applicableComponents.join('\n'),
        vulnerableVersionPresent: hasImpacted || undefined,
        finalResult,
        confidenceLevel: overallConfidence.label.toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW',
        justification: analystRationale.trim(),
        recommendedAction: '',
        componentImpactDecisions,
        componentAnalystDispositions: componentImpactDecisions,
      });
      setAssessmentId(saved.id);

      if (proceed) setActiveStep(3);
      else setActionNotice('Assessment saved successfully.');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setAssessmentBusy(false);
    }
  }

  async function createFindings(): Promise<void> {
    if (selectedFindingIds.size === 0) {
      setActionError('Select at least one finding row before creating findings.');
      return;
    }
    setFindingBusy(true);
    setActionError(null);
    try {
      const result = await cveWorkbenchApi.createManualFindings(item.externalId, {
        justification: findingNotes.trim(),
        componentIds: Array.from(selectedFindingIds),
        componentApplicabilityDecisions: Object.fromEntries(applicabilityDecisions),
        componentAnalystDispositions: Object.fromEntries(impactDecisions),
      });
      await onRefreshDetail();
      const parts: string[] = [result.message];
      if (result.createdCount > 0) parts.push(`Created ${result.createdCount}.`);
      if (result.reopenedCount > 0) parts.push(`Reopened ${result.reopenedCount}.`);
      if (result.alreadyOpenCount > 0) parts.push(`${result.alreadyOpenCount} already open.`);
      setActionNotice(parts.join(' '));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setFindingBusy(false);
    }
  }

  function toggleFindingRow(componentId: string): void {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(componentId)) next.delete(componentId);
      else next.add(componentId);
      return next;
    });
  }

  function selectAllFindings(): void {
    setSelectedFindingIds(new Set(filteredFindingSoftware.filter((row) => row.selectable).map((row) => row.software.componentId)));
  }

  function clearAllFindings(): void {
    setSelectedFindingIds(new Set());
  }

  const stepLabels: Array<{ step: WorkflowStep; label: string }> = [
    { step: 1, label: 'Investigation' },
    { step: 2, label: 'Applicability' },
    { step: 3, label: 'Create Findings' },
  ];

  return (
    <div className="cve-assessment-page">
      {/* Breadcrumb */}
      <div className="cve-assessment-breadcrumb">
        <button type="button" onClick={() => guardedNav(onBack)}>CVE Assessment</button>
        <span aria-hidden="true">›</span>
        <button type="button" onClick={() => guardedNav(() => setActiveStep(1))}>{item.externalId}</button>
        {currentBreadcrumbStep && (
          <>
            <span aria-hidden="true">›</span>
            <span>{currentBreadcrumbStep}</span>
          </>
        )}
      </div>

      {/* Header */}
      <div className="cve-assessment-header">
        <div className="cve-assessment-header-left">
          <span className="cve-assessment-id">{item.externalId}</span>
          <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span>
          {item.cvssScore != null && <span className="cve-score-pill">{item.cvssScore.toFixed(1)}</span>}
          {item.inKev && <span className="severity-pill severity-critical">KEV</span>}
          {detail?.signals.exploitAvailable && (
            <span className="status-pill status-in-progress">
              {detail.signals.exploitReason || 'Exploit Available'}
            </span>
          )}
        </div>
        <span className="cve-assessment-last-reviewed">
          Last evaluated {detail?.summary.modifiedAt ? formatDate(detail.summary.modifiedAt) : '-'}
        </span>
      </div>

      {/* Stepper */}
      <div className="cve-stepper">
        {stepLabels.map(({ step, label }, index) => (
          <React.Fragment key={step}>
            {index > 0 && <span className="cve-stepper-connector" aria-hidden="true">›</span>}
            <div
              className={`cve-stepper-item ${activeStep === step ? 'active' : ''} ${activeStep > step ? 'completed' : ''}`}
            >
              <span className="cve-stepper-number">
                {activeStep > step ? (
                  <svg viewBox="0 0 14 14" fill="none" aria-hidden="true">
                    <path d="M2.5 7L5.5 10L11.5 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                ) : step}
              </span>
              <span className="cve-stepper-label">{label}</span>
            </div>
          </React.Fragment>
        ))}
      </div>

      {loading ? (
        <div className="notice">Loading CVE details...</div>
      ) : error ? (
        <div className="notice error">{error}</div>
      ) : !detail ? (
        <div className="notice error">No detail available for this CVE.</div>
      ) : (
        <>
          {actionNotice && <div className="notice">{actionNotice}</div>}
          {actionError && <div className="notice error">{actionError}</div>}

          {/* Step 1 — Investigation */}
          {activeStep === 1 && (
            <div className="cve-assessment-layout">
              <CveSummarySidebar item={item} detail={detail} cvssFields={cvssFields} softwareGroups={softwareGroups} />
              <div className="cve-investigation-main">
                <InvestigationContent
                  item={item}
                  detail={detail}
                  softwareGroups={softwareGroups}
                  vendorRows={vendorRows}
                  overallConfidence={overallConfidence}
                  investigationNotes={investigationNotes}
                  autoNote={autoNote}
                  onNotesChange={setInvestigationNotes}
                />
              </div>
            </div>
          )}

          {/* Step 2 — Applicability */}
          {activeStep === 2 && (
            <div className="cve-applicability-layout">
              <div className="cve-applicability-main">
                <ApplicabilityTable
                  matchedSoftware={detail.matchedSoftware}
                  applicabilityDecisions={applicabilityDecisions}
                  impactDecisions={impactDecisions}
                  expandedEvidenceComponentId={expandedEvidenceComponentId}
                  vexEvidenceByComponent={vexEvidenceByComponent}
                  vexEvidenceErrors={vexEvidenceErrors}
                  vexEvidenceLoadingComponentId={vexEvidenceLoadingComponentId}
                  onApplicabilityDecision={setApplicabilityDecision}
                  onBulkApplicabilityDecision={(decision) => {
                    detail.matchedSoftware.forEach((sw) => setApplicabilityDecision(sw.componentId, decision));
                  }}
                  onImpactDecision={setImpactDecision}
                  onToggleVexEvidence={toggleVexEvidence}
                />
              </div>
              <DecisionSummary
                matchedSoftware={detail.matchedSoftware}
                applicabilityDecisions={applicabilityDecisions}
                impactDecisions={impactDecisions}
                analystRationale={analystRationale}
                onAnalystRationaleChange={setAnalystRationale}
                latestAssessment={latestAssessment}
                saveBusy={assessmentBusy}
                analystId={analystId}
                onSave={() => saveAssessment(false)}
                onProceed={() => saveAssessment(true)}
                onBack={() => guardedNav(() => setActiveStep(1))}
              />
            </div>
          )}

          {/* Step 3 — Create Findings */}
          {activeStep === 3 && (
            <div className="cve-applicability-layout">
              <FindingsContent
                filteredSoftware={filteredFindingSoftware}
                selectedIds={selectedFindingIds}
                groupBy={findingGroupBy}
                showFilter={findingShowFilter}
                severity={item.severity}
                onToggleRow={toggleFindingRow}
                onSelectAll={selectAllFindings}
                onClearAll={clearAllFindings}
                onGroupByChange={setFindingGroupBy}
                onShowFilterChange={setFindingShowFilter}
              />
              <FindingConfigSidebar
                filteredSoftware={filteredFindingSoftware}
                selectedIds={selectedFindingIds}
                findingTitle={findingTitle}
                findingPriority={findingPriority}
                assignmentGroup={assignmentGroup}
                ticketTarget={ticketTarget}
                dueDate={dueDate}
                findingNotes={findingNotes}
                findingBusy={findingBusy}
                onFindingTitleChange={setFindingTitle}
                onFindingPriorityChange={setFindingPriority}
                onAssignmentGroupChange={setAssignmentGroup}
                onTicketTargetChange={setTicketTarget}
                onDueDateChange={setDueDate}
                onFindingNotesChange={setFindingNotes}
                onRequestCreateFindings={() => setPendingFindingAction(() => createFindings)}
                onRequestCreateGrouped={() => setPendingFindingAction(() => createFindings)}
                onSaveAssessment={() => saveAssessment(false)}
                onBack={() => setActiveStep(2)}
              />
            </div>
          )}

          {/* Footer — only for step 1 */}
          {activeStep === 1 && (
            <div className="cve-assessment-footer">
              <div className="cve-assessment-footer-left">
                <button type="button" className="btn btn-secondary" onClick={() => guardedNav(onBack)}>← Workbench</button>
                <button type="button" className="btn btn-secondary">Mark Deferred</button>
                <button type="button" className="btn btn-secondary">Export Evidence</button>
              </div>
              <div className="cve-assessment-footer-right">
                <button type="button" className="btn btn-primary" onClick={saveInvestigationAndContinue} disabled={investigationBusy}>
                  {investigationBusy ? 'Saving...' : 'Continue to Applicability'}
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Unsaved-changes navigation guard */}
      <ConfirmDialog
        isOpen={pendingNavAction !== null}
        title="Unsaved Changes"
        message="You have unsaved notes or rationale. Navigating away will discard them. Continue?"
        confirmLabel="Discard & Leave"
        cancelLabel="Stay"
        onConfirm={() => {
          const action = pendingNavAction;
          setPendingNavAction(null);
          action?.();
        }}
        onCancel={() => setPendingNavAction(null)}
      />

      {/* Finding creation confirmation */}
      <ConfirmDialog
        isOpen={pendingFindingAction !== null}
        title={`Create ${selectedFindingIds.size} Finding${selectedFindingIds.size === 1 ? '' : 's'}?`}
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
    </div>
  );
}
