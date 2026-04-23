import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import type { Finding } from '../features/findings/types';
import { pathForVulnRepoView, pathForInventoryHostAsset, type VulnerabilityIntelRouteView } from '../app/routes';
import { apiRequest, api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { AiSolutionApiResponse } from '../features/cve-workbench/api';
import type { CveDetail, VendorIntelligence, ServiceNowIncidentResponse, CreateServiceNowIncidentRequest } from '../features/cve-workbench/types';
import type { HostAssetSummary } from '../features/inventory/api-types';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';
import { computeFindingPriorityScore, riskScoreLabel } from '../lib/riskScoring';

// ─── helpers ──────────────────────────────────────────────────────────────────

function fmt(v?: string | null): string {
  if (!v) return '—';
  return v.replace(/[_-]+/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
}

function fmtDate(v?: string | null): string {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function fmtDt(v?: string | null): string {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function isOverdue(dueAt?: string | null): boolean {
  if (!dueAt) return false;
  return new Date(dueAt).getTime() < Date.now();
}

function statusCls(f: Finding): string {
  if (f.status === 'RESOLVED') return 'status-pill status-resolved';
  if (f.status === 'SUPPRESSED') return 'status-pill status-suppressed';
  if (f.status === 'AUTO_CLOSED') return 'status-pill status-auto-closed';
  if (f.status === 'OPEN' && f.decisionState === 'UNDER_INVESTIGATION') return 'status-pill status-investigating';
  return 'status-pill status-open';
}

function statusLabel(f: Finding): string {
  if (f.status === 'RESOLVED') return 'Resolved';
  if (f.status === 'AUTO_CLOSED') return 'Closed';
  if (f.status === 'SUPPRESSED') {
    const r = (f.suppressionReason ?? '').toUpperCase();
    if (r.includes('FALSE_POSITIVE')) return 'False Positive';
    if (r.includes('DUPLICATE')) return 'Duplicate';
    return 'Deferred';
  }
  if (f.status === 'OPEN' && f.decisionState === 'UNDER_INVESTIGATION') return 'Under Investigation';
  if (f.status === 'OPEN') return 'Open';
  return fmt(f.status);
}

function decisionCls(d: string) {
  if (d === 'AFFECTED') return 'fd3-decision fd3-decision--affected';
  if (d === 'NOT_AFFECTED') return 'fd3-decision fd3-decision--not-affected';
  if (d === 'FIXED') return 'fd3-decision fd3-decision--fixed';
  if (d === 'UNDER_INVESTIGATION') return 'fd3-decision fd3-decision--investigating';
  return 'fd3-decision fd3-decision--review';
}

// UUID pattern – finding IDs from the backend are always UUID format
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function updateWorkflow(findingId: string, payload: Record<string, unknown>) {
  if (!findingId || !UUID_RE.test(findingId)) {
    throw new Error(`Invalid finding ID "${findingId}" – navigate back to the Findings list and reopen this finding.`);
  }
  return apiRequest(`/findings/${findingId}/workflow`, { method: 'PUT', body: JSON.stringify(payload) });
}

// ─── sub-components ───────────────────────────────────────────────────────────

function KVRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="fd3-kv-row">
      <span className="fd3-kv-key">{label}</span>
      <span className="fd3-kv-val">{children ?? <span className="fd3-empty">—</span>}</span>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="fd3-panel">
      <div className="fd3-panel-title">{title}</div>
      <div className="fd3-panel-body">{children}</div>
    </div>
  );
}

// ─── main component ───────────────────────────────────────────────────────────

type ActionType = 'create-incident' | 'defer' | 'resolve' | 'under-investigation' | 'false-positive' | 'reopen';

export function FindingDetailPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const finding = (location.state as { finding?: Finding } | null)?.finding ?? null;
  const returnTo = searchParams.get('returnTo') || '/findings';
  const policyQuery = useRiskPolicyQuery();

  // ── local state ────────────────────────────────────────────────────────────
  const [currentFinding, setCurrentFinding] = React.useState<Finding | null>(finding);
  const [assignedTo, setAssignedTo] = React.useState(finding?.assignedTo ?? '');
  const [editingAssignee, setEditingAssignee] = React.useState(false);
  const [assigneeSaving, setAssigneeSaving] = React.useState(false);

  const [assignmentGroup, setAssignmentGroup] = React.useState('');
  const [editingGroup, setEditingGroup] = React.useState(false);
  const [groupSaving, setGroupSaving] = React.useState(false);

  const [actionModal, setActionModal] = React.useState<ActionType | null>(null);
  const [actionLoading, setActionLoading] = React.useState(false);
  const [actionError, setActionError] = React.useState('');
  const [actionDone, setActionDone] = React.useState('');

  // action form fields
  const [deferReason, setDeferReason] = React.useState('');
  const [deferExpiry, setDeferExpiry] = React.useState('');
  const [fpJustification, setFpJustification] = React.useState('');
  const [incidentPriority, setIncidentPriority] = React.useState('3');
  const [incidentAssignedTo, setIncidentAssignedTo] = React.useState('');
  const [incidentAssignmentGroup, setIncidentAssignmentGroup] = React.useState('');
  const [incidentDueDate, setIncidentDueDate] = React.useState('');
  const [incidentNotes, setIncidentNotes] = React.useState('');
  const [incidentResult, setIncidentResult] = React.useState<ServiceNowIncidentResponse[] | null>(null);

  // remote data
  const [cveDetail, setCveDetail] = React.useState<CveDetail | null>(null);
  const [vendorIntel, setVendorIntel] = React.useState<VendorIntelligence[] | null>(null);
  const [aiSolution, setAiSolution] = React.useState<AiSolutionApiResponse | null>(null);
  const [hostAssetId, setHostAssetId] = React.useState<string | null>(null);
  const [hostAsset, setHostAsset] = React.useState<HostAssetSummary | null>(null);

  React.useEffect(() => {
    if (!currentFinding) return;
    cveWorkbenchApi.getCveDetail(currentFinding.vulnerabilityId)
      .then(d => { setCveDetail(d); setVendorIntel(d.vendorIntelligence ?? []); })
      .catch(() => { setCveDetail(null); setVendorIntel([]); });
    cveWorkbenchApi.getSavedAiSolution(currentFinding.vulnerabilityId)
      .then(r => setAiSolution(r))
      .catch(() => setAiSolution(null));
  }, [currentFinding?.vulnerabilityId]);

  React.useEffect(() => {
    if (!currentFinding) return;
    api.listAssets().then(assets => {
      const match = assets.find(
        a => a.identifier === currentFinding.assetIdentifier || a.name === currentFinding.assetName
      );
      if (match) {
        setHostAssetId(match.id);
        api.getHostAssetDetail(match.id)
          .then(detail => setHostAsset(detail.host))
          .catch(() => {});
      }
    }).catch(() => {});
  }, [currentFinding?.assetIdentifier]);

  if (!currentFinding) {
    return (
      <div className="page-grid">
        <section className="panel">
          <div style={{ padding: 48, textAlign: 'center' }}>
            <h2 style={{ marginBottom: 12 }}>Finding not available</h2>
            <p style={{ color: 'var(--muted)', marginBottom: 16 }}>
              Navigate here from the Findings list or the CVE Assessment Workbench.
            </p>
            <button className="btn btn-secondary" onClick={() => navigate(returnTo)}>← Back to Findings</button>
          </div>
        </section>
      </div>
    );
  }

  const overdue = isOverdue(currentFinding.dueAt) && currentFinding.status === 'OPEN';

  // ── assignee save ──────────────────────────────────────────────────────────
  async function saveAssignee() {
    setAssigneeSaving(true);
    try {
      await updateWorkflow(currentFinding!.id, { assignedTo: assignedTo.trim() || null, actor: 'local-analyst' });
      setCurrentFinding(f => f ? { ...f, assignedTo: assignedTo.trim() || undefined } : f);
      setEditingAssignee(false);
    } catch { /**/ }
    finally { setAssigneeSaving(false); }
  }

  async function saveAssignmentGroup() {
    setGroupSaving(true);
    try {
      await updateWorkflow(currentFinding!.id, { assignmentGroup: assignmentGroup.trim() || null, actor: 'local-analyst' });
      setEditingGroup(false);
    } catch { /**/ }
    finally { setGroupSaving(false); }
  }

  // ── modal helpers ──────────────────────────────────────────────────────────
  function openModal(t: ActionType) {
    setActionModal(t); setActionError(''); setActionDone(''); setIncidentResult(null);
  }
  function closeModal() {
    setActionModal(null); setActionError(''); setActionDone('');
    setDeferReason(''); setDeferExpiry(''); setFpJustification('');
    setIncidentPriority('3'); setIncidentAssignedTo(''); setIncidentAssignmentGroup('');
    setIncidentDueDate(''); setIncidentNotes(''); setIncidentResult(null);
  }
  async function applyWorkflow(payload: Record<string, unknown>, successMsg: string) {
    setActionLoading(true); setActionError('');
    try {
      await updateWorkflow(currentFinding!.id, payload);
      setCurrentFinding(f => {
        if (!f) return f;
        const updates: Partial<Finding> = {};
        if (payload.status) updates.status = payload.status as Finding['status'];
        if (payload.decisionState) updates.decisionState = payload.decisionState as Finding['decisionState'];
        if (payload.suppressionReason) updates.suppressionReason = payload.suppressionReason as string;
        if (payload.suppressedUntil) updates.suppressedUntil = payload.suppressedUntil as string;
        return { ...f, ...updates };
      });
      setActionDone(successMsg);
    } catch (e) { setActionError(String(e)); }
    finally { setActionLoading(false); }
  }

  async function handleResolve() {
    await applyWorkflow({ status: 'RESOLVED', actor: 'local-analyst' }, 'Finding marked as Resolved.');
  }
  async function handleDefer() {
    await applyWorkflow({
      status: 'SUPPRESSED',
      suppressionReason: deferReason || 'DEFERRED',
      suppressedUntil: deferExpiry ? new Date(deferExpiry).toISOString() : undefined,
      actor: 'local-analyst',
    }, 'Finding deferred successfully.');
  }
  async function handleFalsePositive() {
    await applyWorkflow({
      status: 'SUPPRESSED',
      suppressionReason: `FALSE_POSITIVE${fpJustification ? ': ' + fpJustification : ''}`,
      actor: 'local-analyst',
    }, 'Finding marked as False Positive.');
  }
  async function handleUnderInvestigation() {
    await applyWorkflow({ status: 'OPEN', decisionState: 'UNDER_INVESTIGATION', actor: 'local-analyst' }, 'Status updated to Under Investigation.');
  }
  async function handleReopen() {
    await applyWorkflow({ status: 'OPEN', actor: 'local-analyst' }, 'Finding re-opened successfully.');
  }
  async function handleCreateIncident() {
    setActionLoading(true); setActionError('');
    const f = currentFinding!;
    try {
      const payload: CreateServiceNowIncidentRequest = {
        findingTitle: `${f.vulnerabilityId} — Vulnerability Remediation`,
        severity: f.severity,
        cvssScore: undefined,
        inKev: f.inKev,
        priority: incidentPriority,
        dueDate: incidentDueDate || undefined,
        assignedTo: incidentAssignedTo.trim() || undefined,
        notes: incidentNotes.trim() || undefined,
        affectedAssets: [{
          componentId: f.componentId,
          assetName: f.assetName,
          assetIdentifier: f.assetIdentifier,
          assetType: f.assetType,
          packageName: f.packageName,
          packageVersion: f.packageVersion,
          assignmentGroup: incidentAssignmentGroup.trim() || undefined,
        }],
      };
      const results = await cveWorkbenchApi.createServiceNowIncident(f.vulnerabilityId, payload);
      setIncidentResult(results);
      if (results[0]?.incidentNumber) {
        setCurrentFinding(f => f ? { ...f, incidentId: results[0]!.incidentNumber } : f);
      }
      setActionDone('Incident created successfully.');
    } catch (e) { setActionError(String(e)); }
    finally { setActionLoading(false); }
  }

  // ── modal render ───────────────────────────────────────────────────────────
  function renderModal() {
    if (!actionModal) return null;
    const TITLES: Record<ActionType, string> = {
      'create-incident': 'Create ServiceNow Incident',
      'defer': 'Defer Finding',
      'resolve': 'Resolve Finding',
      'under-investigation': 'Mark Under Investigation',
      'false-positive': 'Mark as False Positive',
      'reopen': 'Re-open Finding',
    };
    return (
      <div className="fd3-modal-overlay" onClick={e => { if (e.target === e.currentTarget) closeModal(); }}>
        <div className="fd3-modal">
          <div className="fd3-modal-header">
            <span>{TITLES[actionModal]}</span>
            <button className="fd3-modal-close" onClick={closeModal}>✕</button>
          </div>
          <div className="fd3-modal-body">
            {actionError && <div className="notice error" style={{ marginBottom: 12 }}>{actionError}</div>}
            {actionDone && !incidentResult && <div className="notice success" style={{ marginBottom: 12 }}>{actionDone}</div>}

            {actionModal === 'create-incident' && !actionDone && (
              <div className="fd3-form">
                <div className="fd3-form-row">
                  <label>Finding</label>
                  <span className="fd3-form-readonly mono">{currentFinding!.displayId || currentFinding!.id} · {currentFinding!.vulnerabilityId}</span>
                </div>
                <div className="fd3-form-row">
                  <label>Priority</label>
                  <select value={incidentPriority} onChange={e => setIncidentPriority(e.target.value)} className="fd3-form-select">
                    <option value="1">1 - Critical</option>
                    <option value="2">2 - High</option>
                    <option value="3">3 - Moderate</option>
                    <option value="4">4 - Low</option>
                  </select>
                </div>
                <div className="fd3-form-row">
                  <label>Assigned To</label>
                  <input className="fd3-form-input" value={incidentAssignedTo} onChange={e => setIncidentAssignedTo(e.target.value)} placeholder="username or email" />
                </div>
                <div className="fd3-form-row">
                  <label>Assignment Group</label>
                  <input className="fd3-form-input" value={incidentAssignmentGroup} onChange={e => setIncidentAssignmentGroup(e.target.value)} placeholder="Security Operations" />
                </div>
                <div className="fd3-form-row">
                  <label>Due Date</label>
                  <input type="date" className="fd3-form-input" value={incidentDueDate} onChange={e => setIncidentDueDate(e.target.value)} />
                </div>
                <div className="fd3-form-row">
                  <label>Notes</label>
                  <textarea className="fd3-form-textarea" rows={3} value={incidentNotes} onChange={e => setIncidentNotes(e.target.value)} placeholder="Remediation context…" />
                </div>
              </div>
            )}

            {actionModal === 'create-incident' && incidentResult && (
              <div className="fd3-incident-result">
                {incidentResult.map((r, i) => (
                  <div key={i} className={`fd3-incident-card${r.status === 'created' ? '' : ' fd3-incident-card--error'}`}>
                    {r.status === 'created'
                      ? <><strong>✓ Incident Created:</strong> {r.incidentNumber}</>
                      : <><strong>✗ Error:</strong> {r.message}</>
                    }
                  </div>
                ))}
              </div>
            )}

            {actionModal === 'defer' && !actionDone && (
              <div className="fd3-form">
                <p className="fd3-form-desc">Suppress this finding until a specified date.</p>
                <div className="fd3-form-row">
                  <label>Reason</label>
                  <select value={deferReason} onChange={e => setDeferReason(e.target.value)} className="fd3-form-select">
                    <option value="">Select reason…</option>
                    <option value="RISK_ACCEPTED">Risk Accepted</option>
                    <option value="COMPENSATING_CONTROL">Compensating Control</option>
                    <option value="PENDING_PATCH">Pending Patch</option>
                    <option value="DEFERRED">Deferred</option>
                  </select>
                </div>
                <div className="fd3-form-row">
                  <label>Expires</label>
                  <input type="date" className="fd3-form-input" value={deferExpiry} onChange={e => setDeferExpiry(e.target.value)} />
                </div>
              </div>
            )}

            {actionModal === 'resolve' && !actionDone && (
              <p className="fd3-form-desc">Mark this finding as resolved. This indicates the vulnerability has been remediated.</p>
            )}

            {actionModal === 'under-investigation' && !actionDone && (
              <p className="fd3-form-desc">Mark the decision state as <strong>Under Investigation</strong>. The finding will remain open while being actively reviewed.</p>
            )}

            {actionModal === 'false-positive' && !actionDone && (
              <div className="fd3-form">
                <p className="fd3-form-desc">Mark this finding as a false positive and suppress it.</p>
                <div className="fd3-form-row">
                  <label>Justification</label>
                  <textarea className="fd3-form-textarea" rows={3} value={fpJustification} onChange={e => setFpJustification(e.target.value)} placeholder="Why is this a false positive?" />
                </div>
              </div>
            )}

            {actionModal === 'reopen' && !actionDone && (
              <p className="fd3-form-desc">Re-open this finding and set its status back to <strong>Open</strong>. Any previous deferral or suppression will be cleared.</p>
            )}
          </div>
          <div className="fd3-modal-footer">
            {actionDone
              ? <button className="btn btn-secondary" onClick={closeModal}>Close</button>
              : <>
                  <button className="btn btn-secondary" onClick={closeModal} disabled={actionLoading}>Cancel</button>
                  <button className="btn btn-primary" disabled={actionLoading}
                    onClick={() => {
                      if (actionModal === 'create-incident') void handleCreateIncident();
                      else if (actionModal === 'defer') void handleDefer();
                      else if (actionModal === 'resolve') void handleResolve();
                      else if (actionModal === 'under-investigation') void handleUnderInvestigation();
                      else if (actionModal === 'false-positive') void handleFalsePositive();
                      else if (actionModal === 'reopen') void handleReopen();
                    }}>
                    {actionLoading ? 'Working…'
                      : actionModal === 'create-incident' ? 'Create Incident'
                      : actionModal === 'defer' ? 'Defer'
                      : actionModal === 'resolve' ? 'Resolve'
                      : actionModal === 'under-investigation' ? 'Set Under Investigation'
                      : actionModal === 'reopen' ? 'Re-open'
                      : 'Mark False Positive'}
                  </button>
                </>
            }
          </div>
        </div>
      </div>
    );
  }

  // ─── render ────────────────────────────────────────────────────────────────

  const cve = currentFinding.vulnerabilityId;
  const ownership = currentFinding.ownership;
  const ownershipSource = ownership?.sourceSystem || ownership?.sourceType || '—';

  return (
    <div className="fd3-page">

      {/* ── top bar ─────────────────────────────────────────────────────── */}
      <div className="fd3-topbar">
        <button className="fd3-back-btn" onClick={() => navigate(returnTo)}>← Back</button>
        <span className="fd3-finding-id mono">{currentFinding.displayId || currentFinding.id}</span>
        <span className={statusCls(currentFinding)}>{statusLabel(currentFinding)}</span>
        {overdue && <span className="fd3-target-missed">⚠ Target Missed</span>}
        <div style={{ flex: 1 }} />
        {/* Actions */}
        <div className="fd3-actions">
          <button className="fd3-action-btn fd3-action-btn--incident" onClick={() => openModal('create-incident')}>+ Create Incident</button>
          {currentFinding.status === 'OPEN' && (
            <>
              <button className="fd3-action-btn" onClick={() => openModal('under-investigation')}>Under Investigation</button>
              <button className="fd3-action-btn" onClick={() => openModal('defer')}>Defer</button>
              <button className="fd3-action-btn" onClick={() => openModal('resolve')}>Resolve</button>
              <button className="fd3-action-btn fd3-action-btn--fp" onClick={() => openModal('false-positive')}>False Positive</button>
            </>
          )}
          {currentFinding.status !== 'OPEN' && (
            <button className="fd3-action-btn fd3-action-btn--reopen" onClick={() => openModal('reopen')}>Re-open</button>
          )}
        </div>
      </div>

      {/* ── 2-column body ───────────────────────────────────────────────── */}
      <div className="fd3-body">

        {/* ── LEFT: Asset + Workflow ──────────────────────────────────── */}
        <div className="fd3-col fd3-col-left">

          <Panel title="Affected Configuration Item">
            <div className="fd3-ci-root">
              {/* CI identifier row */}
              <div className="fd3-ci-id-row">
                <span className="fd3-ci-id-label">Configuration item</span>
                {hostAssetId ? (
                  <button className="fd3-asset-link" onClick={() => navigate(pathForInventoryHostAsset(hostAssetId))}>
                    {currentFinding.assetIdentifier}
                  </button>
                ) : (
                  <span className="fd3-ci-id-val">{currentFinding.assetIdentifier || currentFinding.assetName}</span>
                )}
              </div>

              {/* Grid row 1: Name · OS Version · Internet Facing */}
              <div className="fd3-ci-grid">
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Name</div>
                  <div className="fd3-ci-cell-value">{currentFinding.assetName}</div>
                </div>
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">OS Version</div>
                  <div className="fd3-ci-cell-value">{hostAsset?.managedBy || '—'}</div>
                </div>
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Internet Facing</div>
                  <div className="fd3-ci-cell-value">—</div>
                </div>
              </div>

              {/* Grid row 2: Class · Category · Asset tag */}
              <div className="fd3-ci-grid">
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Class</div>
                  <div className="fd3-ci-cell-value">{fmt(currentFinding.assetType)}</div>
                </div>
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Category</div>
                  <div className="fd3-ci-cell-value">{hostAsset?.department || '—'}</div>
                </div>
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Asset tag</div>
                  <div className="fd3-ci-cell-value">{hostAsset?.sysId ? <span className="mono" style={{ fontSize: 11 }}>{hostAsset.sysId.slice(0, 10)}…</span> : '—'}</div>
                </div>
              </div>

              {/* Grid row 3: Install Status · Environment */}
              <div className="fd3-ci-grid">
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Install Status</div>
                  <div className="fd3-ci-cell-value">{fmt(hostAsset?.state) || '—'}</div>
                </div>
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Environment</div>
                  <div className="fd3-ci-cell-value">{hostAsset?.environment || '—'}</div>
                </div>
              </div>

              {/* Assigned to */}
              <div className="fd3-ci-grid">
                <div className="fd3-ci-cell">
                  <div className="fd3-ci-cell-label">Assigned to</div>
                  <div className="fd3-ci-cell-value fd3-ci-assignee">{hostAsset?.assignedTo || '—'}</div>
                </div>
              </div>

              {/* Software row */}
              <div className="fd3-ci-sep" />
              <div className="fd3-kv-table">
                <KVRow label="Package">
                  <span className="mono">{currentFinding.packageName}</span>
                </KVRow>
                <KVRow label="Version">
                  <span className="mono">{currentFinding.packageVersion || '—'}</span>
                </KVRow>
                {currentFinding.isEol && (
                  <KVRow label="EOL Status">
                    <span className="fd3-eol-badge">End of Life</span>
                    {currentFinding.eolDate && <span className="fd3-muted"> · {fmtDate(currentFinding.eolDate)}</span>}
                  </KVRow>
                )}
              </div>
            </div>
          </Panel>

          {ownership && (
            <Panel title="Asset Ownership">
              <div className="fd3-kv-table">
                <KVRow label="Owner">{ownership.displayName || 'Unassigned'}</KVRow>
                <KVRow label="Owner Team">{ownership.ownerTeam || '—'}</KVRow>
                <KVRow label="Owner Email">{ownership.ownerEmail || '—'}</KVRow>
                <KVRow label="Managed By">{ownership.managedBy || '—'}</KVRow>
                <KVRow label="Department">{ownership.department || '—'}</KVRow>
                <KVRow label="Support Group">{ownership.supportGroup || '—'}</KVRow>
                <KVRow label="Asset Assigned To">{ownership.assignedTo || '—'}</KVRow>
                <KVRow label="Source">{ownershipSource}</KVRow>
                <KVRow label="Authority">{ownership.authority || '—'}</KVRow>
                <KVRow label="Last Ownership Sync">{fmtDt(currentFinding.ownershipSyncedAt)}</KVRow>
              </div>
            </Panel>
          )}

          <Panel title="Details">
            <div className="fd3-kv-table">
              <KVRow label="Status">
                <span className={statusCls(currentFinding)}>{statusLabel(currentFinding)}</span>
              </KVRow>
              {(() => {
                const p = computeFindingPriorityScore(currentFinding, policyQuery.data);
                const cls = `risk-score-badge risk-score-badge--${riskScoreLabel(p.score).toLowerCase()}`;
                return (
                  <KVRow label="S.AI Priority">
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                      <span className={cls}>{p.score.toFixed(1)}</span>
                      {p.topReasons.length > 0 && (
                        <span className="fd3-muted" style={{ fontSize: 11 }}>
                          {p.topReasons.join(' · ')}
                        </span>
                      )}
                    </span>
                  </KVRow>
                );
              })()}
              <KVRow label="Due Date">
                {currentFinding.dueAt
                  ? <span className={overdue ? 'fd3-overdue' : undefined}>{fmtDate(currentFinding.dueAt)}{overdue && ' ⚠'}</span>
                  : <span className="fd3-muted">—</span>}
              </KVRow>
              {currentFinding.status === 'SUPPRESSED' && !((currentFinding.suppressionReason ?? '').toUpperCase().includes('FALSE_POSITIVE')) && (
                <KVRow label="Deferral Date">{fmtDate(currentFinding.suppressedUntil)}</KVRow>
              )}
              <KVRow label="Assigned To">
                {editingAssignee ? (
                  <span className="fd3-assign-wrap">
                    <input autoFocus className="fd3-assign-input"
                      value={assignedTo} onChange={e => setAssignedTo(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') void saveAssignee(); if (e.key === 'Escape') setEditingAssignee(false); }}
                      placeholder="username or email" />
                    <button className="fd3-assign-save" onClick={() => void saveAssignee()} disabled={assigneeSaving}>
                      {assigneeSaving ? '…' : '✓'}
                    </button>
                    <button className="fd3-assign-cancel" onClick={() => { setAssignedTo(currentFinding.assignedTo ?? ''); setEditingAssignee(false); }}>✕</button>
                  </span>
                ) : (
                  <span className="fd3-assign-display" onClick={() => setEditingAssignee(true)}>
                    {currentFinding.assignedTo || <span className="fd3-muted">Unassigned</span>}
                    <span className="fd3-assign-edit-icon">✏</span>
                  </span>
                )}
              </KVRow>
              <KVRow label="Assignment Group">
                {editingGroup ? (
                  <span className="fd3-assign-wrap">
                    <input autoFocus className="fd3-assign-input"
                      value={assignmentGroup} onChange={e => setAssignmentGroup(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') void saveAssignmentGroup(); if (e.key === 'Escape') setEditingGroup(false); }}
                      placeholder="e.g. Security Operations" />
                    <button className="fd3-assign-save" onClick={() => void saveAssignmentGroup()} disabled={groupSaving}>
                      {groupSaving ? '…' : '✓'}
                    </button>
                    <button className="fd3-assign-cancel" onClick={() => setEditingGroup(false)}>✕</button>
                  </span>
                ) : (
                  <span className="fd3-assign-display" onClick={() => setEditingGroup(true)}>
                    {assignmentGroup || <span className="fd3-muted">—</span>}
                    <span className="fd3-assign-edit-icon">✏</span>
                  </span>
                )}
              </KVRow>
              {currentFinding.incidentId && (
                <KVRow label="Incident ID">
                  <span className="mono fd3-incident-link">{currentFinding.incidentId}</span>
                </KVRow>
              )}
              <KVRow label="First Observed">{fmtDt(currentFinding.firstObservedAt)}</KVRow>
              <KVRow label="Last Observed">{fmtDt(currentFinding.lastObservedAt)}</KVRow>
            </div>
          </Panel>

        </div>

        {/* ── RIGHT: CVE + Vendor + Solution ─────────────────────────── */}
        <div className="fd3-col fd3-col-right">

          <Panel title="Vulnerability">
            <div className="fd3-kv-table">
              <KVRow label="CVE ID">
                <button className="fd3-cve-link" onClick={() => navigate(pathForVulnRepoView('org-cves' as VulnerabilityIntelRouteView, cve))}>
                  {cve}
                </button>
              </KVRow>
              {cveDetail?.summary.description && (
                <KVRow label="Summary">
                  <span style={{ fontSize: 12, lineHeight: 1.5 }}>{cveDetail.summary.description}</span>
                </KVRow>
              )}
              <KVRow label="Modified Severity">
                <span className={`severity-pill severity-${currentFinding.severity.toLowerCase()}`}>{currentFinding.severity}</span>
              </KVRow>
              <KVRow label="Risk Score">{Math.round(currentFinding.riskScore * 100)}</KVRow>
              {cveDetail?.summary.cvssScore != null && (
                <KVRow label="Vulnerability Score (v3)">{cveDetail.summary.cvssScore.toFixed(1)}</KVRow>
              )}
              {cveDetail?.summary.publishedAt && (
                <KVRow label="Date Published">{fmtDate(cveDetail.summary.publishedAt)}</KVRow>
              )}
              {cveDetail?.signals && (
                <KVRow label="Exploit Exists">{cveDetail.signals.exploitAvailable ? 'Yes' : 'No'}</KVRow>
              )}

              {currentFinding.epss != null && (
                <KVRow label="EPSS">{(currentFinding.epss * 100).toFixed(2)}%</KVRow>
              )}
              {cveDetail?.summary.modifiedAt && (
                <KVRow label="Last Modified">{fmtDate(cveDetail.summary.modifiedAt)}</KVRow>
              )}
            </div>
          </Panel>

          {/* AI Solution / Remediation */}
          {aiSolution?.data && (
            <Panel title="Remediation Guidance">
              {aiSolution.data.bottom_line && (
                <div className="fd3-solution-summary">
                  <p className="fd3-solution-text">{aiSolution.data.bottom_line.summary}</p>
                </div>
              )}
              {aiSolution.data.primary_fix && (
                <div className="fd3-kv-table" style={{ marginTop: 10 }}>
                  <KVRow label="Action">{aiSolution.data.primary_fix.action}</KVRow>
                  {aiSolution.data.primary_fix.target_version && (
                    <KVRow label="Target Version"><span className="mono">{aiSolution.data.primary_fix.target_version}</span></KVRow>
                  )}
                  {aiSolution.data.primary_fix.verification && (
                    <KVRow label="Verification">{aiSolution.data.primary_fix.verification}</KVRow>
                  )}
                  {aiSolution.data.primary_fix.reboot_required != null && (
                    <KVRow label="Reboot Required">{aiSolution.data.primary_fix.reboot_required ? 'Yes' : 'No'}</KVRow>
                  )}
                </div>
              )}
              {aiSolution.data.timeline && aiSolution.data.timeline.length > 0 && (
                <div className="fd3-timeline">
                  {aiSolution.data.timeline.map((t, i) => (
                    <div key={i} className="fd3-timeline-item" style={{ borderLeftColor: t.color }}>
                      <div className="fd3-timeline-window">{t.window} · {t.label}</div>
                      <ul className="fd3-timeline-actions">
                        {t.actions.map((a, j) => <li key={j}>{a}</li>)}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
              {aiSolution.data.compensating_controls && aiSolution.data.compensating_controls.length > 0 && (
                <details className="fd3-details">
                  <summary className="fd3-details-summary">Compensating Controls ({aiSolution.data.compensating_controls.length})</summary>
                  <div className="fd3-kv-table" style={{ marginTop: 8 }}>
                    {aiSolution.data.compensating_controls.map((c, i) => (
                      <KVRow key={i} label={c.control}>
                        <span className="fd3-muted">{c.effort} effort · {c.effectiveness} effectiveness</span>
                      </KVRow>
                    ))}
                  </div>
                </details>
              )}
            </Panel>
          )}

        </div>
      </div>

      {renderModal()}
    </div>
  );
}
