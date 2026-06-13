import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../../api/client';
import type {
  CampaignDetail,
  CampaignExceptionStatus,
  CampaignStatus,
} from './types';

type DetailTab = 'overview' | 'assets' | 'findings' | 'exceptions' | 'evidence' | 'activity';

type ExceptionForm = {
  findingDisplayId: string;
  title: string;
  reason: string;
  decisionDueDate: string;
};

function statusBadgeClass(status: CampaignStatus): string {
  if (status === 'ACTIVE') return 'campaign-status-badge active';
  if (status === 'PAUSED') return 'campaign-status-badge paused';
  if (status === 'BLOCKED') return 'campaign-status-badge blocked';
  if (status === 'CLOSED' || status === 'CANCELLED') return 'campaign-status-badge closed';
  if (status === 'IN_REVIEW') return 'campaign-status-badge review';
  return 'campaign-status-badge draft';
}

function formatStatus(status: CampaignStatus): string {
  return status.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatDate(value?: string | null): string {
  if (!value) return 'TBD';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function daysLeft(dueAt?: string | null): number | null {
  if (!dueAt) return null;
  const d = new Date(dueAt);
  if (Number.isNaN(d.getTime())) return null;
  return Math.ceil((d.getTime() - Date.now()) / 86_400_000);
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? '')
    .join('');
}

export function CampaignDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [detail, setDetail] = React.useState<CampaignDetail | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [tab, setTab] = React.useState<DetailTab>('overview');
  const [statusBusy, setStatusBusy] = React.useState<CampaignStatus | null>(null);
  const [noteDraft, setNoteDraft] = React.useState('');
  const [savingNote, setSavingNote] = React.useState(false);
  const [savingException, setSavingException] = React.useState(false);
  const [exceptionStatusBusy, setExceptionStatusBusy] = React.useState<string | null>(null);
  const [exceptionForm, setExceptionForm] = React.useState<ExceptionForm>({
    findingDisplayId: '', title: '', reason: '', decisionDueDate: '',
  });

  const reload = React.useCallback(async () => {
    if (!id) return;
    try {
      const result = await api.getCampaign(id);
      setDetail(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [id]);

  React.useEffect(() => {
    if (!id) return;
    setLoading(true);
    api.getCampaign(id)
      .then((d) => setDetail(d))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, [id]);

  async function transition(status: CampaignStatus): Promise<void> {
    if (!id) return;
    setStatusBusy(status);
    try {
      const updated = await api.updateCampaignStatus(id, status);
      setDetail(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setStatusBusy(null);
    }
  }

  async function submitNote(): Promise<void> {
    if (!id || !noteDraft.trim()) return;
    setSavingNote(true);
    try {
      await api.addCampaignNote(id, noteDraft.trim());
      setNoteDraft('');
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingNote(false);
    }
  }

  async function submitException(): Promise<void> {
    if (!id || !exceptionForm.title.trim() || !exceptionForm.reason.trim()) return;
    setSavingException(true);
    try {
      const finding = detail?.findings.find((f) => f.displayId === exceptionForm.findingDisplayId);
      await api.addCampaignException(id, {
        findingDisplayId: exceptionForm.findingDisplayId || null,
        assetName: finding?.assetName ?? null,
        packageName: finding?.packageName ?? null,
        title: exceptionForm.title.trim(),
        reason: exceptionForm.reason.trim(),
        decisionDueAt: exceptionForm.decisionDueDate
          ? new Date(`${exceptionForm.decisionDueDate}T00:00:00Z`).toISOString()
          : null,
      });
      setExceptionForm({ findingDisplayId: '', title: '', reason: '', decisionDueDate: '' });
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingException(false);
    }
  }

  async function updateExceptionStatus(exceptionId: string, status: CampaignExceptionStatus): Promise<void> {
    if (!id) return;
    setExceptionStatusBusy(exceptionId + status);
    try {
      const updated = await api.updateCampaignExceptionStatus(id, exceptionId, status);
      setDetail(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExceptionStatusBusy(null);
    }
  }

  if (loading) {
    return <div className="cd-loading">Loading campaign…</div>;
  }

  if (error || !detail) {
    return (
      <div className="cd-loading">
        <p>{error ?? 'Campaign not found.'}</p>
        <button type="button" className="btn btn-secondary" onClick={() => navigate('/vuln-repo/campaigns')}>
          Back to Campaigns
        </button>
      </div>
    );
  }

  const s = detail.summary;
  const left = daysLeft(s.dueAt);
  const pct = s.completionPercent;
  const notifyOwner = detail.notifyGroups[0];
  const notifyResolver = detail.notifyGroups[1] ?? detail.notifyGroups[0];
  const cveLabel = s.cveIds.join(', ');

  // Group assets by supportGroup from assets list
  type OwnerGroup = { group: string; total: number; resolved: number; exceptions: number };
  const ownerGroupMap = new Map<string, OwnerGroup>();
  detail.assets.forEach((a) => {
    const grp = a.supportGroup || 'Other';
    const existing = ownerGroupMap.get(grp) ?? { group: grp, total: 0, resolved: 0, exceptions: 0 };
    ownerGroupMap.set(grp, {
      group: grp,
      total: existing.total + 1,
      resolved: existing.resolved + a.resolvedFindings,
      exceptions: existing.exceptions,
    });
  });
  // Add exceptions per group based on findings
  detail.exceptions.forEach((ex) => {
    const finding = detail.findings.find((f) => f.displayId === ex.findingDisplayId);
    if (finding?.ownerGroup) {
      const existing = ownerGroupMap.get(finding.ownerGroup);
      if (existing) ownerGroupMap.set(finding.ownerGroup, { ...existing, exceptions: existing.exceptions + 1 });
    }
  });
  const ownerGroups = Array.from(ownerGroupMap.values());

  const TABS: { key: DetailTab; label: string; count?: number }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'assets', label: 'Assets', count: s.assetCount },
    { key: 'findings', label: 'Findings', count: s.totalFindings },
    { key: 'exceptions', label: 'Exceptions', count: s.exceptionCount },
    { key: 'evidence', label: 'Evidence' },
    { key: 'activity', label: 'Activity' },
  ];

  return (
    <div className="cd-page">
      {/* ── Top bar ───────────────────────────────────────────────── */}
      <div className="cd-topbar">
        <div className="cd-breadcrumb">
          <button type="button" className="cd-breadcrumb-link" onClick={() => navigate('/vuln-repo/campaigns')}>
            Campaigns
          </button>
          <span className="cd-breadcrumb-sep">/</span>
          <span className="cd-breadcrumb-current">{s.name}</span>
        </div>
        <div className="cd-topbar-actions">
          <span className={statusBadgeClass(s.status)}>{formatStatus(s.status)}</span>
          {s.cveIds.length > 0 && (
            <span className="cd-severity-badge">
              {detail.vulnerabilities[0]?.severity ?? 'CVE'}
            </span>
          )}
          <button type="button" className="btn btn-secondary" disabled={statusBusy !== null}>
            Link Ticket
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={statusBusy !== null}
            onClick={() => setTab('exceptions')}
          >
            Add Exception
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={statusBusy === 'CLOSED'}
            onClick={() => void transition('CLOSED')}
          >
            {statusBusy === 'CLOSED' ? 'Closing…' : 'Mark Evidence ✓'}
          </button>
        </div>
      </div>

      {/* ── Sub-nav tabs ─────────────────────────────────────────── */}
      <div className="cd-tabnav">
        {TABS.map(({ key, label, count }) => (
          <button
            key={key}
            type="button"
            className={tab === key ? 'cd-tab active' : 'cd-tab'}
            onClick={() => setTab(key)}
          >
            {label}
            {count != null && (
              <span className={`cd-tab-count ${key === 'exceptions' && count > 0 ? 'warn' : ''}`}>
                {count}
              </span>
            )}
          </button>
        ))}
      </div>

      {error && <div className="notice error" style={{ margin: '0 24px 12px' }}>{error}</div>}

      {/* ── Tab content ──────────────────────────────────────────── */}
      <div className="cd-body">
        {tab === 'overview' && (
          <div className="cd-overview-layout">
            {/* Main column */}
            <div className="cd-overview-main">
              {/* Hero card */}
              <div className="cd-hero-card">
                <div className="cd-hero-top">
                  <div>
                    <h2 className="cd-hero-title">{s.name}</h2>
                    <div className="cd-hero-meta">
                      {cveLabel}
                      {s.summary ? ` · ${s.summary}` : ''}
                      {s.startedAt ? ` · Created ${formatDate(s.startedAt)}` : ''}
                    </div>
                  </div>
                  <div className="cd-risk-reduction">
                    <span className="cd-risk-delta">–{pct > 0 ? (pct / 10).toFixed(1) : '0.0'}</span>
                    <span className="cd-risk-label">RISK REDUCTION</span>
                    <span className="cd-risk-sub">S.AI score delta (verified)</span>
                  </div>
                </div>
                <div className="cd-hero-stats">
                  <div className="cd-hero-stat">
                    <strong>{s.assetCount}</strong>
                    <span>ASSETS</span>
                  </div>
                  <div className="cd-hero-stat">
                    <strong>{s.totalFindings}</strong>
                    <span>FINDINGS</span>
                  </div>
                  <div className="cd-hero-stat resolved">
                    <strong>{s.resolvedFindings}</strong>
                    <span>RESOLVED</span>
                  </div>
                  <div className="cd-hero-stat warn">
                    <strong>{s.exceptionCount}</strong>
                    <span>EXCEPTIONS</span>
                  </div>
                  <div className={`cd-hero-stat ${left != null && left < 14 ? 'warn' : ''}`}>
                    <strong>{left != null ? Math.max(0, left) : '—'}</strong>
                    <span>DAYS LEFT</span>
                  </div>
                </div>
              </div>

              {/* Execution Progress */}
              <div className="cd-progress-card">
                <div className="cd-progress-header">
                  <span className="cd-progress-title">Execution Progress</span>
                  <span className="cd-progress-summary">{pct}% complete · {Math.max(0, s.assetCount - s.resolvedFindings)} assets remaining</span>
                </div>
                <div className="cd-progress-bar-wrap">
                  <div className="cd-progress-bar">
                    <div className="cd-progress-fill" style={{ width: `${pct}%` }} />
                  </div>
                </div>
                <div className="cd-progress-labels">
                  <span>0</span>
                  <span className="cd-progress-resolved">{s.resolvedFindings} resolved</span>
                  <span>{s.assetCount} total</span>
                </div>

                {ownerGroups.length > 0 && (
                  <>
                    <div className="cd-group-section-label">ASSETS BY OWNER GROUP</div>
                    <div className="cd-group-list">
                      {ownerGroups.map((grp) => {
                        const grpPct = grp.total > 0 ? Math.round((grp.resolved / grp.total) * 100) : 0;
                        const hasExceptions = grp.exceptions > 0;
                        return (
                          <div key={grp.group} className="cd-group-row">
                            <div className="cd-group-avatar" style={{ background: hasExceptions ? 'rgba(245,158,11,0.2)' : 'rgba(99,102,241,0.2)' }}>
                              {initials(grp.group)}
                            </div>
                            <div className="cd-group-info">
                              <strong>{grp.group}</strong>
                              <span>
                                {grp.total} assets · {grp.resolved} resolved
                                {grp.exceptions > 0 ? ` · ${grp.exceptions} exceptions` : ''}
                              </span>
                            </div>
                            <div className="cd-group-bar-wrap">
                              <div className="cd-group-bar">
                                <div
                                  className="cd-group-bar-fill"
                                  style={{
                                    width: `${grpPct}%`,
                                    background: hasExceptions ? '#f59e0b' : grpPct >= 70 ? '#22c55e' : '#6366f1'
                                  }}
                                />
                              </div>
                              <span className="cd-group-pct">{grpPct}%</span>
                            </div>
                            <span className={hasExceptions ? 'cd-group-status warn' : 'cd-group-status ok'}>
                              {hasExceptions ? `${grp.exceptions} exceptions` : '● On track'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </>
                )}
              </div>

              {/* Status actions */}
              <div className="cd-action-row">
                <button type="button" className="btn btn-secondary" disabled={statusBusy === 'PAUSED'} onClick={() => void transition('PAUSED')}>
                  {statusBusy === 'PAUSED' ? '…' : 'Pause'}
                </button>
                <button type="button" className="btn btn-secondary" disabled={statusBusy === 'ACTIVE'} onClick={() => void transition('ACTIVE')}>
                  {statusBusy === 'ACTIVE' ? '…' : 'Resume'}
                </button>
                <button type="button" className="btn btn-secondary" disabled={statusBusy === 'IN_REVIEW'} onClick={() => void transition('IN_REVIEW')}>
                  {statusBusy === 'IN_REVIEW' ? '…' : 'Review'}
                </button>
                <button type="button" className="btn btn-secondary" disabled={statusBusy === 'BLOCKED'} onClick={() => void transition('BLOCKED')}>
                  {statusBusy === 'BLOCKED' ? '…' : 'Block'}
                </button>
              </div>
            </div>

            {/* Right sidebar */}
            <div className="cd-overview-sidebar">
              {/* Campaign Details */}
              <div className="cd-sidebar-card">
                <div className="cd-sidebar-card-title">CAMPAIGN DETAILS</div>
                <div className="cd-details-grid">
                  <span className="cd-detail-label">Owner</span>
                  <span className="cd-detail-value">
                    {notifyOwner ? (
                      <>
                        <span className="cd-avatar">{initials(notifyOwner.groupName)}</span>
                        {notifyOwner.groupName}
                      </>
                    ) : '—'}
                  </span>

                  <span className="cd-detail-label">Resolver Group</span>
                  <span className="cd-detail-value">{notifyResolver?.groupName ?? '—'}</span>

                  <span className="cd-detail-label">Due Date</span>
                  <span className="cd-detail-value">{formatDate(s.dueAt)}</span>

                  <span className="cd-detail-label">CVE</span>
                  <span className="cd-detail-value mono">{cveLabel || '—'}</span>

                  <span className="cd-detail-label">Evidence</span>
                  <span className={`cd-detail-value ${s.resolvedFindings > 0 && s.resolvedFindings < s.totalFindings ? 'cd-evidence-partial' : ''}`}>
                    {s.resolvedFindings === 0 ? 'None' : s.resolvedFindings === s.totalFindings ? 'Complete' : 'Partial'}
                  </span>
                </div>
              </div>

              {/* Exceptions */}
              {detail.exceptions.length > 0 && (
                <div className="cd-sidebar-card">
                  <div className="cd-sidebar-card-header">
                    <span className="cd-sidebar-card-title cd-exceptions-title">
                      EXCEPTIONS ({detail.exceptions.length})
                    </span>
                    <button type="button" className="cd-view-all" onClick={() => setTab('exceptions')}>
                      View all
                    </button>
                  </div>
                  <div className="cd-exceptions-list">
                    {detail.exceptions.slice(0, 3).map((ex) => (
                      <div key={ex.id} className="cd-exception-item">
                        <strong>{ex.assetName || ex.findingDisplayId || ex.title}</strong>
                        <span>{ex.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Projected Risk Reduction */}
              <div className="cd-sidebar-card">
                <div className="cd-sidebar-card-title">PROJECTED RISK REDUCTION</div>
                <div className="cd-risk-proj">
                  <div>
                    <span className="cd-detail-label">Resolved findings</span>
                    <strong>{s.resolvedFindings} / {s.totalFindings}</strong>
                  </div>
                  <div>
                    <span className="cd-detail-label">Completion</span>
                    <strong>{pct}%</strong>
                  </div>
                  <div>
                    <span className="cd-detail-label">Open exceptions</span>
                    <strong>{s.exceptionCount}</strong>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'assets' && (
          <div className="cd-tab-body">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Support Group</th>
                  <th>Environment</th>
                  <th>Open</th>
                  <th>Resolved</th>
                </tr>
              </thead>
              <tbody>
                {detail.assets.map((a) => (
                  <tr key={`${a.assetIdentifier}-${a.assetName}`}>
                    <td>
                      <div>
                        <strong>{a.assetName || a.assetIdentifier || 'Asset'}</strong>
                        <div className="muted">{a.assetIdentifier}</div>
                      </div>
                    </td>
                    <td>{a.supportGroup || '—'}</td>
                    <td>{a.environment || '—'}</td>
                    <td>{a.openFindings}</td>
                    <td className="text-success">{a.resolvedFindings}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {detail.assets.length === 0 && <div className="cd-empty">No assets scoped yet.</div>}
          </div>
        )}

        {tab === 'findings' && (
          <div className="cd-tab-body">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Asset</th>
                  <th>Package</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Owner Group</th>
                  <th>Due</th>
                </tr>
              </thead>
              <tbody>
                {detail.findings.map((f) => (
                  <tr key={`${f.displayId}-${f.assetIdentifier}`}>
                    <td className="mono">{f.displayId || '—'}</td>
                    <td>{f.assetName || f.assetIdentifier || '—'}</td>
                    <td>{f.packageName || '—'}</td>
                    <td>{f.severity || '—'}</td>
                    <td>{f.status}</td>
                    <td>{f.ownerGroup || 'Unassigned'}</td>
                    <td>{formatDate(f.dueAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {detail.findings.length === 0 && <div className="cd-empty">No findings tracked yet.</div>}
          </div>
        )}

        {tab === 'exceptions' && (
          <div className="cd-tab-body">
            <div className="cd-exception-compose-card">
              <h4>Add Exception</h4>
              <div className="cd-exception-form">
                <select
                  value={exceptionForm.findingDisplayId}
                  onChange={(e) => setExceptionForm((c) => ({ ...c, findingDisplayId: e.target.value }))}
                >
                  <option value="">Optional related finding</option>
                  {detail.findings.map((f) => (
                    <option key={`${f.displayId}-${f.assetIdentifier}`} value={f.displayId || ''}>
                      {f.displayId || 'Finding'} — {f.assetName || f.assetIdentifier || 'Asset'}
                    </option>
                  ))}
                </select>
                <input
                  value={exceptionForm.title}
                  onChange={(e) => setExceptionForm((c) => ({ ...c, title: e.target.value }))}
                  placeholder="Exception title"
                />
                <textarea
                  value={exceptionForm.reason}
                  onChange={(e) => setExceptionForm((c) => ({ ...c, reason: e.target.value }))}
                  placeholder="Reason / context"
                />
                <input
                  type="date"
                  value={exceptionForm.decisionDueDate}
                  onChange={(e) => setExceptionForm((c) => ({ ...c, decisionDueDate: e.target.value }))}
                />
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={savingException}
                  onClick={() => void submitException()}
                >
                  {savingException ? 'Saving…' : 'Add Exception'}
                </button>
              </div>
            </div>

            <div className="cd-exceptions-table">
              {detail.exceptions.map((ex) => (
                <div key={ex.id} className="cd-exception-card">
                  <div className="cd-exception-card-top">
                    <strong>{ex.title}</strong>
                    <span className={`campaign-status-badge ${ex.status === 'APPROVED' ? 'active' : ex.status === 'REJECTED' ? 'blocked' : 'paused'}`}>
                      {ex.status.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <p className="cd-exception-reason">{ex.reason}</p>
                  <div className="cd-exception-meta">
                    {ex.assetName && <span>Asset: {ex.assetName}</span>}
                    {ex.findingDisplayId && <span>Finding: {ex.findingDisplayId}</span>}
                    <span>Requested by {ex.requestedBy} · {formatDate(ex.requestedAt)}</span>
                  </div>
                  <div className="cd-exception-actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={exceptionStatusBusy === ex.id + 'APPROVED'}
                      onClick={() => void updateExceptionStatus(ex.id, 'APPROVED')}
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={exceptionStatusBusy === ex.id + 'REJECTED'}
                      onClick={() => void updateExceptionStatus(ex.id, 'REJECTED')}
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
              {detail.exceptions.length === 0 && <div className="cd-empty">No exceptions recorded.</div>}
            </div>
          </div>
        )}

        {tab === 'evidence' && (
          <div className="cd-tab-body">
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Finding</th>
                  <th>Asset</th>
                  <th>Package</th>
                  <th>Status</th>
                  <th>Incident</th>
                  <th>Due</th>
                </tr>
              </thead>
              <tbody>
                {detail.evidence.map((row) => (
                  <tr key={`${row.displayId}-${row.assetIdentifier}-${row.packageName}`}>
                    <td className="mono">{row.cveId || '—'}</td>
                    <td className="mono">{row.displayId || '—'}</td>
                    <td>{row.assetName || row.assetIdentifier || '—'}</td>
                    <td>{row.packageName || '—'}</td>
                    <td>{row.status}</td>
                    <td>{row.incidentId || '—'}</td>
                    <td>{formatDate(row.dueAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {detail.evidence.length === 0 && <div className="cd-empty">No evidence rows yet.</div>}
          </div>
        )}

        {tab === 'activity' && (
          <div className="cd-tab-body">
            <div className="cd-note-compose">
              <textarea
                value={noteDraft}
                onChange={(e) => setNoteDraft(e.target.value)}
                placeholder="Add a note for resolvers and stakeholders…"
              />
              <button
                type="button"
                className="btn btn-primary"
                disabled={savingNote || !noteDraft.trim()}
                onClick={() => void submitNote()}
              >
                {savingNote ? 'Saving…' : 'Add Note'}
              </button>
            </div>
            <div className="cd-activity-list">
              {detail.activity.map((ev) => (
                <div key={ev.id} className="cd-activity-row">
                  <div className="cd-activity-dot" />
                  <div>
                    <p>{ev.body}</p>
                    <span className="muted">{ev.actor} · {formatDate(ev.createdAt)}</span>
                  </div>
                </div>
              ))}
              {detail.notes.map((note) => (
                <div key={note.id} className="cd-activity-row">
                  <div className="cd-activity-dot note" />
                  <div>
                    <p>{note.body}</p>
                    <span className="muted">{note.author} · {formatDate(note.createdAt)}</span>
                  </div>
                </div>
              ))}
              {detail.activity.length === 0 && detail.notes.length === 0 && (
                <div className="cd-empty">No activity yet.</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
