import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { pathForFindingDetail, pathForVulnRepoView, pathForVulnRepoHostAsset } from '../app/routes';
import { buildAssetRowsFromMatchedSoftware } from '../features/cve-workbench/asset-report';
import { useCveDetailQuery } from '../features/cve-workbench/queries';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { useFindingsQuery } from '../features/findings/queries';
import type { Finding } from '../features/findings/types';

const PRIORITY_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  CRITICAL: { bg: '#9b233522', color: '#9b2335', border: '#9b233544' },
  HIGH:     { bg: '#c5303022', color: '#c53030', border: '#c5303044' },
  MEDIUM:   { bg: '#b7791f22', color: '#b7791f', border: '#b7791f44' },
  LOW:      { bg: '#2d6a4f22', color: '#2d6a4f', border: '#2d6a4f44' },
};

const INPUT_STYLE: React.CSSProperties = {
  width: '100%', fontSize: 12, padding: '3px 6px',
  background: 'var(--input-bg, var(--panel-muted))',
  border: '1px solid var(--border)', borderRadius: 4,
  color: 'var(--text)', outline: 'none',
};

const TH_STYLE: React.CSSProperties = {
  padding: '8px 10px', textAlign: 'left',
  fontWeight: 600, color: 'var(--muted)',
  fontSize: 11, letterSpacing: '0.06em',
  whiteSpace: 'nowrap',
};

function PriorityBadge({ priority }: { priority: string }) {
  const label = priority.toUpperCase();
  const style = PRIORITY_COLORS[label];
  if (!style) return <span style={{ color: 'var(--muted)' }}>—</span>;
  return (
    <span style={{
      display: 'inline-block', padding: '2px 10px', borderRadius: 12,
      fontSize: 11, fontWeight: 700, letterSpacing: '0.04em',
      background: style.bg, color: style.color, border: `1px solid ${style.border}`,
    }}>
      {label}
    </span>
  );
}

export function VulnRepoCveAssetsPage() {
  const navigate = useNavigate();
  const params = useParams<{ cveId?: string }>();
  const cveId = params.cveId ?? null;

  const detailQuery = useCveDetailQuery(cveId);
  const findingsQuery = useFindingsQuery({ vulnerabilityId: cveId ?? '', size: 1000 });

  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set());
  const [creating, setCreating] = React.useState(false);
  const [createMsg, setCreateMsg] = React.useState<string | null>(null);

  // Finding Configuration modal state
  const [showConfigModal, setShowConfigModal] = React.useState(false);
  const [cfgTitle, setCfgTitle] = React.useState('');
  const [cfgPriority, setCfgPriority] = React.useState('Medium');
  const [cfgDueDate, setCfgDueDate] = React.useState('');
  const [cfgTags, setCfgTags] = React.useState('');
  const [cfgAssignment, setCfgAssignment] = React.useState('Assign to lead analyst');
  const [cfgServiceNow, setCfgServiceNow] = React.useState(true);
  const [cfgNotes, setCfgNotes] = React.useState('');

  const [filterAsset, setFilterAsset] = React.useState('');
  const [filterFinding, setFilterFinding] = React.useState('');
  const [filterSoftware, setFilterSoftware] = React.useState('');
  const [filterFalsePositive, setFilterFalsePositive] = React.useState('All');
  const [filterSupportGroup, setFilterSupportGroup] = React.useState('');
  const [filterPriority, setFilterPriority] = React.useState('All');

  const allAssetRows = React.useMemo(
    () => buildAssetRowsFromMatchedSoftware(
      (detailQuery.data?.matchedSoftware ?? []).filter((sw) => sw.assetId != null),
      detailQuery.data?.summary.severity ?? 'Unknown'
    ),
    [detailQuery.data?.matchedSoftware, detailQuery.data?.summary.severity]
  );

  // Map assetIdentifier → first finding for this CVE
  const findingsByAsset = React.useMemo(() => {
    const map = new Map<string, Finding>();
    for (const f of findingsQuery.data?.items ?? []) {
      if (!map.has(f.assetIdentifier)) map.set(f.assetIdentifier, f);
    }
    return map;
  }, [findingsQuery.data?.items]);

  // Map assetIdentifier → componentIds (for Create Findings)
  // componentsByAsset: all APPLICABLE components per asset (for Create Findings)
  const componentsByAsset = React.useMemo(() => {
    const map = new Map<string, string[]>();
    for (const sw of (detailQuery.data?.matchedSoftware ?? []).filter(
      (s) => s.assetId != null && s.applicabilityState === 'APPLICABLE'
    )) {
      const key = sw.assetIdentifier ?? sw.assetId ?? sw.componentId;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(sw.componentId);
    }
    return map;
  }, [detailQuery.data?.matchedSoftware]);

  // Track which components are already eligible (vs need IMPACTED override)
  const componentEligibility = React.useMemo(() => {
    const map = new Map<string, boolean>();
    for (const sw of detailQuery.data?.matchedSoftware ?? []) {
      map.set(sw.componentId, sw.eligibleForFinding);
    }
    return map;
  }, [detailQuery.data?.matchedSoftware]);

  const enrichedRows = React.useMemo(() => (
    allAssetRows.map((asset) => {
      const finding = findingsByAsset.get(asset.identifier);
      return {
        ...asset,
        finding,
        softwareLabel: asset.matchedSoftware.map((s) => `${s.software} ${s.version}`.trim()).join(', ') || '—',
        falsePositive: finding?.vexStatus === 'not_affected' ? 'Yes' : '—',
        supportGroup: finding?.ownership?.supportGroup ?? asset.supportGroup ?? '—',
        owner: finding?.ownership?.ownerTeam ?? finding?.ownership?.displayName ?? '—',
        priority: finding?.severity ?? detailQuery.data?.summary.severity ?? '—',
        incidentId: finding?.incidentId ?? '—',
      };
    })
  ), [allAssetRows, findingsByAsset, detailQuery.data?.summary.severity]);

  const filteredRows = React.useMemo(() => (
    enrichedRows.filter((row) => {
      if (filterAsset && !row.entity.toLowerCase().includes(filterAsset.toLowerCase())) return false;
      if (filterFinding && !(row.finding?.displayId ?? '—').toLowerCase().includes(filterFinding.toLowerCase())) return false;
      if (filterSoftware && !row.softwareLabel.toLowerCase().includes(filterSoftware.toLowerCase())) return false;
      if (filterFalsePositive !== 'All' && row.falsePositive !== filterFalsePositive) return false;
      if (filterSupportGroup && !(row.supportGroup).toLowerCase().includes(filterSupportGroup.toLowerCase())) return false;
      if (filterPriority !== 'All' && row.priority.toUpperCase() !== filterPriority) return false;
      return true;
    })
  ), [enrichedRows, filterAsset, filterFinding, filterSoftware, filterFalsePositive, filterSupportGroup, filterPriority]);

  const allSelected = filteredRows.length > 0 && filteredRows.every((r) => selectedIds.has(r.id));

  const toggleAll = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allSelected) {
        filteredRows.forEach((r) => next.delete(r.id));
      } else {
        filteredRows.forEach((r) => next.add(r.id));
      }
      return next;
    });
  };

  const toggleRow = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const openConfigModal = () => {
    if (selectedIds.size === 0) {
      setCreateMsg('Select at least one asset to create findings.');
      return;
    }
    setCfgTitle(cveId ?? '');
    setCfgDueDate('');
    setCfgTags('');
    setCfgNotes('');
    setCreateMsg(null);
    setShowConfigModal(true);
  };

  const handleCreateFindings = async () => {
    if (!cveId) return;
    const componentIds = Array.from(selectedIds).flatMap((id) => componentsByAsset.get(id) ?? []);
    if (componentIds.length === 0) {
      setCreateMsg('None of the selected assets have eligible components. Components need confirmed impact (IMPACTED disposition or no available patch) to create findings.');
      setShowConfigModal(false);
      return;
    }
    // For components not yet eligible, pass IMPACTED disposition — the analyst explicitly
    // requesting finding creation is an implicit confirmation of impact.
    const componentAnalystDispositions: Record<string, 'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN'> = {};
    componentIds.forEach((id) => {
      if (!componentEligibility.get(id)) {
        componentAnalystDispositions[id] = 'IMPACTED';
      }
    });
    const dispositions = Object.keys(componentAnalystDispositions).length > 0
      ? componentAnalystDispositions : undefined;

    setCreating(true);
    setCreateMsg(null);
    setShowConfigModal(false);
    try {
      const result = await cveWorkbenchApi.createManualFindings(cveId, {
        justification: cfgNotes.trim(),
        componentIds,
        componentAnalystDispositions: dispositions,
      });
      await findingsQuery.refetch();
      const parts: string[] = [];
      if (result.createdCount > 0) parts.push(`Created ${result.createdCount} finding(s).`);
      if (result.reopenedCount > 0) parts.push(`Reopened ${result.reopenedCount}.`);
      if (result.alreadyOpenCount > 0) parts.push(`${result.alreadyOpenCount} already open.`);
      setCreateMsg(parts.length > 0 ? parts.join(' ') : 'No eligible components found for the selected assets.');
    } catch {
      setCreateMsg('Failed to create findings.');
    } finally {
      setCreating(false);
    }
  };

  return (
    <>
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
        <div>
          <div className="org-cve-back-link">Affected Entities</div>
          <h3>{cveId ?? 'CVE Assets'}</h3>
          <span className="panel-caption">
            {allAssetRows.length.toLocaleString()} entities matched to this CVE.
          </span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate(pathForVulnRepoView('org-cves', cveId))}
            disabled={!cveId}
          >
            Back to CVE
          </button>
        </div>
      </div>

      {/* Action bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
        <span style={{ fontSize: 13, color: 'var(--muted)' }}>
          Total Assets: <strong style={{ color: 'var(--text)' }}>{filteredRows.length}</strong>
          &nbsp;&nbsp;Selected Assets: <strong style={{ color: 'var(--text)' }}>{selectedIds.size}</strong>
        </span>
        <div style={{ flex: 1 }} />
        <button
          type="button"
          className="btn btn-primary"
          onClick={openConfigModal}
          disabled={creating || selectedIds.size === 0}
        >
          {creating ? 'Creating…' : 'Create Findings'}
        </button>
      </div>

      {createMsg && (
        <div style={{ padding: '6px 0', fontSize: 13, color: createMsg.startsWith('Failed') ? '#c53030' : '#2d6a4f' }}>
          {createMsg}
        </div>
      )}

      {detailQuery.isLoading || detailQuery.isFetching ? (
        <div className="notice">Loading affected entities...</div>
      ) : detailQuery.error instanceof Error ? (
        <div className="notice error">{detailQuery.error.message}</div>
      ) : allAssetRows.length === 0 ? (
        <div className="empty-state"><p>No affected entities were found for this CVE.</p></div>
      ) : (
        <div className="table-scroll">
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'var(--panel-muted)', borderBottom: '1px solid var(--border)' }}>
                <th style={{ width: 36, padding: '8px 10px' }}>
                  <input type="checkbox" checked={allSelected} onChange={toggleAll} />
                </th>
                <th style={TH_STYLE}>ASSET / CI</th>
                <th style={TH_STYLE}>FINDING ID</th>
                <th style={TH_STYLE}>SOFTWARE</th>
                <th style={TH_STYLE}>FALSE POSITIVE</th>
                <th style={TH_STYLE}>SUPPORT GROUP</th>
                <th style={TH_STYLE}>OWNER</th>
                <th style={TH_STYLE}>PRIORITY</th>
                <th style={TH_STYLE}>INCIDENT ID</th>
              </tr>
              <tr style={{ background: 'var(--panel-muted)', borderBottom: '2px solid var(--border)' }}>
                <td />
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter asset..." value={filterAsset} onChange={(e) => setFilterAsset(e.target.value)} />
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter ID..." value={filterFinding} onChange={(e) => setFilterFinding(e.target.value)} />
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter software..." value={filterSoftware} onChange={(e) => setFilterSoftware(e.target.value)} />
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <select style={INPUT_STYLE} value={filterFalsePositive} onChange={(e) => setFilterFalsePositive(e.target.value)}>
                    <option>All</option>
                    <option>Yes</option>
                    <option value="—">No</option>
                  </select>
                </td>
                <td style={{ padding: '4px 10px' }}>
                  <input style={INPUT_STYLE} placeholder="Filter group..." value={filterSupportGroup} onChange={(e) => setFilterSupportGroup(e.target.value)} />
                </td>
                <td />
                <td style={{ padding: '4px 10px' }}>
                  <select style={INPUT_STYLE} value={filterPriority} onChange={(e) => setFilterPriority(e.target.value)}>
                    <option>All</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </td>
                <td />
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => (
                <tr key={row.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px', textAlign: 'center' }}>
                    <input type="checkbox" checked={selectedIds.has(row.id)} onChange={() => toggleRow(row.id)} />
                  </td>
                  <td style={{ padding: '10px' }}>
                    <button
                      type="button"
                      style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--accent)', fontWeight: 600, fontSize: 13, textAlign: 'left' }}
                      onClick={() => {
                        const navId = row.assetId ?? row.id;
                        navigate(pathForVulnRepoHostAsset(navId, `/vuln-repo/org-cves/${encodeURIComponent(cveId ?? '')}/assets`));
                      }}
                    >
                      {row.entity}
                    </button>
                    <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace', marginTop: 2 }}>{row.identifier}</div>
                    <div style={{ marginTop: 3 }}>
                      <span style={{ fontSize: 11, padding: '1px 6px', borderRadius: 4, background: 'var(--panel-muted)', border: '1px solid var(--border)', color: 'var(--muted)' }}>
                        {row.owner === '—' ? 'Unassigned' : row.owner}
                      </span>
                    </div>
                  </td>
                  <td style={{ padding: '10px' }}>
                    {row.finding ? (
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--accent)', fontFamily: 'monospace', fontSize: 13 }}
                        onClick={() => navigate(
                          pathForFindingDetail(row.finding!.displayId, `/vuln-repo/org-cves/${encodeURIComponent(cveId ?? '')}/assets`),
                          { state: { finding: row.finding } }
                        )}
                      >
                        {row.finding.displayId}
                      </button>
                    ) : <span style={{ color: 'var(--muted)' }}>—</span>}
                  </td>
                  <td style={{ padding: '10px', color: 'var(--text)' }}>{row.softwareLabel}</td>
                  <td style={{ padding: '10px', color: 'var(--muted)' }}>{row.falsePositive}</td>
                  <td style={{ padding: '10px', color: 'var(--muted)' }}>{row.supportGroup}</td>
                  <td style={{ padding: '10px', color: 'var(--muted)' }}>{row.owner}</td>
                  <td style={{ padding: '10px' }}>
                    {row.priority !== '—' ? <PriorityBadge priority={row.priority} /> : <span style={{ color: 'var(--muted)' }}>—</span>}
                  </td>
                  <td style={{ padding: '10px', color: 'var(--muted)', fontFamily: 'monospace', fontSize: 12 }}>{row.incidentId}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>

      {/* Finding Configuration Modal */}
      {showConfigModal && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            background: 'rgba(0,0,0,0.45)', display: 'flex',
            alignItems: 'flex-start', justifyContent: 'flex-end',
          }}
          onClick={(e) => { if (e.target === e.currentTarget) setShowConfigModal(false); }}
        >
          <div style={{
            width: 560, maxHeight: '100vh', overflowY: 'auto',
            background: 'var(--panel)', borderLeft: '1px solid var(--border)',
            padding: '28px 28px 24px', display: 'flex', flexDirection: 'column', gap: 20,
          }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
              <div>
                <h2 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Finding Configuration</h2>
                <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 6, lineHeight: 1.5 }}>
                  Configure due date, tags, and assignment logic for the selected impacted assets without leaving the current findings workspace.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowConfigModal(false)}
                style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, width: 32, height: 32, cursor: 'pointer', fontSize: 16, color: 'var(--text)', flexShrink: 0 }}
              >
                ×
              </button>
            </div>

            <div style={{ borderTop: '1px solid var(--border)' }} />

            {/* Finding Title */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>FINDING TITLE</label>
              <input
                style={{ width: '100%', padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', boxSizing: 'border-box' }}
                value={cfgTitle}
                onChange={(e) => setCfgTitle(e.target.value)}
              />
            </div>

            {/* Priority + Due Date */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>PRIORITY</label>
                <select
                  style={{ padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                  value={cfgPriority}
                  onChange={(e) => setCfgPriority(e.target.value)}
                >
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>DUE DATE</label>
                <input
                  type="date"
                  style={{ padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                  value={cfgDueDate}
                  onChange={(e) => setCfgDueDate(e.target.value)}
                />
              </div>
            </div>

            {/* Tags */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>TAGS</label>
              <input
                style={{ width: '100%', padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', boxSizing: 'border-box' }}
                placeholder="e.g. internet-facing, zero-day, patching"
                value={cfgTags}
                onChange={(e) => setCfgTags(e.target.value)}
              />
            </div>

            {/* Assignment */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>ASSIGNMENT / OWNERSHIP LOGIC</label>
              <select
                style={{ padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                value={cfgAssignment}
                onChange={(e) => setCfgAssignment(e.target.value)}
              >
                <option>Assign to lead analyst</option>
                <option>Assign by support group</option>
                <option>Assign by asset owner</option>
                <option>Leave unassigned</option>
              </select>
            </div>

            {/* ServiceNow */}
            <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 14, fontWeight: 600, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={cfgServiceNow}
                onChange={(e) => setCfgServiceNow(e.target.checked)}
                style={{ width: 16, height: 16, accentColor: 'var(--accent)' }}
              />
              Create tickets in ServiceNow
            </label>

            {/* Notes */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.06em' }}>NOTES</label>
              <textarea
                rows={4}
                style={{ width: '100%', padding: '10px 12px', fontSize: 14, background: 'var(--input-bg, var(--panel-muted))', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', resize: 'vertical', boxSizing: 'border-box', fontFamily: 'inherit' }}
                placeholder="Describe the remediation approach or ticket creation context..."
                value={cfgNotes}
                onChange={(e) => setCfgNotes(e.target.value)}
              />
            </div>

            <div style={{ borderTop: '1px solid var(--border)' }} />

            {/* Footer */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowConfigModal(false)}
              >
                Close
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleCreateFindings}
                disabled={creating}
              >
                {creating ? 'Creating…' : `Create Findings (${selectedIds.size})`}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
