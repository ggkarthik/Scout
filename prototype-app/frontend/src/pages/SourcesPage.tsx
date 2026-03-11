import React from 'react';
import { api } from '../api/client';
import { SyncRun, SyncRunSnapshot, VexAssertionRepairSummary } from '../types';
import { ResizableTable } from '../components/ResizableTable';

type FocusSource = 'all' | 'vuln-only' | 'nvd' | 'kev' | 'ghsa' | 'github' | 'microsoft-csaf' | 'redhat-csaf' | 'advisories';
type Props = {
  focusSource?: FocusSource;
  title?: string;
  caption?: string;
  showTriggers?: boolean;
  showQueue?: boolean;
  refreshSignal?: number;
};

function humanDuration(startedAt: string, completedAt?: string): string {
  if (!completedAt) return 'In progress';
  const start = new Date(startedAt).getTime();
  const end = new Date(completedAt).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return 'n/a';
  }
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

function isRunning(status: string): boolean {
  const value = status.trim().toUpperCase();
  return value === 'RUNNING' || value === 'STARTED' || value === 'QUEUED';
}

function includesType(run: SyncRun, needle: string): boolean {
  return run.syncType.toUpperCase().includes(needle.toUpperCase());
}

function queuePositionLabel(run: SyncRun): string {
  if (!isRunning(run.status) || run.queuePosition == null) {
    return '-';
  }
  return run.queuePosition === 1 ? 'Running now' : `#${run.queuePosition}`;
}

function renderSnapshot(snapshot?: SyncRunSnapshot, emptyLabel = 'No run yet') {
  if (!snapshot) {
    return emptyLabel;
  }
  return (
    <>
      <div>{snapshot.status}</div>
      <div className="panel-caption">
        {snapshot.startedAt ? new Date(snapshot.startedAt).toLocaleString() : 'No start time'}
      </div>
      {snapshot.errorMessage && (
        <div className="panel-caption">{snapshot.errorMessage}</div>
      )}
    </>
  );
}

function deltaLabel(before: number, after: number): string {
  const delta = after - before;
  if (delta === 0) {
    return `${after} (no change)`;
  }
  return `${after} (${delta > 0 ? '+' : ''}${delta})`;
}

export function SourcesPage({
  focusSource = 'all',
  title = 'Source Ingestion',
  caption = 'Ingest NVD/KEV/CSAF/VEX/advisories and normalize vulnerability intelligence',
  showTriggers = true,
  showQueue = true,
  refreshSignal = 0
}: Props) {
  const [syncRuns, setSyncRuns] = React.useState<SyncRun[]>([]);
  const [message, setMessage] = React.useState('');
  const [busy, setBusy] = React.useState<string | null>(null);
  const [loadingRuns, setLoadingRuns] = React.useState(false);
  const [confirmFullSync, setConfirmFullSync] = React.useState(false);
  const [vexRepairSummary, setVexRepairSummary] = React.useState<VexAssertionRepairSummary | null>(null);
  const [loadingVexRepairSummary, setLoadingVexRepairSummary] = React.useState(false);
  const showVexRepairPanel = focusSource === 'all'
    || focusSource === 'vuln-only'
    || focusSource === 'microsoft-csaf'
    || focusSource === 'redhat-csaf';

  const refreshRuns = React.useCallback(async () => {
    setLoadingRuns(true);
    try {
      const rows = await api.listSyncRuns();
      setSyncRuns(rows);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingRuns(false);
    }
  }, []);

  const refreshVexRepairSummary = React.useCallback(async () => {
    if (!showVexRepairPanel) {
      return;
    }
    setLoadingVexRepairSummary(true);
    try {
      const summary = await api.getVexAssertionRepairSummary();
      setVexRepairSummary(summary);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingVexRepairSummary(false);
    }
  }, [showVexRepairPanel]);

  React.useEffect(() => {
    if (!showQueue) {
      return;
    }
    refreshRuns();
  }, [refreshRuns, showQueue, refreshSignal]);

  React.useEffect(() => {
    refreshVexRepairSummary();
  }, [refreshSignal, refreshVexRepairSummary]);

  React.useEffect(() => {
    if (!showQueue) {
      return undefined;
    }
    if (!syncRuns.some((run) => isRunning(run.status))) {
      return undefined;
    }
    const id = window.setInterval(() => {
      refreshRuns();
      refreshVexRepairSummary();
    }, 3000);
    return () => window.clearInterval(id);
  }, [syncRuns, refreshRuns, refreshVexRepairSummary, showQueue]);

  const runAction = async (
    label: string,
    fn: () => Promise<{ runId?: string; status?: string; message?: string } | unknown>
  ): Promise<void> => {
    setBusy(label);
    setMessage(`${label} started...`);
    try {
      const response = await fn();
      if (response && typeof response === 'object' && 'runId' in response) {
        const typed = response as { runId?: string; status?: string; message?: string };
        setMessage(`${label} queued: ${typed.runId ?? 'n/a'} (${typed.status ?? 'queued'})`);
      } else if (response && typeof response === 'object' && 'inserted' in response) {
        const typed = response as { inserted?: number; updated?: number };
        setMessage(`${label} finished. Inserted ${typed.inserted ?? 0}, updated ${typed.updated ?? 0}.`);
      } else {
        setMessage(`${label} completed`);
      }
      if (showQueue) {
        await refreshRuns();
      }
      await refreshVexRepairSummary();
    } catch (e) {
      setMessage(`${label} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  const visibleRuns = syncRuns.filter((run) => {
    if (focusSource === 'vuln-only') {
      return !includesType(run, 'GITHUB_');
    }
    if (focusSource === 'nvd') {
      return includesType(run, 'NVD');
    }
    if (focusSource === 'kev') {
      return includesType(run, 'KEV');
    }
    if (focusSource === 'ghsa') {
      return includesType(run, 'GHSA');
    }
    if (focusSource === 'github') {
      return includesType(run, 'GITHUB_');
    }
    if (focusSource === 'advisories') {
      return includesType(run, 'ADVISORY') || includesType(run, 'RECOMPUTE');
    }
    if (focusSource === 'microsoft-csaf') {
      return includesType(run, 'CSAF_MICROSOFT')
        || includesType(run, 'VEX_ASSERTION_REPAIR')
        || includesType(run, 'VEX_ROLLOUT_BACKFILL');
    }
    if (focusSource === 'redhat-csaf') {
      return includesType(run, 'CSAF_REDHAT')
        || includesType(run, 'VEX_ASSERTION_REPAIR')
        || includesType(run, 'VEX_ROLLOUT_BACKFILL');
    }
    return true;
  });

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>{title}</h3>
        <span className="panel-caption">{caption}</span>
      </div>

      {(showTriggers || showQueue) && (
      <div className="button-row section-actions">
        {showTriggers && (focusSource === 'all' || focusSource === 'nvd') && (
          <>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy !== null}
              onClick={() => runAction('NVD Full Sync', () => api.syncNvdFull())}
            >
              {busy === 'NVD Full Sync' ? 'Running...' : 'Run NVD Full Sync'}
            </button>
          </>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'kev') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null}
            onClick={() => runAction('KEV Sync', () => api.syncKev())}
          >
            {busy === 'KEV Sync' ? 'Running...' : 'Run KEV Sync'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'ghsa') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null}
            onClick={() => runAction('GHSA Sync', () => api.syncGhsa())}
          >
            {busy === 'GHSA Sync' ? 'Running...' : 'Run GHSA Sync'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'microsoft-csaf') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null}
            onClick={() => runAction('Microsoft CSAF/VEX Sync', () => api.syncMicrosoftCsaf())}
          >
            {busy === 'Microsoft CSAF/VEX Sync' ? 'Running...' : 'Run Microsoft CSAF/VEX Sync'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'redhat-csaf') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null}
            onClick={() => runAction('Red Hat CSAF/VEX Sync', () => api.syncRedhatCsaf())}
          >
            {busy === 'Red Hat CSAF/VEX Sync' ? 'Running...' : 'Run Red Hat CSAF/VEX Sync'}
          </button>
        )}
        {showTriggers && showVexRepairPanel && (
          <button
            type="button"
            className="btn btn-secondary"
            disabled={
              busy !== null
              || (vexRepairSummary != null && (!vexRepairSummary.vexRolloutControlsEnabled || !vexRepairSummary.vexRolloutBackfillEnabled))
            }
            onClick={() => runAction('Vendor VEX Backfill', () => api.triggerVexRolloutBackfill())}
          >
            {busy === 'Vendor VEX Backfill' ? 'Running...' : 'Run Vendor VEX Backfill'}
          </button>
        )}
        {showTriggers && showVexRepairPanel && (
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy !== null || (vexRepairSummary != null && !vexRepairSummary.vexRolloutControlsEnabled)}
            onClick={() => runAction('VEX Assertion Repair', () => api.triggerVexAssertionRepair())}
          >
            {busy === 'VEX Assertion Repair' ? 'Running...' : 'Rebuild Persisted VEX State'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'advisories') && (
          <>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy !== null}
              onClick={() => runAction('Seed Demo', () => api.seedDemo())}
            >
              {busy === 'Seed Demo' ? 'Running...' : 'Seed Demo Advisories'}
            </button>
          </>
        )}
        {showQueue && (
          <button
            type="button"
            className="btn btn-secondary"
            disabled={loadingRuns || loadingVexRepairSummary}
            onClick={async () => {
              await refreshRuns();
              await refreshVexRepairSummary();
            }}
          >
            {loadingRuns || loadingVexRepairSummary ? 'Refreshing...' : 'Refresh'}
          </button>
        )}
      </div>
      )}

      {showVexRepairPanel && (
        <div className="section-block">
          <h4 className="section-title">VEX Rollout Status</h4>
          <div className="panel-caption">
            Run vendor CSAF/VEX re-ingest and persisted assertion repair from one place, then compare current VEX coverage and
            exact-match exposure state without leaving the shared source queue.
          </div>
          {vexRepairSummary && (
            <div className="panel-caption" style={{ marginTop: 8 }}>
              Controls: {vexRepairSummary.vexRolloutControlsEnabled ? 'enabled' : 'disabled'} | Backfill: {vexRepairSummary.vexRolloutBackfillEnabled ? 'enabled' : 'disabled'} |
              VEX policy: {vexRepairSummary.vexPolicyEnabled ? 'enabled' : 'disabled'} | Risk modifiers: {vexRepairSummary.vexRiskModifiersEnabled ? 'enabled' : 'disabled'}
            </div>
          )}
          {vexRepairSummary ? (
            <div className="table-scroll">
              <ResizableTable storageKey="vex-repair-summary-widths">
                <thead>
                  <tr>
                    <th>VEX-like Targets</th>
                    <th>Persisted Assertions</th>
                    <th>Matched Active States</th>
                    <th>Applicable Awaiting VEX</th>
                    <th>Source Systems</th>
                    <th>Latest Backfill Run</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>{vexRepairSummary.vexLikeTargetCount}</td>
                    <td>{vexRepairSummary.persistedAssertionCount}</td>
                    <td>{vexRepairSummary.activeMatchedComponentCount}</td>
                    <td>{vexRepairSummary.activeApplicableAwaitingVexCount}</td>
                    <td>{vexRepairSummary.sourceSystems.length > 0 ? vexRepairSummary.sourceSystems.join(', ') : '-'}</td>
                    <td>{renderSnapshot(vexRepairSummary.latestBackfillRun, 'No backfill run yet')}</td>
                  </tr>
                </tbody>
              </ResizableTable>
            </div>
          ) : (
            <div className="empty-state">
              <p>{loadingVexRepairSummary ? 'Loading VEX repair summary...' : 'No VEX repair summary available yet.'}</p>
            </div>
          )}
          {vexRepairSummary?.latestBackfillComparison && (
            <div className="table-scroll" style={{ marginTop: 12 }}>
              <ResizableTable storageKey="vex-rollout-comparison-widths">
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>Before Backfill</th>
                    <th>After Backfill</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>VEX-like Targets</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.vexLikeTargetCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.vexLikeTargetCount,
                      vexRepairSummary.latestBackfillComparison.after.vexLikeTargetCount
                    )}</td>
                  </tr>
                  <tr>
                    <td>Persisted Assertions</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.persistedAssertionCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.persistedAssertionCount,
                      vexRepairSummary.latestBackfillComparison.after.persistedAssertionCount
                    )}</td>
                  </tr>
                  <tr>
                    <td>Matched Active States</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.activeMatchedComponentCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.activeMatchedComponentCount,
                      vexRepairSummary.latestBackfillComparison.after.activeMatchedComponentCount
                    )}</td>
                  </tr>
                  <tr>
                    <td>Applicable Awaiting VEX</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.activeApplicableAwaitingVexCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.activeApplicableAwaitingVexCount,
                      vexRepairSummary.latestBackfillComparison.after.activeApplicableAwaitingVexCount
                    )}</td>
                  </tr>
                </tbody>
              </ResizableTable>
            </div>
          )}
          {vexRepairSummary && (
            <div className="table-scroll" style={{ marginTop: 12 }}>
              <ResizableTable storageKey="vex-rollout-runs-widths">
                <thead>
                  <tr>
                    <th>Microsoft CSAF/VEX</th>
                    <th>Red Hat CSAF/VEX</th>
                    <th>Persisted VEX Repair</th>
                    <th>Summary Generated</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>{renderSnapshot(vexRepairSummary.latestMicrosoftRun, 'No Microsoft sync yet')}</td>
                    <td>{renderSnapshot(vexRepairSummary.latestRedhatRun, 'No Red Hat sync yet')}</td>
                    <td>{renderSnapshot(vexRepairSummary.latestRepairRun, 'No repair run yet')}</td>
                    <td>{new Date(vexRepairSummary.generatedAt).toLocaleString()}</td>
                  </tr>
                </tbody>
              </ResizableTable>
            </div>
          )}
        </div>
      )}

      {showTriggers && (focusSource === 'all' || focusSource === 'nvd') && (
        <div className="section-block">
        <h4 className="section-title">Danger Zone</h4>
        <div className="panel-caption">
          NVD Full Sync ingests the full upstream vulnerability corpus. Use it for first-time baseline or data reset recovery.
        </div>
        <div className="bulk-selection-row">
          <label className="bulk-checkbox">
            <input
              type="checkbox"
              checked={confirmFullSync}
              onChange={(event) => setConfirmFullSync(event.target.checked)}
            />
            <span>I understand this can take longer and increase DB load.</span>
          </label>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy !== null || !confirmFullSync}
            onClick={() => runAction('NVD Full Sync', () => api.syncNvdFull())}
          >
            {busy === 'NVD Full Sync' ? 'Running...' : 'Run NVD Full Sync'}
          </button>
        </div>
        </div>
      )}

      {message && <div className="notice">{message}</div>}

      {showQueue && (
        <>
          <h4 className="section-title section-divider">Recent Sync Runs</h4>
          {focusSource === 'github' && (
            <div className="panel-caption" style={{ marginBottom: 12 }}>
              GitHub ingestion runs use <span className="mono">Fetched</span> for discovered images or repositories,
              <span className="mono"> Inserted</span> for ingested components, <span className="mono"> Updated</span> for generated findings,
              and <span className="mono"> Failed</span> for assets that did not ingest successfully.
            </div>
          )}
          {visibleRuns.length === 0 ? (
            <div className="empty-state">
              <p>No sync runs yet for this source. Trigger sync to populate this activity feed.</p>
            </div>
          ) : (
            <div className="table-scroll">
              <ResizableTable storageKey="sync-runs-table-widths">
                <thead>
                <tr>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Queue</th>
                  <th>Fetched</th>
                  <th>Inserted</th>
                  <th>Updated</th>
                  <th>Failed</th>
                  <th>Started</th>
                  <th>Completed</th>
                  <th>Duration</th>
                  <th>Error</th>
                </tr>
                </thead>
                <tbody>
                {visibleRuns.map((run) => (
                  <tr key={run.id}>
                    <td>{run.syncType}</td>
                    <td>
                      <span className={`status-pill ${isRunning(run.status) ? 'status-open' : 'status-resolved'}`}>
                        {run.status}
                      </span>
                    </td>
                    <td>{queuePositionLabel(run)}</td>
                    <td>{run.recordsFetched}</td>
                    <td>{run.recordsInserted}</td>
                    <td>{run.recordsUpdated}</td>
                    <td>{run.recordsFailed ?? 0}</td>
                    <td>{new Date(run.startedAt).toLocaleString()}</td>
                    <td>{run.completedAt ? new Date(run.completedAt).toLocaleString() : 'In progress'}</td>
                    <td>{humanDuration(run.startedAt, run.completedAt)}</td>
                    <td className="panel-caption">{run.errorMessage || '-'}</td>
                  </tr>
                ))}
                </tbody>
              </ResizableTable>
            </div>
          )}
        </>
      )}
    </div>
  );
}
