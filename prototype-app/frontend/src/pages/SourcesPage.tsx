import React from 'react';
import { api } from '../api/client';
import { SyncRun, SyncRunSnapshot, VexAssertionRepairSummary } from '../types';
import { ResizableTable } from '../components/ResizableTable';

type FocusSource = 'all' | 'vuln-only' | 'processing' | 'nvd' | 'kev' | 'ghsa' | 'github' | 'microsoft-csaf' | 'redhat-csaf' | 'advisories';
type Props = {
  focusSource?: FocusSource;
  title?: string;
  caption?: string;
  hideHeader?: boolean;
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

function isRunDomain(run: SyncRun, runDomain: SyncRun['runDomain']): boolean {
  return run.runDomain === runDomain;
}

function formatRunClass(runClass: SyncRun['runClass']): string {
  return runClass
    .split('_')
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1).toLowerCase())
    .join(' ');
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
  hideHeader = false,
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
  const showConnectorStatus = !showQueue && (focusSource === 'microsoft-csaf' || focusSource === 'redhat-csaf');
  const showVexRepairPanel = focusSource === 'processing';
  const shouldLoadVexRepairSummary = showVexRepairPanel;
  const showProcessingTriggers = focusSource === 'processing';
  const shouldLoadRuns = showQueue || showConnectorStatus;
  const showNvdConnectorHero = showTriggers && focusSource === 'nvd' && !showQueue;

  const refreshRuns = React.useCallback(async () => {
    setLoadingRuns(true);
    try {
      const rows = await api.listSyncRuns(
        focusSource === 'github'
          ? { category: 'inventory', limit: 50 }
          : focusSource === 'processing'
            ? { category: 'processing', limit: 50 }
          : focusSource === 'all'
            ? { category: 'all', limit: 25 }
            : { category: 'vuln-intel', limit: 50 }
      );
      setSyncRuns(rows);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingRuns(false);
    }
  }, [focusSource]);

  const refreshVexRepairSummary = React.useCallback(async () => {
    if (!shouldLoadVexRepairSummary) {
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
  }, [shouldLoadVexRepairSummary]);

  React.useEffect(() => {
    if (!shouldLoadRuns) {
      return;
    }
    refreshRuns();
  }, [refreshRuns, shouldLoadRuns, refreshSignal]);

  React.useEffect(() => {
    refreshVexRepairSummary();
  }, [refreshSignal, refreshVexRepairSummary]);

  React.useEffect(() => {
    if (!shouldLoadRuns) {
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
  }, [syncRuns, refreshRuns, refreshVexRepairSummary, shouldLoadRuns]);

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
      if (shouldLoadRuns) {
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
      return isRunDomain(run, 'VULN_INTEL');
    }
    if (focusSource === 'processing') {
      return isRunDomain(run, 'PROCESSING');
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
      return includesType(run, 'CSAF_MICROSOFT');
    }
    if (focusSource === 'redhat-csaf') {
      return includesType(run, 'CSAF_REDHAT');
    }
    return true;
  });
  const orderedVisibleRuns = [...visibleRuns].sort(
    (left, right) => new Date(right.startedAt).getTime() - new Date(left.startedAt).getTime()
  );
  const latestConnectorRun = showConnectorStatus ? orderedVisibleRuns[0] : undefined;
  const connectorRunLabel = focusSource === 'microsoft-csaf' ? 'Latest Microsoft CSAF/VEX sync' : 'Latest Red Hat CSAF/VEX sync';

  const renderSyncRunSummary = (run?: SyncRun, emptyLabel = 'No run yet') => {
    if (!run) {
      return emptyLabel;
    }
    return (
      <>
        <div>{run.status}</div>
        <div className="panel-caption">{new Date(run.startedAt).toLocaleString()}</div>
        {run.errorMessage && <div className="panel-caption">{run.errorMessage}</div>}
      </>
    );
  };

  return (
    <div className="panel">
      {!hideHeader && (
        <div className="panel-header">
          <h3>{title}</h3>
          <span className="panel-caption">{caption}</span>
        </div>
      )}

      {(showTriggers || showQueue) && (
      <div className="button-row section-actions">
        {showTriggers && !showNvdConnectorHero && (focusSource === 'all' || focusSource === 'nvd') && (
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
        {showTriggers && showProcessingTriggers && (
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
        {showTriggers && showProcessingTriggers && (
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

      {showNvdConnectorHero && (
        <div className="source-focus-hero">
          <div className="source-focus-hero-copy">
            <span className="source-focus-kicker">Recommended</span>
            <h4 className="source-focus-title">Routine CVE Delta Sync</h4>
            <p className="source-focus-description">
              Pull the latest NVD changes from the last 24 hours and refresh normalized vulnerability intelligence without
              running the full upstream corpus again.
            </p>
            <div className="source-focus-pill-row">
              <span className="status-pill status-success">24h Delta</span>
              <span className="status-pill status-warning">Lower DB Load</span>
            </div>
          </div>
          <div className="source-focus-hero-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy !== null}
              onClick={() => runAction('NVD Sync', () => api.syncNvd())}
            >
              {busy === 'NVD Sync' ? 'Running...' : 'Run 24h Sync'}
            </button>
            <span className="panel-caption">Best for daily refreshes and repeat validation.</span>
          </div>
        </div>
      )}

      {showConnectorStatus && (
        <div className="connector-status-grid section-block">
          <div className="connector-status-card">
            <div className="connector-status-label">{connectorRunLabel}</div>
            <div className="connector-status-value">{renderSyncRunSummary(latestConnectorRun, 'No sync run recorded yet.')}</div>
          </div>
        </div>
      )}

      {showVexRepairPanel && (
        <div className="section-block">
          <h4 className="section-title">Shared VEX Maintenance</h4>
          <div className="panel-caption">
            Run vendor CSAF/VEX backfill and persisted assertion repair from one place, then compare current VEX coverage,
            rollout impact, and latest cross-vendor maintenance activity.
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
          <div className="sync-danger-card">
            <div className="sync-danger-copy">
              <span className="sync-danger-kicker">Danger Zone</span>
              <h4 className="sync-danger-title">Run NVD Full Corpus Sync</h4>
              <div className="panel-caption">
                Use this for first-time baseline setup or after prototype-reset recovery. It ingests the full upstream
                vulnerability corpus and can noticeably increase DB load.
              </div>
            </div>
            <div className="sync-danger-controls">
              <label className="bulk-checkbox sync-danger-checkbox">
                <input
                  type="checkbox"
                  checked={confirmFullSync}
                  onChange={(event) => setConfirmFullSync(event.target.checked)}
                />
                <span>I understand the runtime and database impact.</span>
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
        </div>
      )}

      {message && <div className="notice">{message}</div>}

      {showQueue && (
        <>
          <h4 className="section-title section-divider">
            {focusSource === 'processing' ? 'Recent Processing Jobs' : 'Recent Sync Runs'}
          </h4>
          {focusSource === 'github' && (
            <div className="panel-caption" style={{ marginBottom: 12 }}>
              GitHub ingestion runs use <span className="mono">Fetched</span> for discovered images or repositories,
              <span className="mono"> Inserted</span> for ingested components, <span className="mono"> Updated</span> for generated findings,
              and <span className="mono"> Failed</span> for assets that did not ingest successfully.
            </div>
          )}
          {focusSource === 'processing' && (
            <div className="panel-caption" style={{ marginBottom: 12 }}>
              Processing jobs track internal maintenance work like persisted VEX repair and rollout backfills. They do not represent upstream feed fetches.
            </div>
          )}
                {orderedVisibleRuns.length === 0 ? (
            <div className="empty-state">
              <p>{focusSource === 'processing'
                ? 'No processing jobs have been recorded yet.'
                : 'No sync runs yet for this source. Trigger sync to populate this activity feed.'}</p>
            </div>
          ) : (
            <div className="table-scroll">
              <ResizableTable storageKey="sync-runs-table-widths">
                <thead>
                <tr>
                  <th>Type</th>
                  <th>Class</th>
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
                {orderedVisibleRuns.map((run) => (
                  <tr key={run.id}>
                    <td>{run.syncType}</td>
                    <td>{formatRunClass(run.runClass)}</td>
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
