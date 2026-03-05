import React from 'react';
import { api } from '../api/client';
import { SyncRun } from '../types';
import { ResizableTable } from '../components/ResizableTable';

type FocusSource = 'all' | 'nvd' | 'kev' | 'ghsa' | 'microsoft-csaf' | 'redhat-csaf' | 'advisories';
type Props = {
  focusSource?: FocusSource;
  title?: string;
  caption?: string;
  showTriggers?: boolean;
  showQueue?: boolean;
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

export function SourcesPage({
  focusSource = 'all',
  title = 'Source Ingestion',
  caption = 'Ingest NVD/KEV/CSAF/VEX/advisories and normalize vulnerability intelligence',
  showTriggers = true,
  showQueue = true
}: Props) {
  const [syncRuns, setSyncRuns] = React.useState<SyncRun[]>([]);
  const [message, setMessage] = React.useState('');
  const [busy, setBusy] = React.useState<string | null>(null);
  const [loadingRuns, setLoadingRuns] = React.useState(false);
  const [confirmFullSync, setConfirmFullSync] = React.useState(false);

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

  React.useEffect(() => {
    if (!showQueue) {
      return;
    }
    refreshRuns();
  }, [refreshRuns, showQueue]);

  React.useEffect(() => {
    if (!showQueue) {
      return undefined;
    }
    if (!syncRuns.some((run) => isRunning(run.status))) {
      return undefined;
    }
    const id = window.setInterval(() => {
      refreshRuns();
    }, 3000);
    return () => window.clearInterval(id);
  }, [syncRuns, refreshRuns]);

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
    } catch (e) {
      setMessage(`${label} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  const visibleRuns = syncRuns.filter((run) => {
    if (focusSource === 'nvd') {
      return includesType(run, 'NVD');
    }
    if (focusSource === 'kev') {
      return includesType(run, 'KEV');
    }
    if (focusSource === 'ghsa') {
      return includesType(run, 'GHSA');
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
          <button type="button" className="btn btn-secondary" disabled={loadingRuns} onClick={() => refreshRuns()}>
            {loadingRuns ? 'Refreshing...' : 'Refresh'}
          </button>
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
