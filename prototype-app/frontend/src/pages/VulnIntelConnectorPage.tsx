/**
 * Generic Vulnerability Intelligence connector page.
 * Used by NVD, KEV, GHSA, Microsoft CSAF, Red Hat CSAF, Advisory connectors.
 */
import React from 'react';
import { pathForConnectView } from '../app/routes';
import type { SyncTriggerResponse } from '../features/connect/types';
import type { VulnIntelSourceStatus } from '../api/client';

function connectHref(view: 'integration-run-queue'): string {
  return pathForConnectView(view);
}

function formatTimestamp(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function Tooltip({ text }: { text: string }) {
  return <span className="sn-tooltip" title={text} aria-label={text}>ⓘ</span>;
}

export type VulnIntelConnectorConfig = {
  /** Display title shown in the section header */
  title: string;
  /** Source type key used in sync_runs, e.g. "NVD" */
  sourceKey: string;
  /** Function to trigger the sync */
  triggerSync: () => Promise<SyncTriggerResponse>;
  /** Optional: extra config fields rendered between status row and sync settings */
  configFields?: React.ReactNode;
  /** Optional: test connection button (NVD API key check etc.) */
  onTestConnection?: () => Promise<{ ok: boolean; message: string }>;
};

type Props = {
  config: VulnIntelConnectorConfig;
  lastRun?: VulnIntelSourceStatus;
};

export function VulnIntelConnectorPage({ config, lastRun }: Props) {
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<SyncTriggerResponse | null>(null);
  const [error, setError] = React.useState('');
  const [autoSyncEnabled, setAutoSyncEnabled] = React.useState(false);
  const [intervalHours, setIntervalHours] = React.useState(24);

  const trigger = async () => {
    setRunning(true);
    setError('');
    setResult(null);
    try {
      const res = await config.triggerSync();
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  const hasLastRun = lastRun && lastRun.status !== 'never';
  const isFailed = lastRun?.status === 'failed';
  const totalRecords = (lastRun?.recordsInserted ?? 0) + (lastRun?.recordsUpdated ?? 0);

  return (
    <section className="panel">
      {/* Status row */}
      {hasLastRun && (
        <div className={`sn-status-row ${isFailed ? 'sn-status-row--error' : ''}`}>
          {isFailed ? (
            <>
              <span className="sn-status-pill sn-status-fail">Failed</span>
              <span className="sn-status-meta">{formatTimestamp(lastRun?.completedAt)}</span>
              {lastRun?.errorMessage && (
                <span className="sn-status-meta sn-status-error-msg" title={lastRun.errorMessage}>
                  {lastRun.errorMessage.length > 80 ? lastRun.errorMessage.slice(0, 80) + '…' : lastRun.errorMessage}
                </span>
              )}
            </>
          ) : (
            <>
              <span className="sn-status-meta">Last integration run: {formatTimestamp(lastRun?.completedAt)}</span>
              {totalRecords > 0 && (
                <span className="sn-status-meta">
                  {lastRun?.recordsInserted ? `${lastRun.recordsInserted.toLocaleString()} created` : ''}
                  {lastRun?.recordsInserted && lastRun?.recordsUpdated ? ' · ' : ''}
                  {lastRun?.recordsUpdated ? `${lastRun.recordsUpdated.toLocaleString()} updated` : ''}
                </span>
              )}
            </>
          )}
        </div>
      )}

      {error && <div className="notice error">{error}</div>}

      {/* Optional extra config fields (e.g. API key) */}
      {config.configFields && (
        <div className="form-section">
          <h4 className="form-section-title">Configuration</h4>
          {config.configFields}
        </div>
      )}

      {/* Sync Settings */}
      <div className="form-section">
        <h4 className="form-section-title">Sync Settings</h4>
        <div className="sn-toggle-group">
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={autoSyncEnabled}
              onChange={(e) => setAutoSyncEnabled(e.target.checked)}
            />
            <span>Enable scheduled sync</span>
            <Tooltip text="Automatically runs this feed on the configured interval." />
          </label>
        </div>
        {autoSyncEnabled && (
          <div className="form-grid sn-sync-interval-grid">
            <label>
              <span>Sync Interval (hours) <Tooltip text="How often the scheduled sync runs. Minimum 1 hour." /></span>
              <input
                type="number"
                min={1}
                value={intervalHours}
                onChange={(e) => setIntervalHours(Math.max(1, Number(e.target.value)))}
              />
            </label>
          </div>
        )}
      </div>

      {/* Action bar */}
      <div className="button-row section-actions sn-action-bar">
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void trigger()}
          disabled={running}
        >
          {running ? 'Running...' : 'Run Integration now'}
        </button>
      </div>

      {result && (
        <div className="notice">
          <strong>Integration queued.</strong> {result.message}. Track progress in{' '}
          <a href={connectHref('integration-run-queue')}>Integration Run Queue</a>.
        </div>
      )}
    </section>
  );
}
