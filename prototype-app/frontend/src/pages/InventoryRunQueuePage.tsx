import React from 'react';
import { api } from '../api/client';
import { ResizableTable } from '../components/ResizableTable';
import type { SyncRun } from '../types';

type InventoryRunMetadata = {
  sourceSystem?: string;
  assetType?: string;
  assetsDiscovered?: number;
  assetsIngested?: number;
  assetsFailed?: number;
  componentsIngested?: number;
  findingsGenerated?: number;
  triggerMode?: string;
  stage?: string;
  tableName?: string;
  scope?: string;
  installRowsProcessed?: number;
  discoveryRowsProcessed?: number;
  unmatchedDiscoveryRows?: number;
  ciCreated?: number;
  ciAliasesCreated?: number;
  softwareInstancesCreated?: number;
  softwareInstancesUpdated?: number;
  inventoryComponentsCreated?: number;
  inventoryComponentsUpdated?: number;
  message?: string;
};

function parseRunMetadata(value?: string): InventoryRunMetadata {
  if (!value || !value.trim()) return {};
  try {
    return JSON.parse(value) as InventoryRunMetadata;
  } catch {
    return {};
  }
}

function humanDuration(startedAt: string, completedAt?: string): string {
  if (!completedAt) return 'In progress';
  const seconds = Math.round((new Date(completedAt).getTime() - new Date(startedAt).getTime()) / 1000);
  if (Number.isNaN(seconds) || seconds < 0) return 'n/a';
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function isActiveRun(status: string): boolean {
  const value = status.trim().toUpperCase();
  return value === 'RUNNING' || value === 'STARTED' || value === 'QUEUED';
}

function isInventoryRunType(syncType: string): boolean {
  const normalized = syncType.trim().toUpperCase();
  return normalized.startsWith('GITHUB_') || normalized === 'SERVICENOW_CMDB';
}

function isInventoryRun(run: SyncRun): boolean {
  return run.runDomain === 'INVENTORY' || isInventoryRunType(run.syncType);
}

function queueLabel(run: SyncRun): string {
  if (!isActiveRun(run.status) || run.queuePosition == null) return '-';
  return run.queuePosition === 1 ? 'Running now' : `#${run.queuePosition}`;
}

function formatSourceSystem(value?: string): string {
  if (!value || value.trim().length === 0) return 'Unknown';
  const normalized = value.trim().toLowerCase();
  if (normalized === 'api') return 'API Endpoint';
  if (normalized === 'github') return 'GitHub';
  if (normalized === 'servicenow') return 'ServiceNow';
  return value;
}

function formatSyncType(value: string): string {
  const normalized = value.trim().toUpperCase();
  if (normalized === 'SERVICENOW_CMDB') return 'ServiceNow CMDB Live Sync';
  if (normalized === 'GITHUB_REPOSITORY_SBOM') return 'GitHub Repository SBOM';
  if (normalized === 'GITHUB_GHCR_SBOM') return 'GitHub GHCR SBOM';
  return value;
}

function formatRunStatus(value: string): string {
  return value
    .split('_')
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1).toLowerCase())
    .join(' ');
}

function runStatusClass(value: string): string {
  const normalized = value.trim().toUpperCase();
  if (normalized === 'FAILED') return 'status-failure';
  if (normalized === 'PARTIAL_SUCCESS') return 'status-warning';
  if (normalized === 'COMPLETED') return 'status-success';
  if (normalized === 'RUNNING' || normalized === 'STARTED') return 'status-open';
  if (normalized === 'QUEUED') return 'status-open';
  return `status-${value.toLowerCase().replace('_', '-')}`;
}

function formatCount(value?: number): string {
  return value == null ? '-' : String(value);
}

function readAssetsIngested(run: SyncRun, metadata: InventoryRunMetadata): number | undefined {
  return metadata.assetsIngested;
}

function readComponentsIngested(run: SyncRun, metadata: InventoryRunMetadata): number | undefined {
  if (metadata.componentsIngested != null) {
    return metadata.componentsIngested;
  }
  if (metadata.inventoryComponentsCreated != null || metadata.inventoryComponentsUpdated != null) {
    return (metadata.inventoryComponentsCreated ?? 0) + (metadata.inventoryComponentsUpdated ?? 0);
  }
  const normalizedType = run.syncType.trim().toUpperCase();
  if (normalizedType.startsWith('GITHUB_') && run.recordsInserted > 0) {
    return run.recordsInserted;
  }
  return undefined;
}

function readFindingsGenerated(run: SyncRun, metadata: InventoryRunMetadata): number | undefined {
  if (metadata.findingsGenerated != null) {
    return metadata.findingsGenerated;
  }
  const normalizedType = run.syncType.trim().toUpperCase();
  if (normalizedType.startsWith('GITHUB_') && run.recordsUpdated > 0) {
    return run.recordsUpdated;
  }
  return undefined;
}

function detailLine(label: string, value?: string | number | null) {
  if (value == null || value === '') {
    return null;
  }
  return (
    <div className="panel-caption" key={label}>
      {label}: {value}
    </div>
  );
}

export function InventoryRunQueuePage() {
  const [inventoryRuns, setInventoryRuns] = React.useState<SyncRun[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');

  const refresh = React.useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const runRows = await api.listSyncRuns({ category: 'inventory', limit: 100 });
      setInventoryRuns(runRows.filter((run) => isInventoryRun(run)));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  React.useEffect(() => {
    if (!inventoryRuns.some((run) => isActiveRun(run.status))) {
      return undefined;
    }
    const intervalId = window.setInterval(() => {
      void refresh();
    }, 3000);
    return () => window.clearInterval(intervalId);
  }, [inventoryRuns, refresh]);

  const queueRows = React.useMemo(
    () => inventoryRuns.map((run) => ({ run, metadata: parseRunMetadata(run.metadataJson) })),
    [inventoryRuns]
  );

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>Inventory Run Queue</h3>
          <span className="panel-caption">
            One row per inventory ingestion run across host, application, and container sources.
          </span>
        </div>
        <div className="button-row">
          <button type="button" className="btn btn-secondary" disabled={loading} onClick={() => void refresh()}>
            {loading ? 'Refreshing...' : 'Refresh Queue'}
          </button>
        </div>
      </div>

      {error && <div className="notice error">{error}</div>}

      {queueRows.length === 0 ? (
        <div className="empty-state">
          <p>No inventory-source runs have been recorded yet.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <ResizableTable storageKey="inventory-run-queue-runs-table-widths">
            <thead>
              <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Assets</th>
                <th>Components</th>
                <th>Findings</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {queueRows.map(({ run, metadata }) => (
                <tr key={run.id}>
                  <td>
                    <div>{formatSyncType(run.syncType)}</div>
                    <div className="panel-caption">{formatSourceSystem(metadata.sourceSystem)}</div>
                  </td>
                  <td>
                    <span className={`status-pill ${runStatusClass(run.status)}`}>
                      {formatRunStatus(run.status)}
                    </span>
                    {isActiveRun(run.status) && run.queuePosition != null && (
                      <div className="panel-caption">{queueLabel(run)}</div>
                    )}
                  </td>
                  <td>{new Date(run.startedAt).toLocaleString()}</td>
                  <td>{humanDuration(run.startedAt, run.completedAt)}</td>
                  <td>{formatCount(readAssetsIngested(run, metadata))}</td>
                  <td>{formatCount(readComponentsIngested(run, metadata))}</td>
                  <td>{formatCount(readFindingsGenerated(run, metadata))}</td>
                  <td>
                    <details className="evidence-details">
                      <summary>Details</summary>
                      {detailLine('Trigger', metadata.triggerMode)}
                      {detailLine('Scope', metadata.scope)}
                      {detailLine('Stage', metadata.stage)}
                      {detailLine('Table', metadata.tableName)}
                      {detailLine('Assets discovered', metadata.assetsDiscovered)}
                      {detailLine('Assets ingested', metadata.assetsIngested)}
                      {detailLine('Assets failed', metadata.assetsFailed)}
                      {detailLine('Fetched', run.recordsFetched)}
                      {detailLine('Failed', run.recordsFailed ?? 0)}
                      {detailLine('Inserted', run.recordsInserted)}
                      {detailLine('Updated', run.recordsUpdated)}
                      {detailLine('Install rows', metadata.installRowsProcessed)}
                      {detailLine('Discovery rows', metadata.discoveryRowsProcessed)}
                      {detailLine('Unmatched discovery', metadata.unmatchedDiscoveryRows)}
                      {detailLine('Hosts created', metadata.ciCreated)}
                      {detailLine('Aliases created', metadata.ciAliasesCreated)}
                      {detailLine('Software created', metadata.softwareInstancesCreated)}
                      {detailLine('Software updated', metadata.softwareInstancesUpdated)}
                      {detailLine('Components created', metadata.inventoryComponentsCreated)}
                      {detailLine('Components updated', metadata.inventoryComponentsUpdated)}
                      {detailLine('Findings generated', metadata.findingsGenerated)}
                      {detailLine('Completed', run.completedAt ? new Date(run.completedAt).toLocaleString() : null)}
                      {detailLine('Message', metadata.message)}
                      {detailLine('Error', run.errorMessage)}
                    </details>
                  </td>
                </tr>
              ))}
            </tbody>
          </ResizableTable>
        </div>
      )}
    </section>
  );
}
