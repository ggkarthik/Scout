import React from 'react';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { useSyncRunsQuery } from '../features/connect/queries';
import type { SyncRun } from '../features/connect/types';

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

const INVENTORY_RUN_COLUMNS: DataTableColumn[] = [
  { id: 'type', label: 'Type', header: 'Type', initialSize: 220 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 160 },
  { id: 'started', label: 'Started', header: 'Started', initialSize: 180 },
  { id: 'duration', label: 'Duration', header: 'Duration', initialSize: 140 },
  { id: 'assets', label: 'Assets', header: 'Assets', initialSize: 100 },
  { id: 'components', label: 'Components', header: 'Components', initialSize: 120 },
  { id: 'findings', label: 'Findings', header: 'Findings', initialSize: 100 },
  { id: 'details', label: 'Details', header: 'Details', initialSize: 320 }
];

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

function readAssetsIngested(metadata: InventoryRunMetadata): number | undefined {
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

function buildRunRows(runs: SyncRun[]): DataTableRow[] {
  return runs.map((run) => {
    const metadata = parseRunMetadata(run.metadataJson);

    return {
      id: run.id,
      cells: {
        type: {
          content: (
            <>
              <div>{formatSyncType(run.syncType)}</div>
              <div className="panel-caption">{formatSourceSystem(metadata.sourceSystem)}</div>
            </>
          )
        },
        status: {
          content: (
            <>
              <span className={`status-pill ${runStatusClass(run.status)}`}>
                {formatRunStatus(run.status)}
              </span>
              {isActiveRun(run.status) && run.queuePosition != null && (
                <div className="panel-caption">{queueLabel(run)}</div>
              )}
            </>
          )
        },
        started: { content: new Date(run.startedAt).toLocaleString() },
        duration: { content: humanDuration(run.startedAt, run.completedAt) },
        assets: { content: formatCount(readAssetsIngested(metadata)) },
        components: { content: formatCount(readComponentsIngested(run, metadata)) },
        findings: { content: formatCount(readFindingsGenerated(run, metadata)) },
        details: {
          content: (
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
          )
        }
      }
    };
  });
}

export function InventoryRunQueuePage() {
  const inventoryRunsQuery = useSyncRunsQuery({ category: 'inventory', limit: 100 });
  const inventoryRuns = React.useMemo(
    () => (inventoryRunsQuery.data ?? []).filter((run) => isInventoryRun(run)),
    [inventoryRunsQuery.data]
  );
  const loading = inventoryRunsQuery.isPending && !inventoryRunsQuery.data;
  const refreshing = inventoryRunsQuery.isFetching;
  const error = inventoryRunsQuery.error instanceof Error ? inventoryRunsQuery.error.message : '';
  const queueRows = React.useMemo(() => buildRunRows(inventoryRuns), [inventoryRuns]);

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
          <button
            type="button"
            className="btn btn-secondary"
            disabled={refreshing}
            onClick={() => void inventoryRunsQuery.refetch()}
          >
            {refreshing ? 'Refreshing...' : 'Refresh Queue'}
          </button>
        </div>
      </div>

      {error && <div className="notice error">{error}</div>}

      {loading ? (
        <div className="notice">Loading inventory-source runs...</div>
      ) : queueRows.length === 0 ? (
        <div className="empty-state">
          <p>No inventory-source runs have been recorded yet.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey="inventory-run-queue-runs-table-widths"
            columns={INVENTORY_RUN_COLUMNS}
            rows={queueRows}
          />
        </div>
      )}
    </section>
  );
}
