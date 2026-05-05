import React from 'react';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../../components/DataTable';
import { EolBadge } from '../../components/EolBadge';
import type {
  InventoryComponentRecord
} from './api-types';
import {
  buildHostReviewLabels,
  formatAssetType,
  formatInventorySourceSystem
} from './helpers';
import type { InventoryViewKey } from './types';

type Props = {
  selectedView: InventoryViewKey;
  error: string;
  loading: boolean;
  rows: InventoryComponentRecord[];
  componentPage: number;
  componentTotalPages: number;
  selectedHostAssetId: string | null;
  onOpenHostDetail: (assetId: string) => void;
  onPreviousComponentPage: () => void;
  onNextComponentPage: () => void;
};

const COMPONENT_COLUMNS: DataTableColumn[] = [
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 220 },
  { id: 'assetType', label: 'Asset Type', header: 'Asset Type', initialSize: 120 },
  { id: 'component', label: 'Component', header: 'Component', initialSize: 180 },
  { id: 'normalizedName', label: 'Normalized Name', header: 'Normalized Name', initialSize: 180 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 140 },
  { id: 'normalizedVersion', label: 'Normalized Version', header: 'Normalized Version', initialSize: 160 },
  { id: 'ecosystem', label: 'Ecosystem', header: 'Ecosystem', initialSize: 140 },
  { id: 'softwareIdentity', label: 'Software Identity', header: 'Software Identity', initialSize: 180 },
  { id: 'review', label: 'Review', header: 'Review', initialSize: 200 },
  { id: 'eolStatus', label: 'EOL Status', header: 'EOL Status', initialSize: 160 },
  { id: 'componentStatus', label: 'Component Status', header: 'Component Status', initialSize: 140 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 180 },
  { id: 'purl', label: 'PURL', header: 'PURL', initialSize: 220 },
  { id: 'uploaded', label: 'Uploaded', header: 'Uploaded', initialSize: 180 },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 }
];

function formatDateTime(value?: string): string {
  return value ? new Date(value).toLocaleString() : '-';
}

function buildComponentRows(
  selectedView: InventoryViewKey,
  rows: InventoryComponentRecord[],
  selectedHostAssetId: string | null,
  onOpenHostDetail: (assetId: string) => void
): DataTableRow[] {
  return rows.map((row) => ({
    id: row.id,
    rowProps: {
      className: selectedView === 'hosts' && row.assetId === selectedHostAssetId ? 'table-row-selected' : undefined
    },
    cells: {
      asset: {
        content: (
          <>
            {selectedView === 'hosts' ? (
              <button
                type="button"
                className="btn-link"
                onClick={() => onOpenHostDetail(row.assetId)}
              >
                {row.assetName}
              </button>
            ) : (
              <div>{row.assetName}</div>
            )}
            <div className="panel-caption mono">{row.assetIdentifier}</div>
            {selectedView === 'hosts' && (
              <div className="panel-caption">Open host detail</div>
            )}
          </>
        )
      },
      assetType: { content: formatAssetType(row.assetType) },
      component: { content: row.packageName },
      normalizedName: { content: row.normalizedName || '-', props: { className: 'mono' } },
      version: { content: row.version, props: { className: 'mono' } },
      normalizedVersion: { content: row.normalizedVersion || '-', props: { className: 'mono' } },
      ecosystem: { content: row.ecosystem || '-' },
      softwareIdentity: { content: row.softwareIdentity || '-' },
      review: {
        content: row.needsReview ? (
          <>
            <div className="panel-caption">
              {row.reviewItemCount} review item{row.reviewItemCount === 1 ? '' : 's'}
            </div>
            <div className="findings-inline-pill-row">
              {buildHostReviewLabels(row).map((label) => (
                <span key={`${row.id}-${label}`} className="status-pill status-in-progress">
                  {label}
                </span>
              ))}
            </div>
          </>
        ) : (
          <span className="status-pill status-suppressed">Clear</span>
        )
      },
      eolStatus: {
        content: (
          <EolBadge
            isEol={row.isEol}
            daysRemaining={row.eolDaysRemaining}
            eolDate={row.eolDate}
          />
        )
      },
      componentStatus: {
        content: (
          <span className={`status-pill ${row.componentStatus === 'ACTIVE' ? 'status-open' : 'status-auto_closed'}`}>
            {row.componentStatus}
          </span>
        )
      },
      source: {
        content: (
          <>
            <div>{row.sourceSystem ? formatInventorySourceSystem(row.sourceSystem) : '-'}</div>
            <div className="panel-caption">
              {row.sourceReference || row.sourceType || '-'}
            </div>
          </>
        )
      },
      purl: { content: row.purl || '-', props: { className: 'mono' } },
      uploaded: { content: formatDateTime(row.uploadedAt) },
      lastObserved: { content: formatDateTime(row.lastObservedAt) }
    }
  }));
}

export function InventoryResultsPanel({
  selectedView,
  error,
  loading,
  rows,
  componentPage,
  componentTotalPages,
  selectedHostAssetId,
  onOpenHostDetail,
  onPreviousComponentPage,
  onNextComponentPage
}: Props) {
  const tableColumns = React.useMemo(
    () => COMPONENT_COLUMNS.filter((column) => selectedView === 'hosts' || column.id !== 'review'),
    [selectedView]
  );
  const tableRows = React.useMemo(
    () => buildComponentRows(selectedView, rows, selectedHostAssetId, onOpenHostDetail),
    [onOpenHostDetail, rows, selectedHostAssetId, selectedView]
  );

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Component Inventory Records</h3>
        <span className="panel-caption">
          Inventory records are normalized and persisted consistently across application, container-image, and host inventory views.
        </span>
      </div>

      {error && <div className="notice error">Failed to load inventory: {error}</div>}

      {loading && rows.length === 0 ? (
        <div className="notice">Loading inventory records...</div>
      ) : rows.length === 0 ? (
        <div className="empty-state">
          <p>
            No inventory records found for this view. Connect an SBOM source from <span className="mono">Connect &gt; Inventory Sources</span>.
          </p>
        </div>
      ) : (
        <>
          <div className="table-scroll">
            <DataTable
              storageKey="inventory-components-table-widths"
              columns={tableColumns}
              rows={tableRows}
            />
          </div>
          <div className="pagination-row">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onPreviousComponentPage}
              disabled={componentPage <= 0 || loading}
            >
              Previous
            </button>
            <span className="panel-caption pagination-caption">
              Page {componentTotalPages === 0 ? 0 : componentPage + 1} of {Math.max(componentTotalPages, 1)}
            </span>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onNextComponentPage}
              disabled={loading || componentTotalPages === 0 || componentPage + 1 >= componentTotalPages}
            >
              Next
            </button>
          </div>
        </>
      )}
    </section>
  );
}
