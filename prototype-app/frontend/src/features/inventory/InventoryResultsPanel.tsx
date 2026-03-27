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
import type { VulnerabilityIntelRecord } from '../vulnerability-intel/types';
import {
  buildHostReviewLabels,
  formatAssetType,
  formatInventorySourceSystem,
  formatSourceSystem
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
  vulnerabilityIntelRows: VulnerabilityIntelRecord[];
  vulnerabilityIntelPage: number;
  vulnerabilityIntelTotalPages: number;
  selectedVulnerabilityIntelId: string | null;
  onOpenVulnerabilityIntelDetail: (externalId: string) => void;
  onPreviousVulnerabilityIntelPage: () => void;
  onNextVulnerabilityIntelPage: () => void;
};

const VULNERABILITY_INTEL_COLUMNS: DataTableColumn[] = [
  { id: 'vulnerabilityId', label: 'Vulnerability ID', header: 'Vulnerability ID', initialSize: 160 },
  { id: 'description', label: 'Description', header: 'Description', initialSize: 280 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'cvss', label: 'CVSS', header: 'CVSS', initialSize: 100 },
  { id: 'epss', label: 'EPSS', header: 'EPSS', initialSize: 100 },
  { id: 'affectedPackages', label: 'Affected Packages', header: 'Affected Packages', initialSize: 240 },
  { id: 'primarySource', label: 'Primary Source', header: 'Primary Source', initialSize: 160 },
  { id: 'allSources', label: 'All Sources', header: 'All Sources', initialSize: 200 },
  { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 120 },
  { id: 'published', label: 'Published', header: 'Published', initialSize: 180 },
  { id: 'lastModified', label: 'Last Modified', header: 'Last Modified', initialSize: 180 }
];

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

function renderAffectedPackages(record: VulnerabilityIntelRecord): string {
  if (!record.affectedPackages || record.affectedPackages.length === 0) {
    return '-';
  }
  const summary = record.affectedPackages.slice(0, 3).map((pkg) => (
    pkg.packageName
      ? `${pkg.packageName}${pkg.ecosystem ? ` (${pkg.ecosystem})` : ''}`
      : pkg.cpe ?? '-'
  )).join(', ');
  return record.affectedPackages.length > 3
    ? `${summary} +${record.affectedPackages.length - 3} more`
    : summary;
}

function buildVulnerabilityIntelRows(
  rows: VulnerabilityIntelRecord[],
  selectedId: string | null,
  onOpenDetail: (externalId: string) => void
): DataTableRow[] {
  return rows.map((record) => ({
    id: record.id,
    rowProps: {
      className: `table-row-clickable ${selectedId === record.externalId ? 'table-row-selected' : ''}`,
      onClick: () => onOpenDetail(record.externalId),
      onKeyDown: (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onOpenDetail(record.externalId);
        }
      },
      tabIndex: 0,
      'aria-label': `Open vulnerability intelligence detail ${record.externalId}`
    },
    cells: {
      vulnerabilityId: {
        content: <span className="mono">{record.externalId}</span>
      },
      description: { content: record.descriptionSnippet || '-' },
      severity: { content: record.severity || '-' },
      cvss: { content: record.cvssScore ?? '-' },
      epss: { content: record.epssScore ?? '-' },
      affectedPackages: { content: renderAffectedPackages(record) },
      primarySource: { content: record.sources.length > 0 ? formatSourceSystem(record.sources[0]) : '-' },
      allSources: { content: record.sources.length > 0 ? record.sources.map(formatSourceSystem).join(', ') : '-' },
      openFindings: { content: record.openFindings },
      published: { content: formatDateTime(record.publishedAt) },
      lastModified: { content: formatDateTime(record.lastModifiedAt) }
    }
  }));
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

function VulnerabilityIntelTable({
  rows,
  loading,
  page,
  totalPages,
  selectedId,
  onOpenDetail,
  onPreviousPage,
  onNextPage
}: {
  rows: VulnerabilityIntelRecord[];
  loading: boolean;
  page: number;
  totalPages: number;
  selectedId: string | null;
  onOpenDetail: (externalId: string) => void;
  onPreviousPage: () => void;
  onNextPage: () => void;
}) {
  const tableRows = React.useMemo(
    () => buildVulnerabilityIntelRows(rows, selectedId, onOpenDetail),
    [onOpenDetail, rows, selectedId]
  );

  if (loading && rows.length === 0) {
    return <div className="notice">Loading vulnerability intelligence records...</div>;
  }

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        <p>
          No vulnerability intelligence records found. Run source sync from <span className="mono">Connect</span>.
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="table-scroll">
        <DataTable
          storageKey="inventory-vulnerability-intel-table-widths"
          columns={VULNERABILITY_INTEL_COLUMNS}
          rows={tableRows}
        />
      </div>
      <div className="pagination-row">
        <button
          type="button"
          className="btn btn-secondary"
          onClick={onPreviousPage}
          disabled={page <= 0 || loading}
        >
          Previous
        </button>
        <span className="panel-caption pagination-caption">
          Page {totalPages === 0 ? 0 : page + 1} of {Math.max(totalPages, 1)}
        </span>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={onNextPage}
          disabled={loading || totalPages === 0 || page + 1 >= totalPages}
        >
          Next
        </button>
      </div>
    </>
  );
}

function ComponentInventoryTable({
  selectedView,
  rows,
  loading,
  page,
  totalPages,
  selectedHostAssetId,
  onOpenHostDetail,
  onPreviousPage,
  onNextPage
}: {
  selectedView: InventoryViewKey;
  rows: InventoryComponentRecord[];
  loading: boolean;
  page: number;
  totalPages: number;
  selectedHostAssetId: string | null;
  onOpenHostDetail: (assetId: string) => void;
  onPreviousPage: () => void;
  onNextPage: () => void;
}) {
  const tableColumns = React.useMemo(
    () => COMPONENT_COLUMNS.filter((column) => selectedView === 'hosts' || column.id !== 'review'),
    [selectedView]
  );
  const tableRows = React.useMemo(
    () => buildComponentRows(selectedView, rows, selectedHostAssetId, onOpenHostDetail),
    [onOpenHostDetail, rows, selectedHostAssetId, selectedView]
  );

  if (loading && rows.length === 0) {
    return <div className="notice">Loading inventory records...</div>;
  }

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        <p>
          No inventory records found for this view. Connect an SBOM source from <span className="mono">Connect &gt; Inventory Sources</span>.
        </p>
      </div>
    );
  }

  return (
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
          onClick={onPreviousPage}
          disabled={page <= 0 || loading}
        >
          Previous
        </button>
        <span className="panel-caption pagination-caption">
          Page {totalPages === 0 ? 0 : page + 1} of {Math.max(totalPages, 1)}
        </span>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={onNextPage}
          disabled={loading || totalPages === 0 || page + 1 >= totalPages}
        >
          Next
        </button>
      </div>
    </>
  );
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
  onNextComponentPage,
  vulnerabilityIntelRows,
  vulnerabilityIntelPage,
  vulnerabilityIntelTotalPages,
  selectedVulnerabilityIntelId,
  onOpenVulnerabilityIntelDetail,
  onPreviousVulnerabilityIntelPage,
  onNextVulnerabilityIntelPage
}: Props) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>
          {selectedView === 'vulnerability-intelligence'
            ? 'Unified Vulnerability Records'
            : 'Component Inventory Records'}
        </h3>
        {selectedView !== 'vulnerability-intelligence' && (
          <span className="panel-caption">
            Inventory records are normalized and persisted consistently across application, container-image, and host inventory views.
          </span>
        )}
      </div>

      {error && <div className="notice error">Failed to load inventory: {error}</div>}

      {selectedView === 'vulnerability-intelligence' ? (
        <VulnerabilityIntelTable
          rows={vulnerabilityIntelRows}
          loading={loading}
          page={vulnerabilityIntelPage}
          totalPages={vulnerabilityIntelTotalPages}
          selectedId={selectedVulnerabilityIntelId}
          onOpenDetail={onOpenVulnerabilityIntelDetail}
          onPreviousPage={onPreviousVulnerabilityIntelPage}
          onNextPage={onNextVulnerabilityIntelPage}
        />
      ) : (
        <ComponentInventoryTable
          selectedView={selectedView}
          rows={rows}
          loading={loading}
          page={componentPage}
          totalPages={componentTotalPages}
          selectedHostAssetId={selectedHostAssetId}
          onOpenHostDetail={onOpenHostDetail}
          onPreviousPage={onPreviousComponentPage}
          onNextPage={onNextComponentPage}
        />
      )}
    </section>
  );
}
