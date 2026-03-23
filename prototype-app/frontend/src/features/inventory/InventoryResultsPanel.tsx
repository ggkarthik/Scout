import React from 'react';
import { ResizableTable } from '../../components/ResizableTable';
import { EolBadge } from '../../components/EolBadge';
import type {
  InventoryComponentRecord,
  VulnerabilityIntelRecord
} from '../../types';
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
        <ResizableTable storageKey="inventory-vulnerability-intel-table-widths">
          <thead>
            <tr>
              <th>Vulnerability ID</th>
              <th>Description</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>EPSS</th>
              <th>Affected Packages</th>
              <th>Primary Source</th>
              <th>All Sources</th>
              <th>Open Findings</th>
              <th>Published</th>
              <th>Last Modified</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((record) => (
              <tr
                key={record.id}
                className={`table-row-clickable ${selectedId === record.externalId ? 'table-row-selected' : ''}`}
                onClick={() => onOpenDetail(record.externalId)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    onOpenDetail(record.externalId);
                  }
                }}
                tabIndex={0}
                aria-label={`Open vulnerability intelligence detail ${record.externalId}`}
              >
                <td><span className="mono">{record.externalId}</span></td>
                <td>{record.descriptionSnippet || '-'}</td>
                <td>{record.severity || '-'}</td>
                <td>{record.cvssScore ?? '-'}</td>
                <td>{record.epssScore ?? '-'}</td>
                <td>{renderAffectedPackages(record)}</td>
                <td>{record.sources.length > 0 ? formatSourceSystem(record.sources[0]) : '-'}</td>
                <td>{record.sources.length > 0 ? record.sources.map(formatSourceSystem).join(', ') : '-'}</td>
                <td>{record.openFindings}</td>
                <td>{formatDateTime(record.publishedAt)}</td>
                <td>{formatDateTime(record.lastModifiedAt)}</td>
              </tr>
            ))}
          </tbody>
        </ResizableTable>
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
        <ResizableTable storageKey="inventory-components-table-widths">
          <thead>
            <tr>
              <th>Asset</th>
              <th>Asset Type</th>
              <th>Component</th>
              <th>Normalized Name</th>
              <th>Version</th>
              <th>Normalized Version</th>
              <th>Ecosystem</th>
              <th>Software Identity</th>
              {selectedView === 'hosts' && <th>Review</th>}
              <th>EOL Status</th>
              <th>Component Status</th>
              <th>Source</th>
              <th>PURL</th>
              <th>Uploaded</th>
              <th>Last Observed</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                className={selectedView === 'hosts' && row.assetId === selectedHostAssetId ? 'table-row-selected' : ''}
              >
                <td>
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
                </td>
                <td>{formatAssetType(row.assetType)}</td>
                <td>{row.packageName}</td>
                <td className="mono">{row.normalizedName || '-'}</td>
                <td className="mono">{row.version}</td>
                <td className="mono">{row.normalizedVersion || '-'}</td>
                <td>{row.ecosystem || '-'}</td>
                <td>{row.softwareIdentity || '-'}</td>
                {selectedView === 'hosts' && (
                  <td>
                    {row.needsReview ? (
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
                    )}
                  </td>
                )}
                <td>
                  <EolBadge
                    isEol={row.isEol}
                    daysRemaining={row.eolDaysRemaining}
                    eolDate={row.eolDate}
                  />
                </td>
                <td>
                  <span className={`status-pill ${row.componentStatus === 'ACTIVE' ? 'status-open' : 'status-auto_closed'}`}>
                    {row.componentStatus}
                  </span>
                </td>
                <td>
                  <div>{row.sourceSystem ? formatInventorySourceSystem(row.sourceSystem) : '-'}</div>
                  <div className="panel-caption">
                    {row.sourceReference || row.sourceType || '-'}
                  </div>
                </td>
                <td className="mono">{row.purl || '-'}</td>
                <td>{formatDateTime(row.uploadedAt)}</td>
                <td>{formatDateTime(row.lastObservedAt)}</td>
              </tr>
            ))}
          </tbody>
        </ResizableTable>
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
