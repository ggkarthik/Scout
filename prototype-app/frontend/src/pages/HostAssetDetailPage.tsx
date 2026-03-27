import React from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { EolBadge } from '../components/EolBadge';
import type { HostAssetDetail } from '../features/inventory/api-types';
import { useHostAssetDetailQuery } from '../features/inventory/queries';
import { readHostAssetIdFromSearch } from '../features/inventory/searchState';

type HostAssetDetailPageProps = {
  assetId?: string | null;
  onClose?: () => void;
};

const ALIAS_COLUMNS: DataTableColumn[] = [
  { id: 'alias', label: 'Alias', header: 'Alias', initialSize: 220 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 160 },
  { id: 'confidence', label: 'Confidence', header: 'Confidence', initialSize: 120 },
  { id: 'firstSeen', label: 'First Seen', header: 'First Seen', initialSize: 180 },
  { id: 'lastSeen', label: 'Last Seen', header: 'Last Seen', initialSize: 180 }
];

const SOFTWARE_COLUMNS: DataTableColumn[] = [
  { id: 'software', label: 'Software', header: 'Software', initialSize: 220 },
  { id: 'vendor', label: 'Vendor', header: 'Vendor', initialSize: 160 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 160 },
  { id: 'identity', label: 'Identity', header: 'Identity', initialSize: 220 },
  { id: 'eolStatus', label: 'EOL Status', header: 'EOL Status', initialSize: 160 },
  { id: 'reviewFlags', label: 'Review Flags', header: 'Review Flags', initialSize: 220 },
  { id: 'observed', label: 'Observed', header: 'Observed', initialSize: 180 }
];

const FINDING_COLUMNS: DataTableColumn[] = [
  { id: 'vulnerability', label: 'Vulnerability', header: 'Vulnerability', initialSize: 180 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 140 },
  { id: 'decision', label: 'Decision', header: 'Decision', initialSize: 140 },
  { id: 'risk', label: 'Risk', header: 'Risk', initialSize: 120 },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 }
];

function formatTimestamp(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatConfidence(value?: number): string {
  if (value == null) {
    return '-';
  }
  return `${Math.round(value * 100)}%`;
}

function statusClass(value?: string): string {
  return `status-pill status-${(value ?? 'unknown').toLowerCase().replace(/_/g, '-')}`;
}

function buildAliasRows(aliases: HostAssetDetail['aliases']): DataTableRow[] {
  return aliases.map((alias) => ({
    id: alias.id,
    cells: {
      alias: { content: alias.aliasName, props: { className: 'mono' } },
      source: { content: alias.sourceSystem },
      confidence: { content: formatConfidence(alias.confidence) },
      firstSeen: { content: formatTimestamp(alias.firstSeenAt) },
      lastSeen: { content: formatTimestamp(alias.lastSeenAt) }
    }
  }));
}

function buildSoftwareRows(softwareRows: HostAssetDetail['software']): DataTableRow[] {
  return softwareRows.map((software) => {
    const flags = [
      software.needsVersionReview ? 'Missing version' : null,
      software.needsIdentityReview ? 'Unmapped identity' : null,
      software.needsDiscoveryModelReview ? 'Discovery review' : null
    ].filter((value): value is string => Boolean(value));

    return {
      id: software.id,
      cells: {
        software: {
          content: (
            <>
              <div>{software.displayName}</div>
              <div className="panel-caption mono">
                {software.normalizedPublisher}:{software.normalizedProduct}
              </div>
            </>
          )
        },
        vendor: { content: software.publisher ?? '-' },
        version: {
          content: software.version ?? software.normalizedVersion ?? 'Needs review',
          props: { className: 'mono' }
        },
        identity: {
          content: (
            <>
              <div>{software.softwareIdentity ?? '-'}</div>
              <div className="panel-caption mono">{software.cpe23 ?? '-'}</div>
            </>
          )
        },
        eolStatus: {
          content: (
            <EolBadge
              isEol={software.isEol}
              daysRemaining={software.eolDaysRemaining}
              eolDate={software.eolDate}
            />
          )
        },
        reviewFlags: {
          content: flags.length === 0 ? (
            <span className="panel-caption">Clear</span>
          ) : (
            <div className="host-flag-list">
              {flags.map((flag) => (
                <span key={flag} className="host-flag-chip">{flag}</span>
              ))}
            </div>
          )
        },
        observed: { content: formatTimestamp(software.lastScanned ?? software.lastUsed ?? software.installDate) }
      }
    };
  });
}

function buildFindingRows(findings: HostAssetDetail['findings']): DataTableRow[] {
  return findings.map((finding) => ({
    id: finding.id,
    cells: {
      vulnerability: {
        content: finding.vulnerabilityId ?? '-',
        props: { className: 'mono' }
      },
      severity: { content: finding.severity ?? '-' },
      status: {
        content: <span className={statusClass(finding.status)}>{finding.status ?? 'UNKNOWN'}</span>
      },
      decision: { content: finding.decisionState ?? '-' },
      risk: { content: finding.riskScore?.toFixed(2) ?? '-' },
      lastObserved: { content: formatTimestamp(finding.lastObservedAt) }
    }
  }));
}

type HostDetailSectionsProps = {
  assetId: string | null;
  hostDetail: HostAssetDetail | null;
  loadingDetail: boolean;
};

function HostDetailSections({ assetId, hostDetail, loadingDetail }: HostDetailSectionsProps) {
  const aliasRows = React.useMemo(() => buildAliasRows(hostDetail?.aliases ?? []), [hostDetail]);
  const softwareRows = React.useMemo(() => buildSoftwareRows(hostDetail?.software ?? []), [hostDetail]);
  const findingRows = React.useMemo(() => buildFindingRows(hostDetail?.findings ?? []), [hostDetail]);

  if (!assetId) {
    return <div className="empty-state"><p>Select a host to load its detail.</p></div>;
  }
  if (loadingDetail) {
    return <div className="empty-state"><p>Loading host detail...</p></div>;
  }
  if (!hostDetail) {
    return <div className="empty-state"><p>No host detail is available for the selected asset.</p></div>;
  }

  return (
    <>
      <div className="host-summary-grid">
        <div className="summary-card">
          <strong>Host</strong>
          <span>{hostDetail.host.name}</span>
          <span className="panel-caption mono">{hostDetail.host.identifier}</span>
        </div>
        <div className="summary-card">
          <strong>System ID</strong>
          <span className="mono">{hostDetail.host.sysId}</span>
        </div>
        <div className="summary-card">
          <strong>Criticality</strong>
          <span>{hostDetail.host.businessCriticality ?? '-'}</span>
        </div>
        <div className="summary-card">
          <strong>Environment</strong>
          <span>{hostDetail.host.environment ?? '-'}</span>
        </div>
        <div className="summary-card">
          <strong>Open Findings</strong>
          <span>{hostDetail.host.openFindingCount}</span>
        </div>
        <div className="summary-card">
          <strong>Needs Review</strong>
          <span>{hostDetail.host.unresolvedReviewCount}</span>
        </div>
      </div>

      <h4 className="section-title section-divider">Host Aliases</h4>
      {aliasRows.length === 0 ? (
        <div className="empty-state"><p>No aliases were recorded for this host.</p></div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey="host-detail-aliases-table-widths"
            columns={ALIAS_COLUMNS}
            rows={aliasRows}
          />
        </div>
      )}

      <h4 className="section-title section-divider">Installed Software</h4>
      {softwareRows.length === 0 ? (
        <div className="empty-state"><p>No host software has been materialized for this host yet.</p></div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey="host-detail-software-table-widths"
            columns={SOFTWARE_COLUMNS}
            rows={softwareRows}
          />
        </div>
      )}

      <h4 className="section-title section-divider">Host Findings</h4>
      {findingRows.length === 0 ? (
        <div className="empty-state"><p>No findings are currently attached to this host.</p></div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey="host-detail-findings-table-widths"
            columns={FINDING_COLUMNS}
            rows={findingRows}
          />
        </div>
      )}
    </>
  );
}

export function HostAssetDetailPage({ assetId, onClose }: HostAssetDetailPageProps = {}) {
  const [searchParams] = useSearchParams();
  const selectedAssetId = assetId ?? readHostAssetIdFromSearch(searchParams);
  const hostDetailQuery = useHostAssetDetailQuery(selectedAssetId);
  const selectedHost = hostDetailQuery.data ?? null;
  const loadingDetail = hostDetailQuery.isLoading || hostDetailQuery.isFetching;
  const error = hostDetailQuery.error instanceof Error ? hostDetailQuery.error.message : '';

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>{selectedHost?.host.name ?? 'Host Detail'}</h3>
          <span className="panel-caption">
            {selectedHost
              ? `${selectedHost.host.identifier} · ${selectedHost.host.sysId}`
              : 'Review aliases, installed software evidence, and findings for the selected host.'}
          </span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => { if (selectedAssetId) void hostDetailQuery.refetch(); }}
            disabled={loadingDetail || !selectedAssetId}
          >
            {loadingDetail ? 'Refreshing...' : 'Refresh Host'}
          </button>
          {onClose && (
            <button
              type="button"
              className="modal-close-btn"
              onClick={onClose}
              aria-label="Close host detail"
            >
              x
            </button>
          )}
        </div>
      </div>

      <div className="inline-note">
        Host drilldown from <span className="mono">Inventory &gt; Hosts</span>. Use this view to inspect aliases, installed
        software evidence, review blockers, and findings for a single host.
      </div>

      {error && <div className="notice error">{error}</div>}
      <HostDetailSections assetId={selectedAssetId} hostDetail={selectedHost} loadingDetail={loadingDetail} />
    </section>
  );
}
