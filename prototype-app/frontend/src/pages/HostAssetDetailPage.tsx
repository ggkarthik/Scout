import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
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

type HostDetailTab = 'software' | 'applicable-cves' | 'findings' | 'aliases';

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

const APPLICABLE_CVE_COLUMNS: DataTableColumn[] = [
  { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 180 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'cvss', label: 'CVSS', header: 'CVSS', initialSize: 100 },
  { id: 'epss', label: 'EPSS', header: 'EPSS', initialSize: 100 },
  { id: 'software', label: 'Matched Software', header: 'Matched Software', initialSize: 220 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 160 },
  { id: 'impact', label: 'Impact', header: 'Impact', initialSize: 140 },
  { id: 'evaluated', label: 'Last Evaluated', header: 'Last Evaluated', initialSize: 180 }
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

function formatCount(value?: number): string {
  return (value ?? 0).toLocaleString();
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

function formatPercent(value?: number): string {
  if (value == null) {
    return '-';
  }
  return `${(value * 100).toFixed(1)}%`;
}

function buildApplicableCveRows(applicableCves: HostAssetDetail['applicableCves']): DataTableRow[] {
  return applicableCves.map((cve) => ({
    id: cve.stateId,
    cells: {
      cve: {
        content: cve.externalId ?? '-',
        props: { className: 'mono' }
      },
      severity: { content: cve.severity ?? '-' },
      cvss: { content: cve.cvssScore?.toFixed(1) ?? '-' },
      epss: { content: formatPercent(cve.epssScore) },
      software: { content: cve.packageName ?? '-' },
      version: {
        content: cve.version ?? '-',
        props: { className: 'mono' }
      },
      impact: {
        content: <span className={statusClass(cve.impactState)}>{cve.impactState ?? 'UNKNOWN'}</span>
      },
      evaluated: { content: formatTimestamp(cve.lastEvaluatedAt) }
    }
  }));
}

type HostDetailSectionsProps = {
  assetId: string | null;
  hostDetail: HostAssetDetail | null;
  loadingDetail: boolean;
};

function HostDetailSections({ assetId, hostDetail, loadingDetail }: HostDetailSectionsProps) {
  const location = useLocation();
  const [activeTab, setActiveTab] = React.useState<HostDetailTab>('software');
  const aliasRows = React.useMemo(() => buildAliasRows(hostDetail?.aliases ?? []), [hostDetail]);
  const softwareRows = React.useMemo(() => buildSoftwareRows(hostDetail?.software ?? []), [hostDetail]);
  const findingRows = React.useMemo(() => buildFindingRows(hostDetail?.findings ?? []), [hostDetail]);
  const applicableCveRows = React.useMemo(() => buildApplicableCveRows(hostDetail?.applicableCves ?? []), [hostDetail]);

  React.useEffect(() => {
    if (!hostDetail || !location.hash) {
      return;
    }
    const targetId = location.hash.replace(/^#/, '');
    if (!targetId) {
      return;
    }
    if (targetId === 'applicable-cves') {
      setActiveTab('applicable-cves');
    } else if (targetId === 'host-findings') {
      setActiveTab('findings');
    }
    window.requestAnimationFrame(() => {
      document.getElementById(targetId)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }, [hostDetail, location.hash]);

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
      <div className="host-hero">
        <div className="host-hero-ident">
          <div className="host-hero-icon" aria-hidden="true">🖥</div>
          <div>
            <h2 className="host-hero-title">{hostDetail.host.name}</h2>
            <div className="host-hero-subtitle mono">{hostDetail.host.identifier}</div>
          </div>
        </div>
        <div className="host-hero-actions">
          <button type="button" className="btn btn-secondary">Refresh host</button>
          <button type="button" className="btn btn-secondary">Edit asset</button>
        </div>
      </div>

      <div className="host-summary-strip">
        <div className="host-stat-card">
          <span className="host-stat-label">Criticality</span>
          <span className="host-stat-pill host-stat-pill-warning">{hostDetail.host.businessCriticality ?? '-'}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Asset State</span>
          <span className="host-stat-pill host-stat-pill-success">{hostDetail.host.state ?? 'Active'}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Owner</span>
          <span className="host-stat-value">{hostDetail.host.ownerEmail ?? '-'}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Environment</span>
          <span className="host-stat-value">{hostDetail.host.environment ?? '—'}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Open Findings</span>
          <span className="host-stat-number host-stat-number-danger">{formatCount(hostDetail.host.openFindingCount)}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Needs Review</span>
          <span className="host-stat-number host-stat-number-warning">{formatCount(hostDetail.host.unresolvedReviewCount)}</span>
        </div>
      </div>

      <div className="host-detail-tabs" role="tablist" aria-label="Host detail sections">
        <button type="button" className={`host-detail-tab ${activeTab === 'software' ? 'active' : ''}`} onClick={() => setActiveTab('software')}>Installed software</button>
        <button type="button" className={`host-detail-tab ${activeTab === 'applicable-cves' ? 'active' : ''}`} onClick={() => setActiveTab('applicable-cves')}>Applicable CVEs</button>
        <button type="button" className={`host-detail-tab ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>Created findings</button>
        <button type="button" className={`host-detail-tab ${activeTab === 'aliases' ? 'active' : ''}`} onClick={() => setActiveTab('aliases')}>Host aliases</button>
      </div>

      <div className="host-detail-surface">
        {activeTab === 'aliases' ? (
          aliasRows.length === 0 ? (
            <div className="empty-state"><p>No aliases were recorded for this host.</p></div>
          ) : (
            <div className="table-scroll">
              <DataTable
                storageKey="host-detail-aliases-table-widths"
                columns={ALIAS_COLUMNS}
                rows={aliasRows}
              />
            </div>
          )
        ) : null}

        {activeTab === 'software' ? (
          softwareRows.length === 0 ? (
            <div className="empty-state"><p>No host software has been materialized for this host yet.</p></div>
          ) : (
            <div className="table-scroll">
              <DataTable
                storageKey="host-detail-software-table-widths"
                columns={SOFTWARE_COLUMNS}
                rows={softwareRows}
              />
            </div>
          )
        ) : null}

        {activeTab === 'applicable-cves' ? (
          applicableCveRows.length === 0 ? (
            <div id="applicable-cves" className="empty-state"><p>No applicable CVEs are currently correlated to this host.</p></div>
          ) : (
            <div id="applicable-cves" className="table-scroll">
              <DataTable
                storageKey="host-detail-applicable-cves-table-widths"
                columns={APPLICABLE_CVE_COLUMNS}
                rows={applicableCveRows}
              />
            </div>
          )
        ) : null}

        {activeTab === 'findings' ? (
          findingRows.length === 0 ? (
            <div id="host-findings" className="empty-state"><p>No findings are currently attached to this host.</p></div>
          ) : (
            <div id="host-findings" className="table-scroll">
              <DataTable
                storageKey="host-detail-findings-table-widths"
                columns={FINDING_COLUMNS}
                rows={findingRows}
              />
            </div>
          )
        ) : null}
      </div>
    </>
  );
}

export function HostAssetDetailPage({ assetId, onClose }: HostAssetDetailPageProps = {}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const selectedAssetId = assetId ?? readHostAssetIdFromSearch(searchParams);
  const returnTo = searchParams.get('returnTo')?.trim() || (typeof location.state === 'object' && location.state && 'returnTo' in location.state
    ? String((location.state as { returnTo?: string }).returnTo ?? '').trim()
    : '');
  const hostDetailQuery = useHostAssetDetailQuery(selectedAssetId);
  const selectedHost = hostDetailQuery.data ?? null;
  const loadingDetail = hostDetailQuery.isLoading || hostDetailQuery.isFetching;
  const error = hostDetailQuery.error instanceof Error ? hostDetailQuery.error.message : '';
  const handleClose = React.useCallback(() => {
    if (onClose) {
      onClose();
      return;
    }
    if (returnTo) {
      navigate(returnTo);
      return;
    }
    navigate(-1);
  }, [navigate, onClose, returnTo]);

  return (
    <section className="host-detail-page">
      {(onClose || returnTo) && (
        <div className="button-row host-detail-close-row">
          <button
            type="button"
            className="modal-close-btn"
            onClick={handleClose}
            aria-label="Close host detail"
          >
            ×
          </button>
        </div>
      )}
      {error && <div className="notice error">{error}</div>}
      <HostDetailSections assetId={selectedAssetId} hostDetail={selectedHost} loadingDetail={loadingDetail} />
    </section>
  );
}
