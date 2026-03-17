import React from 'react';
import { api } from '../api/client';
import { ResizableTable } from '../components/ResizableTable';
import { EolBadge } from '../components/EolBadge';
import type { HostAssetDetail } from '../types';

export const HOST_ASSET_QUERY_KEY = 'hostAssetId';

type HostAssetDetailPageProps = {
  assetId?: string | null;
  onClose?: () => void;
};

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

export function readSelectedHostAssetId(): string | null {
  return new URLSearchParams(window.location.search).get(HOST_ASSET_QUERY_KEY);
}

export function updateSelectedHostAssetId(assetId: string | null): void {
  const url = new URL(window.location.href);
  if (assetId) {
    url.searchParams.set(HOST_ASSET_QUERY_KEY, assetId);
  } else {
    url.searchParams.delete(HOST_ASSET_QUERY_KEY);
  }
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

type HostDetailSectionsProps = {
  assetId: string | null;
  hostDetail: HostAssetDetail | null;
  loadingDetail: boolean;
};

function HostDetailSections({ assetId, hostDetail, loadingDetail }: HostDetailSectionsProps) {
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
      {hostDetail.aliases.length === 0 ? (
        <div className="empty-state"><p>No aliases were recorded for this host.</p></div>
      ) : (
        <div className="table-scroll">
          <ResizableTable storageKey="host-detail-aliases-table-widths">
            <thead>
              <tr>
                <th>Alias</th>
                <th>Source</th>
                <th>Confidence</th>
                <th>First Seen</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {hostDetail.aliases.map((alias) => (
                <tr key={alias.id}>
                  <td className="mono">{alias.aliasName}</td>
                  <td>{alias.sourceSystem}</td>
                  <td>{formatConfidence(alias.confidence)}</td>
                  <td>{formatTimestamp(alias.firstSeenAt)}</td>
                  <td>{formatTimestamp(alias.lastSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </ResizableTable>
        </div>
      )}

      <h4 className="section-title section-divider">Installed Software</h4>
      {hostDetail.software.length === 0 ? (
        <div className="empty-state"><p>No host software has been materialized for this host yet.</p></div>
      ) : (
        <div className="table-scroll">
          <ResizableTable storageKey="host-detail-software-table-widths">
            <thead>
              <tr>
                <th>Software</th>
                <th>Vendor</th>
                <th>Version</th>
                <th>Identity</th>
                <th>EOL Status</th>
                <th>Review Flags</th>
                <th>Observed</th>
              </tr>
            </thead>
            <tbody>
              {hostDetail.software.map((software) => {
                const flags = [
                  software.needsVersionReview ? 'Missing version' : null,
                  software.needsIdentityReview ? 'Unmapped identity' : null,
                  software.needsDiscoveryModelReview ? 'Discovery review' : null
                ].filter(Boolean);

                return (
                  <tr key={software.id}>
                    <td>
                      <div>{software.displayName}</div>
                      <div className="panel-caption mono">{software.normalizedPublisher}:{software.normalizedProduct}</div>
                    </td>
                    <td>{software.publisher ?? '-'}</td>
                    <td className="mono">{software.version ?? software.normalizedVersion ?? 'Needs review'}</td>
                    <td>
                      <div>{software.softwareIdentity ?? '-'}</div>
                      <div className="panel-caption mono">{software.cpe23 ?? '-'}</div>
                    </td>
                    <td>
                      <EolBadge
                        isEol={software.isEol}
                        daysRemaining={software.eolDaysRemaining}
                        eolDate={software.eolDate}
                      />
                    </td>
                    <td>
                      {flags.length === 0 ? (
                        <span className="panel-caption">Clear</span>
                      ) : (
                        <div className="host-flag-list">
                          {flags.map((flag) => (
                            <span key={flag} className="host-flag-chip">{flag}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td>{formatTimestamp(software.lastScanned ?? software.lastUsed ?? software.installDate)}</td>
                  </tr>
                );
              })}
            </tbody>
          </ResizableTable>
        </div>
      )}

      <h4 className="section-title section-divider">Host Findings</h4>
      {hostDetail.findings.length === 0 ? (
        <div className="empty-state"><p>No findings are currently attached to this host.</p></div>
      ) : (
        <div className="table-scroll">
          <ResizableTable storageKey="host-detail-findings-table-widths">
            <thead>
              <tr>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Decision</th>
                <th>Risk</th>
                <th>Last Observed</th>
              </tr>
            </thead>
            <tbody>
              {hostDetail.findings.map((finding) => (
                <tr key={finding.id}>
                  <td className="mono">{finding.vulnerabilityId ?? '-'}</td>
                  <td>{finding.severity ?? '-'}</td>
                  <td><span className={statusClass(finding.status)}>{finding.status ?? 'UNKNOWN'}</span></td>
                  <td>{finding.decisionState ?? '-'}</td>
                  <td>{finding.riskScore?.toFixed(2) ?? '-'}</td>
                  <td>{formatTimestamp(finding.lastObservedAt)}</td>
                </tr>
              ))}
            </tbody>
          </ResizableTable>
        </div>
      )}
    </>
  );
}

export function HostAssetDetailPage({ assetId, onClose }: HostAssetDetailPageProps = {}) {
  const selectedAssetId = assetId ?? readSelectedHostAssetId();
  const [selectedHost, setSelectedHost] = React.useState<HostAssetDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = React.useState(false);
  const [error, setError] = React.useState('');

  const loadDetail = React.useCallback(async (resolvedAssetId: string) => {
    setLoadingDetail(true);
    setError('');
    try {
      const response = await api.getHostAssetDetail(resolvedAssetId);
      setSelectedHost(response);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
      setSelectedHost(null);
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  React.useEffect(() => {
    if (!selectedAssetId) {
      setSelectedHost(null);
      return;
    }
    void loadDetail(selectedAssetId);
  }, [loadDetail, selectedAssetId]);

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
            onClick={() => { if (selectedAssetId) void loadDetail(selectedAssetId); }}
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
        Host drilldown from <span className="mono">Inventory &gt; Hosts</span>. Use this view to inspect aliases, installed software evidence, review blockers, and findings for a single host.
      </div>

      {error && <div className="notice error">{error}</div>}
      <HostDetailSections assetId={selectedAssetId} hostDetail={selectedHost} loadingDetail={loadingDetail} />
    </section>
  );
}
