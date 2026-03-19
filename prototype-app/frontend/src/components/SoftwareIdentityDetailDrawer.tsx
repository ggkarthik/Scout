import React from 'react';
import { api } from '../api/client';
import { SoftwareIdentityDetail } from '../types';
import { EolBadge } from './EolBadge';

type Props = {
  softwareIdentityId: string;
  refreshNonce?: number;
  onClose: () => void;
};

function formatInstant(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function joinValues(values: string[]): string {
  return values.length === 0 ? '-' : values.join(', ');
}

function lifecycleLabel(detail: SoftwareIdentityDetail): string {
  if (detail.eolComponentCount > 0) {
    return `${detail.eolComponentCount} EOL`;
  }
  if (detail.nearEolComponentCount > 0) {
    return `${detail.nearEolComponentCount} near EOL`;
  }
  if (detail.unknownEolComponentCount > 0) {
    return `${detail.unknownEolComponentCount} unknown`;
  }
  return 'Supported';
}

export function SoftwareIdentityDetailDrawer({ softwareIdentityId, refreshNonce = 0, onClose }: Props) {
  const [detail, setDetail] = React.useState<SoftwareIdentityDetail | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let active = true;
    setDetail(null);
    setError(null);
    api.getSoftwareIdentityDetail(softwareIdentityId)
      .then((response) => {
        if (active) {
          setDetail(response);
        }
      })
      .catch((e) => {
        if (active) {
          setError(e instanceof Error ? e.message : String(e));
        }
      });
    return () => {
      active = false;
    };
  }, [refreshNonce, softwareIdentityId]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel modal-panel-wide" onClick={(event) => event.stopPropagation()}>
        <div className="panel-header">
          <div>
            <h3>Software Identity Detail</h3>
            {detail && (
              <>
                <div>{detail.displayName}</div>
                <div className="panel-caption mono">{detail.canonicalKey}</div>
              </>
            )}
          </div>
          <div className="button-row">
            {detail && detail.eolSlug && <span className="panel-caption mono">EOL: {detail.eolSlug}</span>}
            <button
              type="button"
              className="modal-close-btn"
              onClick={onClose}
              aria-label="Close software identity detail"
            >
              x
            </button>
          </div>
        </div>

        {error && <div className="notice error">Unable to load software identity detail: {error}</div>}
        {!detail && !error && <div className="notice">Loading software identity detail...</div>}

        {detail && (
          <>
            <div className="host-summary-grid">
              <div className="summary-card">
                <strong>Identity</strong>
                <span>{detail.displayName}</span>
                <span className="panel-caption">{detail.vendor || '-'} / {detail.product || '-'}</span>
              </div>
              <div className="summary-card">
                <strong>Identifiers</strong>
                <span className="mono">{detail.purl || '-'}</span>
                <span className="panel-caption mono">{detail.cpe23 || '-'}</span>
              </div>
              <div className="summary-card">
                <strong>Footprint</strong>
                <span>{detail.assetCount} assets</span>
                <span className="panel-caption">{detail.componentCount} components · {detail.versionCount} versions</span>
              </div>
              <div className="summary-card">
                <strong>Exposure</strong>
                <span>{detail.openVulnerabilityCount} open CVEs</span>
                <span className="panel-caption">{detail.openFindingCount} open findings</span>
              </div>
              <div className="summary-card">
                <strong>Lifecycle</strong>
                <span>{lifecycleLabel(detail)}</span>
                <span className="panel-caption">Mapped slug: {detail.eolSlug || 'None'}</span>
                <span className="panel-caption">
                  {detail.needsEolMapping
                    ? 'Needs EOL mapping review'
                    : detail.mappingConfirmed
                      ? 'Manual override confirmed'
                      : 'Mapping resolved'}
                </span>
              </div>
            </div>

            <div className="software-identity-drawer-meta">
              <div className="software-identity-drawer-meta-item">
                <strong>Asset Types</strong>
                <span>{joinValues(detail.assetTypes)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Ecosystems</strong>
                <span>{joinValues(detail.ecosystems)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Sources</strong>
                <span>{joinValues(detail.sourceSystems)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Last Observed</strong>
                <span>{formatInstant(detail.lastObservedAt)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Normalized Key</strong>
                <span className="mono">{detail.normalizedKey}</span>
              </div>
            </div>

            <section className="software-identity-drawer-section">
              <div className="panel-header">
                <h4>Observed Versions</h4>
                <span className="panel-caption">{detail.versions.length} version rows</span>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Version</th>
                      <th>Lifecycle</th>
                      <th>Footprint</th>
                      <th>Open Exposure</th>
                      <th>Last Observed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.versions.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '24px 0' }}>
                          <span className="panel-caption">No version rows available.</span>
                        </td>
                      </tr>
                    ) : detail.versions.map((versionRow) => (
                      <tr key={versionRow.version}>
                        <td className="mono">{versionRow.version || '(unknown)'}</td>
                        <td>
                          <div className="software-identity-row-stack">
                            <EolBadge
                              isEol={versionRow.isEol}
                              daysRemaining={versionRow.eolDaysRemaining}
                              eolDate={versionRow.eolDate}
                            />
                            <span className="panel-caption mono">
                              {(versionRow.eolSlug || '-')}{versionRow.eolCycle ? ` / ${versionRow.eolCycle}` : ''}
                            </span>
                          </div>
                        </td>
                        <td>{versionRow.assetCount} assets · {versionRow.componentCount} components</td>
                        <td>{versionRow.openVulnerabilityCount} CVEs · {versionRow.openFindingCount} findings</td>
                        <td>{formatInstant(versionRow.lastObservedAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="software-identity-drawer-section">
              <div className="panel-header">
                <h4>Linked Inventory Components</h4>
                <span className="panel-caption">{detail.assets.length} rows shown</span>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Asset</th>
                      <th>Component</th>
                      <th>Source</th>
                      <th>Lifecycle</th>
                      <th>Open Exposure</th>
                      <th>Last Observed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.assets.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', padding: '24px 0' }}>
                          <span className="panel-caption">No linked inventory components available.</span>
                        </td>
                      </tr>
                    ) : detail.assets.map((assetRow) => (
                      <tr key={assetRow.componentId}>
                        <td>
                          <div>{assetRow.assetName}</div>
                          <div className="panel-caption mono">{assetRow.assetIdentifier}</div>
                          <div className="panel-caption">{assetRow.assetType}</div>
                        </td>
                        <td>
                          <div>{assetRow.packageName}</div>
                          <div className="panel-caption mono">
                            {(assetRow.ecosystem || '-')}{assetRow.version ? `@${assetRow.version}` : ''}
                          </div>
                        </td>
                        <td>{assetRow.sourceSystem || '-'}</td>
                        <td>
                          <div className="software-identity-row-stack">
                            <EolBadge
                              isEol={assetRow.isEol}
                              daysRemaining={assetRow.eolDaysRemaining}
                              eolDate={assetRow.eolDate}
                            />
                            <span className="panel-caption mono">
                              {(assetRow.eolSlug || '-')}{assetRow.eolCycle ? ` / ${assetRow.eolCycle}` : ''}
                            </span>
                          </div>
                        </td>
                        <td>{assetRow.openVulnerabilityCount} CVEs · {assetRow.openFindingCount} findings</td>
                        <td>{formatInstant(assetRow.lastObservedAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
