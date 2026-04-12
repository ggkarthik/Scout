import React from 'react';
import { useNavigate } from 'react-router-dom';
import { pathForInventoryHostAsset } from '../app/routes';
import { useSoftwareIdentitiesQuery, useSoftwareIdentityDetailQuery } from '../features/software-identities/queries';

function formatTimestamp(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatLabel(value?: string): string {
  if (!value) {
    return '-';
  }
  return value
    .replace(/[_/:-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function SummaryCard({
  label,
  value,
  subtext
}: {
  label: string;
  value: string;
  subtext: string;
}) {
  return (
    <article className="inventory-summary-card">
      <span className="inventory-summary-label">{label}</span>
      <strong className="inventory-summary-value">{value}</strong>
      <span className="inventory-summary-subtext">{subtext}</span>
    </article>
  );
}

export function SoftwareIdentitiesPage() {
  const navigate = useNavigate();
  const [query, setQuery] = React.useState('');
  const [selectedIdentityId, setSelectedIdentityId] = React.useState<string | null>(null);

  const identitiesQuery = useSoftwareIdentitiesQuery({
    page: 0,
    size: 250,
    query: query.trim() || undefined,
    assetType: ['HOST']
  });

  const identities = React.useMemo(() => (
    (identitiesQuery.data?.content ?? [])
      .filter((identity) => identity.assetCount > 0)
      .sort((left, right) => {
        if (right.openVulnerabilityCount !== left.openVulnerabilityCount) {
          return right.openVulnerabilityCount - left.openVulnerabilityCount;
        }
        if (right.assetCount !== left.assetCount) {
          return right.assetCount - left.assetCount;
        }
        return left.displayName.localeCompare(right.displayName);
      })
  ), [identitiesQuery.data?.content]);

  React.useEffect(() => {
    if (!selectedIdentityId && identities.length > 0) {
      setSelectedIdentityId(identities[0].id);
    }
    if (selectedIdentityId && !identities.some((identity) => identity.id === selectedIdentityId)) {
      setSelectedIdentityId(identities[0]?.id ?? null);
    }
  }, [identities, selectedIdentityId]);

  const selectedIdentity = React.useMemo(
    () => identities.find((identity) => identity.id === selectedIdentityId) ?? null,
    [identities, selectedIdentityId]
  );

  const detailQuery = useSoftwareIdentityDetailQuery(selectedIdentityId, Boolean(selectedIdentityId));
  const detail = detailQuery.data;

  const totalHosts = React.useMemo(
    () => identities.reduce((sum, identity) => sum + identity.assetCount, 0),
    [identities]
  );
  const totalOpenCves = React.useMemo(
    () => identities.reduce((sum, identity) => sum + identity.openVulnerabilityCount, 0),
    [identities]
  );
  const totalOpenFindings = React.useMemo(
    () => identities.reduce((sum, identity) => sum + identity.openFindingCount, 0),
    [identities]
  );

  const loading = identitiesQuery.isPending && identities.length === 0;
  const errorMessage = identitiesQuery.error instanceof Error ? identitiesQuery.error.message : null;

  return (
    <section className="inventory-page-shell">
      <header className="inventory-page-header">
        <div>
          <h1>Software identities</h1>
          <p className="panel-caption">
            Third-party software deployed on enterprise hosts, correlated to host inventory, CVEs, and findings.
          </p>
        </div>
        <div className="inventory-page-header-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => void identitiesQuery.refetch()}
          >
            Refresh
          </button>
        </div>
      </header>

      <div className="inventory-summary-grid">
        <SummaryCard label="Software Identities" value={identities.length.toLocaleString()} subtext="Deployed third-party software correlated to hosts" />
        <SummaryCard label="Host Deployments" value={totalHosts.toLocaleString()} subtext="Total host-to-software deployment relationships" />
        <SummaryCard label="Open CVEs" value={totalOpenCves.toLocaleString()} subtext="Applicable CVEs across deployed software identities" />
        <SummaryCard label="Open Findings" value={totalOpenFindings.toLocaleString()} subtext="Findings currently tied to deployed software" />
      </div>

      <div className="inventory-toolbar">
        <div className="inventory-search-row inventory-search-row-single">
          <label className="inventory-search-field">
            <span className="panel-caption">Search software, vendor, product, or identity…</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="SQL Server, WebLogic, JBoss, Palo Alto, Fortinet…"
            />
          </label>
        </div>
      </div>

      {errorMessage ? (
        <div className="inventory-error-banner">
          Failed to load software identities: {errorMessage}
        </div>
      ) : null}

      <div className="inventory-two-column-layout">
        <div className="inventory-section-card">
          <div className="inventory-section-header">
            <div>
              <h2>Deployed software identities</h2>
              <p className="panel-caption">Normalized software identities built from software deployed on hosts.</p>
            </div>
            <span className="panel-caption">{identities.length.toLocaleString()} identities</span>
          </div>

          {loading ? (
            <div className="empty-state"><p>Loading software identities…</p></div>
          ) : (
            <div className="inventory-table-shell">
              <table className="inventory-table">
                <thead>
                  <tr>
                    <th>Software</th>
                    <th>Vendor</th>
                    <th>Hosts</th>
                    <th>Versions</th>
                    <th>Open CVEs</th>
                    <th>Open Findings</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {identities.length === 0 ? (
                    <tr>
                      <td colSpan={7}>
                        <div className="empty-state"><p>No deployed software identities matched the current search.</p></div>
                      </td>
                    </tr>
                  ) : identities.map((identity) => (
                    <tr
                      key={identity.id}
                      className={`inventory-table-row-clickable ${selectedIdentityId === identity.id ? 'active' : ''}`}
                      onClick={() => setSelectedIdentityId(identity.id)}
                    >
                      <td>
                        <div className="inventory-primary-text">{identity.displayName}</div>
                        <div className="panel-caption mono">{identity.normalizedKey}</div>
                      </td>
                      <td>{identity.vendor || identity.product || '-'}</td>
                      <td>{identity.assetCount.toLocaleString()}</td>
                      <td>{identity.versionCount.toLocaleString()}</td>
                      <td>{identity.openVulnerabilityCount.toLocaleString()}</td>
                      <td>{identity.openFindingCount.toLocaleString()}</td>
                      <td>{formatTimestamp(identity.lastObservedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <aside className="inventory-section-card inventory-detail-card">
          <div className="inventory-section-header">
            <div>
              <h2>Identity detail</h2>
              <p className="panel-caption">
                Deployment context for the selected software identity across enterprise hosts.
              </p>
            </div>
          </div>

          {!selectedIdentity ? (
            <div className="empty-state"><p>Select a software identity to inspect its host deployments.</p></div>
          ) : detailQuery.isPending && !detail ? (
            <div className="empty-state"><p>Loading identity detail…</p></div>
          ) : !detail ? (
            <div className="empty-state"><p>Identity detail is not available.</p></div>
          ) : (
            <div className="inventory-detail-stack">
              <div className="inventory-detail-hero">
                <div>
                  <h3>{detail.displayName}</h3>
                  <div className="panel-caption mono">{detail.normalizedKey}</div>
                </div>
                <span className="status-pill status-active">{detail.assetCount} hosts</span>
              </div>

              <div className="inventory-detail-grid">
                <div className="inventory-detail-metric">
                  <span className="inventory-summary-label">Vendor</span>
                  <strong>{detail.vendor || '-'}</strong>
                </div>
                <div className="inventory-detail-metric">
                  <span className="inventory-summary-label">Product</span>
                  <strong>{detail.product || '-'}</strong>
                </div>
                <div className="inventory-detail-metric">
                  <span className="inventory-summary-label">Open CVEs</span>
                  <strong>{detail.openVulnerabilityCount.toLocaleString()}</strong>
                </div>
                <div className="inventory-detail-metric">
                  <span className="inventory-summary-label">Open Findings</span>
                  <strong>{detail.openFindingCount.toLocaleString()}</strong>
                </div>
              </div>

              <div className="inventory-inline-list">
                <span className="panel-caption">Observed versions</span>
                <div className="inventory-chip-row">
                  {detail.versions.slice(0, 6).map((version) => (
                    <span key={version.version} className="inventory-chip static">
                      {version.version || 'Unknown'}
                    </span>
                  ))}
                </div>
              </div>

              <div className="inventory-inline-list">
                <span className="panel-caption">Deployed hosts</span>
                <div className="inventory-detail-host-list">
                  {detail.assets.slice(0, 8).map((asset) => (
                    <button
                      key={asset.componentId}
                      type="button"
                      className="inventory-detail-host-item"
                      onClick={() => navigate(pathForInventoryHostAsset(asset.assetId, '/inventory/software-identities'))}
                    >
                      <strong>{asset.assetName}</strong>
                      <span className="panel-caption mono">{asset.assetIdentifier}</span>
                      <span className="panel-caption">
                        {asset.version || 'Unknown version'} · {formatLabel(asset.assetType)}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}
