import React from 'react';
import { useNavigate } from 'react-router-dom';
import { pathForInventoryHostAsset } from '../app/routes';
import { useSoftwareIdentitiesQuery, useSoftwareIdentityDetailQuery } from '../features/software-identities/queries';
import { EolBadge } from '../components/EolBadge';
import type { SoftwareIdentitySummary } from '../features/software-identities/types';

const COL_SPAN = 7;

function formatDate(value?: string | null): string {
  if (!value) return '—';
  return value;
}

function eolSummaryLabel(identity: SoftwareIdentitySummary): string {
  if (identity.eolComponentCount > 0) return `${identity.eolComponentCount} EOL`;
  if (identity.nearEolComponentCount > 0) return `${identity.nearEolComponentCount} near EOL`;
  if (identity.unknownEolComponentCount > 0) return 'Unknown';
  return 'Supported';
}

function eolSummaryClass(identity: SoftwareIdentitySummary): string {
  if (identity.eolComponentCount > 0) return 'si-eol-summary si-eol-summary-risk';
  if (identity.nearEolComponentCount > 0) return 'si-eol-summary si-eol-summary-warn';
  return 'si-eol-summary';
}

function SummaryCard({ label, value, subtext }: { label: string; value: string; subtext: string }) {
  return (
    <article className="inventory-summary-card">
      <span className="inventory-summary-label">{label}</span>
      <strong className="inventory-summary-value">{value}</strong>
      <span className="inventory-summary-subtext">{subtext}</span>
    </article>
  );
}

// ─── Active panel state ────────────────────────────────────────────────────

type ActivePanel = {
  type: 'hosts' | 'cves';
  identityId: string;
  identityName: string;
  versionFilter?: string;
} | null;

// ─── Entity list panel ─────────────────────────────────────────────────────

function EntityListPanel({ panel, onClose }: { panel: NonNullable<ActivePanel>; onClose: () => void }) {
  const navigate = useNavigate();
  const detailQuery = useSoftwareIdentityDetailQuery(panel.identityId, true);
  const detail = detailQuery.data;

  const assets = React.useMemo(() => {
    if (!detail) return [];
    let list = detail.assets;
    if (panel.versionFilter) {
      list = list.filter(a => a.version === panel.versionFilter);
    }
    if (panel.type === 'cves') {
      list = list.filter(a => a.openVulnerabilityCount > 0);
      return [...list].sort((a, b) => b.openVulnerabilityCount - a.openVulnerabilityCount);
    }
    return list;
  }, [detail, panel.type, panel.versionFilter]);

  const versionSuffix = panel.versionFilter ? ` @ ${panel.versionFilter}` : '';
  const title = panel.type === 'hosts'
    ? `Hosts — ${panel.identityName}${versionSuffix}`
    : `CVE Exposure — ${panel.identityName}${versionSuffix}`;
  const subtitle = panel.type === 'hosts'
    ? `Enterprise hosts running this software identity.${panel.versionFilter ? ` Filtered to version ${panel.versionFilter}.` : ''}`
    : `Hosts with open CVE exposure.${panel.versionFilter ? ` Filtered to version ${panel.versionFilter}.` : ''}`;

  const cveColCount = panel.type === 'cves' ? COL_SPAN : COL_SPAN - 1;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel modal-panel-wide" onClick={e => e.stopPropagation()}>
        <div className="panel-header">
          <div>
            <h3>{title}</h3>
            <p className="panel-caption">{subtitle}</p>
          </div>
          <button
            type="button"
            className="modal-close-btn"
            aria-label="Close panel"
            onClick={onClose}
          >
            ×
          </button>
        </div>

        {detailQuery.isPending && !detail && (
          <div className="empty-state"><p>Loading…</p></div>
        )}

        {detail && (
          <div className="inventory-table-shell si-panel-table-shell">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Version</th>
                  <th>Type</th>
                  {panel.type === 'cves' && <th>Open CVEs</th>}
                  <th>Open Findings</th>
                  <th>EOL Status</th>
                  <th>EOL Date</th>
                </tr>
              </thead>
              <tbody>
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={cveColCount}>
                      <div className="empty-state">
                        <p>No {panel.type === 'cves' ? 'CVE exposure' : 'hosts'} found
                          {panel.versionFilter ? ` for version ${panel.versionFilter}` : ''}.
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : assets.map(asset => (
                  <tr
                    key={asset.componentId}
                    className="inventory-table-row-clickable"
                    onClick={() => navigate(pathForInventoryHostAsset(asset.assetId, '/inventory/software-identities'))}
                  >
                    <td>
                      <div className="inventory-primary-text">{asset.assetName}</div>
                      <div className="panel-caption mono">{asset.assetIdentifier}</div>
                    </td>
                    <td><span className="mono">{asset.version || '—'}</span></td>
                    <td>{asset.assetType || '—'}</td>
                    {panel.type === 'cves' && (
                      <td>
                        <span className="si-cve-count-pill">{asset.openVulnerabilityCount}</span>
                      </td>
                    )}
                    <td>{asset.openFindingCount}</td>
                    <td>
                      <EolBadge
                        isEol={asset.isEol}
                        daysRemaining={asset.eolDaysRemaining}
                        eolDate={asset.eolDate}
                      />
                    </td>
                    <td className="mono panel-caption">{formatDate(asset.eolDate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Expanded version rows ─────────────────────────────────────────────────

type ExpandedVersionRowsProps = {
  identityId: string;
  vendor?: string;
  onHostsClick: (version?: string) => void;
  onCvesClick: (version?: string) => void;
};

function ExpandedVersionRows({ identityId, vendor, onHostsClick, onCvesClick }: ExpandedVersionRowsProps) {
  const detailQuery = useSoftwareIdentityDetailQuery(identityId, true);
  const detail = detailQuery.data;

  if (detailQuery.isPending && !detail) {
    return (
      <tr>
        <td colSpan={COL_SPAN} className="si-version-state-row">
          Loading versions…
        </td>
      </tr>
    );
  }

  if (!detail?.versions.length) {
    return (
      <tr>
        <td colSpan={COL_SPAN} className="si-version-state-row">
          No version data available.
        </td>
      </tr>
    );
  }

  return (
    <>
      {detail.versions.map((v, i) => (
        <tr key={`${v.version}-${i}`} className="si-version-row">
          <td>
            <span className="si-version-indent">↳</span>
          </td>
          <td>
            <span className="mono si-version-tag">{v.version || '(unknown)'}</span>
          </td>
          <td className="panel-caption">{vendor || '—'}</td>
          <td>
            {v.assetCount > 0 ? (
              <button
                type="button"
                className="si-count-link"
                onClick={e => { e.stopPropagation(); onHostsClick(v.version); }}
              >
                {v.assetCount.toLocaleString()}
              </button>
            ) : (
              <span className="panel-caption">0</span>
            )}
          </td>
          <td>
            {v.openVulnerabilityCount > 0 ? (
              <button
                type="button"
                className="si-count-link si-count-link-cve"
                onClick={e => { e.stopPropagation(); onCvesClick(v.version); }}
              >
                {v.openVulnerabilityCount.toLocaleString()}
              </button>
            ) : (
              <span className="panel-caption">0</span>
            )}
          </td>
          <td className="panel-caption">{v.openFindingCount}</td>
          <td>
            <div className="si-eol-cell">
              <EolBadge isEol={v.isEol} daysRemaining={v.eolDaysRemaining} eolDate={v.eolDate} />
              <div className="si-eol-dates">
                {v.eolDate && (
                  <span className="panel-caption">
                    EOL: <span className="mono">{v.eolDate}</span>
                  </span>
                )}
                {v.supportEndDate && (
                  <span className="panel-caption">
                    EOS: <span className="mono">{v.supportEndDate}</span>
                  </span>
                )}
              </div>
            </div>
          </td>
        </tr>
      ))}
    </>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────

export function SoftwareIdentitiesPage() {
  const [query, setQuery] = React.useState('');
  const [expandedIds, setExpandedIds] = React.useState<Set<string>>(new Set());
  const [activePanel, setActivePanel] = React.useState<ActivePanel>(null);

  const identitiesQuery = useSoftwareIdentitiesQuery({
    page: 0,
    size: 250,
    query: query.trim() || undefined,
    assetType: ['HOST']
  });

  const identities = React.useMemo(() => (
    (identitiesQuery.data?.content ?? [])
      .filter(identity => identity.assetCount > 0)
      .sort((a, b) => {
        if (b.openVulnerabilityCount !== a.openVulnerabilityCount) return b.openVulnerabilityCount - a.openVulnerabilityCount;
        if (b.assetCount !== a.assetCount) return b.assetCount - a.assetCount;
        return a.displayName.localeCompare(b.displayName);
      })
  ), [identitiesQuery.data?.content]);

  const totalHosts = React.useMemo(
    () => identities.reduce((sum, i) => sum + i.assetCount, 0),
    [identities]
  );
  const totalOpenCves = React.useMemo(
    () => identities.reduce((sum, i) => sum + i.openVulnerabilityCount, 0),
    [identities]
  );
  const totalOpenFindings = React.useMemo(
    () => identities.reduce((sum, i) => sum + i.openFindingCount, 0),
    [identities]
  );

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const openHostsPanel = (identityId: string, identityName: string, versionFilter?: string) => {
    setActivePanel({ type: 'hosts', identityId, identityName, versionFilter });
  };

  const openCvesPanel = (identityId: string, identityName: string, versionFilter?: string) => {
    setActivePanel({ type: 'cves', identityId, identityName, versionFilter });
  };

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
        <SummaryCard
          label="Software Identities"
          value={identities.length.toLocaleString()}
          subtext="Deployed third-party software correlated to hosts"
        />
        <SummaryCard
          label="Host Deployments"
          value={totalHosts.toLocaleString()}
          subtext="Total host-to-software deployment relationships"
        />
        <SummaryCard
          label="Open CVEs"
          value={totalOpenCves.toLocaleString()}
          subtext="Applicable CVEs across deployed software identities"
        />
        <SummaryCard
          label="Open Findings"
          value={totalOpenFindings.toLocaleString()}
          subtext="Findings currently tied to deployed software"
        />
      </div>

      <div className="inventory-toolbar">
        <div className="inventory-search-row inventory-search-row-single">
          <label className="inventory-search-field">
            <span className="panel-caption">Search software, vendor, product, or identity…</span>
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="SQL Server, WebLogic, JBoss, Palo Alto, Fortinet…"
            />
          </label>
        </div>
      </div>

      {errorMessage && (
        <div className="inventory-error-banner">
          Failed to load software identities: {errorMessage}
        </div>
      )}

      <div className="inventory-section-card">
        <div className="inventory-section-header">
          <div>
            <h2>Deployed software identities</h2>
            <p className="panel-caption">
              Click a row to expand version-level breakdown with EOL and CVE exposure.
            </p>
          </div>
          <span className="panel-caption">{identities.length.toLocaleString()} identities</span>
        </div>

        {loading ? (
          <div className="empty-state"><p>Loading software identities…</p></div>
        ) : (
          <div className="inventory-table-shell">
            <table className="inventory-table si-identities-table">
              <thead>
                <tr>
                  <th>Software</th>
                  <th>Version</th>
                  <th>Vendor</th>
                  <th>Hosts</th>
                  <th>CVEs</th>
                  <th>Open Findings</th>
                  <th>EOL</th>
                </tr>
              </thead>
              <tbody>
                {identities.length === 0 ? (
                  <tr>
                    <td colSpan={COL_SPAN}>
                      <div className="empty-state">
                        <p>No deployed software identities matched the current search.</p>
                      </div>
                    </td>
                  </tr>
                ) : identities.map(identity => {
                  const isExpanded = expandedIds.has(identity.id);
                  return (
                    <React.Fragment key={identity.id}>
                      <tr
                        className={`inventory-table-row-clickable si-identity-row${isExpanded ? ' si-identity-row-expanded' : ''}`}
                        onClick={() => toggleExpand(identity.id)}
                      >
                        <td>
                          <div className="si-identity-name-cell">
                            <span className={`si-expand-toggle${isExpanded ? ' si-expand-toggle-open' : ''}`}>▶</span>
                            <div>
                              <div className="inventory-primary-text">{identity.displayName}</div>
                              <div className="panel-caption mono">{identity.normalizedKey}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className="si-version-count">
                            {identity.versionCount.toLocaleString()} version{identity.versionCount !== 1 ? 's' : ''}
                          </span>
                        </td>
                        <td>{identity.vendor || identity.product || '—'}</td>
                        <td>
                          {identity.assetCount > 0 ? (
                            <button
                              type="button"
                              className="si-count-link"
                              onClick={e => {
                                e.stopPropagation();
                                openHostsPanel(identity.id, identity.displayName);
                              }}
                            >
                              {identity.assetCount.toLocaleString()}
                            </button>
                          ) : (
                            <span className="panel-caption">0</span>
                          )}
                        </td>
                        <td>
                          {identity.openVulnerabilityCount > 0 ? (
                            <button
                              type="button"
                              className="si-count-link si-count-link-cve"
                              onClick={e => {
                                e.stopPropagation();
                                openCvesPanel(identity.id, identity.displayName);
                              }}
                            >
                              {identity.openVulnerabilityCount.toLocaleString()}
                            </button>
                          ) : (
                            <span className="panel-caption">0</span>
                          )}
                        </td>
                        <td>{identity.openFindingCount.toLocaleString()}</td>
                        <td>
                          <span className={eolSummaryClass(identity)}>
                            {eolSummaryLabel(identity)}
                          </span>
                        </td>
                      </tr>

                      {isExpanded && (
                        <ExpandedVersionRows
                          identityId={identity.id}
                          vendor={identity.vendor || identity.product}
                          onHostsClick={vf => openHostsPanel(identity.id, identity.displayName, vf)}
                          onCvesClick={vf => openCvesPanel(identity.id, identity.displayName, vf)}
                        />
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {activePanel && (
        <EntityListPanel
          panel={activePanel}
          onClose={() => setActivePanel(null)}
        />
      )}
    </section>
  );
}
