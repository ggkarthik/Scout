import React from 'react';
import { IngestionPage, IngestionMode } from './IngestionPage';
import { SourcesPage } from './SourcesPage';
import { AssetsPage } from './AssetsPage';

type ConnectorId =
  | 'sbom-upload'
  | 'sbom-endpoint'
  | 'sbom-github'
  | 'servicenow-cmdb'
  | 'nvd-api'
  | 'cisa-kev'
  | 'ghsa-feed'
  | 'microsoft-csaf-vex'
  | 'redhat-csaf-vex'
  | 'advisory-feed';

type CategoryFilter = 'all' | 'inventory' | 'vulnerability';
type ConnectView = 'sources' | 'integration-queue';

type ConnectorDefinition = {
  id: ConnectorId;
  name: string;
  summary: string;
  icon: string;
};

const CONNECT_SOURCE_QUERY_KEY = 'connectSource';
const CONNECT_VIEW_QUERY_KEY = 'connectView';

const CONNECTORS: ConnectorDefinition[] = [
  {
    id: 'sbom-upload',
    name: 'SBOM File Upload',
    summary: 'Ingest CycloneDX/SPDX files from local uploads and persist evidence.',
    icon: '📄'
  },
  {
    id: 'sbom-endpoint',
    name: 'SBOM API Endpoint',
    summary: 'Pull SBOM JSON from authenticated API endpoints.',
    icon: '🌐'
  },
  {
    id: 'sbom-github',
    name: 'GitHub Generated SBOM',
    summary: 'Fetch `/dependency-graph/sbom` for a single repo or all repos in a GitHub account.',
    icon: '🐙'
  },
  {
    id: 'servicenow-cmdb',
    name: 'ServiceNow CMDB',
    summary: 'Sync asset ownership and context records from ServiceNow.',
    icon: '🧾'
  },
  {
    id: 'nvd-api',
    name: 'NVD Vulnerability Feed',
    summary: 'Synchronize CVE records and refresh normalized vulnerability intelligence.',
    icon: '🛡️'
  },
  {
    id: 'cisa-kev',
    name: 'CISA KEV Feed',
    summary: 'Ingest known-exploited vulnerabilities and update prioritization.',
    icon: '⚠️'
  },
  {
    id: 'ghsa-feed',
    name: 'GitHub Advisory Database (GHSA)',
    summary: 'Ingest GHSA advisories with package-version applicability for correlation.',
    icon: '🐙'
  },
  {
    id: 'microsoft-csaf-vex',
    name: 'Microsoft CSAF + VEX',
    summary: 'Ingest Microsoft CSAF advisories and VEX applicability data.',
    icon: '🪟'
  },
  {
    id: 'redhat-csaf-vex',
    name: 'Red Hat CSAF + VEX',
    summary: 'Ingest Red Hat CSAF advisories and VEX applicability data.',
    icon: '🎩'
  },
  {
    id: 'advisory-feed',
    name: 'Advisory Imports',
    summary: 'Import curated advisories for package and product mappings.',
    icon: '🧠'
  }
];

const VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS: ConnectorId[] = [
  'nvd-api',
  'cisa-kev',
  'ghsa-feed',
  'microsoft-csaf-vex',
  'redhat-csaf-vex',
  'advisory-feed'
];

const INVENTORY_SOURCE_CONNECTOR_IDS: ConnectorId[] = [
  'sbom-upload',
  'sbom-endpoint',
  'sbom-github',
  'servicenow-cmdb'
];

function isConnectView(value: string | null): value is ConnectView {
  return value === 'sources' || value === 'integration-queue';
}

function readInitialConnectView(): ConnectView {
  const fromQuery = new URLSearchParams(window.location.search).get(CONNECT_VIEW_QUERY_KEY);
  return isConnectView(fromQuery) ? fromQuery : 'sources';
}

function writeConnectQuery(connectorId: ConnectorId | null, view: ConnectView): void {
  const url = new URL(window.location.href);
  if (connectorId) {
    url.searchParams.set(CONNECT_SOURCE_QUERY_KEY, connectorId);
  } else {
    url.searchParams.delete(CONNECT_SOURCE_QUERY_KEY);
  }
  url.searchParams.set(CONNECT_VIEW_QUERY_KEY, view);
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

type ConnectorDetailsProps = {
  connectorId: ConnectorId;
};

function ConnectorDetailContent({ connectorId }: ConnectorDetailsProps) {
  if (connectorId === 'sbom-upload') {
    return (
      <IngestionPage
        initialMode={'upload' as IngestionMode}
        hideModeToggle
        title="SBOM File Upload Connector"
        caption="Upload CycloneDX/SPDX files to ingest software inventory."
      />
    );
  }
  if (connectorId === 'sbom-endpoint') {
    return (
      <IngestionPage
        initialMode={'endpoint' as IngestionMode}
        hideModeToggle
        title="SBOM API Endpoint Connector"
        caption="Configure endpoint URL/auth headers to fetch SBOM JSON."
      />
    );
  }
  if (connectorId === 'sbom-github') {
    return (
      <IngestionPage
        initialMode={'github' as IngestionMode}
        hideModeToggle
        title="GitHub Generated SBOM Connector"
        caption="Fetch GitHub-generated SBOMs across account repositories and preserve per-repo evidence."
      />
    );
  }
  if (connectorId === 'nvd-api') {
    return (
      <SourcesPage
        focusSource="nvd"
        title="NVD Vulnerability Feed"
        caption="Run NVD synchronization and monitor NVD-specific sync runs."
      />
    );
  }
  if (connectorId === 'cisa-kev') {
    return (
      <SourcesPage
        focusSource="kev"
        title="CISA KEV Feed"
        caption="Run KEV ingestion and track known-exploited vulnerability sync activity."
      />
    );
  }
  if (connectorId === 'ghsa-feed') {
    return (
      <SourcesPage
        focusSource="ghsa"
        title="GitHub Advisory Database (GHSA)"
        caption="Run GHSA ingestion and track advisory-package correlation coverage."
      />
    );
  }
  if (connectorId === 'microsoft-csaf-vex') {
    return (
      <SourcesPage
        focusSource="microsoft-csaf"
        title="Microsoft CSAF + VEX Feed"
        caption="Run Microsoft CSAF/VEX ingestion and track source-specific sync runs."
      />
    );
  }
  if (connectorId === 'redhat-csaf-vex') {
    return (
      <SourcesPage
        focusSource="redhat-csaf"
        title="Red Hat CSAF + VEX Feed"
        caption="Run Red Hat CSAF/VEX ingestion and track source-specific sync runs."
      />
    );
  }
  if (connectorId === 'advisory-feed') {
    return (
      <SourcesPage
        focusSource="advisories"
        title="Advisory Import Feed"
        caption="Seed/import advisory records and maintain normalized vulnerability intelligence."
      />
    );
  }
  if (connectorId === 'servicenow-cmdb') {
    return <AssetsPage />;
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Connector Setup</h3>
        <span className="panel-caption">This connector detail page is reserved for Phase 2 integration.</span>
      </div>
      <div className="empty-state">
        <p>Connector scaffolding is ready. Detailed authentication, test connection, and scheduling controls will be added here.</p>
      </div>
    </section>
  );
}

export function ConnectPage() {
  const [activeView, setActiveView] = React.useState<ConnectView>(readInitialConnectView);
  const [categoryFilter, setCategoryFilter] = React.useState<CategoryFilter>('all');
  const [search, setSearch] = React.useState('');
  const [activeConnector, setActiveConnector] = React.useState<ConnectorId | null>(null);

  React.useEffect(() => {
    writeConnectQuery(activeConnector, activeView);
  }, [activeConnector, activeView]);

  React.useEffect(() => {
    if (!activeConnector) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setActiveConnector(null);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeConnector]);

  const query = search.trim().toLowerCase();
  const matchesSearch = (connector: ConnectorDefinition): boolean => {
    if (!query) {
      return true;
    }
    return (
      connector.name.toLowerCase().includes(query)
      || connector.summary.toLowerCase().includes(query)
    );
  };

  const vulnerabilityConnectors = CONNECTORS
    .filter((connector) => VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS.includes(connector.id))
    .filter(matchesSearch);

  const inventoryConnectors = CONNECTORS
    .filter((connector) => INVENTORY_SOURCE_CONNECTOR_IDS.includes(connector.id))
    .filter(matchesSearch);

  const allSections = [
    {
      key: 'inventory' as const,
      title: 'Inventory Sources',
      connectors: inventoryConnectors,
      caption: 'SBOM, CMDB, cloud and platform integrations that ingest asset/component inventory.'
    },
    {
      key: 'vulnerability' as const,
      title: 'Vulnerability Intelligence Sources',
      connectors: vulnerabilityConnectors,
      caption: 'NVD, KEV, GHSA, CSAF/VEX and advisory feeds that normalize into central CVE intelligence.'
    }
  ];

  const visibleSections = categoryFilter === 'all'
    ? allSections
    : allSections.filter((s) => s.key === categoryFilter);

  const totalVisible = visibleSections.reduce((sum, section) => sum + section.connectors.length, 0);

  const selectedConnector = activeConnector ? CONNECTORS.find((connector) => connector.id === activeConnector) ?? null : null;

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Connect</h3>
          <span className="panel-caption">
            {activeView === 'sources'
              ? 'Connect inventory and vulnerability sources. Click any source to open its configuration.'
              : 'Monitor vulnerability intelligence ingestion jobs and the shared integration queue.'}
          </span>
        </div>
      </section>

      <section className="panel">
        <div className="connect-filter-bar">
          {(['sources', 'integration-queue'] as const).map((view) => (
            <button
              key={view}
              type="button"
              className={`connect-filter-btn${activeView === view ? ' active' : ''}`}
              onClick={() => {
                setActiveView(view);
                if (view !== 'sources') {
                  setActiveConnector(null);
                }
              }}
            >
              {view === 'sources' && 'Sources'}
              {view === 'integration-queue' && 'Integration Run Queue'}
            </button>
          ))}
        </div>
      </section>

      {activeView === 'sources' ? (
        <section className="panel connect-catalog-panel">
          <div className="connect-search-row">
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search sources..."
              aria-label="Search sources"
            />
          </div>

          <div className="connect-filter-bar">
            {(['all', 'inventory', 'vulnerability'] as const).map((filter) => (
              <button
                key={filter}
                type="button"
                className={`connect-filter-btn${categoryFilter === filter ? ' active' : ''}`}
                onClick={() => setCategoryFilter(filter)}
              >
                {filter === 'all' && 'All'}
                {filter === 'inventory' && <>Inventory Sources <strong>{inventoryConnectors.length}</strong></>}
                {filter === 'vulnerability' && <>Vulnerability Intelligence <strong>{vulnerabilityConnectors.length}</strong></>}
              </button>
            ))}
          </div>

          <div className="connect-sections-layout">
            {totalVisible === 0 ? (
              <div className="empty-state">
                <p>No sources match the current search.</p>
              </div>
            ) : (
              visibleSections.map((section) => (
                <div key={section.key} className="connect-source-section">
                  <div className="connect-source-section-head">
                    <h4>{section.title}</h4>
                    <span className="panel-caption">{section.caption}</span>
                  </div>
                  {section.connectors.length === 0 ? (
                    <div className="empty-state">
                      <p>No sources in this section match the search.</p>
                    </div>
                  ) : (
                    <div className="connect-card-grid">
                      {section.connectors.map((connector) => (
                        <button
                          key={connector.id}
                          type="button"
                          className={`connect-source-card${activeConnector === connector.id ? ' connect-source-card--active' : ''}`}
                          onClick={() => setActiveConnector(connector.id)}
                        >
                          <div className="connect-source-icon" aria-hidden="true">{connector.icon}</div>
                          <div>
                            <div className="connect-source-name">{connector.name}</div>
                            <div className="panel-caption">{connector.summary}</div>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </section>
      ) : (
        <SourcesPage
          focusSource="all"
          title="Integration Queue"
          caption="NVD, KEV, GHSA, and CSAF/VEX ingestion jobs are processed in a shared queue."
        />
      )}

      {activeConnector && selectedConnector && (
        <div
          className="modal-overlay"
          onClick={(e) => { if (e.target === e.currentTarget) setActiveConnector(null); }}
          role="dialog"
          aria-modal="true"
          aria-label={selectedConnector.name}
        >
          <div className="modal-panel modal-panel-wide">
            <div className="connector-drawer-header">
              <div className="connector-drawer-title">
                <span className="connect-source-icon" aria-hidden="true">{selectedConnector.icon}</span>
                <div>
                  <h3>{selectedConnector.name}</h3>
                  <span className="panel-caption">{selectedConnector.summary}</span>
                </div>
              </div>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setActiveConnector(null)}
                aria-label="Close connector setup"
              >
                ✕
              </button>
            </div>
            <ConnectorDetailContent connectorId={activeConnector} />
          </div>
        </div>
      )}
    </div>
  );
}
