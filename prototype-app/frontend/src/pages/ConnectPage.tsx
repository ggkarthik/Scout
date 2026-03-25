import React from 'react';
import { IngestionPage } from './IngestionPage';
import { SourcesPage } from './SourcesPage';
import { AssetsPage } from './AssetsPage';
import { InventoryRunQueuePage } from './InventoryRunQueuePage';
import { GithubPipelineManager } from '../components/GithubPipelineManager';
import { EolSourcePanel } from '../components/EolSourcePanel';
import { readQueryParam, replaceBrowserQueryParams } from '../utils/queryState';

type ConnectorId =
  | 'sbom-endpoint'
  | 'sbom-github'
  | 'servicenow-cmdb'
  | 'nvd-api'
  | 'cisa-kev'
  | 'ghsa-feed'
  | 'microsoft-csaf-vex'
  | 'redhat-csaf-vex'
  | 'advisory-feed'
  | 'endoflife-date';

type CategoryFilter = 'all' | 'inventory' | 'vulnerability';
type ConnectView = 'sources' | 'inventory-run-queue' | 'vuln-intel-queue' | 'processing-jobs';

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
    id: 'sbom-endpoint',
    name: 'SBOM API Endpoint',
    summary: 'Pull SBOM JSON from authenticated API endpoints.',
    icon: '🌐'
  },
  {
    id: 'sbom-github',
    name: 'GitHub SBOM',
    summary: 'Run repository or GHCR SBOM ingestion and manage reusable GitHub ingestion pipelines.',
    icon: '🐙'
  },
  {
    id: 'servicenow-cmdb',
    name: 'ServiceNow CMDB',
    summary: 'Pull host inventory from ServiceNow Table APIs and review ingestion history in Connect.',
    icon: '🧾'
  },
  {
    id: 'nvd-api',
    name: 'NVD Vulnerability Feed',
    summary: '',
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
  },
  {
    id: 'endoflife-date',
    name: 'endoflife.date EOL Feed',
    summary: 'Run endoflife.date catalog, release, mapping, and denormalization jobs.',
    icon: '📅'
  }
];

const VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS: ConnectorId[] = [
  'nvd-api',
  'cisa-kev',
  'ghsa-feed',
  'microsoft-csaf-vex',
  'redhat-csaf-vex',
  'advisory-feed',
  'endoflife-date'
];

const INVENTORY_SOURCE_CONNECTOR_IDS: ConnectorId[] = [
  'sbom-endpoint',
  'sbom-github',
  'servicenow-cmdb'
];

function isConnectView(value: string | null): value is ConnectView {
  return value === 'sources' || value === 'inventory-run-queue' || value === 'vuln-intel-queue' || value === 'processing-jobs';
}

function readInitialConnectView(): ConnectView {
  const fromQuery = readQueryParam(CONNECT_VIEW_QUERY_KEY);
  if (fromQuery === 'github-pipelines') return 'sources';
  if (fromQuery === 'integration-queue') return 'vuln-intel-queue';
  if (fromQuery === 'inventory-run-queue') return 'inventory-run-queue';
  if (fromQuery === 'processing-jobs') return 'processing-jobs';
  return isConnectView(fromQuery) ? fromQuery : 'sources';
}

function isConnectorId(value: string | null): value is ConnectorId {
  return CONNECTORS.some((connector) => connector.id === value);
}

function readInitialConnector(): ConnectorId | null {
  const source = readQueryParam(CONNECT_SOURCE_QUERY_KEY);
  if (isConnectorId(source)) {
    return source;
  }
  if (readQueryParam(CONNECT_VIEW_QUERY_KEY) === 'github-pipelines') {
    return 'sbom-github';
  }
  return null;
}

function writeConnectQuery(connectorId: ConnectorId | null, view: ConnectView): void {
  replaceBrowserQueryParams({
    [CONNECT_SOURCE_QUERY_KEY]: connectorId,
    [CONNECT_VIEW_QUERY_KEY]: view
  });
}

type ConnectorDetailsProps = {
  connectorId: ConnectorId;
};

function ConnectorDetailContent({ connectorId }: ConnectorDetailsProps) {
  if (connectorId === 'sbom-endpoint') {
    return (
      <IngestionPage
        initialMode="endpoint"
        hideModeToggle
        title="SBOM API Endpoint Connector"
        caption="Configure endpoint URL/auth headers to fetch SBOM JSON."
      />
    );
  }
  if (connectorId === 'sbom-github') {
    return (
      <GithubPipelineManager
        title="GitHub SBOM Connector"
        caption="Use GitHub as the single anchor for repository SBOM and GHCR image ingestion, reusable pipelines, and ingestion evidence."
      />
    );
  }
  if (connectorId === 'nvd-api') {
    return (
        <SourcesPage
          focusSource="nvd"
          showQueue={false}
          hideHeader
          title="NVD Vulnerability Feed"
          caption="Trigger NVD synchronization. View run history in Vuln Intel Feed Queue."
        />
      );
  }
  if (connectorId === 'cisa-kev') {
    return (
        <SourcesPage
          focusSource="kev"
          showQueue={false}
          hideHeader
          title="CISA KEV Feed"
          caption="Trigger KEV ingestion. View run history in Vuln Intel Feed Queue."
        />
      );
  }
  if (connectorId === 'ghsa-feed') {
    return (
        <SourcesPage
          focusSource="ghsa"
          showQueue={false}
          hideHeader
          title="GitHub Advisory Database (GHSA)"
          caption="Trigger GHSA ingestion. View run history in Vuln Intel Feed Queue."
        />
      );
  }
  if (connectorId === 'microsoft-csaf-vex') {
    return (
        <SourcesPage
          focusSource="microsoft-csaf"
          showQueue={false}
          hideHeader
          title="Microsoft CSAF + VEX Feed"
          caption="Trigger Microsoft CSAF/VEX ingestion. View feed runs in Vuln Intel Feed Queue."
        />
      );
  }
  if (connectorId === 'redhat-csaf-vex') {
    return (
        <SourcesPage
          focusSource="redhat-csaf"
          showQueue={false}
          hideHeader
          title="Red Hat CSAF + VEX Feed"
          caption="Trigger Red Hat CSAF/VEX ingestion. View feed runs in Vuln Intel Feed Queue."
        />
      );
  }
  if (connectorId === 'advisory-feed') {
    return (
        <SourcesPage
          focusSource="advisories"
          showQueue={false}
          hideHeader
          title="Advisory Import Feed"
          caption="Seed/import advisory records. View run history in Vuln Intel Feed Queue."
        />
      );
  }
  if (connectorId === 'endoflife-date') {
    return (
      <EolSourcePanel
        title="endoflife.date EOL Feed"
        caption=""
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
  const [activeConnector, setActiveConnector] = React.useState<ConnectorId | null>(readInitialConnector);

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
            {activeView === 'sources' && 'Connect inventory and vulnerability sources. Click any source to open its configuration.'}
            {activeView === 'inventory-run-queue' && 'Shared inventory ingestion run history across host, container-image, and application inventory sources.'}
            {activeView === 'vuln-intel-queue' && 'Upstream vulnerability-feed ingestion history for NVD, KEV, GHSA, CSAF, and advisory sources.'}
            {activeView === 'processing-jobs' && 'Internal maintenance jobs like VEX repair, rollout backfills, and future recompute tasks.'}
          </span>
        </div>
      </section>

      <section className="panel">
        <div className="connect-filter-bar">
          {(['sources', 'inventory-run-queue', 'vuln-intel-queue', 'processing-jobs'] as const).map((view) => (
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
              {view === 'inventory-run-queue' && 'Inventory Run Queue'}
              {view === 'vuln-intel-queue' && 'Vuln Intel Feed Queue'}
              {view === 'processing-jobs' && 'Processing Jobs'}
            </button>
          ))}
        </div>
      </section>

      {activeView === 'sources' && (
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
      )}

      {activeView === 'inventory-run-queue' && <InventoryRunQueuePage />}

      {activeView === 'vuln-intel-queue' && (
        <SourcesPage
          focusSource="vuln-only"
          title="Vuln Intel Feed Queue"
          caption="External vulnerability-feed runs only: NVD, KEV, GHSA, CSAF, and advisory ingestion."
        />
      )}

      {activeView === 'processing-jobs' && (
        <SourcesPage
          focusSource="processing"
          title="Processing Jobs"
          caption="Internal maintenance and rebuild jobs such as persisted VEX repair and vendor rollout backfills."
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
