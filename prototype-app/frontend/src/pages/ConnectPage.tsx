import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { IngestionPage } from './IngestionPage';
import { SourcesPage } from './SourcesPage';
import { AssetsPage } from './AssetsPage';
import { IntegrationRunQueuePage } from './IntegrationRunQueuePage';
import { GithubPipelineManager } from '../components/GithubPipelineManager';
import { EolSourcePanel } from '../components/EolSourcePanel';
import { SccmConnectorPage } from './SccmConnectorPage';
import { VulnIntelConfigPage } from './VulnIntelConfigPage';
import { api } from '../api/client';
import type { VulnIntelSourcesSummary } from '../api/client';
import type { ServiceNowCmdbConfig, SccmCmdbConfig } from '../features/connect/types';

function timeAgo(iso?: string): string | null {
  if (!iso) return null;
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hr ago`;
  const days = Math.floor(hrs / 24);
  return `${days} day${days === 1 ? '' : 's'} ago`;
}

type ConnectorId =
  | 'sbom-endpoint'
  | 'sbom-github'
  | 'servicenow-cmdb'
  | 'sccm-cmdb'
  | 'nvd-api'
  | 'cisa-kev'
  | 'ghsa-feed'
  | 'microsoft-csaf-vex'
  | 'redhat-csaf-vex'
  | 'advisory-feed'
  | 'endoflife-date';

type ConnectView = 'sources' | 'integration-run-queue' | 'processing-jobs';

type ConnectorDefinition = {
  id: ConnectorId;
  name: string;
  summary: string;
  icon: string;
};

const CONNECT_SOURCE_QUERY_KEY = 'connectSource';
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
    id: 'sccm-cmdb',
    name: 'SCCM / MECM',
    summary: 'Ingest hardware asset and installed software inventory from Microsoft Endpoint Configuration Manager (SCCM/MECM) via direct SQL Server connection.',
    icon: '🖥️'
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
  'servicenow-cmdb',
  'sccm-cmdb'
];

function isConnectorId(value: string | null): value is ConnectorId {
  return CONNECTORS.some((connector) => connector.id === value);
}

function readConnectorFromSearch(searchParams: URLSearchParams): ConnectorId | null {
  const source = searchParams.get(CONNECT_SOURCE_QUERY_KEY);
  if (isConnectorId(source)) {
    return source;
  }
  return null;
}

type ConnectorDetailsProps = {
  connectorId: ConnectorId;
  vulnSummary?: VulnIntelSourcesSummary | null;
};

function ConnectorDetailContent({ connectorId, vulnSummary }: ConnectorDetailsProps) {
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
  if (
    connectorId === 'nvd-api' ||
    connectorId === 'cisa-kev' ||
    connectorId === 'ghsa-feed' ||
    connectorId === 'microsoft-csaf-vex' ||
    connectorId === 'redhat-csaf-vex' ||
    connectorId === 'advisory-feed'
  ) {
    return <VulnIntelConfigPage vulnSummary={vulnSummary} />;
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
  if (connectorId === 'sccm-cmdb') {
    return <SccmConnectorPage />;
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

type ConnectPageProps = {
  initialView?: ConnectView;
  onViewChange?: (view: ConnectView) => void;
};

export function ConnectPage({ initialView = 'sources', onViewChange }: ConnectPageProps = {}) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeView, setActiveView] = React.useState<ConnectView>(initialView);
  const [activeConnector, setActiveConnector] = React.useState<ConnectorId | null>(() => readConnectorFromSearch(searchParams));
  const [snConfig, setSnConfig] = React.useState<ServiceNowCmdbConfig | null>(null);
  const [sccmConfig, setSccmConfig] = React.useState<SccmCmdbConfig | null>(null);
  const [vulnSummary, setVulnSummary] = React.useState<VulnIntelSourcesSummary | null>(null);

  React.useEffect(() => {
    api.getServiceNowCmdbConfig().then(setSnConfig).catch(() => {});
    api.getSccmCmdbConfig().then(setSccmConfig).catch(() => {});
    api.getVulnIntelSourcesSummary().then(setVulnSummary).catch(() => {});
  }, []);

  React.useEffect(() => {
    setActiveView(initialView);
  }, [initialView]);

  React.useEffect(() => {
    setActiveConnector(readConnectorFromSearch(searchParams));
  }, [searchParams]);

  React.useEffect(() => {
    const nextParams = new URLSearchParams(searchParams);
    if (activeConnector) {
      nextParams.set(CONNECT_SOURCE_QUERY_KEY, activeConnector);
    } else {
      nextParams.delete(CONNECT_SOURCE_QUERY_KEY);
    }
    if (nextParams.toString() !== searchParams.toString()) {
      setSearchParams(nextParams, { replace: true });
    }
  }, [activeConnector, searchParams, setSearchParams]);

  React.useEffect(() => {
    if (!activeConnector) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setActiveConnector(null);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeConnector]);

  const vulnerabilityConnectors = CONNECTORS
    .filter((connector) => VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS.includes(connector.id));

  const inventoryConnectors = CONNECTORS
    .filter((connector) => INVENTORY_SOURCE_CONNECTOR_IDS.includes(connector.id));

  const visibleSections = [
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

  const selectedConnector = activeConnector ? CONNECTORS.find((connector) => connector.id === activeConnector) ?? null : null;

  return (
    <div className="page-grid">
      <div className="connect-filter-bar connect-filter-bar--standalone">
        {(['sources', 'integration-run-queue', 'processing-jobs'] as const).map((view) => (
          <button
            key={view}
            type="button"
            className={`connect-filter-btn${activeView === view ? ' active' : ''}`}
            onClick={() => {
              setActiveView(view);
              onViewChange?.(view);
              if (view !== 'sources') {
                setActiveConnector(null);
              }
            }}
          >
            {view === 'sources' && 'Sources'}
            {view === 'integration-run-queue' && 'Integration Run Queue'}
            {view === 'processing-jobs' && 'Processing Jobs'}
          </button>
        ))}
      </div>

      {activeView === 'sources' && !activeConnector && (
        <section className="panel connect-catalog-panel">
          <div className="connect-sections-layout">
            {visibleSections.map((section) => (
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
                      {section.connectors.map((connector) => {
                        // Map connector IDs to sync summary keys
                        const vulnKeyMap: Record<string, string> = {
                          'nvd-api': 'NVD',
                          'cisa-kev': 'KEV',
                          'ghsa-feed': 'GHSA',
                          'microsoft-csaf-vex': 'CSAF_MICROSOFT',
                          'redhat-csaf-vex': 'CSAF_REDHAT',
                          'advisory-feed': 'ADVISORY'
                        };
                        const vulnKey = vulnKeyMap[connector.id];
                        const vulnRun = vulnKey ? vulnSummary?.sources[vulnKey] : undefined;

                        const lastSyncAt =
                          connector.id === 'servicenow-cmdb' ? snConfig?.lastSyncAt :
                          connector.id === 'sccm-cmdb' ? sccmConfig?.lastSyncAt :
                          vulnRun?.completedAt ?? undefined;

                        const lastSync = timeAgo(lastSyncAt);
                        const runStatus = vulnRun?.status;
                        const isFailed = runStatus === 'failed';
                        const totalRecords = vulnRun ? (vulnRun.recordsInserted + vulnRun.recordsUpdated) : null;

                        const hasSynced =
                          connector.id === 'servicenow-cmdb' ? snConfig?.lastSyncAt != null :
                          connector.id === 'sccm-cmdb' ? sccmConfig?.lastSyncAt != null :
                          vulnRun != null && vulnRun.status !== 'never';

                        const dotClass = isFailed ? 'connect-source-dot--fail' :
                                         hasSynced ? 'connect-source-dot--ok' :
                                         'connect-source-dot--warn';

                        return (
                          <button
                            key={connector.id}
                            type="button"
                            className={`connect-source-card${activeConnector === connector.id ? ' connect-source-card--active' : ''}`}
                            onClick={() => setActiveConnector(connector.id)}
                          >
                            <div className="connect-source-icon" aria-hidden="true">{connector.icon}</div>
                            <div className="connect-source-body">
                              <div className="connect-source-name-row">
                                <span className="connect-source-name">{connector.name}</span>
                                <span className={`connect-source-dot ${dotClass}`} />
                              </div>
                              <div className="panel-caption">{connector.summary}</div>
                              {isFailed && lastSync && (
                                <div className="connect-source-lastsync connect-source-lastsync--fail">
                                  Failed · {lastSync}
                                </div>
                              )}
                              {!isFailed && lastSync && (
                                <div className="connect-source-lastsync">
                                  Last sync · {lastSync}
                                  {totalRecords !== null && totalRecords > 0 && ` · ${totalRecords.toLocaleString()} records`}
                                </div>
                              )}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              ))}
          </div>
        </section>
      )}

      {activeView === 'integration-run-queue' && <IntegrationRunQueuePage />}

      {activeView === 'processing-jobs' && (
        <SourcesPage
          focusSource="processing"
          title="Processing Jobs"
          caption="Internal maintenance and rebuild jobs such as persisted VEX repair and vendor rollout backfills."
        />
      )}

      {activeConnector && selectedConnector && (
        <section className="panel">
          <div className="connector-page-back-row">
            <button
              type="button"
              className="btn-link"
              onClick={() => setActiveConnector(null)}
            >
              ← Back to Sources
            </button>
            <span className="connector-page-title">{selectedConnector.name}</span>
          </div>
          <ConnectorDetailContent connectorId={activeConnector} vulnSummary={vulnSummary} />
        </section>
      )}
    </div>
  );
}
