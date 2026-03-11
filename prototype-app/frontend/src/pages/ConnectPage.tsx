import React from 'react';
import { IngestionPage, IngestionMode } from './IngestionPage';
import { SourcesPage } from './SourcesPage';
import { AssetsPage } from './AssetsPage';
import { GithubPipelineManager } from '../components/GithubPipelineManager';
import { api } from '../api/client';
import { SbomUploadEvidence, SyncRun } from '../types';
import { ResizableTable } from '../components/ResizableTable';

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) return 'N/A';
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function parseEvidenceJson(value?: string): string {
  if (!value || !value.trim()) return '{}';
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function uploadStatusClass(value: string): string {
  return `status-${value.toLowerCase().replace('_', '-')}`;
}

function humanDuration(startedAt: string, completedAt?: string): string {
  if (!completedAt) return 'In progress';
  const seconds = Math.round((new Date(completedAt).getTime() - new Date(startedAt).getTime()) / 1000);
  if (Number.isNaN(seconds) || seconds < 0) return 'n/a';
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function isGithubRunActive(status: string): boolean {
  const v = status.trim().toUpperCase();
  return v === 'RUNNING' || v === 'STARTED' || v === 'QUEUED';
}

function queueLabel(run: SyncRun): string {
  if (!isGithubRunActive(run.status) || run.queuePosition == null) return '-';
  return run.queuePosition === 1 ? 'Running now' : `#${run.queuePosition}`;
}

function InventoryRunQueue() {
  const [uploads, setUploads] = React.useState<SbomUploadEvidence[]>([]);
  const [githubRuns, setGithubRuns] = React.useState<SyncRun[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');

  const refresh = React.useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [uploadRows, runRows] = await Promise.all([
        api.listSbomUploads(),
        api.listSyncRuns()
      ]);
      setUploads(uploadRows);
      setGithubRuns(runRows.filter((r) => r.syncType.toUpperCase().includes('GITHUB_')));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { void refresh(); }, [refresh]);

  React.useEffect(() => {
    if (!githubRuns.some((r) => isGithubRunActive(r.status))) return undefined;
    const id = window.setInterval(() => { void refresh(); }, 3000);
    return () => window.clearInterval(id);
  }, [githubRuns, refresh]);

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Inventory Run Queue</h3>
        <span className="panel-caption">SBOM upload evidence and GitHub ingestion run history across all inventory sources.</span>
      </div>
      <div className="button-row section-actions">
        <button type="button" className="btn btn-secondary" disabled={loading} onClick={() => void refresh()}>
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>
      {error && <div className="notice error">{error}</div>}

      <h4 className="section-title section-divider">SBOM Upload Evidence</h4>
      {uploads.length === 0 ? (
        <div className="empty-state"><p>No SBOM uploads yet. Upload a file or fetch from an endpoint to build evidence history.</p></div>
      ) : (
        <div className="table-scroll">
          <ResizableTable storageKey="inv-queue-uploads-table-widths">
            <thead>
              <tr>
                <th>Uploaded</th>
                <th>Status</th>
                <th>Asset</th>
                <th>Source</th>
                <th>Format</th>
                <th>Size</th>
                <th>Components</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {uploads.map((upload) => (
                <tr key={upload.id}>
                  <td>{new Date(upload.uploadedAt).toLocaleString()}</td>
                  <td>
                    <span className={`status-pill ${uploadStatusClass(upload.status)}`}>
                      {upload.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td>
                    <div>{upload.assetName}</div>
                    <div className="panel-caption mono">{upload.assetIdentifier}</div>
                  </td>
                  <td>
                    <div>{upload.ingestionSourceType ?? 'UNKNOWN'}</div>
                    <div className="panel-caption">{upload.sourceReference ?? upload.originalFilename}</div>
                  </td>
                  <td>{upload.format}</td>
                  <td>{formatBytes(upload.contentLengthBytes)}</td>
                  <td>{upload.componentCount ?? 'N/A'}</td>
                  <td>
                    <details className="evidence-details">
                      <summary>View</summary>
                      <pre>{parseEvidenceJson(upload.evidenceJson)}</pre>
                    </details>
                  </td>
                </tr>
              ))}
            </tbody>
          </ResizableTable>
        </div>
      )}

      <h4 className="section-title section-divider">GitHub Ingestion Runs</h4>
      {githubRuns.length === 0 ? (
        <div className="empty-state"><p>No GitHub ingestion runs yet. Trigger a GitHub repository or GHCR ingestion to see run history here.</p></div>
      ) : (
        <div className="table-scroll">
          <ResizableTable storageKey="inv-queue-github-runs-table-widths">
            <thead>
              <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Queue</th>
                <th>Fetched</th>
                <th>Inserted</th>
                <th>Updated</th>
                <th>Failed</th>
                <th>Started</th>
                <th>Completed</th>
                <th>Duration</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {githubRuns.map((run) => (
                <tr key={run.id}>
                  <td>{run.syncType}</td>
                  <td>
                    <span className={`status-pill ${isGithubRunActive(run.status) ? 'status-open' : 'status-resolved'}`}>
                      {run.status}
                    </span>
                  </td>
                  <td>{queueLabel(run)}</td>
                  <td>{run.recordsFetched}</td>
                  <td>{run.recordsInserted}</td>
                  <td>{run.recordsUpdated}</td>
                  <td>{run.recordsFailed ?? 0}</td>
                  <td>{new Date(run.startedAt).toLocaleString()}</td>
                  <td>{run.completedAt ? new Date(run.completedAt).toLocaleString() : 'In progress'}</td>
                  <td>{humanDuration(run.startedAt, run.completedAt)}</td>
                  <td className="panel-caption">{run.errorMessage || '-'}</td>
                </tr>
              ))}
            </tbody>
          </ResizableTable>
        </div>
      )}
    </section>
  );
}

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
type ConnectView = 'sources' | 'vuln-intel-queue' | 'inventory-run-queue';

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
    name: 'GitHub SBOM',
    summary: 'Run repository or GHCR SBOM ingestion and manage reusable GitHub ingestion pipelines.',
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
  return value === 'sources' || value === 'vuln-intel-queue' || value === 'inventory-run-queue';
}

function readInitialConnectView(): ConnectView {
  const fromQuery = new URLSearchParams(window.location.search).get(CONNECT_VIEW_QUERY_KEY);
  if (fromQuery === 'github-pipelines') return 'sources';
  if (fromQuery === 'integration-queue') return 'vuln-intel-queue';
  return isConnectView(fromQuery) ? fromQuery : 'sources';
}

function isConnectorId(value: string | null): value is ConnectorId {
  return CONNECTORS.some((connector) => connector.id === value);
}

function readInitialConnector(): ConnectorId | null {
  const params = new URLSearchParams(window.location.search);
  const source = params.get(CONNECT_SOURCE_QUERY_KEY);
  if (isConnectorId(source)) {
    return source;
  }
  if (params.get(CONNECT_VIEW_QUERY_KEY) === 'github-pipelines') {
    return 'sbom-github';
  }
  return null;
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
        title="NVD Vulnerability Feed"
        caption="Trigger NVD synchronization. View run history in Vuln Intel Run Queue."
      />
    );
  }
  if (connectorId === 'cisa-kev') {
    return (
      <SourcesPage
        focusSource="kev"
        showQueue={false}
        title="CISA KEV Feed"
        caption="Trigger KEV ingestion. View run history in Vuln Intel Run Queue."
      />
    );
  }
  if (connectorId === 'ghsa-feed') {
    return (
      <SourcesPage
        focusSource="ghsa"
        showQueue={false}
        title="GitHub Advisory Database (GHSA)"
        caption="Trigger GHSA ingestion. View run history in Vuln Intel Run Queue."
      />
    );
  }
  if (connectorId === 'microsoft-csaf-vex') {
    return (
      <SourcesPage
        focusSource="microsoft-csaf"
        showQueue={false}
        title="Microsoft CSAF + VEX Feed"
        caption="Trigger Microsoft CSAF/VEX ingestion. View run history in Vuln Intel Run Queue."
      />
    );
  }
  if (connectorId === 'redhat-csaf-vex') {
    return (
      <SourcesPage
        focusSource="redhat-csaf"
        showQueue={false}
        title="Red Hat CSAF + VEX Feed"
        caption="Trigger Red Hat CSAF/VEX ingestion. View run history in Vuln Intel Run Queue."
      />
    );
  }
  if (connectorId === 'advisory-feed') {
    return (
      <SourcesPage
        focusSource="advisories"
        showQueue={false}
        title="Advisory Import Feed"
        caption="Seed/import advisory records. View run history in Vuln Intel Run Queue."
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
              {activeView === 'vuln-intel-queue' && 'NVD, KEV, GHSA, and CSAF/VEX ingestion run history.'}
              {activeView === 'inventory-run-queue' && 'SBOM upload evidence and GitHub ingestion run history.'}
          </span>
        </div>
      </section>

      <section className="panel">
        <div className="connect-filter-bar">
          {(['sources', 'vuln-intel-queue', 'inventory-run-queue'] as const).map((view) => (
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
              {view === 'vuln-intel-queue' && 'Vuln Intel Run Queue'}
              {view === 'inventory-run-queue' && 'Inventory Run Queue'}
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

      {activeView === 'vuln-intel-queue' && (
        <SourcesPage
          focusSource="vuln-only"
          title="Vuln Intel Run Queue"
          caption="NVD, KEV, GHSA, and CSAF/VEX ingestion runs."
        />
      )}

      {activeView === 'inventory-run-queue' && <InventoryRunQueue />}

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
