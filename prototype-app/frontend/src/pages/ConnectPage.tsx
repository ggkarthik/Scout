import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { IngestionPage } from './IngestionPage';
import { SourcesPage } from './SourcesPage';
import { AssetsPage } from './AssetsPage';
import { IntegrationRunQueuePage } from './IntegrationRunQueuePage';
import { GithubPipelineManager } from '../components/GithubPipelineManager';
import { EolSourcePanel } from '../components/EolSourcePanel';
import { SccmConnectorPage } from './SccmConnectorPage';
import { AwsDiscoveryConnectorPage } from './AwsDiscoveryConnectorPage';
import { api } from '../api/client';
import type { VulnIntelSourceStatus, VulnIntelSourcesSummary } from '../api/client';
import type { ServiceNowCmdbConfig, SccmCmdbConfig, AwsDiscoveryConfig } from '../features/connect/types';
import { useActor } from '../features/auth/context';
import { canAccessPlatformConsole, hasRole } from '../features/auth/roles';
import { timeAgo } from '../lib/time';
import { VulnIntelConfigPage } from './VulnIntelConfigPage';
import { PlatformConnectorsPage } from './PlatformConnectorsPage';

type ConnectorId =
  | 'sbom-endpoint'
  | 'sbom-github'
  | 'servicenow-cmdb'
  | 'sccm-cmdb'
  | 'aws-discovery'
  | 'nvd-api'
  | 'cisa-kev'
  | 'ghsa-feed'
  | 'microsoft-csaf-vex'
  | 'redhat-csaf-vex'
  | 'advisory-feed'
  | 'endoflife-date'
  | 'euvd-feed'
  | 'jvn-feed';

type ConnectView = 'sources' | 'connectors' | 'run-history' | 'processing-jobs';

type ConnectorDefinition = {
  id: ConnectorId;
  name: string;
  summary: string;
  icon: React.ReactNode;
};

/* ── Inline SVG connector icons ─────────────────────────────────────────────
   Cross-platform consistent icons replacing OS-dependent emoji.
   Each icon is 20×20, stroke-based, using currentColor for theme support. */

const IconGlobe = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="10" cy="10" r="8" />
    <ellipse cx="10" cy="10" rx="4" ry="8" />
    <path d="M2.5 10h15" />
    <path d="M3.5 5.5h13" />
    <path d="M3.5 14.5h13" />
  </svg>
);

const IconGitHub = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
    <path d="M10 1.5a8.5 8.5 0 0 0-2.69 16.56c.43.08.58-.18.58-.4v-1.51c-2.37.52-2.87-1.01-2.87-1.01a2.26 2.26 0 0 0-.95-1.25c-.77-.53.06-.52.06-.52a1.8 1.8 0 0 1 1.31.88 1.82 1.82 0 0 0 2.49.71 1.82 1.82 0 0 1 .54-1.14c-1.89-.22-3.88-.95-3.88-4.22a3.3 3.3 0 0 1 .88-2.29 3.07 3.07 0 0 1 .08-2.26s.72-.23 2.35.88a8.1 8.1 0 0 1 4.28 0c1.63-1.1 2.35-.88 2.35-.88a3.07 3.07 0 0 1 .08 2.26 3.3 3.3 0 0 1 .88 2.29c0 3.28-2 4-3.9 4.21a2.04 2.04 0 0 1 .58 1.58v2.35c0 .22.15.49.59.4A8.5 8.5 0 0 0 10 1.5Z" />
  </svg>
);

const IconServiceNow = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="4" y="3" width="12" height="14" rx="2" />
    <path d="M7 7h6" />
    <path d="M7 10h6" />
    <path d="M7 13h4" />
  </svg>
);

const IconDesktop = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="16" height="11" rx="2" />
    <path d="M7 17h6" />
    <path d="M10 14v3" />
  </svg>
);

const IconCloud = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M5.5 15.5a3.5 3.5 0 0 1-.4-6.97 5.5 5.5 0 0 1 10.64 1.22A3 3 0 0 1 15 15.5H5.5Z" />
  </svg>
);

const IconShield = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 2 4 5v4.5c0 4.14 2.56 7.02 6 8.5 3.44-1.48 6-4.36 6-8.5V5l-6-3Z" />
    <path d="M7.5 10l2 2 3.5-4" />
  </svg>
);

const IconWarning = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 3 2 17h16L10 3Z" />
    <path d="M10 8v4" />
    <circle cx="10" cy="14.5" r="0.5" fill="currentColor" stroke="none" />
  </svg>
);

const IconWindow = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="14" height="14" rx="2" />
    <path d="M3 7h14" />
    <path d="M10 7v10" />
  </svg>
);

const IconHat = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 14c0-2 3.13-5 7-5s7 3 7 5" />
    <ellipse cx="10" cy="14" rx="8" ry="2.5" />
    <path d="M6 9.5C6 7.5 7.8 5 10 5s4 2.5 4 4.5" />
  </svg>
);

const IconBrain = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 17V8" />
    <path d="M7 4a3 3 0 0 0-3 3c0 1.1.6 2 1.5 2.5a3 3 0 0 0 1 5.5" />
    <path d="M13 4a3 3 0 0 1 3 3c0 1.1-.6 2-1.5 2.5a3 3 0 0 1-1 5.5" />
    <path d="M7 4c0-1.1.9-2 2-2h2c1.1 0 2 .9 2 2" />
  </svg>
);

const IconCalendar = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="4" width="14" height="13" rx="2" />
    <path d="M3 8h14" />
    <path d="M7 2v4" />
    <path d="M13 2v4" />
  </svg>
);

const IconEu = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="10" cy="10" r="8" />
    <path d="M6 8h5" />
    <path d="M6 10h4" />
    <path d="M6 12h5" />
    <path d="M13 8v4" />
  </svg>
);

const IconJvn = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="10" cy="10" r="8" />
    <path d="M10 6v5" />
    <path d="M7 8.5l3-2.5 3 2.5" />
    <path d="M7.5 13.5c0 1 1.1 1.5 2.5 1.5s2.5-.5 2.5-1.5v-4" />
  </svg>
);

const CONNECT_SOURCE_QUERY_KEY = 'connectSource';
const CONNECTORS: ConnectorDefinition[] = [
  {
    id: 'sbom-endpoint',
    name: 'SBOM API Endpoint',
    summary: 'Pull SBOM JSON from authenticated API endpoints.',
    icon: IconGlobe
  },
  {
    id: 'sbom-github',
    name: 'GitHub SBOM',
    summary: 'Run repository or GHCR SBOM ingestion and manage reusable GitHub ingestion pipelines.',
    icon: IconGitHub
  },
  {
    id: 'servicenow-cmdb',
    name: 'ServiceNow CMDB',
    summary: 'Pull host inventory from ServiceNow Table APIs and review ingestion history in Connect.',
    icon: IconServiceNow
  },
  {
    id: 'sccm-cmdb',
    name: 'SCCM / MECM',
    summary: 'Ingest hardware asset and installed software inventory from Microsoft Endpoint Configuration Manager (SCCM/MECM) via direct SQL Server connection.',
    icon: IconDesktop
  },
  {
    id: 'aws-discovery',
    name: 'AWS Cloud Discovery',
    summary: 'Discover EC2 compute instances from AWS accounts and ingest SSM package inventory into Host Inventory.',
    icon: IconCloud
  },
  {
    id: 'nvd-api',
    name: 'NVD Vulnerability Feed',
    summary: '',
    icon: IconShield
  },
  {
    id: 'cisa-kev',
    name: 'CISA KEV Feed',
    summary: 'Ingest known-exploited vulnerabilities and update prioritization.',
    icon: IconWarning
  },
  {
    id: 'ghsa-feed',
    name: 'GitHub Advisory Database (GHSA)',
    summary: 'Ingest GHSA advisories with package-version applicability for correlation.',
    icon: IconGitHub
  },
  {
    id: 'microsoft-csaf-vex',
    name: 'Microsoft CSAF + VEX',
    summary: 'Ingest Microsoft CSAF advisories and VEX applicability data.',
    icon: IconWindow
  },
  {
    id: 'redhat-csaf-vex',
    name: 'Red Hat CSAF + VEX',
    summary: 'Ingest Red Hat CSAF advisories and VEX applicability data.',
    icon: IconHat
  },
  {
    id: 'advisory-feed',
    name: 'Advisory Imports',
    summary: 'Import curated advisories for package and product mappings.',
    icon: IconBrain
  },
  {
    id: 'endoflife-date',
    name: 'endoflife.date EOL Feed',
    summary: 'Run endoflife.date catalog, release, mapping, and denormalization jobs.',
    icon: IconCalendar
  },
  {
    id: 'euvd-feed',
    name: 'ENISA EUVD Feed',
    summary: 'Ingest ENISA European Vulnerability Database records and sync EUVD-to-CVE correlations.',
    icon: IconEu
  },
  {
    id: 'jvn-feed',
    name: 'JVN Vulnerability Database',
    summary: 'Ingest Japan Vulnerability Notes (JVNdb) records via the MyJVN API and sync JVNDB-to-CVE correlations.',
    icon: IconJvn
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

const CMDB_CONNECTOR_IDS: ConnectorId[] = [
  'sbom-endpoint',
  'sbom-github',
  'servicenow-cmdb',
  'sccm-cmdb'
];

const CLOUD_CONNECTOR_IDS: ConnectorId[] = [
  'aws-discovery'
];

function formatInstantConnect(iso?: string): string {
  if (!iso) return 'Never';
  return new Date(iso).toLocaleString();
}

function EuvdConnectorPanel() {
  const actor = useActor();
  const canSync = hasRole(actor, 'PLATFORM_OWNER');
  const [status, setStatus] = React.useState<VulnIntelSourceStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState('');

  const loadStatus = React.useCallback(async () => {
    try {
      const summary: VulnIntelSourcesSummary = await api.getVulnIntelSourcesSummary();
      setStatus(summary?.sources?.EUVD ?? summary?.sources?.euvd ?? null);
    } catch {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { void loadStatus(); }, [loadStatus]);

  const executeSync = async () => {
    if (!canSync) { setMessage('Platform owner access is required to execute EUVD sync.'); return; }
    setBusy(true);
    setMessage('');
    try {
      const response = await api.syncEuvd();
      setMessage((response as { message?: string }).message || 'EUVD sync queued.');
      await loadStatus();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'EUVD sync failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>ENISA EUVD Feed</h3>
        <span className="panel-caption">
          Ingest the latest EUVD records from ENISA and refresh EUVD-to-CVE cross-source correlations.
        </span>
      </div>
      <div style={{ padding: '16px 24px', display: 'grid', gap: 16 }}>
        {message && (
          <div className="notice">{message}</div>
        )}
        <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--panel-muted)', padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: '1rem' }}>EUVD Vulnerability Feed</div>
              <div className="field-hint" style={{ marginTop: 4 }}>
                Source records are stored separately and linked back to CVEs when cross-references exist.
              </div>
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void executeSync()} disabled={!canSync || busy}>
              {busy ? 'Executing…' : 'Execute now'}
            </button>
          </div>
          <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Status</div>
              <div style={{ fontWeight: 700, marginTop: 4, textTransform: 'capitalize' }}>
                {loading ? 'Loading…' : (status?.status ?? 'never')}
              </div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Last completed</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>{formatInstantConnect(status?.completedAt)}</div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Fetched / Inserted / Updated</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>
                {(status?.recordsFetched ?? 0).toLocaleString()} / {(status?.recordsInserted ?? 0).toLocaleString()} / {(status?.recordsUpdated ?? 0).toLocaleString()}
              </div>
            </div>
          </div>
          <div className="field-hint" style={{ marginTop: 12 }}>
            The execute action runs the backend EUVD sync endpoint immediately.
          </div>
        </div>
      </div>
    </section>
  );
}

function JvnConnectorPanel() {
  const actor = useActor();
  const canSync = hasRole(actor, 'PLATFORM_OWNER');
  const [status, setStatus] = React.useState<VulnIntelSourceStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState('');

  const loadStatus = React.useCallback(async () => {
    try {
      const summary: VulnIntelSourcesSummary = await api.getVulnIntelSourcesSummary();
      setStatus(summary?.sources?.['japan-vulndb'] ?? summary?.sources?.JVN ?? null);
    } catch {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { void loadStatus(); }, [loadStatus]);

  const executeSync = async () => {
    if (!canSync) { setMessage('Platform owner access is required to execute JVN sync.'); return; }
    setBusy(true);
    setMessage('');
    try {
      const response = await api.syncJvn();
      setMessage((response as { message?: string }).message || 'JVN sync queued.');
      await loadStatus();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'JVN sync failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>JVN Vulnerability Database</h3>
        <span className="panel-caption">
          Ingest Japan Vulnerability Notes (JVNdb) records via the MyJVN API and sync JVNDB-to-CVE cross-source correlations.
        </span>
      </div>
      <div style={{ padding: '16px 24px', display: 'grid', gap: 16 }}>
        {message && (
          <div className="notice">{message}</div>
        )}
        <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--panel-muted)', padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: '1rem' }}>JVN Vulnerability Feed</div>
              <div className="field-hint" style={{ marginTop: 4 }}>
                Source records are stored separately and linked back to CVEs when cross-references exist.
              </div>
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void executeSync()} disabled={!canSync || busy}>
              {busy ? 'Executing…' : 'Execute now'}
            </button>
          </div>
          <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Status</div>
              <div style={{ fontWeight: 700, marginTop: 4, textTransform: 'capitalize' }}>
                {loading ? 'Loading…' : (status?.status ?? 'never')}
              </div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Last completed</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>{formatInstantConnect(status?.completedAt)}</div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Fetched / Inserted / Updated</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>
                {(status?.recordsFetched ?? 0).toLocaleString()} / {(status?.recordsInserted ?? 0).toLocaleString()} / {(status?.recordsUpdated ?? 0).toLocaleString()}
              </div>
            </div>
          </div>
          <div className="field-hint" style={{ marginTop: 12 }}>
            The execute action runs the backend JVN sync endpoint immediately. Records are fetched from the
            MyJVN API at jvndb.jvn.jp and correlated with CVEs where cross-references are present.
          </div>
        </div>
      </div>
    </section>
  );
}

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
        title="NVD Vulnerability Feed"
        caption="Configure NVD input filters and run NVD delta or full corpus syncs."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'cisa-kev') {
    return (
      <SourcesPage
        focusSource="kev"
        title="CISA KEV Feed"
        caption="Configure KEV input filters and run the known-exploited vulnerability feed."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'ghsa-feed') {
    return (
      <SourcesPage
        focusSource="ghsa"
        title="GitHub Advisory Database (GHSA)"
        caption="Configure GHSA severity filters and run package advisory ingestion."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'microsoft-csaf-vex') {
    return (
      <SourcesPage
        focusSource="microsoft-csaf"
        title="Microsoft CSAF + VEX"
        caption="Run Microsoft CSAF advisories and VEX applicability ingestion."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'redhat-csaf-vex') {
    return (
      <SourcesPage
        focusSource="redhat-csaf"
        title="Red Hat CSAF + VEX"
        caption="Configure Red Hat input filters and run CSAF/VEX ingestion."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'advisory-feed') {
    return (
      <SourcesPage
        focusSource="advisories"
        title="Advisory Imports"
        caption="Import curated advisories and seed demo advisory data."
        showQueue={false}
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
  if (connectorId === 'euvd-feed') {
    return <EuvdConnectorPanel />;
  }
  if (connectorId === 'jvn-feed') {
    return <JvnConnectorPanel />;
  }
  if (connectorId === 'servicenow-cmdb') {
    return <AssetsPage />;
  }
  if (connectorId === 'sccm-cmdb') {
    return <SccmConnectorPage />;
  }
  if (connectorId === 'aws-discovery') {
    return <AwsDiscoveryConnectorPage />;
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
  const actor = useActor();
  const platformScope = !!actor?.platformScope && canAccessPlatformConsole(actor);
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeView, setActiveView] = React.useState<ConnectView>(initialView);
  const [activeConnector, setActiveConnector] = React.useState<ConnectorId | null>(() => readConnectorFromSearch(searchParams));
  const [snConfig, setSnConfig] = React.useState<ServiceNowCmdbConfig | null>(null);
  const [sccmConfig, setSccmConfig] = React.useState<SccmCmdbConfig | null>(null);
  const [awsConfig, setAwsConfig] = React.useState<AwsDiscoveryConfig | null>(null);

  React.useEffect(() => {
    api.getServiceNowCmdbConfig().then(setSnConfig).catch(() => {});
    api.getSccmCmdbConfig().then(setSccmConfig).catch(() => {});
    api.getAwsDiscoveryConfig().then(setAwsConfig).catch(() => {});
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

  const selectedConnector = activeConnector ? CONNECTORS.find((connector) => connector.id === activeConnector) ?? null : null;
  const canAccessPlatformConnectors = canAccessPlatformConsole(actor);
  const platformConnectorSummaryQuery = useQuery({
    queryKey: ['vuln-intel-sources-summary'],
    queryFn: api.getVulnIntelSourcesSummary,
    enabled: canAccessPlatformConnectors
  });
  const selectedConnectorAllowed = selectedConnector != null
    && !VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS.includes(selectedConnector.id);

  const availableViews = React.useMemo(
    () => (canAccessPlatformConnectors
      ? (['sources', 'connectors', 'run-history'] as const)
      : (['sources', 'run-history'] as const)),
    [canAccessPlatformConnectors]
  );

  React.useEffect(() => {
    if (!(availableViews as readonly ConnectView[]).includes(activeView)) {
      const fallbackView = availableViews[0];
      setActiveView(fallbackView);
      onViewChange?.(fallbackView);
    }
  }, [activeView, availableViews, onViewChange]);

  React.useEffect(() => {
    if (!activeConnector) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setActiveConnector(null);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeConnector]);

  if (platformScope) {
    return <PlatformConnectorsPage initialView={initialView} onViewChange={onViewChange} />;
  }

  const cmdbConnectors = CONNECTORS
    .filter((connector) => CMDB_CONNECTOR_IDS.includes(connector.id));

  const cloudConnectors = CONNECTORS
    .filter((connector) => CLOUD_CONNECTOR_IDS.includes(connector.id));

  const visibleSections = [
    {
      key: 'cmdb-sbom' as const,
      title: 'Inventory — CMDB & SBOM',
      connectors: cmdbConnectors,
      caption: 'SBOM file upload, GitHub, ServiceNow CMDB, and SCCM/MECM inventory sources.',
    },
    {
      key: 'cloud-sources' as const,
      title: 'Inventory — Cloud Sources',
      connectors: cloudConnectors,
      caption: 'Cloud hyperscaler discovery — AWS, and future Azure/GCP integrations.',
    }
  ];

  return (
    <div className="page-grid">
      <div className="connect-filter-bar connect-filter-bar--standalone">
        {availableViews.map((view) => (
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
            {view === 'connectors' && 'Connectors'}
            {view === 'run-history' && 'Run History'}
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
                        const lastSyncAt =
                          connector.id === 'servicenow-cmdb' ? snConfig?.lastSyncAt :
                          connector.id === 'sccm-cmdb' ? sccmConfig?.lastSyncAt :
                          connector.id === 'aws-discovery' ? awsConfig?.lastSyncAt :
                          undefined;

                        const lastSync = timeAgo(lastSyncAt);
                        const isFailed = false;

                        const hasSynced =
                          connector.id === 'servicenow-cmdb' ? snConfig?.lastSyncAt != null :
                          connector.id === 'sccm-cmdb' ? sccmConfig?.lastSyncAt != null :
                          connector.id === 'aws-discovery' ? awsConfig?.lastSyncAt != null :
                          false;

                        const dotClass = isFailed ? 'connect-source-dot--fail' :
                                         hasSynced ? 'connect-source-dot--ok' :
                                         'connect-source-dot--warn';
                        const demoDisabled = false;

                        return (
                          <button
                            key={connector.id}
                            type="button"
                            className={`connect-source-card${activeConnector === connector.id ? ' connect-source-card--active' : ''}${demoDisabled ? ' connect-source-card--disabled' : ''}`}
                            onClick={() => setActiveConnector(connector.id)}
                          >
                            <div className="connect-source-icon" aria-hidden="true">{connector.icon}</div>
                            <div className="connect-source-body">
                              <div className="connect-source-name-row">
                                <span className="connect-source-name">{connector.name}</span>
                                <span className={`connect-source-dot ${dotClass}`} />
                              </div>
                              <div className="panel-caption">{connector.summary}</div>
                              {demoDisabled && (
                                <div className="connect-source-lastsync">Unavailable in 7-day demo</div>
                              )}
                              {isFailed && lastSync && (
                                <div className="connect-source-lastsync connect-source-lastsync--fail">
                                  Failed · {lastSync}
                                </div>
                              )}
                              {!isFailed && lastSync && (
                                <div className="connect-source-lastsync">
                                  Last sync · {lastSync}
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

      {activeView === 'connectors' && canAccessPlatformConnectors && (
        <section className="panel">
          <VulnIntelConfigPage vulnSummary={platformConnectorSummaryQuery.data ?? null} />
        </section>
      )}

      {activeView === 'run-history' && <IntegrationRunQueuePage />}

      {activeView === 'processing-jobs' && (
        <section className="panel">
          <div className="notice" role="note">
            Processing jobs are platform-owned maintenance work. Use the Platform console to run or inspect repair and rollout jobs.
          </div>
        </section>
      )}

      {activeConnector && selectedConnector && !selectedConnectorAllowed && (
        <section className="panel">
          <div className="notice" role="note">
            {'Central vulnerability repository feeds are platform-owned. Use the Platform console to run NVD, KEV, GHSA, CSAF/VEX, advisory, EOL, or repair jobs.'}
          </div>
          <button type="button" className="btn btn-secondary" onClick={() => setActiveConnector(null)}>
            Back to customer sources
          </button>
        </section>
      )}

      {activeConnector && selectedConnector && selectedConnectorAllowed && (
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
          <ConnectorDetailContent connectorId={activeConnector} />
        </section>
      )}
    </div>
  );
}
