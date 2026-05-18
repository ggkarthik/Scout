import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { ConnectRouteView } from '../app/routes';
import { usePlatformInventoryConnectorHealthQuery } from '../features/admin/queries';
import type { InventoryConnectorHealth } from '../features/admin/types';
import { IntegrationRunQueuePage } from './IntegrationRunQueuePage';
import { VulnIntelConfigPage } from './VulnIntelConfigPage';

type PlatformConnectorsPageProps = {
  initialView?: ConnectRouteView;
  onViewChange?: (view: ConnectRouteView) => void;
};

type PlatformConnectorsView = 'vulnerability-sources' | 'vulnerability-run-history' | 'tenant-integrations-history';

function mapInitialView(view?: ConnectRouteView): PlatformConnectorsView {
  if (view === 'run-history') {
    return 'vulnerability-run-history';
  }
  if (view === 'sources' || view === 'connectors') {
    return 'vulnerability-sources';
  }
  return 'vulnerability-sources';
}

function connectorLabel(connectorKey: string): string {
  const normalized = connectorKey.trim().toUpperCase();
  if (normalized === 'SERVICENOW_CMDB') return 'ServiceNow CMDB';
  if (normalized === 'SCCM_CMDB') return 'SCCM / MECM';
  if (normalized === 'AWS_DISCOVERY') return 'AWS Discovery';
  if (normalized === 'GITHUB_REPOSITORY_SBOM') return 'GitHub Repository SBOM';
  if (normalized === 'GITHUB_GHCR_SBOM') return 'GitHub GHCR SBOM';
  return connectorKey;
}

function healthStateClass(health: InventoryConnectorHealth): string {
  const normalized = health.healthState.trim().toUpperCase();
  if (normalized === 'HEALTHY' || normalized === 'SUCCESS') return 'status-success';
  if (normalized === 'DEGRADED' || normalized === 'WARNING') return 'status-warning';
  if (normalized === 'ERROR' || normalized === 'FAILED' || normalized === 'UNHEALTHY') return 'status-failure';
  return 'status-open';
}

export function PlatformConnectorsPage({
  initialView = 'sources',
  onViewChange,
}: PlatformConnectorsPageProps) {
  const [activeView, setActiveView] = React.useState<PlatformConnectorsView>(() => mapInitialView(initialView));
  const connectorHealthQuery = usePlatformInventoryConnectorHealthQuery();
  const vulnSummaryQuery = useQuery({
    queryKey: ['platform-vuln-intel-sources-summary'],
    queryFn: api.getVulnIntelSourcesSummary,
  });
  const healthRows = connectorHealthQuery.data ?? [];

  React.useEffect(() => {
    setActiveView(mapInitialView(initialView));
  }, [initialView]);

  const activate = (view: PlatformConnectorsView) => {
    setActiveView(view);
    if (!onViewChange) {
      return;
    }
    if (view === 'vulnerability-run-history') {
      onViewChange('run-history');
      return;
    }
    onViewChange('connectors');
  };

  return (
    <div className="page-grid">
      <div className="connect-filter-bar connect-filter-bar--standalone">
        <button
          type="button"
          className={`connect-filter-btn${activeView === 'vulnerability-sources' ? ' active' : ''}`}
          onClick={() => activate('vulnerability-sources')}
        >
          Vulnerability Sources
        </button>
        <button
          type="button"
          className={`connect-filter-btn${activeView === 'vulnerability-run-history' ? ' active' : ''}`}
          onClick={() => activate('vulnerability-run-history')}
        >
          Vulnerability Integration Run History
        </button>
        <button
          type="button"
          className={`connect-filter-btn${activeView === 'tenant-integrations-history' ? ' active' : ''}`}
          onClick={() => activate('tenant-integrations-history')}
        >
          Tenant Integrations History
        </button>
      </div>

      {activeView === 'vulnerability-sources' ? (
        <section className="panel">
          <VulnIntelConfigPage vulnSummary={vulnSummaryQuery.data ?? null} />
        </section>
      ) : activeView === 'vulnerability-run-history' ? (
        <IntegrationRunQueuePage
          title="Vulnerability Integration Run History"
          caption="Track platform-owned vulnerability ingestion jobs triggered from the platform console."
          queryParams={{ category: 'vuln-intel', limit: 200 }}
          storageKey="platform-vulnerability-run-history-table-widths"
        />
      ) : (
        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Tenant Integrations History</h3>
              <span className="panel-caption">
                Cross-tenant health for inventory integrations configured by customer tenants.
              </span>
            </div>
            <div className="button-row">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={connectorHealthQuery.isFetching}
                onClick={() => void connectorHealthQuery.refetch()}
              >
                {connectorHealthQuery.isFetching ? 'Refreshing…' : 'Refresh'}
              </button>
            </div>
          </div>

          {connectorHealthQuery.error instanceof Error ? (
            <div className="notice error">{connectorHealthQuery.error.message}</div>
          ) : connectorHealthQuery.isPending && healthRows.length === 0 ? (
            <div className="notice">Loading tenant integration health…</div>
          ) : healthRows.length === 0 ? (
            <div className="empty-state">
              <p>No tenant integrations are configured yet.</p>
            </div>
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Tenant</th>
                    <th>Connector</th>
                    <th>Health</th>
                    <th>Enabled</th>
                    <th>Auto Sync</th>
                    <th>Last Test</th>
                    <th>Last Sync</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {healthRows.map((row) => (
                    <tr key={`${row.tenantId}:${row.connectorKey}`}>
                      <td>{row.tenantName}</td>
                      <td>{connectorLabel(row.connectorKey)}</td>
                      <td>
                        <span className={`status-pill ${healthStateClass(row)}`}>
                          {row.healthState}
                        </span>
                      </td>
                      <td>{row.enabled ? 'Yes' : 'No'}</td>
                      <td>{row.autoSyncEnabled ? 'Yes' : 'No'}</td>
                      <td>{row.lastTestedAt ? new Date(row.lastTestedAt).toLocaleString() : '—'}</td>
                      <td>{row.lastSyncAt ? new Date(row.lastSyncAt).toLocaleString() : '—'}</td>
                      <td>{row.lastTestMessage?.trim() || row.lastTestStatus || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
