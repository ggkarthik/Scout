import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { pathForConnectView, pathForInventoryView } from '../app/routes';
import type {
  SccmAuthType,
  SccmCmdbConfig,
  SccmCmdbConfigRequest,
  SccmConnectionTestResponse,
  SyncTriggerResponse
} from '../features/connect/types';
import { useSccmCmdbConfigQuery } from '../features/connect/queries';

function connectHref(view: 'inventory-run-queue'): string {
  return pathForConnectView(view);
}

function inventoryHref(view: 'hosts'): string {
  return pathForInventoryView(view);
}

function defaultForm(): SccmCmdbConfigRequest {
  return {
    jdbcUrl: '',
    authType: 'SQL_AUTH',
    username: '',
    credentialSecret: '',
    siteCode: '',
    databaseName: 'CM_P01',
    fetchSize: 500,
    queryTimeoutSeconds: 120,
    mockMode: false,
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440
  };
}

function formFromConfig(config: SccmCmdbConfig | null): SccmCmdbConfigRequest {
  if (!config) {
    return defaultForm();
  }
  return {
    jdbcUrl: config.jdbcUrl ?? '',
    authType: config.authType,
    username: config.username ?? '',
    credentialSecret: '',
    siteCode: config.siteCode ?? '',
    databaseName: config.databaseName ?? 'CM_P01',
    fetchSize: config.fetchSize ?? 500,
    queryTimeoutSeconds: config.queryTimeoutSeconds ?? 120,
    mockMode: config.mockMode,
    enabled: config.enabled,
    autoSyncEnabled: config.autoSyncEnabled,
    intervalMinutes: config.intervalMinutes ?? 1440
  };
}

function formatTimestamp(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function Tooltip({ text }: { text: string }) {
  return (
    <span className="sn-tooltip" title={text} aria-label={text}>
      &#9432;
    </span>
  );
}

type HealthStatus = 'healthy' | 'error' | 'warning' | 'neutral';

function healthCardClass(status: HealthStatus): string {
  return `sn-health-card sn-health-${status}`;
}

export function SccmConnectorPage() {
  const queryClient = useQueryClient();
  const sccmConfigQuery = useSccmCmdbConfigQuery();
  const config = sccmConfigQuery.data ?? null;

  const [form, setForm] = React.useState<SccmCmdbConfigRequest>(defaultForm);
  const [credentialSecret, setCredentialSecret] = React.useState('');
  const [testResult, setTestResult] = React.useState<SccmConnectionTestResponse | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);
  const [error, setError] = React.useState('');
  const [syncResult, setSyncResult] = React.useState<SyncTriggerResponse | null>(null);
  const [showSecret, setShowSecret] = React.useState(false);
  const [showAdvanced, setShowAdvanced] = React.useState(false);

  React.useEffect(() => {
    setForm(formFromConfig(config));
    setCredentialSecret('');
  }, [config]);

  const updateField = <K extends keyof SccmCmdbConfigRequest>(key: K, value: SccmCmdbConfigRequest[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const saveConnector = async (): Promise<SccmCmdbConfig | null> => {
    setSaving(true);
    setError('');
    try {
      const payload: SccmCmdbConfigRequest = {
        ...form,
        jdbcUrl: form.jdbcUrl?.trim() ?? '',
        username: form.authType === 'SQL_AUTH' ? form.username?.trim() ?? '' : '',
        credentialSecret: credentialSecret.trim().length > 0 ? credentialSecret.trim() : undefined,
        siteCode: form.siteCode?.trim() ?? '',
        databaseName: form.databaseName?.trim() || 'CM_P01',
        fetchSize: Math.max(1, Number(form.fetchSize) || 500),
        queryTimeoutSeconds: Math.max(1, Number(form.queryTimeoutSeconds) || 120),
        intervalMinutes: Math.max(5, Number(form.intervalMinutes) || 1440)
      };
      const saved = await api.saveSccmCmdbConfig(payload);
      queryClient.setQueryData(['sccm-cmdb-config'], saved);
      setForm(formFromConfig(saved));
      setCredentialSecret('');
      return saved;
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
      return null;
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async (): Promise<void> => {
    setTestResult(null);
    const saved = await saveConnector();
    if (!saved) return;
    setTesting(true);
    setError('');
    try {
      const response = await api.testSccmCmdbConnection();
      setTestResult(response);
      const refreshed = await api.getSccmCmdbConfig();
      queryClient.setQueryData(['sccm-cmdb-config'], refreshed);
      setForm(formFromConfig(refreshed));
      setCredentialSecret('');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setTesting(false);
    }
  };

  const triggerSync = async (): Promise<void> => {
    setSyncing(true);
    setError('');
    setSyncResult(null);
    try {
      const saved = await saveConnector();
      if (!saved) return;
      const result = await api.triggerSccmCmdbSync();
      setSyncResult(result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setSyncing(false);
    }
  };

  // Health bar state derivation
  const connStatus: HealthStatus = !config?.configured
    ? 'warning'
    : config.lastTestStatus === 'SUCCESS'
      ? 'healthy'
      : config.lastTestStatus === 'FAILED'
        ? 'error'
        : 'warning';

  const connLabel = !config?.configured
    ? 'Needs Setup'
    : config.lastTestStatus === 'SUCCESS'
      ? 'Connected'
      : config.lastTestStatus === 'FAILED'
        ? 'Test Failed'
        : 'Not Tested';

  const credStatus: HealthStatus = config?.hasCredential || form.mockMode ? 'healthy' : 'error';
  const credLabel = form.mockMode
    ? 'Mock Mode — No Credentials Needed'
    : config?.hasCredential
      ? 'Credentials Stored'
      : 'Credentials Missing';

  const syncStatus: HealthStatus = form.autoSyncEnabled ? 'healthy' : 'neutral';
  const syncLabel = form.autoSyncEnabled ? `Every ${form.intervalMinutes} min` : 'Manual Only';

  const queryError = sccmConfigQuery.error instanceof Error ? sccmConfigQuery.error.message : '';
  const displayError = error || queryError;

  if (sccmConfigQuery.isPending && !config) {
    return <section className="panel">Loading SCCM / MECM connector...</section>;
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>SCCM / MECM Connector</h3>
          <span className="panel-caption">
            Direct SQL Server ingestion from Microsoft Endpoint Configuration Manager. Configure the
            JDBC connection, test connectivity, then sync hardware and software inventory into Scout.
          </span>
        </div>
      </div>

      {/* Health bar */}
      <div className="sn-health-bar">
        <div className={healthCardClass(connStatus)}>
          <span className="sn-health-label">Connection Health</span>
          <span className="sn-health-value">{connLabel}</span>
          {config?.lastTestedAt ? (
            <span className="sn-health-meta">Last tested {formatTimestamp(config.lastTestedAt)}</span>
          ) : (
            <span className="sn-health-meta">No test run yet</span>
          )}
          {!config?.configured && (
            <a className="sn-health-cta" href="#sccm-jdbc-url">Complete Setup ↓</a>
          )}
        </div>

        <div className={healthCardClass(credStatus)}>
          <span className="sn-health-label">Auth &amp; Credentials</span>
          <span className="sn-health-value">
            {form.mockMode ? 'Mock Mode' : form.authType === 'WINDOWS_AUTH' ? 'Windows Auth' : 'SQL Auth'}
          </span>
          <span className={`sn-health-meta ${credStatus === 'error' ? 'sn-health-meta-error' : ''}`}>{credLabel}</span>
          {!config?.hasCredential && !form.mockMode && (
            <a className="sn-health-cta" href="#sccm-credential">Add Credentials ↓</a>
          )}
        </div>

        <div className={healthCardClass(syncStatus)}>
          <span className="sn-health-label">Sync Status</span>
          <span className="sn-health-value">{syncLabel}</span>
          <span className="sn-health-meta">
            {form.autoSyncEnabled ? 'Scheduled ingestion active' : 'Configure in Sync Settings below'}
          </span>
        </div>
      </div>

      {/* Mock mode notice */}
      {form.mockMode && (
        <div className="notice">
          <strong>Mock Mode is enabled.</strong> All syncs will return realistic fixture data without
          connecting to a real SQL Server. Disable mock mode and provide a JDBC URL to run live syncs.
        </div>
      )}

      {/* Setup banner */}
      {!config?.configured && !form.mockMode && (
        <div className="notice">
          This connector is not yet configured. Fill in the Connection section below to enable live
          SQL Server pulls from SCCM/MECM.
        </div>
      )}

      {displayError && <div className="notice error">{displayError}</div>}

      {/* SECTION 1: Connection */}
      <div className="form-section">
        <h4 className="form-section-title">Connection</h4>
        <div className="form-grid">
          <label id="sccm-jdbc-url">
            <span>
              JDBC URL <span className="sn-required">*</span>{' '}
              <Tooltip text="Full SQL Server JDBC URL including database name and TLS options." />
            </span>
            <input
              type="text"
              value={form.jdbcUrl ?? ''}
              onChange={(e) => updateField('jdbcUrl', e.target.value)}
              placeholder="jdbc:sqlserver://sccm-server:1433;databaseName=CM_P01;encrypt=true;trustServerCertificate=true"
              disabled={form.mockMode}
            />
          </label>

          <label>
            <span>
              Auth Method <span className="sn-required">*</span>{' '}
              <Tooltip text="SQL Auth uses a SQL Server login. Windows Auth uses integrated Kerberos/NTLM (requires integratedSecurity=true in the JDBC driver)." />
            </span>
            <select
              value={form.authType}
              onChange={(e) => updateField('authType', e.target.value as SccmAuthType)}
              disabled={form.mockMode}
            >
              <option value="SQL_AUTH">SQL Server Auth</option>
              <option value="WINDOWS_AUTH">Windows Auth (Integrated)</option>
            </select>
          </label>

          {form.authType === 'SQL_AUTH' && (
            <label>
              <span>
                SQL Login Username <span className="sn-required">*</span>{' '}
                <Tooltip text="A SQL Server login with db_datareader access to the SCCM database." />
              </span>
              <input
                type="text"
                value={form.username ?? ''}
                onChange={(e) => updateField('username', e.target.value)}
                placeholder="svc-noscan-sccm"
                disabled={form.mockMode}
              />
            </label>
          )}

          {form.authType === 'SQL_AUTH' && (
            <label id="sccm-credential">
              <span>
                SQL Login Password <span className="sn-required">*</span>{' '}
                <Tooltip text={config?.hasCredential ? 'A password is already saved. Enter a new value only to rotate it.' : 'Required before live syncs can work.'} />
              </span>
              <div className="secure-input-row">
                <input
                  type={showSecret ? 'text' : 'password'}
                  value={credentialSecret}
                  onChange={(e) => setCredentialSecret(e.target.value)}
                  placeholder={config?.hasCredential ? 'Leave blank to keep saved password' : 'Enter SQL password'}
                  disabled={form.mockMode}
                />
                <button
                  type="button"
                  className="btn btn-secondary btn-inline"
                  onClick={() => setShowSecret((v) => !v)}
                  aria-label={showSecret ? 'Hide password' : 'Show password'}
                >
                  {showSecret ? 'Hide' : 'Show'}
                </button>
              </div>
              {config?.hasCredential && (
                <span className="sn-saved-badge">&#10003; Password saved — leave blank to keep it</span>
              )}
            </label>
          )}

          <label>
            <span>
              Site Code{' '}
              <Tooltip text="The SCCM/MECM three-character site code (e.g. P01). Used for documentation; not required for the SQL query." />
            </span>
            <input
              type="text"
              value={form.siteCode ?? ''}
              onChange={(e) => updateField('siteCode', e.target.value)}
              placeholder="P01"
              maxLength={20}
            />
          </label>

          <label>
            <span>
              Database Name <span className="sn-required">*</span>{' '}
              <Tooltip text="The SCCM SQL Server database name. Typically CM_ followed by your site code." />
            </span>
            <input
              type="text"
              value={form.databaseName ?? 'CM_P01'}
              onChange={(e) => updateField('databaseName', e.target.value)}
              placeholder="CM_P01"
              disabled={form.mockMode}
            />
          </label>
        </div>
      </div>

      {/* SECTION 2: Performance */}
      <div className="form-section">
        <h4 className="form-section-title">Performance</h4>
        <div className="form-grid">
          <label>
            <span>
              Fetch Size{' '}
              <Tooltip text="Number of rows the JDBC driver buffers per round-trip. Reduce if the SQL Server runs out of memory during the query." />
            </span>
            <input
              type="number"
              min={1}
              max={10000}
              value={form.fetchSize ?? 500}
              onChange={(e) => updateField('fetchSize', Number(e.target.value))}
            />
          </label>

          <label>
            <span>
              Query Timeout (seconds){' '}
              <Tooltip text="Maximum time in seconds allowed for the inventory query to complete. Increase for very large SCCM databases." />
            </span>
            <input
              type="number"
              min={1}
              max={3600}
              value={form.queryTimeoutSeconds ?? 120}
              onChange={(e) => updateField('queryTimeoutSeconds', Number(e.target.value))}
            />
          </label>
        </div>
      </div>

      {/* SECTION 3: Sync Settings */}
      <div className="form-section">
        <h4 className="form-section-title">Sync Settings</h4>
        <div className="sn-toggle-group">
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.mockMode ?? false}
              onChange={(e) => updateField('mockMode', e.target.checked)}
            />
            <span>Mock mode (use fixture data, no real SQL Server needed)</span>
            <Tooltip text="When enabled, every sync returns hardcoded fixture rows. Useful for testing the ingestion pipeline without a live SCCM deployment." />
          </label>
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.enabled ?? true}
              onChange={(e) => updateField('enabled', e.target.checked)}
            />
            <span>Connector enabled</span>
            <Tooltip text="When disabled, no syncs (manual or scheduled) will be triggered." />
          </label>
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.autoSyncEnabled ?? false}
              onChange={(e) => updateField('autoSyncEnabled', e.target.checked)}
            />
            <span>Enable scheduled sync</span>
            <Tooltip text="Automatically syncs SCCM inventory on the configured interval." />
          </label>
        </div>
        {form.autoSyncEnabled && (
          <div className="form-grid sn-sync-interval-grid">
            <label>
              <span>
                Sync Interval (minutes){' '}
                <Tooltip text="How often the scheduled sync runs. Minimum 5 minutes." />
              </span>
              <input
                type="number"
                min={5}
                value={form.intervalMinutes ?? 1440}
                onChange={(e) => updateField('intervalMinutes', Number(e.target.value))}
              />
            </label>
          </div>
        )}
      </div>

      {/* SECTION 4: Advanced (accordion) */}
      <div className="form-section">
        <button
          type="button"
          className="sn-advanced-toggle"
          onClick={() => setShowAdvanced((v) => !v)}
          aria-expanded={showAdvanced}
        >
          <span className="sn-advanced-toggle-chevron">{showAdvanced ? '▾' : '▸'}</span>
          <span>Advanced Notes</span>
          <span className="sn-advanced-toggle-hint">SCCM view requirements and SQL query details</span>
        </button>
        {showAdvanced && (
          <div className="form-grid sn-advanced-grid">
            <div>
              <p className="panel-caption">
                The connector queries <code>v_R_System</code> JOINed with{' '}
                <code>v_GS_INSTALLED_SOFTWARE</code>. The SQL Server login requires at minimum{' '}
                <code>db_datareader</code> on the SCCM database. Both views must exist — they are
                standard SCCM built-in views present on all supported versions (SCCM 2012 R2 and
                newer / MECM 2002+).
              </p>
              <p className="panel-caption">
                For WINDOWS_AUTH, the mssql-jdbc driver must be able to resolve a Kerberos ticket
                for the service account running the Scout backend. Ensure{' '}
                <code>integratedSecurity=true</code> is set in the JDBC URL and the native
                authentication library is on the JVM path.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Action bar */}
      <div className="button-row section-actions sn-action-bar">
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => void saveConnector()}
          disabled={saving || testing}
        >
          {saving ? 'Saving...' : 'Save Connector'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void testConnection()}
          disabled={testing || saving}
        >
          {testing ? 'Testing...' : 'Test Connection'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void triggerSync()}
          disabled={syncing || saving || testing || sccmConfigQuery.isFetching}
        >
          {syncing ? 'Queueing Sync...' : 'Sync Now'}
        </button>
        <button
          type="button"
          className="btn-link"
          onClick={() => void sccmConfigQuery.refetch()}
          disabled={sccmConfigQuery.isFetching || saving || testing}
        >
          {sccmConfigQuery.isFetching ? 'Refreshing...' : '↺ Refresh Setup'}
        </button>
        <a className="btn-link sn-queue-link" href={connectHref('inventory-run-queue')}>
          Open Inventory Run Queue →
        </a>
      </div>

      {/* Inline test result */}
      {testResult && (
        <div className={`notice sn-test-result ${testResult.status === 'SUCCESS' ? '' : 'error'}`}>
          <strong>{testResult.status === 'SUCCESS' ? '✓ Connection successful' : '✗ Connection failed'}</strong>
          {' — '}{testResult.message}
          <span className="sn-table-checks">
            <span className={testResult.systemViewReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              v_R_System {testResult.systemViewReachable ? '✓' : '✗'}
            </span>
            <span className={testResult.softwareViewReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              v_GS_INSTALLED_SOFTWARE {testResult.softwareViewReachable ? '✓' : '✗'}
            </span>
          </span>
        </div>
      )}

      {syncResult && (
        <div className="notice">
          <strong>Sync queued.</strong> {syncResult.message}. Track progress in{' '}
          <a href={connectHref('inventory-run-queue')}>Inventory Run Queue</a>.
        </div>
      )}

      <div className="button-row section-actions">
        <a className="btn-link" href={inventoryHref('hosts')}>View Inventory Hosts →</a>
      </div>
    </section>
  );
}
