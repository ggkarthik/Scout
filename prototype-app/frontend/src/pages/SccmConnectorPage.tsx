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

function connectHref(view: 'integration-run-queue'): string {
  return pathForConnectView(view);
}

function inventoryHref(view: 'hosts'): string {
  return pathForInventoryView(view);
}

function formatTimestamp(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
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
  if (!config) return defaultForm();
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

function Tooltip({ text }: { text: string }) {
  return (
    <span className="sn-tooltip" title={text} aria-label={text}>ⓘ</span>
  );
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

  React.useEffect(() => {
    setForm(formFromConfig(config));
    setCredentialSecret('');
  }, [config]);

  const updateField = <K extends keyof SccmCmdbConfigRequest>(key: K, value: SccmCmdbConfigRequest[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  // Display interval as hours; store internally as minutes
  const intervalHours = Math.max(1, Math.round((form.intervalMinutes ?? 1440) / 60));
  const updateIntervalHours = (hours: number) => updateField('intervalMinutes', Math.max(60, hours * 60));

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
        fetchSize: 500,
        queryTimeoutSeconds: 120,
        enabled: true,
        intervalMinutes: Math.max(60, Number(form.intervalMinutes) || 1440)
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

  const queryError = sccmConfigQuery.error instanceof Error ? sccmConfigQuery.error.message : '';
  const displayError = error || queryError;

  if (sccmConfigQuery.isPending && !config) {
    return <section className="panel">Loading SCCM / MECM connector...</section>;
  }

  return (
    <section className="panel">
      {/* Status row */}
      {config?.configured && (
        <div className="sn-status-row">
          {config.lastSyncAt ? (
            <span className="sn-status-meta">Last integration run: {formatTimestamp(config.lastSyncAt)}</span>
          ) : (
            <span className="sn-status-meta">No integration run yet</span>
          )}
        </div>
      )}

      {/* Mock mode notice */}
      {form.mockMode && (
        <div className="notice">
          <strong>Mock Mode is enabled.</strong> All syncs return fixture data without connecting to
          a real SQL Server. Disable mock mode and provide a JDBC URL to run live syncs.
        </div>
      )}

      {/* Setup banner */}
      {!config?.configured && !form.mockMode && (
        <div className="notice">
          This connector is not yet configured. Fill in the Connection section below.
        </div>
      )}

      {displayError && <div className="notice error">{displayError}</div>}

      {/* ── SECTION 1: Connection ── */}
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
              <Tooltip text="SQL Auth uses a SQL Server login. Windows Auth uses integrated Kerberos/NTLM." />
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
                <span className="sn-saved-badge">✓ Password saved — leave blank to keep it</span>
              )}
            </label>
          )}

          <label>
            <span>
              Site Code{' '}
              <Tooltip text="The SCCM/MECM three-character site code (e.g. P01)." />
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

      {/* ── SECTION 2: Sync Settings ── */}
      <div className="form-section">
        <h4 className="form-section-title">Sync Settings</h4>
        <div className="sn-toggle-group">
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.mockMode ?? false}
              onChange={(e) => updateField('mockMode', e.target.checked)}
            />
            <span>Mock mode (fixture data, no real SQL Server needed)</span>
            <Tooltip text="When enabled, every sync returns hardcoded fixture rows — useful for testing without a live SCCM deployment." />
          </label>
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.autoSyncEnabled ?? false}
              onChange={(e) => updateField('autoSyncEnabled', e.target.checked)}
            />
            <span>Enable scheduled live sync</span>
            <Tooltip text="Automatically syncs SCCM inventory on the configured interval." />
          </label>
        </div>
        {form.autoSyncEnabled && (
          <div className="form-grid sn-sync-interval-grid">
            <label>
              <span>
                Sync Interval (hours){' '}
                <Tooltip text="How often the scheduled sync runs. Minimum 1 hour." />
              </span>
              <input
                type="number"
                min={1}
                value={intervalHours}
                onChange={(e) => updateIntervalHours(Number(e.target.value))}
              />
            </label>
          </div>
        )}
      </div>

      {/* ── Action bar ── */}
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
          {syncing ? 'Running...' : 'Run Integration now'}
        </button>
      </div>

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
          <strong>Integration queued.</strong> {syncResult.message}. Track progress in{' '}
          <a href={connectHref('integration-run-queue')}>Integration Run Queue</a>.
        </div>
      )}

      <div className="button-row section-actions">
        <a className="btn-link" href={inventoryHref('hosts')}>View Inventory Hosts →</a>
      </div>
    </section>
  );
}
