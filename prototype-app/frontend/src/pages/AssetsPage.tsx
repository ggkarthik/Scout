import React from 'react';
import { api } from '../api/client';
import type {
  ServiceNowCmdbAuthType,
  ServiceNowCmdbConfig,
  ServiceNowCmdbConfigRequest,
  ServiceNowCmdbConnectionTest,
  SyncTriggerResponse
} from '../types';
import { buildPathWithQueryParams } from '../utils/queryState';

const REVIEW_CATEGORY_QUERY_KEY = 'reviewCategory';
const DEFAULT_INSTALL_FIELDS = [
  'sys_id',
  'display_name',
  'publisher',
  'version',
  'install_date',
  'last_scanned',
  'last_used',
  'active_install',
  'unlicensed_install',
  'installed_on',
  'discovery_model'
].join(',');
const DEFAULT_DISCOVERY_FIELDS = [
  'sys_id',
  'primary_key',
  'normalized_product',
  'normalized_publisher',
  'normalized_version',
  'product_hash',
  'version_hash',
  'full_version',
  'platform',
  'language',
  'normalization_status',
  'approved',
  'low_confidence'
].join(',');

function inventoryHref(view: 'hosts', reviewCategories?: string[]): string {
  return buildPathWithQueryParams({
    tab: 'inventory',
    inventoryView: view,
    [REVIEW_CATEGORY_QUERY_KEY]: reviewCategories
  });
}

function connectHref(view: 'inventory-run-queue'): string {
  return buildPathWithQueryParams({
    tab: 'connect',
    connectView: view
  });
}

function defaultForm(): ServiceNowCmdbConfigRequest {
  return {
    baseUrl: '',
    authType: 'BASIC',
    username: '',
    credentialSecret: '',
    installTable: 'cmdb_sam_sw_install',
    discoveryModelTable: 'cmdb_sam_sw_discovery_model',
    ciTable: 'cmdb_ci',
    installQuery: '',
    discoveryQuery: '',
    installFields: DEFAULT_INSTALL_FIELDS,
    discoveryFields: DEFAULT_DISCOVERY_FIELDS,
    pageSize: 1000,
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440
  };
}

function formFromConfig(config: ServiceNowCmdbConfig | null): ServiceNowCmdbConfigRequest {
  if (!config) {
    return defaultForm();
  }
  return {
    baseUrl: config.baseUrl ?? '',
    authType: config.authType,
    username: config.username ?? '',
    credentialSecret: '',
    installTable: config.installTable ?? 'cmdb_sam_sw_install',
    discoveryModelTable: config.discoveryModelTable ?? 'cmdb_sam_sw_discovery_model',
    ciTable: config.ciTable ?? 'cmdb_ci',
    installQuery: config.installQuery ?? '',
    discoveryQuery: config.discoveryQuery ?? '',
    installFields: config.installFields ?? DEFAULT_INSTALL_FIELDS,
    discoveryFields: config.discoveryFields ?? DEFAULT_DISCOVERY_FIELDS,
    pageSize: config.pageSize ?? 1000,
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

function formatAuthType(value: ServiceNowCmdbAuthType): string {
  return value === 'BEARER' ? 'Bearer Token' : 'Basic Auth';
}

function Tooltip({ text }: { text: string }) {
  return (
    <span className="sn-tooltip" title={text} aria-label={text}>
      ⓘ
    </span>
  );
}

type HealthStatus = 'healthy' | 'error' | 'warning' | 'neutral';

function healthCardClass(status: HealthStatus): string {
  return `sn-health-card sn-health-${status}`;
}

export function AssetsPage() {
  const [config, setConfig] = React.useState<ServiceNowCmdbConfig | null>(null);
  const [form, setForm] = React.useState<ServiceNowCmdbConfigRequest>(defaultForm);
  const [credentialSecret, setCredentialSecret] = React.useState('');
  const [testResult, setTestResult] = React.useState<ServiceNowCmdbConnectionTest | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [syncingLive, setSyncingLive] = React.useState(false);
  const [error, setError] = React.useState('');
  const [liveSyncResult, setLiveSyncResult] = React.useState<SyncTriggerResponse | null>(null);
  const [showSecret, setShowSecret] = React.useState(false);
  const [showAdvanced, setShowAdvanced] = React.useState(false);

  const refresh = React.useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const savedConfig = await api.getServiceNowCmdbConfig();
      setConfig(savedConfig);
      setForm(formFromConfig(savedConfig));
      setCredentialSecret('');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const updateField = <K extends keyof ServiceNowCmdbConfigRequest>(key: K, value: ServiceNowCmdbConfigRequest[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const saveConnector = async (): Promise<ServiceNowCmdbConfig | null> => {
    setSaving(true);
    setError('');
    try {
      const payload: ServiceNowCmdbConfigRequest = {
        ...form,
        username: form.authType === 'BASIC' ? form.username?.trim() ?? '' : '',
        credentialSecret: credentialSecret.trim().length > 0 ? credentialSecret.trim() : undefined,
        installTable: form.installTable.trim(),
        discoveryModelTable: form.discoveryModelTable.trim(),
        ciTable: form.ciTable.trim(),
        installQuery: form.installQuery?.trim() ?? '',
        discoveryQuery: form.discoveryQuery?.trim() ?? '',
        installFields: form.installFields?.trim() ?? DEFAULT_INSTALL_FIELDS,
        discoveryFields: form.discoveryFields?.trim() ?? DEFAULT_DISCOVERY_FIELDS,
        baseUrl: form.baseUrl.trim(),
        pageSize: Math.max(1, Number(form.pageSize) || 1000),
        intervalMinutes: Math.max(5, Number(form.intervalMinutes) || 1440)
      };
      const saved = await api.saveServiceNowCmdbConfig(payload);
      setConfig(saved);
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
      const response = await api.testServiceNowCmdbConnection();
      setTestResult(response);
      const refreshed = await api.getServiceNowCmdbConfig();
      setConfig(refreshed);
      setForm(formFromConfig(refreshed));
      setCredentialSecret('');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setTesting(false);
    }
  };

  const queueLiveSync = async (): Promise<void> => {
    setSyncingLive(true);
    setError('');
    setLiveSyncResult(null);
    try {
      const saved = await saveConnector();
      if (!saved) {
        return;
      }
      const result = await api.triggerServiceNowCmdbSync();
      setLiveSyncResult(result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setSyncingLive(false);
    }
  };

  // Derive health card states
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

  const credStatus: HealthStatus = config?.hasCredentialSecret ? 'healthy' : 'error';
  const credLabel = config?.hasCredentialSecret ? 'Credentials Stored' : 'Credentials Missing';

  const syncStatus: HealthStatus = form.autoSyncEnabled ? 'healthy' : 'neutral';
  const syncLabel = form.autoSyncEnabled ? `Every ${form.intervalMinutes} min` : 'Manual Only';

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>ServiceNow CMDB Connector</h3>
          <span className="panel-caption">
            Live Table API ingestion from ServiceNow. Configure, test connectivity, then review imported hosts in Inventory.
          </span>
        </div>
      </div>

      {/* ── 3-card health bar ── */}
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
            <a className="sn-health-cta" href="#sn-base-url">Complete Setup ↓</a>
          )}
        </div>

        <div className={healthCardClass(credStatus)}>
          <span className="sn-health-label">Auth &amp; Credentials</span>
          <span className="sn-health-value">{formatAuthType(form.authType)}</span>
          <span className={`sn-health-meta ${credStatus === 'error' ? 'sn-health-meta-error' : ''}`}>{credLabel}</span>
          {!config?.hasCredentialSecret && (
            <a className="sn-health-cta" href="#sn-credential">Add Credentials ↓</a>
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

      {/* Setup banner — only shown when not yet configured */}
      {!config?.configured && (
        <div className="notice">
          This connector is not yet configured. Fill in the Connection section below to enable live ServiceNow API pulls.
        </div>
      )}

      {error && <div className="notice error">{error}</div>}

      {/* ── SECTION 1: Connection ── */}
      <div className="form-section">
        <h4 className="form-section-title">Connection</h4>
        <div className="form-grid">
          <label id="sn-base-url">
            <span>
              ServiceNow Base URL <span className="sn-required">*</span>{' '}
              <Tooltip text="Use the root instance URL. The app will call the Table API under this host." />
            </span>
            <input
              type="url"
              value={form.baseUrl}
              onChange={(event) => updateField('baseUrl', event.target.value)}
              placeholder="https://your-instance.service-now.com"
            />
          </label>

          <label>
            <span>
              Auth Method <span className="sn-required">*</span>{' '}
              <Tooltip text="Basic Auth uses username + password. Bearer mode uses a token in the Authorization header." />
            </span>
            <select value={form.authType} onChange={(event) => updateField('authType', event.target.value as ServiceNowCmdbAuthType)}>
              <option value="BASIC">Basic Auth</option>
              <option value="BEARER">Bearer Token</option>
            </select>
          </label>

          <label>
            <span>
              Integration Username{form.authType === 'BASIC' ? <> <span className="sn-required">*</span></> : ' (Optional)'}{' '}
              <Tooltip text={form.authType === 'BASIC' ? 'Use a dedicated read-only ServiceNow integration account.' : 'Optional in Bearer mode. Leave blank if the token is sufficient.'} />
            </span>
            <input
              type="text"
              value={form.username ?? ''}
              onChange={(event) => updateField('username', event.target.value)}
              placeholder={form.authType === 'BEARER' ? 'Optional for audit context' : 'svc-noscan-servicenow'}
            />
          </label>

          <label id="sn-credential">
            <span>
              {form.authType === 'BEARER' ? 'Bearer Token' : 'Password'} <span className="sn-required">*</span>{' '}
              <Tooltip text={config?.hasCredentialSecret ? 'A secret is already saved. Enter a new value only to rotate it.' : 'Required before live pulls can work.'} />
            </span>
            <div className="secure-input-row">
              <input
                type={showSecret ? 'text' : 'password'}
                value={credentialSecret}
                onChange={(event) => setCredentialSecret(event.target.value)}
                placeholder={config?.hasCredentialSecret ? 'Leave blank to keep saved secret' : 'Enter secret'}
              />
              <button
                type="button"
                className="btn btn-secondary btn-inline"
                onClick={() => setShowSecret((v) => !v)}
                aria-label={showSecret ? 'Hide secret' : 'Show secret'}
              >
                {showSecret ? 'Hide' : 'Show'}
              </button>
            </div>
            {config?.hasCredentialSecret && (
              <span className="sn-saved-badge">✓ Secret saved — leave blank to keep it</span>
            )}
          </label>
        </div>
      </div>

      {/* ── SECTION 2: Table Configuration ── */}
      <div className="form-section">
        <h4 className="form-section-title">Table Configuration</h4>
        <div className="form-grid">
          <label>
            <span>
              Install Table <span className="sn-required">*</span>{' '}
              <Tooltip text="ServiceNow table containing installed software rows per host." />
            </span>
            <input
              type="text"
              value={form.installTable}
              onChange={(event) => updateField('installTable', event.target.value)}
              placeholder="cmdb_sam_sw_install"
            />
          </label>

          <label>
            <span>
              Discovery Model Table <span className="sn-required">*</span>{' '}
              <Tooltip text="Provides normalized discovery-model metadata for software records." />
            </span>
            <input
              type="text"
              value={form.discoveryModelTable}
              onChange={(event) => updateField('discoveryModelTable', event.target.value)}
              placeholder="cmdb_sam_sw_discovery_model"
            />
          </label>

          <label>
            <span>
              CI Lookup Table <span className="sn-required">*</span>{' '}
              <Tooltip text="Used for host lookup and CI resolution when install rows do not carry a direct sys_id." />
            </span>
            <input
              type="text"
              value={form.ciTable}
              onChange={(event) => updateField('ciTable', event.target.value)}
              placeholder="cmdb_ci"
            />
          </label>

          <label>
            <span>
              Page Size{' '}
              <Tooltip text="Rows requested per Table API page during live pulls. Reduce if ServiceNow times out." />
            </span>
            <input
              type="number"
              min={1}
              max={10000}
              value={form.pageSize}
              onChange={(event) => updateField('pageSize', Number(event.target.value))}
            />
          </label>
        </div>
      </div>

      {/* ── SECTION 3: Sync Settings ── */}
      <div className="form-section">
        <h4 className="form-section-title">Sync Settings</h4>
        <div className="sn-toggle-group">
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => updateField('enabled', event.target.checked)}
            />
            <span>Connector enabled</span>
            <Tooltip text="When disabled, no live pulls will be triggered." />
          </label>
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.autoSyncEnabled}
              onChange={(event) => updateField('autoSyncEnabled', event.target.checked)}
            />
            <span>Enable scheduled live sync</span>
            <Tooltip text="Automatically pulls data from ServiceNow on the configured interval." />
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
                value={form.intervalMinutes}
                onChange={(event) => updateField('intervalMinutes', Number(event.target.value))}
              />
            </label>
          </div>
        )}
      </div>

      {/* ── SECTION 4: Advanced Options (accordion) ── */}
      <div className="form-section">
        <button
          type="button"
          className="sn-advanced-toggle"
          onClick={() => setShowAdvanced((v) => !v)}
          aria-expanded={showAdvanced}
        >
          <span className="sn-advanced-toggle-chevron">{showAdvanced ? '▾' : '▸'}</span>
          <span>Advanced Options</span>
          <span className="sn-advanced-toggle-hint">Field selection and query overrides for install and discovery tables</span>
        </button>
        {showAdvanced && (
          <div className="form-grid sn-advanced-grid">
            <label>
              <span>
                Install Fields{' '}
                <Tooltip text="Comma-separated ServiceNow fields pulled from the install table. Defaults to only the fields NoScan ingests." />
              </span>
              <textarea
                rows={4}
                value={form.installFields ?? ''}
                onChange={(event) => updateField('installFields', event.target.value)}
                placeholder={DEFAULT_INSTALL_FIELDS}
              />
            </label>
            <label>
              <span>
                Discovery Fields{' '}
                <Tooltip text="Comma-separated ServiceNow fields pulled from the discovery-model table. Defaults to the deterministic normalization fields." />
              </span>
              <textarea
                rows={4}
                value={form.discoveryFields ?? ''}
                onChange={(event) => updateField('discoveryFields', event.target.value)}
                placeholder={DEFAULT_DISCOVERY_FIELDS}
              />
            </label>
            <label>
              <span>
                Install Query Override{' '}
                <Tooltip text="Optional sysparm_query fragment to scope to active rows or a specific business unit." />
              </span>
              <textarea
                rows={4}
                value={form.installQuery ?? ''}
                onChange={(event) => updateField('installQuery', event.target.value)}
                placeholder="Optional sysparm_query fragment for cmdb_sam_sw_install"
              />
            </label>
            <label>
              <span>
                Discovery Query Override{' '}
                <Tooltip text="Optional sysparm_query fragment to filter discovery-model rows." />
              </span>
              <textarea
                rows={4}
                value={form.discoveryQuery ?? ''}
                onChange={(event) => updateField('discoveryQuery', event.target.value)}
                placeholder="Optional sysparm_query fragment for cmdb_sam_sw_discovery_model"
              />
            </label>
          </div>
        )}
      </div>

      {/* ── Action bar ── */}
      <div className="button-row section-actions sn-action-bar">
        <button type="button" className="btn btn-primary" onClick={() => void saveConnector()} disabled={saving || testing}>
          {saving ? 'Saving...' : 'Save Connector'}
        </button>
        <button type="button" className="btn btn-secondary" onClick={() => void testConnection()} disabled={testing || saving}>
          {testing ? 'Testing...' : 'Test Connection'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void queueLiveSync()}
          disabled={syncingLive || saving || testing || loading}
        >
          {syncingLive ? 'Queueing Live Sync...' : 'Run Live Sync'}
        </button>
        <button type="button" className="btn-link" onClick={() => void refresh()} disabled={loading || saving || testing}>
          {loading ? 'Refreshing...' : '↺ Refresh Setup'}
        </button>
        <a className="btn-link sn-queue-link" href={connectHref('inventory-run-queue')}>
          Open Inventory Run Queue →
        </a>
      </div>

      {/* Inline test result — directly below action bar */}
      {testResult && (
        <div className={`notice sn-test-result ${testResult.status === 'SUCCESS' ? '' : 'error'}`}>
          <strong>{testResult.status === 'SUCCESS' ? '✓ Connection successful' : '✗ Connection failed'}</strong>
          {' — '}{testResult.message}
          <span className="sn-table-checks">
            <span className={testResult.ciTableReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              CI {testResult.ciTableReachable ? '✓' : '✗'}
            </span>
            <span className={testResult.installTableReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              Install {testResult.installTableReachable ? '✓' : '✗'}
            </span>
            <span className={testResult.discoveryTableReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              Discovery {testResult.discoveryTableReachable ? '✓' : '✗'}
            </span>
          </span>
        </div>
      )}

      {liveSyncResult && (
        <div className="notice">
          <strong>Live sync queued.</strong> {liveSyncResult.message}. Track progress in{' '}
          <a href={connectHref('inventory-run-queue')}>Inventory Run Queue</a>.
        </div>
      )}

      <div className="button-row section-actions">
        <a className="btn-link" href={inventoryHref('hosts')}>View Inventory Hosts →</a>
        <a className="btn-link" href={inventoryHref('hosts', ['NEEDS_REVIEW'])}>View Hosts Needing Review →</a>
      </div>
    </section>
  );
}
