import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { pathForConnectView, pathForInventoryView } from '../app/routes';
import { InfoTooltip } from '../components/InfoTooltip';
import { useActor } from '../features/auth/context';
import { canManageInventorySources } from '../features/auth/roles';
import type {
  AzureAuthType,
  AzureDiscoveryConfig,
  AzureDiscoveryConfigRequest,
  AzureDiscoveryTarget,
  AzureDiscoveryTargetRequest,
  AzureConnectionTestResponse,
  SyncTriggerResponse
} from '../features/connect/types';
import { useAzureDiscoveryConfigQuery, useAzureDiscoveryTargetsQuery } from '../features/connect/queries';
import { formatTimestamp } from '../lib/time';

// ── Region constants ─────────────────────────────────────────────────────────

const AZURE_REGIONS = [
  'eastus', 'eastus2', 'westus2', 'westeurope',
  'northeurope', 'southeastasia', 'australiaeast', 'centralus',
  'uksouth', 'japaneast', 'canadacentral', 'brazilsouth'
];

function parseRegions(json?: string): string[] {
  if (!json) return ['eastus2'];
  try { return JSON.parse(json) as string[]; } catch { return ['eastus2']; }
}

function isWarningStatus(status?: string): boolean {
  return status?.trim().toUpperCase() === 'SUCCESS_WITH_WARNINGS';
}

function isFailedStatus(status?: string): boolean {
  return status?.trim().toUpperCase() === 'FAILED';
}

function testResultTone(status?: string): 'success' | 'warning' | 'error' {
  if (isFailedStatus(status)) return 'error';
  if (isWarningStatus(status)) return 'warning';
  return 'success';
}

function testResultLabel(status?: string): string {
  if (isFailedStatus(status)) return 'Connection failed';
  if (isWarningStatus(status)) return 'Connection succeeded with warnings';
  return 'Connection successful';
}

// ── Default form ──────────────────────────────────────────────────────────────

function defaultForm(): AzureDiscoveryConfigRequest {
  return {
    authType: 'CLIENT_SECRET',
    azureTenantId: '',
    clientId: '',
    credentialSecret: '',
    subscriptionIdsJson: '[]',
    regionsJson: '["eastus2"]',
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440
  };
}

function formFromConfig(config: AzureDiscoveryConfig | null): AzureDiscoveryConfigRequest {
  if (!config) return defaultForm();
  return {
    authType: config.authType ?? 'CLIENT_SECRET',
    azureTenantId: config.azureTenantId ?? '',
    clientId: config.clientId ?? '',
    credentialSecret: '',
    subscriptionIdsJson: config.subscriptionIdsJson ?? '[]',
    regionsJson: config.regionsJson ?? '["eastus2"]',
    enabled: config.enabled,
    autoSyncEnabled: config.autoSyncEnabled,
    intervalMinutes: config.intervalMinutes ?? 1440
  };
}

function defaultTargetForm(config: AzureDiscoveryConfig | null): AzureDiscoveryTargetRequest {
  return {
    subscriptionId: '',
    subscriptionName: '',
    enabled: true,
    regionsJson: config?.regionsJson ?? '["eastus2"]'
  };
}

function targetToForm(target: AzureDiscoveryTarget): AzureDiscoveryTargetRequest {
  return {
    subscriptionId: target.subscriptionId ?? '',
    subscriptionName: target.subscriptionName ?? '',
    enabled: target.enabled,
    regionsJson: target.regionsJson
  };
}

// ── Component ─────────────────────────────────────────────────────────────────

export function AzureDiscoveryConnectorPage() {
  const actor = useActor();
  const canManageConnector = canManageInventorySources(actor);
  const queryClient = useQueryClient();
  const configQuery = useAzureDiscoveryConfigQuery();
  const config = configQuery.data ?? null;
  const targetsQuery = useAzureDiscoveryTargetsQuery(Boolean(config?.configured));
  const targets = targetsQuery.data ?? [];

  const [activeTab, setActiveTab] = React.useState<'connection' | 'subscriptions'>('connection');
  const [form, setForm] = React.useState<AzureDiscoveryConfigRequest>(defaultForm);
  const [selectedRegions, setSelectedRegions] = React.useState<string[]>(['eastus2']);
  const [showSecret, setShowSecret] = React.useState(false);
  const [testResult, setTestResult] = React.useState<AzureConnectionTestResponse | null>(null);
  const [syncResult, setSyncResult] = React.useState<SyncTriggerResponse | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);
  const [error, setError] = React.useState('');
  const [editingTargetId, setEditingTargetId] = React.useState<string | null>(null);
  const [targetForm, setTargetForm] = React.useState<AzureDiscoveryTargetRequest>(defaultTargetForm(null));
  const [targetBusy, setTargetBusy] = React.useState('');

  React.useEffect(() => {
    const f = formFromConfig(config);
    setForm(f);
    setSelectedRegions(parseRegions(f.regionsJson));
  }, [config]);

  React.useEffect(() => {
    if (!editingTargetId) {
      setTargetForm(defaultTargetForm(config));
    }
  }, [config, editingTargetId]);

  const updateField = <K extends keyof AzureDiscoveryConfigRequest>(key: K, value: AzureDiscoveryConfigRequest[K]) => {
    setForm((cur) => ({ ...cur, [key]: value }));
  };

  // ── Build payload ───────────────────────────────────────────────────────────
  const buildPayload = (): AzureDiscoveryConfigRequest => {
    return {
      ...form,
      regionsJson: JSON.stringify(selectedRegions)
    };
  };

  // ── Actions ─────────────────────────────────────────────────────────────────
  const saveConnector = async (): Promise<AzureDiscoveryConfig | null> => {
    setSaving(true);
    setError('');
    try {
      const payload = buildPayload();
      const saved = await api.saveAzureDiscoveryConfig(payload);
      queryClient.setQueryData(['azure-discovery-config'], saved);
      setForm(formFromConfig(saved));
      return saved;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
      const result = await api.testAzureDiscoveryConnection();
      setTestResult(result);
      const refreshed = await api.getAzureDiscoveryConfig();
      queryClient.setQueryData(['azure-discovery-config'], refreshed);
      setForm(formFromConfig(refreshed));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
      const result = await api.triggerAzureDiscoverySync();
      setSyncResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSyncing(false);
    }
  };

  const refreshTargets = async () => {
    await queryClient.invalidateQueries({ queryKey: ['azure-discovery-targets'] });
  };

  const editTarget = (target: AzureDiscoveryTarget) => {
    setEditingTargetId(target.id);
    setTargetForm(targetToForm(target));
    setError('');
  };

  const resetTargetForm = () => {
    setEditingTargetId(null);
    setTargetForm(defaultTargetForm(config));
  };

  const saveTarget = async (): Promise<void> => {
    setTargetBusy('save');
    setError('');
    try {
      const savedConfig = await saveConnector();
      if (!savedConfig) return;
      if (editingTargetId) {
        await api.updateAzureDiscoveryTarget(editingTargetId, targetForm);
      } else {
        await api.createAzureDiscoveryTarget(targetForm);
      }
      resetTargetForm();
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const deleteTarget = async (targetId: string): Promise<void> => {
    setTargetBusy(targetId);
    setError('');
    try {
      await api.deleteAzureDiscoveryTarget(targetId);
      if (editingTargetId === targetId) resetTargetForm();
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const testTarget = async (targetId: string): Promise<void> => {
    setTargetBusy(targetId);
    setError('');
    try {
      const result = await api.testAzureDiscoveryTarget(targetId);
      setTestResult(result);
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const syncTarget = async (targetId: string): Promise<void> => {
    setTargetBusy(targetId);
    setError('');
    try {
      const result = await api.triggerAzureDiscoveryTargetSync(targetId);
      setSyncResult(result);
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const queryError = configQuery.error instanceof Error ? configQuery.error.message
    : targetsQuery.error instanceof Error ? targetsQuery.error.message : '';
  const displayError = error || queryError;

  if (configQuery.isPending && !config) {
    return <section className="panel">Loading Azure Cloud Discovery connector...</section>;
  }

  const intervalOptions = [
    { label: 'Hourly', minutes: 60 },
    { label: 'Every 6 hours', minutes: 360 },
    { label: 'Every 12 hours', minutes: 720 },
    { label: 'Daily', minutes: 1440 },
    { label: 'Weekly', minutes: 10080 }
  ];

  return (
    <section className="panel">
      {/* Status row */}
      {config?.configured && (
        <div className="sn-status-row">
          {config.lastSyncAt ? (
            <span className="sn-status-meta">
              Last integration run: {formatTimestamp(config.lastSyncAt)}
            </span>
          ) : (
            <span className="sn-status-meta">No integration run yet</span>
          )}
        </div>
      )}

      {config?.lastTestStatus && (
        <div className={`notice ${testResultTone(config.lastTestStatus)}`}>
          <strong>Last Azure test: {config.lastTestStatus}</strong>
          {config.lastTestedAt && ` · ${formatTimestamp(config.lastTestedAt)}`}
          {config.lastTestMessage && (
            <div className="panel-caption" style={{ marginTop: 6, color: 'inherit' }}>
              {config.lastTestMessage}
            </div>
          )}
        </div>
      )}

      {!config?.configured && (
        <div className="notice">
          This connector is not yet configured. Select an authentication method and save.
        </div>
      )}

      {displayError && <div className="notice error">{displayError}</div>}

      {/* ── Tab navigation ── */}
      <div className="connector-tab-bar">
        <button
          type="button"
          className={`connector-tab-btn${activeTab === 'connection' ? ' connector-tab-btn--active' : ''}`}
          onClick={() => setActiveTab('connection')}
        >
          Connection
        </button>
        <button
          type="button"
          className={`connector-tab-btn${activeTab === 'subscriptions' ? ' connector-tab-btn--active' : ''}`}
          onClick={() => setActiveTab('subscriptions')}
        >
          Multi-Subscription
        </button>
      </div>

      {/* ── Tab 1: Connection ── */}
      {activeTab === 'connection' && (
        <>
          {/* Authentication */}
          <div className="form-section">
            <h4 className="form-section-title">Authentication</h4>
            <div className="form-grid">
              <label>
                <span>
                  Auth Method <span className="sn-required">*</span>{' '}
                  <InfoTooltip text="How VulnWatch authenticates to Azure. Client Secret uses a service principal (tenant ID, client ID, client secret). Managed Identity uses the identity assigned to the host running VulnWatch." />
                </span>
                <select
                  value={form.authType}
                  onChange={(e) => updateField('authType', e.target.value as AzureAuthType)}
                >
                  <option value="CLIENT_SECRET">Service Principal (Client Secret)</option>
                  <option value="MANAGED_IDENTITY">Managed Identity</option>
                </select>
              </label>

              {form.authType === 'CLIENT_SECRET' && (
                <>
                  <label>
                    <span>
                      Azure Tenant ID <span className="sn-required">*</span>
                    </span>
                    <input
                      type="text"
                      value={form.azureTenantId ?? ''}
                      onChange={(e) => updateField('azureTenantId', e.target.value)}
                      placeholder="00000000-0000-0000-0000-000000000000"
                    />
                  </label>
                  <label>
                    <span>
                      Client ID <span className="sn-required">*</span>
                    </span>
                    <input
                      type="text"
                      value={form.clientId ?? ''}
                      onChange={(e) => updateField('clientId', e.target.value)}
                      placeholder="00000000-0000-0000-0000-000000000000"
                    />
                  </label>
                  <label>
                    <span>
                      Client Secret <span className="sn-required">*</span>{' '}
                      <InfoTooltip text={config?.hasCredential ? 'A secret is saved. Enter a new value only to rotate it.' : 'Required to authenticate API calls.'} />
                    </span>
                    <div className="secure-input-row">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        value={form.credentialSecret ?? ''}
                        onChange={(e) => updateField('credentialSecret', e.target.value)}
                        placeholder={config?.hasCredential ? 'Leave blank to keep saved secret' : 'Enter client secret'}
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
                    {config?.hasCredential && (
                      <span className="sn-saved-badge">✓ Secret saved — leave blank to keep it</span>
                    )}
                  </label>
                </>
              )}

              {form.authType === 'MANAGED_IDENTITY' && (
                <label>
                  <span>
                    Managed Identity Client ID{' '}
                    <InfoTooltip text="Optional. Set only when using a user-assigned managed identity rather than the system-assigned identity." />
                  </span>
                  <input
                    type="text"
                    value={form.clientId ?? ''}
                    onChange={(e) => updateField('clientId', e.target.value)}
                    placeholder="Optional user-assigned identity client ID"
                  />
                </label>
              )}

              <label>
                <span>
                  Subscription IDs <span className="sn-required">*</span>{' '}
                  <InfoTooltip text="Comma-separated list of Azure subscription IDs to discover resources in." />
                </span>
                <input
                  type="text"
                  value={parseCommaList(form.subscriptionIdsJson)}
                  onChange={(e) => updateField('subscriptionIdsJson', JSON.stringify(splitCommaList(e.target.value)))}
                  placeholder="00000000-0000-0000-0000-000000000000, 11111111-1111-1111-1111-111111111111"
                />
              </label>
            </div>
          </div>

          {/* Regions */}
          <div className="form-section">
            <h4 className="form-section-title">Regions</h4>
            <fieldset className="aws-region-fieldset">
              <legend className="aws-region-legend">
                Azure Regions <span className="sn-required">*</span>{' '}
                <InfoTooltip text="Select one or more Azure regions to discover resources in." />
              </legend>
              <div className="aws-region-actions">
                <button type="button" className="btn btn-secondary btn-inline" onClick={() => setSelectedRegions([...AZURE_REGIONS])}>Select all</button>
                <button type="button" className="btn btn-secondary btn-inline" onClick={() => setSelectedRegions([AZURE_REGIONS[0]])}>Clear</button>
              </div>
              <div className="aws-region-grid">
                {AZURE_REGIONS.map((region) => (
                  <label key={region} className="aws-region-checkbox">
                    <input
                      type="checkbox"
                      checked={selectedRegions.includes(region)}
                      onChange={(e) => {
                        setSelectedRegions((prev) => {
                          if (e.target.checked) return [...prev, region];
                          const next = prev.filter((r) => r !== region);
                          return next.length > 0 ? next : prev;
                        });
                      }}
                    />
                    <span>{region}</span>
                  </label>
                ))}
              </div>
              <span className="panel-caption" style={{ marginTop: 4, display: 'block' }}>
                Selected: {selectedRegions.join(', ') || '—'}
              </span>
            </fieldset>
          </div>

          {/* Sync Settings */}
          <div className="form-section">
            <h4 className="form-section-title">Sync Settings</h4>
            <div className="sn-toggle-group">
              <label className="sn-toggle-row">
                <input
                  type="checkbox"
                  checked={form.autoSyncEnabled ?? false}
                  onChange={(e) => updateField('autoSyncEnabled', e.target.checked)}
                />
                <span>Enable scheduled sync</span>
                <InfoTooltip text="Automatically discovers Azure resources on the configured interval." />
              </label>
            </div>
            {form.autoSyncEnabled && (
              <div className="form-grid sn-sync-interval-grid" style={{ marginTop: 8 }}>
                <label>
                  <span>Sync Interval <InfoTooltip text="How frequently the scheduled sync runs." /></span>
                  <select
                    value={form.intervalMinutes ?? 1440}
                    onChange={(e) => updateField('intervalMinutes', Number(e.target.value))}
                  >
                    {intervalOptions.map(({ label, minutes }) => (
                      <option key={minutes} value={minutes}>{label}</option>
                    ))}
                  </select>
                </label>
              </div>
            )}
          </div>

          {/* Connection tab action bar */}
          <div className="button-row section-actions sn-action-bar">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void saveConnector()}
              disabled={!canManageConnector || saving || testing || syncing}
            >
              {saving ? 'Saving...' : 'Save Connector'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void testConnection()}
              disabled={!canManageConnector || testing || saving || syncing}
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void triggerSync()}
              disabled={!canManageConnector || syncing || saving || testing}
            >
              {syncing ? 'Running...' : 'Run Integration Now'}
            </button>
          </div>

          {testResult && (
            <div className={`notice sn-test-result ${testResultTone(testResult.status)}`}>
              <strong>{testResultLabel(testResult.status)}</strong>
              {' — '}{testResult.message}
              {!isFailedStatus(testResult.status) && testResult.reachableSubscriptions.length > 0 && (
                <span className="sn-table-checks">
                  Reachable subscriptions: {testResult.reachableSubscriptions.join(', ')}
                </span>
              )}
              {testResult.warnings.length > 0 && (
                <div className="panel-caption" style={{ marginTop: 6 }}>
                  Warnings: {testResult.warnings.join(' | ')}
                </div>
              )}
            </div>
          )}

          {syncResult && (
            <div className="notice">
              <strong>Integration queued.</strong> {syncResult.message}. Track progress in{' '}
              <a href={pathForConnectView('run-history')}>Integration Run Queue</a>.
            </div>
          )}
        </>
      )}

      {/* ── Tab 2: Multi-Subscription ── */}
      {activeTab === 'subscriptions' && (
        <>
          <div className="form-section">
            <h4 className="form-section-title">Azure Subscription Targets</h4>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Subscription</th>
                    <th>Regions</th>
                    <th>Status</th>
                    <th>Host Count</th>
                    <th>Last Sync</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.length === 0 && (
                    <tr>
                      <td colSpan={6} className="empty-state">No Azure subscriptions configured yet.</td>
                    </tr>
                  )}
                  {targets.map((target) => (
                    <tr key={target.id}>
                      <td>
                        <strong>{target.subscriptionName || target.subscriptionId || 'Azure Subscription'}</strong>
                        <span className="panel-caption" style={{ display: 'block' }}>{target.subscriptionId || 'Subscription ID unresolved'}</span>
                      </td>
                      <td><span className="panel-caption">{parseRegions(target.regionsJson).join(', ')}</span></td>
                      <td>
                        <span className={target.enabled ? 'status-pill status-success' : 'status-pill'}>
                          {target.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        {target.lastTestStatus && <span className="panel-caption" style={{ display: 'block' }}>{target.lastTestStatus}</span>}
                        {target.lastTestMessage && <span className="panel-caption" style={{ display: 'block', marginTop: 4 }}>{target.lastTestMessage}</span>}
                      </td>
                      <td>{target.hostCount}</td>
                      <td>{formatTimestamp(target.lastSyncAt)}</td>
                      <td>
                        <div className="button-row">
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => editTarget(target)} disabled={!canManageConnector}>Edit</button>
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => void testTarget(target.id)} disabled={!canManageConnector || Boolean(targetBusy)}>Test</button>
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => void syncTarget(target.id)} disabled={!canManageConnector || Boolean(targetBusy)}>Sync</button>
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => void deleteTarget(target.id)} disabled={!canManageConnector || Boolean(targetBusy)}>Delete</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="form-grid" style={{ marginTop: 16 }}>
              <label>
                <span>Subscription name</span>
                <input
                  type="text"
                  value={targetForm.subscriptionName ?? ''}
                  onChange={(e) => setTargetForm((cur) => ({ ...cur, subscriptionName: e.target.value }))}
                  placeholder="Production subscription"
                />
              </label>
              <label>
                <span>Subscription ID</span>
                <input
                  type="text"
                  value={targetForm.subscriptionId ?? ''}
                  onChange={(e) => setTargetForm((cur) => ({ ...cur, subscriptionId: e.target.value }))}
                  placeholder="00000000-0000-0000-0000-000000000000"
                />
              </label>
              <label>
                <span>Regions JSON</span>
                <input
                  type="text"
                  value={targetForm.regionsJson ?? ''}
                  onChange={(e) => setTargetForm((cur) => ({ ...cur, regionsJson: e.target.value }))}
                  placeholder='["eastus2"]'
                />
              </label>
            </div>
            <label className="sn-toggle-row" style={{ marginTop: 8 }}>
              <input
                type="checkbox"
                checked={targetForm.enabled ?? true}
                onChange={(e) => setTargetForm((cur) => ({ ...cur, enabled: e.target.checked }))}
              />
              <span>Enable this subscription target</span>
            </label>
            <div className="button-row section-actions">
              <button type="button" className="btn btn-primary" onClick={() => void saveTarget()} disabled={Boolean(targetBusy) || saving}>
                {targetBusy === 'save' ? 'Saving...' : editingTargetId ? 'Update Subscription' : 'Add Subscription'}
              </button>
              {editingTargetId && (
                <button type="button" className="btn btn-secondary" onClick={resetTargetForm} disabled={Boolean(targetBusy)}>
                  Cancel
                </button>
              )}
            </div>
          </div>

          {/* Subscriptions tab action bar */}
          <div className="button-row section-actions sn-action-bar">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void saveConnector()}
              disabled={!canManageConnector || saving || testing || syncing}
            >
              {saving ? 'Saving...' : 'Save Connector'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void testConnection()}
              disabled={!canManageConnector || testing || saving || syncing}
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void triggerSync()}
              disabled={!canManageConnector || syncing || saving || testing}
            >
              {syncing ? 'Running...' : 'Run Integration Now'}
            </button>
          </div>

          {testResult && (
            <div className={`notice sn-test-result ${testResultTone(testResult.status)}`}>
              <strong>{testResultLabel(testResult.status)}</strong>
              {' — '}{testResult.message}
              {!isFailedStatus(testResult.status) && testResult.reachableSubscriptions.length > 0 && (
                <span className="sn-table-checks">
                  Reachable subscriptions: {testResult.reachableSubscriptions.join(', ')}
                </span>
              )}
              {testResult.warnings.length > 0 && (
                <div className="panel-caption" style={{ marginTop: 6 }}>
                  Warnings: {testResult.warnings.join(' | ')}
                </div>
              )}
            </div>
          )}

          {syncResult && (
            <div className="notice">
              <strong>Integration queued.</strong> {syncResult.message}. Track progress in{' '}
              <a href={pathForConnectView('run-history')}>Integration Run Queue</a>.
            </div>
          )}
        </>
      )}

      <div className="button-row section-actions">
        <a className="btn-link" href={pathForInventoryView('hosts')}>
          View Host Inventory →
        </a>
      </div>
    </section>
  );
}

function splitCommaList(value: string): string[] {
  return value
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

function parseCommaList(json?: string): string {
  if (!json) return '';
  try {
    const values = JSON.parse(json) as string[];
    return values.join(', ');
  } catch {
    return '';
  }
}
