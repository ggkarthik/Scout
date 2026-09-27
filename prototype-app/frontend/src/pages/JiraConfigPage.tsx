import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import { canManageInventorySources } from '../features/auth/roles';
import type {
  JiraAuthType,
  JiraConfig,
  JiraConfigRequest,
  JiraConnectionTest,
  JiraFieldMapping
} from '../features/connect/types';
import { useJiraConfigQuery, useJiraProjectsQuery, useJiraIssueTypesQuery } from '../features/connect/queries';
import { formatTimestamp } from '../lib/time';

function defaultForm(): JiraConfigRequest {
  return {
    baseUrl: '',
    authType: 'BASIC',
    username: '',
    credentialSecret: '',
    oauthClientId: '',
    oauthClientSecret: '',
    projectKey: '',
    issueTypeId: '',
    issueTypeNames: '',
    fieldMappingJson: {},
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440
  };
}

function formFromConfig(config: JiraConfig | null): JiraConfigRequest {
  if (!config) return defaultForm();
  return {
    baseUrl: config.baseUrl ?? '',
    authType: config.authType,
    username: config.username ?? '',
    credentialSecret: '',
    oauthClientId: config.oauthClientId ?? '',
    oauthClientSecret: '',
    projectKey: config.projectKey ?? '',
    issueTypeId: config.issueTypeId ?? '',
    issueTypeNames: config.issueTypeNames ?? '',
    fieldMappingJson: config.fieldMappingJson ?? {},
    enabled: config.enabled,
    autoSyncEnabled: config.autoSyncEnabled,
    intervalMinutes: config.intervalMinutes ?? 1440
  };
}

export function JiraConfigPage() {
  const actor = useActor();
  const canManageConnector = canManageInventorySources(actor);
  const queryClient = useQueryClient();
  const jiraConfigQuery = useJiraConfigQuery();
  const config = jiraConfigQuery.data ?? null;

  const [form, setForm] = React.useState<JiraConfigRequest>(defaultForm());
  const [credentialSecret, setCredentialSecret] = React.useState('');
  const [oauthClientSecret, setOauthClientSecret] = React.useState('');
  const [testResult, setTestResult] = React.useState<JiraConnectionTest | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [error, setError] = React.useState('');
  const [showSecret, setShowSecret] = React.useState(false);

  // Queries for project/issue type dropdowns (enabled when baseUrl and auth are present)
  const projectsQuery = useJiraProjectsQuery(
    Boolean(canManageConnector && form.baseUrl && form.authType && credentialSecret.length > 0)
  );
  const issueTypesQuery = useJiraIssueTypesQuery(
    form.projectKey,
    Boolean(canManageConnector && form.baseUrl && form.projectKey)
  );

  React.useEffect(() => {
    setForm(formFromConfig(config));
    setCredentialSecret('');
    setOauthClientSecret('');
  }, [config]);

  const updateField = <K extends keyof JiraConfigRequest>(key: K, value: JiraConfigRequest[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const updateFieldMapping = (mapping: Partial<JiraFieldMapping>) => {
    setForm((current) => ({
      ...current,
      fieldMappingJson: { ...current.fieldMappingJson, ...mapping }
    }));
  };

  const testConnection = async () => {
    setTesting(true);
    setError('');
    setTestResult(null);
    try {
      const _testPayload: JiraConfigRequest = {
        ...form,
        baseUrl: form.baseUrl?.trim() ?? '',
        username: form.authType === 'BASIC' ? form.username?.trim() ?? '' : '',
        credentialSecret: credentialSecret.trim().length > 0 ? credentialSecret.trim() : undefined,
        oauthClientId: form.authType === 'OAUTH2' ? form.oauthClientId?.trim() ?? '' : '',
        oauthClientSecret: form.authType === 'OAUTH2' ? oauthClientSecret.trim() : undefined,
        projectKey: form.projectKey?.trim() ?? ''
      };
      const result = await api.testJiraConnection();
      setTestResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test connection failed');
    } finally {
      setTesting(false);
    }
  };

  const saveConnector = async (): Promise<JiraConfig | null> => {
    setSaving(true);
    setError('');
    try {
      const payload: JiraConfigRequest = {
        ...form,
        baseUrl: form.baseUrl?.trim() ?? '',
        username: form.authType === 'BASIC' ? form.username?.trim() ?? '' : '',
        credentialSecret: credentialSecret.trim().length > 0 ? credentialSecret.trim() : undefined,
        oauthClientId: form.authType === 'OAUTH2' ? form.oauthClientId?.trim() ?? '' : '',
        oauthClientSecret: form.authType === 'OAUTH2' ? oauthClientSecret.trim() : undefined,
        projectKey: form.projectKey?.trim() ?? '',
        issueTypeId: form.issueTypeId?.trim() ?? ''
      };

      const saved = await api.saveJiraConfig(payload);
      queryClient.invalidateQueries({ queryKey: ['jira-config'] });
      setCredentialSecret('');
      setOauthClientSecret('');
      return saved;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save configuration');
      return null;
    } finally {
      setSaving(false);
    }
  };

  if (jiraConfigQuery.isLoading) {
    return <div className="connector-detail-loading">Loading Jira configuration...</div>;
  }

  const intervalHours = Math.max(1, Math.round((form.intervalMinutes ?? 1440) / 60));
  const updateIntervalHours = (hours: number) => updateField('intervalMinutes', Math.max(60, hours * 60));

  return (
    <div className="connector-detail-content">
      <div className="connector-detail-header">
        <h2>Jira Cloud Configuration</h2>
        <p className="text-secondary">Configure Jira Cloud for automated ticket creation</p>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {testResult && testResult.status === 'SUCCESS' && (
        <div className="alert alert-success">
          Connection successful • Tested at {formatTimestamp(testResult.testedAt)}
        </div>
      )}
      {testResult && testResult.status === 'FAILED' && (
        <div className="alert alert-error">
          Connection failed: {testResult.message}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
        {/* Left column: Authentication */}
        <div className="form-section">
          <h3>Authentication</h3>

          <div className="form-group">
            <label>Authentication Type</label>
            <select
              value={form.authType}
              onChange={(e) => updateField('authType', e.target.value as JiraAuthType)}
              disabled={!canManageConnector || saving}
            >
              <option value="BASIC">Basic Auth (Username + API Token)</option>
              <option value="OAUTH2">OAuth 2.0</option>
              <option value="PAT">Personal Access Token</option>
            </select>
          </div>

          <div className="form-group">
            <label>Base URL</label>
            <input
              type="text"
              placeholder="https://your-domain.atlassian.net"
              value={form.baseUrl}
              onChange={(e) => updateField('baseUrl', e.target.value)}
              disabled={!canManageConnector || saving}
            />
          </div>

          {form.authType === 'BASIC' && (
            <>
              <div className="form-group">
                <label>Username / Email</label>
                <input
                  type="email"
                  placeholder="user@example.com"
                  value={form.username ?? ''}
                  onChange={(e) => updateField('username', e.target.value)}
                  disabled={!canManageConnector || saving}
                />
              </div>
              <div className="form-group">
                <label>API Token</label>
                <input
                  type={showSecret ? 'text' : 'password'}
                  placeholder="Enter API token"
                  value={credentialSecret}
                  onChange={(e) => setCredentialSecret(e.target.value)}
                  disabled={!canManageConnector || saving}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="button-link"
                >
                  {showSecret ? 'Hide' : 'Show'}
                </button>
              </div>
            </>
          )}

          {form.authType === 'OAUTH2' && (
            <>
              <div className="form-group">
                <label>OAuth Client ID</label>
                <input
                  type="text"
                  value={form.oauthClientId ?? ''}
                  onChange={(e) => updateField('oauthClientId', e.target.value)}
                  disabled={!canManageConnector || saving}
                />
              </div>
              <div className="form-group">
                <label>OAuth Client Secret</label>
                <input
                  type={showSecret ? 'text' : 'password'}
                  value={oauthClientSecret}
                  onChange={(e) => setOauthClientSecret(e.target.value)}
                  disabled={!canManageConnector || saving}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="button-link"
                >
                  {showSecret ? 'Hide' : 'Show'}
                </button>
              </div>
            </>
          )}

          {form.authType === 'PAT' && (
            <div className="form-group">
              <label>Personal Access Token</label>
              <input
                type={showSecret ? 'text' : 'password'}
                value={credentialSecret}
                onChange={(e) => setCredentialSecret(e.target.value)}
                disabled={!canManageConnector || saving}
              />
              <button
                type="button"
                onClick={() => setShowSecret(!showSecret)}
                className="button-link"
              >
                {showSecret ? 'Hide' : 'Show'}
              </button>
            </div>
          )}
        </div>

        {/* Right column: Project Configuration */}
        <div className="form-section">
          <h3>Project Configuration</h3>

          <div className="form-group">
            <label>Project Key</label>
            {projectsQuery.isLoading ? (
              <p className="text-secondary">Loading projects...</p>
            ) : projectsQuery.data && projectsQuery.data.length > 0 ? (
              <select
                value={form.projectKey ?? ''}
                onChange={(e) => updateField('projectKey', e.target.value)}
                disabled={!canManageConnector || saving}
              >
                <option value="">Select a project</option>
                {projectsQuery.data.map((proj) => (
                  <option key={proj.key} value={proj.key}>
                    {proj.name} ({proj.key})
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                placeholder="e.g., SEC"
                value={form.projectKey ?? ''}
                onChange={(e) => updateField('projectKey', e.target.value)}
                disabled={!canManageConnector || saving}
              />
            )}
          </div>

          <div className="form-group">
            <label>Issue Type</label>
            {issueTypesQuery.isLoading ? (
              <p className="text-secondary">Loading issue types...</p>
            ) : issueTypesQuery.data && issueTypesQuery.data.length > 0 ? (
              <select
                value={form.issueTypeId ?? ''}
                onChange={(e) => updateField('issueTypeId', e.target.value)}
                disabled={!canManageConnector || saving}
              >
                <option value="">Select issue type</option>
                {issueTypesQuery.data.map((issueType) => (
                  <option key={issueType.id} value={issueType.id}>
                    {issueType.name}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                placeholder="e.g., Bug, Task"
                value={form.issueTypeNames ?? ''}
                onChange={(e) => updateField('issueTypeNames', e.target.value)}
                disabled={!canManageConnector || saving}
              />
            )}
          </div>

          <div className="form-group">
            <label>
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => updateField('enabled', e.target.checked)}
                disabled={!canManageConnector || saving}
              />
              Enable ticket creation
            </label>
          </div>
        </div>
      </div>

      <div className="form-section">
        <h3>Field Mapping</h3>
        <p className="text-secondary">Map vulnerability fields to Jira custom fields</p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <div className="form-group">
            <label>Severity Field</label>
            <input
              type="text"
              placeholder="e.g., customfield_10001"
              value={form.fieldMappingJson?.severityField ?? ''}
              onChange={(e) => updateFieldMapping({ severityField: e.target.value })}
              disabled={!canManageConnector || saving}
            />
          </div>

          <div className="form-group">
            <label>CVSS Score Field</label>
            <input
              type="text"
              placeholder="e.g., customfield_10002"
              value={form.fieldMappingJson?.cvssScoreField ?? ''}
              onChange={(e) => updateFieldMapping({ cvssScoreField: e.target.value })}
              disabled={!canManageConnector || saving}
            />
          </div>

          <div className="form-group">
            <label>EPSS Score Field</label>
            <input
              type="text"
              placeholder="e.g., customfield_10003"
              value={form.fieldMappingJson?.epssScoreField ?? ''}
              onChange={(e) => updateFieldMapping({ epssScoreField: e.target.value })}
              disabled={!canManageConnector || saving}
            />
          </div>

          <div className="form-group">
            <label>CISA KEV Field</label>
            <input
              type="text"
              placeholder="e.g., customfield_10004"
              value={form.fieldMappingJson?.inCisaKevField ?? ''}
              onChange={(e) => updateFieldMapping({ inCisaKevField: e.target.value })}
              disabled={!canManageConnector || saving}
            />
          </div>
        </div>
      </div>

      <div className="form-section">
        <h3>Sync Settings</h3>

        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={form.autoSyncEnabled}
              onChange={(e) => updateField('autoSyncEnabled', e.target.checked)}
              disabled={!canManageConnector || saving}
            />
            Auto-sync ticket status
          </label>
        </div>

        <div className="form-group">
          <label>Sync Interval (hours)</label>
          <input
            type="number"
            min="1"
            value={intervalHours}
            onChange={(e) => updateIntervalHours(Number(e.target.value))}
            disabled={!canManageConnector || saving || !form.autoSyncEnabled}
          />
        </div>
      </div>

      {config && (
        <div className="form-section text-secondary small">
          <div>Last tested: {config.lastTestedAt ? formatTimestamp(config.lastTestedAt) : 'Never'}</div>
          <div>Last status: {config.lastTestStatus || 'Unknown'}</div>
        </div>
      )}

      <div className="connector-detail-actions">
        <button
          onClick={testConnection}
          disabled={!canManageConnector || testing || !form.baseUrl}
          className="button-secondary"
        >
          {testing ? 'Testing...' : 'Test Connection'}
        </button>
        <button
          onClick={saveConnector}
          disabled={!canManageConnector || saving || !form.baseUrl || !form.projectKey}
          className="button-primary"
        >
          {saving ? 'Saving...' : 'Save Configuration'}
        </button>
      </div>
    </div>
  );
}
