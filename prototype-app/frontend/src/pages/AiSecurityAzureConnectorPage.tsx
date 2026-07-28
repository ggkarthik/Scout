import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type {
  AiSecurityAzureConnectionTest,
  AiSecurityAzureCredentialProfile,
} from '../features/ai-security/types';
import { useAzureDiscoveryTargetsQuery } from '../features/connect/queries';
import { timeAgo } from '../lib/time';

const DEFAULT_EXPIRY_DAYS = 90;

function defaultExpiry(): string {
  const value = new Date(Date.now() + DEFAULT_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
  return value.toISOString().slice(0, 16);
}

export function AiSecurityAzureConnectorPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const targetsQuery = useAzureDiscoveryTargetsQuery(true);
  const profilesQuery = useQuery({
    queryKey: ['ai-security-azure-credentials'],
    queryFn: api.listAiSecurityAzureCredentials,
  });
  const connectorsQuery = useQuery({
    queryKey: ['ai-security-azure-connectors'],
    queryFn: api.listAiSecurityAzureConnectors,
  });
  const requirementsQuery = useQuery({
    queryKey: ['ai-security-azure-requirements'],
    queryFn: api.getAiSecurityAzureRequirements,
  });
  const runsQuery = useQuery({
    queryKey: ['ai-security-runs', 'AZURE'],
    queryFn: () => api.listAiSecurityRuns('AZURE'),
  });
  const latestRunId = runsQuery.data?.[0]?.id;
  const latestSuccessfulRun = runsQuery.data?.find((run) => run.status === 'COMPLETED');
  const scopesQuery = useQuery({
    queryKey: ['ai-security-run-scopes', latestRunId],
    queryFn: () => api.listAiSecurityRunScopes(latestRunId as string),
    enabled: latestRunId != null,
  });

  const [name, setName] = React.useState('AI Security Azure');
  const [azureTenantId, setAzureTenantId] = React.useState('');
  const [clientId, setClientId] = React.useState('');
  const [clientSecret, setClientSecret] = React.useState('');
  const [expiresAt, setExpiresAt] = React.useState(defaultExpiry);
  const [profileId, setProfileId] = React.useState('');
  const [targetId, setTargetId] = React.useState('');
  const [testResult, setTestResult] = React.useState<AiSecurityAzureConnectionTest | null>(null);
  const [replacementSecret, setReplacementSecret] = React.useState('');
  const [replacementExpiry, setReplacementExpiry] = React.useState(defaultExpiry);

  React.useEffect(() => {
    if (!profileId && profilesQuery.data?.[0]) setProfileId(profilesQuery.data[0].id);
  }, [profileId, profilesQuery.data]);
  React.useEffect(() => {
    if (!targetId && targetsQuery.data?.find((target) => target.enabled)) {
      setTargetId(targetsQuery.data.find((target) => target.enabled)?.id ?? '');
    }
  }, [targetId, targetsQuery.data]);

  const createProfile = useMutation({
    mutationFn: () => api.createAiSecurityAzureCredential({
      name,
      azureTenantId,
      clientId,
      clientSecret,
      expiresAt: new Date(expiresAt).toISOString(),
    }),
    onSuccess: (profile) => {
      setClientSecret('');
      setProfileId(profile.id);
      void queryClient.invalidateQueries({ queryKey: ['ai-security-azure-credentials'] });
    },
  });
  const saveConnector = useMutation({
    mutationFn: () => api.saveAiSecurityAzureConnector({
      credentialProfileId: profileId,
      targetId,
      enabled: true,
    }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-azure-connectors'] }),
  });
  const rotateProfile = useMutation({
    mutationFn: (profile: AiSecurityAzureCredentialProfile) => {
      const target = targetsQuery.data?.find((candidate) => candidate.id === targetId);
      if (!target?.subscriptionId) throw new Error('Select an Azure subscription target first.');
      return api.rotateAiSecurityAzureCredential(profile.id, {
        clientSecret: replacementSecret,
        expiresAt: new Date(replacementExpiry).toISOString(),
        subscriptionId: target.subscriptionId,
      });
    },
    onSuccess: () => {
      setReplacementSecret('');
      void queryClient.invalidateQueries({ queryKey: ['ai-security-azure-credentials'] });
    },
  });
  const runDiscovery = useMutation({
    mutationFn: (selectedTargetId: string) => api.runAiSecurityAzureTarget(selectedTargetId),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-runs', 'AZURE'] }),
  });

  const connectorForTarget = connectorsQuery.data?.find((connector) => connector.sourceTargetId === targetId);
  const selectedProfile = profilesQuery.data?.find((profile) => profile.id === profileId);
  const error = createProfile.error ?? saveConnector.error ?? rotateProfile.error ?? runDiscovery.error;

  const testConnector = async () => {
    if (!connectorForTarget) return;
    setTestResult(await api.testAiSecurityAzureConnector(connectorForTarget.id));
  };

  return (
    <div className="ai-security-page">
      <section className="ai-security-hero connector">
        <div>
          <span className="ai-security-kicker">Inventory · AI · Azure</span>
          <h2>Azure AI Security</h2>
          <p>Discover Foundry, Azure ML, AI Search, and Bot resources without entering Asset or CVE pipelines.</p>
        </div>
        <span className="status-pill warning">Staged activation</span>
      </section>

      {error && <div className="notice error">{error instanceof Error ? error.message : String(error)}</div>}

      <section className="panel connector-settings">
        <div className="panel-header">
          <div><h3>1. Credential profile</h3><span className="panel-caption">The secret is encrypted and never displayed again.</span></div>
        </div>
        <div className="form-grid">
          <label>Profile name<input value={name} onChange={(event) => setName(event.target.value)} /></label>
          <label>Entra tenant ID<input value={azureTenantId} onChange={(event) => setAzureTenantId(event.target.value)} /></label>
          <label>Application (client) ID<input value={clientId} onChange={(event) => setClientId(event.target.value)} /></label>
          <label>Client secret<input type="password" autoComplete="new-password" value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} /></label>
          <label>Secret expiry<input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
        </div>
        <button
          className="btn btn-secondary"
          type="button"
          disabled={!name || !azureTenantId || !clientId || !clientSecret || createProfile.isPending}
          onClick={() => createProfile.mutate()}
        >
          {createProfile.isPending ? 'Securing credential…' : 'Create credential profile'}
        </button>
      </section>

      <section className="panel connector-settings">
        <div className="panel-header">
          <div>
            <h3>Permission blueprint</h3>
            <span className="panel-caption">
              Matrix v{requirementsQuery.data?.matrixVersion ?? '…'} · generated from shipped policy evidence
            </span>
          </div>
        </div>
        {requirementsQuery.isError ? (
          <div className="notice error">Azure permission requirements could not be loaded.</div>
        ) : (
          <div className="ai-security-split">
            <div>
              <h4>Required read actions</h4>
              <ul>
                {requirementsQuery.data?.roleTemplate.actions.map((action) => <li key={action}>{action}</li>)}
              </ul>
            </div>
            <div>
              <h4>Explicitly excluded</h4>
              <ul>
                {requirementsQuery.data?.prohibitedActions.map((action) => <li key={action}>{action}</li>)}
              </ul>
            </div>
          </div>
        )}
      </section>

      <section className="panel connector-settings">
        <div className="panel-header">
          <div><h3>2. Bind an approved subscription</h3><span className="panel-caption">AI Security reuses the existing tenant-scoped Azure target.</span></div>
        </div>
        {(targetsQuery.data?.length ?? 0) === 0 ? (
          <div className="empty-state">
            <p>Create and verify an Azure Cloud Discovery subscription target before binding AI Security.</p>
            <button className="btn btn-primary" type="button" onClick={() => navigate('/connect/sources?connectSource=azure-discovery')}>
              Configure Azure target
            </button>
          </div>
        ) : (
          <>
            <div className="form-grid">
              <label>Credential profile
                <select value={profileId} onChange={(event) => setProfileId(event.target.value)}>
                  <option value="">Select profile</option>
                  {profilesQuery.data?.filter((profile) => profile.status === 'ACTIVE').map((profile) => (
                    <option key={profile.id} value={profile.id}>{profile.name}</option>
                  ))}
                </select>
              </label>
              <label>Subscription target
                <select value={targetId} onChange={(event) => { setTargetId(event.target.value); setTestResult(null); }}>
                  <option value="">Select subscription</option>
                  {targetsQuery.data?.filter((target) => target.enabled).map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.subscriptionName || target.subscriptionId}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="ai-security-review-actions">
              <button className="btn btn-primary" disabled={!profileId || !targetId || saveConnector.isPending} onClick={() => saveConnector.mutate()}>
                {saveConnector.isPending ? 'Binding…' : connectorForTarget ? 'Update binding' : 'Bind subscription'}
              </button>
              <button className="btn btn-secondary" disabled={!connectorForTarget} onClick={() => void testConnector()}>Test permissions</button>
              <button
                className="btn btn-secondary"
                disabled={!connectorForTarget || !targetId || runDiscovery.isPending}
                onClick={() => runDiscovery.mutate(targetId)}
              >
                {runDiscovery.isPending ? 'Queuing…' : 'Run discovery'}
              </button>
            </div>
          </>
        )}
      </section>

      {testResult && (
        <section className="panel">
          <div className={`notice ${testResult.success ? 'success' : 'error'}`}>
            {testResult.message} Correlation ID: {testResult.correlationId}
          </div>
          <table className="data-table">
            <thead><tr><th>Resource family</th><th>Status</th><th>Required permission</th></tr></thead>
            <tbody>{testResult.resourceFamilies.map((family) => (
              <tr key={family.resourceFamily}>
                <td>{family.resourceFamily.replace(/_/g, ' ')}</td>
                <td><span className={`status-pill ${family.missing.length ? 'danger' : 'success'}`}>{family.status.replace(/_/g, ' ')}</span></td>
                <td>{family.required.join(', ')}</td>
              </tr>
            ))}</tbody>
          </table>
        </section>
      )}

      {selectedProfile?.authType === 'CLIENT_SECRET' && (
        <section className="panel connector-settings">
          <div className="panel-header">
            <div>
              <h3>Credential lifecycle</h3>
              <span className="panel-caption">
                {selectedProfile.expiresAt ? `Expires ${timeAgo(selectedProfile.expiresAt) ?? selectedProfile.expiresAt}` : 'No expiry recorded'}
              </span>
            </div>
          </div>
          <div className="form-grid">
            <label>Replacement secret<input type="password" autoComplete="new-password" value={replacementSecret} onChange={(event) => setReplacementSecret(event.target.value)} /></label>
            <label>Replacement expiry<input type="datetime-local" value={replacementExpiry} onChange={(event) => setReplacementExpiry(event.target.value)} /></label>
          </div>
          <div className="ai-security-review-actions">
            <button className="btn btn-secondary" disabled={!replacementSecret || !targetId || rotateProfile.isPending} onClick={() => rotateProfile.mutate(selectedProfile)}>
              Test and promote replacement
            </button>
            <button
              className="btn btn-danger"
              onClick={() => void api.revokeAiSecurityAzureCredential(selectedProfile.id).then(() => {
                setProfileId('');
                void queryClient.invalidateQueries({ queryKey: ['ai-security-azure-credentials'] });
              })}
            >
              Emergency revoke
            </button>
          </div>
        </section>
      )}

      <section className="panel ai-connector-runs">
        <div className="panel-header">
          <div>
            <h3>Azure discovery health</h3>
            <span className="panel-caption">
              {latestSuccessfulRun
                ? `Last successful run ${timeAgo(latestSuccessfulRun.completedAt ?? latestSuccessfulRun.startedAt) ?? 'recently'}`
                : 'No successful Azure AI Security run yet'}
            </span>
          </div>
        </div>
        {(runsQuery.data ?? []).length === 0 ? (
          <div className="empty-state"><p>No Azure AI Security discovery runs yet.</p></div>
        ) : (
          <div className="ai-run-list">
            {(runsQuery.data ?? []).slice(0, 10).map((run) => (
              <article key={run.id}>
                <div>
                  <strong>{run.status.replace(/_/g, ' ')}</strong>
                  <span>{new Date(run.startedAt).toLocaleString()}</span>
                </div>
                <div>
                  <span>{run.recordsFetched} observations</span>
                  <span>{run.recordsFailed} incomplete scopes</span>
                </div>
                {run.errorMessage && <p>{run.errorMessage}</p>}
              </article>
            ))}
          </div>
        )}
        {(scopesQuery.data ?? []).length > 0 && (
          <>
            <div className="panel-header ai-scope-header">
              <div>
                <h3>Latest scope completeness</h3>
                <span className="panel-caption">Only COMPLETE scopes can deactivate inventory or resolve findings.</span>
              </div>
            </div>
            <div className="ai-scope-list">
              {(scopesQuery.data ?? []).map((scope) => {
                const diagnostic = scope.diagnostics.items?.[0];
                return (
                  <article key={scope.id}>
                    <div>
                      <strong>{scope.resourceFamily.replace(/_/g, ' ')}</strong>
                      <span className={`status-pill ${scope.status.toLowerCase()}`}>{scope.status}</span>
                    </div>
                    <p>{scope.accountId} · {scope.region}</p>
                    {diagnostic && (
                      <div className="ai-scope-diagnostic">
                        <strong>{diagnostic.code}</strong>
                        <span>{diagnostic.message}</span>
                        {diagnostic.missingPermissions.length > 0 && (
                          <small>Missing: {diagnostic.missingPermissions.join(', ')}</small>
                        )}
                        <small>
                          {diagnostic.retryable ? 'Retryable' : 'User action required'}
                          {' · '}Correlation {diagnostic.correlationId}
                        </small>
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
