import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api } from '../api/client';
import type { AiSecurityConnectionTest } from '../features/ai-security/types';

const DEFAULT_REGIONS = ['us-east-1', 'us-west-2'];

export function AiSecurityConnectorPage() {
  const queryClient = useQueryClient();
  const configQuery = useQuery({
    queryKey: ['ai-security-connector'],
    queryFn: api.getAiSecurityConnector,
  });
  const runsQuery = useQuery({
    queryKey: ['ai-security-runs'],
    queryFn: api.listAiSecurityRuns,
  });
  const latestRunId = runsQuery.data?.[0]?.id;
  const scopesQuery = useQuery({
    queryKey: ['ai-security-run-scopes', latestRunId],
    queryFn: () => api.listAiSecurityRunScopes(latestRunId as string),
    enabled: latestRunId != null,
  });
  const [accountId, setAccountId] = React.useState('');
  const [roleArn, setRoleArn] = React.useState('');
  const [externalId, setExternalId] = React.useState('');
  const [regions, setRegions] = React.useState(DEFAULT_REGIONS.join(', '));
  const [enabled, setEnabled] = React.useState(true);
  const [testResult, setTestResult] = React.useState<AiSecurityConnectionTest | null>(null);

  React.useEffect(() => {
    const config = configQuery.data;
    if (!config) return;
    setAccountId(config.accountId);
    setRoleArn(config.roleArn ?? '');
    setRegions(config.regions.join(', '));
    setEnabled(config.enabled);
  }, [configQuery.data]);

  const saveMutation = useMutation({
    mutationFn: () => api.saveAiSecurityConnector({
      accountId,
      roleArn: roleArn || undefined,
      externalId: externalId || undefined,
      regions: regions.split(',').map((region) => region.trim()).filter(Boolean),
      enabled,
    }),
    onSuccess: () => {
      setExternalId('');
      void queryClient.invalidateQueries({ queryKey: ['ai-security-connector'] });
    },
  });
  const testMutation = useMutation({
    mutationFn: api.testAiSecurityConnector,
    onSuccess: setTestResult,
  });
  const runMutation = useMutation({
    mutationFn: api.runAiSecurityConnector,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-runs'] }),
  });

  return (
    <div className="ai-connector-layout">
      <section className="ai-security-hero connector">
        <div>
          <span className="ai-security-kicker">Inventory · AI</span>
          <h2>AWS Bedrock Discovery</h2>
          <p>Read-only inventory and configuration evidence using short-lived AWS credentials.</p>
        </div>
        <span className={`status-pill ${configQuery.data?.enabled ? 'success' : 'muted'}`}>
          {configQuery.data ? (configQuery.data.enabled ? 'Configured' : 'Disabled') : 'Not configured'}
        </span>
      </section>

      <div className="ai-connector-columns">
        <section className="panel ai-connector-form">
          <div className="panel-header"><div><h3>Connection</h3><span className="panel-caption">Static AWS access keys are not accepted.</span></div></div>
          <label>AWS account ID<input value={accountId} onChange={(event) => setAccountId(event.target.value)} placeholder="123456789012" /></label>
          <label>Cross-account role ARN<input value={roleArn} onChange={(event) => setRoleArn(event.target.value)} placeholder="arn:aws:iam::123456789012:role/ScoutAiSecurity" /></label>
          <label>External ID<input type="password" value={externalId} onChange={(event) => setExternalId(event.target.value)} placeholder={configQuery.data ? 'Leave blank to keep or replace securely' : 'Optional but recommended'} /></label>
          <label>Regions<input value={regions} onChange={(event) => setRegions(event.target.value)} placeholder="us-east-1, us-west-2" /></label>
          <label className="ai-connector-enabled"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />Enable scheduled discovery</label>
          {saveMutation.isError && <div className="notice error">{saveMutation.error.message}</div>}
          {testResult && (
            <div className={`notice ${testResult.success ? 'success' : 'error'}`}>
              <strong>{testResult.message}</strong>
              {testResult.missingPermissions.length > 0 && <p>Missing: {testResult.missingPermissions.join(', ')}</p>}
              {!testResult.success && testResult.code && <small>Code: {testResult.code}</small>}
            </div>
          )}
          <div className="ai-connector-actions">
            <button className="btn btn-primary" type="button" onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>Save connection</button>
            <button className="btn btn-secondary" type="button" onClick={() => testMutation.mutate()} disabled={!configQuery.data || testMutation.isPending}>Test</button>
            <button className="btn btn-secondary" type="button" onClick={() => runMutation.mutate()} disabled={!configQuery.data?.enabled || runMutation.isPending}>Run discovery</button>
          </div>
        </section>

        <section className="panel ai-connector-runs">
          <div className="panel-header"><div><h3>Recent runs</h3><span className="panel-caption">Scope failures retain prior inventory and findings.</span></div></div>
          {(runsQuery.data ?? []).length === 0 ? (
            <div className="empty-state"><p>No AI Security discovery runs yet.</p></div>
          ) : (
            <div className="ai-run-list">
              {(runsQuery.data ?? []).slice(0, 10).map((run) => (
                <article key={run.id}>
                  <div><strong>{run.status.replace(/_/g, ' ')}</strong><span>{new Date(run.startedAt).toLocaleString()}</span></div>
                  <div><span>{run.recordsFetched} observations</span><span>{run.recordsFailed} failed scopes</span></div>
                  {run.errorMessage && <p>{run.errorMessage}</p>}
                </article>
              ))}
            </div>
          )}
          {(scopesQuery.data ?? []).length > 0 && (
            <>
              <div className="panel-header ai-scope-header">
                <div><h3>Latest scope coverage</h3><span className="panel-caption">Only complete scopes are authoritative.</span></div>
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
                      <p>{scope.accountId} · {scope.region} · {scope.acceptedChunks}/{scope.expectedChunks} chunks</p>
                      {diagnostic && (
                        <div className="ai-scope-diagnostic">
                          <strong>{diagnostic.code}</strong>
                          <span>{diagnostic.message}</span>
                          {diagnostic.missingPermissions.length > 0 && (
                            <small>Missing: {diagnostic.missingPermissions.join(', ')}</small>
                          )}
                          <small>{diagnostic.retryable ? 'Retryable' : 'User action required'} · Correlation {diagnostic.correlationId}</small>
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
    </div>
  );
}
