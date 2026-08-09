import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { AiGridOwaspCoverage, AiGridPolicyCandidate, AiGridPolicyDistribution, AiGridPolicyImpactPreview, AiGridPolicyReleaseReadiness, AiGridPolicySelection, AiGridPolicyTenantReconciliation } from '../features/ai-security/types';

const SELECTIONS: AiGridPolicySelection[] = ['REQUIRED', 'ENABLED', 'PREVIEW', 'DISABLED'];
const STAGES: AiGridPolicyDistribution['rolloutStage'][] = ['GENERAL_AVAILABILITY', 'CANARY', 'PAUSED', 'RETIRED'];

export function PlatformAiPolicyStudio() {
  const queryClient = useQueryClient();
  const catalogQuery = useQuery({ queryKey: ['platform-ai-grid-policies'], queryFn: api.listPlatformAiGridPolicies });
  const tenantsQuery = useQuery({ queryKey: ['platform-policy-preview-tenants'], queryFn: api.listTenants });
  const [tenantId, setTenantId] = React.useState('');
  React.useEffect(() => {
    if (!tenantId && tenantsQuery.data?.[0]) setTenantId(tenantsQuery.data[0].id);
  }, [tenantId, tenantsQuery.data]);
  const [preview, setPreview] = React.useState<AiGridPolicyImpactPreview | null>(null);
  const [reconciliation, setReconciliation] = React.useState<AiGridPolicyTenantReconciliation[] | null>(null);
  const retirementQuery = useQuery({ queryKey: ['platform-ai-grid-policy-retirement'], queryFn: api.getPlatformAiGridPolicyRetirementStatus });
  const owaspQuery = useQuery({ queryKey: ['platform-ai-grid-policy-owasp'], queryFn: api.getPlatformAiGridOwaspCoverage });
  const candidatesQuery = useQuery({ queryKey: ['platform-ai-grid-policy-candidates'], queryFn: api.getPlatformAiGridPolicyCandidates });
  const reconciliationQuery = useMutation({ mutationFn: api.getPlatformAiGridPolicyReconciliation, onSuccess: setReconciliation });
  const migrationQuery = useMutation({ mutationFn: api.migratePlatformAiGridLegacySelections, onSuccess: setReconciliation });
  const mutation = useMutation({
    mutationFn: ({ policy, patch, canaryTenantIds }: { policy: AiGridPolicyDistribution; patch: Partial<AiGridPolicyDistribution>; canaryTenantIds?: string[] }) => api.updatePlatformAiGridPolicyDistribution(policy.policyId, {
      available: patch.available ?? policy.available,
      defaultSelection: patch.defaultSelection ?? policy.defaultSelection,
      rolloutStage: patch.rolloutStage ?? policy.rolloutStage,
      pinnedVersion: patch.pinnedVersion ?? policy.pinnedVersion,
      canaryTenantIds: canaryTenantIds ?? JSON.parse(policy.canaryTenantIdsJson || '[]'),
    }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-policies'] }),
  });
  const policies = catalogQuery.data ?? [];
  const counts = policies.reduce((result, policy) => ({
    total: result.total + 1,
    defaultEnforced: result.defaultEnforced + (policy.available && ['REQUIRED', 'ENABLED'].includes(policy.defaultSelection) ? 1 : 0),
    preview: result.preview + (policy.defaultSelection === 'PREVIEW' ? 1 : 0),
  }), { total: 0, defaultEnforced: 0, preview: 0 });

  return (
    <section className="platform-ai-policy-studio">
      <header className="ai-security-hero policies">
        <div><span className="ai-security-kicker">Platform-owned, versioned controls</span><h2>AI Policy Studio</h2>
          <p>Review catalog distribution and release state. New definitions are imported from reviewed Git policy packages.</p></div>
      </header>
      <div className="summary-strip" aria-label="AI policy catalog summary">
        <span><strong>{counts.total}</strong> catalog policies</span><span><strong>{counts.defaultEnforced}</strong> default-enforced</span><span><strong>{counts.preview}</strong> Preview</span>
      </div>
      <div className="connect-filter-bar connect-filter-bar--standalone">
        <label htmlFor="policy-preview-tenant">Impact-preview tenant</label>
        <select id="policy-preview-tenant" value={tenantId} onChange={(event) => { setTenantId(event.target.value); setPreview(null); }}>
          <option value="">Select tenant</option>{(tenantsQuery.data ?? []).map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
        </select>
      </div>
      {catalogQuery.isError ? <div className="notice error">The governed policy catalog could not be loaded.</div> : null}
      <div className="panel ai-security-table-panel">
        <table className="data-table"><thead><tr><th>Policy</th><th>Version</th><th>Severity</th><th>Availability</th><th>Tenant default</th><th>Rollout</th><th>Save</th></tr></thead>
          <tbody>{policies.map((policy) => <PolicyRow key={policy.policyId} policy={policy} saving={mutation.isPending} tenantId={tenantId} onPreview={setPreview} onSave={(patch, canaryTenantIds) => mutation.mutate({ policy, patch, canaryTenantIds })} />)}</tbody>
        </table>
        {!catalogQuery.isLoading && policies.length === 0 ? <div className="empty-state"><p>No governed policies are distributed yet.</p></div> : null}
      </div>
      {preview ? <ImpactPreview preview={preview} /> : null}
      <PolicyPortfolio owasp={owaspQuery.data ?? []} candidates={candidatesQuery.data ?? []} />
      <section className="panel"><h3>Legacy migration reconciliation</h3><p>Verify that legacy settings and policy-linked data have governed equivalents before retiring compatibility reads.</p>
        {retirementQuery.data ? <p><strong>{retirementQuery.data.eligibleForRetirement ? 'Ready to retire compatibility reads' : 'Compatibility reads still required'}</strong> — {retirementQuery.data.unmappedRecordCount} unmapped record(s) across {retirementQuery.data.activeTenantCount} active tenant(s). The deployment flag is currently {retirementQuery.data.legacyFallbackEnabled ? 'enabled' : 'disabled'}.</p> : null}
        <button type="button" className="btn btn-secondary" disabled={reconciliationQuery.isPending} onClick={() => reconciliationQuery.mutate()}>Run reconciliation</button>
        <button type="button" className="btn btn-link" disabled={migrationQuery.isPending} onClick={() => migrationQuery.mutate()}>Migrate remaining legacy selections</button>
        {reconciliation ? <table className="data-table"><thead><tr><th>Tenant</th><th>Legacy</th><th>Governed</th><th>Unmapped records</th></tr></thead><tbody>{reconciliation.map((row) => <tr key={row.tenantId}><td>{row.tenantName}</td><td>{row.legacySelections}</td><td>{row.governedSelections}</td><td>{row.unmappedLegacySelections + row.unmappedScopes + row.unmappedExceptions + row.unmappedParameters + row.unmappedFindings}</td></tr>)}</tbody></table> : null}
      </section>
    </section>
  );
}

function PolicyPortfolio({ owasp, candidates }: { owasp: AiGridOwaspCoverage[]; candidates: AiGridPolicyCandidate[] }) {
  const queryClient = useQueryClient();
  const [title, setTitle] = React.useState('');
  const [rationale, setRationale] = React.useState('');
  const [sourceType, setSourceType] = React.useState('COVERAGE_GAP');
  const create = useMutation({ mutationFn: () => api.createPlatformAiGridPolicyCandidate({ title, rationale, sourceType, status: 'INTAKE', frameworkMappings: {}, riskScore: 3, reachScore: 3, evidenceMaturity: 3, remediationClarity: 3 }), onSuccess: () => { setTitle(''); setRationale(''); void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-policy-candidates'] }); } });
  return <section className="panel"><h3>Policy portfolio</h3><p>Prioritize new controls by customer risk, expected reach, evidence maturity, and remediation clarity.</p>
    <div className="summary-strip">{owasp.map((item) => <span key={item.owaspId}><strong>{item.owaspId}</strong> {item.publishedPolicyCount === 0 ? 'unmapped' : `${item.publishedPolicyCount} control(s)`}</span>)}</div>
    <div className="connect-filter-bar connect-filter-bar--standalone"><input aria-label="Candidate policy title" value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Candidate policy title" /><select aria-label="Candidate source" value={sourceType} onChange={(event) => setSourceType(event.target.value)}><option>COVERAGE_GAP</option><option>CONNECTOR_CAPABILITY</option><option>THREAT_RESEARCH</option><option>CUSTOMER_REQUEST</option><option>INCIDENT</option><option>COMPLIANCE_FRAMEWORK</option><option>DESIGN_PARTNER</option></select><input aria-label="Candidate rationale" value={rationale} onChange={(event) => setRationale(event.target.value)} placeholder="Why this control matters" /><button type="button" className="btn btn-secondary" disabled={!title.trim() || !rationale.trim() || create.isPending} onClick={() => create.mutate()}>Add candidate</button></div>
    {candidates.length > 0 ? <table className="data-table"><thead><tr><th>Candidate</th><th>Source</th><th>Status</th><th>Evidence</th><th>Priority</th></tr></thead><tbody>{candidates.map((candidate) => <tr key={candidate.id}><td>{candidate.title}</td><td>{candidate.sourceType}</td><td>{candidate.status}</td><td>{candidate.evidenceMaturity}/5</td><td>{candidate.priorityScore}</td></tr>)}</tbody></table> : <p>No policy candidates have been recorded yet.</p>}
  </section>;
}

function PolicyRow({ policy, saving, tenantId, onPreview, onSave }: { policy: AiGridPolicyDistribution; saving: boolean; tenantId: string; onPreview: (preview: AiGridPolicyImpactPreview) => void; onSave: (patch: Partial<AiGridPolicyDistribution>, canaryTenantIds: string[]) => void }) {
  const [draft, setDraft] = React.useState<Partial<AiGridPolicyDistribution>>({});
  const [canaryTenantIds, setCanaryTenantIds] = React.useState<string[]>(() => JSON.parse(policy.canaryTenantIdsJson || '[]'));
  const value = <K extends keyof AiGridPolicyDistribution>(key: K) => draft[key] ?? policy[key];
  return <tr><td><strong>{policy.name}</strong><br /><small>{policy.policyId}</small></td><td>{policy.version}</td><td>{policy.severity}</td>
    <td><input aria-label={`${policy.name} availability`} type="checkbox" checked={Boolean(value('available'))} onChange={(event) => setDraft((current) => ({ ...current, available: event.target.checked }))} /></td>
    <td><select aria-label={`${policy.name} tenant default`} value={String(value('defaultSelection'))} onChange={(event) => setDraft((current) => ({ ...current, defaultSelection: event.target.value as AiGridPolicySelection }))}>{SELECTIONS.map((option) => <option key={option}>{option}</option>)}</select></td>
    <td><select aria-label={`${policy.name} rollout`} value={String(value('rolloutStage'))} onChange={(event) => setDraft((current) => ({ ...current, rolloutStage: event.target.value as AiGridPolicyDistribution['rolloutStage'] }))}>{STAGES.map((option) => <option key={option}>{option}</option>)}</select></td>
    <td>{String(value('rolloutStage')) === 'CANARY' ? <span><button type="button" className="btn btn-link" disabled={!tenantId || canaryTenantIds.includes(tenantId)} onClick={() => setCanaryTenantIds((current) => [...current, tenantId])}>Add selected tenant</button><small>{canaryTenantIds.length} tenant(s) in cohort</small></span> : null}
      <button type="button" className="btn btn-secondary" disabled={saving || (Object.keys(draft).length === 0 && JSON.stringify(canaryTenantIds) === policy.canaryTenantIdsJson)} onClick={() => { onSave(draft, canaryTenantIds); setDraft({}); }}>Save</button>
      <PreviewButton policy={policy} tenantId={tenantId} onPreview={onPreview} /> <ReleaseButton policy={policy} /></td></tr>;
}

function PreviewButton({ policy, tenantId, onPreview }: { policy: AiGridPolicyDistribution; tenantId: string; onPreview: (preview: AiGridPolicyImpactPreview) => void }) {
  const previewMutation = useMutation({ mutationFn: () => api.getPlatformAiGridPolicyImpactPreview(policy.policyId, policy.version, tenantId), onSuccess: onPreview });
  return <button type="button" className="btn btn-link" disabled={!tenantId || previewMutation.isPending} onClick={() => previewMutation.mutate()}>{previewMutation.isPending ? 'Previewing…' : 'Preview impact'}</button>;
}

function ImpactPreview({ preview }: { preview: AiGridPolicyImpactPreview }) {
  const missing = Object.entries(preview.missingFacts).sort((left, right) => right[1] - left[1]);
  return <section className="panel"><h3>Impact preview</h3><p>{preview.policyId} v{preview.version} against the selected tenant’s latest collected facts. This preview does not create findings.</p>
    <div className="summary-strip"><span><strong>{preview.applicableArtifacts}</strong> candidates</span><span><strong>{preview.expectedFail}</strong> expected fail</span><span><strong>{preview.expectedPass}</strong> expected pass</span><span><strong>{preview.expectedNoDecision}</strong> no decision</span><span><strong>{preview.expectedNotApplicable}</strong> not applicable</span></div>
    {missing.length > 0 ? <p><strong>Missing evidence:</strong> {missing.map(([fact, count]) => `${fact} (${count})`).join(' · ')}</p> : <p>All applicable artifacts have the candidate’s required facts.</p>}
  </section>;
}

function ReleaseButton({ policy }: { policy: AiGridPolicyDistribution }) {
  const [readiness, setReadiness] = React.useState<AiGridPolicyReleaseReadiness | null>(null);
  const readinessMutation = useMutation({ mutationFn: () => api.getPlatformAiGridPolicyReleaseReadiness(policy.policyId, policy.version), onSuccess: setReadiness });
  const publishMutation = useMutation({ mutationFn: () => api.publishPlatformAiGridPolicy(policy.policyId, policy.version), onSuccess: () => void readinessMutation.mutate() });
  return <span><button type="button" className="btn btn-link" disabled={readinessMutation.isPending} onClick={() => readinessMutation.mutate()}>Release gate</button>
    {readiness ? <span title={readiness.blockers.join(' · ')}>{readiness.ready ? <button type="button" className="btn btn-link" disabled={publishMutation.isPending} onClick={() => publishMutation.mutate()}>Publish</button> : <small>Blocked: {readiness.blockers.join(', ')}</small>}</span> : null}</span>;
}
