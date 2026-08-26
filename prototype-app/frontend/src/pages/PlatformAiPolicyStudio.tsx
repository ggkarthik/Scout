import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { AiGridControlCoverage, AiGridCoverageStatus, AiGridPhase1CertificationReadiness, AiGridPhase1CorpusReadiness, AiGridPhase1MigrationPreview, AiGridPolicyCandidate, AiGridPolicyDistribution, AiGridPolicyImpactPreview, AiGridPolicyReleaseReadiness, AiGridPolicySelection } from '../features/ai-security/types';

const SELECTIONS: AiGridPolicySelection[] = ['REQUIRED', 'ENABLED', 'PREVIEW', 'DISABLED'];
const STAGES: AiGridPolicyDistribution['rolloutStage'][] = ['GENERAL_AVAILABILITY', 'CANARY', 'PAUSED', 'RETIRED'];
const COVERAGE_STATUS_LABELS: Record<AiGridCoverageStatus, string> = {
  AUTOMATED: 'Automated',
  CONDITIONAL_AUTOMATED: 'Conditional (needs connector capability)',
  PREVENTIVE_ONLY: 'Preventive configuration only',
  REQUIRES_RUNTIME_OR_TEST: 'Requires runtime or test evidence',
  NOT_COVERED: 'Not covered',
};

export function PlatformAiPolicyStudio() {
  const queryClient = useQueryClient();
  const catalogQuery = useQuery({ queryKey: ['platform-ai-grid-policies'], queryFn: api.listPlatformAiGridPolicies });
  const tenantsQuery = useQuery({ queryKey: ['platform-policy-preview-tenants'], queryFn: api.listTenants });
  const [tenantId, setTenantId] = React.useState('');
  React.useEffect(() => {
    if (!tenantId && tenantsQuery.data?.[0]) setTenantId(tenantsQuery.data[0].id);
  }, [tenantId, tenantsQuery.data]);
  const [preview, setPreview] = React.useState<AiGridPolicyImpactPreview | null>(null);
  const frameworkCoverageQuery = useQuery({ queryKey: ['platform-ai-grid-framework-coverage', 'OWASP_GENAI_LLM_TOP_10', '2026'], queryFn: () => api.getPlatformAiGridFrameworkCoverage('OWASP_GENAI_LLM_TOP_10', '2026') });
  const candidatesQuery = useQuery({ queryKey: ['platform-ai-grid-policy-candidates'], queryFn: api.getPlatformAiGridPolicyCandidates });
  const certificationQuery = useQuery({ queryKey: ['platform-ai-grid-phase-1-certification'], queryFn: api.getPlatformAiGridPhase1CertificationReadiness });
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
      <CertificationLedger readiness={certificationQuery.data} loading={certificationQuery.isLoading} failed={certificationQuery.isError} />
      <div className="connect-filter-bar connect-filter-bar--standalone">
        <label htmlFor="policy-preview-tenant">Impact-preview tenant</label>
        <select id="policy-preview-tenant" value={tenantId} onChange={(event) => { setTenantId(event.target.value); setPreview(null); }}>
          <option value="">Select tenant</option>{(tenantsQuery.data ?? []).map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
        </select>
      </div>
      <Phase1TenantMigration tenantId={tenantId} tenantName={(tenantsQuery.data ?? []).find((tenant) => tenant.id === tenantId)?.name} />
      {catalogQuery.isError ? <div className="notice error">The governed policy catalog could not be loaded.</div> : null}
      <div className="panel ai-security-table-panel">
        <table className="data-table"><thead><tr><th>Policy</th><th>Version</th><th>Severity</th><th>Availability</th><th>Tenant default</th><th>Rollout</th><th>Save</th></tr></thead>
          <tbody>{policies.map((policy) => <PolicyRow key={policy.policyId} policy={policy} saving={mutation.isPending} tenantId={tenantId} onPreview={setPreview} onSave={(patch, canaryTenantIds) => mutation.mutate({ policy, patch, canaryTenantIds })} />)}</tbody>
        </table>
        {!catalogQuery.isLoading && policies.length === 0 ? <div className="empty-state"><p>No governed policies are distributed yet.</p></div> : null}
      </div>
      {preview ? <ImpactPreview preview={preview} /> : null}
      <PolicyPortfolio coverage={frameworkCoverageQuery.data ?? []} candidates={candidatesQuery.data ?? []} />
    </section>
  );
}

function Phase1TenantMigration({ tenantId, tenantName }: { tenantId: string; tenantName?: string }) {
  const queryClient = useQueryClient();
  const [preview, setPreview] = React.useState<AiGridPhase1MigrationPreview | null>(null);
  const [confirmation, setConfirmation] = React.useState('');
  const previewMutation = useMutation({
    mutationFn: () => api.getPlatformAiGridPhase1MigrationPreview(tenantId),
    onSuccess: (result) => { setPreview(result); setConfirmation(''); },
  });
  const applyMutation = useMutation({
    mutationFn: () => api.applyPlatformAiGridPhase1Migration(tenantId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-policies'] });
      void previewMutation.mutate();
    },
  });
  const canApply = Boolean(preview && preview.actions.length > 0 && preview.blockers.length === 0 && confirmation === 'MIGRATE');
  return <section className="panel"><h3>Phase 1 tenant migration</h3>
    <p>Applies the approved legacy-policy ledger only to the selected tenant. It copies safe one-to-one selections/configuration, preserves history, and auto-closes only policies explicitly retired for insufficient evidence.</p>
    <div className="connect-filter-bar connect-filter-bar--standalone"><button type="button" className="btn btn-secondary" disabled={!tenantId || previewMutation.isPending} onClick={() => previewMutation.mutate()}>{previewMutation.isPending ? 'Reviewing…' : `Preview ${tenantName ?? 'tenant'} migration`}</button></div>
    {previewMutation.isError ? <p className="notice error">Migration preview could not be loaded.</p> : null}
    {preview ? <><div className="summary-strip"><span><strong>{preview.legacySelections}</strong> legacy selections</span><span><strong>{preview.selectionCopies}</strong> selection copies</span><span><strong>{preview.retirements}</strong> retirements</span><span><strong>{preview.openFindingsToClose}</strong> findings to close</span><span><strong>{preview.openFindingsReconciled}</strong> findings reconciled</span><span><strong>{preview.parameterManualReviews}</strong> manual config reviews</span></div>
      <DeprecationBanner actions={preview.actions} />
      {preview.blockers.length > 0 ? <p className="notice error">Migration blocked: {preview.blockers.join(' · ')}</p> : preview.actions.length === 0 ? <p className="notice success">No selected legacy Phase 1 policies remain for this tenant.</p> : <><details><summary>View planned migration actions</summary><table className="data-table"><thead><tr><th>Legacy policy</th><th>Disposition</th><th>Successors</th><th>Manual review</th></tr></thead><tbody>{preview.actions.map((action) => <tr key={action.legacyDetectorId}><td>{action.legacyDetectorId}</td><td>{action.disposition}</td><td>{action.selectionCopies.map((copy) => `${copy.policyId} (${copy.selection})`).join(', ') || 'Retire'}</td><td>{action.manualConfigurationReview ? 'Required' : 'None'}</td></tr>)}</tbody></table></details>
        <div className="connect-filter-bar connect-filter-bar--standalone"><input aria-label="Confirm Phase 1 migration" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} placeholder="Type MIGRATE to apply" /><button type="button" className="btn btn-danger" disabled={!canApply || applyMutation.isPending} onClick={() => applyMutation.mutate()}>{applyMutation.isPending ? 'Applying…' : 'Apply approved migration'}</button></div>
      </>}
    </> : null}
    {applyMutation.isSuccess ? <p className="notice success">Migration applied. Review any configuration marked for manual handling before the next assessment run.</p> : null}
    {applyMutation.isError ? <p className="notice error">Migration was not applied. Reload the preview and resolve any reported blocker.</p> : null}
  </section>;
}

function DeprecationBanner({ actions }: { actions: AiGridPhase1MigrationPreview['actions'] }) {
  const retired = actions.filter((action) => action.disposition === 'RETIRED_INSUFFICIENT_EVIDENCE');
  if (retired.length === 0) return null;
  return <div className="notice warning ai-policy-deprecation-banner">
    <strong>Deprecated for insufficient evidence.</strong> These legacy detectors are retired in Phase 1. Their open findings are closed with a machine-readable reason (never “remediated”), history is preserved, and each is tracked as a connector-capability backlog candidate for reactivation once evidence exists.
    <ul>{retired.map((action) => <li key={action.legacyDetectorId}><code>{action.legacyDetectorId}</code> — {action.closureReason ?? 'POLICY_RETIRED_INSUFFICIENT_EVIDENCE'}</li>)}</ul>
  </div>;
}

function CertificationLedger({ readiness, loading, failed }: { readiness?: AiGridPhase1CertificationReadiness; loading: boolean; failed: boolean }) {
  const queryClient = useQueryClient();
  const corpusQuery = useQuery({ queryKey: ['platform-ai-grid-phase-1-corpus'], queryFn: api.getPlatformAiGridPhase1CorpusReadiness });
  const [engineeringOwner, setEngineeringOwner] = React.useState('');
  const [securityReviewer, setSecurityReviewer] = React.useState('');
  const [reviewDueAt, setReviewDueAt] = React.useState('');
  const bootstrap = useMutation({
    mutationFn: () => api.bootstrapPlatformAiGridPhase1CertificationCorpus({
      engineeringOwner, securityReviewer, reviewDueAt: new Date(reviewDueAt).toISOString(),
    }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-phase-1-certification'] });
      void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-phase-1-corpus'] });
    },
  });
  const certify = useMutation({
    mutationFn: api.certifyPlatformAiGridPhase1Corpus,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-phase-1-certification'] });
      void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-phase-1-corpus'] });
    },
  });
  const canBootstrap = engineeringOwner.trim().length > 0 && securityReviewer.trim().length > 0
    && engineeringOwner.trim().toLowerCase() !== securityReviewer.trim().toLowerCase() && reviewDueAt.length > 0;
  return <section className="panel"><h3>Phase 1 certification ledger</h3>
    <p>Answer-key and precision evidence are tracked separately. Draft cases are not certified evidence.</p>
    {loading ? <p>Loading certification readiness…</p> : failed ? <div className="notice error">Certification readiness could not be loaded.</div> : readiness ? <>
      <div className="summary-strip" aria-label="Phase 1 certification summary"><span><strong>{readiness.totalPolicies}</strong> policies</span><span><strong>{readiness.answerKeyReadyPolicies}</strong> answer-key ready</span><span><strong>{readiness.precisionReadyPolicies}</strong> precision ready</span><span><strong>{readiness.releaseReadyPolicies}</strong> release ready</span><span><strong>{readiness.pendingPolicies}</strong> pending</span></div>
      <details><summary>View policies still awaiting evidence</summary><table className="data-table"><thead><tr><th>Policy</th><th>Answer key</th><th>Precision</th><th>Release</th><th>Blockers</th></tr></thead><tbody>{readiness.policies.filter((policy) => !policy.releaseReady).map((policy) => <tr key={`${policy.policyId}@${policy.version}`}><td>{policy.policyId} v{policy.version}</td><td>{policy.answerKeyReady ? 'Ready' : 'Pending'}</td><td>{policy.precisionReady ? 'Ready' : 'Pending'}</td><td>{policy.releaseReady ? 'Ready' : 'Blocked'}</td><td>{policy.blockers.join(', ')}</td></tr>)}</tbody></table></details>
    </> : null}
    <div className="connect-filter-bar connect-filter-bar--standalone"><input aria-label="Certification engineering owner" placeholder="Engineering owner" value={engineeringOwner} onChange={(event) => setEngineeringOwner(event.target.value)} /><input aria-label="Certification security reviewer" placeholder="Independent security reviewer" value={securityReviewer} onChange={(event) => setSecurityReviewer(event.target.value)} /><input aria-label="Certification review due date" type="datetime-local" value={reviewDueAt} onChange={(event) => setReviewDueAt(event.target.value)} /><button type="button" className="btn btn-secondary" disabled={!canBootstrap || bootstrap.isPending} onClick={() => bootstrap.mutate()}>{bootstrap.isPending ? 'Creating drafts…' : 'Bootstrap draft corpus'}</button></div>
    <CorpusCertification readiness={corpusQuery.data} loading={corpusQuery.isLoading} failed={corpusQuery.isError} certifying={certify.isPending} onCertify={() => certify.mutate()} />
    {bootstrap.isSuccess ? <p className="notice success">Draft corpus synchronized: {bootstrap.data.environmentsCreated} environments and {bootstrap.data.casesCreated} cases created. Platform-run evidence and independent precision review are still required.</p> : null}
    {certify.isSuccess ? <p className="notice success">Corpus certification completed for {certify.data.environmentsCertified} draft environments. This still does not create answer-key run evidence or precision labels.</p> : null}
    {bootstrap.isError ? <p className="notice error">Draft corpus could not be bootstrapped. Check independent owner/reviewer values and the review due date.</p> : null}
  </section>;
}

function CorpusCertification({ readiness, loading, failed, certifying, onCertify }: { readiness?: AiGridPhase1CorpusReadiness; loading: boolean; failed: boolean; certifying: boolean; onCertify: () => void }) {
  if (loading) return <p>Loading corpus certification state…</p>;
  if (failed) return <p className="notice error">Corpus certification state could not be loaded.</p>;
  if (!readiness) return null;
  const readyDrafts = readiness.draftEnvironments - readiness.blockedEnvironments;
  return <div className="panel"><h4>Answer-key corpus status</h4>
    <div className="summary-strip"><span><strong>{readiness.certifiedEnvironments}</strong> certified</span><span><strong>{readiness.draftEnvironments}</strong> drafts</span><span><strong>{readiness.missingEnvironments}</strong> missing</span><span><strong>{readiness.blockedEnvironments}</strong> blocked</span></div>
    <p>Certification confirms that the corpus shape is complete; it is not a platform-run result. {readyDrafts > 0 ? `${readyDrafts} draft environment(s) can be certified.` : 'No draft environments are ready to certify.'}</p>
    <button type="button" className="btn btn-secondary" disabled={readyDrafts <= 0 || certifying} onClick={onCertify}>{certifying ? 'Certifying corpus…' : 'Certify complete corpus drafts'}</button>
    {readiness.blockedEnvironments > 0 ? <details><summary>View blocked environments</summary><ul>{readiness.environments.filter((environment) => environment.certificationBlockers.length > 0).map((environment) => <li key={environment.policyId}>{environment.policyId}: {environment.certificationBlockers.join(', ')}</li>)}</ul></details> : null}
  </div>;
}

function PolicyPortfolio({ coverage, candidates }: { coverage: AiGridControlCoverage[]; candidates: AiGridPolicyCandidate[] }) {
  const queryClient = useQueryClient();
  const [title, setTitle] = React.useState('');
  const [rationale, setRationale] = React.useState('');
  const [sourceType, setSourceType] = React.useState('COVERAGE_GAP');
  const create = useMutation({ mutationFn: () => api.createPlatformAiGridPolicyCandidate({ title, rationale, sourceType, status: 'INTAKE', frameworkMappings: {}, riskScore: 3, reachScore: 3, evidenceMaturity: 3, remediationClarity: 3 }), onSuccess: () => { setTitle(''); setRationale(''); void queryClient.invalidateQueries({ queryKey: ['platform-ai-grid-policy-candidates'] }); } });
  return <section className="panel"><h3>Policy portfolio</h3><p>Prioritize new controls by customer risk, expected reach, evidence maturity, and remediation clarity.</p>
    <FrameworkCoveragePanel coverage={coverage} />
    <div className="connect-filter-bar connect-filter-bar--standalone"><input aria-label="Candidate policy title" value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Candidate policy title" /><select aria-label="Candidate source" value={sourceType} onChange={(event) => setSourceType(event.target.value)}><option>COVERAGE_GAP</option><option>CONNECTOR_CAPABILITY</option><option>THREAT_RESEARCH</option><option>CUSTOMER_REQUEST</option><option>INCIDENT</option><option>COMPLIANCE_FRAMEWORK</option><option>DESIGN_PARTNER</option></select><input aria-label="Candidate rationale" value={rationale} onChange={(event) => setRationale(event.target.value)} placeholder="Why this control matters" /><button type="button" className="btn btn-secondary" disabled={!title.trim() || !rationale.trim() || create.isPending} onClick={() => create.mutate()}>Add candidate</button></div>
    {candidates.length > 0 ? <table className="data-table"><thead><tr><th>Candidate</th><th>Source</th><th>Status</th><th>Evidence</th><th>Priority</th></tr></thead><tbody>{candidates.map((candidate) => <tr key={candidate.id}><td>{candidate.title}</td><td>{candidate.sourceType}</td><td>{candidate.status}</td><td>{candidate.evidenceMaturity}/5</td><td>{candidate.priorityScore}</td></tr>)}</tbody></table> : <p>No policy candidates have been recorded yet.</p>}
  </section>;
}

function FrameworkCoveragePanel({ coverage }: { coverage: AiGridControlCoverage[] }) {
  return <div className="panel"><h4>OWASP GenAI LLM Top 10 (2026) coverage</h4>
    <p>Independently authored mappings that communicate risk alignment — not framework certification or complete runtime protection. Coverage status reflects the evidence Phase 1 can actually decide.</p>
    {coverage.length === 0 ? <p>No framework coverage is available yet.</p> : <table className="data-table"><thead><tr><th>Control</th><th>Coverage status</th><th>Mapped policies</th></tr></thead>
      <tbody>{coverage.map((control) => <tr key={control.controlId}>
        <td><strong>{control.controlId}</strong></td>
        <td><span className={`coverage-status coverage-status--${control.coverageStatus.toLowerCase()}`}>{COVERAGE_STATUS_LABELS[control.coverageStatus] ?? control.coverageStatus}</span></td>
        <td>{control.policies.length === 0 ? <em>No mapped policy</em> : <ul className="coverage-mapping-list">{control.policies.map((policy) => <li key={policy.policyId}><strong>{policy.policyId}</strong> <span className="coverage-mapping-type">{policy.mappingType}</span>{policy.conditional ? <span className="coverage-conditional"> · conditional</span> : null}<br /><small>{policy.rationale}</small></li>)}</ul>}</td>
      </tr>)}</tbody></table>}
  </div>;
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
