import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { formatDate, formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import type {
  AiSecurityFinding,
  PolicyExceptionOverride,
  PolicyScopeCondition,
  PolicyScopeMode,
} from '../features/ai-security/types';
import { timeAgo } from '../lib/time';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
type PolicyDetailTab = 'overview' | 'configure' | 'findings' | 'artifacts';

const SCOPE_FIELD_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'ARTIFACT_TYPE', label: 'Artifact type' },
  { value: 'PROVIDER', label: 'Provider' },
  { value: 'REGION', label: 'Region' },
  { value: 'ACCOUNT_ID', label: 'Account ID' },
  { value: 'NATIVE_KIND', label: 'Native type' },
  { value: 'NAME', label: 'Name' },
];

const SCOPE_OPERATOR_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'EQUALS', label: 'is' },
  { value: 'NOT_EQUALS', label: 'is not' },
  { value: 'CONTAINS', label: 'contains' },
  { value: 'NOT_CONTAINS', label: 'does not contain' },
];

const SCOPE_MODE_OPTIONS: Array<{ value: PolicyScopeMode; label: string }> = [
  { value: 'ALL', label: 'All AI inventory' },
  { value: 'MATCH_RULES', label: 'Match rules' },
  { value: 'CUSTOM_LIST', label: 'Custom list' },
];

type ImpactedArtifact = {
  artifactId: string;
  artifactName: string;
  openFindings: number;
  totalFindings: number;
  worstSeverity: string;
  lastObservedAt: string;
};

function buildImpactedArtifacts(findings: AiSecurityFinding[]): ImpactedArtifact[] {
  const byArtifact = new Map<string, ImpactedArtifact>();
  findings.forEach((finding) => {
    const isOpen = finding.status === 'OPEN';
    const existing = byArtifact.get(finding.artifactId);
    if (!existing) {
      byArtifact.set(finding.artifactId, {
        artifactId: finding.artifactId,
        artifactName: finding.artifactName,
        openFindings: isOpen ? 1 : 0,
        totalFindings: 1,
        worstSeverity: finding.severity,
        lastObservedAt: finding.lastObservedAt,
      });
      return;
    }
    existing.totalFindings += 1;
    if (isOpen) existing.openFindings += 1;
    if ((SEVERITY_RANK[finding.severity.toUpperCase()] ?? 99) < (SEVERITY_RANK[existing.worstSeverity.toUpperCase()] ?? 99)) {
      existing.worstSeverity = finding.severity;
    }
    if (new Date(finding.lastObservedAt).getTime() > new Date(existing.lastObservedAt).getTime()) {
      existing.lastObservedAt = finding.lastObservedAt;
    }
  });
  return Array.from(byArtifact.values())
    .sort((left, right) => (SEVERITY_RANK[left.worstSeverity.toUpperCase()] ?? 99) - (SEVERITY_RANK[right.worstSeverity.toUpperCase()] ?? 99));
}

function coverageStatusLabel(status: 'PASS' | 'FAIL' | 'NO_DATA'): string {
  if (status === 'NO_DATA') return 'Coverage not measured';
  return status === 'PASS' ? 'Pilot coverage gate passed' : 'Pilot coverage gate blocked';
}

type DraftScope = {
  mode: PolicyScopeMode;
  conditionLogic: 'AND' | 'OR';
  conditions: PolicyScopeCondition[];
};

export function AiPolicyDetailPage({ policyId }: { policyId: string }) {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const canManage = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'PLATFORM_OWNER') || hasRole(actor, 'SECURITY_ANALYST');
  const [tab, setTab] = React.useState<PolicyDetailTab>('overview');
  const [findingsStatusFilter, setFindingsStatusFilter] = React.useState('OPEN');

  const policiesQuery = useQuery({
    queryKey: ['ai-security-policies'],
    queryFn: api.listAiSecurityPolicies,
  });
  const findingsQuery = useQuery({
    queryKey: ['ai-security-findings-for-policy', policyId],
    queryFn: () => api.listAiSecurityFindings(policyId, undefined, 0, 200),
  });
  const mutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.updateAiSecurityPolicy(id, enabled),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-policies'] }),
  });

  const policy = policiesQuery.data?.find((item) => item.id === policyId) ?? null;
  const allFindings = React.useMemo(() => findingsQuery.data?.items ?? [], [findingsQuery.data?.items]);
  const visibleFindings = React.useMemo(() => (
    findingsStatusFilter ? allFindings.filter((finding) => finding.status === findingsStatusFilter) : allFindings
  ), [allFindings, findingsStatusFilter]);
  const impactedArtifacts = React.useMemo(() => buildImpactedArtifacts(allFindings), [allFindings]);

  const configQuery = useQuery({
    queryKey: ['ai-security-policy-configuration', policyId],
    queryFn: () => api.getAiSecurityPolicyConfiguration(policyId),
  });
  const configuration = configQuery.data ?? null;

  const [draftScope, setDraftScope] = React.useState<DraftScope | null>(null);
  const [scopeDirty, setScopeDirty] = React.useState(false);
  React.useEffect(() => {
    if (configuration && !scopeDirty) {
      setDraftScope({
        mode: configuration.scope.mode,
        conditionLogic: configuration.scope.conditionLogic,
        conditions: configuration.scope.conditions,
      });
    }
  }, [configuration, scopeDirty]);

  const [draftParameters, setDraftParameters] = React.useState<Record<string, string>>({});
  const [parametersDirty, setParametersDirty] = React.useState(false);
  React.useEffect(() => {
    if (configuration && !parametersDirty) {
      const next: Record<string, string> = {};
      configuration.parameters.forEach((param) => { next[param.key] = param.value; });
      setDraftParameters(next);
    }
  }, [configuration, parametersDirty]);

  const refreshAfterConfigChange = React.useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['ai-security-findings-for-policy', policyId] });
    void queryClient.invalidateQueries({ queryKey: ['ai-security-policies'] });
  }, [queryClient, policyId]);

  const scopeMutation = useMutation({
    mutationFn: () => {
      if (!draftScope) throw new Error('Scope is not loaded yet');
      return api.updateAiSecurityPolicyScope(policyId, draftScope.mode, draftScope.conditionLogic, draftScope.conditions);
    },
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      setScopeDirty(false);
      refreshAfterConfigChange();
    },
  });

  const parametersMutation = useMutation({
    mutationFn: () => api.updateAiSecurityPolicyParameters(policyId, draftParameters),
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      setParametersDirty(false);
      refreshAfterConfigChange();
    },
  });

  const candidateArtifactType = policy?.artifactTypes[0];
  const candidateArtifactsQuery = useQuery({
    queryKey: ['ai-security-artifacts-for-exception', candidateArtifactType],
    queryFn: () => api.listAiSecurityArtifacts(candidateArtifactType, 0, 200),
    enabled: tab === 'configure' && !!candidateArtifactType,
  });
  const [exceptionArtifactId, setExceptionArtifactId] = React.useState('');
  const [exceptionOverride, setExceptionOverride] = React.useState<PolicyExceptionOverride>('EXCLUDED');
  const [exceptionReason, setExceptionReason] = React.useState('');

  const addExceptionMutation = useMutation({
    mutationFn: () => api.addAiSecurityPolicyException(policyId, exceptionArtifactId, exceptionOverride, exceptionReason || undefined),
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      setExceptionArtifactId('');
      setExceptionReason('');
      refreshAfterConfigChange();
    },
  });
  const removeExceptionMutation = useMutation({
    mutationFn: (artifactId: string) => api.removeAiSecurityPolicyException(policyId, artifactId),
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      refreshAfterConfigChange();
    },
  });

  const explainQuery = useQuery({
    queryKey: ['ai-security-policy-explain', policyId],
    queryFn: () => api.explainAiSecurityPolicy(policyId),
    enabled: false,
  });

  const updateCondition = (index: number, next: PolicyScopeCondition) => {
    if (!draftScope) return;
    const conditions = draftScope.conditions.slice();
    conditions[index] = next;
    setDraftScope({ ...draftScope, conditions });
    setScopeDirty(true);
  };
  const removeCondition = (index: number) => {
    if (!draftScope) return;
    setDraftScope({ ...draftScope, conditions: draftScope.conditions.filter((_, i) => i !== index) });
    setScopeDirty(true);
  };
  const addCondition = () => {
    if (!draftScope) return;
    setDraftScope({
      ...draftScope,
      conditions: [...draftScope.conditions, { field: 'ARTIFACT_TYPE', operator: 'EQUALS', value: '' }],
    });
    setScopeDirty(true);
  };

  if (policiesQuery.isLoading) {
    return <section className="panel"><div className="empty-state"><p>Loading policy…</p></div></section>;
  }
  if (policiesQuery.isError) {
    return <section className="panel"><div className="notice error">AI Security policies could not be loaded.</div></section>;
  }
  if (!policy) {
    return (
      <section className="panel">
        <div className="empty-state">
          <p>Policy <strong>{policyId}</strong> was not found.</p>
          <button type="button" className="btn btn-secondary" onClick={() => navigate('/policies')}>← Back to Policies</button>
        </div>
      </section>
    );
  }

  return (
    <div className="cvd2-page ai-policy-detail-page">
      <div className="ai-policy-detail-topbar">
        <button type="button" className="cvd-ov-link" onClick={() => navigate('/policies')}>← Back to Policies</button>
        <label className="ai-policy-switch">
          <input
            type="checkbox"
            checked={policy.enabled}
            disabled={!canManage || mutation.isPending}
            onChange={(event) => mutation.mutate({ id: policy.id, enabled: event.target.checked })}
          />
          <span>{policy.enabled ? 'Enabled' : 'Disabled'}</span>
        </label>
      </div>

      <div className="cvd2-tab-bar">
        <button type="button" className={`cvd2-tab${tab === 'overview' ? ' active' : ''}`} onClick={() => setTab('overview')}>
          Overview
        </button>
        <button type="button" className={`cvd2-tab${tab === 'configure' ? ' active' : ''}`} onClick={() => setTab('configure')}>
          Configure
        </button>
        <button type="button" className={`cvd2-tab${tab === 'findings' ? ' active' : ''}`} onClick={() => setTab('findings')}>
          Findings · {policy.openFindings}
        </button>
        <button type="button" className={`cvd2-tab${tab === 'artifacts' ? ' active' : ''}`} onClick={() => setTab('artifacts')}>
          AI Artifacts · {impactedArtifacts.length}
        </button>
      </div>

      <div className="cvd2-tab-content">
        {tab === 'overview' && (
          <div className="cvd2-overview-body">
            <div className="cvd2-overview-main">
              <div className="cvd2-panel">
                <div className="cvd-ov-left">
                  <div className="cvd-ov-meta">
                    <span className={`cvd-status-pill ${policy.enabled ? 'cvd-status-ok' : 'cvd-status-neutral'}`}>
                      {policy.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    {policy.lastEvaluatedAt && (
                      <span className="cvd-ov-meta-eval">· Last evaluated {formatDate(policy.lastEvaluatedAt)}</span>
                    )}
                  </div>
                  <div className="cvd-ov-first-seen">{policy.id} · v{policy.version}</div>
                  <h1 className="cvd-ov-cve-id">{policy.name}</h1>
                  <div className="cvd-ov-badges">
                    <span className={severityClassName(policy.severity)}>{policy.severity}</span>
                    <span className="cvd-signal-pill">Coverage {Math.round(policy.decisionCoverage * 100)}%</span>
                    <span className="cvd-signal-pill">{policy.openFindings} open finding{policy.openFindings === 1 ? '' : 's'}</span>
                    <span className="cvd-signal-pill">{impactedArtifacts.length} artifact{impactedArtifacts.length === 1 ? '' : 's'} impacted</span>
                    <span className="cvd-signal-pill">{policy.requiredResourceFamilies.length} evidence source{policy.requiredResourceFamilies.length === 1 ? '' : 's'}</span>
                    {configuration && configuration.scope.mode !== 'ALL' && (
                      <span className="cvd-signal-pill ai-policy-scope-pill">
                        Scoped · {configuration.matchedArtifactCount} of {configuration.totalArtifactCount}
                      </span>
                    )}
                  </div>
                </div>
                <p className="cvd-ov-description">{policy.description}</p>
                <div className="cvd-ov-divider" />
                <div className="cvd-ov-links">
                  <button type="button" className="cvd-ov-link" onClick={() => setTab('configure')}>
                    Configure scope and parameters →
                  </button>
                  <button type="button" className="cvd-ov-link" onClick={() => setTab('findings')}>
                    {policy.openFindings} open finding{policy.openFindings === 1 ? '' : 's'} →
                  </button>
                  <button type="button" className="cvd-ov-link" onClick={() => setTab('artifacts')}>
                    {impactedArtifacts.length} AI artifact{impactedArtifacts.length === 1 ? '' : 's'} impacted →
                  </button>
                </div>
              </div>

              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Policy Details</div>
                <div className="cvd-tech-attrs">
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Policy ID</span>
                    <span className="cvd-tech-attr-value mono">{policy.id}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Version</span>
                    <span className="cvd-tech-attr-value">v{policy.version}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Artifact types</span>
                    <span className="cvd-tech-attr-value">{policy.artifactTypes.map((type) => formatLabel(type)).join(', ')}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Lifetime findings</span>
                    <span className="cvd-tech-attr-value">{policy.lifetimeFindings.toLocaleString()}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Last evaluated</span>
                    <span className="cvd-tech-attr-value">{policy.lastEvaluatedAt ? formatDate(policy.lastEvaluatedAt) : 'Never'}</span>
                  </div>
                </div>
              </div>

              {Object.keys(policy.controlMappings).length > 0 && (
                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Control Mappings · {Object.keys(policy.controlMappings).length}</div>
                  <div className="cvd-refs-list">
                    {Object.entries(policy.controlMappings).map(([framework, control]) => (
                      <div key={framework} className="cvd-ref-row">
                        <span style={{ color: 'var(--title)', fontSize: 13, fontWeight: 500 }}>{framework}</span>
                        <span className="cvd-src-tag">{control}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="cvd2-overview-sidebar">
              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Decision Coverage</div>
                <div className={`ai-policy-coverage-gate ${policy.decisionCoverageStatus.toLowerCase()}`} style={{ margin: 16, borderRadius: 'var(--radius-md)' }}>
                  <strong style={{ fontSize: '1.6rem', fontFamily: 'var(--font-display)' }}>
                    {Math.round(policy.decisionCoverage * 100)}%
                  </strong>
                  <span>{coverageStatusLabel(policy.decisionCoverageStatus)}</span>
                </div>
                <div className="cvd-tech-attrs">
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Evaluated</span>
                    <span className="cvd-tech-attr-value">{policy.evaluatedArtifacts.toLocaleString()}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">No decision</span>
                    <span className="cvd-tech-attr-value">{policy.noDecisionCount.toLocaleString()}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Required</span>
                    <span className="cvd-tech-attr-value">{Math.round(policy.decisionCoverageThreshold * 100)}%</span>
                  </div>
                </div>
              </div>

              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Required Evidence · {policy.requiredResourceFamilies.length}</div>
                <div className="cvd2-wf-cards">
                  {policy.requiredResourceFamilies.map((family, index) => (
                    <div key={family} className="cvd2-wf-card" style={{ cursor: 'default' }}>
                      <div className="cvd2-wf-card-num">{index + 1}</div>
                      <div className="cvd2-wf-card-body">
                        <div className="cvd2-wf-card-title-row">
                          <span className="cvd2-wf-card-title">{formatLabel(family)}</span>
                          <span className="cvd-wf-badge cvd-wf-badge--pending">Required</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Remediation</div>
                <p className="cvd-ov-description" style={{ padding: 16 }}>{policy.remediation}</p>
              </div>
            </div>
          </div>
        )}

        {tab === 'configure' && (
          configQuery.isLoading || !draftScope ? (
            <div className="empty-state"><p>Loading configuration…</p></div>
          ) : configQuery.isError || !configuration ? (
            <div className="notice error">This policy's configuration could not be loaded.</div>
          ) : (
            <div className="cvd2-overview-body">
              <div className="cvd2-overview-main">
                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Scope · which AI inventory this policy evaluates</div>
                  <div className="ai-policy-config-body">
                    <p className="card-note">
                      Artifacts outside scope are skipped entirely — any existing finding for them is suppressed, not just hidden.
                    </p>
                    <div className="ai-policy-scope-modes" role="tablist" aria-label="Scope mode">
                      {SCOPE_MODE_OPTIONS.map((option) => (
                        <button
                          key={option.value}
                          type="button"
                          className={`ai-policy-scope-mode-btn${draftScope.mode === option.value ? ' active' : ''}`}
                          disabled={!canManage}
                          onClick={() => { setDraftScope({ ...draftScope, mode: option.value }); setScopeDirty(true); }}
                        >
                          {option.label}
                        </button>
                      ))}
                    </div>

                    {draftScope.mode === 'MATCH_RULES' && (
                      <>
                        <div className="ai-policy-rule-logic">
                          Match
                          <div className="ai-policy-scope-modes ai-policy-rule-logic-toggle">
                            {(['AND', 'OR'] as const).map((logic) => (
                              <button
                                key={logic}
                                type="button"
                                className={`ai-policy-scope-mode-btn${draftScope.conditionLogic === logic ? ' active' : ''}`}
                                disabled={!canManage}
                                onClick={() => { setDraftScope({ ...draftScope, conditionLogic: logic }); setScopeDirty(true); }}
                              >
                                {logic === 'AND' ? 'ALL' : 'ANY'}
                              </button>
                            ))}
                          </div>
                          of the following conditions
                        </div>
                        {draftScope.conditions.map((condition, index) => (
                          <div className="ai-policy-rule-row" key={index}>
                            <select
                              value={condition.field}
                              disabled={!canManage}
                              onChange={(event) => updateCondition(index, { ...condition, field: event.target.value })}
                            >
                              {SCOPE_FIELD_OPTIONS.map((option) => (
                                <option key={option.value} value={option.value}>{option.label}</option>
                              ))}
                            </select>
                            <select
                              value={condition.operator}
                              disabled={!canManage}
                              onChange={(event) => updateCondition(index, { ...condition, operator: event.target.value })}
                            >
                              {SCOPE_OPERATOR_OPTIONS.map((option) => (
                                <option key={option.value} value={option.value}>{option.label}</option>
                              ))}
                            </select>
                            <input
                              type="text"
                              value={condition.value}
                              disabled={!canManage}
                              placeholder="Value"
                              onChange={(event) => updateCondition(index, { ...condition, value: event.target.value })}
                            />
                            <button
                              type="button"
                              className="ai-policy-rule-remove"
                              aria-label="Remove condition"
                              disabled={!canManage}
                              onClick={() => removeCondition(index)}
                            >
                              ✕
                            </button>
                          </div>
                        ))}
                        <button type="button" className="ai-policy-add-row" disabled={!canManage} onClick={addCondition}>
                          + Add condition
                        </button>
                      </>
                    )}

                    {draftScope.mode === 'CUSTOM_LIST' && (
                      <p className="card-note">
                        Nothing is in scope by default. Mark specific artifacts as “Included” in Exceptions below.
                      </p>
                    )}

                    <div className="ai-policy-scope-preview">
                      <span>
                        <strong>{configuration.matchedArtifactCount} of {configuration.totalArtifactCount}</strong>{' '}
                        eligible artifact{configuration.totalArtifactCount === 1 ? '' : 's'} currently match this scope
                      </span>
                    </div>

                    <div className="button-row" style={{ marginTop: 12 }}>
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={!canManage || !scopeDirty || scopeMutation.isPending}
                        onClick={() => scopeMutation.mutate()}
                      >
                        {scopeMutation.isPending ? 'Saving…' : 'Save scope'}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Exceptions · {configuration.exceptions.length}</div>
                  <div className="ai-policy-config-body">
                    {configuration.exceptions.length === 0 ? (
                      <p className="card-note">No per-artifact overrides yet.</p>
                    ) : (
                      configuration.exceptions.map((exception) => (
                        <div className="ai-policy-exception-row" key={exception.artifactId}>
                          <div>
                            <div className="ai-policy-exception-name">{exception.artifactName}</div>
                            <div className="panel-caption">
                              {exception.override === 'EXCLUDED' ? 'Excluded' : 'Included'} by {exception.createdBy} · {formatDate(exception.createdAt)}
                              {exception.reason ? ` · "${exception.reason}"` : ''}
                            </div>
                          </div>
                          <button
                            type="button"
                            className="ai-policy-rule-remove"
                            aria-label={`Remove exception for ${exception.artifactName}`}
                            disabled={!canManage || removeExceptionMutation.isPending}
                            onClick={() => removeExceptionMutation.mutate(exception.artifactId)}
                          >
                            ✕
                          </button>
                        </div>
                      ))
                    )}

                    {canManage && (
                      <div className="ai-policy-add-exception">
                        <select
                          aria-label="Artifact"
                          value={exceptionArtifactId}
                          onChange={(event) => setExceptionArtifactId(event.target.value)}
                        >
                          <option value="">Select an artifact…</option>
                          {(candidateArtifactsQuery.data?.items ?? [])
                            .filter((artifact) => !configuration.exceptions.some((exception) => exception.artifactId === artifact.id))
                            .map((artifact) => (
                              <option key={artifact.id} value={artifact.id}>{artifact.name}</option>
                            ))}
                        </select>
                        <select
                          aria-label="Override"
                          value={exceptionOverride}
                          onChange={(event) => setExceptionOverride(event.target.value as PolicyExceptionOverride)}
                        >
                          <option value="EXCLUDED">Exclude</option>
                          <option value="INCLUDED">Include</option>
                        </select>
                        <input
                          type="text"
                          placeholder="Reason (optional)"
                          value={exceptionReason}
                          onChange={(event) => setExceptionReason(event.target.value)}
                        />
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          disabled={!exceptionArtifactId || addExceptionMutation.isPending}
                          onClick={() => addExceptionMutation.mutate()}
                        >
                          + Add exception
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Parameters · tenant-tuned thresholds</div>
                  <div className="ai-policy-config-body">
                    {configuration.parameters.length === 0 ? (
                      <p className="card-note">
                        This policy has no tenant-configurable parameters — it evaluates a fixed condition.
                      </p>
                    ) : (
                      <>
                        {configuration.parameters.map((param) => (
                          <div className="ai-policy-param-row" key={param.key}>
                            <div>
                              <div className="ai-policy-param-label">{param.label}</div>
                              <div className="panel-caption">{param.helpText}</div>
                              <div className="panel-caption">Platform default: {formatLabel(param.defaultValue)}</div>
                            </div>
                            <select
                              value={draftParameters[param.key] ?? param.value}
                              disabled={!canManage}
                              onChange={(event) => {
                                setDraftParameters({ ...draftParameters, [param.key]: event.target.value });
                                setParametersDirty(true);
                              }}
                            >
                              {param.options.map((option) => (
                                <option key={option} value={option}>{formatLabel(option)}</option>
                              ))}
                            </select>
                          </div>
                        ))}
                        <div className="button-row" style={{ marginTop: 12 }}>
                          <button
                            type="button"
                            className="btn btn-primary"
                            disabled={!canManage || !parametersDirty || parametersMutation.isPending}
                            onClick={() => parametersMutation.mutate()}
                          >
                            {parametersMutation.isPending ? 'Saving…' : 'Save parameters'}
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>

              <div className="cvd2-overview-sidebar">
                <div className="cvd2-panel ai-policy-assist-card">
                  <div className="cvd2-panel-hdr"><span className="ai-assist-badge">AI</span>Assist</div>
                  <div className="ai-policy-config-body">
                    <div className="ai-policy-assist-action">
                      <div className="ai-policy-assist-title">Explain this policy for our environment</div>
                      <p className="panel-caption">
                        Reads your current AI inventory and open findings to translate the policy into what it means for your tenant right now.
                      </p>
                      <button
                        type="button"
                        className="btn btn-ai btn-sm"
                        disabled={explainQuery.isFetching}
                        onClick={() => void explainQuery.refetch()}
                      >
                        {explainQuery.isFetching ? 'Thinking…' : explainQuery.data ? 'Regenerate' : 'Explain'}
                      </button>
                      {explainQuery.data && <div className="ai-policy-assist-result">{explainQuery.data.summary}</div>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )
        )}

        {tab === 'findings' && (
          <div className="cvd2-panel">
            <div className="cvd2-panel-hdr ai-policy-detail-panel-hdr-row">
              <span>Findings · {visibleFindings.length}</span>
              <select
                value={findingsStatusFilter}
                onChange={(event) => setFindingsStatusFilter(event.target.value)}
                aria-label="Finding status"
              >
                <option value="OPEN">Open</option>
                <option value="RESOLVED">Resolved</option>
                <option value="SUPPRESSED_BY_POLICY">Suppressed by policy</option>
                <option value="">All states</option>
              </select>
            </div>
            {findingsQuery.isLoading ? (
              <div className="empty-state"><p>Loading findings…</p></div>
            ) : findingsQuery.isError ? (
              <div className="notice error">AI findings could not be loaded.</div>
            ) : visibleFindings.length === 0 ? (
              <div className="empty-state"><p>No findings match this filter.</p></div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr><th>Finding</th><th>Artifact</th><th>State</th><th>Observed</th></tr>
                </thead>
                <tbody>
                  {visibleFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td><span className={severityClassName(finding.severity)}>{finding.severity}</span><strong>{finding.displayId}</strong><small>{finding.title}</small></td>
                      <td>{finding.artifactName}</td>
                      <td><span className="status-pill">{finding.status.replace(/_/g, ' ')}</span></td>
                      <td>{timeAgo(finding.lastObservedAt) ?? 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'artifacts' && (
          <div className="cvd2-panel">
            <div className="cvd2-panel-hdr">AI Artifacts Impacted · {impactedArtifacts.length}</div>
            {findingsQuery.isLoading ? (
              <div className="empty-state"><p>Loading impacted artifacts…</p></div>
            ) : findingsQuery.isError ? (
              <div className="notice error">AI findings could not be loaded.</div>
            ) : impactedArtifacts.length === 0 ? (
              <div className="empty-state"><p>No AI artifacts have findings from this policy.</p></div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr><th>Artifact</th><th>Worst severity</th><th>Open findings</th><th>Total findings</th><th>Last observed</th></tr>
                </thead>
                <tbody>
                  {impactedArtifacts.map((artifact) => (
                    <tr key={artifact.artifactId}>
                      <td><strong>{artifact.artifactName}</strong><small>{artifact.artifactId}</small></td>
                      <td><span className={severityClassName(artifact.worstSeverity)}>{artifact.worstSeverity}</span></td>
                      <td>{artifact.openFindings}</td>
                      <td>{artifact.totalFindings}</td>
                      <td>{timeAgo(artifact.lastObservedAt) ?? 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
