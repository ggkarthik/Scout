import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { RiskPolicy } from '../features/configurations/types';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';

type ConfigurationSectionKey =
  | 'risk-score'
  | 'asset-boost'
  | 'sla'
  | 'auto-close'
  | 'finding-generation'
  | 'prototype-reset';

const CONFIGURATION_SECTIONS: Array<{ key: ConfigurationSectionKey; title: string }> = [
  { key: 'risk-score', title: 'Risk Score Calculator' },
  { key: 'asset-boost', title: 'Asset Context Risk Boost' },
  { key: 'sla', title: 'SLA Configuration (Risk + Asset Context)' },
  { key: 'auto-close', title: 'Auto Close Configuration' },
  { key: 'finding-generation', title: 'Org CVE Finding Generation' },
  { key: 'prototype-reset', title: 'Prototype Data Reset' }
];

type PolicyValidationError = {
  field: keyof RiskPolicy;
  message: string;
};

function validateRiskPolicy(policy: RiskPolicy): PolicyValidationError[] {
  const errors: PolicyValidationError[] = [];
  const validateRange = (
    field: keyof RiskPolicy,
    value: number,
    min: number,
    max: number,
    label: string
  ): void => {
    if (Number.isNaN(value) || value < min || value > max) {
      errors.push({ field, message: `${label} must be between ${min} and ${max}.` });
    }
  };

  validateRange('cvssWeight', policy.cvssWeight, 0, 5, 'CVSS weight');
  validateRange('kevBoost', policy.kevBoost, 0, 5, 'KEV boost');
  validateRange('epssWeight', policy.epssWeight, 0, 5, 'EPSS weight');
  validateRange('vexNotAffectedFreshnessDays', policy.vexNotAffectedFreshnessDays, 1, 365, 'VEX not-affected freshness');
  validateRange('vexFixedFreshnessDays', policy.vexFixedFreshnessDays, 1, 365, 'VEX fixed freshness');
  validateRange('vexKnownAffectedBoost', policy.vexKnownAffectedBoost, 0, 3, 'VEX known-affected boost');
  validateRange('vexUnderInvestigationPenalty', policy.vexUnderInvestigationPenalty, 0, 3, 'VEX under-investigation penalty');
  validateRange('vexNotAffectedReduction', policy.vexNotAffectedReduction, 0, 3, 'VEX not-affected reduction');
  validateRange('vexStalePenalty', policy.vexStalePenalty, 0, 3, 'VEX stale penalty');
  validateRange('criticalThreshold', policy.criticalThreshold, 0, 10, 'Critical threshold');
  validateRange('highThreshold', policy.highThreshold, 0, 10, 'High threshold');
  if (policy.highThreshold > policy.criticalThreshold) {
    errors.push({
      field: 'highThreshold',
      message: 'High threshold cannot exceed critical threshold.'
    });
  }
  validateRange('criticalSlaDays', policy.criticalSlaDays, 0, 365, 'Critical SLA');
  validateRange('highSlaDays', policy.highSlaDays, 0, 365, 'High SLA');
  validateRange('mediumSlaDays', policy.mediumSlaDays, 0, 365, 'Medium SLA');
  validateRange('lowSlaDays', policy.lowSlaDays, 0, 365, 'Low SLA');
  validateRange('assetCriticalSlaMultiplier', policy.assetCriticalSlaMultiplier, 0, 5, 'Critical SLA multiplier');
  validateRange('assetHighSlaMultiplier', policy.assetHighSlaMultiplier, 0, 5, 'High SLA multiplier');
  validateRange('assetMediumSlaMultiplier', policy.assetMediumSlaMultiplier, 0, 5, 'Medium SLA multiplier');
  validateRange('assetLowSlaMultiplier', policy.assetLowSlaMultiplier, 0, 5, 'Low SLA multiplier');
  validateRange('autoCloseAfterDays', policy.autoCloseAfterDays, 0, 365, 'Auto-close days');
  return errors;
}

const SECTION_POLICY_FIELDS: Partial<Record<ConfigurationSectionKey, ReadonlyArray<keyof RiskPolicy>>> = {
  'risk-score': ['cvssWeight', 'kevBoost', 'epssWeight', 'vexNotAffectedFreshnessDays', 'vexFixedFreshnessDays', 'vexKnownAffectedBoost', 'vexUnderInvestigationPenalty', 'vexNotAffectedReduction', 'vexStalePenalty', 'criticalThreshold', 'highThreshold'],
  'sla': ['criticalSlaDays', 'highSlaDays', 'mediumSlaDays', 'lowSlaDays', 'assetCriticalSlaMultiplier', 'assetHighSlaMultiplier', 'assetMediumSlaMultiplier', 'assetLowSlaMultiplier'],
  'auto-close': ['autoCloseAfterDays']
};

export function ConfigurationsPage() {
  const queryClient = useQueryClient();
  const riskPolicyQuery = useRiskPolicyQuery();
  const [policy, setPolicy] = React.useState<RiskPolicy | null>(null);
  const [policyMessage, setPolicyMessage] = React.useState('');
  const [policySaving, setPolicySaving] = React.useState(false);
  const [resetBusy, setResetBusy] = React.useState(false);
  const [resetMessage, setResetMessage] = React.useState('');
  const [activeSection, setActiveSection] = React.useState<ConfigurationSectionKey>('risk-score');
  const [openSections, setOpenSections] = React.useState<Set<ConfigurationSectionKey>>(
    () => new Set(CONFIGURATION_SECTIONS.map((section) => section.key))
  );
  const [showAdvancedVex, setShowAdvancedVex] = React.useState(false);
  const policyValidationErrors = React.useMemo(
    () => (policy == null ? [] : validateRiskPolicy(policy)),
    [policy]
  );

  React.useEffect(() => {
    if (riskPolicyQuery.data) {
      setPolicy(riskPolicyQuery.data);
    }
  }, [riskPolicyQuery.data]);

  const updatePolicy = (key: keyof RiskPolicy, value: number | boolean | string): void => {
    if (!policy) return;
    setPolicy({ ...policy, [key]: value });
  };

  const savePolicy = async (): Promise<void> => {
    if (!policy) return;
    if (policyValidationErrors.length > 0) {
      setPolicyMessage('Validation failed. Fix unsafe values before saving.');
      return;
    }
    setPolicySaving(true);
    setPolicyMessage('');
    try {
      const updated = await api.updateRiskPolicy(policy);
      queryClient.setQueryData(['risk-policy'], updated);
      setPolicy(updated);
      setPolicyMessage('Configuration saved');
    } catch (e) {
      setPolicyMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setPolicySaving(false);
    }
  };

  const cleanAllPrototypeData = async (): Promise<void> => {
    const confirmed = window.confirm(
      'This will permanently delete findings, inventory, vulnerability intelligence, and sync run history. Continue?'
    );
    if (!confirmed) {
      return;
    }
    setResetBusy(true);
    setResetMessage('');
    try {
      const result = await api.cleanAllPrototypeData();
      const total = Object.values(result.deletedRows ?? {}).reduce((sum, value) => sum + Number(value || 0), 0);
      setResetMessage(`Prototype data reset complete. Deleted ${total} rows.`);
      await riskPolicyQuery.refetch();
    } catch (e) {
      setResetMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setResetBusy(false);
    }
  };

  if (!policy) {
    if (riskPolicyQuery.error instanceof Error) {
      return <div className="panel">Failed to load configuration: {riskPolicyQuery.error.message}</div>;
    }
    return <div className="panel">Loading configuration...</div>;
  }

  const isSectionOpen = (key: ConfigurationSectionKey): boolean => openSections.has(key);

  const toggleSection = (key: ConfigurationSectionKey): void => {
    setOpenSections((current) => {
      const next = new Set(current);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const openSection = (key: ConfigurationSectionKey): void => {
    setActiveSection(key);
    setOpenSections((current) => {
      if (current.has(key)) {
        return current;
      }
      const next = new Set(current);
      next.add(key);
      return next;
    });
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Configurations</h3>
        <span className="panel-caption">Centralized settings for risk, SLA, auto-close, org CVE finding generation, and prototype controls</span>
      </div>
      <div className="config-subtabs">
        {CONFIGURATION_SECTIONS.map((section) => (
          <button
            key={section.key}
            className={activeSection === section.key ? 'config-subtab active' : 'config-subtab'}
            onClick={() => openSection(section.key)}
            type="button"
          >
            {section.title}
          </button>
        ))}
      </div>

      {activeSection === 'risk-score' && (
      <section id="config-section-risk-score" className="config-accordion-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('risk-score')}>
          <span>Risk Score Calculator</span>
          <span className={isSectionOpen('risk-score') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('risk-score') && (
          <div className="config-accordion-body">
            <div className="form-grid ingestion-grid">
              <label>CVSS Weight
                <input type="number" step="0.1" min={0} max={5} value={policy.cvssWeight} onChange={(e) => updatePolicy('cvssWeight', Number(e.target.value))} />
              </label>
              <label>KEV Boost
                <input type="number" step="0.1" min={0} max={5} value={policy.kevBoost} onChange={(e) => updatePolicy('kevBoost', Number(e.target.value))} />
              </label>
              <label>EPSS Weight
                <input type="number" step="0.1" min={0} max={5} value={policy.epssWeight} onChange={(e) => updatePolicy('epssWeight', Number(e.target.value))} />
              </label>
              <label>Critical Threshold
                <input type="number" step="0.1" min={0} max={10} value={policy.criticalThreshold} onChange={(e) => updatePolicy('criticalThreshold', Number(e.target.value))} />
                <span className="field-hint">Findings with risk score &ge; {policy.criticalThreshold} are classified as Critical</span>
              </label>
              <label>High Threshold
                <input type="number" step="0.1" min={0} max={10} value={policy.highThreshold} onChange={(e) => updatePolicy('highThreshold', Number(e.target.value))} />
                <span className="field-hint">Findings with risk score &ge; {policy.highThreshold} are classified as High</span>
              </label>
            </div>

            <div className="advanced-vex-toggle-row">
              <button
                type="button"
                className="btn-link"
                onClick={() => setShowAdvancedVex((v) => !v)}
              >
                <span className={showAdvancedVex ? 'config-chevron open' : 'config-chevron'}>▾</span>
                {showAdvancedVex ? 'Hide advanced VEX settings' : 'Show advanced VEX settings'}
              </button>
              {!showAdvancedVex && (
                <span className="field-hint">Freshness windows, score modifiers for VEX assertion states</span>
              )}
            </div>

            {showAdvancedVex && (
              <div className="form-grid ingestion-grid">
                <label>VEX Not-Affected Freshness (days)
                  <input type="number" min={1} max={365} value={policy.vexNotAffectedFreshnessDays} onChange={(e) => updatePolicy('vexNotAffectedFreshnessDays', Number(e.target.value))} />
                </label>
                <label>VEX Fixed Freshness (days)
                  <input type="number" min={1} max={365} value={policy.vexFixedFreshnessDays} onChange={(e) => updatePolicy('vexFixedFreshnessDays', Number(e.target.value))} />
                </label>
                <label>VEX Known-Affected Boost
                  <input type="number" step="0.1" min={0} max={3} value={policy.vexKnownAffectedBoost} onChange={(e) => updatePolicy('vexKnownAffectedBoost', Number(e.target.value))} />
                </label>
                <label>VEX Under-Investigation Penalty
                  <input type="number" step="0.1" min={0} max={3} value={policy.vexUnderInvestigationPenalty} onChange={(e) => updatePolicy('vexUnderInvestigationPenalty', Number(e.target.value))} />
                </label>
                <label>VEX Not-Affected Reduction
                  <input type="number" step="0.1" min={0} max={3} value={policy.vexNotAffectedReduction} onChange={(e) => updatePolicy('vexNotAffectedReduction', Number(e.target.value))} />
                </label>
                <label>VEX Stale Assertion Penalty
                  <input type="number" step="0.1" min={0} max={3} value={policy.vexStalePenalty} onChange={(e) => updatePolicy('vexStalePenalty', Number(e.target.value))} />
                </label>
              </div>
            )}
            {policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['risk-score']?.includes(e.field)).length > 0 && (
              <div className="notice error">
                <ul>{policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['risk-score']?.includes(e.field)).map((e) => <li key={e.field}>{e.message}</li>)}</ul>
              </div>
            )}
            <div className="button-row form-submit-row">
              <button type="button" className="btn btn-primary" onClick={savePolicy} disabled={policySaving || policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['risk-score']?.includes(e.field)).length > 0}>
                {policySaving ? 'Saving...' : 'Save'}
              </button>
            </div>
            {policyMessage && activeSection === 'risk-score' && <div className="notice">{policyMessage}</div>}
          </div>
        )}
      </section>
      )}

      {activeSection === 'asset-boost' && (
      <section id="config-section-asset-boost" className="config-accordion-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('asset-boost')}>
          <span>Asset Context Risk Boost</span>
          <span className={isSectionOpen('asset-boost') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('asset-boost') && (
          <div className="config-accordion-body">
            <div className="form-grid ingestion-grid">
              <label>Critical Asset Boost
                <input type="number" step="0.1" value={policy.assetCriticalRiskBoost} onChange={(e) => updatePolicy('assetCriticalRiskBoost', Number(e.target.value))} />
              </label>
              <label>High Asset Boost
                <input type="number" step="0.1" value={policy.assetHighRiskBoost} onChange={(e) => updatePolicy('assetHighRiskBoost', Number(e.target.value))} />
              </label>
              <label>Medium Asset Boost
                <input type="number" step="0.1" value={policy.assetMediumRiskBoost} onChange={(e) => updatePolicy('assetMediumRiskBoost', Number(e.target.value))} />
              </label>
              <label>Low Asset Boost
                <input type="number" step="0.1" value={policy.assetLowRiskBoost} onChange={(e) => updatePolicy('assetLowRiskBoost', Number(e.target.value))} />
              </label>
            </div>
            <div className="button-row form-submit-row">
              <button type="button" className="btn btn-primary" onClick={savePolicy} disabled={policySaving}>
                {policySaving ? 'Saving...' : 'Save'}
              </button>
            </div>
            {policyMessage && activeSection === 'asset-boost' && <div className="notice">{policyMessage}</div>}
          </div>
        )}
      </section>
      )}

      {activeSection === 'sla' && (
      <section id="config-section-sla" className="config-accordion-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('sla')}>
          <span>SLA Configuration (Risk + Asset Context)</span>
          <span className={isSectionOpen('sla') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('sla') && (
          <div className="config-accordion-body">
            <div className="form-grid ingestion-grid">
              <label>Critical Risk SLA (days)
                <input type="number" min={0} max={365} value={policy.criticalSlaDays} onChange={(e) => updatePolicy('criticalSlaDays', Number(e.target.value))} />
                <span className="field-hint">Teams have {policy.criticalSlaDays} days to remediate Critical findings</span>
              </label>
              <label>High Risk SLA (days)
                <input type="number" min={0} max={365} value={policy.highSlaDays} onChange={(e) => updatePolicy('highSlaDays', Number(e.target.value))} />
                <span className="field-hint">Teams have {policy.highSlaDays} days to remediate High findings</span>
              </label>
              <label>Medium Risk SLA (days)
                <input type="number" min={0} max={365} value={policy.mediumSlaDays} onChange={(e) => updatePolicy('mediumSlaDays', Number(e.target.value))} />
                <span className="field-hint">Teams have {policy.mediumSlaDays} days to remediate Medium findings</span>
              </label>
              <label>Low Risk SLA (days)
                <input type="number" min={0} max={365} value={policy.lowSlaDays} onChange={(e) => updatePolicy('lowSlaDays', Number(e.target.value))} />
                <span className="field-hint">Teams have {policy.lowSlaDays} days to remediate Low findings</span>
              </label>
              <label>Critical Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetCriticalSlaMultiplier} onChange={(e) => updatePolicy('assetCriticalSlaMultiplier', Number(e.target.value))} />
                <span className="field-hint">Critical assets get ~{Math.round(policy.criticalSlaDays * policy.assetCriticalSlaMultiplier)} days for Critical findings</span>
              </label>
              <label>High Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetHighSlaMultiplier} onChange={(e) => updatePolicy('assetHighSlaMultiplier', Number(e.target.value))} />
                <span className="field-hint">High assets get ~{Math.round(policy.highSlaDays * policy.assetHighSlaMultiplier)} days for High findings</span>
              </label>
              <label>Medium Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetMediumSlaMultiplier} onChange={(e) => updatePolicy('assetMediumSlaMultiplier', Number(e.target.value))} />
                <span className="field-hint">Medium assets get ~{Math.round(policy.mediumSlaDays * policy.assetMediumSlaMultiplier)} days for Medium findings</span>
              </label>
              <label>Low Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetLowSlaMultiplier} onChange={(e) => updatePolicy('assetLowSlaMultiplier', Number(e.target.value))} />
                <span className="field-hint">Low assets get ~{Math.round(policy.lowSlaDays * policy.assetLowSlaMultiplier)} days for Low findings</span>
              </label>
            </div>
            {policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['sla']?.includes(e.field)).length > 0 && (
              <div className="notice error">
                <ul>{policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['sla']?.includes(e.field)).map((e) => <li key={e.field}>{e.message}</li>)}</ul>
              </div>
            )}
            <div className="button-row form-submit-row">
              <button type="button" className="btn btn-primary" onClick={savePolicy} disabled={policySaving || policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['sla']?.includes(e.field)).length > 0}>
                {policySaving ? 'Saving...' : 'Save'}
              </button>
            </div>
            {policyMessage && activeSection === 'sla' && <div className="notice">{policyMessage}</div>}
          </div>
        )}
      </section>
      )}

      {activeSection === 'auto-close' && (
      <section id="config-section-auto-close" className="config-accordion-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('auto-close')}>
          <span>Auto Close Configuration</span>
          <span className={isSectionOpen('auto-close') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('auto-close') && (
          <div className="config-accordion-body">
            <div className="form-grid ingestion-grid">
              <label>Enable Auto Close
                <select
                  value={policy.autoCloseEnabled ? 'true' : 'false'}
                  onChange={(e) => updatePolicy('autoCloseEnabled', e.target.value === 'true')}
                >
                  <option value="false">Disabled</option>
                  <option value="true">Enabled</option>
                </select>
              </label>
              <label>Asset Identifier
                <input
                  value={policy.autoCloseAssetIdentifier ?? ''}
                  onChange={(e) => updatePolicy('autoCloseAssetIdentifier', e.target.value)}
                  placeholder="github:owner/repo or app:payments-api:prod"
                />
              </label>
              <label>Auto Close After (days)
                <input
                  type="number"
                  min={0}
                  max={365}
                  value={policy.autoCloseAfterDays}
                  onChange={(e) => updatePolicy('autoCloseAfterDays', Number(e.target.value))}
                />
              </label>
            </div>
            <div className="inline-note">
              Findings matching the configured asset identifier will be moved to <span className="mono">AUTO_CLOSED</span> after the configured age.
            </div>
            {policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['auto-close']?.includes(e.field)).length > 0 && (
              <div className="notice error">
                <ul>{policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['auto-close']?.includes(e.field)).map((e) => <li key={e.field}>{e.message}</li>)}</ul>
              </div>
            )}
            <div className="button-row form-submit-row">
              <button type="button" className="btn btn-primary" onClick={savePolicy} disabled={policySaving || policyValidationErrors.filter((e) => SECTION_POLICY_FIELDS['auto-close']?.includes(e.field)).length > 0}>
                {policySaving ? 'Saving...' : 'Save'}
              </button>
            </div>
            {policyMessage && activeSection === 'auto-close' && <div className="notice">{policyMessage}</div>}
          </div>
        )}
      </section>
      )}

      {activeSection === 'finding-generation' && (
      <section id="config-section-finding-generation" className="config-accordion-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('finding-generation')}>
          <span>Org CVE Finding Generation</span>
          <span className={isSectionOpen('finding-generation') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('finding-generation') && (
          <div className="config-accordion-body">
            <div className="form-grid ingestion-grid">
              <label>Finding generation mode
                <select
                  value={policy.findingGenerationMode}
                  onChange={(e) => updatePolicy('findingGenerationMode', e.target.value)}
                >
                  <option value="AUTO">Generate findings automatically</option>
                  <option value="MANUAL">Require manual CVE review before creating findings</option>
                </select>
              </label>
            </div>
            <div className="inline-note">
              <strong>AUTO</strong> creates findings automatically during recompute. <strong>MANUAL</strong> still computes org-level CVE exposure, but no findings are auto-created until an analyst reviews the CVE and triggers manual finding creation explicitly.
            </div>
            <div className="button-row form-submit-row">
              <button type="button" className="btn btn-primary" onClick={savePolicy} disabled={policySaving}>
                {policySaving ? 'Saving...' : 'Save'}
              </button>
            </div>
            {policyMessage && activeSection === 'finding-generation' && <div className="notice">{policyMessage}</div>}
          </div>
        )}
      </section>
      )}

      {activeSection === 'prototype-reset' && (
      <section id="config-section-prototype-reset" className="config-accordion-section danger-zone-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('prototype-reset')}>
          <span>Prototype Data Reset</span>
          <span className={isSectionOpen('prototype-reset') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('prototype-reset') && (
          <div className="config-accordion-body">
            <div className="inline-note">
              Use this only in prototype mode. This action clears findings, software inventory, assets, vulnerability intelligence records, org exposure rows, and sync run history.
            </div>
            <div className="button-row form-submit-row">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={cleanAllPrototypeData}
                disabled={resetBusy}
              >
                {resetBusy ? 'Cleaning...' : 'Clean All'}
              </button>
            </div>
            {resetMessage && <div className="notice">{resetMessage}</div>}
          </div>
        )}
      </section>
      )}

    </div>
  );
}
