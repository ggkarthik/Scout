import React from 'react';
import { api } from '../api/client';
import { GithubSbomSource, RiskPolicy } from '../types';
import { ResizableTable } from '../components/ResizableTable';
import { SourcesPage } from './SourcesPage';

type ConfigurationSectionKey =
  | 'risk-score'
  | 'asset-boost'
  | 'sla'
  | 'auto-close'
  | 'github-pipelines'
  | 'prototype-reset'
  | 'integration-queue';

const CONFIGURATION_SECTIONS: Array<{ key: ConfigurationSectionKey; title: string }> = [
  { key: 'risk-score', title: 'Risk Score Calculator' },
  { key: 'asset-boost', title: 'Asset Context Risk Boost' },
  { key: 'sla', title: 'SLA Configuration (Risk + Asset Context)' },
  { key: 'auto-close', title: 'Auto Close Configuration' },
  { key: 'github-pipelines', title: 'GitHub Auto Ingestion Pipelines' },
  { key: 'prototype-reset', title: 'Prototype Data Reset' },
  { key: 'integration-queue', title: 'Integration Run Queue' }
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

export function ConfigurationsPage() {
  const [policy, setPolicy] = React.useState<RiskPolicy | null>(null);
  const [policyMessage, setPolicyMessage] = React.useState('');
  const [policySaving, setPolicySaving] = React.useState(false);

  const [githubSources, setGithubSources] = React.useState<GithubSbomSource[]>([]);
  const [sourceBusyId, setSourceBusyId] = React.useState<string | null>(null);
  const [sourceMessage, setSourceMessage] = React.useState('');

  const [sourceName, setSourceName] = React.useState('');
  const [sourceOwner, setSourceOwner] = React.useState('');
  const [sourceRepo, setSourceRepo] = React.useState('');
  const [sourceAssetType, setSourceAssetType] = React.useState<'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'>('APPLICATION');
  const [sourceAssetName, setSourceAssetName] = React.useState('');
  const [sourceAssetIdentifier, setSourceAssetIdentifier] = React.useState('');
  const [sourceFrequency, setSourceFrequency] = React.useState<'ONCE' | 'INTERVAL'>('ONCE');
  const [sourceIntervalMinutes, setSourceIntervalMinutes] = React.useState('60');
  const [sourceEnabled, setSourceEnabled] = React.useState(true);
  const [resetBusy, setResetBusy] = React.useState(false);
  const [resetMessage, setResetMessage] = React.useState('');
  const [activeSection, setActiveSection] = React.useState<ConfigurationSectionKey>('risk-score');
  const [openSections, setOpenSections] = React.useState<Set<ConfigurationSectionKey>>(
    () => new Set(CONFIGURATION_SECTIONS.map((section) => section.key))
  );
  const policyValidationErrors = React.useMemo(
    () => (policy == null ? [] : validateRiskPolicy(policy)),
    [policy]
  );

  const loadPolicy = React.useCallback(async () => {
    try {
      const value = await api.getRiskPolicy();
      setPolicy(value);
    } catch (e) {
      setPolicyMessage(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const loadGithubSources = React.useCallback(async () => {
    try {
      const rows = await api.listGithubSbomSources();
      setGithubSources(rows);
    } catch (e) {
      setSourceMessage(e instanceof Error ? e.message : String(e));
    }
  }, []);

  React.useEffect(() => {
    loadPolicy();
    loadGithubSources();
  }, [loadPolicy, loadGithubSources]);

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
      setPolicy(updated);
      setPolicyMessage('Configuration saved');
    } catch (e) {
      setPolicyMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setPolicySaving(false);
    }
  };

  const createGithubSource = async (): Promise<void> => {
    if (!sourceName.trim()) {
      setSourceMessage('Pipeline name is required');
      return;
    }
    if (!sourceOwner.trim() || !sourceRepo.trim()) {
      setSourceMessage('GitHub owner and repository are required');
      return;
    }

    setSourceMessage('');
    setSourceBusyId('create');
    try {
      await api.createGithubSbomSource({
        name: sourceName.trim(),
        owner: sourceOwner.trim(),
        repo: sourceRepo.trim(),
        assetType: sourceAssetType,
        assetName: sourceAssetName.trim() || undefined,
        assetIdentifier: sourceAssetIdentifier.trim() || undefined,
        frequency: sourceFrequency,
        intervalMinutes: sourceFrequency === 'INTERVAL' ? Math.max(5, Number(sourceIntervalMinutes) || 60) : undefined,
        enabled: sourceEnabled
      });
      setSourceMessage('GitHub pipeline created');
      await loadGithubSources();
    } catch (e) {
      setSourceMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setSourceBusyId(null);
    }
  };

  const runGithubSource = async (id: string): Promise<void> => {
    setSourceBusyId(id);
    setSourceMessage('');
    try {
      await api.runGithubSbomSource(id);
      setSourceMessage('Pipeline run queued');
      await loadGithubSources();
    } catch (e) {
      setSourceMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setSourceBusyId(null);
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
      await loadPolicy();
      await loadGithubSources();
    } catch (e) {
      setResetMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setResetBusy(false);
    }
  };

  if (!policy) {
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
        <span className="panel-caption">Centralized settings for risk, SLA, auto-close and GitHub auto-ingestion pipelines</span>
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
              <label>Critical Threshold
                <input type="number" step="0.1" min={0} max={10} value={policy.criticalThreshold} onChange={(e) => updatePolicy('criticalThreshold', Number(e.target.value))} />
              </label>
              <label>High Threshold
                <input type="number" step="0.1" min={0} max={10} value={policy.highThreshold} onChange={(e) => updatePolicy('highThreshold', Number(e.target.value))} />
              </label>
            </div>
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
              </label>
              <label>High Risk SLA (days)
                <input type="number" min={0} max={365} value={policy.highSlaDays} onChange={(e) => updatePolicy('highSlaDays', Number(e.target.value))} />
              </label>
              <label>Medium Risk SLA (days)
                <input type="number" min={0} max={365} value={policy.mediumSlaDays} onChange={(e) => updatePolicy('mediumSlaDays', Number(e.target.value))} />
              </label>
              <label>Low Risk SLA (days)
                <input type="number" min={0} max={365} value={policy.lowSlaDays} onChange={(e) => updatePolicy('lowSlaDays', Number(e.target.value))} />
              </label>
              <label>Critical Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetCriticalSlaMultiplier} onChange={(e) => updatePolicy('assetCriticalSlaMultiplier', Number(e.target.value))} />
              </label>
              <label>High Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetHighSlaMultiplier} onChange={(e) => updatePolicy('assetHighSlaMultiplier', Number(e.target.value))} />
              </label>
              <label>Medium Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetMediumSlaMultiplier} onChange={(e) => updatePolicy('assetMediumSlaMultiplier', Number(e.target.value))} />
              </label>
              <label>Low Asset SLA Multiplier
                <input type="number" step="0.1" min={0} max={5} value={policy.assetLowSlaMultiplier} onChange={(e) => updatePolicy('assetLowSlaMultiplier', Number(e.target.value))} />
              </label>
            </div>
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
          </div>
        )}
      </section>
      )}

      {activeSection === 'github-pipelines' && (
      <section id="config-section-github-pipelines" className="config-accordion-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('github-pipelines')}>
          <span>GitHub Auto Ingestion Pipelines</span>
          <span className={isSectionOpen('github-pipelines') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('github-pipelines') && (
          <div className="config-accordion-body">
            <div className="form-grid ingestion-grid">
              <label>Pipeline Name
                <input value={sourceName} onChange={(e) => setSourceName(e.target.value)} placeholder="payments-main-sbom" />
              </label>
              <label>GitHub Owner
                <input value={sourceOwner} onChange={(e) => setSourceOwner(e.target.value)} placeholder="org-name" />
              </label>
              <label>GitHub Repo
                <input value={sourceRepo} onChange={(e) => setSourceRepo(e.target.value)} placeholder="service-repo" />
              </label>
              <label>Asset Type
                <select value={sourceAssetType} onChange={(e) => setSourceAssetType(e.target.value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE')}>
                  <option value="APPLICATION">Application</option>
                  <option value="HOST">Host</option>
                  <option value="CONTAINER_IMAGE">Container Image</option>
                </select>
              </label>
              <label>Asset Name (optional)
                <input value={sourceAssetName} onChange={(e) => setSourceAssetName(e.target.value)} placeholder="owner/repo default" />
              </label>
              <label>Asset Identifier (optional)
                <input value={sourceAssetIdentifier} onChange={(e) => setSourceAssetIdentifier(e.target.value)} placeholder="github:owner/repo default" />
              </label>
              <label>Frequency
                <select value={sourceFrequency} onChange={(e) => setSourceFrequency(e.target.value as 'ONCE' | 'INTERVAL')}>
                  <option value="ONCE">Once</option>
                  <option value="INTERVAL">Every N minutes</option>
                </select>
              </label>
              {sourceFrequency === 'INTERVAL' && (
                <label>Interval (minutes)
                  <input
                    type="number"
                    min={5}
                    max={1440}
                    value={sourceIntervalMinutes}
                    onChange={(e) => setSourceIntervalMinutes(e.target.value)}
                  />
                </label>
              )}
              <label>Enabled
                <select value={sourceEnabled ? 'true' : 'false'} onChange={(e) => setSourceEnabled(e.target.value === 'true')}>
                  <option value="true">Enabled</option>
                  <option value="false">Disabled</option>
                </select>
              </label>
            </div>

            <div className="button-row form-submit-row">
              <button type="button" className="btn btn-primary" onClick={createGithubSource} disabled={sourceBusyId === 'create'}>
                {sourceBusyId === 'create' ? 'Saving...' : 'Create Auto Pipeline'}
              </button>
              <button type="button" className="btn btn-secondary" onClick={loadGithubSources} disabled={sourceBusyId != null}>
                Refresh
              </button>
            </div>
            {sourceMessage && <div className="notice">{sourceMessage}</div>}

            {githubSources.length === 0 ? (
              <div className="empty-state">
                <p>No GitHub auto-ingestion pipelines configured.</p>
              </div>
            ) : (
              <div className="table-scroll">
                <ResizableTable storageKey="github-source-pipelines-table-widths">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Repository</th>
                      <th>Endpoint</th>
                      <th>Asset</th>
                      <th>Frequency</th>
                      <th>Enabled</th>
                      <th>Last Run</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {githubSources.map((source) => (
                      <tr key={source.id}>
                        <td>{source.name}</td>
                        <td>{`${source.owner}/${source.repo}`}</td>
                        <td className="mono">{source.path || '-'}</td>
                        <td>{`${source.assetName} (${source.assetIdentifier})`}</td>
                        <td>{source.frequency === 'ONCE' ? 'Once' : `Every ${source.intervalMinutes}m`}</td>
                        <td>{source.enabled ? 'Yes' : 'No'}</td>
                        <td>{source.lastRunAt ? new Date(source.lastRunAt).toLocaleString() : 'Never'}</td>
                        <td>{source.lastRunStatus ?? '-'}</td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-secondary btn-inline"
                            onClick={() => runGithubSource(source.id)}
                            disabled={sourceBusyId === source.id}
                          >
                            {sourceBusyId === source.id ? 'Running...' : 'Run Now'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </ResizableTable>
              </div>
            )}
          </div>
        )}
      </section>
      )}

      {activeSection === 'prototype-reset' && (
      <section id="config-section-prototype-reset" className="config-accordion-section">
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

      {activeSection === 'integration-queue' && (
      <section id="config-section-integration-queue" className="config-accordion-section">
        <button type="button" className="config-accordion-toggle" onClick={() => toggleSection('integration-queue')}>
          <span>Integration Run Queue</span>
          <span className={isSectionOpen('integration-queue') ? 'config-chevron open' : 'config-chevron'}>▾</span>
        </button>
        {isSectionOpen('integration-queue') && (
          <div className="config-accordion-body">
            <SourcesPage
              focusSource="all"
              title="Integration Queue"
              caption="NVD, KEV, and CSAF/VEX ingestion jobs are processed in a single shared queue."
            />
          </div>
        )}
      </section>
      )}

      {policyValidationErrors.length > 0 && (
        <div className="notice error">
          <strong>Inline validation:</strong>
          <ul>
            {policyValidationErrors.map((error) => (
              <li key={`${error.field}-${error.message}`}>{error.message}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="button-row form-submit-row">
        <button
          type="button"
          className="btn btn-primary"
          onClick={savePolicy}
          disabled={policySaving || policyValidationErrors.length > 0}
        >
          {policySaving ? 'Saving...' : 'Save Configuration'}
        </button>
      </div>
      {policyMessage && <div className="notice">{policyMessage}</div>}
    </div>
  );
}
