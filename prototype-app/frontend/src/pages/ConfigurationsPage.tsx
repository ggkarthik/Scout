import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { RiskPolicy } from '../features/configurations/types';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';

type ConfigNavKey = 'triage' | 'risk-score' | 'sla' | 'automation' | 'dev-tools';

interface ConfigNavItem {
  key: ConfigNavKey;
  label: string;
  description: string;
  badge?: string;
}

const CONFIG_NAV: ConfigNavItem[] = [
  {
    key: 'sla',
    label: 'SLA & Remediation',
    description: 'Remediation deadlines by risk and asset tier',
  },
  {
    key: 'risk-score',
    label: 'Vulnerability Scoring',
    description: 'CVSS, EPSS, KEV weights and VEX modifiers',
  },
  {
    key: 'triage',
    label: 'S.AI Prioritization',
    description: 'AI urgency signal weights for risk ranking',
    badge: 'AI',
  },
  {
    key: 'automation',
    label: 'Workflow Automation',
    description: 'Auto-close and finding generation rules',
  },
  {
    key: 'dev-tools',
    label: 'Developer Tools',
    description: 'Prototype data controls',
  },
];

interface TriageSignalDef {
  field: keyof Pick<
    RiskPolicy,
    | 'triageExploitabilityWeight'
    | 'triageBlastRadiusWeight'
    | 'triageEolRiskWeight'
    | 'triageSlaBreachWeight'
    | 'triageMissingOwnerBoost'
    | 'triagePatchGapBoost'
  >;
  label: string;
  icon: string;
  businessReason: string;
  urgencyTag: string;
}

const TRIAGE_SIGNALS: TriageSignalDef[] = [
  {
    field: 'triageExploitabilityWeight',
    label: 'Exploitability',
    icon: '⚡',
    businessReason:
      'High EPSS score or inclusion in KEV means attackers are actively weaponizing this CVE now — not someday. Every day without a patch is active exposure.',
    urgencyTag: 'EPSS > 0.5 or in KEV',
  },
  {
    field: 'triageBlastRadiusWeight',
    label: 'Asset Blast Radius',
    icon: '📡',
    businessReason:
      'The more assets a vulnerability affects, the wider the breach impact if exploited. High blast radius means multiple teams must coordinate patching at the same time.',
    urgencyTag: '10+ matched assets',
  },
  {
    field: 'triageEolRiskWeight',
    label: 'EOL / End-of-Life Risk',
    icon: '⏱',
    businessReason:
      'Software past end-of-life receives no vendor patches. Vulnerabilities in EOL components are permanent until the software is replaced — not just delayed.',
    urgencyTag: 'EOL component affected',
  },
  {
    field: 'triageSlaBreachWeight',
    label: 'SLA Breach Proximity',
    icon: '📅',
    businessReason:
      'Items close to SLA deadline create audit and compliance exposure. Near-breach findings need unblocking now or the team needs escalation support.',
    urgencyTag: '< 5 days to SLA breach',
  },
  {
    field: 'triageMissingOwnerBoost',
    label: 'Missing Owner',
    icon: '👤',
    businessReason:
      'Findings with no assigned owner have no accountable team driving remediation. They age silently. Surfacing them early reduces chronic ownership gaps.',
    urgencyTag: 'No owner assigned',
  },
  {
    field: 'triagePatchGapBoost',
    label: 'Patch Gap',
    icon: '🔧',
    businessReason:
      'When no vendor fix exists, risk stays active until compensating controls are deployed. These findings need manual mitigation planning, not just a ticket to patch.',
    urgencyTag: 'No patch available',
  },
];

type PolicyValidationError = {
  field: keyof RiskPolicy;
  message: string;
};

function validateRiskPolicy(policy: RiskPolicy): PolicyValidationError[] {
  const errors: PolicyValidationError[] = [];
  const chk = (
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

  chk('cvssWeight', policy.cvssWeight, 0, 5, 'CVSS weight');
  chk('kevBoost', policy.kevBoost, 0, 5, 'KEV boost');
  chk('epssWeight', policy.epssWeight, 0, 5, 'EPSS weight');
  chk('vexNotAffectedFreshnessDays', policy.vexNotAffectedFreshnessDays, 1, 365, 'VEX not-affected freshness');
  chk('vexFixedFreshnessDays', policy.vexFixedFreshnessDays, 1, 365, 'VEX fixed freshness');
  chk('vexKnownAffectedBoost', policy.vexKnownAffectedBoost, 0, 3, 'VEX known-affected boost');
  chk('vexUnderInvestigationPenalty', policy.vexUnderInvestigationPenalty, 0, 3, 'VEX under-investigation penalty');
  chk('vexNotAffectedReduction', policy.vexNotAffectedReduction, 0, 3, 'VEX not-affected reduction');
  chk('vexStalePenalty', policy.vexStalePenalty, 0, 3, 'VEX stale penalty');
  chk('criticalThreshold', policy.criticalThreshold, 0, 10, 'Critical threshold');
  chk('highThreshold', policy.highThreshold, 0, 10, 'High threshold');
  if (policy.highThreshold > policy.criticalThreshold) {
    errors.push({ field: 'highThreshold', message: 'High threshold cannot exceed critical threshold.' });
  }
  chk('criticalSlaDays', policy.criticalSlaDays, 0, 365, 'Critical SLA');
  chk('highSlaDays', policy.highSlaDays, 0, 365, 'High SLA');
  chk('mediumSlaDays', policy.mediumSlaDays, 0, 365, 'Medium SLA');
  chk('lowSlaDays', policy.lowSlaDays, 0, 365, 'Low SLA');
  chk('assetCriticalSlaMultiplier', policy.assetCriticalSlaMultiplier, 0, 5, 'Critical SLA multiplier');
  chk('assetHighSlaMultiplier', policy.assetHighSlaMultiplier, 0, 5, 'High SLA multiplier');
  chk('assetMediumSlaMultiplier', policy.assetMediumSlaMultiplier, 0, 5, 'Medium SLA multiplier');
  chk('assetLowSlaMultiplier', policy.assetLowSlaMultiplier, 0, 5, 'Low SLA multiplier');
  chk('autoCloseAfterDays', policy.autoCloseAfterDays, 0, 365, 'Auto-close days');
  chk('triageExploitabilityWeight', policy.triageExploitabilityWeight, 0, 2, 'Exploitability weight');
  chk('triageBlastRadiusWeight', policy.triageBlastRadiusWeight, 0, 2, 'Blast radius weight');
  chk('triageEolRiskWeight', policy.triageEolRiskWeight, 0, 2, 'EOL risk weight');
  chk('triageSlaBreachWeight', policy.triageSlaBreachWeight, 0, 2, 'SLA breach weight');
  chk('triageMissingOwnerBoost', policy.triageMissingOwnerBoost, 0, 2, 'Missing owner boost');
  chk('triagePatchGapBoost', policy.triagePatchGapBoost, 0, 2, 'Patch gap boost');
  return errors;
}

const SECTION_FIELDS: Partial<Record<ConfigNavKey, ReadonlyArray<keyof RiskPolicy>>> = {
  triage: [
    'triageExploitabilityWeight',
    'triageBlastRadiusWeight',
    'triageEolRiskWeight',
    'triageSlaBreachWeight',
    'triageMissingOwnerBoost',
    'triagePatchGapBoost',
  ],
  'risk-score': [
    'cvssWeight',
    'kevBoost',
    'epssWeight',
    'criticalThreshold',
    'highThreshold',
    'vexNotAffectedFreshnessDays',
    'vexFixedFreshnessDays',
    'vexKnownAffectedBoost',
    'vexUnderInvestigationPenalty',
    'vexNotAffectedReduction',
    'vexStalePenalty',
  ],
  sla: [
    'criticalSlaDays',
    'highSlaDays',
    'mediumSlaDays',
    'lowSlaDays',
    'assetCriticalSlaMultiplier',
    'assetHighSlaMultiplier',
    'assetMediumSlaMultiplier',
    'assetLowSlaMultiplier',
  ],
  automation: ['autoCloseEnabled', 'autoCloseAfterDays', 'findingGenerationMode'],
};

// Module-level helper — used in both useEffect (initial load) and savePolicy
// (after save response) so the triage sliders always have a numeric value even
// when the backend is running pre-V1062 and doesn't return these fields.
type TriageKeys =
  | 'triageExploitabilityWeight'
  | 'triageBlastRadiusWeight'
  | 'triageEolRiskWeight'
  | 'triageSlaBreachWeight'
  | 'triageMissingOwnerBoost'
  | 'triagePatchGapBoost';

function applyTriageDefaults(data: RiskPolicy): RiskPolicy {
  const base = data as Omit<RiskPolicy, TriageKeys>;
  const raw = data as unknown as Record<string, unknown>;
  return {
    ...base,
    triageExploitabilityWeight: (raw.triageExploitabilityWeight as number | undefined) ?? 1.0,
    triageBlastRadiusWeight: (raw.triageBlastRadiusWeight as number | undefined) ?? 1.0,
    triageEolRiskWeight: (raw.triageEolRiskWeight as number | undefined) ?? 0.8,
    triageSlaBreachWeight: (raw.triageSlaBreachWeight as number | undefined) ?? 1.2,
    triageMissingOwnerBoost: (raw.triageMissingOwnerBoost as number | undefined) ?? 0.5,
    triagePatchGapBoost: (raw.triagePatchGapBoost as number | undefined) ?? 0.3,
  };
}

function scoreSeverityLabel(score: number): { label: string; color: string } {
  if (score >= 9) return { label: 'Critical', color: 'var(--critical)' };
  if (score >= 7) return { label: 'High', color: 'var(--high)' };
  if (score >= 4) return { label: 'Medium', color: 'var(--medium)' };
  return { label: 'Low', color: 'var(--low)' };
}

function fmt2(n: number): string {
  return n.toFixed(2);
}

export function ConfigurationsPage() {
  const queryClient = useQueryClient();
  const riskPolicyQuery = useRiskPolicyQuery();
  const [policy, setPolicy] = React.useState<RiskPolicy | null>(null);
  const [policyMessage, setPolicyMessage] = React.useState('');
  const [policySaving, setPolicySaving] = React.useState(false);
  const [resetBusy, setResetBusy] = React.useState(false);
  const [resetMessage, setResetMessage] = React.useState('');
  const [activeSection, setActiveSection] = React.useState<ConfigNavKey>('sla');
  const [showAdvancedVex, setShowAdvancedVex] = React.useState(false);

  // Risk score live simulator state
  const [simCvss, setSimCvss] = React.useState(7.5);
  const [simEpss, setSimEpss] = React.useState(0.12);
  const [simInKev, setSimInKev] = React.useState(false);
  const [simAsset, setSimAsset] = React.useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('MEDIUM');

  // Triage score live simulator state
  const [triageSimEpss, setTriageSimEpss] = React.useState(0.45);
  const [triageSimInKev, setTriageSimInKev] = React.useState(true);
  const [triageSimAssets, setTriageSimAssets] = React.useState(18);
  const [triageSimHasEol, setTriageSimHasEol] = React.useState(false);
  const [triageSimSlaDays, setTriageSimSlaDays] = React.useState(4);
  const [triageSimMissingOwner, setTriageSimMissingOwner] = React.useState(false);
  const [triageSimPatchGap, setTriageSimPatchGap] = React.useState(false);

  const policyValidationErrors = React.useMemo(
    () => (policy == null ? [] : validateRiskPolicy(policy)),
    [policy]
  );

  React.useEffect(() => {
    if (riskPolicyQuery.data) {
      setPolicy(applyTriageDefaults(riskPolicyQuery.data));
    }
  }, [riskPolicyQuery.data]);

  const updatePolicy = (key: keyof RiskPolicy, value: number | boolean | string): void => {
    if (!policy) return;
    setPolicy({ ...policy, [key]: value });
  };

  const savePolicy = async (): Promise<void> => {
    if (!policy) return;
    if (policyValidationErrors.length > 0) {
      setPolicyMessage('Fix validation errors before saving.');
      return;
    }
    setPolicySaving(true);
    setPolicyMessage('');
    try {
      const updated = applyTriageDefaults(await api.updateRiskPolicy(policy));
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
    if (!confirmed) return;
    setResetBusy(true);
    setResetMessage('');
    try {
      const result = await api.cleanAllPrototypeData();
      const total = Object.values(result.deletedRows ?? {}).reduce(
        (sum, value) => sum + Number(value || 0),
        0
      );
      setResetMessage(`Prototype data reset complete. Deleted ${total} rows.`);
      await riskPolicyQuery.refetch();
    } catch (e) {
      setResetMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setResetBusy(false);
    }
  };

  // Computed risk score sim
  const riskSim = React.useMemo(() => {
    if (!policy) return null;
    const cvssC = simCvss * policy.cvssWeight;
    const epssC = simEpss * 10 * policy.epssWeight;
    const kevC = simInKev ? policy.kevBoost : 0;
    const assetBoosts = {
      CRITICAL: policy.assetCriticalRiskBoost,
      HIGH: policy.assetHighRiskBoost,
      MEDIUM: policy.assetMediumRiskBoost,
      LOW: policy.assetLowRiskBoost,
    };
    const assetC = assetBoosts[simAsset];
    const raw = cvssC + epssC + kevC + assetC;
    const final = Math.min(10, Math.max(0, raw));
    const maxRaw = Math.max(raw, 0.01);
    return { cvssC, epssC, kevC, assetC, raw, final, maxRaw };
  }, [policy, simCvss, simEpss, simInKev, simAsset]);

  // Computed triage sim
  const triageSim = React.useMemo(() => {
    if (!policy) return null;
    const exploitSignal = Math.min(1, triageSimEpss * 1.4 + (triageSimInKev ? 0.35 : 0));
    const blastSignal = Math.min(1, triageSimAssets / 40);
    const eolSignal = triageSimHasEol ? 1 : 0;
    const slaSignal = Math.max(0, 1 - triageSimSlaDays / 20);
    const ownerSignal = triageSimMissingOwner ? 1 : 0;
    const patchSignal = triageSimPatchGap ? 1 : 0;

    const exploitC = exploitSignal * policy.triageExploitabilityWeight;
    const blastC = blastSignal * policy.triageBlastRadiusWeight;
    const eolC = eolSignal * policy.triageEolRiskWeight;
    const slaC = slaSignal * policy.triageSlaBreachWeight;
    const ownerC = ownerSignal * policy.triageMissingOwnerBoost;
    const patchC = patchSignal * policy.triagePatchGapBoost;

    const raw = exploitC + blastC + eolC + slaC + ownerC + patchC;
    const normalized = Math.min(10, raw * 1.8);

    const activeReasons: string[] = [];
    if (triageSimInKev) activeReasons.push('Known exploited (KEV)');
    if (triageSimEpss >= 0.5) activeReasons.push(`High EPSS (${(triageSimEpss * 100).toFixed(0)}%)`);
    if (triageSimAssets >= 10) activeReasons.push(`${triageSimAssets} assets affected`);
    if (triageSimHasEol) activeReasons.push('EOL component');
    if (triageSimSlaDays <= 5) activeReasons.push(`SLA breach in ${triageSimSlaDays}d`);
    if (triageSimMissingOwner) activeReasons.push('No owner assigned');
    if (triageSimPatchGap) activeReasons.push('No patch available');

    return { exploitC, blastC, eolC, slaC, ownerC, patchC, raw, normalized, activeReasons };
  }, [
    policy,
    triageSimEpss,
    triageSimInKev,
    triageSimAssets,
    triageSimHasEol,
    triageSimSlaDays,
    triageSimMissingOwner,
    triageSimPatchGap,
  ]);

  if (!policy) {
    if (riskPolicyQuery.error instanceof Error) {
      return <div className="panel">Failed to load configuration: {riskPolicyQuery.error.message}</div>;
    }
    return <div className="panel">Loading configuration...</div>;
  }

  const sectionErrors = (key: ConfigNavKey): PolicyValidationError[] => {
    const fields = SECTION_FIELDS[key];
    if (!fields) return [];
    return policyValidationErrors.filter((e) => (fields as ReadonlyArray<keyof RiskPolicy>).includes(e.field));
  };

  // Plain render helper — NOT a component, so React never sees a type change
  // across renders (avoids the inner-component unmount/remount anti-pattern).
  const renderSaveRow = (sectionKey: ConfigNavKey) => {
    const errs = sectionErrors(sectionKey);
    return (
      <>
        {errs.length > 0 && (
          <div className="notice error" style={{ marginTop: 12 }}>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {errs.map((e) => <li key={e.field}>{e.message}</li>)}
            </ul>
          </div>
        )}
        <div className="button-row form-submit-row">
          <button
            type="button"
            className="btn btn-primary"
            onClick={savePolicy}
            disabled={policySaving || errs.length > 0}
          >
            {policySaving ? 'Saving…' : 'Save'}
          </button>
          {policyMessage && activeSection === sectionKey && (
            <span className="field-hint" style={{ marginLeft: 10, color: policyMessage.includes('saved') ? 'var(--low)' : 'var(--critical)' }}>
              {policyMessage}
            </span>
          )}
        </div>
      </>
    );
  };

  // ── Triage section ─────────────────────────────────────────────────────────
  const renderTriage = () => (
    <div className="config-section-body">
      <div className="config-section-intro">
        <p>
          These weights control how the system ranks findings and CVEs{' '}
          <strong>before any investigation starts</strong>. Signals with higher weight push
          matching items to the top of the recommended work queue. Set a signal to{' '}
          <span className="mono">0</span> to ignore it entirely.
        </p>
      </div>

      <div className="triage-signal-list">
        {TRIAGE_SIGNALS.map((sig) => {
          const val = (policy[sig.field] as number) ?? 0;
          const pct = (val / 2) * 100;
          return (
            <div key={sig.field} className="triage-signal-card">
              <div className="triage-signal-top">
                <span className="triage-signal-icon" aria-hidden="true">{sig.icon}</span>
                <div className="triage-signal-meta">
                  <div className="triage-signal-name">{sig.label}</div>
                  <div className="triage-signal-reason">{sig.businessReason}</div>
                  <div className="triage-urgency-tag" style={{ marginTop: 5 }}>
                    Example signal: {sig.urgencyTag}
                  </div>
                </div>
              </div>
              <div className="triage-weight-row">
                <span className="triage-weight-label">Off</span>
                <div style={{ flex: 1, position: 'relative' }}>
                  <input
                    type="range"
                    className="triage-weight-slider"
                    min={0}
                    max={2}
                    step={0.1}
                    value={val}
                    onChange={(e) => updatePolicy(sig.field, Number(e.target.value))}
                    aria-label={`${sig.label} weight`}
                  />
                  <div
                    className="triage-slider-track-fill"
                    style={{ width: `${pct}%` }}
                    aria-hidden="true"
                  />
                </div>
                <span className="triage-weight-label">Max</span>
                <span className="triage-weight-value">{val.toFixed(1)}</span>
              </div>
            </div>
          );
        })}
      </div>

      {renderSaveRow("triage")}

      {/* Triage score simulator */}
      <div className="score-sim" style={{ marginTop: 20 }}>
        <div className="score-sim-header">
          Triage Score Simulator — see how a sample finding ranks under your current weights
        </div>
        <div className="score-sim-body">
          <div className="score-sim-inputs">
            <div className="score-sim-input-row">
              <label>EPSS Score (exploitation probability)</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.01}
                  value={triageSimEpss}
                  onChange={(e) => setTriageSimEpss(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{(triageSimEpss * 100).toFixed(0)}%</span>
              </div>
            </div>
            <div className="score-sim-input-row">
              <label>Assets affected</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={50}
                  step={1}
                  value={triageSimAssets}
                  onChange={(e) => setTriageSimAssets(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{triageSimAssets}</span>
              </div>
            </div>
            <div className="score-sim-input-row">
              <label>Days until SLA breach</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={30}
                  step={1}
                  value={triageSimSlaDays}
                  onChange={(e) => setTriageSimSlaDays(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{triageSimSlaDays}d</span>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 4 }}>
              {[
                { label: 'Known exploited (KEV)', val: triageSimInKev, set: setTriageSimInKev },
                { label: 'EOL component', val: triageSimHasEol, set: setTriageSimHasEol },
                { label: 'No owner assigned', val: triageSimMissingOwner, set: setTriageSimMissingOwner },
                { label: 'No patch available', val: triageSimPatchGap, set: setTriageSimPatchGap },
              ].map(({ label, val, set }) => (
                <label
                  key={label}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8rem', cursor: 'pointer', fontWeight: 500 }}
                >
                  <input
                    type="checkbox"
                    checked={val}
                    onChange={(e) => set(e.target.checked)}
                    style={{ accentColor: 'var(--accent)', width: 14, height: 14 }}
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>

          {triageSim && (
            <div className="score-sim-result">
              {(() => {
                const { label, color } = scoreSeverityLabel(triageSim.normalized);
                return (
                  <div
                    className="score-sim-badge"
                    style={{ background: `color-mix(in srgb, ${color} 12%, var(--panel-muted))`, border: `1px solid color-mix(in srgb, ${color} 30%, var(--border))` }}
                  >
                    <div>
                      <div
                        className="score-sim-badge-number"
                        style={{ color }}
                      >
                        {triageSim.normalized.toFixed(1)}
                      </div>
                      <div className="score-sim-badge-label" style={{ color }}>
                        {label} Triage Priority
                      </div>
                    </div>
                  </div>
                );
              })()}

              {triageSim.activeReasons.length > 0 && (
                <div>
                  <div style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--muted)', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Active urgency signals
                  </div>
                  <div className="triage-urgency-signals">
                    {triageSim.activeReasons.map((r) => (
                      <span key={r} className="triage-urgency-tag">{r}</span>
                    ))}
                  </div>
                </div>
              )}

              <div className="score-breakdown-list">
                {[
                  { label: 'Exploitability', val: triageSim.exploitC, color: 'var(--critical)' },
                  { label: 'Blast Radius', val: triageSim.blastC, color: 'var(--high)' },
                  { label: 'EOL Risk', val: triageSim.eolC, color: 'var(--medium)' },
                  { label: 'SLA Breach', val: triageSim.slaC, color: 'var(--accent)' },
                  { label: 'Missing Owner', val: triageSim.ownerC, color: 'var(--muted)' },
                  { label: 'Patch Gap', val: triageSim.patchC, color: 'var(--muted)' },
                ].map(({ label, val, color }) => (
                  <div key={label} className="score-breakdown-row">
                    <span className="score-breakdown-label">{label}</span>
                    <div className="score-breakdown-bar-bg">
                      <div
                        className="score-breakdown-bar-fill"
                        style={{
                          width: `${Math.min(100, (val / Math.max(triageSim.raw, 0.01)) * 100)}%`,
                          background: color,
                        }}
                      />
                    </div>
                    <span className="score-breakdown-value">{fmt2(val)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // ── Risk Score section ─────────────────────────────────────────────────────
  const renderRiskScore = () => (
    <div className="config-section-body">
      <div className="config-section-intro">
        <p>
          Controls how the risk score (0–10) is computed for each finding.
          Score = <span className="mono">cvss × cvssWeight + epss×10 × epssWeight + kevBoost + assetBoost + vexModifiers</span>,
          clamped to [0, 10].
        </p>
      </div>

      <div className="form-grid ingestion-grid">
        <label>CVSS Weight
          <input
            type="number"
            step="0.1"
            min={0}
            max={5}
            value={policy.cvssWeight}
            onChange={(e) => updatePolicy('cvssWeight', Number(e.target.value))}
          />
          <span className="field-hint">Multiplier on CVSS base score (0–10)</span>
        </label>
        <label>EPSS Weight
          <input
            type="number"
            step="0.1"
            min={0}
            max={5}
            value={policy.epssWeight}
            onChange={(e) => updatePolicy('epssWeight', Number(e.target.value))}
          />
          <span className="field-hint">Multiplier on EPSS × 10 (normalized to CVSS scale)</span>
        </label>
        <label>KEV Boost
          <input
            type="number"
            step="0.1"
            min={0}
            max={5}
            value={policy.kevBoost}
            onChange={(e) => updatePolicy('kevBoost', Number(e.target.value))}
          />
          <span className="field-hint">Flat additive boost when CVE is in CISA KEV catalog</span>
        </label>
        <label>Critical Threshold
          <input
            type="number"
            step="0.1"
            min={0}
            max={10}
            value={policy.criticalThreshold}
            onChange={(e) => updatePolicy('criticalThreshold', Number(e.target.value))}
          />
          <span className="field-hint">Score ≥ {policy.criticalThreshold} → Critical</span>
        </label>
        <label>High Threshold
          <input
            type="number"
            step="0.1"
            min={0}
            max={10}
            value={policy.highThreshold}
            onChange={(e) => updatePolicy('highThreshold', Number(e.target.value))}
          />
          <span className="field-hint">Score ≥ {policy.highThreshold} → High</span>
        </label>
      </div>

      <div className="advanced-vex-toggle-row" style={{ marginTop: 12 }}>
        <button
          type="button"
          className="btn-link"
          onClick={() => setShowAdvancedVex((v) => !v)}
        >
          <span className={showAdvancedVex ? 'config-chevron open' : 'config-chevron'}>▾</span>
          {showAdvancedVex ? 'Hide VEX modifiers' : 'Show VEX modifiers'}
        </button>
        {!showAdvancedVex && (
          <span className="field-hint">Freshness windows and score adjustments for VEX assertion states</span>
        )}
      </div>

      {showAdvancedVex && (
        <div className="form-grid ingestion-grid" style={{ marginTop: 8 }}>
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

      {renderSaveRow("risk-score")}

      {/* Live Score Simulator */}
      <div className="score-sim" style={{ marginTop: 20 }}>
        <div className="score-sim-header">Score Simulator — preview how weights affect a sample CVE</div>
        <div className="score-sim-body">
          <div className="score-sim-inputs">
            <div className="score-sim-input-row">
              <label>CVSS Score</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={10}
                  step={0.1}
                  value={simCvss}
                  onChange={(e) => setSimCvss(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{simCvss.toFixed(1)}</span>
              </div>
            </div>
            <div className="score-sim-input-row">
              <label>EPSS Score (exploitation probability)</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.01}
                  value={simEpss}
                  onChange={(e) => setSimEpss(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{(simEpss * 100).toFixed(0)}%</span>
              </div>
            </div>
            <div className="score-sim-input-row">
              <label>Asset criticality</label>
              <select
                value={simAsset}
                onChange={(e) => setSimAsset(e.target.value as typeof simAsset)}
              >
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: '0.82rem', cursor: 'pointer', fontWeight: 500, marginTop: 4 }}>
              <input
                type="checkbox"
                checked={simInKev}
                onChange={(e) => setSimInKev(e.target.checked)}
                style={{ accentColor: 'var(--accent)', width: 14, height: 14 }}
              />
              In CISA KEV catalog (known exploited)
            </label>
          </div>

          {riskSim && (
            <div className="score-sim-result">
              {(() => {
                const { label, color } = scoreSeverityLabel(riskSim.final);
                return (
                  <div
                    className="score-sim-badge"
                    style={{ background: `color-mix(in srgb, ${color} 12%, var(--panel-muted))`, border: `1px solid color-mix(in srgb, ${color} 30%, var(--border))` }}
                  >
                    <div>
                      <div className="score-sim-badge-number" style={{ color }}>
                        {riskSim.final.toFixed(2)}
                      </div>
                      <div className="score-sim-badge-label" style={{ color }}>
                        Risk Score — {label}
                      </div>
                    </div>
                  </div>
                );
              })()}

              <div className="score-breakdown-list">
                {[
                  { label: 'CVSS contribution', val: riskSim.cvssC, color: 'var(--accent)' },
                  { label: 'EPSS contribution', val: riskSim.epssC, color: 'var(--medium)' },
                  { label: 'KEV boost', val: riskSim.kevC, color: 'var(--critical)' },
                  { label: 'Asset boost', val: riskSim.assetC, color: 'var(--high)' },
                ].map(({ label, val, color }) => (
                  <div key={label} className="score-breakdown-row">
                    <span className="score-breakdown-label">{label}</span>
                    <div className="score-breakdown-bar-bg">
                      <div
                        className="score-breakdown-bar-fill"
                        style={{
                          width: `${Math.min(100, (val / riskSim.maxRaw) * 100)}%`,
                          background: color,
                        }}
                      />
                    </div>
                    <span className="score-breakdown-value">{fmt2(val)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // ── SLA section ────────────────────────────────────────────────────────────
  const renderSla = () => (
    <div className="config-section-body">
      <div className="config-section-intro">
        <p>
          Sets remediation deadlines per risk tier. Asset multipliers tighten SLAs for
          high-criticality assets — a multiplier below 1.0 means less time.
        </p>
      </div>

      <div style={{ marginBottom: 16 }}>
        <div className="config-subsection-label">Base SLA Days</div>
        <div className="form-grid ingestion-grid">
          <label>Critical Risk
            <input type="number" min={0} max={365} value={policy.criticalSlaDays} onChange={(e) => updatePolicy('criticalSlaDays', Number(e.target.value))} />
            <span className="field-hint">{policy.criticalSlaDays} days to remediate Critical findings</span>
          </label>
          <label>High Risk
            <input type="number" min={0} max={365} value={policy.highSlaDays} onChange={(e) => updatePolicy('highSlaDays', Number(e.target.value))} />
            <span className="field-hint">{policy.highSlaDays} days to remediate High findings</span>
          </label>
          <label>Medium Risk
            <input type="number" min={0} max={365} value={policy.mediumSlaDays} onChange={(e) => updatePolicy('mediumSlaDays', Number(e.target.value))} />
            <span className="field-hint">{policy.mediumSlaDays} days to remediate Medium findings</span>
          </label>
          <label>Low Risk
            <input type="number" min={0} max={365} value={policy.lowSlaDays} onChange={(e) => updatePolicy('lowSlaDays', Number(e.target.value))} />
            <span className="field-hint">{policy.lowSlaDays} days to remediate Low findings</span>
          </label>
        </div>
      </div>

      <div>
        <div className="config-subsection-label">Asset Criticality Multipliers</div>
        <div className="form-grid ingestion-grid">
          <label>Critical Asset Multiplier
            <input type="number" step="0.1" min={0} max={5} value={policy.assetCriticalSlaMultiplier} onChange={(e) => updatePolicy('assetCriticalSlaMultiplier', Number(e.target.value))} />
            <span className="field-hint">Effective: ~{Math.round(policy.criticalSlaDays * policy.assetCriticalSlaMultiplier)} days for Critical findings</span>
          </label>
          <label>High Asset Multiplier
            <input type="number" step="0.1" min={0} max={5} value={policy.assetHighSlaMultiplier} onChange={(e) => updatePolicy('assetHighSlaMultiplier', Number(e.target.value))} />
            <span className="field-hint">Effective: ~{Math.round(policy.highSlaDays * policy.assetHighSlaMultiplier)} days for High findings</span>
          </label>
          <label>Medium Asset Multiplier
            <input type="number" step="0.1" min={0} max={5} value={policy.assetMediumSlaMultiplier} onChange={(e) => updatePolicy('assetMediumSlaMultiplier', Number(e.target.value))} />
            <span className="field-hint">Effective: ~{Math.round(policy.mediumSlaDays * policy.assetMediumSlaMultiplier)} days for Medium findings</span>
          </label>
          <label>Low Asset Multiplier
            <input type="number" step="0.1" min={0} max={5} value={policy.assetLowSlaMultiplier} onChange={(e) => updatePolicy('assetLowSlaMultiplier', Number(e.target.value))} />
            <span className="field-hint">Effective: ~{Math.round(policy.lowSlaDays * policy.assetLowSlaMultiplier)} days for Low findings</span>
          </label>
        </div>
      </div>

      {renderSaveRow("sla")}
    </div>
  );

  // ── Automation section ─────────────────────────────────────────────────────
  const renderAutomation = () => (
    <div className="config-section-body">
      <div style={{ marginBottom: 20 }}>
        <div className="config-subsection-label">Org CVE Finding Generation</div>
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
        <div className="inline-note" style={{ marginTop: 8 }}>
          <strong>AUTO</strong> creates findings automatically during recompute.{' '}
          <strong>MANUAL</strong> computes org-level CVE exposure, but findings are not
          auto-created until an analyst reviews and explicitly triggers creation.
        </div>
      </div>

      <div>
        <div className="config-subsection-label">Auto Close</div>
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
        <div className="inline-note" style={{ marginTop: 8 }}>
          Findings matching the configured asset identifier are moved to{' '}
          <span className="mono">AUTO_CLOSED</span> after the configured age.
        </div>
      </div>

      {renderSaveRow("automation")}
    </div>
  );

  // ── Dev tools section ──────────────────────────────────────────────────────
  const renderDevTools = () => (
    <div className="config-section-body">
      <div className="config-section-body danger-zone-section" style={{ marginTop: 0 }}>
        <div className="inline-note" style={{ marginBottom: 16 }}>
          Use this only in prototype mode. This action permanently clears findings, software
          inventory, assets, vulnerability intelligence records, org exposure rows, and sync
          run history.
        </div>
        <div className="button-row form-submit-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={cleanAllPrototypeData}
            disabled={resetBusy}
          >
            {resetBusy ? 'Cleaning…' : 'Clean All Prototype Data'}
          </button>
        </div>
        {resetMessage && <div className="notice" style={{ marginTop: 10 }}>{resetMessage}</div>}
      </div>
    </div>
  );

  const SECTION_TITLES: Record<ConfigNavKey, { title: string; description: string }> = {
    'risk-score': {
      title: 'Vulnerability Scoring',
      description:
        'Tune how CVSS, EPSS, KEV, asset context, and VEX assertions combine into a 0–10 risk score.',
    },
    triage: {
      title: 'S.AI Prioritization',
      description:
        'Configure how urgency signals are weighted when the S.AI engine ranks findings and CVEs before investigation starts.',
    },
    sla: {
      title: 'SLA & Remediation',
      description:
        'Set remediation deadlines per risk tier and apply asset criticality multipliers.',
    },
    automation: {
      title: 'Workflow Automation',
      description:
        'Control how findings are auto-generated and when stale findings are auto-closed.',
    },
    'dev-tools': {
      title: 'Developer Tools',
      description: 'Prototype controls — use only in development environments.',
    },
  };

  const { title, description } = SECTION_TITLES[activeSection];

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Configurations</h3>
        <span className="panel-caption">
          Vulnerability scoring, S.AI prioritization, SLA, workflow automation, and prototype controls
        </span>
      </div>

      <div className="config-layout">
        {/* Sidebar */}
        <nav className="config-sidebar" aria-label="Configuration sections">
          <div className="config-sidebar-title">Settings</div>
          {CONFIG_NAV.map((item) => (
            <button
              key={item.key}
              type="button"
              className={`config-nav-item${activeSection === item.key ? ' active' : ''}`}
              onClick={() => {
                setActiveSection(item.key);
                setPolicyMessage('');
              }}
              aria-current={activeSection === item.key ? 'page' : undefined}
            >
              <span className="config-nav-item-label">
                {item.label}
                {item.badge && (
                  <span className="config-nav-badge">{item.badge}</span>
                )}
              </span>
              <span className="config-nav-item-desc">{item.description}</span>
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="config-content">
          <div className="config-section-head">
            <div className="config-section-head-text">
              <h3>{title}</h3>
              <p>{description}</p>
            </div>
          </div>

          {activeSection === 'triage' && renderTriage()}
          {activeSection === 'risk-score' && renderRiskScore()}
          {activeSection === 'sla' && renderSla()}
          {activeSection === 'automation' && renderAutomation()}
          {activeSection === 'dev-tools' && renderDevTools()}
        </div>
      </div>
    </div>
  );
}
