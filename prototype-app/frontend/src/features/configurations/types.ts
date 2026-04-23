export type RiskPolicy = {
  cvssWeight: number;
  kevBoost: number;
  epssWeight: number;
  vexNotAffectedFreshnessDays: number;
  vexFixedFreshnessDays: number;
  vexKnownAffectedBoost: number;
  vexUnderInvestigationPenalty: number;
  vexNotAffectedReduction: number;
  vexStalePenalty: number;
  criticalThreshold: number;
  highThreshold: number;
  assetCriticalRiskBoost: number;
  assetHighRiskBoost: number;
  assetMediumRiskBoost: number;
  assetLowRiskBoost: number;
  criticalSlaDays: number;
  highSlaDays: number;
  mediumSlaDays: number;
  lowSlaDays: number;
  assetCriticalSlaMultiplier: number;
  assetHighSlaMultiplier: number;
  assetMediumSlaMultiplier: number;
  assetLowSlaMultiplier: number;
  autoCloseEnabled: boolean;
  autoCloseAssetIdentifier?: string;
  autoCloseAfterDays: number;
  findingGenerationMode: 'AUTO' | 'MANUAL';
  // Triage urgency signal weights — control how findings/CVEs are ranked
  // before investigation starts. All weights 0–2; 0 = disabled, 2 = highest influence.
  triageExploitabilityWeight: number;
  triageBlastRadiusWeight: number;
  triageEolRiskWeight: number;
  triageSlaBreachWeight: number;
  triageMissingOwnerBoost: number;
  triagePatchGapBoost: number;
};

export type PrototypeDataResetResponse = {
  deletedRows: Record<string, number>;
  resetAt: string;
};
