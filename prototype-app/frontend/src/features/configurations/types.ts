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
};

export type PrototypeDataResetResponse = {
  deletedRows: Record<string, number>;
  resetAt: string;
};
