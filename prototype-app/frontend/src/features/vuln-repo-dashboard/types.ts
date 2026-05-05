export type VulnRepoDashboardSummaryCards = {
  trackedCount: number;
  trackedAddedLastWeek: number;
  applicableCount: number;
  applicableAddedLastWeek: number;
  impactedInvestigationDoneCount: number;
  impactedAddedLastWeek: number;
  remediationCveCount: number;
  needsAttentionCount: number;
  criticalCount: number;
  exploitCount: number;
  exploitCoveragePercent: number;
  impactedCriticalCount: number;
  impactedHighCount: number;
  impactedMediumCount: number;
  impactedLowCount: number;
  impactedKevCount: number;
  kevAddedLastWeek: number;
  criticalUninvestigatedCount: number;
  kevReinvestigationCount: number;
};

export type VulnRepoDashboardSeverityBreakdownItem = {
  severity: string;
  count: number;
};

export type VulnRepoDashboardResolutionStatus = {
  unresolvedCount: number;
  resolvedCount: number;
  inProgressCount: number;
  acceptedRiskCount: number;
};

export type VulnRepoDashboardCriticalUnresolvedItem = {
  externalId: string;
  title: string;
  severity: string;
  statusLabel: string;
  exploitKnown: boolean;
  findingCount: number;
};

export type VulnRepoDashboardTopAffectedSoftwareItem = {
  softwareIdentityId: string;
  software: string;
  vendor: string;
  cveCount: number;
  criticalCount: number;
  highCount: number;
  impactedAssetCount: number;
  highestSeverity: string;
};

export type VulnRepoDashboardRecentAdvisoryItem = {
  externalId: string;
  title: string;
  descriptionSnippet: string;
  severity: string;
  source: string;
  publishedAt?: string;
  lastModifiedAt?: string;
};

export type VulnRepoDashboardImpactedAssetItem = {
  assetId: string;
  assetName: string;
  assetType: string;
  identifier: string;
  environment?: string;
  cveCount: number;
};

export type VulnRepoDashboard = {
  generatedAt: string;
  summaryCards: VulnRepoDashboardSummaryCards;
  severityBreakdown: VulnRepoDashboardSeverityBreakdownItem[];
  resolutionStatus: VulnRepoDashboardResolutionStatus;
  criticalUnresolved: VulnRepoDashboardCriticalUnresolvedItem[];
  topAffectedSoftware: VulnRepoDashboardTopAffectedSoftwareItem[];
  recentAdvisories: VulnRepoDashboardRecentAdvisoryItem[];
  impactedAssets: VulnRepoDashboardImpactedAssetItem[];
};
