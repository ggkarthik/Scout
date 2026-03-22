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

export type Finding = {
  id: string;
  assetName: string;
  assetType: string;
  packageName: string;
  packageVersion: string;
  vulnerabilityId: string;
  source: string;
  severity: string;
  inKev: boolean;
  epss?: number;
  riskScore: number;
  confidenceScore: number;
  matchedBy: string;
  assignedTo?: string;
  dueAt?: string;
  suppressionReason?: string;
  suppressedUntil?: string;
  evidence: string;
  precedenceTrace?: string;
  vexStatus?: string;
  vexProvider?: string;
  vexFreshness?: string;
  matchedVexAssertionId?: string;
  impactReason?: string;
  firstObservedAt: string;
  lastObservedAt: string;
  decisionState: 'AFFECTED' | 'NOT_AFFECTED' | 'FIXED' | 'UNDER_INVESTIGATION' | 'NEEDS_REVIEW';
  status: 'OPEN' | 'RESOLVED' | 'SUPPRESSED' | 'AUTO_CLOSED';
  updatedAt: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
};

export type Dashboard = {
  assets: number;
  components: number;
  openFindings: number;
  criticalFindings: number;
  openCritical: number;
  openHigh: number;
  openMedium: number;
  openLow: number;
  averageOpenRiskScore: number;
  averageOpenConfidenceScore: number;
  highConfidenceOpenFindings: number;
  topVulnerabilities: TopFindingMetric[];
  topInstalledComponents: TopFindingMetric[];
  topAssetsAtRisk: TopFindingMetric[];
  topVulnerabilityProductIdentities: TopFindingMetric[];
  latestFindings: Finding[];
  noiseReduction: DashboardNoiseReduction;
  csafVexAnalytics: DashboardCsafVexAnalytics;
  correlationEfficiency: DashboardCorrelationEfficiency;
};

export type TopFindingMetric = {
  key: string;
  count: number;
};

export type DashboardNoiseReduction = {
  totalFilteredNotApplicable: number;
  neverOpenedNotApplicable: number;
  autoResolvedNotApplicable: number;
  deferredUnderInvestigation: number;
  potentialFindingsWithoutCorrelation: number;
  filteredPercentOfPotential: number;
  categories: TopFindingMetric[];
  trendLast30Days: TopFindingMetric[];
};

export type DashboardCsafVexAnalytics = {
  csafRunsLast30Days: number;
  csafSuccessfulRunsLast30Days: number;
  csafPartialFailureRunsLast30Days: number;
  csafNormalizationSuccessRate: number;
  csafPartialFailureRate: number;
  activeVexCoveragePercent: number;
  activeVexMatchedStateCount: number;
  activeApplicableAwaitingVexCount: number;
  activeVexConfirmedImpactedCount: number;
  activeVexConfirmedNotAffectedCount: number;
  activeVexNoPatchCount: number;
  findingsSuppressedByVex: number;
  suppressedByStaleVex: number;
  underInvestigationAging: number;
  vexCoverageByProvider: TopFindingMetric[];
  staleSuppressionsTrendLast30Days: TopFindingMetric[];
};

export type DashboardCorrelationEfficiency = {
  activeComponents: number;
  cpeEligibleActiveComponents: number;
  cpeIneligibleActiveComponents: number;
  cpeCoveragePercent: number;
  openFindingsMatchedByCpe: number;
  openFindingsCpeDirect: number;
  openFindingsCpeFallback: number;
  cpeDirectSharePercent: number;
  cpeFallbackSharePercent: number;
  averageOpenCpeConfidenceScore: number;
  cpeFindingsCreatedLast24Hours: number;
  nonCpeFindingsCreatedLast24Hours: number;
};

export type ApplicableSoftwareRecord = {
  componentId: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  ecosystem: string;
  packageName: string;
  version: string;
  applicableCveCount: number;
  awaitingVexCveCount: number;
  vexMatchedCveCount: number;
  impactedCveCount: number;
  noPatchCveCount: number;
  lastEvaluatedAt?: string;
};

export type ApplicableSoftwarePage = {
  items: ApplicableSoftwareRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type ImpactedCveRecord = {
  vulnerabilityId: string;
  externalId: string;
  severity: string;
  cvssScore?: number;
  epssScore?: number;
  inKev: boolean;
  impactedComponentCount: number;
  impactedAssetCount: number;
  noPatchComponentCount: number;
  lastEvaluatedAt?: string;
  lastModifiedAt?: string;
};

export type ImpactedCvePage = {
  items: ImpactedCveRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type CveInventoryMappingRecord = {
  vulnerabilityId: string;
  externalId: string;
  severity: string;
  cvssScore?: number;
  epssScore?: number;
  inKev: boolean;
  impactedComponentCount: number;
  noPatchComponentCount: number;
  lastModifiedAt?: string;
  matchedIdentifiers: string[];
  mappedSoftware: string[];
  mappedSoftwareCount: number;
};

export type DashboardCveInventoryMap = {
  topHighRisk: CveInventoryMappingRecord[];
  latest: CveInventoryMappingRecord[];
};

export type OperationalEndpointMetric = {
  key: string;
  label: string;
  requestCount: number;
  successCount: number;
  errorCount: number;
  averageMs: number;
  p95Ms: number;
  p99Ms: number;
  maxMs: number;
  lastMs: number;
  lastRecordedAt?: string;
};

export type OperationalExecutiveHealth = {
  ingestionSuccessRateLast24h: number;
  recomputeP95Ms: number;
  normalizationCoveragePercent: number;
  correlationNoiseReductionPercent: number;
  openCriticalFindings: number;
};

export type OperationalIngestionSourceMetric = {
  source: string;
  runs: number;
  successes: number;
  failures: number;
  successRatePercent: number;
  fetched: number;
  inserted: number;
  updated: number;
};

export type OperationalIngestionEfficiency = {
  sbomIngestionsLast24h: number;
  sbomIngestionsPerHour: number;
  sbomSuccessRatePercent: number;
  syncRunsLast24h: number;
  syncSuccessRatePercent: number;
  queueBacklog: number;
  recordsFetchedLast24h: number;
  recordsInsertedLast24h: number;
  recordsUpdatedLast24h: number;
  sourceBreakdown: OperationalIngestionSourceMetric[];
};

export type OperationalNormalizationQuality = {
  activeComponents: number;
  normalizedNameCoveragePercent: number;
  normalizedVersionCoveragePercent: number;
  softwareIdentityCoveragePercent: number;
};

export type OperationalCorrelationEffectiveness = {
  openFindings: number;
  highConfidenceAffectedRatePercent: number;
  unknownDecisionRatePercent: number;
  selectedMethodDistribution: TopFindingMetric[];
  decisionStateDistribution: TopFindingMetric[];
  workflowStatusDistribution: TopFindingMetric[];
};

export type OperationalNoiseLifecycle = {
  totalFilteredNotApplicable: number;
  neverOpenedNotApplicable: number;
  autoResolvedNotApplicable: number;
  deferredUnderInvestigation: number;
  filteredPercentOfPotential: number;
  reopenRatePercent: number;
  notApplicableCategories: TopFindingMetric[];
};

export type OperationalApiReadPath = {
  summaryReadModelReady: boolean;
  canonicalCveCount: number;
  summaryCveCount: number;
  summaryCoveragePercent: number;
  noiseProjectionReady?: boolean;
  noiseProjectionLastComputedAt?: string;
  noiseProjectionAgeSeconds?: number;
  noiseProjectionRefreshP95Ms?: number;
  noiseProjectionRefreshFailures?: number;
  filterCacheActive: boolean;
  filterCacheExpiresAt?: string;
  filterCacheHits: number;
  filterCacheMisses: number;
  filterCacheHitRatioPercent: number;
  endpointMetrics: OperationalEndpointMetric[];
};

export type OperationalSourceFreshness = {
  source: string;
  lastSuccessfulAt?: string;
  ageHours: number;
  stale: boolean;
};

export type OperationalFreshnessDrift = {
  staleThresholdHours: number;
  staleSourceCount: number;
  normalizationCoverageDrift7d: number;
  cpeFallbackShareDrift7d: number;
  sourceFreshness: OperationalSourceFreshness[];
};

export type OperationalMetricDefinition = {
  section: string;
  key: string;
  label: string;
  description: string;
};

export type OperationalSectionResponse<T> = {
  generatedAt: string;
  data: T;
};

export type OperationalQualityDomainCount = {
  domain: string;
  issueCount: number;
};

export type OperationalQualitySummary = {
  generatedAt: string;
  totalIssues: number;
  criticalIssues: number;
  affectsActiveFindingsCount: number;
  newIssuesLast24h: number;
  domainCounts: OperationalQualityDomainCount[];
};

export type OperationalQualityIssue = {
  id: string;
  issueKey: string;
  domain: string;
  issueType: string;
  severity: string;
  reasonCode: string;
  title: string;
  sourceObjectType: string;
  sourceObjectId?: string;
  primaryLabel?: string;
  secondaryLabel?: string;
  assetType?: string;
  sourceSystem?: string;
  ecosystem?: string;
  affectsActiveFindings: boolean;
  affectedAssetCount: number;
  affectedComponentCount: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
};

export type OperationalQualityDrilldownTarget = {
  label: string;
  href: string;
};

export type OperationalQualitySampleRecord = {
  label: string;
  primaryValue: string;
  secondaryValue?: string;
};

export type OperationalQualityIssueDetail = OperationalQualityIssue & {
  whyThisMatters: string;
  evidenceJson: string;
  recommendedAction: string;
  drilldownTargets: OperationalQualityDrilldownTarget[];
  sampleRecords: OperationalQualitySampleRecord[];
};

export type OperationalQualityIssuePage = {
  items: OperationalQualityIssue[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type OperationalQualityFilterValues = {
  domains: string[];
  issueTypes: string[];
  severities: string[];
  assetTypes: string[];
  sourceSystems: string[];
  ecosystems: string[];
};

export type OperationalDashboard = {
  generatedAt: string;
  executiveHealth: OperationalExecutiveHealth;
  ingestionEfficiency: OperationalIngestionEfficiency;
  normalizationQuality: OperationalNormalizationQuality;
  correlationEffectiveness: OperationalCorrelationEffectiveness;
  noiseLifecycle: OperationalNoiseLifecycle;
  apiReadPath: OperationalApiReadPath;
  freshnessDrift: OperationalFreshnessDrift;
  metricCatalog: OperationalMetricDefinition[];
};

export type IngestionResult = {
  status: string;
  fetched: number;
  inserted: number;
  updated: number;
  message: string;
};

export type SyncTriggerResponse = {
  runId: string;
  status: string;
  message: string;
};

export type SyncRun = {
  id: string;
  syncType: string;
  runDomain: 'INVENTORY' | 'VULN_INTEL' | 'PROCESSING';
  runClass: 'INGESTION' | 'REPAIR' | 'BACKFILL' | 'RECOMPUTE';
  status: string;
  queuePosition?: number;
  recordsFetched: number;
  recordsInserted: number;
  recordsUpdated: number;
  recordsFailed: number;
  startedAt: string;
  completedAt?: string;
  errorMessage?: string;
  metadataJson?: string;
};

export type VexAssertionRepairSummary = {
  vexLikeTargetCount: number;
  persistedAssertionCount: number;
  activeMatchedComponentCount: number;
  activeApplicableAwaitingVexCount: number;
  sourceSystems: string[];
  vexPolicyEnabled: boolean;
  vexRiskModifiersEnabled: boolean;
  vexRolloutControlsEnabled: boolean;
  vexRolloutBackfillEnabled: boolean;
  latestRepairRun?: SyncRunSnapshot;
  latestMicrosoftRun?: SyncRunSnapshot;
  latestRedhatRun?: SyncRunSnapshot;
  latestBackfillRun?: SyncRunSnapshot;
  latestBackfillComparison?: VexRolloutComparison;
  generatedAt: string;
};

export type SyncRunSnapshot = {
  runId: string;
  status: string;
  startedAt?: string;
  completedAt?: string;
  errorMessage?: string;
};

export type VexRolloutMetricsSnapshot = {
  vexLikeTargetCount: number;
  persistedAssertionCount: number;
  activeMatchedComponentCount: number;
  activeApplicableAwaitingVexCount: number;
  capturedAt: string;
};

export type VexRolloutComparison = {
  before: VexRolloutMetricsSnapshot;
  after: VexRolloutMetricsSnapshot;
};

export type IngestionEvidence = {
  id: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: string;
  status: 'IN_PROGRESS' | 'SUCCESS' | 'FAILURE';
  format: string;
  uploadedAt: string;
  originalFilename: string;
  ingestionSourceType?: string;
  ingestionSourceSystem?: string;
  sourceReference?: string;
  sourceEndpoint?: string;
  fetchStatusCode?: number;
  contentType?: string;
  contentLengthBytes?: number;
  contentSha256?: string;
  componentCount?: number;
  findingsGenerated?: number;
  evidenceJson?: string;
};

export type FindingPage = {
  items: Finding[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type FindingFilterValues = {
  severities: string[];
  statuses: string[];
  decisionStates: string[];
  matchMethods: string[];
  vexStatuses: string[];
  vexFreshness: string[];
  vexProviders: string[];
};

export type FindingBulkWorkflowRequest = {
  findingIds?: string[];
  applyToFiltered?: boolean;
  severity?: string[];
  status?: string[];
  decisionState?: string[];
  matchMethod?: string[];
  vexStatus?: string[];
  vexFreshness?: string[];
  vexProvider?: string[];
  minConfidence?: number;
  vulnerabilityId?: string;
  packageName?: string;
  ecosystem?: string;
  workflowStatus?: 'OPEN' | 'RESOLVED' | 'SUPPRESSED' | 'AUTO_CLOSED';
  assignedTo?: string;
  dueAt?: string;
  suppressionReason?: string;
  suppressedUntil?: string;
  actor?: string;
};

export type FindingBulkWorkflowResponse = {
  targeted: number;
  updated: number;
  failed: number;
  message: string;
};

export type Asset = {
  id: string;
  type: string;
  name: string;
  identifier: string;
  serviceName?: string;
  environment?: string;
  ownerTeam?: string;
  ownerEmail?: string;
  businessCriticality: string;
  state: string;
  lastInventoryAt?: string;
  lastCmdbSyncAt?: string;
};

export type HostAssetSummary = {
  assetId: string;
  ciId: string;
  name: string;
  identifier: string;
  sysId: string;
  environment?: string;
  ownerEmail?: string;
  businessCriticality?: string;
  state?: string;
  lastInventoryAt?: string;
  lastCmdbSyncAt?: string;
  aliasCount: number;
  installedSoftwareCount: number;
  openFindingCount: number;
  totalFindingCount: number;
  unresolvedReviewCount: number;
};

export type HostAliasRecord = {
  id: string;
  aliasName: string;
  sourceSystem: string;
  confidence?: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
};

export type HostSoftwareInstanceRecord = {
  id: string;
  inventoryComponentId?: string;
  displayName: string;
  publisher?: string;
  version?: string;
  normalizedPublisher?: string;
  normalizedProduct?: string;
  normalizedVersion?: string;
  sourceSystem: string;
  versionEvidence?: string;
  activeInstall: boolean;
  unlicensedInstall: boolean;
  installDate?: string;
  lastScanned?: string;
  lastUsed?: string;
  discoveryModelPrimaryKey?: string;
  softwareIdentity?: string;
  cpe23?: string;
  needsVersionReview: boolean;
  needsIdentityReview: boolean;
  needsDiscoveryModelReview: boolean;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
};

export type HostFindingRecord = {
  id: string;
  vulnerabilityId?: string;
  severity?: string;
  status?: string;
  decisionState?: string;
  riskScore?: number;
  confidenceScore?: number;
  matchedBy?: string;
  firstObservedAt?: string;
  lastObservedAt?: string;
};

export type HostAssetDetail = {
  host: HostAssetSummary;
  aliases: HostAliasRecord[];
  software: HostSoftwareInstanceRecord[];
  findings: HostFindingRecord[];
};

export type InventoryComponentRecord = {
  id: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
  componentStatus: 'ACTIVE' | 'RETIRED';
  ecosystem: string;
  packageName: string;
  version?: string;
  normalizedName?: string;
  normalizedVersion?: string;
  purl: string;
  componentDigest?: string;
  softwareIdentity?: string;
  sourceSystem?: string;
  sourceType?: string;
  sourceReference?: string;
  uploadedAt?: string;
  lastObservedAt: string;
  retiredAt?: string;
  needsReview: boolean;
  reviewItemCount: number;
  reviewMissingVersion: boolean;
  reviewUnmappedSoftware: boolean;
  reviewLowConfidenceAlias: boolean;
  reviewDiscoveryModel: boolean;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
};

export type SoftwareIdentitySummary = {
  id: string;
  displayName: string;
  canonicalKey: string;
  vendor?: string;
  product?: string;
  normalizedKey: string;
  assetTypes: string[];
  ecosystems: string[];
  sourceSystems: string[];
  eolSlug?: string;
  mappingConfirmed: boolean;
  needsEolMapping: boolean;
  assetCount: number;
  componentCount: number;
  versionCount: number;
  eolComponentCount: number;
  nearEolComponentCount: number;
  unknownEolComponentCount: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
};

export type SoftwareIdentityPage = {
  content: SoftwareIdentitySummary[];
  number: number;
  size: number;
  totalElements: number;
  totalPages: number;
};

export type SoftwareIdentityVersion = {
  version: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
  assetCount: number;
  componentCount: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
};

export type SoftwareIdentityAsset = {
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: string;
  componentId: string;
  packageName: string;
  ecosystem?: string;
  version?: string;
  sourceSystem?: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
};

export type SoftwareIdentityDetail = {
  id: string;
  displayName: string;
  canonicalKey: string;
  vendor?: string;
  product?: string;
  normalizedKey: string;
  purl?: string;
  cpe23?: string;
  assetTypes: string[];
  ecosystems: string[];
  sourceSystems: string[];
  eolSlug?: string;
  mappingConfirmed: boolean;
  needsEolMapping: boolean;
  assetCount: number;
  componentCount: number;
  versionCount: number;
  eolComponentCount: number;
  nearEolComponentCount: number;
  unknownEolComponentCount: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
  versions: SoftwareIdentityVersion[];
  assets: SoftwareIdentityAsset[];
};

export type InventoryComponentPage = {
  items: InventoryComponentRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type InventoryComponentFilterValues = {
  assetTypes: string[];
  componentStatuses: string[];
  sourceSystems: string[];
  ecosystems: string[];
};

export type AffectedPackage = {
  ecosystem?: string;
  packageName?: string;
  affectedVersions: string;
  fixedVersion?: string;
  cpe?: string;
  vexStatus?: string;
  vexSource?: string;
  vexProvider?: string;
  vexFreshness?: string;
  vexDocumentId?: string;
  vexEvidenceUrl?: string;
};

export type VulnerabilityIntelVexEvidence = {
  assertionId: string;
  sourceSystem: string;
  provider: string;
  status: string;
  trustTier: string;
  freshness: string;
  ecosystem?: string;
  packageName?: string;
  affectedVersions?: string;
  fixedVersion?: string;
  normalizedProductKey?: string;
  cpe?: string;
  documentId: string;
  evidenceUrl?: string;
  publishedAt?: string;
  lastSeenAt?: string;
};

export type VulnerabilityIntelRecord = {
  id: string;
  externalId: string;
  title: string;
  descriptionSnippet?: string;
  severity: string;
  cvssScore?: number;
  epssScore?: number;
  inKev: boolean;
  vulnStatus?: string;
  sourceCount: number;
  sources: string[];
  openFindings: number;
  publishedAt?: string;
  lastModifiedAt?: string;
  updatedAt: string;
  vexCoverage: 'EXACT_MATCH' | 'MIXED' | 'VENDOR_ONLY' | 'NONE';
  vexCoveredPackageCount: number;
  vexPackageCount: number;
  affectedPackages: AffectedPackage[];
};

export type VulnerabilityIntelObservation = {
  id: string;
  sourceSystem: string;
  sourceRecordId: string;
  sourceUrl?: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
  epssScore?: number;
  inKev?: boolean;
  vulnStatus?: string;
  sourceIdentifier?: string;
  cweIds?: string;
  references: string[];
  title?: string;
  description?: string;
  publishedAt?: string;
  lastModifiedAt?: string;
  observedAt: string;
  lastSeenAt: string;
};

export type VulnerabilityIntelDetail = {
  externalId: string;
  source: string;
  title: string;
  description?: string;
  severity: string;
  cvssScore?: number;
  cvssVector?: string;
  epssScore?: number;
  inKev: boolean;
  vulnStatus?: string;
  cweIds?: string;
  references: string[];
  sourceIdentifier?: string;
  publishedAt?: string;
  lastModifiedAt?: string;
  updatedAt: string;
  sourceCount: number;
  sources: string[];
  openFindings: number;
  vexCoverage: 'EXACT_MATCH' | 'MIXED' | 'VENDOR_ONLY' | 'NONE';
  vexCoveredPackageCount: number;
  vexPackageCount: number;
  observations: VulnerabilityIntelObservation[];
  affectedPackages: AffectedPackage[];
  vexEvidence: VulnerabilityIntelVexEvidence[];
};

export type VulnerabilityIntelPage = {
  items: VulnerabilityIntelRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type VulnerabilityIntelDashboardSummary = {
  trackedCount: number;
  resolvedCount: number;
  criticalCount: number;
  exploitCount: number;
  criticalRecords: VulnerabilityIntelPage;
};

export type VulnerabilityIntelFilterValues = {
  severities: string[];
  sources: string[];
  vulnStatuses: string[];
  inKevValues: string[];
};

export type CmdbAssetRecord = {
  assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
  assetName: string;
  assetIdentifier: string;
  serviceName?: string;
  environment?: string;
  ownerTeam?: string;
  ownerEmail?: string;
  businessCriticality?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  state?: 'ACTIVE' | 'INACTIVE' | 'RETIRED' | 'DECOMMISSIONED';
  // BLG-011: OCI/container artifact identity (only for CONTAINER_IMAGE assets)
  imageDigest?: string;
  imageTag?: string;
  imageRepository?: string;
  baseImageDigest?: string;
};

// BLG-014: SLO status types
export type SloEntry = {
  name: string;
  description: string;
  unit: string;
  target: number;
  current: number;
  compliant: boolean;
  window: string;
};

export type SloStatus = {
  evaluatedAt: string;
  overallCompliant: boolean;
  slos: SloEntry[];
};

export type CmdbAssetSyncResponse = {
  received: number;
  inserted: number;
  updated: number;
  message: string;
};

export type CmdbInventorySyncResponse = {
  sourceSystem: string;
  installRowsProcessed: number;
  discoveryRowsProcessed: number;
  unmatchedDiscoveryRows: number;
  ciCreated: number;
  ciAliasesCreated: number;
  softwareInstancesCreated: number;
  softwareInstancesUpdated: number;
  inventoryComponentsCreated: number;
  inventoryComponentsUpdated: number;
  findingsRecomputed: number;
  message: string;
};

export type ServiceNowCmdbAuthType = 'BASIC' | 'BEARER';

export type ServiceNowCmdbConfig = {
  id?: string;
  sourceSystem: string;
  configured: boolean;
  baseUrl: string;
  authType: ServiceNowCmdbAuthType;
  username: string;
  hasCredentialSecret: boolean;
  installTable: string;
  discoveryModelTable: string;
  ciTable: string;
  installQuery: string;
  discoveryQuery: string;
  installFields: string;
  discoveryFields: string;
  pageSize: number;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
};

export type ServiceNowCmdbConfigRequest = {
  baseUrl: string;
  authType: ServiceNowCmdbAuthType;
  username?: string;
  credentialSecret?: string;
  installTable: string;
  discoveryModelTable: string;
  ciTable: string;
  installQuery?: string;
  discoveryQuery?: string;
  installFields?: string;
  discoveryFields?: string;
  pageSize: number;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
};

export type ServiceNowCmdbConnectionTest = {
  status: 'SUCCESS' | 'FAILED';
  message: string;
  ciTableReachable: boolean;
  installTableReachable: boolean;
  discoveryTableReachable: boolean;
  testedAt: string;
};

export type GithubSbomSource = {
  id: string;
  name: string;
  owner: string;
  repo: string;
  path: string;
  assetType: string;
  assetName: string;
  assetIdentifier: string;
  frequency: 'ONCE' | 'INTERVAL';
  intervalMinutes: number;
  enabled: boolean;
  lastRunAt?: string;
  lastRunStatus?: string;
  lastError?: string;
};

export type FindingComment = {
  id: string;
  author: string;
  body: string;
  createdAt: string;
};

export type FindingEvent = {
  id: string;
  eventType: string;
  actor: string;
  summary: string;
  detailsJson?: string;
  createdAt: string;
};

export type FindingTimeline = {
  findingId: string;
  events: FindingEvent[];
  comments: FindingComment[];
};

export type VulnerabilityDetail = {
  externalId: string;
  source: string;
  title: string;
  description: string;
  severity: string;
  cvssScore?: number;
  cvssVersion?: string;
  cvssVector?: string;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  exploitabilityScore?: number;
  impactScore?: number;
  cweIds?: string;
  references: string[];
  sourceIdentifier?: string;
  vulnStatus?: string;
  publishedAt?: string;
  lastModifiedAt?: string;
  inKev: boolean;
  relatedOpenFindings: number;
};

export type EolSummary = {
  totalTracked: number;
  eolCount: number;
  nearEolCount: number;
  supportedCount: number;
  unknownCount: number;
};

export type ComponentEolStatus = {
  componentId: string;
  packageName: string;
  ecosystem: string;
  version?: string;
  assetName: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
};

export type EolProductCatalog = {
  slug: string;
  displayName?: string;
  cpeVendor?: string;
  cpeProduct?: string;
  purlType?: string;
  purlNamespace?: string;
  aliases?: string[];
  lastModified?: string;
  lastFetchedAt?: string;
};

export type EolRelease = {
  cycle: string;
  releaseDate?: string;
  eolDate?: string;
  eolBoolean?: boolean;
  supportEndDate?: string;
  extendedSupportDate?: string;
  securitySupportDate?: string;
  latestVersion?: string;
  latestReleaseDate?: string;
  lts: boolean;
  isEol: boolean;
  isEoas?: boolean;
  isEoes?: boolean;
  discontinued: boolean;
  officialSourceUrl?: string;
  supportPhase?: string;
};

export type EolComponentPage = {
  content: ComponentEolStatus[];
  number: number;
  size: number;
  totalElements: number;
  totalPages: number;
};
