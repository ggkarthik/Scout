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
  firstObservedAt: string;
  lastObservedAt: string;
  decisionState: 'AFFECTED' | 'NOT_AFFECTED' | 'FIXED' | 'UNDER_INVESTIGATION' | 'NEEDS_REVIEW';
  status: 'OPEN' | 'RESOLVED' | 'SUPPRESSED' | 'AUTO_CLOSED';
  updatedAt: string;
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
  status: string;
  queuePosition?: number;
  recordsFetched: number;
  recordsInserted: number;
  recordsUpdated: number;
  recordsFailed: number;
  startedAt: string;
  completedAt?: string;
  errorMessage?: string;
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

export type SbomUploadEvidence = {
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

export type GithubRepoIngestionResult = {
  owner: string;
  repo: string;
  assetIdentifier: string;
  status: 'SUCCESS' | 'FAILURE';
  componentsIngested?: number;
  findingsGenerated?: number;
  message?: string;
};

export type GithubSbomIngestionBatchResponse = {
  repositoriesDiscovered: number;
  repositoriesProcessed: number;
  repositoriesSucceeded: number;
  repositoriesFailed: number;
  componentsIngested: number;
  findingsGenerated: number;
  results: GithubRepoIngestionResult[];
};

export type GithubGhcrImageIngestionResult = {
  imageRepository: string;
  assetIdentifier: string;
  status: 'SUCCESS' | 'FAILURE';
  componentsIngested?: number;
  findingsGenerated?: number;
  message?: string;
};

export type GithubGhcrIngestionSummary = {
  imagesDiscovered: number;
  imagesProcessed: number;
  imagesSucceeded: number;
  imagesFailed: number;
  componentsIngested: number;
  findingsGenerated: number;
  failureSummary?: string;
  results: GithubGhcrImageIngestionResult[];
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

export type InventoryComponentRecord = {
  id: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
  componentStatus: 'ACTIVE' | 'RETIRED';
  ecosystem: string;
  packageName: string;
  version: string;
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
  observations: VulnerabilityIntelObservation[];
  affectedPackages: AffectedPackage[];
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
