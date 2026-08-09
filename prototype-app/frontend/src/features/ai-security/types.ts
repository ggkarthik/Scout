export type AiArtifactType = 'AI_AGENT' | 'AI_MODEL' | 'OTHER_AI_ARTIFACT';

export type AiSecuritySummary = {
  artifactCounts: Record<string, number>;
  openFindings: number;
  incompleteScopes: number;
  lastCompleteSnapshotAt: string | null;
};

export type AiGridSystem = {
  id: string;
  name: string;
  status: string;
  revision: number;
  memberCount: number;
  updatedAt: string;
};

export type AiGridCoverage = {
  runId: string | null;
  coverageEpochId: string | null;
  authoritativeScopeHeads: number;
  currentArtifacts: number;
  applicablePublished: number;
  required: number;
  tenantEnabled: number;
  preview: number;
  tenantDisabled: number;
  evidenceReady: number;
  evaluatedPass: number;
  evaluatedFail: number;
  noDecision: number;
  notApplicable: number;
  stale: number;
  unsupported: number;
};

export type AiGridCoverageDimension = {
  coverageEpochId: string;
  dimension: 'TECHNOLOGY' | 'PROVIDER' | 'FAMILY' | 'ACCOUNT' | 'ENVIRONMENT' | 'OWNER' | 'POLICY' | 'FRAMEWORK';
  value: string;
  expected: number;
  recorded: number;
  missing: number;
  pass: number;
  fail: number;
  noDecision: number;
};

export type AiGridPolicySelection = 'REQUIRED' | 'ENABLED' | 'PREVIEW' | 'DISABLED';

export type AiGridPolicy = {
  policyId: string;
  version: string;
  name: string;
  severity: string;
  lifecycle: string;
  workflowClass: string;
  selection: AiGridPolicySelection;
};

export type AiGridOwner = {
  artifactId: string;
  ownerName: string;
  ownerState: 'CONFIRMED';
  ownerSource: string;
  confidence: number | null;
  confidenceMethod: string | null;
  confidenceMethodVersion: string | null;
};

export type AiGridRunMetrics = {
  runId: string;
  provider: string | null;
  completedScopeCount: number;
  processingDurationMs: number;
  providerApiCalls: number | null;
  providerCallMeasurementState: string;
  artifactCount: number;
  snapshotManifestCount: number;
  snapshotBytes: number;
  newSnapshotBytes: number;
  retainedSnapshotBytes: number;
  budgetState: string;
  factCount: number;
  assessmentCount: number;
  passCount: number;
  failCount: number;
  noDecisionCount: number;
  openGapCount: number;
  firstInventoryAt: string | null;
  firstDecisionAt: string | null;
  firstFindingAt: string | null;
  firstGapAt: string | null;
};

export type AiSecurityArtifact = {
  id: string;
  provider: string;
  providerResourceId: string;
  artifactType: string;
  nativeKind: string;
  name: string;
  accountId: string;
  region: string;
  active: boolean;
  attributes: Record<string, unknown>;
  ownerName: string | null;
  ownerState: 'CONFIRMED' | 'INFERRED' | 'CANDIDATE' | 'UNOWNED';
  ownerSource: string | null;
  ownerConfidence: number | null;
  ownerConfidenceMethod: string | null;
  ownerConfidenceMethodVersion: string | null;
  businessCriticality: string | null;
  environment: string | null;
  firstObservedAt: string;
  lastObservedAt: string;
};

export type AiSecurityPage<T> = {
  items: T[];
  page: number;
  size: number;
  total: number;
};

export type AiSecurityRelationship = {
  id: string;
  relationshipType: string;
  sourceArtifactId: string;
  sourceName: string;
  targetArtifactId: string;
  targetName: string;
  attributes: Record<string, unknown>;
};

export type AiSecurityGraph = {
  nodes: AiSecurityArtifact[];
  edges: AiSecurityRelationship[];
  truncated: boolean;
};

export type AiSecurityFinding = {
  id: string;
  displayId: string;
  policyId: string;
  policyVersion: string;
  artifactId: string;
  artifactName: string;
  severity: string;
  status: string;
  title: string;
  evidence: Record<string, unknown>;
  reviewDisposition: string;
  firstObservedAt: string;
  lastObservedAt: string;
  resolvedAt: string | null;
};

export type AiSecurityPolicy = {
  id: string;
  version: string;
  name: string;
  severity: string;
  artifactTypes: string[];
  requiredResourceFamilies: string[];
  description: string;
  remediation: string;
  controlMappings: Record<string, string>;
  available: boolean;
  enabled: boolean;
  openFindings: number;
  lifetimeFindings: number;
  lastEvaluatedAt: string | null;
  decisionCoverage: number;
  decisionCoverageThreshold: number;
  decisionCoverageStatus: 'PASS' | 'FAIL' | 'NO_DATA';
  evaluatedArtifacts: number;
  noDecisionCount: number;
};

export type PolicyScopeMode = 'ALL' | 'MATCH_RULES' | 'CUSTOM_LIST';

export type PolicyScopeField = 'PROVIDER' | 'REGION' | 'ACCOUNT_ID' | 'ARTIFACT_TYPE' | 'NATIVE_KIND' | 'NAME';

export type PolicyScopeOperator = 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'NOT_CONTAINS';

export type PolicyScopeCondition = {
  field: PolicyScopeField | string;
  operator: PolicyScopeOperator | string;
  value: string;
};

export type PolicyScope = {
  mode: PolicyScopeMode;
  conditionLogic: 'AND' | 'OR';
  conditions: PolicyScopeCondition[];
  updatedBy: string | null;
  updatedAt: string | null;
};

export type PolicyExceptionOverride = 'INCLUDED' | 'EXCLUDED';

export type PolicyException = {
  artifactId: string;
  artifactName: string;
  override: PolicyExceptionOverride;
  reason: string | null;
  createdBy: string;
  createdAt: string;
};

export type PolicyParameterValue = {
  key: string;
  label: string;
  type: string;
  options: string[];
  defaultValue: string;
  helpText: string;
  value: string;
};

export type PolicyConfiguration = {
  scope: PolicyScope;
  exceptions: PolicyException[];
  parameters: PolicyParameterValue[];
  matchedArtifactCount: number;
  totalArtifactCount: number;
};

export type PolicyAssistExplanation = {
  summary: string;
  generatedAt: string;
};

export type AiSecurityRun = {
  id: string;
  status: string;
  recordsFetched: number;
  recordsFailed: number;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
};

export type AiSecurityScopeDiagnostic = {
  code: string;
  message: string;
  retryable: boolean;
  missingPermissions: string[];
  correlationId: string;
};

export type AiSecurityScope = {
  id: string;
  runId: string;
  accountId: string;
  region: string;
  resourceFamily: string;
  scopeKey: string;
  status: 'COMPLETE' | 'PARTIAL' | 'FAILED' | 'UNSUPPORTED';
  acceptedChunks: number;
  expectedChunks: number;
  diagnosticCode: string | null;
  diagnostics: { items?: AiSecurityScopeDiagnostic[] };
  startedAt: string;
  completedAt: string | null;
};

export type AiSecurityConnectorConfig = {
  id: string;
  accountId: string;
  roleArn: string | null;
  authMode: 'WORKLOAD_IDENTITY' | 'CROSS_ACCOUNT_ROLE';
  regions: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

export type AiSecurityConnectionTest = {
  success: boolean;
  code: string | null;
  message: string;
  retryable: boolean;
  missingPermissions: string[];
};

export type AiSecurityAzureCredentialProfile = {
  id: string;
  name: string;
  authType: 'CLIENT_SECRET' | 'MANAGED_IDENTITY' | 'WORKLOAD_FEDERATION';
  azureTenantId: string;
  clientId: string | null;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  expiresAt: string | null;
  lastVerifiedAt: string | null;
  lastVerificationStatus: string | null;
  createdAt: string;
  updatedAt: string;
};

export type AiSecurityAzureConnector = {
  id: string;
  subscriptionId: string;
  azureTenantId: string;
  credentialProfileId: string;
  sourceConfigId: string;
  sourceTargetId: string;
  regions: string[];
  resourceFamilies: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

export type AiSecurityAzureFoundryConfig = {
  configured: boolean;
  azureTenantId: string | null;
  clientId: string | null;
  hasCredential: boolean;
  primarySubscriptionId: string | null;
  subscriptionIds: string[];
  regions: string[];
  foundryEndpointUrl: string | null;
  connectorId: string | null;
  credentialExpiresAt: string | null;
};

export type AiSecurityAzureFamilyPermission = {
  resourceFamily: string;
  required: string[];
  granted: string[];
  missing: string[];
  status: string;
};

export type AiSecurityAzureConnectionTest = {
  success: boolean;
  code: string | null;
  message: string;
  retryable: boolean;
  correlationId: string;
  resourceFamilies: AiSecurityAzureFamilyPermission[];
};

export type AiSecurityAzureRequirements = {
  matrixVersion: number;
  provider: 'AZURE';
  resourceFamilies: Array<{
    resourceFamily: string;
    apiVersion: string;
    role: string;
    actions: string[];
  }>;
  policies: Array<{
    policyId: string;
    version: string;
    resourceFamilies: string[];
    facts: string[];
    scopes: string[];
    connectorTest: string;
  }>;
  prohibitedActions: string[];
  roleTemplate: {
    name: string;
    isCustom: boolean;
    description: string;
    actions: string[];
    notActions: string[];
    dataActions: string[];
    notDataActions: string[];
    assignableScopes: string[];
  };
};

export type AiGridExposureSummary = {
  id: string;
  correlationId: string;
  correlationVersion: string;
  title: string;
  severity: string;
  state: 'EXPOSURE_HYPOTHESIS' | 'VALIDATED_EXPOSURE' | 'CLOSED';
  status: 'OPEN' | 'CLOSED';
  confidence: number;
  rootCauseArtifactId: string;
  firstObservedAt: string;
  lastObservedAt: string;
  findingId: string | null;
  affectedSystems: number;
  impact: string;
  rootCause: string;
  breakpoint: string;
  confidenceMethod: string;
};

export type AiGridExposurePage = { items: AiGridExposureSummary[]; nextCursor: string | null };

export type AiExposurePriority = {
  id: string; title: string; severity: string; priority: number;
  severityPoints: number; confidencePoints: number; publicExposurePoints: number;
  criticalityPoints: number; recencyPoints: number; confidence: number;
  rootCauseArtifactId: string; breakpoint: string; owner: string; provider: string;
  accountId: string; lastObservedAt: string;
};

export type AiOverviewActivity = {
  eventType: 'DISCOVERED' | 'VALIDATED'; subjectType: 'ARTIFACT' | 'EXPOSURE'; subjectId: string;
  name: string; provider: string; accountId: string; observedAt: string;
};

export type AiExposureIntelligenceOverview = {
  systemCount: number; assetCount: number; validatedExposureCount: number; criticalHighExposureCount: number;
  incompleteScopeCount: number; unsupportedScopeCount: number; authoritativeAt: string | null;
  topPriorities: AiExposurePriority[]; recentActivity: AiOverviewActivity[];
};

export type AiActionQueueItem = {
  id: string; kind: 'VALIDATED_EXPOSURE' | 'POLICY_FINDING'; title: string; severity: string;
  priority: number; owner: string; provider: string; accountId: string; remediation: string;
  confidence: number | null; lastObservedAt: string;
};

export type AiAssetPosture = {
  artifactId: string;
  controls: Array<{ policyId: string; selection: string; evidenceReadiness: string; decision: string; missingEvidenceJson: string }>;
  exposures: AiExposurePriority[];
};

export type AiGridExposureDetail = {
  exposure: AiGridExposureSummary;
  observations: Array<{
    id: string; runId: string; state: string; entryArtifactId: string | null; systemId: string | null;
    pathJson: string; evidenceJson: string; validFrom: string;
    validUntil: string | null; confidence: number; observedAt: string;
  }>;
  associations: Array<{ systemId: string | null; artifactId: string | null; role: string }>;
};
