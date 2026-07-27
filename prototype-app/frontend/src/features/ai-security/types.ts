export type AiArtifactType = 'AI_AGENT' | 'AI_MODEL' | 'OTHER_AI_ARTIFACT';

export type AiSecuritySummary = {
  artifactCounts: Record<string, number>;
  openFindings: number;
  incompleteScopes: number;
  lastCompleteSnapshotAt: string | null;
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
