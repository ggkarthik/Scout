import type { OwnershipSummary } from '../../types/ownership';

export type Finding = {
  id: string;
  displayId: string;
  componentId: string;
  assetName: string;
  assetIdentifier: string;
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
  incidentId?: string;
  incidentStatus?: string;
  ownershipSyncedAt?: string;
  ownership?: OwnershipSummary;
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
  owners: string[];
  supportGroups: string[];
  assignedTo: string[];
  ownershipSources: string[];
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
  owner?: string[];
  supportGroup?: string[];
  ownershipSource?: string[];
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
