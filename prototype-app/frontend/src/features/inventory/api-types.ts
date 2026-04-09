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

export type HostApplicableCveRecord = {
  stateId: string;
  vulnerabilityId: string;
  externalId?: string;
  severity?: string;
  cvssScore?: number;
  epssScore?: number;
  packageName?: string;
  version?: string;
  impactState?: string;
  lastEvaluatedAt?: string;
};

export type HostAssetDetail = {
  host: HostAssetSummary;
  aliases: HostAliasRecord[];
  software: HostSoftwareInstanceRecord[];
  findings: HostFindingRecord[];
  applicableCves: HostApplicableCveRecord[];
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
