export type InventoryViewKey =
  | 'overview'
  | 'software-identities'
  | 'manage-software'
  | 'hosts'
  | 'container-images'
  | 'secured-image-catalog'
  | 'container-registries'
  | 'sbom'
  | 'hosted-technologies'
  | 'code-repositories'
  | 'source-mappings'
  | 'developers'
  | 'kubernetes-clusters'
  | 'datastores'
  | 'subscriptions'
  | 'iam'
  | 'api-endpoints'
  | 'application-endpoints'
  | 'vulnerability-intelligence';

export type InventoryScopedAssetType = 'ALL' | 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
export type InventoryComponentFilterKey = 'assetType' | 'componentStatus' | 'sourceSystem' | 'ecosystem' | 'reviewCategory' | 'query';
export type VulnerabilityIntelFilterKey = 'severity' | 'source' | 'vulnStatus' | 'inKev' | 'affectedPackage' | 'query';
export type HostReviewCategory =
  | 'NEEDS_REVIEW'
  | 'MISSING_VERSION'
  | 'UNMAPPED_SOFTWARE'
  | 'LOW_CONFIDENCE_ALIAS'
  | 'DISCOVERY_MODEL_REVIEW';

export const HOST_REVIEW_CATEGORIES: HostReviewCategory[] = [
  'NEEDS_REVIEW',
  'MISSING_VERSION',
  'UNMAPPED_SOFTWARE',
  'LOW_CONFIDENCE_ALIAS',
  'DISCOVERY_MODEL_REVIEW'
];
