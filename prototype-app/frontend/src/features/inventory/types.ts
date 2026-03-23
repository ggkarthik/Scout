export type InventoryViewKey =
  | 'vulnerability-intelligence'
  | 'software-identities'
  | 'technologies'
  | 'service-catalog'
  | 'cloud-resources'
  | 'hosts'
  | 'kubernetes-clusters'
  | 'container-images'
  | 'secured-image-catalog'
  | 'container-registries'
  | 'datastores'
  | 'subscriptions'
  | 'iam'
  | 'hosted-technologies'
  | 'sbom'
  | 'api-endpoints'
  | 'application-endpoints'
  | 'code-repositories'
  | 'source-mappings'
  | 'developers';

export type InventoryScopedAssetType = 'ALL' | 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
export type InventoryComponentFilterKey = 'assetType' | 'componentStatus' | 'sourceSystem' | 'ecosystem' | 'reviewCategory' | 'query';
export type VulnerabilityIntelFilterKey = 'severity' | 'source' | 'vulnStatus' | 'inKev' | 'query';
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
