export type InventoryViewKey =
  | 'overview'
  | 'software-identities'
  | 'hosts'
  | 'container-images'
  | 'sbom';

export type InventoryScopedAssetType = 'ALL' | 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
export type InventoryComponentFilterKey = 'assetType' | 'componentStatus' | 'sourceSystem' | 'ecosystem' | 'reviewCategory' | 'query';
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
