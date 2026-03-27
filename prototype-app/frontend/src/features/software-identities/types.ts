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
