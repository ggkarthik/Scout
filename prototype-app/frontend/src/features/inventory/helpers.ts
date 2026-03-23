import type {
  InventoryComponentRecord,
  VulnerabilityIntelDetail,
  VulnerabilityIntelRecord
} from '../../types';
import { readQueryParam, readQueryParams, replaceBrowserQueryParams } from '../../utils/queryState';
import {
  HOST_REVIEW_CATEGORIES,
  HostReviewCategory,
  InventoryScopedAssetType,
  InventoryViewKey
} from './types';

const HOST_REVIEW_CATEGORY_QUERY_KEY = 'reviewCategory';

const SOURCE_LABELS: Record<string, string> = {
  nvd: 'NVD',
  kev: 'KEV (CISA)',
  ghsa: 'GHSA',
  msrc: 'MSRC',
  redhat: 'Red Hat',
  'csaf-microsoft': 'MSRC CSAF',
  'vex-microsoft': 'MSRC VEX',
  'csaf-redhat': 'Red Hat CSAF',
  'vex-redhat': 'Red Hat VEX',
  advisory: 'Advisory'
};

export function defaultAssetTypeForView(view: InventoryViewKey): InventoryScopedAssetType {
  if (view === 'container-images' || view === 'secured-image-catalog' || view === 'container-registries') {
    return 'CONTAINER_IMAGE';
  }
  if (
    view === 'sbom'
    || view === 'hosted-technologies'
    || view === 'code-repositories'
    || view === 'source-mappings'
    || view === 'developers'
  ) {
    return 'APPLICATION';
  }
  if (
    view === 'hosts'
    || view === 'kubernetes-clusters'
    || view === 'datastores'
    || view === 'subscriptions'
    || view === 'iam'
    || view === 'api-endpoints'
    || view === 'application-endpoints'
  ) {
    return 'HOST';
  }
  return 'ALL';
}

export function formatAssetType(value: InventoryComponentRecord['assetType']): string {
  if (value === 'CONTAINER_IMAGE') return 'Container Image';
  if (value === 'APPLICATION') return 'Application';
  return 'Host';
}

export function canonicalVulnerabilitySource(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/[_\s]+/g, '-');
  if (normalized === 'microsoft-csaf' || normalized === 'msrc-csaf' || normalized === 'msrc-csaf-advisory') return 'csaf-microsoft';
  if (normalized === 'microsoft-vex' || normalized === 'msrc-vex') return 'vex-microsoft';
  if (normalized === 'redhat-csaf' || normalized === 'red-hat-csaf') return 'csaf-redhat';
  if (normalized === 'redhat-vex' || normalized === 'red-hat-vex') return 'vex-redhat';
  if (normalized === 'cisa-kev' || normalized === 'cisa-kve' || normalized === 'kve') return 'kev';
  if (normalized === 'github-advisory') return 'ghsa';
  if (normalized === 'advisories' || normalized === 'vendor-advisory') return 'advisory';
  return normalized;
}

export function vulnerabilitySourceFilterValue(value: string): string {
  const canonical = canonicalVulnerabilitySource(value);
  if (canonical === 'csaf-microsoft' || canonical === 'vex-microsoft') return 'msrc';
  if (canonical === 'csaf-redhat' || canonical === 'vex-redhat') return 'redhat';
  return canonical;
}

export function expandVulnerabilitySourceFilters(values: string[]): string[] {
  const expanded = new Set<string>();
  values.forEach((value) => {
    const normalized = vulnerabilitySourceFilterValue(value);
    if (normalized === 'msrc') {
      expanded.add('csaf-microsoft');
      expanded.add('vex-microsoft');
      return;
    }
    if (normalized === 'redhat') {
      expanded.add('csaf-redhat');
      expanded.add('vex-redhat');
      return;
    }
    expanded.add(normalized);
  });
  return Array.from(expanded);
}

export function formatSourceSystem(value: string): string {
  const canonical = canonicalVulnerabilitySource(value);
  return SOURCE_LABELS[canonical] ?? value;
}

export function formatInventorySourceSystem(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'upload') return 'Legacy Upload';
  if (normalized === 'api') return 'API Endpoint';
  if (normalized === 'github') return 'GitHub Generated';
  if (normalized === 'servicenow') return 'ServiceNow';
  return value;
}

export function formatInventoryLabel(value: string): string {
  return value
    .trim()
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function formatVexCoverage(value?: VulnerabilityIntelRecord['vexCoverage'] | VulnerabilityIntelDetail['vexCoverage']): string {
  if (!value) {
    return 'None';
  }
  if (value === 'EXACT_MATCH') return 'Exact Match';
  if (value === 'VENDOR_ONLY') return 'Vendor Only';
  return formatInventoryLabel(value);
}

export function vexCoverageClass(value?: VulnerabilityIntelRecord['vexCoverage'] | VulnerabilityIntelDetail['vexCoverage']): string {
  if (value === 'EXACT_MATCH') return 'status-open';
  if (value === 'MIXED') return 'status-in-progress';
  if (value === 'VENDOR_ONLY') return 'status-suppressed';
  return 'status-auto_closed';
}

export function formatHostReviewLabel(value: HostReviewCategory): string {
  if (value === 'NEEDS_REVIEW') return 'Needs Review';
  if (value === 'MISSING_VERSION') return 'Missing Version';
  if (value === 'UNMAPPED_SOFTWARE') return 'Unmapped Identity';
  if (value === 'LOW_CONFIDENCE_ALIAS') return 'Alias Review';
  return 'Discovery Review';
}

export function normalizeHostReviewCategory(value: string): HostReviewCategory | null {
  const normalized = value.trim().toUpperCase().replace(/[-\s]+/g, '_');
  return HOST_REVIEW_CATEGORIES.includes(normalized as HostReviewCategory)
    ? normalized as HostReviewCategory
    : null;
}

export function readSelectedHostReviewCategories(): HostReviewCategory[] {
  const rawValues = readQueryParams(HOST_REVIEW_CATEGORY_QUERY_KEY);
  if (rawValues.length === 0 && readQueryParam('inventoryView') === 'host-review-queue') {
    return ['NEEDS_REVIEW'];
  }
  return Array.from(new Set(
    rawValues
      .map(normalizeHostReviewCategory)
      .filter((value): value is HostReviewCategory => value !== null)
  ));
}

export function updateSelectedHostReviewCategories(categories: HostReviewCategory[]): void {
  replaceBrowserQueryParams({ [HOST_REVIEW_CATEGORY_QUERY_KEY]: categories });
}

export function buildHostReviewLabels(row: InventoryComponentRecord): string[] {
  const labels: string[] = [];
  if (row.reviewMissingVersion) labels.push('Missing Version');
  if (row.reviewUnmappedSoftware) labels.push('Unmapped Identity');
  if (row.reviewLowConfidenceAlias) labels.push('Alias Review');
  if (row.reviewDiscoveryModel) labels.push('Discovery Review');
  return labels;
}
