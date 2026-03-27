import type {
  InventoryComponentFilterValues
} from './api-types';
import type { VulnerabilityIntelFilterValues } from '../vulnerability-intel/types';
import type { FilterBuilderCategory, FilterBuilderField } from '../../components/FilterBuilder';

export const DEFAULT_VULNERABILITY_INTEL_FILTERS: VulnerabilityIntelFilterValues = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'],
  sources: ['nvd', 'kev', 'ghsa', 'msrc', 'redhat', 'advisory'],
  vulnStatuses: ['KNOWN_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'NOT_AFFECTED', 'UNKNOWN'],
  inKevValues: ['true', 'false']
};

export const DEFAULT_COMPONENT_FILTERS: InventoryComponentFilterValues = {
  assetTypes: ['APPLICATION', 'HOST', 'CONTAINER_IMAGE'],
  componentStatuses: ['ACTIVE', 'RETIRED'],
  sourceSystems: ['api', 'github', 'servicenow'],
  ecosystems: []
};

export const INVENTORY_FILTER_CATEGORIES: FilterBuilderCategory[] = [
  { key: 'inventory', label: 'Inventory' },
  { key: 'ingestion', label: 'Ingestion' },
  { key: 'review', label: 'Review' }
];

export const INVENTORY_FILTER_FIELDS: FilterBuilderField[] = [
  {
    key: 'assetType',
    label: 'Asset Type',
    categoryKey: 'inventory',
    description: 'Filter inventory records by the underlying asset class.',
    typeLabel: 'Enum property'
  },
  {
    key: 'componentStatus',
    label: 'Component Status',
    categoryKey: 'inventory',
    description: 'Filter inventory rows by whether the component is active or retired.',
    typeLabel: 'Enum property'
  },
  {
    key: 'ecosystem',
    label: 'Ecosystem',
    categoryKey: 'inventory',
    description: 'Filter by package ecosystem such as Maven, npm, or PyPI.',
    typeLabel: 'Enum property'
  },
  {
    key: 'sourceSystem',
    label: 'Source System',
    categoryKey: 'ingestion',
    description: 'Filter records by how the inventory was ingested.',
    typeLabel: 'Enum property'
  },
  {
    key: 'reviewCategory',
    label: 'Host Review',
    categoryKey: 'review',
    description: 'Filter host inventory rows by deterministic review blockers such as missing version, unmapped software, or low-confidence host alias resolution.',
    typeLabel: 'Enum property'
  },
  {
    key: 'query',
    label: 'Inventory Search',
    categoryKey: 'inventory',
    description: 'Search asset name, asset identifier, package, normalized name, software identity, or PURL.',
    typeLabel: 'String property'
  }
];

export const VULNERABILITY_INTEL_FILTER_CATEGORIES: FilterBuilderCategory[] = [
  { key: 'vulnerability', label: 'Vulnerability' },
  { key: 'source', label: 'Source Intelligence' }
];

export const VULNERABILITY_INTEL_FILTER_FIELDS: FilterBuilderField[] = [
  {
    key: 'severity',
    label: 'Severity',
    categoryKey: 'vulnerability',
    description: 'Filter normalized vulnerability records by canonical severity.',
    typeLabel: 'Enum property'
  },
  {
    key: 'vulnStatus',
    label: 'Vulnerability Status',
    categoryKey: 'vulnerability',
    description: 'Filter by normalized vulnerability status from source observations.',
    typeLabel: 'Enum property'
  },
  {
    key: 'inKev',
    label: 'KEV Presence',
    categoryKey: 'vulnerability',
    description: 'Filter vulnerabilities based on whether they are listed in CISA KEV.',
    typeLabel: 'Boolean property'
  },
  {
    key: 'affectedPackage',
    label: 'Affected Package',
    categoryKey: 'vulnerability',
    description: 'Filter normalized vulnerability records by affected package name, normalized target key, or CPE.',
    typeLabel: 'String property'
  },
  {
    key: 'source',
    label: 'Source',
    categoryKey: 'source',
    description: 'Filter vulnerabilities by contributing source systems such as NVD, KEV, GHSA, or CSAF/VEX.',
    typeLabel: 'Enum property'
  },
  {
    key: 'query',
    label: 'Vulnerability Search',
    categoryKey: 'vulnerability',
    description: 'Search by vulnerability identifier or title.',
    typeLabel: 'String property'
  }
];
