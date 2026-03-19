import React from 'react';
import { api } from '../api/client';
import {
  InventoryComponentFilterValues,
  InventoryComponentRecord,
  VulnerabilityIntelDetail,
  VulnerabilityIntelFilterValues,
  VulnerabilityIntelRecord
} from '../types';
import { ResizableTable } from '../components/ResizableTable';
import { StatCard } from '../components/StatCard';
import { FilterBuilder, FilterBuilderCategory, FilterBuilderField } from '../components/FilterBuilder';
import { FilterValueOption, FilterValueSelectCard } from '../components/FilterValueSelectCard';
import { HostAssetDetailPage, readSelectedHostAssetId, updateSelectedHostAssetId } from './HostAssetDetailPage';
import { EolBadge } from '../components/EolBadge';

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

type Props = {
  selectedView: InventoryViewKey;
};

type InventoryComponentFilterKey = 'assetType' | 'componentStatus' | 'sourceSystem' | 'ecosystem' | 'reviewCategory' | 'query';
type VulnerabilityIntelFilterKey = 'severity' | 'source' | 'vulnStatus' | 'inKev' | 'query';
type HostReviewCategory = 'NEEDS_REVIEW' | 'MISSING_VERSION' | 'UNMAPPED_SOFTWARE' | 'LOW_CONFIDENCE_ALIAS' | 'DISCOVERY_MODEL_REVIEW';

const HOST_REVIEW_CATEGORY_QUERY_KEY = 'reviewCategory';
const HOST_REVIEW_CATEGORIES: HostReviewCategory[] = [
  'NEEDS_REVIEW',
  'MISSING_VERSION',
  'UNMAPPED_SOFTWARE',
  'LOW_CONFIDENCE_ALIAS',
  'DISCOVERY_MODEL_REVIEW'
];

const VULNERABILITY_INTEL_PAGE_SIZE = 25;
const COMPONENTS_PAGE_SIZE = 25;
const DEFAULT_VULNERABILITY_INTEL_FILTERS: VulnerabilityIntelFilterValues = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'],
  sources: ['nvd', 'kev', 'ghsa', 'msrc', 'redhat', 'advisory'],
  vulnStatuses: ['KNOWN_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'NOT_AFFECTED', 'UNKNOWN'],
  inKevValues: ['true', 'false']
};
const DEFAULT_COMPONENT_FILTERS: InventoryComponentFilterValues = {
  assetTypes: ['APPLICATION', 'HOST', 'CONTAINER_IMAGE'],
  componentStatuses: ['ACTIVE', 'RETIRED'],
  sourceSystems: ['api', 'github', 'servicenow'],
  ecosystems: []
};

const INVENTORY_FILTER_CATEGORIES: FilterBuilderCategory[] = [
  { key: 'inventory', label: 'Inventory' },
  { key: 'ingestion', label: 'Ingestion' },
  { key: 'review', label: 'Review' }
];

const INVENTORY_FILTER_FIELDS: FilterBuilderField[] = [
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

const VULNERABILITY_INTEL_FILTER_CATEGORIES: FilterBuilderCategory[] = [
  { key: 'vulnerability', label: 'Vulnerability' },
  { key: 'source', label: 'Source Intelligence' }
];

const VULNERABILITY_INTEL_FILTER_FIELDS: FilterBuilderField[] = [
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

function defaultAssetTypeForView(view: InventoryViewKey): 'ALL' | InventoryComponentRecord['assetType'] {
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

function formatAssetType(value: InventoryComponentRecord['assetType']): string {
  if (value === 'CONTAINER_IMAGE') return 'Container Image';
  if (value === 'APPLICATION') return 'Application';
  return 'Host';
}

function formatSourceSystem(value: string): string {
  const canonical = canonicalVulnerabilitySource(value);
  return SOURCE_LABELS[canonical] ?? value;
}

function formatInventorySourceSystem(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'upload') return 'Legacy Upload';
  if (normalized === 'api') return 'API Endpoint';
  if (normalized === 'github') return 'GitHub Generated';
  if (normalized === 'servicenow') return 'ServiceNow';
  return value;
}

function formatInventoryLabel(value: string): string {
  return value
    .trim()
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatVexCoverage(value?: VulnerabilityIntelRecord['vexCoverage'] | VulnerabilityIntelDetail['vexCoverage']): string {
  if (!value) {
    return 'None';
  }
  if (value === 'EXACT_MATCH') return 'Exact Match';
  if (value === 'VENDOR_ONLY') return 'Vendor Only';
  return formatInventoryLabel(value);
}

function vexCoverageClass(value?: VulnerabilityIntelRecord['vexCoverage'] | VulnerabilityIntelDetail['vexCoverage']): string {
  if (value === 'EXACT_MATCH') return 'status-open';
  if (value === 'MIXED') return 'status-in-progress';
  if (value === 'VENDOR_ONLY') return 'status-suppressed';
  return 'status-auto_closed';
}

function formatHostReviewLabel(value: HostReviewCategory): string {
  if (value === 'NEEDS_REVIEW') return 'Needs Review';
  if (value === 'MISSING_VERSION') return 'Missing Version';
  if (value === 'UNMAPPED_SOFTWARE') return 'Unmapped Identity';
  if (value === 'LOW_CONFIDENCE_ALIAS') return 'Alias Review';
  return 'Discovery Review';
}

function normalizeHostReviewCategory(value: string): HostReviewCategory | null {
  const normalized = value.trim().toUpperCase().replace(/[-\s]+/g, '_');
  return HOST_REVIEW_CATEGORIES.includes(normalized as HostReviewCategory)
    ? normalized as HostReviewCategory
    : null;
}

function readSelectedHostReviewCategories(): HostReviewCategory[] {
  const url = new URL(window.location.href);
  const rawValues = url.searchParams.getAll(HOST_REVIEW_CATEGORY_QUERY_KEY);
  if (rawValues.length === 0 && url.searchParams.get('inventoryView') === 'host-review-queue') {
    return ['NEEDS_REVIEW'];
  }
  return Array.from(new Set(
    rawValues
      .map(normalizeHostReviewCategory)
      .filter((value): value is HostReviewCategory => value !== null)
  ));
}

function updateSelectedHostReviewCategories(categories: HostReviewCategory[]): void {
  const url = new URL(window.location.href);
  url.searchParams.delete(HOST_REVIEW_CATEGORY_QUERY_KEY);
  categories.forEach((value) => url.searchParams.append(HOST_REVIEW_CATEGORY_QUERY_KEY, value));
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

function canonicalVulnerabilitySource(value: string): string {
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

function vulnerabilitySourceFilterValue(value: string): string {
  const canonical = canonicalVulnerabilitySource(value);
  if (canonical === 'csaf-microsoft' || canonical === 'vex-microsoft') return 'msrc';
  if (canonical === 'csaf-redhat' || canonical === 'vex-redhat') return 'redhat';
  return canonical;
}

function expandVulnerabilitySourceFilters(values: string[]): string[] {
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

export function InventoryPage({ selectedView }: Props) {
  const scopedAssetType = defaultAssetTypeForView(selectedView);
  const [rows, setRows] = React.useState<InventoryComponentRecord[]>([]);
  const [componentPage, setComponentPage] = React.useState(0);
  const [componentTotalItems, setComponentTotalItems] = React.useState(0);
  const [componentTotalPages, setComponentTotalPages] = React.useState(0);
  const [componentQuery, setComponentQuery] = React.useState('');
  const [debouncedComponentQuery, setDebouncedComponentQuery] = React.useState('');
  const [componentAssetTypes, setComponentAssetTypes] = React.useState<string[]>([]);
  const [componentStatuses, setComponentStatuses] = React.useState<string[]>([]);
  const [componentSourceSystems, setComponentSourceSystems] = React.useState<string[]>([]);
  const [componentEcosystems, setComponentEcosystems] = React.useState<string[]>([]);
  const [componentReviewCategories, setComponentReviewCategories] = React.useState<HostReviewCategory[]>(() => (
    selectedView === 'hosts' ? readSelectedHostReviewCategories() : []
  ));
  const [componentActiveFilters, setComponentActiveFilters] = React.useState<InventoryComponentFilterKey[]>(() => (
    selectedView === 'hosts' && readSelectedHostReviewCategories().length > 0 ? ['reviewCategory'] : []
  ));
  const [vulnerabilityIntelRows, setVulnerabilityIntelRows] = React.useState<VulnerabilityIntelRecord[]>([]);
  const [vulnerabilityIntelPage, setVulnerabilityIntelPage] = React.useState(0);
  const [vulnerabilityIntelTotalItems, setVulnerabilityIntelTotalItems] = React.useState(0);
  const [vulnerabilityIntelTotalPages, setVulnerabilityIntelTotalPages] = React.useState(0);
  const [vulnerabilityIntelQuery, setVulnerabilityIntelQuery] = React.useState('');
  const [debouncedVulnerabilityIntelQuery, setDebouncedVulnerabilityIntelQuery] = React.useState('');
  const [vulnerabilityIntelSeverities, setVulnerabilityIntelSeverities] = React.useState<string[]>([]);
  const [vulnerabilityIntelSources, setVulnerabilityIntelSources] = React.useState<string[]>([]);
  const [vulnerabilityIntelStatuses, setVulnerabilityIntelStatuses] = React.useState<string[]>([]);
  const [vulnerabilityIntelInKevValues, setVulnerabilityIntelInKevValues] = React.useState<string[]>([]);
  const [vulnerabilityIntelActiveFilters, setVulnerabilityIntelActiveFilters] = React.useState<VulnerabilityIntelFilterKey[]>([]);
  const [vulnerabilityIntelFilterValues, setVulnerabilityIntelFilterValues] = React.useState<VulnerabilityIntelFilterValues>(
    DEFAULT_VULNERABILITY_INTEL_FILTERS
  );
  const [componentFilterValues, setComponentFilterValues] = React.useState<InventoryComponentFilterValues>(DEFAULT_COMPONENT_FILTERS);
  const [selectedHostAssetId, setSelectedHostAssetId] = React.useState<string | null>(() => (
    selectedView === 'hosts' ? readSelectedHostAssetId() : null
  ));
  const [selectedVulnerabilityIntelId, setSelectedVulnerabilityIntelId] = React.useState<string | null>(null);
  const [selectedVulnerabilityIntelDetail, setSelectedVulnerabilityIntelDetail] = React.useState<VulnerabilityIntelDetail | null>(null);
  const [vulnerabilityIntelDetailLoading, setVulnerabilityIntelDetailLoading] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');
  const loadRequestIdRef = React.useRef(0);

  React.useEffect(() => {
    const timeout = window.setTimeout(() => {
      setDebouncedComponentQuery(componentQuery);
    }, 300);
    return () => window.clearTimeout(timeout);
  }, [componentQuery]);

  React.useEffect(() => {
    const timeout = window.setTimeout(() => {
      setDebouncedVulnerabilityIntelQuery(vulnerabilityIntelQuery);
    }, 300);
    return () => window.clearTimeout(timeout);
  }, [vulnerabilityIntelQuery]);

  React.useEffect(() => {
    if (selectedView === 'vulnerability-intelligence') {
      setVulnerabilityIntelPage(0);
      setSelectedVulnerabilityIntelId(null);
      setSelectedVulnerabilityIntelDetail(null);
    } else {
      const initialHostReviewCategories = selectedView === 'hosts' ? readSelectedHostReviewCategories() : [];
      setComponentPage(0);
      setComponentQuery('');
      setDebouncedComponentQuery('');
      setComponentAssetTypes([]);
      setComponentStatuses([]);
      setComponentSourceSystems([]);
      setComponentEcosystems([]);
      setComponentReviewCategories(initialHostReviewCategories);
      setComponentActiveFilters(initialHostReviewCategories.length > 0 ? ['reviewCategory'] : []);
    }
  }, [selectedView]);

  React.useEffect(() => {
    if (selectedView === 'hosts') {
      setSelectedHostAssetId(readSelectedHostAssetId());
      setComponentReviewCategories(readSelectedHostReviewCategories());
      return;
    }
    setSelectedHostAssetId(null);
    setComponentReviewCategories([]);
    updateSelectedHostAssetId(null);
    updateSelectedHostReviewCategories([]);
  }, [selectedView]);

  React.useEffect(() => {
    if (selectedView === 'hosts') {
      updateSelectedHostAssetId(selectedHostAssetId);
    }
  }, [selectedHostAssetId, selectedView]);

  React.useEffect(() => {
    if (selectedView === 'hosts') {
      updateSelectedHostReviewCategories(componentReviewCategories);
    }
  }, [componentReviewCategories, selectedView]);

  const vulnerabilityIntelInKevFilter = React.useMemo<boolean | undefined>(() => {
    const hasTrue = vulnerabilityIntelInKevValues.includes('true');
    const hasFalse = vulnerabilityIntelInKevValues.includes('false');
    if (hasTrue && !hasFalse) return true;
    if (!hasTrue && hasFalse) return false;
    return undefined;
  }, [vulnerabilityIntelInKevValues]);

  const severityOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>(DEFAULT_VULNERABILITY_INTEL_FILTERS.severities);
    vulnerabilityIntelFilterValues.severities.forEach((severity) => {
      if (severity && severity.trim().length > 0) {
        values.add(severity.trim().toUpperCase());
      }
    });
    vulnerabilityIntelRows.forEach((record) => {
      if (record.severity && record.severity.trim().length > 0) {
        values.add(record.severity.trim().toUpperCase());
      }
    });
    vulnerabilityIntelSeverities.forEach((severity) => {
      if (severity && severity.trim().length > 0) {
        values.add(severity.trim().toUpperCase());
      }
    });

    const toTone = (value: string): FilterValueOption['tone'] => {
      if (value === 'CRITICAL') return 'critical';
      if (value === 'HIGH') return 'high';
      if (value === 'MEDIUM') return 'medium';
      if (value === 'LOW') return 'low';
      return 'neutral';
    };

    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: value.charAt(0) + value.slice(1).toLowerCase().replace(/_/g, ' '),
        tone: toTone(value)
      }));
  }, [vulnerabilityIntelFilterValues.severities, vulnerabilityIntelRows, vulnerabilityIntelSeverities]);

  const sourceOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>();
    DEFAULT_VULNERABILITY_INTEL_FILTERS.sources.forEach((source) => values.add(source));
    vulnerabilityIntelFilterValues.sources.forEach((source) => {
      if (source && source.trim().length > 0) {
        values.add(vulnerabilitySourceFilterValue(source));
      }
    });
    vulnerabilityIntelRows.forEach((record) => {
      record.sources.forEach((source) => {
        if (source && source.trim().length > 0) {
          values.add(vulnerabilitySourceFilterValue(source));
        }
      });
    });
    vulnerabilityIntelSources.forEach((source) => {
      if (source && source.trim().length > 0) {
        values.add(vulnerabilitySourceFilterValue(source));
      }
    });
    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: formatSourceSystem(value)
      }));
  }, [vulnerabilityIntelFilterValues.sources, vulnerabilityIntelRows, vulnerabilityIntelSources]);

  const vulnStatusOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>(DEFAULT_VULNERABILITY_INTEL_FILTERS.vulnStatuses);
    vulnerabilityIntelFilterValues.vulnStatuses.forEach((status) => {
      if (status && status.trim().length > 0) {
        values.add(status.trim().toUpperCase());
      }
    });
    vulnerabilityIntelRows.forEach((record) => {
      if (record.vulnStatus && record.vulnStatus.trim().length > 0) {
        values.add(record.vulnStatus.trim().toUpperCase());
      }
    });
    vulnerabilityIntelStatuses.forEach((status) => {
      if (status && status.trim().length > 0) {
        values.add(status.trim().toUpperCase());
      }
    });
    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: value.replace(/_/g, ' ')
      }));
  }, [vulnerabilityIntelFilterValues.vulnStatuses, vulnerabilityIntelRows, vulnerabilityIntelStatuses]);

  const kevOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>(DEFAULT_VULNERABILITY_INTEL_FILTERS.inKevValues);
    vulnerabilityIntelFilterValues.inKevValues.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toLowerCase());
      }
    });
    vulnerabilityIntelInKevValues.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toLowerCase());
      }
    });
    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: value === 'true' ? 'In KEV' : value === 'false' ? 'Not in KEV' : value
      }));
  }, [vulnerabilityIntelFilterValues.inKevValues, vulnerabilityIntelInKevValues]);

  const inventoryFilterFields = React.useMemo<FilterBuilderField[]>(() => (
    INVENTORY_FILTER_FIELDS.filter((field) => {
      if (scopedAssetType !== 'ALL' && field.key === 'assetType') {
        return false;
      }
      if (selectedView !== 'hosts' && field.key === 'reviewCategory') {
        return false;
      }
      return true;
    })
  ), [scopedAssetType, selectedView]);

  const assetTypeOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>(DEFAULT_COMPONENT_FILTERS.assetTypes);
    componentFilterValues.assetTypes.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toUpperCase());
      }
    });
    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: formatAssetType(value as InventoryComponentRecord['assetType'])
      }));
  }, [componentFilterValues.assetTypes]);

  const componentStatusOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>(DEFAULT_COMPONENT_FILTERS.componentStatuses);
    componentFilterValues.componentStatuses.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toUpperCase());
      }
    });
    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: formatInventoryLabel(value)
      }));
  }, [componentFilterValues.componentStatuses]);

  const sourceSystemOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>(DEFAULT_COMPONENT_FILTERS.sourceSystems);
    componentFilterValues.sourceSystems.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toLowerCase());
      }
    });
    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: formatInventorySourceSystem(value)
      }));
  }, [componentFilterValues.sourceSystems]);

  const ecosystemOptions = React.useMemo<FilterValueOption[]>(() => {
    const values = new Set<string>(DEFAULT_COMPONENT_FILTERS.ecosystems);
    componentFilterValues.ecosystems.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toLowerCase());
      }
    });
    componentEcosystems.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toLowerCase());
      }
    });
    return Array.from(values)
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({
        value,
        label: formatInventoryLabel(value)
      }));
  }, [componentFilterValues.ecosystems, componentEcosystems]);

  const hostReviewOptions = React.useMemo<FilterValueOption[]>(() => (
    HOST_REVIEW_CATEGORIES.map((value) => ({
      value,
      label: formatHostReviewLabel(value),
      tone: value === 'NEEDS_REVIEW' || value === 'MISSING_VERSION'
        ? 'medium'
        : value === 'UNMAPPED_SOFTWARE' || value === 'LOW_CONFIDENCE_ALIAS'
          ? 'neutral'
          : 'low'
    }))
  ), []);

  const addVulnerabilityIntelFilter = React.useCallback((key: VulnerabilityIntelFilterKey) => {
    setVulnerabilityIntelActiveFilters((current) => (current.includes(key) ? current : [...current, key]));
  }, []);

  const removeVulnerabilityIntelFilter = React.useCallback((key: VulnerabilityIntelFilterKey) => {
    setVulnerabilityIntelActiveFilters((current) => current.filter((item) => item !== key));
    if (key === 'severity') {
      setVulnerabilityIntelSeverities([]);
    } else if (key === 'source') {
      setVulnerabilityIntelSources([]);
    } else if (key === 'vulnStatus') {
      setVulnerabilityIntelStatuses([]);
    } else if (key === 'inKev') {
      setVulnerabilityIntelInKevValues([]);
    } else if (key === 'query') {
      setVulnerabilityIntelQuery('');
    }
    setVulnerabilityIntelPage(0);
  }, []);

  const clearVulnerabilityIntelFilters = React.useCallback(() => {
    setVulnerabilityIntelSeverities([]);
    setVulnerabilityIntelSources([]);
    setVulnerabilityIntelStatuses([]);
    setVulnerabilityIntelInKevValues([]);
    setVulnerabilityIntelQuery('');
    setVulnerabilityIntelPage(0);
    setVulnerabilityIntelActiveFilters([]);
  }, []);

  const addComponentFilter = React.useCallback((key: InventoryComponentFilterKey) => {
    setComponentActiveFilters((current) => (current.includes(key) ? current : [...current, key]));
  }, []);

  const removeComponentFilter = React.useCallback((key: InventoryComponentFilterKey) => {
    setComponentActiveFilters((current) => current.filter((item) => item !== key));
    if (key === 'assetType') {
      setComponentAssetTypes([]);
    } else if (key === 'componentStatus') {
      setComponentStatuses([]);
    } else if (key === 'sourceSystem') {
      setComponentSourceSystems([]);
    } else if (key === 'ecosystem') {
      setComponentEcosystems([]);
    } else if (key === 'reviewCategory') {
      setComponentReviewCategories([]);
    } else if (key === 'query') {
      setComponentQuery('');
    }
    setComponentPage(0);
  }, []);

  const clearComponentFilters = React.useCallback(() => {
    setComponentQuery('');
    setComponentAssetTypes([]);
    setComponentStatuses([]);
    setComponentSourceSystems([]);
    setComponentEcosystems([]);
    setComponentReviewCategories([]);
    setComponentPage(0);
    setComponentActiveFilters([]);
  }, []);

  const loadInventory = React.useCallback(async () => {
    const requestId = loadRequestIdRef.current + 1;
    loadRequestIdRef.current = requestId;
    setLoading(true);
    setError('');
    try {
      if (selectedView === 'vulnerability-intelligence') {
        const response = await api.listVulnerabilityIntelligence({
          page: vulnerabilityIntelPage,
          size: VULNERABILITY_INTEL_PAGE_SIZE,
          query: debouncedVulnerabilityIntelQuery.trim() || undefined,
          severity: vulnerabilityIntelSeverities.length > 0 ? vulnerabilityIntelSeverities : undefined,
          source: vulnerabilityIntelSources.length > 0 ? expandVulnerabilitySourceFilters(vulnerabilityIntelSources) : undefined,
          vulnStatus: vulnerabilityIntelStatuses.length > 0 ? vulnerabilityIntelStatuses : undefined,
          inKev: vulnerabilityIntelInKevFilter
        });
        if (requestId !== loadRequestIdRef.current) {
          return;
        }
        const normalizedRows = response.items.map((record) => ({
          ...record,
          sources: Array.from(
            new Set(
              (record.sources || [])
                .filter((source) => source && source.trim().length > 0)
                .map((source) => canonicalVulnerabilitySource(source))
            )
          )
        }));
        setVulnerabilityIntelRows(normalizedRows);
        setVulnerabilityIntelTotalItems(response.totalItems);
        setVulnerabilityIntelTotalPages(response.totalPages);
        setRows([]);
        setComponentTotalItems(0);
        setComponentTotalPages(0);

        void api.listVulnerabilityIntelligenceFilters()
          .then((availableFilters) => {
            if (requestId !== loadRequestIdRef.current) {
              return;
            }
            setVulnerabilityIntelFilterValues({
              severities: Array.from(new Set(
                (availableFilters.severities || [])
                  .filter((value) => value && value.trim().length > 0)
                  .map((value) => value.trim().toUpperCase())
              )),
              sources: Array.from(new Set(
              (availableFilters.sources || [])
                  .filter((value) => value && value.trim().length > 0)
                  .map((value) => vulnerabilitySourceFilterValue(value))
              )),
              vulnStatuses: Array.from(new Set(
                (availableFilters.vulnStatuses || [])
                  .filter((value) => value && value.trim().length > 0)
                  .map((value) => value.trim().toUpperCase())
              )),
              inKevValues: Array.from(new Set(
                (availableFilters.inKevValues || [])
                  .filter((value) => value && value.trim().length > 0)
                  .map((value) => value.trim().toLowerCase())
              ))
            });
          })
          .catch(() => {
            if (requestId !== loadRequestIdRef.current) {
              return;
            }
            setVulnerabilityIntelFilterValues(DEFAULT_VULNERABILITY_INTEL_FILTERS);
          });
      } else {
        const assetTypeParam = scopedAssetType === 'ALL'
          ? (
            componentActiveFilters.includes('assetType') && componentAssetTypes.length > 0
              ? componentAssetTypes.filter((value): value is InventoryComponentRecord['assetType'] => (
                value === 'APPLICATION' || value === 'HOST' || value === 'CONTAINER_IMAGE'
              ))
              : undefined
          )
          : [scopedAssetType as InventoryComponentRecord['assetType']];
        const componentStatusParam = componentActiveFilters.includes('componentStatus') && componentStatuses.length > 0
          ? componentStatuses.filter((value): value is InventoryComponentRecord['componentStatus'] => (
            value === 'ACTIVE' || value === 'RETIRED'
          ))
          : undefined;
        const [data, availableFilters] = await Promise.all([
          api.listInventoryComponents({
            assetType: assetTypeParam,
            componentStatus: componentStatusParam,
            sourceSystem: componentActiveFilters.includes('sourceSystem') && componentSourceSystems.length > 0
              ? componentSourceSystems
              : undefined,
            ecosystem: componentActiveFilters.includes('ecosystem') && componentEcosystems.length > 0
              ? componentEcosystems
              : undefined,
            reviewCategory: selectedView === 'hosts'
              && componentActiveFilters.includes('reviewCategory')
              && componentReviewCategories.length > 0
              ? componentReviewCategories
              : undefined,
            query: componentActiveFilters.includes('query') ? debouncedComponentQuery.trim() : undefined,
            page: componentPage,
            size: COMPONENTS_PAGE_SIZE
          }),
          api.listInventoryComponentFilters().catch(() => DEFAULT_COMPONENT_FILTERS)
        ]);
        if (requestId !== loadRequestIdRef.current) {
          return;
        }
        setComponentFilterValues({
          assetTypes: Array.from(new Set(
            (availableFilters.assetTypes || [])
              .filter((value) => value && value.trim().length > 0)
              .map((value) => value.trim().toUpperCase())
          )),
          componentStatuses: Array.from(new Set(
            (availableFilters.componentStatuses || [])
              .filter((value) => value && value.trim().length > 0)
              .map((value) => value.trim().toUpperCase())
          )),
          sourceSystems: Array.from(new Set(
            (availableFilters.sourceSystems || [])
              .filter((value) => value && value.trim().length > 0)
              .map((value) => value.trim().toLowerCase())
          )),
          ecosystems: Array.from(new Set(
            (availableFilters.ecosystems || [])
              .filter((value) => value && value.trim().length > 0)
              .map((value) => value.trim().toLowerCase())
          ))
        });
        setRows(data.items);
        setComponentTotalItems(data.totalItems);
        setComponentTotalPages(data.totalPages);
        setVulnerabilityIntelRows([]);
        setVulnerabilityIntelTotalItems(0);
        setVulnerabilityIntelTotalPages(0);
      }
    } catch (requestError) {
      if (requestId !== loadRequestIdRef.current) {
        return;
      }
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      if (requestId === loadRequestIdRef.current) {
        setLoading(false);
      }
    }
  }, [
    scopedAssetType,
    componentActiveFilters,
    componentAssetTypes,
    componentStatuses,
    componentSourceSystems,
    componentEcosystems,
    componentReviewCategories,
    selectedView,
    componentPage,
    debouncedComponentQuery,
    vulnerabilityIntelPage,
    debouncedVulnerabilityIntelQuery,
    vulnerabilityIntelSeverities,
    vulnerabilityIntelSources,
    vulnerabilityIntelStatuses,
    vulnerabilityIntelInKevFilter
  ]);

  React.useEffect(() => {
    loadInventory();
  }, [loadInventory]);

  const closeVulnerabilityIntelDetail = React.useCallback((): void => {
    setSelectedVulnerabilityIntelId(null);
    setSelectedVulnerabilityIntelDetail(null);
  }, []);

  const openHostDetail = React.useCallback((assetId: string): void => {
    setSelectedHostAssetId(assetId);
  }, []);

  const closeHostDetail = React.useCallback((): void => {
    setSelectedHostAssetId(null);
  }, []);

  React.useEffect(() => {
    if (selectedView !== 'vulnerability-intelligence' || !selectedVulnerabilityIntelId) {
      return;
    }
    let cancelled = false;
    setVulnerabilityIntelDetailLoading(true);
    api.getVulnerabilityIntelligenceDetail(selectedVulnerabilityIntelId)
      .then((detail) => {
        if (!cancelled) {
          setSelectedVulnerabilityIntelDetail(detail);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedVulnerabilityIntelDetail(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setVulnerabilityIntelDetailLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedView, selectedVulnerabilityIntelId]);

  const openVulnerabilityIntelDetail = (externalId: string): void => {
    setSelectedVulnerabilityIntelId(externalId);
  };

  const hostReviewLabels = React.useCallback((row: InventoryComponentRecord): string[] => {
    const labels: string[] = [];
    if (row.reviewMissingVersion) labels.push('Missing Version');
    if (row.reviewUnmappedSoftware) labels.push('Unmapped Identity');
    if (row.reviewLowConfidenceAlias) labels.push('Alias Review');
    if (row.reviewDiscoveryModel) labels.push('Discovery Review');
    return labels;
  }, []);

  const activeCount = rows.filter((row) => row.componentStatus === 'ACTIVE').length;
  const retiredCount = rows.filter((row) => row.componentStatus === 'RETIRED').length;
  const assetCount = new Set(rows.map((row) => row.assetId)).size;
  const needsReviewCount = rows.filter((row) => row.needsReview).length;

  return (
    <div className="page-grid">
      <section className={selectedView === 'vulnerability-intelligence' ? 'panel panel-vuln-intel-filters' : 'panel'}>
        <div>
          {selectedView === 'vulnerability-intelligence' ? (
            <>
              <div className="findings-filter-shell">
                <div className="findings-filter-builder-row">
                  <FilterBuilder
                    categories={VULNERABILITY_INTEL_FILTER_CATEGORIES}
                    fields={VULNERABILITY_INTEL_FILTER_FIELDS}
                    activeKeys={vulnerabilityIntelActiveFilters}
                    onAddFilter={(key) => addVulnerabilityIntelFilter(key as VulnerabilityIntelFilterKey)}
                  />
                  <div className="findings-filter-active-chips">
                    {vulnerabilityIntelActiveFilters.map((key) => {
                      let label = '';
                      if (key === 'severity') {
                        label = `Severity${vulnerabilityIntelSeverities.length > 0 ? ` (${vulnerabilityIntelSeverities.length})` : ''}`;
                      } else if (key === 'source') {
                        label = `Source${vulnerabilityIntelSources.length > 0 ? ` (${vulnerabilityIntelSources.length})` : ''}`;
                      } else if (key === 'vulnStatus') {
                        label = `Vulnerability Status${vulnerabilityIntelStatuses.length > 0 ? ` (${vulnerabilityIntelStatuses.length})` : ''}`;
                      } else if (key === 'inKev') {
                        label = `KEV${vulnerabilityIntelInKevValues.length > 0 ? ` (${vulnerabilityIntelInKevValues.length})` : ''}`;
                      } else {
                        label = `Vulnerability Search${vulnerabilityIntelQuery.trim() ? ' (1)' : ''}`;
                      }
                      return (
                        <button
                          key={key}
                          type="button"
                          className="findings-filter-chip-tag"
                          onClick={() => removeVulnerabilityIntelFilter(key)}
                          title="Remove filter"
                        >
                          <span>{label}</span>
                          <span aria-hidden="true">x</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="findings-active-filter-grid">
                  {vulnerabilityIntelActiveFilters.includes('severity') && (
                    <FilterValueSelectCard
                      label="Severity"
                      selectedValues={vulnerabilityIntelSeverities}
                      options={severityOptions}
                      onChange={(values) => {
                        setVulnerabilityIntelSeverities(values);
                        setVulnerabilityIntelPage(0);
                      }}
                      onRemove={() => removeVulnerabilityIntelFilter('severity')}
                    />
                  )}

                  {vulnerabilityIntelActiveFilters.includes('source') && (
                    <FilterValueSelectCard
                      label="Source"
                      selectedValues={vulnerabilityIntelSources}
                      options={sourceOptions}
                      onChange={(values) => {
                        setVulnerabilityIntelSources(values);
                        setVulnerabilityIntelPage(0);
                      }}
                      onRemove={() => removeVulnerabilityIntelFilter('source')}
                    />
                  )}

                  {vulnerabilityIntelActiveFilters.includes('vulnStatus') && (
                    <FilterValueSelectCard
                      label="Vulnerability Status"
                      selectedValues={vulnerabilityIntelStatuses}
                      options={vulnStatusOptions}
                      onChange={(values) => {
                        setVulnerabilityIntelStatuses(values);
                        setVulnerabilityIntelPage(0);
                      }}
                      onRemove={() => removeVulnerabilityIntelFilter('vulnStatus')}
                    />
                  )}

                  {vulnerabilityIntelActiveFilters.includes('inKev') && (
                    <FilterValueSelectCard
                      label="KEV"
                      selectedValues={vulnerabilityIntelInKevValues}
                      options={kevOptions}
                      onChange={(values) => {
                        setVulnerabilityIntelInKevValues(values);
                        setVulnerabilityIntelPage(0);
                      }}
                      onRemove={() => removeVulnerabilityIntelFilter('inKev')}
                    />
                  )}

                  {vulnerabilityIntelActiveFilters.includes('query') && (
                    <label className="findings-filter-chip findings-filter-text-card">Vulnerability Search
                      <button
                        type="button"
                        className="findings-filter-chip-remove"
                        onClick={() => removeVulnerabilityIntelFilter('query')}
                        aria-label="Remove Vulnerability Search filter"
                      >
                        x
                      </button>
                      <input
                        value={vulnerabilityIntelQuery}
                        onChange={(event) => {
                          setVulnerabilityIntelQuery(event.target.value);
                          setVulnerabilityIntelPage(0);
                        }}
                        placeholder="CVE-2024-12345, ADV-DEMO-001, or title"
                        className="mono"
                      />
                    </label>
                  )}
                </div>

                <div className="findings-filter-row vuln-intel-filter-row">
                  <div className="findings-filter-actions">
                    <button className="btn btn-secondary btn-inline" type="button" onClick={clearVulnerabilityIntelFilters}>
                      Clear Filters
                    </button>
                    <button className="btn btn-secondary btn-inline" type="button" onClick={loadInventory} disabled={loading}>
                      {loading ? 'Refreshing...' : 'Refresh Vulnerability Intelligence'}
                    </button>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <>
              {selectedView === 'sbom' && (
                <div className="panel-caption">
                  Repository inventory is scoped to application assets. GHCR image SBOMs appear only in <span className="mono">Inventory &gt; Container Images</span>.
                </div>
              )}
              {selectedView === 'hosts' && (
                <div className="panel-caption">
                  Host inventory is persisted as normalized software components across host assets. When a source already provides trustworthy normalized
                  inventory, it is retained; otherwise deterministic normalization is applied before the software appears here.
                </div>
              )}
              <div className="findings-filter-shell">
                <div className="findings-filter-builder-row">
                  <FilterBuilder
                    categories={INVENTORY_FILTER_CATEGORIES}
                    fields={inventoryFilterFields}
                    activeKeys={componentActiveFilters}
                    onAddFilter={(key) => addComponentFilter(key as InventoryComponentFilterKey)}
                  />
                  <div className="findings-filter-active-chips">
                    {componentActiveFilters.map((key) => {
                      let label = '';
                      if (key === 'assetType') {
                        label = `Asset Type${componentAssetTypes.length > 0 ? ` (${componentAssetTypes.length})` : ''}`;
                      } else if (key === 'componentStatus') {
                        label = `Component Status${componentStatuses.length > 0 ? ` (${componentStatuses.length})` : ''}`;
                      } else if (key === 'sourceSystem') {
                        label = `Source System${componentSourceSystems.length > 0 ? ` (${componentSourceSystems.length})` : ''}`;
                      } else if (key === 'ecosystem') {
                        label = `Ecosystem${componentEcosystems.length > 0 ? ` (${componentEcosystems.length})` : ''}`;
                      } else if (key === 'reviewCategory') {
                        label = `Host Review${componentReviewCategories.length > 0 ? ` (${componentReviewCategories.length})` : ''}`;
                      } else {
                        label = `Inventory Search${componentQuery.trim() ? ' (1)' : ''}`;
                      }
                      return (
                        <button
                          key={key}
                          type="button"
                          className="findings-filter-chip-tag"
                          onClick={() => removeComponentFilter(key)}
                          title="Remove filter"
                        >
                          <span>{label}</span>
                          <span aria-hidden="true">x</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="findings-active-filter-grid">
                  {scopedAssetType === 'ALL' && componentActiveFilters.includes('assetType') && (
                    <FilterValueSelectCard
                      label="Asset Type"
                      selectedValues={componentAssetTypes}
                      options={assetTypeOptions}
                      onChange={(values) => {
                        setComponentAssetTypes(values);
                        setComponentPage(0);
                      }}
                      onRemove={() => removeComponentFilter('assetType')}
                    />
                  )}

                  {componentActiveFilters.includes('componentStatus') && (
                    <FilterValueSelectCard
                      label="Component Status"
                      selectedValues={componentStatuses}
                      options={componentStatusOptions}
                      onChange={(values) => {
                        setComponentStatuses(values);
                        setComponentPage(0);
                      }}
                      onRemove={() => removeComponentFilter('componentStatus')}
                    />
                  )}

                  {componentActiveFilters.includes('sourceSystem') && (
                    <FilterValueSelectCard
                      label="Source System"
                      selectedValues={componentSourceSystems}
                      options={sourceSystemOptions}
                      onChange={(values) => {
                        setComponentSourceSystems(values);
                        setComponentPage(0);
                      }}
                      onRemove={() => removeComponentFilter('sourceSystem')}
                    />
                  )}

                  {componentActiveFilters.includes('ecosystem') && (
                    <FilterValueSelectCard
                      label="Ecosystem"
                      selectedValues={componentEcosystems}
                      options={ecosystemOptions}
                      onChange={(values) => {
                        setComponentEcosystems(values);
                        setComponentPage(0);
                      }}
                      onRemove={() => removeComponentFilter('ecosystem')}
                    />
                  )}

                  {selectedView === 'hosts' && componentActiveFilters.includes('reviewCategory') && (
                    <FilterValueSelectCard
                      label="Host Review"
                      selectedValues={componentReviewCategories}
                      options={hostReviewOptions}
                      onChange={(values) => {
                        setComponentReviewCategories(values
                          .map(normalizeHostReviewCategory)
                          .filter((value): value is HostReviewCategory => value !== null));
                        setComponentPage(0);
                      }}
                      onRemove={() => removeComponentFilter('reviewCategory')}
                    />
                  )}

                  {componentActiveFilters.includes('query') && (
                    <label className="findings-filter-chip findings-filter-text-card">Inventory Search
                      <button
                        type="button"
                        className="findings-filter-chip-remove"
                        onClick={() => removeComponentFilter('query')}
                        aria-label="Remove Inventory Search filter"
                      >
                        x
                      </button>
                      <input
                        value={componentQuery}
                        onChange={(event) => {
                          setComponentQuery(event.target.value);
                          setComponentPage(0);
                        }}
                        placeholder="asset, package, software identity, or purl"
                        className="mono"
                      />
                    </label>
                  )}
                </div>

                <div className="findings-filter-row">
                  <div className="findings-filter-actions">
                    <button className="btn btn-secondary btn-inline" type="button" onClick={clearComponentFilters}>
                      Clear Filters
                    </button>
                    <button className="btn btn-secondary btn-inline" type="button" onClick={loadInventory} disabled={loading}>
                      {loading ? 'Refreshing...' : 'Refresh Inventory'}
                    </button>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </section>

      {selectedView !== 'vulnerability-intelligence' && (
        <div className="stats-grid">
          <StatCard
            title="Inventory Records"
            value={componentTotalItems}
          />
          <StatCard title="Active Components" value={activeCount} />
          <StatCard title="Retired Components" value={retiredCount} />
          <StatCard
            title="Assets Represented"
            value={assetCount}
          />
          {selectedView === 'hosts' && (
            <StatCard
              title="Rows Needing Review"
              value={needsReviewCount}
            />
          )}
        </div>
      )}

      <section className="panel">
        <div className="panel-header">
          <h3>
            {selectedView === 'vulnerability-intelligence'
              ? 'Unified Vulnerability Records'
              : 'Component Inventory Records'}
          </h3>
          {selectedView !== 'vulnerability-intelligence' && (
            <span className="panel-caption">
              Inventory records are normalized and persisted consistently across application, container-image, and host inventory views.
            </span>
          )}
        </div>

        {error && <div className="notice error">Failed to load inventory: {error}</div>}

        {selectedView === 'vulnerability-intelligence' ? (
          loading && vulnerabilityIntelRows.length === 0 ? (
            <div className="notice">Loading vulnerability intelligence records...</div>
          ) : vulnerabilityIntelRows.length === 0 ? (
            <div className="empty-state">
              <p>
                No vulnerability intelligence records found. Run source sync from <span className="mono">Connect</span>.
              </p>
            </div>
          ) : (
            <>
              <div className="table-scroll">
                <ResizableTable storageKey="inventory-vulnerability-intel-table-widths">
                  <thead>
                    <tr>
                      <th>Vulnerability ID</th>
                      <th>Description</th>
                      <th>Severity</th>
                      <th>CVSS</th>
                      <th>EPSS</th>
                      <th>Affected Packages</th>
                      <th>Primary Source</th>
                      <th>All Sources</th>
                      <th>Open Findings</th>
                      <th>Published</th>
                      <th>Last Modified</th>
                    </tr>
                  </thead>
                  <tbody>
                  {vulnerabilityIntelRows.map((record) => (
                    <tr
                      key={record.id}
                      className={`table-row-clickable ${selectedVulnerabilityIntelId === record.externalId ? 'table-row-selected' : ''}`}
                      onClick={() => openVulnerabilityIntelDetail(record.externalId)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          openVulnerabilityIntelDetail(record.externalId);
                        }
                      }}
                      tabIndex={0}
                      aria-label={`Open vulnerability intelligence detail ${record.externalId}`}
                    >
                      <td>
                        <span className="mono">{record.externalId}</span>
                      </td>
                      <td>{record.descriptionSnippet || '-'}</td>
                      <td>{record.severity || '-'}</td>
                      <td>{record.cvssScore ?? '-'}</td>
                      <td>{record.epssScore ?? '-'}</td>
                      <td>
                        {record.affectedPackages && record.affectedPackages.length > 0
                          ? record.affectedPackages.slice(0, 3).map((pkg) =>
                              pkg.packageName
                                ? `${pkg.packageName}${pkg.ecosystem ? ` (${pkg.ecosystem})` : ''}`
                                : pkg.cpe ?? '-'
                            ).join(', ') + (record.affectedPackages.length > 3 ? ` +${record.affectedPackages.length - 3} more` : '')
                          : '-'}
                      </td>
                      <td>{record.sources.length > 0 ? formatSourceSystem(record.sources[0]) : '-'}</td>
                      <td>
                        {record.sources.length > 0 ? record.sources.map(formatSourceSystem).join(', ') : '-'}
                      </td>
                      <td>{record.openFindings}</td>
                      <td>{record.publishedAt ? new Date(record.publishedAt).toLocaleString() : '-'}</td>
                      <td>{record.lastModifiedAt ? new Date(record.lastModifiedAt).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                  </tbody>
                </ResizableTable>
              </div>
              <div className="pagination-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setVulnerabilityIntelPage((current) => Math.max(0, current - 1))}
                  disabled={vulnerabilityIntelPage <= 0 || loading}
                >
                  Previous
                </button>
                <span className="panel-caption pagination-caption">
                  Page {vulnerabilityIntelTotalPages === 0 ? 0 : vulnerabilityIntelPage + 1} of {Math.max(vulnerabilityIntelTotalPages, 1)}
                </span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setVulnerabilityIntelPage((current) => (current + 1 < vulnerabilityIntelTotalPages ? current + 1 : current))}
                  disabled={loading || vulnerabilityIntelTotalPages === 0 || vulnerabilityIntelPage + 1 >= vulnerabilityIntelTotalPages}
                >
                  Next
                </button>
              </div>
            </>
          )
        ) : loading && rows.length === 0 ? (
          <div className="notice">Loading inventory records...</div>
        ) : rows.length === 0 ? (
          <div className="empty-state">
            <p>
              No inventory records found for this view. Connect an SBOM source from <span className="mono">Connect &gt; Inventory Sources</span>.
            </p>
          </div>
        ) : (
          <>
            <div className="table-scroll">
              <ResizableTable storageKey="inventory-components-table-widths">
                <thead>
                <tr>
                  <th>Asset</th>
                  <th>Asset Type</th>
                  <th>Component</th>
                  <th>Normalized Name</th>
                  <th>Version</th>
                  <th>Normalized Version</th>
                  <th>Ecosystem</th>
                  <th>Software Identity</th>
                  {selectedView === 'hosts' && <th>Review</th>}
                  <th>EOL Status</th>
                  <th>Component Status</th>
                  <th>Source</th>
                  <th>PURL</th>
                  <th>Uploaded</th>
                  <th>Last Observed</th>
                </tr>
                </thead>
                <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.id}
                    className={selectedView === 'hosts' && row.assetId === selectedHostAssetId ? 'table-row-selected' : ''}
                  >
                    <td>
                      {selectedView === 'hosts' ? (
                        <button
                          type="button"
                          className="btn-link"
                          onClick={() => openHostDetail(row.assetId)}
                        >
                          {row.assetName}
                        </button>
                      ) : (
                        <div>{row.assetName}</div>
                      )}
                      <div className="panel-caption mono">{row.assetIdentifier}</div>
                      {selectedView === 'hosts' && (
                        <div className="panel-caption">Open host detail</div>
                      )}
                    </td>
                    <td>{formatAssetType(row.assetType)}</td>
                    <td>{row.packageName}</td>
                    <td className="mono">{row.normalizedName || '-'}</td>
                    <td className="mono">{row.version}</td>
                    <td className="mono">{row.normalizedVersion || '-'}</td>
                    <td>{row.ecosystem || '-'}</td>
                    <td>{row.softwareIdentity || '-'}</td>
                    {selectedView === 'hosts' && (
                      <td>
                        {row.needsReview ? (
                          <>
                            <div className="panel-caption">
                              {row.reviewItemCount} review item{row.reviewItemCount === 1 ? '' : 's'}
                            </div>
                            <div className="findings-inline-pill-row">
                              {hostReviewLabels(row).map((label) => (
                                <span key={`${row.id}-${label}`} className="status-pill status-in-progress">
                                  {label}
                                </span>
                              ))}
                            </div>
                          </>
                        ) : (
                          <span className="status-pill status-suppressed">Clear</span>
                        )}
                      </td>
                    )}
                    <td>
                      <EolBadge
                        isEol={row.isEol}
                        daysRemaining={row.eolDaysRemaining}
                        eolDate={row.eolDate}
                      />
                    </td>
                    <td>
                      <span className={`status-pill ${row.componentStatus === 'ACTIVE' ? 'status-open' : 'status-auto_closed'}`}>
                        {row.componentStatus}
                      </span>
                    </td>
                    <td>
                      <div>{row.sourceSystem ? formatInventorySourceSystem(row.sourceSystem) : '-'}</div>
                      <div className="panel-caption">
                        {row.sourceReference || row.sourceType || '-'}
                      </div>
                    </td>
                    <td className="mono">{row.purl || '-'}</td>
                    <td>{row.uploadedAt ? new Date(row.uploadedAt).toLocaleString() : '-'}</td>
                    <td>{row.lastObservedAt ? new Date(row.lastObservedAt).toLocaleString() : '-'}</td>
                  </tr>
                ))}
                </tbody>
              </ResizableTable>
            </div>
            <div className="pagination-row">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setComponentPage((current) => Math.max(0, current - 1))}
                disabled={componentPage <= 0 || loading}
              >
                Previous
              </button>
              <span className="panel-caption pagination-caption">
                Page {componentTotalPages === 0 ? 0 : componentPage + 1} of {Math.max(componentTotalPages, 1)}
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setComponentPage((current) => (current + 1 < componentTotalPages ? current + 1 : current))}
                disabled={loading || componentTotalPages === 0 || componentPage + 1 >= componentTotalPages}
              >
                Next
              </button>
            </div>
          </>
        )}
      </section>

      {selectedView === 'hosts' && selectedHostAssetId && (
        <div
          className="modal-overlay"
          onClick={closeHostDetail}
        >
          <div
            className="modal-panel modal-panel-wide"
            onClick={(event) => event.stopPropagation()}
          >
            <HostAssetDetailPage
              assetId={selectedHostAssetId}
              onClose={closeHostDetail}
            />
          </div>
        </div>
      )}

      {selectedView === 'vulnerability-intelligence' && selectedVulnerabilityIntelId && (
        <div
          className="modal-overlay"
          onClick={closeVulnerabilityIntelDetail}
        >
          <div
            className="modal-panel modal-panel-wide"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="panel-header">
              <h3>Normalized CVE Detail</h3>
              <div className="button-row">
                <span className="panel-caption mono">{selectedVulnerabilityIntelId}</span>
                <button
                  type="button"
                  className="modal-close-btn"
                  onClick={closeVulnerabilityIntelDetail}
                  aria-label="Close vulnerability detail"
                >
                  x
                </button>
              </div>
            </div>
            {vulnerabilityIntelDetailLoading ? (
              <div className="notice">Loading CVE detail...</div>
            ) : !selectedVulnerabilityIntelDetail ? (
              <div className="notice error">Unable to load source observations for this CVE.</div>
            ) : (
              <>
                <div className="details-grid">
                  <div><strong>Severity:</strong> {selectedVulnerabilityIntelDetail.severity}</div>
                  <div><strong>CVSS:</strong> {selectedVulnerabilityIntelDetail.cvssScore ?? '-'}</div>
                  <div><strong>EPSS:</strong> {selectedVulnerabilityIntelDetail.epssScore ?? '-'}</div>
                  <div><strong>KEV:</strong> {selectedVulnerabilityIntelDetail.inKev ? 'Yes' : 'No'}</div>
                  <div><strong>Status:</strong> {selectedVulnerabilityIntelDetail.vulnStatus ?? '-'}</div>
                  <div><strong>Source Count:</strong> {selectedVulnerabilityIntelDetail.sourceCount}</div>
                  <div><strong>Open Findings:</strong> {selectedVulnerabilityIntelDetail.openFindings}</div>
                  <div><strong>Sources:</strong> {selectedVulnerabilityIntelDetail.sources.map(formatSourceSystem).join(', ') || '-'}</div>
                  <div>
                    <strong>VEX Coverage:</strong>{' '}
                    <span className={`status-pill ${vexCoverageClass(selectedVulnerabilityIntelDetail.vexCoverage)}`}>
                      {formatVexCoverage(selectedVulnerabilityIntelDetail.vexCoverage)}
                    </span>
                  </div>
                  <div>
                    <strong>VEX Package Coverage:</strong> {selectedVulnerabilityIntelDetail.vexCoveredPackageCount}/
                    {selectedVulnerabilityIntelDetail.vexPackageCount}
                  </div>
                </div>
                {selectedVulnerabilityIntelDetail.affectedPackages && selectedVulnerabilityIntelDetail.affectedPackages.length > 0 && (
                  <div className="section-block">
                    <h4 className="section-title">Affected Packages</h4>
                    <div className="table-scroll">
                      <ResizableTable storageKey="inventory-vuln-intel-affected-packages-widths">
                        <thead>
                          <tr>
                            <th>Package</th>
                            <th>Ecosystem</th>
                            <th>Affected Versions</th>
                            <th>Fixed In</th>
                            <th>CPE</th>
                            <th>VEX Status</th>
                            <th>VEX Source</th>
                            <th>Provider</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedVulnerabilityIntelDetail.affectedPackages.map((pkg, idx) => (
                            <tr key={idx}>
                              <td className="mono">{pkg.packageName ?? '-'}</td>
                              <td>{pkg.ecosystem ?? '-'}</td>
                              <td className="mono">{pkg.affectedVersions}</td>
                              <td className="mono">{pkg.fixedVersion ?? '-'}</td>
                              <td className="mono">{pkg.cpe ?? '-'}</td>
                              <td>{pkg.vexStatus ?? '-'}</td>
                              <td>{pkg.vexSource ? formatSourceSystem(pkg.vexSource) : '-'}</td>
                              <td>{pkg.vexProvider ?? '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </ResizableTable>
                    </div>
                  </div>
                )}
                {selectedVulnerabilityIntelDetail.vexEvidence && selectedVulnerabilityIntelDetail.vexEvidence.length > 0 && (
                  <div className="section-block">
                    <h4 className="section-title">VEX Evidence</h4>
                    <div className="table-scroll">
                      <ResizableTable storageKey="inventory-vuln-intel-vex-evidence-widths">
                        <thead>
                          <tr>
                            <th>Package</th>
                            <th>Ecosystem</th>
                            <th>Affected Versions</th>
                            <th>Fixed In</th>
                            <th>Source</th>
                            <th>Provider</th>
                            <th>Status</th>
                            <th>Trust</th>
                            <th>Freshness</th>
                            <th>Document</th>
                            <th>Evidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedVulnerabilityIntelDetail.vexEvidence.map((evidence) => (
                            <tr key={evidence.assertionId}>
                              <td className="mono">{evidence.packageName ?? evidence.normalizedProductKey ?? '-'}</td>
                              <td>{evidence.ecosystem ?? '-'}</td>
                              <td className="mono">{evidence.affectedVersions ?? '-'}</td>
                              <td className="mono">{evidence.fixedVersion ?? '-'}</td>
                              <td>{formatSourceSystem(evidence.sourceSystem)}</td>
                              <td>{evidence.provider ?? '-'}</td>
                              <td>{formatInventoryLabel(evidence.status)}</td>
                              <td>{formatInventoryLabel(evidence.trustTier)}</td>
                              <td>{formatInventoryLabel(evidence.freshness)}</td>
                              <td className="mono">{evidence.documentId}</td>
                              <td className="mono">
                                {evidence.evidenceUrl ? (
                                  <a href={evidence.evidenceUrl} target="_blank" rel="noreferrer">
                                    Open
                                  </a>
                                ) : '-'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </ResizableTable>
                    </div>
                  </div>
                )}
                {selectedVulnerabilityIntelDetail.references.length > 0 && (
                  <div className="section-block">
                    <h4 className="section-title">References</h4>
                    <div className="table-scroll">
                      {selectedVulnerabilityIntelDetail.references.map((reference) => (
                        <div key={reference} className="panel-caption mono">{reference}</div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="table-scroll" style={{ marginTop: 12 }}>
                  <ResizableTable storageKey="inventory-vulnerability-intel-observations-table-widths">
                    <thead>
                    <tr>
                      <th>Source System</th>
                      <th>Source Record</th>
                      <th>Severity</th>
                      <th>CVSS</th>
                      <th>EPSS</th>
                      <th>KEV</th>
                      <th>Published</th>
                      <th>Last Modified</th>
                      <th>Last Seen</th>
                      <th>Source URL</th>
                      <th>References</th>
                    </tr>
                    </thead>
                    <tbody>
                    {selectedVulnerabilityIntelDetail.observations.map((observation) => (
                      <tr key={observation.id}>
                        <td>{formatSourceSystem(observation.sourceSystem)}</td>
                        <td className="mono">{observation.sourceRecordId}</td>
                        <td>{observation.severity ?? '-'}</td>
                        <td>{observation.cvssScore ?? '-'}</td>
                        <td>{observation.epssScore ?? '-'}</td>
                        <td>{observation.inKev ? 'Yes' : 'No'}</td>
                        <td>{observation.publishedAt ? new Date(observation.publishedAt).toLocaleString() : '-'}</td>
                        <td>{observation.lastModifiedAt ? new Date(observation.lastModifiedAt).toLocaleString() : '-'}</td>
                        <td>{observation.lastSeenAt ? new Date(observation.lastSeenAt).toLocaleString() : '-'}</td>
                        <td className="mono">{observation.sourceUrl ?? '-'}</td>
                        <td>{observation.references.length}</td>
                      </tr>
                    ))}
                    </tbody>
                  </ResizableTable>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
