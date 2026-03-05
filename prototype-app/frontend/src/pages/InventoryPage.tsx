import React from 'react';
import { api } from '../api/client';
import {
  InventoryComponentFilterValues,
  InventoryComponentRecord,
  SoftwareModelRecord,
  VulnerabilityIntelDetail,
  VulnerabilityIntelFilterValues,
  VulnerabilityIntelRecord
} from '../types';
import { ResizableTable } from '../components/ResizableTable';
import { StatCard } from '../components/StatCard';
import { FilterBuilder, FilterBuilderCategory, FilterBuilderField } from '../components/FilterBuilder';
import { FilterValueOption, FilterValueSelectCard } from '../components/FilterValueSelectCard';

export type InventoryViewKey =
  | 'software-models'
  | 'vulnerability-intelligence'
  | 'technologies'
  | 'service-catalog'
  | 'cloud-resources'
  | 'imported-assets'
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

type AssetTypeFilter = 'ALL' | string;
type ComponentStatusFilter = 'ALL' | string;
type SourceSystemFilter = 'ALL' | string;
type VulnerabilityIntelFilterKey = 'severity' | 'source' | 'vulnStatus' | 'inKev' | 'query';
const SOFTWARE_MODELS_PAGE_SIZE = 25;
const VULNERABILITY_INTEL_PAGE_SIZE = 25;
const COMPONENTS_PAGE_SIZE = 25;
const DEFAULT_VULNERABILITY_INTEL_FILTERS: VulnerabilityIntelFilterValues = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'],
  sources: ['nvd', 'kev', 'ghsa', 'csaf-microsoft', 'vex-microsoft', 'csaf-redhat', 'vex-redhat', 'advisory'],
  vulnStatuses: ['KNOWN_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION', 'NOT_AFFECTED', 'UNKNOWN'],
  inKevValues: ['true', 'false']
};
const DEFAULT_COMPONENT_FILTERS: InventoryComponentFilterValues = {
  assetTypes: ['APPLICATION', 'HOST', 'CONTAINER_IMAGE'],
  componentStatuses: ['ACTIVE', 'RETIRED'],
  sourceSystems: ['upload', 'api', 'github']
};

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
  'csaf-microsoft': 'MSRC CSAF',
  'vex-microsoft': 'MSRC VEX',
  'csaf-redhat': 'Red Hat CSAF',
  'vex-redhat': 'Red Hat VEX',
  advisory: 'Advisory'
};

const INVENTORY_VIEW_LABELS: Record<InventoryViewKey, string> = {
  'software-models': 'Software Models',
  'vulnerability-intelligence': 'Vulnerability Intelligence',
  technologies: 'Technologies',
  'service-catalog': 'Service Catalog',
  'cloud-resources': 'Cloud Resources',
  'imported-assets': 'Imported Assets',
  hosts: 'Hosts',
  'kubernetes-clusters': 'Kubernetes Clusters',
  'container-images': 'Container Images',
  'secured-image-catalog': 'Secured Image Catalog',
  'container-registries': 'Container Registries',
  datastores: 'Datastores',
  subscriptions: 'Subscriptions',
  iam: 'IAM',
  'hosted-technologies': 'Hosted Technologies',
  sbom: 'SBOM',
  'api-endpoints': 'API Endpoints',
  'application-endpoints': 'Application Endpoints',
  'code-repositories': 'Code Repositories',
  'source-mappings': 'Source Mappings',
  developers: 'Developers'
};

function defaultAssetTypeForView(view: InventoryViewKey): AssetTypeFilter {
  if (view === 'container-images' || view === 'secured-image-catalog' || view === 'container-registries') {
    return 'CONTAINER_IMAGE';
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
  if (view === 'hosted-technologies' || view === 'code-repositories' || view === 'source-mappings' || view === 'developers') {
    return 'APPLICATION';
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
  if (normalized === 'upload') return 'File Upload';
  if (normalized === 'api') return 'API Endpoint';
  if (normalized === 'github') return 'GitHub Generated';
  return value;
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

export function InventoryPage({ selectedView }: Props) {
  const [rows, setRows] = React.useState<InventoryComponentRecord[]>([]);
  const [componentPage, setComponentPage] = React.useState(0);
  const [componentTotalItems, setComponentTotalItems] = React.useState(0);
  const [componentTotalPages, setComponentTotalPages] = React.useState(0);
  const [softwareModels, setSoftwareModels] = React.useState<SoftwareModelRecord[]>([]);
  const [softwareModelPage, setSoftwareModelPage] = React.useState(0);
  const [softwareModelTotalItems, setSoftwareModelTotalItems] = React.useState(0);
  const [softwareModelTotalPages, setSoftwareModelTotalPages] = React.useState(0);
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
  const [selectedVulnerabilityIntelId, setSelectedVulnerabilityIntelId] = React.useState<string | null>(null);
  const [selectedVulnerabilityIntelDetail, setSelectedVulnerabilityIntelDetail] = React.useState<VulnerabilityIntelDetail | null>(null);
  const [vulnerabilityIntelDetailLoading, setVulnerabilityIntelDetailLoading] = React.useState(false);
  const [assetType, setAssetType] = React.useState<AssetTypeFilter>(() => defaultAssetTypeForView(selectedView));
  const [componentStatus, setComponentStatus] = React.useState<ComponentStatusFilter>('ACTIVE');
  const [sourceSystem, setSourceSystem] = React.useState<SourceSystemFilter>('ALL');
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');
  const loadRequestIdRef = React.useRef(0);

  React.useEffect(() => {
    const timeout = window.setTimeout(() => {
      setDebouncedVulnerabilityIntelQuery(vulnerabilityIntelQuery);
    }, 300);
    return () => window.clearTimeout(timeout);
  }, [vulnerabilityIntelQuery]);

  React.useEffect(() => {
    setAssetType(defaultAssetTypeForView(selectedView));
    if (selectedView === 'software-models') {
      setSourceSystem('ALL');
      setComponentStatus('ALL');
      setSoftwareModelPage(0);
    } else if (selectedView === 'vulnerability-intelligence') {
      setSourceSystem('ALL');
      setComponentStatus('ALL');
      setVulnerabilityIntelPage(0);
      setSelectedVulnerabilityIntelId(null);
      setSelectedVulnerabilityIntelDetail(null);
    } else {
      setSourceSystem('ALL');
      setComponentStatus('ACTIVE');
      setComponentPage(0);
    }
  }, [selectedView]);

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
        values.add(canonicalVulnerabilitySource(source));
      }
    });
    vulnerabilityIntelRows.forEach((record) => {
      record.sources.forEach((source) => {
        if (source && source.trim().length > 0) {
          values.add(canonicalVulnerabilitySource(source));
        }
      });
    });
    vulnerabilityIntelSources.forEach((source) => {
      if (source && source.trim().length > 0) {
        values.add(canonicalVulnerabilitySource(source));
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

  const assetTypeOptions = React.useMemo<string[]>(() => {
    const values = new Set<string>(DEFAULT_COMPONENT_FILTERS.assetTypes);
    componentFilterValues.assetTypes.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toUpperCase());
      }
    });
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [componentFilterValues.assetTypes]);

  const componentStatusOptions = React.useMemo<string[]>(() => {
    const values = new Set<string>(DEFAULT_COMPONENT_FILTERS.componentStatuses);
    componentFilterValues.componentStatuses.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toUpperCase());
      }
    });
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [componentFilterValues.componentStatuses]);

  const sourceSystemOptions = React.useMemo<string[]>(() => {
    const values = new Set<string>(DEFAULT_COMPONENT_FILTERS.sourceSystems);
    componentFilterValues.sourceSystems.forEach((value) => {
      if (value && value.trim().length > 0) {
        values.add(value.trim().toLowerCase());
      }
    });
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [componentFilterValues.sourceSystems]);

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

  const loadInventory = React.useCallback(async () => {
    const requestId = loadRequestIdRef.current + 1;
    loadRequestIdRef.current = requestId;
    setLoading(true);
    setError('');
    try {
      if (selectedView === 'software-models') {
        const response = await api.listSoftwareModels({
          page: softwareModelPage,
          size: SOFTWARE_MODELS_PAGE_SIZE
        });
        if (requestId !== loadRequestIdRef.current) {
          return;
        }
        setSoftwareModels(response.items);
        setSoftwareModelTotalItems(response.totalItems);
        setSoftwareModelTotalPages(response.totalPages);
        setRows([]);
        setComponentTotalItems(0);
        setComponentTotalPages(0);
        setVulnerabilityIntelRows([]);
        setVulnerabilityIntelTotalItems(0);
        setVulnerabilityIntelTotalPages(0);
      } else if (selectedView === 'vulnerability-intelligence') {
        const response = await api.listVulnerabilityIntelligence({
          page: vulnerabilityIntelPage,
          size: VULNERABILITY_INTEL_PAGE_SIZE,
          query: debouncedVulnerabilityIntelQuery.trim() || undefined,
          severity: vulnerabilityIntelSeverities.length > 0 ? vulnerabilityIntelSeverities : undefined,
          source: vulnerabilityIntelSources.length > 0 ? vulnerabilityIntelSources : undefined,
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
        setSoftwareModels([]);
        setSoftwareModelTotalItems(0);
        setSoftwareModelTotalPages(0);

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
                  .map((value) => canonicalVulnerabilitySource(value))
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
        const assetTypeParam = assetType === 'APPLICATION' || assetType === 'HOST' || assetType === 'CONTAINER_IMAGE'
          ? assetType
          : undefined;
        const componentStatusParam = componentStatus === 'ACTIVE' || componentStatus === 'RETIRED'
          ? componentStatus
          : undefined;
        const [data, availableFilters] = await Promise.all([
          api.listInventoryComponents({
            assetType: assetTypeParam,
            componentStatus: componentStatusParam,
            sourceSystem: sourceSystem === 'ALL' ? undefined : sourceSystem,
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
          ))
        });
        setRows(data.items);
        setComponentTotalItems(data.totalItems);
        setComponentTotalPages(data.totalPages);
        setSoftwareModels([]);
        setSoftwareModelTotalItems(0);
        setSoftwareModelTotalPages(0);
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
    assetType,
    componentStatus,
    sourceSystem,
    selectedView,
    componentPage,
    softwareModelPage,
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

  const activeCount = selectedView === 'software-models'
    ? softwareModels.reduce((sum, model) => sum + model.activeComponents, 0)
    : rows.filter((row) => row.componentStatus === 'ACTIVE').length;
  const retiredCount = selectedView === 'software-models'
    ? Math.max(0, softwareModels.reduce((sum, model) => sum + model.totalComponents, 0) - activeCount)
    : rows.filter((row) => row.componentStatus === 'RETIRED').length;
  const assetCount = selectedView === 'software-models'
    ? softwareModels.reduce((sum, model) => sum + model.assetsRepresented, 0)
    : new Set(rows.map((row) => row.assetId)).size;

  return (
    <div className="page-grid">
      <section className={selectedView === 'vulnerability-intelligence' ? 'panel panel-vuln-intel-filters' : 'panel'}>
        <div>
          {selectedView === 'software-models' ? (
            <div className="button-row form-submit-row">
              <button className="btn btn-secondary" type="button" onClick={loadInventory} disabled={loading}>
                {loading ? 'Refreshing...' : 'Refresh Software Models'}
              </button>
            </div>
          ) : selectedView === 'vulnerability-intelligence' ? (
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
                  Application inventory is part of SBOM view. Set <span className="mono">Asset Type = Application</span>.
                </div>
              )}
              <div className="filters-grid">
                <label>Asset Type
                <select
                  value={assetType}
                  onChange={(event) => {
                    setAssetType(event.target.value as AssetTypeFilter);
                    setComponentPage(0);
                  }}
                >
                  <option value="ALL">All Asset Types</option>
                  {assetTypeOptions.map((value) => (
                    <option key={value} value={value}>
                      {formatAssetType(value as InventoryComponentRecord['assetType'])}
                    </option>
                  ))}
                </select>
              </label>
              <label>Component Status
                <select
                  value={componentStatus}
                  onChange={(event) => {
                    setComponentStatus(event.target.value as ComponentStatusFilter);
                    setComponentPage(0);
                  }}
                >
                  <option value="ALL">All Statuses</option>
                  {componentStatusOptions.map((value) => (
                    <option key={value} value={value}>
                      {value.charAt(0) + value.slice(1).toLowerCase().replace(/_/g, ' ')}
                    </option>
                  ))}
                </select>
              </label>
              <label>Source System
                <select
                  value={sourceSystem}
                  onChange={(event) => {
                    setSourceSystem(event.target.value as SourceSystemFilter);
                    setComponentPage(0);
                  }}
                >
                  <option value="ALL">All Sources</option>
                  {sourceSystemOptions.map((value) => (
                    <option key={value} value={value}>
                      {formatInventorySourceSystem(value)}
                    </option>
                  ))}
                </select>
              </label>
              <div className="button-row form-submit-row">
                <button className="btn btn-secondary" type="button" onClick={loadInventory} disabled={loading}>
                  {loading ? 'Refreshing...' : 'Refresh Inventory'}
                </button>
              </div>
              </div>
            </>
          )}
        </div>
      </section>

      {selectedView !== 'vulnerability-intelligence' && (
        <div className="stats-grid">
          <StatCard
            title={selectedView === 'software-models' ? 'Software Models' : 'Inventory Records'}
            value={selectedView === 'software-models' ? softwareModelTotalItems : componentTotalItems}
          />
          <StatCard title="Active Components" value={activeCount} />
          <StatCard title="Retired Components" value={retiredCount} />
          <StatCard
            title="Assets Represented"
            value={assetCount}
          />
        </div>
      )}

      <section className="panel">
        <div className="panel-header">
          <h3>
            {selectedView === 'software-models'
              ? 'Software Model Records'
              : selectedView === 'vulnerability-intelligence'
                ? 'Unified Vulnerability Records'
                : 'Component Inventory Records'}
          </h3>
          {selectedView !== 'vulnerability-intelligence' && (
            <span className="panel-caption">
              {selectedView === 'software-models'
                ? 'Normalized software model records used by deterministic correlation and matching'
                : 'SBOM ingestions are persisted as inventory evidence and shown by asset type'}
            </span>
          )}
        </div>

        {error && <div className="notice error">Failed to load inventory: {error}</div>}

        {selectedView === 'software-models' ? (
          loading && softwareModels.length === 0 ? (
            <div className="notice">Loading software models...</div>
          ) : softwareModels.length === 0 ? (
            <div className="empty-state">
              <p>
                No software models found yet. Ingest an SBOM from <span className="mono">Connect</span> to populate normalized model records.
              </p>
            </div>
          ) : (
            <>
              <div className="table-scroll">
                <ResizableTable storageKey="inventory-software-models-table-widths">
                  <thead>
                  <tr>
                    <th>Publisher</th>
                    <th>Product</th>
                    <th>Primary Identifier Type</th>
                    <th>Primary Identifier</th>
                    <th>Normalized Key</th>
                    <th>Total Components</th>
                    <th>Active Components</th>
                    <th>Assets Represented</th>
                    <th>Created</th>
                    <th>Updated</th>
                  </tr>
                  </thead>
                  <tbody>
                  {softwareModels.map((model) => (
                    <tr key={model.id}>
                      <td>{model.canonicalPublisher}</td>
                      <td>{model.canonicalProduct}</td>
                      <td className="mono">{model.primaryIdentifierType}</td>
                      <td className="mono">{model.primaryIdentifier}</td>
                      <td className="mono">{model.normalizedKey}</td>
                      <td>{model.totalComponents}</td>
                      <td>{model.activeComponents}</td>
                      <td>{model.assetsRepresented}</td>
                      <td>{model.createdAt ? new Date(model.createdAt).toLocaleString() : '-'}</td>
                      <td>{model.updatedAt ? new Date(model.updatedAt).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                  </tbody>
                </ResizableTable>
              </div>
              <div className="pagination-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setSoftwareModelPage((current) => Math.max(0, current - 1))}
                  disabled={softwareModelPage <= 0 || loading}
                >
                  Previous
                </button>
                <span className="panel-caption pagination-caption">
                  Page {softwareModelTotalPages === 0 ? 0 : softwareModelPage + 1} of {Math.max(softwareModelTotalPages, 1)}
                </span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setSoftwareModelPage((current) => (current + 1 < softwareModelTotalPages ? current + 1 : current))}
                  disabled={loading || softwareModelTotalPages === 0 || softwareModelPage + 1 >= softwareModelTotalPages}
                >
                  Next
                </button>
              </div>
            </>
          )
        ) : selectedView === 'vulnerability-intelligence' ? (
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
                  <th>Software Model Result</th>
                  <th>Component Status</th>
                  <th>Source</th>
                  <th>PURL</th>
                  <th>Uploaded</th>
                  <th>Last Observed</th>
                </tr>
                </thead>
                <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td>
                      <div>{row.assetName}</div>
                      <div className="panel-caption mono">{row.assetIdentifier}</div>
                    </td>
                    <td>{formatAssetType(row.assetType)}</td>
                    <td>{row.packageName}</td>
                    <td className="mono">{row.normalizedName || '-'}</td>
                    <td className="mono">{row.version}</td>
                    <td className="mono">{row.normalizedVersion || '-'}</td>
                    <td>{row.ecosystem || '-'}</td>
                    <td>{row.softwareIdentity || '-'}</td>
                    <td className="mono">{row.softwareModelResult || '-'}</td>
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
                </div>
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
