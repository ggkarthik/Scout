import React from 'react';
import { useSearchParams } from 'react-router-dom';
import type { InventoryComponentRecord } from '../features/inventory/api-types';
import { FilterValueOption } from '../components/FilterValueSelectCard';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import {
  useInventoryData,
  useVulnerabilityIntelDetail
} from '../features/inventory/useInventoryData';
import {
  DEFAULT_COMPONENT_FILTERS,
  DEFAULT_VULNERABILITY_INTEL_FILTERS,
  INVENTORY_FILTER_FIELDS
} from '../features/inventory/config';
import {
  defaultAssetTypeForView,
  expandVulnerabilitySourceFilters,
  formatAssetType,
  formatHostReviewLabel,
  formatInventoryLabel,
  formatInventorySourceSystem,
  formatSourceSystem,
  vulnerabilitySourceFilterValue
} from '../features/inventory/helpers';
import { InventoryFiltersPanel } from '../features/inventory/InventoryFiltersPanel';
import { HostInventoryDetailModal } from '../features/inventory/HostInventoryDetailModal';
import { InventoryResultsPanel } from '../features/inventory/InventoryResultsPanel';
import { InventorySummaryStats } from '../features/inventory/InventorySummaryStats';
import { VulnerabilityIntelDetailModal } from '../features/inventory/VulnerabilityIntelDetailModal';
import {
  clearHostInventorySearchState,
  readHostAssetIdFromSearch,
  readHostReviewCategoriesFromSearch,
  writeHostAssetIdToSearch,
  writeHostReviewCategoriesToSearch
} from '../features/inventory/searchState';
import {
  HOST_REVIEW_CATEGORIES,
  HostReviewCategory,
  InventoryComponentFilterKey,
  InventoryViewKey,
  VulnerabilityIntelFilterKey
} from '../features/inventory/types';

type Props = {
  selectedView: InventoryViewKey;
};

export function InventoryPage({ selectedView }: Props) {
  const [searchParams, setSearchParams] = useSearchParams();
  const scopedAssetType = defaultAssetTypeForView(selectedView);
  const selectedHostAssetId = React.useMemo(
    () => (selectedView === 'hosts' ? readHostAssetIdFromSearch(searchParams) : null),
    [searchParams, selectedView]
  );
  const componentReviewCategories = React.useMemo<HostReviewCategory[]>(
    () => (selectedView === 'hosts' ? readHostReviewCategoriesFromSearch(searchParams) : []),
    [searchParams, selectedView]
  );
  const [componentPage, setComponentPage] = React.useState(0);
  const [componentQuery, setComponentQuery] = React.useState('');
  const [componentAssetTypes, setComponentAssetTypes] = React.useState<string[]>([]);
  const [componentStatuses, setComponentStatuses] = React.useState<string[]>([]);
  const [componentSourceSystems, setComponentSourceSystems] = React.useState<string[]>([]);
  const [componentEcosystems, setComponentEcosystems] = React.useState<string[]>([]);
  const [componentActiveFilters, setComponentActiveFilters] = React.useState<InventoryComponentFilterKey[]>(() => (
    selectedView === 'hosts' && readHostReviewCategoriesFromSearch(searchParams).length > 0 ? ['reviewCategory'] : []
  ));
  const [vulnerabilityIntelPage, setVulnerabilityIntelPage] = React.useState(0);
  const [vulnerabilityIntelQuery, setVulnerabilityIntelQuery] = React.useState('');
  const [vulnerabilityIntelAffectedPackageQuery, setVulnerabilityIntelAffectedPackageQuery] = React.useState('');
  const [vulnerabilityIntelSeverities, setVulnerabilityIntelSeverities] = React.useState<string[]>([]);
  const [vulnerabilityIntelSources, setVulnerabilityIntelSources] = React.useState<string[]>([]);
  const [vulnerabilityIntelStatuses, setVulnerabilityIntelStatuses] = React.useState<string[]>([]);
  const [vulnerabilityIntelInKevValues, setVulnerabilityIntelInKevValues] = React.useState<string[]>([]);
  const [vulnerabilityIntelActiveFilters, setVulnerabilityIntelActiveFilters] = React.useState<VulnerabilityIntelFilterKey[]>([]);
  const [selectedVulnerabilityIntelId, setSelectedVulnerabilityIntelId] = React.useState<string | null>(null);
  const previousSelectedViewRef = React.useRef(selectedView);
  const debouncedComponentQuery = useDebouncedValue(componentQuery);
  const debouncedVulnerabilityIntelQuery = useDebouncedValue(vulnerabilityIntelQuery);
  const debouncedVulnerabilityIntelAffectedPackageQuery = useDebouncedValue(vulnerabilityIntelAffectedPackageQuery);

  React.useEffect(() => {
    if (previousSelectedViewRef.current === selectedView) {
      return;
    }
    previousSelectedViewRef.current = selectedView;
    if (selectedView === 'vulnerability-intelligence') {
      setVulnerabilityIntelPage(0);
      setSelectedVulnerabilityIntelId(null);
    } else {
      setComponentPage(0);
      setComponentQuery('');
      setComponentAssetTypes([]);
      setComponentStatuses([]);
      setComponentSourceSystems([]);
      setComponentEcosystems([]);
      setComponentActiveFilters(componentReviewCategories.length > 0 ? ['reviewCategory'] : []);
    }
  }, [componentReviewCategories.length, selectedView]);

  React.useEffect(() => {
    if (selectedView !== 'hosts') {
      return;
    }
    setComponentActiveFilters((current) => {
      const hasReviewCategory = current.includes('reviewCategory');
      if (componentReviewCategories.length === 0 && !hasReviewCategory) {
        return current;
      }
      if (componentReviewCategories.length > 0 && hasReviewCategory) {
        return current;
      }
      const withoutReviewCategory = current.filter((item) => item !== 'reviewCategory');
      if (componentReviewCategories.length === 0) {
        return withoutReviewCategory;
      }
      return [...withoutReviewCategory, 'reviewCategory'];
    });
  }, [componentReviewCategories.length, selectedView]);

  React.useEffect(() => {
    if (selectedView === 'hosts') {
      return;
    }
    const nextSearchParams = clearHostInventorySearchState(searchParams);
    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [searchParams, selectedView, setSearchParams]);

  const vulnerabilityIntelInKevFilter = React.useMemo<boolean | undefined>(() => {
    const hasTrue = vulnerabilityIntelInKevValues.includes('true');
    const hasFalse = vulnerabilityIntelInKevValues.includes('false');
    if (hasTrue && !hasFalse) return true;
    if (!hasTrue && hasFalse) return false;
    return undefined;
  }, [vulnerabilityIntelInKevValues]);

  const {
    rows,
    componentTotalItems,
    componentTotalPages,
    componentFilterValues,
    vulnerabilityIntelRows,
    vulnerabilityIntelTotalPages,
    vulnerabilityIntelFilterValues,
    loading,
    error,
    refreshInventory
  } = useInventoryData({
    selectedView,
    scopedAssetType,
    componentActiveFilters,
    componentAssetTypes,
    componentStatuses,
    componentSourceSystems,
    componentEcosystems,
    componentReviewCategories,
    componentPage,
    debouncedComponentQuery,
    vulnerabilityIntelPage,
    debouncedVulnerabilityIntelQuery: vulnerabilityIntelActiveFilters.includes('query') ? debouncedVulnerabilityIntelQuery : '',
    debouncedVulnerabilityIntelAffectedPackageQuery: vulnerabilityIntelActiveFilters.includes('affectedPackage')
      ? debouncedVulnerabilityIntelAffectedPackageQuery
      : '',
    vulnerabilityIntelSeverities,
    vulnerabilityIntelSources,
    vulnerabilityIntelStatuses,
    vulnerabilityIntelInKevFilter,
    normalizeVulnerabilitySource: vulnerabilitySourceFilterValue,
    expandVulnerabilitySourceFilters
  });

  const {
    selectedVulnerabilityIntelDetail,
    vulnerabilityIntelDetailLoading
  } = useVulnerabilityIntelDetail({
    selectedView,
    selectedVulnerabilityIntelId
  });

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

  const inventoryFilterFields = React.useMemo(() => (
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
    } else if (key === 'affectedPackage') {
      setVulnerabilityIntelAffectedPackageQuery('');
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
    setVulnerabilityIntelAffectedPackageQuery('');
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
      const nextSearchParams = writeHostReviewCategoriesToSearch(searchParams, []);
      if (nextSearchParams.toString() !== searchParams.toString()) {
        setSearchParams(nextSearchParams, { replace: true });
      }
    } else if (key === 'query') {
      setComponentQuery('');
    }
    setComponentPage(0);
  }, [searchParams, setSearchParams]);

  const clearComponentFilters = React.useCallback(() => {
    setComponentQuery('');
    setComponentAssetTypes([]);
    setComponentStatuses([]);
    setComponentSourceSystems([]);
    setComponentEcosystems([]);
    if (selectedView === 'hosts') {
      const nextSearchParams = writeHostReviewCategoriesToSearch(searchParams, []);
      if (nextSearchParams.toString() !== searchParams.toString()) {
        setSearchParams(nextSearchParams, { replace: true });
      }
    }
    setComponentPage(0);
    setComponentActiveFilters([]);
  }, [searchParams, selectedView, setSearchParams]);

  const closeVulnerabilityIntelDetail = React.useCallback((): void => {
    setSelectedVulnerabilityIntelId(null);
  }, []);

  const openHostDetail = React.useCallback((assetId: string): void => {
    if (selectedView !== 'hosts') {
      return;
    }
    const nextSearchParams = writeHostAssetIdToSearch(searchParams, assetId);
    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [searchParams, selectedView, setSearchParams]);

  const closeHostDetail = React.useCallback((): void => {
    if (selectedView !== 'hosts') {
      return;
    }
    const nextSearchParams = writeHostAssetIdToSearch(searchParams, null);
    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [searchParams, selectedView, setSearchParams]);

  const openVulnerabilityIntelDetail = (externalId: string): void => {
    setSelectedVulnerabilityIntelId(externalId);
  };

  const activeCount = rows.filter((row) => row.componentStatus === 'ACTIVE').length;
  const retiredCount = rows.filter((row) => row.componentStatus === 'RETIRED').length;
  const assetCount = new Set(rows.map((row) => row.assetId)).size;
  const needsReviewCount = rows.filter((row) => row.needsReview).length;
  const setHostReviewCategories = React.useCallback((categories: HostReviewCategory[]) => {
    if (selectedView !== 'hosts') {
      return;
    }
    const nextSearchParams = writeHostReviewCategoriesToSearch(searchParams, categories);
    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [searchParams, selectedView, setSearchParams]);

  return (
    <div className="page-grid">
      <InventoryFiltersPanel
        selectedView={selectedView}
        scopedAssetType={scopedAssetType}
        inventoryFilterFields={inventoryFilterFields}
        loading={loading}
        refreshInventory={() => void refreshInventory()}
        vulnerabilityIntelFilters={{
          activeFilters: vulnerabilityIntelActiveFilters,
          severities: vulnerabilityIntelSeverities,
          sources: vulnerabilityIntelSources,
          statuses: vulnerabilityIntelStatuses,
          inKevValues: vulnerabilityIntelInKevValues,
          affectedPackageQuery: vulnerabilityIntelAffectedPackageQuery,
          query: vulnerabilityIntelQuery,
          severityOptions,
          sourceOptions,
          statusOptions: vulnStatusOptions,
          kevOptions,
          addFilter: addVulnerabilityIntelFilter,
          removeFilter: removeVulnerabilityIntelFilter,
          clearFilters: clearVulnerabilityIntelFilters,
          setSeverities: setVulnerabilityIntelSeverities,
          setSources: setVulnerabilityIntelSources,
          setStatuses: setVulnerabilityIntelStatuses,
          setInKevValues: setVulnerabilityIntelInKevValues,
          setAffectedPackageQuery: setVulnerabilityIntelAffectedPackageQuery,
          setQuery: setVulnerabilityIntelQuery,
          setPage: setVulnerabilityIntelPage
        }}
        componentFilters={{
          activeFilters: componentActiveFilters,
          assetTypes: componentAssetTypes,
          statuses: componentStatuses,
          sourceSystems: componentSourceSystems,
          ecosystems: componentEcosystems,
          reviewCategories: componentReviewCategories,
          query: componentQuery,
          assetTypeOptions,
          componentStatusOptions,
          sourceSystemOptions,
          ecosystemOptions,
          hostReviewOptions,
          addFilter: addComponentFilter,
          removeFilter: removeComponentFilter,
          clearFilters: clearComponentFilters,
          setAssetTypes: setComponentAssetTypes,
          setStatuses: setComponentStatuses,
          setSourceSystems: setComponentSourceSystems,
          setEcosystems: setComponentEcosystems,
          setReviewCategories: setHostReviewCategories,
          setQuery: setComponentQuery,
          setPage: setComponentPage
        }}
      />

      <InventorySummaryStats
        selectedView={selectedView}
        componentTotalItems={componentTotalItems}
        activeCount={activeCount}
        retiredCount={retiredCount}
        assetCount={assetCount}
        needsReviewCount={needsReviewCount}
      />

      <InventoryResultsPanel
        selectedView={selectedView}
        error={error}
        loading={loading}
        rows={rows}
        componentPage={componentPage}
        componentTotalPages={componentTotalPages}
        selectedHostAssetId={selectedHostAssetId}
        onOpenHostDetail={openHostDetail}
        onPreviousComponentPage={() => setComponentPage((current) => Math.max(0, current - 1))}
        onNextComponentPage={() => setComponentPage((current) => (current + 1 < componentTotalPages ? current + 1 : current))}
        vulnerabilityIntelRows={vulnerabilityIntelRows}
        vulnerabilityIntelPage={vulnerabilityIntelPage}
        vulnerabilityIntelTotalPages={vulnerabilityIntelTotalPages}
        selectedVulnerabilityIntelId={selectedVulnerabilityIntelId}
        onOpenVulnerabilityIntelDetail={openVulnerabilityIntelDetail}
        onPreviousVulnerabilityIntelPage={() => setVulnerabilityIntelPage((current) => Math.max(0, current - 1))}
        onNextVulnerabilityIntelPage={() => setVulnerabilityIntelPage((current) => (
          current + 1 < vulnerabilityIntelTotalPages ? current + 1 : current
        ))}
      />

      <HostInventoryDetailModal
        assetId={selectedView === 'hosts' ? selectedHostAssetId : null}
        onClose={closeHostDetail}
      />

      <VulnerabilityIntelDetailModal
        externalId={selectedView === 'vulnerability-intelligence' ? selectedVulnerabilityIntelId : null}
        detail={selectedVulnerabilityIntelDetail}
        loading={vulnerabilityIntelDetailLoading}
        onClose={closeVulnerabilityIntelDetail}
      />
    </div>
  );
}
