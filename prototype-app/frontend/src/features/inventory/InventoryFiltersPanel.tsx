import React from 'react';
import { FilterBuilder, FilterBuilderField } from '../../components/FilterBuilder';
import { FilterValueOption, FilterValueSelectCard } from '../../components/FilterValueSelectCard';
import {
  INVENTORY_FILTER_CATEGORIES,
  VULNERABILITY_INTEL_FILTER_CATEGORIES,
  VULNERABILITY_INTEL_FILTER_FIELDS
} from './config';
import { formatHostReviewLabel, normalizeHostReviewCategory } from './helpers';
import type {
  HostReviewCategory,
  InventoryComponentFilterKey,
  InventoryScopedAssetType,
  InventoryViewKey,
  VulnerabilityIntelFilterKey
} from './types';

type ComponentFilterState = {
  activeFilters: InventoryComponentFilterKey[];
  assetTypes: string[];
  statuses: string[];
  sourceSystems: string[];
  ecosystems: string[];
  reviewCategories: HostReviewCategory[];
  query: string;
  assetTypeOptions: FilterValueOption[];
  componentStatusOptions: FilterValueOption[];
  sourceSystemOptions: FilterValueOption[];
  ecosystemOptions: FilterValueOption[];
  hostReviewOptions: FilterValueOption[];
  addFilter: (key: InventoryComponentFilterKey) => void;
  removeFilter: (key: InventoryComponentFilterKey) => void;
  clearFilters: () => void;
  setAssetTypes: (values: string[]) => void;
  setStatuses: (values: string[]) => void;
  setSourceSystems: (values: string[]) => void;
  setEcosystems: (values: string[]) => void;
  setReviewCategories: (values: HostReviewCategory[]) => void;
  setQuery: (value: string) => void;
  setPage: (page: number) => void;
};

type VulnerabilityIntelFilterState = {
  activeFilters: VulnerabilityIntelFilterKey[];
  severities: string[];
  sources: string[];
  statuses: string[];
  inKevValues: string[];
  affectedPackageQuery: string;
  query: string;
  severityOptions: FilterValueOption[];
  sourceOptions: FilterValueOption[];
  statusOptions: FilterValueOption[];
  kevOptions: FilterValueOption[];
  addFilter: (key: VulnerabilityIntelFilterKey) => void;
  removeFilter: (key: VulnerabilityIntelFilterKey) => void;
  clearFilters: () => void;
  setSeverities: (values: string[]) => void;
  setSources: (values: string[]) => void;
  setStatuses: (values: string[]) => void;
  setInKevValues: (values: string[]) => void;
  setAffectedPackageQuery: (value: string) => void;
  setQuery: (value: string) => void;
  setPage: (page: number) => void;
};

type Props = {
  selectedView: InventoryViewKey;
  scopedAssetType: InventoryScopedAssetType;
  inventoryFilterFields: FilterBuilderField[];
  loading: boolean;
  refreshInventory: () => void;
  componentFilters: ComponentFilterState;
  vulnerabilityIntelFilters: VulnerabilityIntelFilterState;
};

function componentFilterChipLabel(
  key: InventoryComponentFilterKey,
  filters: ComponentFilterState
): string {
  if (key === 'assetType') {
    return `Asset Type${filters.assetTypes.length > 0 ? ` (${filters.assetTypes.length})` : ''}`;
  }
  if (key === 'componentStatus') {
    return `Component Status${filters.statuses.length > 0 ? ` (${filters.statuses.length})` : ''}`;
  }
  if (key === 'sourceSystem') {
    return `Source System${filters.sourceSystems.length > 0 ? ` (${filters.sourceSystems.length})` : ''}`;
  }
  if (key === 'ecosystem') {
    return `Ecosystem${filters.ecosystems.length > 0 ? ` (${filters.ecosystems.length})` : ''}`;
  }
  if (key === 'reviewCategory') {
    return `Host Review${filters.reviewCategories.length > 0 ? ` (${filters.reviewCategories.length})` : ''}`;
  }
  return `Inventory Search${filters.query.trim() ? ' (1)' : ''}`;
}

function vulnerabilityFilterChipLabel(
  key: VulnerabilityIntelFilterKey,
  filters: VulnerabilityIntelFilterState
): string {
  if (key === 'severity') {
    return `Severity${filters.severities.length > 0 ? ` (${filters.severities.length})` : ''}`;
  }
  if (key === 'source') {
    return `Source${filters.sources.length > 0 ? ` (${filters.sources.length})` : ''}`;
  }
  if (key === 'vulnStatus') {
    return `Vulnerability Status${filters.statuses.length > 0 ? ` (${filters.statuses.length})` : ''}`;
  }
  if (key === 'inKev') {
    return `KEV${filters.inKevValues.length > 0 ? ` (${filters.inKevValues.length})` : ''}`;
  }
  if (key === 'affectedPackage') {
    return `Affected Package${filters.affectedPackageQuery.trim() ? ' (1)' : ''}`;
  }
  return `Vulnerability Search${filters.query.trim() ? ' (1)' : ''}`;
}

export function InventoryFiltersPanel({
  selectedView,
  scopedAssetType,
  inventoryFilterFields,
  loading,
  refreshInventory,
  componentFilters,
  vulnerabilityIntelFilters
}: Props) {
  return (
    <section className={selectedView === 'vulnerability-intelligence' ? 'panel panel-vuln-intel-filters' : 'panel'}>
      <div>
        {selectedView === 'vulnerability-intelligence' ? (
          <div className="findings-filter-shell">
            <div className="findings-filter-builder-row">
              <FilterBuilder
                categories={VULNERABILITY_INTEL_FILTER_CATEGORIES}
                fields={VULNERABILITY_INTEL_FILTER_FIELDS}
                activeKeys={vulnerabilityIntelFilters.activeFilters}
                onAddFilter={(key) => vulnerabilityIntelFilters.addFilter(key as VulnerabilityIntelFilterKey)}
              />
              <div className="findings-filter-active-chips">
                {vulnerabilityIntelFilters.activeFilters.map((key) => (
                  <button
                    key={key}
                    type="button"
                    className="findings-filter-chip-tag"
                    onClick={() => vulnerabilityIntelFilters.removeFilter(key)}
                    title="Remove filter"
                  >
                    <span>{vulnerabilityFilterChipLabel(key, vulnerabilityIntelFilters)}</span>
                    <span aria-hidden="true">x</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="findings-active-filter-grid">
              {vulnerabilityIntelFilters.activeFilters.includes('severity') && (
                <FilterValueSelectCard
                  label="Severity"
                  selectedValues={vulnerabilityIntelFilters.severities}
                  options={vulnerabilityIntelFilters.severityOptions}
                  onChange={(values) => {
                    vulnerabilityIntelFilters.setSeverities(values);
                    vulnerabilityIntelFilters.setPage(0);
                  }}
                  onRemove={() => vulnerabilityIntelFilters.removeFilter('severity')}
                />
              )}

              {vulnerabilityIntelFilters.activeFilters.includes('source') && (
                <FilterValueSelectCard
                  label="Source"
                  selectedValues={vulnerabilityIntelFilters.sources}
                  options={vulnerabilityIntelFilters.sourceOptions}
                  onChange={(values) => {
                    vulnerabilityIntelFilters.setSources(values);
                    vulnerabilityIntelFilters.setPage(0);
                  }}
                  onRemove={() => vulnerabilityIntelFilters.removeFilter('source')}
                />
              )}

              {vulnerabilityIntelFilters.activeFilters.includes('vulnStatus') && (
                <FilterValueSelectCard
                  label="Vulnerability Status"
                  selectedValues={vulnerabilityIntelFilters.statuses}
                  options={vulnerabilityIntelFilters.statusOptions}
                  onChange={(values) => {
                    vulnerabilityIntelFilters.setStatuses(values);
                    vulnerabilityIntelFilters.setPage(0);
                  }}
                  onRemove={() => vulnerabilityIntelFilters.removeFilter('vulnStatus')}
                />
              )}

              {vulnerabilityIntelFilters.activeFilters.includes('inKev') && (
                <FilterValueSelectCard
                  label="KEV"
                  selectedValues={vulnerabilityIntelFilters.inKevValues}
                  options={vulnerabilityIntelFilters.kevOptions}
                  onChange={(values) => {
                    vulnerabilityIntelFilters.setInKevValues(values);
                    vulnerabilityIntelFilters.setPage(0);
                  }}
                  onRemove={() => vulnerabilityIntelFilters.removeFilter('inKev')}
                />
              )}

              {vulnerabilityIntelFilters.activeFilters.includes('affectedPackage') && (
                <label className="findings-filter-chip findings-filter-text-card">Affected Package
                  <button
                    type="button"
                    className="findings-filter-chip-remove"
                    onClick={() => vulnerabilityIntelFilters.removeFilter('affectedPackage')}
                    aria-label="Remove Affected Package filter"
                  >
                    x
                  </button>
                  <input
                    value={vulnerabilityIntelFilters.affectedPackageQuery}
                    onChange={(event) => {
                      vulnerabilityIntelFilters.setAffectedPackageQuery(event.target.value);
                      vulnerabilityIntelFilters.setPage(0);
                    }}
                    placeholder="openssl, log4j, pkg:maven, or cpe:2.3"
                    className="mono"
                  />
                </label>
              )}

              {vulnerabilityIntelFilters.activeFilters.includes('query') && (
                <label className="findings-filter-chip findings-filter-text-card">Vulnerability Search
                  <button
                    type="button"
                    className="findings-filter-chip-remove"
                    onClick={() => vulnerabilityIntelFilters.removeFilter('query')}
                    aria-label="Remove Vulnerability Search filter"
                  >
                    x
                  </button>
                  <input
                    value={vulnerabilityIntelFilters.query}
                    onChange={(event) => {
                      vulnerabilityIntelFilters.setQuery(event.target.value);
                      vulnerabilityIntelFilters.setPage(0);
                    }}
                    placeholder="CVE-2024-12345, ADV-DEMO-001, or title"
                    className="mono"
                  />
                </label>
              )}
            </div>

            <div className="findings-filter-row vuln-intel-filter-row">
              <div className="findings-filter-actions">
                <button className="btn btn-secondary btn-inline" type="button" onClick={vulnerabilityIntelFilters.clearFilters}>
                  Clear Filters
                </button>
                <button className="btn btn-secondary btn-inline" type="button" onClick={refreshInventory} disabled={loading}>
                  {loading ? 'Refreshing...' : 'Refresh Vulnerability Intelligence'}
                </button>
              </div>
            </div>
          </div>
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
                  activeKeys={componentFilters.activeFilters}
                  onAddFilter={(key) => componentFilters.addFilter(key as InventoryComponentFilterKey)}
                />
                <div className="findings-filter-active-chips">
                  {componentFilters.activeFilters.map((key) => (
                    <button
                      key={key}
                      type="button"
                      className="findings-filter-chip-tag"
                      onClick={() => componentFilters.removeFilter(key)}
                      title="Remove filter"
                    >
                      <span>{componentFilterChipLabel(key, componentFilters)}</span>
                      <span aria-hidden="true">x</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="findings-active-filter-grid">
                {scopedAssetType === 'ALL' && componentFilters.activeFilters.includes('assetType') && (
                  <FilterValueSelectCard
                    label="Asset Type"
                    selectedValues={componentFilters.assetTypes}
                    options={componentFilters.assetTypeOptions}
                    onChange={(values) => {
                      componentFilters.setAssetTypes(values);
                      componentFilters.setPage(0);
                    }}
                    onRemove={() => componentFilters.removeFilter('assetType')}
                  />
                )}

                {componentFilters.activeFilters.includes('componentStatus') && (
                  <FilterValueSelectCard
                    label="Component Status"
                    selectedValues={componentFilters.statuses}
                    options={componentFilters.componentStatusOptions}
                    onChange={(values) => {
                      componentFilters.setStatuses(values);
                      componentFilters.setPage(0);
                    }}
                    onRemove={() => componentFilters.removeFilter('componentStatus')}
                  />
                )}

                {componentFilters.activeFilters.includes('sourceSystem') && (
                  <FilterValueSelectCard
                    label="Source System"
                    selectedValues={componentFilters.sourceSystems}
                    options={componentFilters.sourceSystemOptions}
                    onChange={(values) => {
                      componentFilters.setSourceSystems(values);
                      componentFilters.setPage(0);
                    }}
                    onRemove={() => componentFilters.removeFilter('sourceSystem')}
                  />
                )}

                {componentFilters.activeFilters.includes('ecosystem') && (
                  <FilterValueSelectCard
                    label="Ecosystem"
                    selectedValues={componentFilters.ecosystems}
                    options={componentFilters.ecosystemOptions}
                    onChange={(values) => {
                      componentFilters.setEcosystems(values);
                      componentFilters.setPage(0);
                    }}
                    onRemove={() => componentFilters.removeFilter('ecosystem')}
                  />
                )}

                {selectedView === 'hosts' && componentFilters.activeFilters.includes('reviewCategory') && (
                  <FilterValueSelectCard
                    label="Host Review"
                    selectedValues={componentFilters.reviewCategories}
                    options={componentFilters.hostReviewOptions}
                    onChange={(values) => {
                      componentFilters.setReviewCategories(values
                        .map(normalizeHostReviewCategory)
                        .filter((value): value is HostReviewCategory => value !== null));
                      componentFilters.setPage(0);
                    }}
                    onRemove={() => componentFilters.removeFilter('reviewCategory')}
                  />
                )}

                {componentFilters.activeFilters.includes('query') && (
                  <label className="findings-filter-chip findings-filter-text-card">Inventory Search
                    <button
                      type="button"
                      className="findings-filter-chip-remove"
                      onClick={() => componentFilters.removeFilter('query')}
                      aria-label="Remove Inventory Search filter"
                    >
                      x
                    </button>
                    <input
                      value={componentFilters.query}
                      onChange={(event) => {
                        componentFilters.setQuery(event.target.value);
                        componentFilters.setPage(0);
                      }}
                      placeholder="asset, package, software identity, or purl"
                      className="mono"
                    />
                  </label>
                )}
              </div>

              <div className="findings-filter-row">
                <div className="findings-filter-actions">
                  <button className="btn btn-secondary btn-inline" type="button" onClick={componentFilters.clearFilters}>
                    Clear Filters
                  </button>
                  <button className="btn btn-secondary btn-inline" type="button" onClick={refreshInventory} disabled={loading}>
                    {loading ? 'Refreshing...' : 'Refresh Inventory'}
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
