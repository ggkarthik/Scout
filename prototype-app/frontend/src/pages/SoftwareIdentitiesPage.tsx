import React from 'react';
import { api } from '../api/client';
import {
  InventoryComponentFilterValues,
  SoftwareIdentityPage,
  SoftwareIdentitySummary
} from '../types';
import { SoftwareIdentityDetailDrawer } from '../components/SoftwareIdentityDetailDrawer';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import { readQueryParam, replaceBrowserQueryParams } from '../utils/queryState';

const PAGE_SIZE = 25;
const SOFTWARE_IDENTITY_QUERY_KEY = 'softwareIdentityId';

const LIFECYCLE_OPTIONS = [
  { value: '', label: 'All Lifecycle States' },
  { value: 'eol', label: 'Has EOL Components' },
  { value: 'near-eol', label: 'Near EOL' },
  { value: 'unknown', label: 'Unknown Lifecycle' },
  { value: 'supported', label: 'Fully Supported' }
] as const;

const MAPPING_OPTIONS = [
  { value: '', label: 'All Mapping States' },
  { value: 'needs-review', label: 'Needs EOL Mapping' },
  { value: 'manual', label: 'Manual Overrides' },
  { value: 'automatic', label: 'Automatic Mappings' },
  { value: 'mapped', label: 'Any Mapped Identity' }
] as const;

type MappingNotice = {
  identityId: string;
  kind: 'error' | 'success';
  message: string;
};

function readSelectedSoftwareIdentityId(): string | null {
  return readQueryParam(SOFTWARE_IDENTITY_QUERY_KEY);
}

function updateSelectedSoftwareIdentityId(softwareIdentityId: string | null): void {
  replaceBrowserQueryParams({ [SOFTWARE_IDENTITY_QUERY_KEY]: softwareIdentityId });
}

function formatLabel(value: string): string {
  return value
    .trim()
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatSourceSystem(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'api') return 'API Endpoint';
  if (normalized === 'github') return 'GitHub';
  if (normalized === 'servicenow') return 'ServiceNow';
  return formatLabel(value);
}

function formatAssetType(value: string): string {
  if (value === 'CONTAINER_IMAGE') return 'Container Image';
  if (value === 'APPLICATION') return 'Application';
  if (value === 'HOST') return 'Host';
  return formatLabel(value);
}

function formatInstant(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function lifecycleTone(summary: SoftwareIdentitySummary): { label: string; className: string } {
  if (summary.eolComponentCount > 0) {
    return {
      label: `${summary.eolComponentCount} EOL`,
      className: 'eol-badge eol-badge-eol'
    };
  }
  if (summary.nearEolComponentCount > 0) {
    return {
      label: `${summary.nearEolComponentCount} near EOL`,
      className: 'eol-badge eol-badge-warn'
    };
  }
  if (summary.unknownEolComponentCount > 0) {
    return {
      label: `${summary.unknownEolComponentCount} unknown`,
      className: 'eol-badge eol-badge-unknown'
    };
  }
  return {
    label: 'Supported',
    className: 'eol-badge eol-badge-ok'
  };
}

function joinValues(values: string[], formatter: (value: string) => string = formatLabel): string {
  if (values.length === 0) {
    return '-';
  }
  return values.map(formatter).join(', ');
}

function mappingStateLabel(identity: SoftwareIdentitySummary): string {
  if (identity.needsEolMapping) {
    return 'Needs EOL mapping';
  }
  if (identity.mappingConfirmed) {
    return 'Manual override';
  }
  if (identity.eolSlug) {
    return 'Mapped automatically';
  }
  return 'No mapping';
}

export function SoftwareIdentitiesPage() {
  const [pageData, setPageData] = React.useState<SoftwareIdentityPage | null>(null);
  const [filterValues, setFilterValues] = React.useState<InventoryComponentFilterValues | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [query, setQuery] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [assetType, setAssetType] = React.useState('');
  const [sourceSystem, setSourceSystem] = React.useState('');
  const [ecosystem, setEcosystem] = React.useState('');
  const [lifecycle, setLifecycle] = React.useState('');
  const [mappingState, setMappingState] = React.useState('');
  const [selectedIdentityId, setSelectedIdentityId] = React.useState<string | null>(() => readSelectedSoftwareIdentityId());
  const [detailRefreshNonce, setDetailRefreshNonce] = React.useState(0);
  const [refreshNonce, setRefreshNonce] = React.useState(0);
  const [expandedMappingId, setExpandedMappingId] = React.useState<string | null>(null);
  const [mappingDrafts, setMappingDrafts] = React.useState<Record<string, string>>({});
  const [mappingBusyId, setMappingBusyId] = React.useState<string | null>(null);
  const [mappingNotice, setMappingNotice] = React.useState<MappingNotice | null>(null);
  const debouncedQuery = useDebouncedValue(query);

  React.useEffect(() => {
    const handlePopState = (): void => {
      setSelectedIdentityId(readSelectedSoftwareIdentityId());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  React.useEffect(() => {
    api.listInventoryComponentFilters()
      .then((response) => setFilterValues(response))
      .catch(() => {});
  }, []);

  React.useEffect(() => {
    setPage(0);
  }, [debouncedQuery, assetType, sourceSystem, ecosystem, lifecycle, mappingState]);

  React.useEffect(() => {
    updateSelectedSoftwareIdentityId(selectedIdentityId);
  }, [selectedIdentityId]);

  React.useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api.listSoftwareIdentities({
      assetType: assetType ? [assetType as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'] : undefined,
      sourceSystem: sourceSystem ? [sourceSystem] : undefined,
      ecosystem: ecosystem ? [ecosystem] : undefined,
      lifecycle: lifecycle ? lifecycle as 'eol' | 'near-eol' | 'unknown' | 'supported' : undefined,
      mappingState: mappingState ? mappingState as 'needs-review' | 'mapped' | 'manual' | 'automatic' : undefined,
      query: debouncedQuery || undefined,
      page,
      size: PAGE_SIZE
    })
      .then((response) => {
        if (active) {
          setPageData(response);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (active) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [assetType, debouncedQuery, ecosystem, lifecycle, mappingState, page, refreshNonce, sourceSystem]);

  function clearFilters() {
    setQuery('');
    setAssetType('');
    setSourceSystem('');
    setEcosystem('');
    setLifecycle('');
    setMappingState('');
    setPage(0);
  }

  function openMappingEditor(identity: SoftwareIdentitySummary) {
    setExpandedMappingId(identity.id);
    setMappingDrafts((current) => ({
      ...current,
      [identity.id]: current[identity.id] ?? identity.eolSlug ?? ''
    }));
    setMappingNotice(null);
  }

  function closeMappingEditor() {
    setExpandedMappingId(null);
    setMappingNotice(null);
  }

  function updateMappingDraft(identityId: string, value: string) {
    setMappingDrafts((current) => ({
      ...current,
      [identityId]: value
    }));
  }

  async function confirmMapping(identity: SoftwareIdentitySummary) {
    const draft = (mappingDrafts[identity.id] ?? '').trim();
    if (!draft) {
      setMappingNotice({
        identityId: identity.id,
        kind: 'error',
        message: 'Enter an endoflife.date slug before confirming.'
      });
      return;
    }
    setMappingBusyId(identity.id);
    setMappingNotice(null);
    try {
      await api.confirmEolMapping(identity.normalizedKey, draft);
      setExpandedMappingId(null);
      setMappingNotice({
        identityId: identity.id,
        kind: 'success',
        message: `Mapped ${identity.displayName} to ${draft}.`
      });
      setRefreshNonce((current) => current + 1);
      setDetailRefreshNonce((current) => current + 1);
    } catch (e) {
      setMappingNotice({
        identityId: identity.id,
        kind: 'error',
        message: e instanceof Error ? e.message : String(e)
      });
    } finally {
      setMappingBusyId(null);
    }
  }

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>Software Identities</h3>
          </div>
        </div>

        <div className="toolbar software-identity-toolbar">
          <label className="software-identity-filter software-identity-filter--search">
            <span className="panel-caption">Search identities</span>
            <input
              type="text"
              className="filter-input"
              placeholder="display name, canonical key, vendor, product, normalized key, purl, or cpe"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Asset Type</span>
            <select className="filter-input" value={assetType} onChange={(event) => setAssetType(event.target.value)}>
              <option value="">All</option>
              {(filterValues?.assetTypes ?? []).map((value) => (
                <option key={value} value={value}>{formatAssetType(value)}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Source</span>
            <select className="filter-input" value={sourceSystem} onChange={(event) => setSourceSystem(event.target.value)}>
              <option value="">All</option>
              {(filterValues?.sourceSystems ?? []).map((value) => (
                <option key={value} value={value}>{formatSourceSystem(value)}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Ecosystem</span>
            <select className="filter-input" value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}>
              <option value="">All</option>
              {(filterValues?.ecosystems ?? []).map((value) => (
                <option key={value} value={value}>{formatLabel(value)}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Lifecycle</span>
            <select className="filter-input" value={lifecycle} onChange={(event) => setLifecycle(event.target.value)}>
              {LIFECYCLE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>

          <label className="software-identity-filter">
            <span className="panel-caption">Mapping</span>
            <select className="filter-input" value={mappingState} onChange={(event) => setMappingState(event.target.value)}>
              {MAPPING_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>

          <div className="button-row software-identity-actions">
            <button type="button" className="btn btn-secondary" onClick={clearFilters}>
              Clear Filters
            </button>
            <span className="panel-caption">
              {pageData ? `${pageData.totalElements.toLocaleString()} identities` : 'Loading identities...'}
            </span>
          </div>
        </div>

        {error && <div className="notice error">Unable to load software identities: {error}</div>}
        {loading ? (
          <div className="notice">Loading software identities...</div>
        ) : (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Software Identity</th>
                    <th>Vendor / Product</th>
                    <th>Footprint</th>
                    <th>Sources</th>
                    <th>Lifecycle</th>
                    <th>Open Exposure</th>
                    <th>Last Observed</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {!pageData || pageData.content.length === 0 ? (
                    <tr>
                      <td colSpan={8} style={{ textAlign: 'center', padding: '32px 0' }}>
                        <span className="panel-caption">
                          No software identities matched the current filters.
                        </span>
                      </td>
                    </tr>
                  ) : pageData.content.map((identity) => {
                    const lifecycleToneValue = lifecycleTone(identity);
                    const showMappingEditor = expandedMappingId === identity.id;
                    const canConfirmMapping = identity.needsEolMapping && identity.normalizedKey !== '::';
                    return (
                      <tr key={identity.id}>
                        <td>
                          <div>{identity.displayName}</div>
                          <div className="panel-caption mono">{identity.canonicalKey}</div>
                          <div className="panel-caption mono">{identity.normalizedKey}</div>
                        </td>
                        <td>
                          <div>{identity.vendor || '-'}</div>
                          <div className="panel-caption">{identity.product || '-'}</div>
                        </td>
                        <td>
                          <div>{identity.assetCount} assets</div>
                          <div className="panel-caption">{identity.componentCount} components · {identity.versionCount} versions</div>
                        </td>
                        <td>
                          <div className="software-identity-row-stack">
                            <span>{joinValues(identity.assetTypes, formatAssetType)}</span>
                            <span className="panel-caption">{joinValues(identity.ecosystems)}</span>
                            <span className="panel-caption">{joinValues(identity.sourceSystems, formatSourceSystem)}</span>
                          </div>
                        </td>
                        <td>
                          <div className="software-identity-row-stack">
                            <span className={lifecycleToneValue.className}>{lifecycleToneValue.label}</span>
                            <span className="panel-caption mono">{identity.eolSlug || 'No mapped slug'}</span>
                            <span className="panel-caption">{mappingStateLabel(identity)}</span>
                          </div>
                        </td>
                        <td>
                          <div>{identity.openVulnerabilityCount} open CVEs</div>
                          <div className="panel-caption">{identity.openFindingCount} open findings</div>
                        </td>
                        <td>{formatInstant(identity.lastObservedAt)}</td>
                        <td>
                          <div className="software-identity-row-stack">
                            <button
                              type="button"
                              className="btn btn-secondary"
                              onClick={() => setSelectedIdentityId(identity.id)}
                            >
                              View Detail
                            </button>

                            {identity.needsEolMapping ? (
                              canConfirmMapping ? (
                                showMappingEditor ? (
                                  <div className="software-identity-mapping-editor">
                                    <div className="panel-caption mono">{identity.normalizedKey}</div>
                                    <input
                                      type="text"
                                      className="filter-input software-identity-mapping-input"
                                      placeholder="endoflife.date slug"
                                      value={mappingDrafts[identity.id] ?? ''}
                                      onChange={(event) => updateMappingDraft(identity.id, event.target.value)}
                                    />
                                    <div className="button-row">
                                      <button
                                        type="button"
                                        className="btn btn-secondary"
                                        disabled={mappingBusyId === identity.id}
                                        onClick={() => confirmMapping(identity)}
                                      >
                                        {mappingBusyId === identity.id ? 'Confirming...' : 'Confirm Mapping'}
                                      </button>
                                      <button
                                        type="button"
                                        className="btn btn-ghost"
                                        disabled={mappingBusyId === identity.id}
                                        onClick={closeMappingEditor}
                                      >
                                        Cancel
                                      </button>
                                    </div>
                                  </div>
                                ) : (
                                  <button
                                    type="button"
                                    className="btn btn-ghost"
                                    onClick={() => openMappingEditor(identity)}
                                  >
                                    Map EOL
                                  </button>
                                )
                              ) : (
                                <span className="panel-caption">Needs normalized vendor/product first</span>
                              )
                            ) : (
                              <span className="panel-caption">
                                {identity.mappingConfirmed ? 'Manual mapping confirmed' : 'No action needed'}
                              </span>
                            )}

                            {mappingNotice?.identityId === identity.id && (
                              <span className={mappingNotice.kind === 'error'
                                ? 'panel-caption software-identity-mapping-error'
                                : 'panel-caption software-identity-mapping-success'}
                              >
                                {mappingNotice.message}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {pageData && pageData.totalPages > 1 && (
              <div className="pagination-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={page === 0}
                  onClick={() => setPage((current) => current - 1)}
                >
                  Previous
                </button>
                <span className="panel-caption">
                  Page {pageData.number + 1} of {pageData.totalPages}
                </span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={page >= pageData.totalPages - 1}
                  onClick={() => setPage((current) => current + 1)}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </section>

      {selectedIdentityId && (
        <SoftwareIdentityDetailDrawer
          softwareIdentityId={selectedIdentityId}
          refreshNonce={detailRefreshNonce}
          onClose={() => setSelectedIdentityId(null)}
        />
      )}
    </div>
  );
}
