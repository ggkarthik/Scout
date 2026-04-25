import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { MultiGroupBy, type MultiGroupByOption } from '../components/MultiGroupBy';
import { FilterValueSelectCard, type FilterValueOption } from '../components/FilterValueSelectCard';
import { api } from '../api/client';
import { pathForInventoryHostAsset } from '../app/routes';
import type { Asset, HostAssetDetail } from '../features/inventory/api-types';
import { formatInventorySourceSystem } from '../features/inventory/helpers';
import {
  HOST_ENVIRONMENT_QUERY_KEY,
  HOST_OPERATING_SYSTEM_QUERY_KEY,
  HOST_QUICK_FILTER_QUERY_KEY,
  INVENTORY_SOURCE_SYSTEM_QUERY_KEY,
  readInventoryGroupByFromSearch,
  readInventoryQueryFromSearch,
  readSearchValueFromSearch,
  readSearchValuesFromSearch,
  writeInventoryGroupByToSearch,
  writeInventoryQueryToSearch,
  writeSearchValueToSearch,
  writeSearchValuesToSearch
} from '../features/inventory/searchState';
import type { InventoryViewKey } from '../features/inventory/types';

const PAGE_SIZE = 50;

type Props = {
  selectedView: InventoryViewKey;
};

type HostInventoryRecord = {
  asset: Asset;
  detail: HostAssetDetail;
  operatingSystem: string;
  deployedSoftwareCount: number;
  openFindingCount: number;
  applicableCveCount: number;
  isOnline: boolean;
};

type HostOsSummary = {
  os: string;
  hostCount: number;
  activeCount: number;
  totalApplicableCves: number;
  totalOpenFindings: number;
  totalSoftware: number;
};

type HostInventoryTab = 'all-hosts' | 'by-os';
type HostQuickFilter = 'all' | 'online' | 'with-findings' | 'linux' | 'windows';
const HOST_GROUP_BY_OPTIONS: MultiGroupByOption[] = [
  { key: 'operatingSystem', label: 'Operating System' },
  { key: 'environment', label: 'Environment' },
  { key: 'status', label: 'Status' },
  { key: 'owner', label: 'Owner' },
  { key: 'sourceSystem', label: 'Source System' }
];

const OS_MATCHERS: Array<{ label: string; test: (value: string) => boolean }> = [
  { label: 'Windows Server 2022', test: (value) => value.includes('windows server 2022') },
  { label: 'Windows Server 2019', test: (value) => value.includes('windows server 2019') },
  { label: 'Windows', test: (value) => value.includes('windows') },
  { label: 'Ubuntu 24.04', test: (value) => value.includes('ubuntu 24.04') },
  { label: 'Ubuntu 22.04', test: (value) => value.includes('ubuntu 22.04') },
  { label: 'Ubuntu 20.04', test: (value) => value.includes('ubuntu 20.04') },
  { label: 'Ubuntu', test: (value) => value.includes('ubuntu') },
  { label: 'Debian 12', test: (value) => value.includes('debian 12') },
  { label: 'Debian 11', test: (value) => value.includes('debian 11') },
  { label: 'Debian 10', test: (value) => value.includes('debian 10') },
  { label: 'Debian', test: (value) => value.includes('debian') },
  { label: 'Amazon Linux 2023', test: (value) => value.includes('amazon linux 2023') },
  { label: 'Amazon Linux 2', test: (value) => value.includes('amazon linux 2') },
  { label: 'Amazon Linux', test: (value) => value.includes('amazon linux') },
  { label: 'RHEL', test: (value) => value.includes('red hat') || value.includes('rhel') },
  { label: 'CentOS', test: (value) => value.includes('centos') },
  { label: 'Rocky Linux', test: (value) => value.includes('rocky') },
  { label: 'AlmaLinux', test: (value) => value.includes('alma') },
  { label: 'SUSE Linux', test: (value) => value.includes('suse') },
  { label: 'macOS', test: (value) => value.includes('mac os') || value.includes('macos') || value.includes('os x') },
  { label: 'Linux', test: (value) => value.includes('linux') }
];

function formatTimestamp(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatHostState(value?: string): string {
  if (!value) {
    return 'Unknown';
  }
  return value
    .toLowerCase()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function inferOperatingSystem(detail: HostAssetDetail): string {
  const candidates = detail.software.flatMap((software) => [
    software.displayName,
    software.publisher,
    software.normalizedProduct,
    software.normalizedPublisher
  ]);

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    const normalized = candidate.trim().toLowerCase();
    const match = OS_MATCHERS.find((matcher) => matcher.test(normalized));
    if (match) {
      return match.label;
    }
  }

  return 'Unknown';
}

function sameValues(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function hostEnvironment(record: HostInventoryRecord): string {
  return record.detail.host.environment ?? record.asset.environment ?? 'Unknown';
}

function hostOwner(record: HostInventoryRecord): string {
  return record.detail.host.ownerEmail ?? record.asset.ownerTeam ?? record.asset.ownerEmail ?? 'Unassigned';
}

function hostSourceSystems(record: HostInventoryRecord): string[] {
  return Array.from(new Set(
    record.detail.software
      .map((software) => software.sourceSystem?.trim())
      .filter((value): value is string => Boolean(value))
  ));
}

function hostGroupValues(record: HostInventoryRecord, key: string): string[] {
  if (key === 'operatingSystem') {
    return [record.operatingSystem];
  }
  if (key === 'environment') {
    return [hostEnvironment(record)];
  }
  if (key === 'status') {
    return [record.isOnline ? 'Online' : formatHostState(record.detail.host.state)];
  }
  if (key === 'owner') {
    return [hostOwner(record)];
  }
  if (key === 'sourceSystem') {
    const values = hostSourceSystems(record);
    return values.length > 0
      ? values.map((value) => formatInventorySourceSystem(value))
      : ['Unspecified source'];
  }
  return ['Unknown'];
}

function toInventoryRecord(asset: Asset, detail: HostAssetDetail): HostInventoryRecord {
  const openFindingCount = detail.findings.filter((finding) => (finding.status ?? '').toUpperCase() !== 'RESOLVED').length;
  const isOnline = (detail.host.state ?? asset.state ?? '').toUpperCase() === 'ACTIVE';
  return {
    asset,
    detail,
    operatingSystem: inferOperatingSystem(detail),
    deployedSoftwareCount: detail.software.length,
    openFindingCount,
    applicableCveCount: detail.applicableCves.length,
    isOnline
  };
}

function buildOsSummary(records: HostInventoryRecord[]): HostOsSummary[] {
  const grouped = new Map<string, HostOsSummary>();

  records.forEach((record) => {
    const current = grouped.get(record.operatingSystem) ?? {
      os: record.operatingSystem,
      hostCount: 0,
      activeCount: 0,
      totalApplicableCves: 0,
      totalOpenFindings: 0,
      totalSoftware: 0
    };

    current.hostCount += 1;
    current.activeCount += record.isOnline ? 1 : 0;
    current.totalApplicableCves += record.applicableCveCount;
    current.totalOpenFindings += record.openFindingCount;
    current.totalSoftware += record.deployedSoftwareCount;
    grouped.set(record.operatingSystem, current);
  });

  return Array.from(grouped.values()).sort((left, right) => {
    if (right.hostCount !== left.hostCount) {
      return right.hostCount - left.hostCount;
    }
    return left.os.localeCompare(right.os);
  });
}

function matchesQuickFilter(record: HostInventoryRecord, filter: HostQuickFilter): boolean {
  switch (filter) {
    case 'online':
      return record.isOnline;
    case 'with-findings':
      return record.openFindingCount > 0;
    case 'linux':
      return record.operatingSystem.toLowerCase().includes('linux')
        || record.operatingSystem.toLowerCase().includes('ubuntu')
        || record.operatingSystem.toLowerCase().includes('debian')
        || record.operatingSystem.toLowerCase().includes('rhel')
        || record.operatingSystem.toLowerCase().includes('centos')
        || record.operatingSystem.toLowerCase().includes('amazon linux');
    case 'windows':
      return record.operatingSystem.toLowerCase().includes('windows');
    case 'all':
    default:
      return true;
  }
}

function matchesSearch(record: HostInventoryRecord, query: string): boolean {
  if (!query) {
    return true;
  }
  const normalizedQuery = query.toLowerCase();
  const haystack = [
    record.asset.name,
    record.asset.identifier,
    record.detail.host.environment ?? record.asset.environment,
    record.asset.ownerTeam,
    record.detail.host.ownerEmail ?? record.asset.ownerEmail,
    record.detail.host.supportGroup,
    record.operatingSystem,
    ...record.detail.software.map((software) => software.displayName),
    ...record.detail.software.map((software) => software.publisher ?? ''),
    ...record.detail.software.map((software) => software.discoveryModelPrimaryKey ?? ''),
    ...record.detail.software.map((software) => software.softwareIdentity ?? '')
  ]
    .join(' ')
    .toLowerCase();

  return haystack.includes(normalizedQuery);
}

function SummaryCard({
  label,
  value,
  subtext
}: {
  label: string;
  value: string;
  subtext: string;
}) {
  return (
    <article className="inventory-summary-card">
      <span className="inventory-summary-label">{label}</span>
      <strong className="inventory-summary-value">{value}</strong>
      <span className="inventory-summary-subtext">{subtext}</span>
    </article>
  );
}

function HostRow({
  record,
  onOpen
}: {
  record: HostInventoryRecord;
  onOpen: (assetId: string) => void;
}) {
  return (
    <tr className="inventory-table-row-clickable" onClick={() => onOpen(record.asset.id)}>
      <td>
        <button
          type="button"
          className="inventory-link-button inventory-link-button-primary"
          onClick={(event) => {
            event.stopPropagation();
            onOpen(record.asset.id);
          }}
        >
          {record.asset.name}
        </button>
        <div className="panel-caption mono">{record.asset.identifier}</div>
      </td>
      <td>{record.detail.host.environment ?? record.asset.environment ?? '-'}</td>
      <td>{record.operatingSystem}</td>
      <td>
        {record.detail.host.ownerEmail ?? record.asset.ownerTeam ?? record.asset.ownerEmail ?? '-'}
      </td>
      <td>{record.detail.host.supportGroup ?? '-'}</td>
      <td>{record.deployedSoftwareCount.toLocaleString()}</td>
      <td>{record.applicableCveCount.toLocaleString()}</td>
      <td>{record.openFindingCount.toLocaleString()}</td>
      <td>
        <span className={`status-pill ${record.isOnline ? 'status-active' : 'status-inactive'}`}>
          {record.isOnline ? 'Online' : formatHostState(record.detail.host.state)}
        </span>
      </td>
      <td>{formatTimestamp(record.detail.host.lastInventoryAt ?? record.detail.host.lastCmdbSyncAt)}</td>
    </tr>
  );
}

export function InventoryPage(_: Props) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialSearchValue = React.useMemo(() => readInventoryQueryFromSearch(searchParams), [searchParams]);
  const initialQuickFilter = React.useMemo<HostQuickFilter>(() => {
    const value = readSearchValueFromSearch(searchParams, HOST_QUICK_FILTER_QUERY_KEY);
    return value === 'online' || value === 'with-findings' || value === 'linux' || value === 'windows'
      ? value
      : 'all';
  }, [searchParams]);
  const initialEnvironments = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, HOST_ENVIRONMENT_QUERY_KEY),
    [searchParams]
  );
  const initialOperatingSystems = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, HOST_OPERATING_SYSTEM_QUERY_KEY),
    [searchParams]
  );
  const initialSourceSystems = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY),
    [searchParams]
  );
  const initialGroupBy = React.useMemo(
    () => readInventoryGroupByFromSearch(searchParams),
    [searchParams]
  );
  const [activeTab, setActiveTab] = React.useState<HostInventoryTab>('all-hosts');
  const [searchValue, setSearchValue] = React.useState(initialSearchValue);
  const [quickFilter, setQuickFilter] = React.useState<HostQuickFilter>(initialQuickFilter);
  const [selectedEnvironments, setSelectedEnvironments] = React.useState<string[]>(initialEnvironments);
  const [selectedOperatingSystems, setSelectedOperatingSystems] = React.useState<string[]>(initialOperatingSystems);
  const [selectedSourceSystems, setSelectedSourceSystems] = React.useState<string[]>(initialSourceSystems);
  const [groupBy, setGroupBy] = React.useState<string[]>(initialGroupBy);
  const [page, setPage] = React.useState(0);

  const assetsQuery = useQuery({
    queryKey: ['inventory-host-assets'],
    queryFn: api.listAssets
  });

  const hostAssets = React.useMemo(
    () => (assetsQuery.data ?? []).filter((asset) => asset.type.toUpperCase() === 'HOST'),
    [assetsQuery.data]
  );

  const hostDetailsQuery = useQuery({
    queryKey: ['inventory-host-assets-detail', hostAssets.map((asset) => asset.id)],
    queryFn: async () => {
      const results = await Promise.allSettled(
        hostAssets.map(async (asset) => ({
          asset,
          detail: await api.getHostAssetDetail(asset.id)
        }))
      );
      return results
        .filter((r): r is PromiseFulfilledResult<{ asset: Asset; detail: HostAssetDetail }> => r.status === 'fulfilled')
        .map((r) => r.value);
    },
    enabled: hostAssets.length > 0
  });

  const hostRecords = React.useMemo<HostInventoryRecord[]>(() => (
    (hostDetailsQuery.data ?? []).map(({ asset, detail }) => toInventoryRecord(asset, detail))
      .sort((left, right) => left.asset.name.localeCompare(right.asset.name))
  ), [hostDetailsQuery.data]);

  const environmentOptions = React.useMemo<FilterValueOption[]>(() => (
    Array.from(new Set(hostRecords.map((record) => hostEnvironment(record))))
      .sort((left, right) => left.localeCompare(right))
      .map((value) => ({ value, label: value }))
  ), [hostRecords]);
  const operatingSystemOptions = React.useMemo<FilterValueOption[]>(() => (
    Array.from(new Set(hostRecords.map((record) => record.operatingSystem)))
      .sort((left, right) => left.localeCompare(right))
      .map((value) => ({ value, label: value }))
  ), [hostRecords]);
  const sourceSystemOptions = React.useMemo<FilterValueOption[]>(() => (
    Array.from(new Set(hostRecords.flatMap((record) => hostSourceSystems(record))))
      .sort((left, right) => left.localeCompare(right))
      .map((value) => ({
        value,
        label: formatInventorySourceSystem(value)
      }))
  ), [hostRecords]);

  React.useEffect(() => {
    const nextSearchValue = readInventoryQueryFromSearch(searchParams);
    const nextQuickFilterValue = readSearchValueFromSearch(searchParams, HOST_QUICK_FILTER_QUERY_KEY);
    const nextQuickFilter = nextQuickFilterValue === 'online'
      || nextQuickFilterValue === 'with-findings'
      || nextQuickFilterValue === 'linux'
      || nextQuickFilterValue === 'windows'
      ? nextQuickFilterValue
      : 'all';
    const nextEnvironments = readSearchValuesFromSearch(searchParams, HOST_ENVIRONMENT_QUERY_KEY);
    const nextOperatingSystems = readSearchValuesFromSearch(searchParams, HOST_OPERATING_SYSTEM_QUERY_KEY);
    const nextSourceSystems = readSearchValuesFromSearch(searchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY);
    const nextGroupBy = readInventoryGroupByFromSearch(searchParams);

    setSearchValue((current) => (current === nextSearchValue ? current : nextSearchValue));
    setQuickFilter((current) => (current === nextQuickFilter ? current : nextQuickFilter));
    setSelectedEnvironments((current) => (sameValues(current, nextEnvironments) ? current : nextEnvironments));
    setSelectedOperatingSystems((current) => (sameValues(current, nextOperatingSystems) ? current : nextOperatingSystems));
    setSelectedSourceSystems((current) => (sameValues(current, nextSourceSystems) ? current : nextSourceSystems));
    setGroupBy((current) => (sameValues(current, nextGroupBy) ? current : nextGroupBy));
  }, [searchParams]);

  React.useEffect(() => {
    let nextSearchParams = new URLSearchParams(searchParams);
    nextSearchParams = writeInventoryQueryToSearch(nextSearchParams, searchValue);
    nextSearchParams = writeSearchValueToSearch(nextSearchParams, HOST_QUICK_FILTER_QUERY_KEY, quickFilter === 'all' ? '' : quickFilter);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, HOST_ENVIRONMENT_QUERY_KEY, selectedEnvironments);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, HOST_OPERATING_SYSTEM_QUERY_KEY, selectedOperatingSystems);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY, selectedSourceSystems);
    nextSearchParams = writeInventoryGroupByToSearch(nextSearchParams, groupBy);

    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [
    groupBy,
    quickFilter,
    searchParams,
    searchValue,
    selectedEnvironments,
    selectedOperatingSystems,
    selectedSourceSystems,
    setSearchParams
  ]);

  const filteredRecords = React.useMemo(
    () => hostRecords.filter((record) => {
      if (!matchesQuickFilter(record, quickFilter) || !matchesSearch(record, searchValue.trim())) {
        return false;
      }
      if (selectedEnvironments.length > 0 && !selectedEnvironments.includes(hostEnvironment(record))) {
        return false;
      }
      if (selectedOperatingSystems.length > 0 && !selectedOperatingSystems.includes(record.operatingSystem)) {
        return false;
      }
      if (selectedSourceSystems.length > 0) {
        const sources = hostSourceSystems(record);
        if (!selectedSourceSystems.some((value) => sources.includes(value))) {
          return false;
        }
      }
      return true;
    }),
    [
      hostRecords,
      quickFilter,
      searchValue,
      selectedEnvironments,
      selectedOperatingSystems,
      selectedSourceSystems
    ]
  );

  React.useEffect(() => {
    setPage(0);
  }, [quickFilter, searchValue, selectedEnvironments, selectedOperatingSystems, selectedSourceSystems]);

  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const paginatedRecords = React.useMemo(
    () => filteredRecords.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [filteredRecords, page]
  );

  const osSummaries = React.useMemo(() => buildOsSummary(filteredRecords), [filteredRecords]);
  const groupedCards = React.useMemo(() => (
    groupBy
      .map((key) => {
        const option = HOST_GROUP_BY_OPTIONS.find((entry) => entry.key === key);
        if (!option) {
          return null;
        }
        const counts = new Map<string, number>();
        filteredRecords.forEach((record) => {
          hostGroupValues(record, key).forEach((value) => {
            counts.set(value, (counts.get(value) ?? 0) + 1);
          });
        });
        return {
          key,
          label: option.label,
          items: Array.from(counts.entries())
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .slice(0, 5)
        };
      })
      .filter((entry): entry is { key: string; label: string; items: Array<[string, number]> } => entry != null)
  ), [filteredRecords, groupBy]);

  const totalSoftware = React.useMemo(
    () => filteredRecords.reduce((sum, record) => sum + record.deployedSoftwareCount, 0),
    [filteredRecords]
  );

  const totalCves = React.useMemo(
    () => filteredRecords.reduce((sum, record) => sum + record.applicableCveCount, 0),
    [filteredRecords]
  );

  const totalFindings = React.useMemo(
    () => filteredRecords.reduce((sum, record) => sum + record.openFindingCount, 0),
    [filteredRecords]
  );

  const onlineHosts = React.useMemo(
    () => filteredRecords.filter((record) => record.isOnline).length,
    [filteredRecords]
  );

  const loading = assetsQuery.isPending || hostDetailsQuery.isPending;
  const errorMessage = assetsQuery.error instanceof Error
    ? assetsQuery.error.message
    : hostDetailsQuery.error instanceof Error
      ? hostDetailsQuery.error.message
      : null;

  const handleOpenHost = React.useCallback((assetId: string) => {
    navigate(pathForInventoryHostAsset(assetId, `${location.pathname}${location.search}`));
  }, [location.pathname, location.search, navigate]);
  const clearFilters = React.useCallback(() => {
    setSearchValue('');
    setQuickFilter('all');
    setSelectedEnvironments([]);
    setSelectedOperatingSystems([]);
    setSelectedSourceSystems([]);
  }, []);

  return (
    <section className="inventory-page-shell">
      <header className="inventory-page-header">
        <div>
          <h1>Hosts</h1>
          <p className="panel-caption">
            Enterprise host inventory with correlated deployed software, applicable CVEs, and open findings.
          </p>
        </div>
        <div className="inventory-page-header-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              void assetsQuery.refetch();
              void hostDetailsQuery.refetch();
            }}
          >
            Refresh
          </button>
        </div>
      </header>

      <div className="inventory-summary-grid">
        <SummaryCard label="Total Hosts" value={filteredRecords.length.toLocaleString()} subtext="Correlated from current enterprise inventory" />
        <SummaryCard label="Online Hosts" value={onlineHosts.toLocaleString()} subtext="Active hosts currently reporting inventory" />
        <SummaryCard label="Deployed Software" value={totalSoftware.toLocaleString()} subtext="Installed software rows correlated to hosts" />
        <SummaryCard label="Applicable CVEs" value={totalCves.toLocaleString()} subtext="CVEs matched against deployed host software" />
        <SummaryCard label="Open Findings" value={totalFindings.toLocaleString()} subtext="Existing findings tied to these host records" />
      </div>

      <div className="inventory-toolbar">
        <div className="inventory-tab-row">
          <button
            type="button"
            className={`inventory-tab-button ${activeTab === 'all-hosts' ? 'active' : ''}`}
            onClick={() => setActiveTab('all-hosts')}
          >
            All hosts
          </button>
          <button
            type="button"
            className={`inventory-tab-button ${activeTab === 'by-os' ? 'active' : ''}`}
            onClick={() => setActiveTab('by-os')}
          >
            By OS
          </button>
        </div>

        <div className="inventory-search-row inventory-search-row-stacked">
          <label className="inventory-search-field">
            <span className="panel-caption">Search hostname, owner, OS, software…</span>
            <input
              value={searchValue}
              onChange={(event) => setSearchValue(event.target.value)}
              placeholder="prod-web-01, SQL Server, JBoss, WebLogic…"
            />
          </label>
          <div className="inventory-chip-row">
            {([
              ['all', 'All hosts'],
              ['online', 'Online'],
              ['with-findings', 'With findings'],
              ['linux', 'Linux'],
              ['windows', 'Windows']
            ] as const).map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={`inventory-chip ${quickFilter === value ? 'active' : ''}`}
                onClick={() => setQuickFilter(value)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="inventory-filter-card-grid">
          <FilterValueSelectCard
            label="Environment"
            selectedValues={selectedEnvironments}
            options={environmentOptions}
            onChange={setSelectedEnvironments}
          />
          <FilterValueSelectCard
            label="Operating System"
            selectedValues={selectedOperatingSystems}
            options={operatingSystemOptions}
            onChange={setSelectedOperatingSystems}
          />
          <FilterValueSelectCard
            label="Source System"
            selectedValues={selectedSourceSystems}
            options={sourceSystemOptions}
            onChange={setSelectedSourceSystems}
          />
        </div>
        <div className="inventory-toolbar-actions">
          <button type="button" className="btn btn-secondary btn-inline" onClick={clearFilters}>
            Clear Filters
          </button>
        </div>
        <div className="findings-groupby-shell">
          <MultiGroupBy
            options={HOST_GROUP_BY_OPTIONS}
            value={groupBy}
            onChange={setGroupBy}
            label="GROUP BY"
            placeholder="No secondary grouping"
            allowEmptyPrimary
            emptyPrimaryLabel="Select..."
            showSelectorsByDefault={false}
          />
        </div>
      </div>

      {errorMessage ? (
        <div className="inventory-error-banner">
          Failed to load hosts inventory: {errorMessage}
        </div>
      ) : null}

      {groupedCards.length > 0 && (
        <div className="inventory-section-card">
          <div className="inventory-section-header findings-title-row">
            <div>
              <h2>Grouped Breakdown</h2>
              <p className="panel-caption">Top host segments in the current filtered inventory result set.</p>
            </div>
          </div>
          <div className="findings-widget-grid">
            {groupedCards.map((group) => (
              <div className="findings-widget-card" key={group.key}>
                <div className="findings-widget-title">{group.label}</div>
                <div className="findings-widget-list">
                  {group.items.length === 0 ? (
                    <div className="panel-caption">No rows in the current result set.</div>
                  ) : (
                    group.items.map(([value, count]) => (
                      <div className="findings-widget-row" key={`${group.key}:${value}`}>
                        <span>{value}</span>
                        <strong>{count.toLocaleString()}</strong>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {loading ? (
        <div className="empty-state"><p>Loading host inventory…</p></div>
      ) : activeTab === 'all-hosts' ? (
        <div className="inventory-section-card">
          <div className="inventory-section-header">
            <div>
              <h2>Host inventory</h2>
              <p className="panel-caption">Each host is correlated to its deployed software, findings, and applicable CVEs.</p>
            </div>
            <span className="panel-caption">{filteredRecords.length.toLocaleString()} hosts</span>
          </div>

          <div className="inventory-table-shell">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Environment</th>
                  <th>OS</th>
                  <th>Owner</th>
                  <th>Support Group</th>
                  <th>Software</th>
                  <th>Applicable CVEs</th>
                  <th>Open Findings</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.length === 0 ? (
                  <tr>
                    <td colSpan={10}>
                      <div className="empty-state"><p>No hosts matched the current filters.</p></div>
                    </td>
                  </tr>
                ) : paginatedRecords.map((record) => (
                  <HostRow key={record.asset.id} record={record} onOpen={handleOpenHost} />
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="pagination">
              <button
                type="button"
                onClick={() => setPage((current) => Math.max(0, current - 1))}
                disabled={page === 0}
              >
                Previous
              </button>
              <span>Page {page + 1} of {totalPages}</span>
              <button
                type="button"
                onClick={() => setPage((current) => (current + 1 < totalPages ? current + 1 : current))}
                disabled={page + 1 >= totalPages}
              >
                Next
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="inventory-section-card">
          <div className="inventory-section-header">
            <div>
              <h2>Hosts by operating system</h2>
              <p className="panel-caption">OS coverage across enterprise hosts with correlated software, CVEs, and findings.</p>
            </div>
            <span className="panel-caption">{osSummaries.length.toLocaleString()} OS groups</span>
          </div>

          <div className="inventory-table-shell">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th>OS</th>
                  <th>Hosts</th>
                  <th>Online</th>
                  <th>Deployed Software</th>
                  <th>Applicable CVEs</th>
                  <th>Open Findings</th>
                </tr>
              </thead>
              <tbody>
                {osSummaries.length === 0 ? (
                  <tr>
                    <td colSpan={6}>
                      <div className="empty-state"><p>No operating-system groups matched the current filters.</p></div>
                    </td>
                  </tr>
                ) : osSummaries.map((summary) => (
                  <tr key={summary.os}>
                    <td>{summary.os}</td>
                    <td>{summary.hostCount.toLocaleString()}</td>
                    <td>{summary.activeCount.toLocaleString()}</td>
                    <td>{summary.totalSoftware.toLocaleString()}</td>
                    <td>{summary.totalApplicableCves.toLocaleString()}</td>
                    <td>{summary.totalOpenFindings.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}
