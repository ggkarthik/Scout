import { useQueries, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api } from '../api/client';
import { pathForTab } from '../app/routes';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from './DataTable';
import {
  useEolUnresolvedMappingsQuery
} from '../features/eol/queries';

const UNRESOLVED_PAGE_SIZE = 25;
import {
  useOperationalQualityIssuesQuery,
  type OperationalQualityIssuesQueryParams
} from '../features/operations/queries';
import type {
  EolSlugSuggestion,
  UnresolvedEolMapping
} from '../features/eol/types';

type Props = {
  initiallyOpen?: boolean;
  qualityFilters?: Pick<
    OperationalQualityIssuesQueryParams,
    'issueType' | 'severity' | 'affectsActiveFindings' | 'assetType' | 'sourceSystem' | 'ecosystem' | 'query'
  >;
};

type MappingNotice = {
  kind: 'error' | 'success';
  message: string;
};

const INVALIDATION_KEYS = [
  ['eol-unresolved-mappings'],
  ['eol-summary'],
  ['eol-component-statuses'],
  ['software-identities'],
  ['software-identity-detail'],
  ['operational-quality-summary'],
  ['operational-quality-issues'],
  ['operational-quality-issue-detail']
] as const;
const MATCHING_ISSUE_TYPE = 'SOFTWARE_IDENTITY_NEEDS_EOL_MAPPING';

function formatInstant(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatCount(value: number | string | undefined): string {
  if (typeof value === 'number') {
    return value.toLocaleString();
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed.toLocaleString();
    }
  }
  return '0';
}

export function EolMappingReviewPanel({ initiallyOpen = false, qualityFilters }: Props) {
  const queryClient = useQueryClient();
  const [unresolvedPage, setUnresolvedPage] = React.useState(0);
  const unresolvedMappingsQuery = useEolUnresolvedMappingsQuery(
    { page: unresolvedPage, size: UNRESOLVED_PAGE_SIZE }
  );
  const unresolvedPageData = unresolvedMappingsQuery.data;
  const unresolvedList = React.useMemo(
    () => unresolvedPageData?.content ?? [],
    [unresolvedPageData]
  );
  const unresolvedTotalPages = unresolvedPageData?.totalPages ?? 1;
  const unresolvedTotalElements = unresolvedPageData?.totalElements ?? 0;
  const normalizedIssueType = (qualityFilters?.issueType ?? '').trim().toUpperCase();
  const issueTypeExcludesMappingReview = normalizedIssueType.length > 0 && normalizedIssueType !== MATCHING_ISSUE_TYPE;
  const [open, setOpen] = React.useState(initiallyOpen);
  const mappingIssueFilters = React.useMemo<OperationalQualityIssuesQueryParams>(() => ({
    domain: 'EOL',
    issueType: MATCHING_ISSUE_TYPE,
    severity: qualityFilters?.severity,
    affectsActiveFindings: qualityFilters?.affectsActiveFindings,
    assetType: qualityFilters?.assetType,
    sourceSystem: qualityFilters?.sourceSystem,
    ecosystem: qualityFilters?.ecosystem,
    query: qualityFilters?.query,
    page: 0,
    size: 200
  }), [qualityFilters]);
  const hasIntersectionFilters = Boolean(
    qualityFilters?.severity
      || qualityFilters?.affectsActiveFindings != null
      || (qualityFilters?.assetType?.length ?? 0) > 0
      || (qualityFilters?.sourceSystem?.length ?? 0) > 0
      || (qualityFilters?.ecosystem?.length ?? 0) > 0
      || (qualityFilters?.query?.trim().length ?? 0) > 0
  );
  const filteredMappingIssuesQuery = useOperationalQualityIssuesQuery(
    mappingIssueFilters,
    hasIntersectionFilters && !issueTypeExcludesMappingReview
  );
  const [confirmSlug, setConfirmSlug] = React.useState<Record<string, string>>({});
  const [busyKey, setBusyKey] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<MappingNotice | null>(null);
  const eolCatalogHref = pathForTab('end-of-life');

  React.useEffect(() => {
    if (initiallyOpen) {
      setOpen(true);
    }
  }, [initiallyOpen]);
  const filteredIdentityIds = React.useMemo(
    () => new Set(
      (filteredMappingIssuesQuery.data?.items ?? [])
        .map((issue) => issue.sourceObjectId)
        .filter((value): value is string => Boolean(value))
    ),
    [filteredMappingIssuesQuery.data?.items]
  );
  const filteredList = React.useMemo(() => {
    if (issueTypeExcludesMappingReview) {
      return [];
    }
    if (!hasIntersectionFilters || !filteredMappingIssuesQuery.data) {
      return unresolvedList;
    }
    return unresolvedList.filter((item) => filteredIdentityIds.has(item.softwareIdentityId));
  }, [
    filteredIdentityIds,
    filteredMappingIssuesQuery.data,
    hasIntersectionFilters,
    issueTypeExcludesMappingReview,
    unresolvedList
  ]);
  const hasActiveQualityFilters = Boolean(
    hasIntersectionFilters
      || issueTypeExcludesMappingReview
  );
  const visibleCount = issueTypeExcludesMappingReview
    ? 0
    : hasIntersectionFilters && filteredMappingIssuesQuery.data
      ? filteredList.length
      : unresolvedTotalElements;
  const loadingReviewList = unresolvedMappingsQuery.isPending
    || (
      hasIntersectionFilters
      && !issueTypeExcludesMappingReview
      && filteredMappingIssuesQuery.isPending
      && !filteredMappingIssuesQuery.data
    );

  const suggestionQueries = useQueries({
    queries: (open ? filteredList : []).map(item => ({
      queryKey: ['eol-slug-suggestions', item.normalizedKey],
      queryFn: () => api.listEolMappingSuggestions(item.normalizedKey),
      staleTime: 5 * 60 * 1000
    }))
  });

  const suggestionsMap = React.useMemo(() => {
    const map = new Map<string, EolSlugSuggestion[]>();
    filteredList.forEach((item, index) => {
      map.set(item.normalizedKey, suggestionQueries[index]?.data ?? []);
    });
    return map;
  }, [filteredList, suggestionQueries]);

  const reviewColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'software', label: 'Software', header: 'Software', initialSize: 220 },
    { id: 'vendorProduct', label: 'Vendor / Product', header: 'Vendor / Product', initialSize: 220 },
    { id: 'footprint', label: 'Active Footprint', header: 'Active Footprint', initialSize: 180 },
    { id: 'exposure', label: 'Exposure', header: 'Exposure', initialSize: 180 },
    { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 },
    { id: 'normalizedKey', label: 'Normalized Key', header: 'Normalized Key', initialSize: 240 },
    { id: 'eolSlug', label: 'EOL Slug', header: 'EOL Slug', initialSize: 300 },
    { id: 'actions', label: 'Actions', header: '', initialSize: 140 }
  ], []);

  const handleConfirmMapping = React.useCallback(async (item: UnresolvedEolMapping) => {
    const slug = confirmSlug[item.normalizedKey]?.trim();
    if (!slug) {
      setNotice({
        kind: 'error',
        message: `Enter an endoflife.date slug before confirming ${item.displayName}.`
      });
      return;
    }

    setBusyKey(item.normalizedKey);
    setNotice(null);
    try {
      await api.confirmEolMapping(item.normalizedKey, slug);
      setConfirmSlug(prev => {
        const next = { ...prev };
        delete next[item.normalizedKey];
        return next;
      });
      setNotice({
        kind: 'success',
        message: `Mapped ${item.displayName} to ${slug}.`
      });
      await Promise.all(
        INVALIDATION_KEYS.map((queryKey) => queryClient.invalidateQueries({ queryKey }))
      );
    } catch (error) {
      setNotice({
        kind: 'error',
        message: error instanceof Error ? error.message : String(error)
      });
    } finally {
      setBusyKey(null);
    }
  }, [confirmSlug, queryClient]);

  const reviewRows = React.useMemo<DataTableRow[]>(() => (
    filteredList.map((item) => {
      const draft = confirmSlug[item.normalizedKey] ?? '';
      const dropdownSuggestions = suggestionsMap.get(item.normalizedKey) ?? [];
      const suggestionListId = `quality-eol-suggestions-${item.softwareIdentityId}`;
      return {
        id: item.normalizedKey,
        cells: {
          software: {
            content: (
              <div className="software-identity-row-stack">
                <span>{item.displayName}</span>
                <span className="panel-caption">
                  Review and assign the official endoflife.date slug
                </span>
              </div>
            )
          },
          vendorProduct: {
            content: (
              <div className="software-identity-row-stack">
                <span>{item.vendor || '-'}</span>
                <span className="panel-caption">{item.product || '-'}</span>
              </div>
            )
          },
          footprint: {
            content: (
              <div className="software-identity-row-stack">
                <span>{formatCount(item.componentCount)} active components</span>
                <span className="panel-caption">
                  {formatCount(item.assetCount)} active assets · {formatCount(item.versionCount)} versions
                </span>
              </div>
            )
          },
          exposure: {
            content: (
              <div className="software-identity-row-stack">
                <span>{formatCount(item.openFindingCount)} open findings</span>
                <span className="panel-caption">
                  {formatCount(item.openVulnerabilityCount)} open vulnerabilities
                </span>
              </div>
            )
          },
          lastObserved: { content: formatInstant(item.lastObservedAt) },
          normalizedKey: { content: <span className="mono">{item.normalizedKey}</span> },
          eolSlug: {
            content: (
              <div className="quality-eol-input-stack">
                <input
                  type="text"
                  className="filter-input"
                  list={suggestionListId}
                  placeholder="Select a slug or type one manually"
                  value={draft}
                  disabled={busyKey === item.normalizedKey}
                  onChange={(event) => setConfirmSlug(prev => ({
                    ...prev,
                    [item.normalizedKey]: event.target.value
                  }))}
                />
                <datalist id={suggestionListId}>
                  {dropdownSuggestions.map((suggestion) => (
                    <option
                      key={`${item.normalizedKey}-${suggestion.slug}`}
                      value={suggestion.slug}
                      label={`${suggestion.displayName ?? suggestion.slug} (${suggestion.confidence})`}
                    />
                  ))}
                </datalist>
              </div>
            )
          },
          actions: {
            content: (
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busyKey === item.normalizedKey || !draft.trim()}
                onClick={() => void handleConfirmMapping(item)}
              >
                {busyKey === item.normalizedKey ? 'Saving...' : 'Confirm'}
              </button>
            )
          }
        }
      };
    })
  ), [busyKey, confirmSlug, filteredList, handleConfirmMapping, suggestionsMap]);

  return (
    <section className="panel quality-eol-review-panel">
      <div className="panel-header quality-eol-review-header">
        <div className="quality-eol-review-copy">
          <h3>Unmatched EOL Software</h3>
          <p className="quality-eol-review-summary">
            These software identities already show up as lifecycle-quality gaps. Review them here, assign the official
            endoflife.date slug, and the Quality and EOL views will refresh around that confirmed mapping. The queue is
            sorted by active exposure first, then by deployment footprint.
          </p>
        </div>

        <div className="button-row quality-eol-review-actions">
          <a href={eolCatalogHref} className="btn btn-secondary">
            Open EOL Catalog
          </a>
          <button
            type="button"
            className="btn btn-secondary quality-eol-review-toggle"
            onClick={() => setOpen(current => !current)}
          >
            {open ? 'Hide Review' : 'Review Unmatched EOL Software'}
            <span className="eol-unresolved-badge">{visibleCount}</span>
          </button>
        </div>
      </div>

      {notice && (
        <div className={`notice${notice.kind === 'error' ? ' error' : ''}`}>
          {notice.message}
        </div>
      )}

      {!open && (
        <div className="panel-caption">
          Open the review queue when you want to work through unmatched lifecycle mappings from the Quality workflow.
        </div>
      )}

      {open && loadingReviewList && (
        <div className="notice">Loading unmatched EOL software...</div>
      )}

      {open && unresolvedMappingsQuery.error instanceof Error && (
        <div className="notice error">
          Unable to load unmatched EOL software: {unresolvedMappingsQuery.error.message}
        </div>
      )}

      {open && hasIntersectionFilters && !issueTypeExcludesMappingReview && filteredMappingIssuesQuery.error instanceof Error && (
        <div className="notice error">
          Unable to apply current Quality filters to unmatched EOL software: {filteredMappingIssuesQuery.error.message}
        </div>
      )}

      {open && issueTypeExcludesMappingReview && (
        <div className="empty-state quality-eol-review-empty">
          <p>The current Issue Type filter excludes unmatched EOL software.</p>
        </div>
      )}

      {open
        && !loadingReviewList
        && !(unresolvedMappingsQuery.error instanceof Error)
        && !(hasIntersectionFilters && filteredMappingIssuesQuery.error instanceof Error)
        && !issueTypeExcludesMappingReview
        && filteredList.length === 0 && (
        <div className="empty-state quality-eol-review-empty">
          <p>
            {hasActiveQualityFilters
              ? 'No unmatched EOL software matches the current filters.'
              : 'No actionable EOL mapping gaps. Library-ecosystem packages (npm, maven, pypi, etc.) are excluded — endoflife.date tracks OS packages, runtimes, and infrastructure software, not individual libraries.'}
          </p>
        </div>
      )}

      {open && filteredList.length > 0 && (
        <>
          <div className="table-scroll">
            <DataTable
              storageKey="operations-quality-eol-mapping-review"
              columns={reviewColumns}
              rows={reviewRows}
            />
          </div>

          {!hasIntersectionFilters && unresolvedTotalPages > 1 && (
            <div className="pagination quality-pagination">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={unresolvedPage === 0}
                onClick={() => setUnresolvedPage(p => p - 1)}
              >
                Previous
              </button>
              <span className="panel-caption">
                Page {unresolvedPage + 1} of {unresolvedTotalPages}
                {' · '}{unresolvedTotalElements.toLocaleString()} unmatched
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={unresolvedPage >= unresolvedTotalPages - 1}
                onClick={() => setUnresolvedPage(p => p + 1)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
