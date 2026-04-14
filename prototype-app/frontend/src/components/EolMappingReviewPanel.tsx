import { useQueries, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { createPortal } from 'react-dom';
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
  qualityFilters?: Pick<
    OperationalQualityIssuesQueryParams,
    'issueType' | 'severity' | 'affectsActiveFindings' | 'assetType' | 'sourceSystem' | 'ecosystem' | 'query'
  >;
};

type MappingNotice = {
  kind: 'error' | 'success';
  message: string;
};

// ---------------------------------------------------------------------------
// Slug suggestion combobox
// ---------------------------------------------------------------------------

function SlugSuggestInput({
  value,
  onChange,
  suggestions,
  disabled,
}: {
  value: string;
  onChange: (val: string) => void;
  suggestions: EolSlugSuggestion[];
  disabled: boolean;
}) {
  const [open, setOpen] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const [dropdownPos, setDropdownPos] = React.useState<{ top: number; left: number; width: number } | null>(null);

  function updatePosition() {
    if (inputRef.current) {
      const rect = inputRef.current.getBoundingClientRect();
      setDropdownPos({ top: rect.bottom + 4, left: rect.left, width: rect.width });
    }
  }

  function confidenceClass(confidence: string) {
    switch (confidence.toUpperCase()) {
      case 'HIGH': return 'slug-suggest-confidence--high';
      case 'MEDIUM': return 'slug-suggest-confidence--medium';
      default: return 'slug-suggest-confidence--low';
    }
  }

  const showDropdown = open && suggestions.length > 0;

  return (
    <div className="slug-suggest-wrap">
      <input
        ref={inputRef}
        type="text"
        className="filter-input"
        placeholder="Select a suggestion or type a slug"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => { updatePosition(); setOpen(true); }}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
      />
      {showDropdown && dropdownPos && createPortal(
        <div
          className="slug-suggest-dropdown"
          style={{
            position: 'fixed',
            top: dropdownPos.top,
            left: dropdownPos.left,
            width: dropdownPos.width,
            zIndex: 9999,
          }}
        >
          {suggestions.map((s) => (
            <button
              key={s.slug}
              type="button"
              className="slug-suggest-option"
              onMouseDown={() => { onChange(s.slug); setOpen(false); }}
            >
              <div className="slug-suggest-top">
                <span className="mono">{s.slug}</span>
                <span className={`slug-suggest-confidence ${confidenceClass(s.confidence)}`}>
                  {s.confidence}
                </span>
              </div>
              <div className="slug-suggest-bottom">
                <span>{s.displayName}</span>
                <span className="panel-caption slug-suggest-method">{s.method}</span>
              </div>
            </button>
          ))}
        </div>,
        document.body
      )}
    </div>
  );
}

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

export function EolMappingReviewPanel({ qualityFilters }: Props) {
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

  const filteredIdentityIds = React.useMemo(
    () => new Set(
      (filteredMappingIssuesQuery.data?.items ?? [])
        .map((issue) => issue.sourceObjectId)
        .filter((value): value is string => Boolean(value))
    ),
    [filteredMappingIssuesQuery.data?.items]
  );
  const filteredList = React.useMemo(() => {
    if (issueTypeExcludesMappingReview) return [];
    if (!hasIntersectionFilters || !filteredMappingIssuesQuery.data) return unresolvedList;
    return unresolvedList.filter((item) => filteredIdentityIds.has(item.softwareIdentityId));
  }, [
    filteredIdentityIds,
    filteredMappingIssuesQuery.data,
    hasIntersectionFilters,
    issueTypeExcludesMappingReview,
    unresolvedList
  ]);

  const loadingReviewList = unresolvedMappingsQuery.isPending
    || (
      hasIntersectionFilters
      && !issueTypeExcludesMappingReview
      && filteredMappingIssuesQuery.isPending
      && !filteredMappingIssuesQuery.data
    );

  const suggestionQueries = useQueries({
    queries: filteredList.map(item => ({
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
    { id: 'software', label: 'Software', header: 'Software', initialSize: 240 },
    { id: 'footprint', label: 'Footprint', header: 'Footprint', initialSize: 200 },
    { id: 'exposure', label: 'Exposure', header: 'Exposure', initialSize: 160 },
    { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 160 },
    { id: 'eolSlug', label: 'EOL Slug', header: 'EOL Slug', initialSize: 360 },
  ], []);

  const handleConfirmMapping = React.useCallback(async (item: UnresolvedEolMapping) => {
    const slug = confirmSlug[item.normalizedKey]?.trim();
    if (!slug) {
      setNotice({ kind: 'error', message: `Enter an endoflife.date slug before confirming ${item.displayName}.` });
      return;
    }
    setBusyKey(item.normalizedKey);
    setNotice(null);
    try {
      await api.confirmEolMapping(item.normalizedKey, slug);
      setConfirmSlug(prev => { const next = { ...prev }; delete next[item.normalizedKey]; return next; });
      setNotice({ kind: 'success', message: `Mapped ${item.displayName} to ${slug}.` });
      await Promise.all(INVALIDATION_KEYS.map((queryKey) => queryClient.invalidateQueries({ queryKey })));
    } catch (error) {
      setNotice({ kind: 'error', message: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusyKey(null);
    }
  }, [confirmSlug, queryClient]);

  const reviewRows = React.useMemo<DataTableRow[]>(() => (
    filteredList.map((item) => {
      const draft = confirmSlug[item.normalizedKey] ?? '';
      const dropdownSuggestions = suggestionsMap.get(item.normalizedKey) ?? [];
      const isBusy = busyKey === item.normalizedKey;
      return {
        id: item.normalizedKey,
        cells: {
          software: {
            content: (
              <div className="software-identity-row-stack">
                <span>{item.displayName}</span>
                <span className="panel-caption mono">{item.normalizedKey}</span>
              </div>
            )
          },
          footprint: {
            content: (
              <div className="software-identity-row-stack">
                <span>{formatCount(item.assetCount)} assets</span>
                <span className="panel-caption">
                  {formatCount(item.componentCount)} components · {formatCount(item.versionCount)} versions
                </span>
              </div>
            )
          },
          exposure: {
            content: (
              <div className="software-identity-row-stack">
                <span>{formatCount(item.openFindingCount)} findings</span>
                <span className="panel-caption">{formatCount(item.openVulnerabilityCount)} vulns</span>
              </div>
            )
          },
          lastObserved: { content: formatInstant(item.lastObservedAt) },
          eolSlug: {
            content: (
              <div className="eol-slug-confirm-row">
                <SlugSuggestInput
                  value={draft}
                  onChange={(val) => setConfirmSlug(prev => ({ ...prev, [item.normalizedKey]: val }))}
                  suggestions={dropdownSuggestions}
                  disabled={isBusy}
                />
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={isBusy || !draft.trim()}
                  onClick={() => void handleConfirmMapping(item)}
                >
                  {isBusy ? 'Saving...' : 'Confirm'}
                </button>
              </div>
            )
          },
        }
      };
    })
  ), [busyKey, confirmSlug, filteredList, handleConfirmMapping, suggestionsMap]);

  return (
    <div className="eol-mapping-review">
      <div className="eol-mapping-review-header">
        <div>
          <span className="panel-caption">
            Software without an endoflife.date match — sorted by exposure then footprint.
            {' '}{unresolvedTotalElements > 0 && <strong>{unresolvedTotalElements.toLocaleString()} remaining</strong>}
          </span>
        </div>
        <a href={eolCatalogHref} className="btn btn-secondary">
          Browse EOL Catalog
        </a>
      </div>

      {notice && (
        <div className={`notice${notice.kind === 'error' ? ' error' : ''}`}>
          {notice.message}
        </div>
      )}

      {loadingReviewList && (
        <div className="panel-caption" style={{ padding: '24px 0' }}>Loading...</div>
      )}

      {!loadingReviewList && unresolvedMappingsQuery.error instanceof Error && (
        <div className="notice error">
          Unable to load unmatched EOL software: {unresolvedMappingsQuery.error.message}
        </div>
      )}

      {!loadingReviewList && hasIntersectionFilters && !issueTypeExcludesMappingReview && filteredMappingIssuesQuery.error instanceof Error && (
        <div className="notice error">
          Unable to apply current Quality filters: {filteredMappingIssuesQuery.error.message}
        </div>
      )}

      {!loadingReviewList && !unresolvedMappingsQuery.error && filteredList.length === 0 && (
        <div className="empty-state">
          <p>
            {issueTypeExcludesMappingReview
              ? 'The current Issue Type filter excludes unmatched EOL software.'
              : hasIntersectionFilters
                ? 'No unmatched EOL software matches the current filters.'
                : 'No actionable EOL mapping gaps. Library-ecosystem packages (npm, maven, pypi, etc.) are excluded — endoflife.date tracks OS packages, runtimes, and infrastructure software, not individual libraries.'}
          </p>
        </div>
      )}

      {!loadingReviewList && filteredList.length > 0 && (
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
    </div>
  );
}
