import type { HostReviewCategory } from './types';
import { normalizeHostReviewCategory } from './helpers';

export const HOST_ASSET_QUERY_KEY = 'hostAssetId';
export const HOST_REVIEW_CATEGORY_QUERY_KEY = 'reviewCategory';

export function readHostAssetIdFromSearch(searchParams: URLSearchParams): string | null {
  return searchParams.get(HOST_ASSET_QUERY_KEY);
}

export function readHostReviewCategoriesFromSearch(searchParams: URLSearchParams): HostReviewCategory[] {
  return Array.from(new Set(
    searchParams
      .getAll(HOST_REVIEW_CATEGORY_QUERY_KEY)
      .map(normalizeHostReviewCategory)
      .filter((value): value is HostReviewCategory => value !== null)
  ));
}

export function writeHostAssetIdToSearch(searchParams: URLSearchParams, assetId: string | null): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  if (assetId) {
    nextSearchParams.set(HOST_ASSET_QUERY_KEY, assetId);
  } else {
    nextSearchParams.delete(HOST_ASSET_QUERY_KEY);
  }
  return nextSearchParams;
}

export function writeHostReviewCategoriesToSearch(
  searchParams: URLSearchParams,
  categories: HostReviewCategory[]
): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  nextSearchParams.delete(HOST_REVIEW_CATEGORY_QUERY_KEY);
  categories.forEach((category) => nextSearchParams.append(HOST_REVIEW_CATEGORY_QUERY_KEY, category));
  return nextSearchParams;
}

export function clearHostInventorySearchState(searchParams: URLSearchParams): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  nextSearchParams.delete(HOST_ASSET_QUERY_KEY);
  nextSearchParams.delete(HOST_REVIEW_CATEGORY_QUERY_KEY);
  return nextSearchParams;
}
