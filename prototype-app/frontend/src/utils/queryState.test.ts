import { describe, expect, it } from 'vitest';
import {
  buildPathWithQueryParams,
  readQueryParam,
  readQueryParams
} from './queryState';

describe('queryState', () => {
  it('reads a single query parameter value', () => {
    expect(readQueryParam('tab', '?tab=inventory&inventoryView=hosts')).toBe('inventory');
    expect(readQueryParam('missing', '?tab=inventory')).toBeNull();
  });

  it('reads repeated query parameter values', () => {
    expect(readQueryParams('reviewCategory', '?reviewCategory=NEEDS_REVIEW&reviewCategory=MISSING_VERSION')).toEqual([
      'NEEDS_REVIEW',
      'MISSING_VERSION'
    ]);
  });

  it('builds an updated path while preserving unrelated query params and hashes', () => {
    expect(buildPathWithQueryParams(
      {
        tab: 'connect',
        inventoryView: null,
        connectView: 'sources',
        reviewCategory: ['NEEDS_REVIEW', 'MISSING_VERSION']
      },
      'https://example.test/prototype.html?tab=inventory&inventoryView=hosts#anchor'
    )).toBe('/prototype.html?tab=connect&connectView=sources&reviewCategory=NEEDS_REVIEW&reviewCategory=MISSING_VERSION#anchor');
  });

  it('removes a query parameter when the next value is null', () => {
    expect(buildPathWithQueryParams(
      {
        hostAssetId: null
      },
      'https://example.test/prototype.html?tab=inventory&hostAssetId=abc-123'
    )).toBe('/prototype.html?tab=inventory');
  });
});
