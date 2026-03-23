import { describe, expect, it } from 'vitest';
import {
  canonicalVulnerabilitySource,
  defaultAssetTypeForView,
  expandVulnerabilitySourceFilters,
  normalizeHostReviewCategory,
  vulnerabilitySourceFilterValue
} from './helpers';

describe('inventory helpers', () => {
  it('maps views to scoped asset types', () => {
    expect(defaultAssetTypeForView('hosts')).toBe('HOST');
    expect(defaultAssetTypeForView('container-images')).toBe('CONTAINER_IMAGE');
    expect(defaultAssetTypeForView('software-identities')).toBe('ALL');
  });

  it('normalizes host review category aliases', () => {
    expect(normalizeHostReviewCategory('missing version')).toBe('MISSING_VERSION');
    expect(normalizeHostReviewCategory('low-confidence-alias')).toBe('LOW_CONFIDENCE_ALIAS');
    expect(normalizeHostReviewCategory('unknown')).toBeNull();
  });

  it('canonicalizes vulnerability source names and filter values', () => {
    expect(canonicalVulnerabilitySource('microsoft-csaf')).toBe('csaf-microsoft');
    expect(canonicalVulnerabilitySource('github-advisory')).toBe('ghsa');
    expect(vulnerabilitySourceFilterValue('vex-redhat')).toBe('redhat');
  });

  it('expands grouped vulnerability source filters', () => {
    expect(expandVulnerabilitySourceFilters(['msrc', 'kev']).sort()).toEqual([
      'csaf-microsoft',
      'kev',
      'vex-microsoft'
    ]);
  });
});
