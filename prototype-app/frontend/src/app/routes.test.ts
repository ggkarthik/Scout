import { describe, expect, it } from 'vitest';
import {
  activeTabForPath,
  buildLegacyCompatiblePath,
  pathForConnectView,
  pathForOperationsView,
  pathForTab
} from './routes';

describe('routes', () => {
  it('maps top-level tabs to canonical paths', () => {
    expect(pathForTab('dashboard')).toBe('/');
    expect(pathForTab('operations')).toBe('/operations/pipeline');
    expect(pathForTab('inventory')).toBe('/inventory/hosts');
    expect(pathForConnectView('vuln-intel-queue')).toBe('/connect/vuln-intel-queue');
    expect(pathForOperationsView('platform-health')).toBe('/operations/platform-health');
  });

  it('infers the active navigation tab from the route path', () => {
    expect(activeTabForPath('/')).toBe('dashboard');
    expect(activeTabForPath('/findings')).toBe('findings');
    expect(activeTabForPath('/operations/platform-health')).toBe('operations');
    expect(activeTabForPath('/inventory/hosts')).toBe('inventory');
    expect(activeTabForPath('/connect/sources')).toBe('connect');
  });

  it('redirects legacy operations deep links to canonical routes', () => {
    expect(buildLegacyCompatiblePath('?tab=operations&operationsView=api-read-path&foo=bar')).toBe(
      '/operations/platform-health?foo=bar'
    );
  });

  it('redirects legacy vulnerability intelligence deep links to canonical routes', () => {
    expect(buildLegacyCompatiblePath('?tab=vulnerability-intelligence&vulnIntelView=org-cves&cveId=CVE-2026-1234')).toBe(
      '/vuln-repo/org-cves/CVE-2026-1234'
    );
    expect(buildLegacyCompatiblePath('?tab=vulnerability-intelligence')).toBe('/vuln-repo/vulnerabilities');
  });

  it('redirects legacy inventory and connect deep links while preserving non-routing params', () => {
    expect(buildLegacyCompatiblePath('?tab=inventory&inventoryView=host-review-queue&reviewCategory=MISSING_VERSION')).toBe(
      '/inventory/hosts?reviewCategory=MISSING_VERSION'
    );
    expect(buildLegacyCompatiblePath('?tab=connect&connectView=integration-queue&source=ghsa')).toBe(
      '/connect/vuln-intel-queue?source=ghsa'
    );
  });

  it('returns null when the URL does not contain legacy navigation state', () => {
    expect(buildLegacyCompatiblePath('?page=1&size=25')).toBeNull();
  });
});
