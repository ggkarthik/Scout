import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoVulnerabilitiesPage } from './VulnRepoVulnerabilitiesPage';

describe('VulnRepoVulnerabilitiesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('uses the vuln repo endpoint and renders ingested-only rows without breaking the table', async () => {
    const listVulnRepoSpy = vi.spyOn(cveWorkbenchApi, 'listVulnRepoVulnerabilities').mockResolvedValue({
      summary: {
        reviewQueueCount: 7,
        applicableCount: 5,
        impactedCount: 3,
        underInvestigationCount: 1,
        resolvedCount: 2,
      },
      items: [
        {
          recordId: '10000000-0000-0000-0000-000000000001',
          vulnerabilityId: '20000000-0000-0000-0000-000000000001',
          externalId: 'CVE-2026-23360',
          title: 'Canonical only',
          descriptionSnippet: 'Only ingested',
          applicability: 'UNKNOWN',
          impacted: false,
          impactState: 'UNKNOWN',
          severity: 'HIGH',
          cvssScore: 8.8,
          epssScore: 0.12,
          inKev: false,
          matchedComponentCount: 0,
          matchedSoftwareCount: 0,
          matchedAssetCount: 0,
          applicableComponentCount: 0,
          impactedComponentCount: 0,
          notAffectedComponentCount: 0,
          fixedComponentCount: 0,
          noPatchComponentCount: 0,
          underInvestigationComponentCount: 0,
          unknownComponentCount: 0,
          openFindings: 0,
          eolComponentCount: 0,
          eosComponentCount: 0,
          hasInvestigationSummary: false,
        },
      ],
      page: 0,
      size: 25,
      totalItems: 1,
      totalPages: 1,
    });
    const listOrgSpecificSpy = vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue({
      summary: {
        reviewQueueCount: 0,
        applicableCount: 0,
        impactedCount: 0,
        underInvestigationCount: 0,
        resolvedCount: 0,
      },
      items: [],
      page: 0,
      size: 25,
      totalItems: 0,
      totalPages: 0,
    });

    renderWithProviders(
      <VulnRepoVulnerabilitiesPage />,
      { route: '/vuln-repo/vulnerabilities?query=CVE-2026-23360' }
    );

    await screen.findByText('CVE-2026-23360');
    await waitFor(() => {
      expect(listVulnRepoSpy).toHaveBeenCalledWith(expect.objectContaining({
        page: 0,
        size: 25,
        query: 'CVE-2026-23360',
      }));
      expect(listOrgSpecificSpy).not.toHaveBeenCalled();
    });

    expect(screen.getByText('Only ingested')).toBeInTheDocument();
    expect(screen.getByText('Not Matched')).toBeInTheDocument();
    expect(screen.getByText('8.8')).toBeInTheDocument();
  });
});
