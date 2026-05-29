import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { CveDetail } from '../features/cve-workbench/types';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoCveAssetsPage } from './VulnRepoCveAssetsPage';

const CVE_ID = 'CVE-2024-1234';
const PAGE_PATH = `/vuln-repo/org-cves/${CVE_ID}/assets`;
const EMPTY_FINDINGS_PAGE = { items: [], page: 0, size: 1000, totalItems: 0, totalPages: 0 };

function buildCveDetail(overrides: Partial<CveDetail> = {}): CveDetail {
  return {
    summary: {
      externalId: CVE_ID,
      title: 'Test CVE',
      description: 'A test vulnerability',
      severity: 'HIGH',
    },
    signals: {
      exploitAvailable: false,
      exploitReason: '',
      systemsImpacted: false,
      componentCount: 0,
      softwareCount: 0,
      assetCount: 0,
      patchAvailable: false,
    },
    investigations: [],
    assessments: [],
    matchedSoftware: [],
    vendorIntelligence: [],
    ...overrides,
  };
}

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/vuln-repo/org-cves/:cveId/assets" element={<VulnRepoCveAssetsPage />} />
    </Routes>,
    { initialEntries: [PAGE_PATH] }
  );
}

describe('VulnRepoCveAssetsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while data is fetching', () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'listFindings').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText('Loading affected entities...')).toBeInTheDocument();
  });

  it('shows error message when the query fails', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockRejectedValue(new Error('Server error'));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('Server error')).toBeInTheDocument());
  });

  it('shows empty state when no assets are matched', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail());
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText('No affected entities were found for this CVE.')).toBeInTheDocument()
    );
  });

  it('renders an asset row when matchedSoftware contains an entry with an assetId', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          assetId: 'asset-1',
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assetType: 'HOST',
          ecosystem: 'npm',
          packageName: 'lodash',
          version: '4.17.15',
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
        },
      ],
    }));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());
  });

  it('disables Create Findings when no asset rows are selected', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          assetId: 'asset-1',
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assetType: 'HOST',
          ecosystem: 'npm',
          packageName: 'lodash',
          version: '4.17.15',
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
        },
      ],
    }));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('web-prod-01')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /create findings/i })).toBeDisabled();
  });

  it('renders the Back to CVE button', () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'listFindings').mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByRole('button', { name: /back to cve/i })).toBeInTheDocument();
  });

  it('shows the ASSET / CI column header when table data is loaded', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(buildCveDetail({
      matchedSoftware: [
        {
          componentId: 'cmp-1',
          assetId: 'asset-1',
          assetName: 'web-prod-01',
          assetIdentifier: 'web-prod-01.example.com',
          assetType: 'HOST',
          ecosystem: 'npm',
          packageName: 'lodash',
          version: '4.17.15',
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
        },
      ],
    }));
    vi.spyOn(api, 'listFindings').mockResolvedValue(EMPTY_FINDINGS_PAGE);
    renderPage();
    await waitFor(() => expect(screen.getByText('ASSET / CI')).toBeInTheDocument());
  });
});
