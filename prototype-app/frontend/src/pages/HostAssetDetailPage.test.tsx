import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { HostAssetDetailPage } from './HostAssetDetailPage';

const EMPTY_BOM_EVIDENCE = {
  documentCount: 0,
  componentCount: 0,
  evidenceCount: 0,
  vulnerabilityLinkCount: 0,
  componentsInWorkflow: 0,
  documents: [],
  components: [],
};

function buildHostDetail(overrides = {}) {
  return {
    host: {
      assetId: 'asset-1',
      ciId: 'ci-1',
      name: 'web-prod-01',
      identifier: 'web-prod-01.example.com',
      sysId: 'sys-1',
      aliasCount: 0,
      installedSoftwareCount: 3,
      openFindingCount: 1,
      totalFindingCount: 1,
      unresolvedReviewCount: 0,
      ...overrides,
    },
    aliases: [],
    software: [],
    findings: [],
    applicableCves: [],
    bomEvidence: EMPTY_BOM_EVIDENCE,
  };
}

describe('HostAssetDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while host detail is fetching', () => {
    vi.spyOn(api, 'getHostAssetDetail').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    expect(screen.getByText('Loading host detail...')).toBeInTheDocument();
  });

  it('renders host name after detail loads', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('web-prod-01')).toBeInTheDocument()
    );
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders host identifier below host name', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('web-prod-01.example.com')).toBeInTheDocument()
    );
  });

  it('shows error notice when host detail fetch fails', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockRejectedValue(new Error('Asset not found'));
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('Asset not found')).toBeInTheDocument()
    );
  });

  it('renders the Ownership section label after data loads', async () => {
    vi.spyOn(api, 'getHostAssetDetail').mockResolvedValue(buildHostDetail());
    renderWithProviders(<HostAssetDetailPage assetId="asset-1" />);
    await waitFor(() =>
      expect(screen.getByText('Ownership')).toBeInTheDocument()
    );
  });

  it('does not show loading when no assetId is provided', () => {
    renderWithProviders(<HostAssetDetailPage />);
    expect(screen.queryByText('Loading host detail...')).not.toBeInTheDocument();
  });
});
