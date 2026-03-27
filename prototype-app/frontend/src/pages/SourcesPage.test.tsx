import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { SourcesPage } from './SourcesPage';

describe('SourcesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does not enter a refetch loop on source drill-down pages', async () => {
    const listSyncRunsSpy = vi.spyOn(api, 'listSyncRuns').mockResolvedValue([]);
    const getSourceFilterConfigSpy = vi.spyOn(api, 'getVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd',
      configured: true,
      isVulnerable: false,
      hasKev: false,
      knownRansomwareCampaignUse: false
    });

    const view = renderWithProviders(
      <SourcesPage
        focusSource="nvd"
        showQueue={false}
      />
    );

    await screen.findByRole('button', { name: 'Save Filters' });
    await waitFor(() => {
      expect(listSyncRunsSpy).toHaveBeenCalledTimes(1);
      expect(getSourceFilterConfigSpy).toHaveBeenCalledTimes(1);
    });

    view.rerender(
      <SourcesPage
        focusSource="nvd"
        showQueue={false}
        refreshSignal={1}
      />
    );

    await waitFor(() => {
      expect(listSyncRunsSpy).toHaveBeenCalledTimes(2);
      expect(getSourceFilterConfigSpy).toHaveBeenCalledTimes(2);
    });
  });
});
