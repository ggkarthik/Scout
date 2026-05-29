import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { PlatformConnectorsPage } from './PlatformConnectorsPage';

describe('PlatformConnectorsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('keeps tenant integrations history selected without routing back to vulnerability sources', async () => {
    vi.spyOn(api, 'getVulnIntelSourcesSummary').mockResolvedValue({ sources: {} });
    vi.spyOn(api, 'listPlatformInventoryConnectorHealth').mockResolvedValue([]);
    const onViewChange = vi.fn();

    renderWithProviders(
      <PlatformConnectorsPage initialView="connectors" onViewChange={onViewChange} />
    );

    fireEvent.click(screen.getByRole('button', { name: 'Tenant Integrations History' }));

    expect(await screen.findByRole('heading', { name: 'Tenant Integrations History' })).toBeInTheDocument();
    expect(screen.queryByText('Vulnerability Sources')).not.toHaveClass('active');
    expect(onViewChange).not.toHaveBeenCalled();
  });
});
