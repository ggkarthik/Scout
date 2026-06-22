import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { api, getStoredAuthToken } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { PlatformConsolePage } from './PlatformConsolePage';
import { createTestQueryClient } from '../test/test-utils';

const PLATFORM_SCOPE_OWNER: ActorContext = {
  creator: true,
  principal: 'owner@example.com',
  userId: 'owner@example.com',
  tenantId: null,
  tenantName: null,
  roles: ['PLATFORM_OWNER'],
  platformScope: true,
  actingAsPlatformOwner: false,
  allowedTenants: [{
    id: 'tenant-a',
    name: 'Tenant A',
    slug: 'tenant-a',
    role: 'PLATFORM_OWNER',
    accessMode: 'READ_ONLY',
    expiresAt: '2026-12-31T00:00:00Z'
  }]
};

describe('PlatformConsolePage tenant context controls', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
  });

  it('switches into tenant context with a fresh token', async () => {
    vi.spyOn(api, 'listTenants').mockResolvedValue([{
      id: 'tenant-a',
      name: 'Tenant A',
      slug: 'tenant-a',
      status: 'ACTIVE',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: null,
      maxServiceAccountCount: null,
      maxDailySbomUploads: null,
      maxExportRows: null,
      maxDailyExposureRefreshes: null,
      createdAt: '2026-06-01T00:00:00Z',
      updatedAt: null
    }]);
    vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
    vi.spyOn(api, 'selectTenantContext').mockResolvedValue({
      token: 'tenant-context-token',
      tokenType: 'Bearer',
      expiresAt: '2026-06-30T00:00:00Z'
    });

    const queryClient = createTestQueryClient();
    renderPlatformTenants(PLATFORM_SCOPE_OWNER, queryClient);

    fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));

    await waitFor(() => {
      expect(getStoredAuthToken()).toBe('tenant-context-token');
    });
  });

  it('returns an acting platform owner back to platform scope', async () => {
    vi.spyOn(api, 'listTenants').mockResolvedValue([{
      id: 'tenant-a',
      name: 'Tenant A',
      slug: 'tenant-a',
      status: 'ACTIVE',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: null,
      maxServiceAccountCount: null,
      maxDailySbomUploads: null,
      maxExportRows: null,
      maxDailyExposureRefreshes: null,
      createdAt: '2026-06-01T00:00:00Z',
      updatedAt: null
    }]);
    vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
    vi.spyOn(api, 'clearTenantContext').mockResolvedValue({
      token: 'platform-scope-token',
      tokenType: 'Bearer',
      expiresAt: '2026-06-30T00:00:00Z'
    });

    const queryClient = createTestQueryClient();
    renderPlatformTenants({
      ...PLATFORM_SCOPE_OWNER,
      tenantId: 'tenant-a',
      tenantName: 'Tenant A',
      platformScope: false,
      actingAsPlatformOwner: true
    }, queryClient);

    fireEvent.click(await screen.findByRole('button', { name: 'Return to platform scope' }));

    await waitFor(() => {
      expect(getStoredAuthToken()).toBe('platform-scope-token');
    });
  });

  it('renders backend-provided tenant attention and connector issue data in operations overview', async () => {
    mockOperationsApi({
      tenantAttention: [{
        tenantId: 'tenant-a',
        tenantName: 'Tenant A',
        tenantStatus: 'SUSPENDED',
        reasons: ['TENANT_SUSPENDED', 'CONNECTOR_ERROR'],
        affectedConnectors: ['aws'],
        latestRelevantSyncAt: '2026-06-20T10:00:00Z'
      }],
      connectorIssues: [{
        connectorKey: 'aws',
        affectedTenantCount: 1,
        affectedTenants: ['Tenant A']
      }]
    });

    renderPlatformOperations();

    expect(await screen.findByText('Tenant Attention Queue')).toBeInTheDocument();
    expect(screen.getAllByText('Tenant A')).toHaveLength(2);
    expect(screen.getByText('Tenant suspended, Connector error')).toBeInTheDocument();
    expect(screen.getAllByText('aws')).toHaveLength(2);
    expect(screen.getByText('Connector Issues')).toBeInTheDocument();
    expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(2);
  });

  it('renders operations empty states when no tenants or connectors need attention', async () => {
    mockOperationsApi();

    renderPlatformOperations();

    expect(await screen.findByText('No tenant currently requires attention')).toBeInTheDocument();
    expect(screen.getByText('No tenants currently impacted')).toBeInTheDocument();
  });

  it('shows info-icon help text for the new operations overview metrics', async () => {
    mockOperationsApi();

    renderPlatformOperations();

    expect(await screen.findByRole('button', {
      name: /Tenants With Connector Issues: Number of distinct tenants that currently have at least one unhealthy connector\./
    })).toBeInTheDocument();

    expect(screen.getByRole('button', {
      name: /Affected Tenants: The tenants currently impacted by this connector problem\./
    })).toBeInTheDocument();
  });
});

function renderPlatformTenants(actor: ActorContext, queryClient: ReturnType<typeof createTestQueryClient>) {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/platform/tenants']}>
        <ActorContextState.Provider value={actor}>
          <Routes>
            <Route path="/platform/tenants" element={<PlatformConsolePage selectedView="tenants" />} />
            <Route path="/" element={<div>Tenant Dashboard</div>} />
          </Routes>
        </ActorContextState.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function renderPlatformOperations() {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/platform/operations?ops=overview']}>
        <Routes>
          <Route path="/platform/operations" element={<PlatformConsolePage selectedView="operations" />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function mockOperationsApi({
  tenantAttention = [],
  connectorIssues = []
}: {
  tenantAttention?: Awaited<ReturnType<typeof api.getOperationalTenantAttention>>;
  connectorIssues?: Awaited<ReturnType<typeof api.getOperationalConnectorIssues>>;
} = {}) {
  vi.spyOn(api, 'getOperationalOverview').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      ingestionSuccessRateLast24h: 98.2,
      recomputeP95Ms: 2200,
      normalizationCoveragePercent: 97.4,
      correlationNoiseReductionPercent: 42.1,
      openCriticalFindings: 3
    }
  });
  vi.spyOn(api, 'getOperationalIngestionEfficiency').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      sbomIngestionsLast24h: 12,
      sbomIngestionsPerHour: 0.5,
      sbomSuccessRatePercent: 100,
      syncRunsLast24h: 24,
      syncSuccessRatePercent: 95,
      queueBacklog: 0,
      recordsFetchedLast24h: 1000,
      recordsInsertedLast24h: 200,
      recordsUpdatedLast24h: 300,
      sourceBreakdown: []
    }
  });
  vi.spyOn(api, 'getOperationalFreshnessDrift').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      staleThresholdHours: 24,
      staleSourceCount: 0,
      normalizationCoverageDrift7d: 0,
      cpeFallbackShareDrift7d: 0,
      sourceFreshness: []
    }
  });
  vi.spyOn(api, 'getOperationalQualitySummary').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    totalIssues: 0,
    criticalIssues: 0,
    affectsActiveFindingsCount: 0,
    newIssuesLast24h: 0,
    domainCounts: []
  });
  vi.spyOn(api, 'getOperationalApiReadPath').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      summaryReadModelReady: true,
      canonicalCveCount: 0,
      summaryCveCount: 0,
      summaryCoveragePercent: 100,
      filterCacheActive: true,
      filterCacheExpiresAt: undefined,
      filterCacheHits: 0,
      filterCacheMisses: 0,
      filterCacheHitRatioPercent: 100,
      endpointMetrics: []
    }
  });
  vi.spyOn(api, 'getSloStatus').mockResolvedValue({
    evaluatedAt: '2026-06-22T00:00:00Z',
    overallCompliant: true,
    slos: []
  });
  vi.spyOn(api, 'listTenants').mockResolvedValue([]);
  vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
  vi.spyOn(api, 'getOperationalTenantAttention').mockResolvedValue(tenantAttention);
  vi.spyOn(api, 'getOperationalConnectorIssues').mockResolvedValue(connectorIssues);
}
