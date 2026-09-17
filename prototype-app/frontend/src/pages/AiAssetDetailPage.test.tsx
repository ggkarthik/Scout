import { screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useLocation } from 'react-router-dom';
import { api } from '../api/client';
import { mockElementDimensionsForReactFlow } from '../features/ai-security/test-support';
import type { AiSecurityArtifact, AiSecurityFinding, AiSecurityPolicy } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiAssetDetailPage } from './AiAssetDetailPage';

function buildArtifact(overrides: Partial<AiSecurityArtifact> = {}): AiSecurityArtifact {
  return {
    id: 'artifact-1',
    provider: 'AZURE',
    providerResourceId: '/subscriptions/abc/resourceGroups/rg/providers/microsoft.botservice/botservices/claims-triage-agent',
    artifactType: 'AI_AGENT',
    nativeKind: 'AZURE_BOT_SERVICES',
    name: 'claims-triage-agent45800',
    accountId: 'abc-123',
    region: 'GLOBAL',
    active: true,
    attributes: { kind: 'azurebot', msaAppType: 'SingleTenant' },
    firstObservedAt: '2026-06-01T00:00:00Z',
    lastObservedAt: '2026-07-30T23:00:00Z',
    ownerName: null,
    ownerState: 'UNOWNED',
    ownerSource: null,
    ownerConfidence: null,
    ownerConfidenceMethod: null,
    ownerConfidenceMethodVersion: null,
    businessCriticality: null,
    environment: null,
    piiScanStatus: 'NOT_APPLICABLE',
    piiSource: null,
    piiInfoTypes: [],
    piiFindingCount: 0,
    piiLastScannedAt: null,
    ...overrides,
  };
}

function buildPolicy(overrides: Partial<AiSecurityPolicy> = {}): AiSecurityPolicy {
  return {
    id: 'AZURE_BOT_PUBLIC_ENDPOINT',
    version: '1.0.0',
    name: 'Public bot endpoint exposed',
    severity: 'HIGH',
    lifecycle: 'PUBLISHED',
    artifactTypes: ['AI_AGENT'],
    requiredResourceFamilies: ['AZURE_BOT_SERVICES'],
    description: 'A bot service exposes a public messaging endpoint without network restrictions.',
    remediation: 'Restrict the endpoint to private networking or add authentication.',
    controlMappings: {},
    available: true,
    enabled: true,
    openFindings: 1,
    lifetimeFindings: 1,
    lastEvaluatedAt: '2026-07-01T00:00:00Z',
    decisionCoverage: 1,
    decisionCoverageThreshold: 0.95,
    decisionCoverageStatus: 'PASS',
    evaluatedArtifacts: 1,
    noDecisionCount: 0,
    ...overrides,
  };
}

function buildFinding(overrides: Partial<AiSecurityFinding> = {}): AiSecurityFinding {
  return {
    id: 'finding-1',
    displayId: 'AIF-001',
    policyId: 'AZURE_BOT_PUBLIC_ENDPOINT',
    policyVersion: '1.0.0',
    artifactId: 'artifact-1',
    artifactName: 'claims-triage-agent45800',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'Public bot endpoint exposed',
    evidence: {},
    reviewDisposition: 'NEEDS_INVESTIGATION',
    firstObservedAt: '2026-06-01T00:00:00Z',
    lastObservedAt: '2026-07-01T00:00:00Z',
    resolvedAt: null,
    ...overrides,
  };
}

function LocationDisplay() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}{location.search}</output>;
}

describe('AiAssetDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the asset identity and opens on the Overview tab by default', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [buildFinding()], page: 0, size: 200, total: 1 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);

    expect(await screen.findByText('claims-triage-agent45800')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Overview' })).toHaveClass('fd3-tab--active');
    expect(screen.getByText('Resource details')).toBeInTheDocument();
    expect(screen.getByText('Observed facts')).toBeInTheDocument();
    expect(screen.queryByText('Public bot endpoint exposed')).not.toBeInTheDocument();
  });

  it('renders array-of-object observed attributes (e.g. guardrail content filters) as readable summaries, not "N items"', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact({
      artifactType: 'OTHER_AI_ARTIFACT',
      nativeKind: 'AWS_BEDROCK_GUARDRAIL',
      attributes: {
        status: 'READY',
        minimumStrength: 'HIGH',
        contentFilterCount: 1,
        contentFilters: [
          { type: 'HATE', inputStrength: 'HIGH', outputStrength: 'HIGH' },
        ],
        deniedTopics: [],
      },
    }));
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);

    expect(await screen.findByText('Observed facts')).toBeInTheDocument();
    // A one-item array of an object renders its fields inline instead of collapsing to "1 item".
    expect(screen.getByText(/type: HATE/)).toBeInTheDocument();
    expect(screen.getByText(/inputStrength: HIGH/)).toBeInTheDocument();
    expect(screen.queryByText('1 item')).not.toBeInTheDocument();
    // An empty array still renders as "None", not an empty/garbled string.
    expect(screen.getByText('None')).toBeInTheDocument();
  });

  it('shows an explicit insufficient-evidence state for unknown data sensitivity', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact({
      artifactType: 'DATA_STORE',
      nativeKind: 'AZURE_STORAGE_ACCOUNT',
      piiScanStatus: 'UNKNOWN',
    }));
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);

    expect(await screen.findByText('Unknown — insufficient evidence')).toBeInTheDocument();
  });

  it('shows applicable policies scoped to this artifact type in the Policies tab', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([
      buildPolicy(),
      buildPolicy({ id: 'OTHER_MODEL_POLICY', name: 'Model-only policy', artifactTypes: ['AI_MODEL'] }),
    ]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [buildFinding()], page: 0, size: 200, total: 1 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);
    await screen.findByText('claims-triage-agent45800');

    fireEvent.click(screen.getByRole('button', { name: /^Policies/ }));
    expect(await screen.findByText('Public bot endpoint exposed')).toBeInTheDocument();
    expect(screen.queryByText('Model-only policy')).not.toBeInTheDocument();
  });

  it('shows only findings scoped to this artifact in the Findings tab', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({
      items: [buildFinding(), buildFinding({ id: 'finding-2', displayId: 'AIF-002', artifactId: 'other-artifact' })],
      page: 0,
      size: 200,
      total: 2,
    });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);
    await screen.findByText('claims-triage-agent45800');

    fireEvent.click(screen.getByRole('button', { name: /^Findings/ }));
    expect(await screen.findByText('AIF-001')).toBeInTheDocument();
    expect(screen.queryByText('AIF-002')).not.toBeInTheDocument();
  });

  it('shows connected resources in the Relationships tab', async () => {
    mockElementDimensionsForReactFlow();
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({
      nodes: [
        buildArtifact(),
        buildArtifact({ id: 'artifact-2', name: 'claims-model', artifactType: 'AI_MODEL', nativeKind: 'AZURE_OPENAI_DEPLOYMENT' }),
      ],
      edges: [{
        id: 'edge-1',
        relationshipType: 'INVOKES_MODEL',
        sourceArtifactId: 'artifact-1',
        sourceName: 'claims-triage-agent45800',
        targetArtifactId: 'artifact-2',
        targetName: 'claims-model',
        attributes: {},
      }],
      truncated: false,
    });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);
    await screen.findByText('claims-triage-agent45800');

    fireEvent.click(screen.getByRole('button', { name: /^Relationships/ }));
    expect(await screen.findByText('claims-model')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'AI artifact dependency graph' })).toBeInTheDocument();
  });

  it('keeps the definition graph visible while runtime activity is loading', async () => {
    mockElementDimensionsForReactFlow();
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    const graph = vi.spyOn(api, 'getAiSecurityGraph')
      .mockResolvedValueOnce({
        nodes: [buildArtifact(), buildArtifact({ id: 'artifact-2', name: 'definition-model', artifactType: 'AI_MODEL' })],
        edges: [{ id: 'edge-1', relationshipType: 'INVOKES_MODEL', sourceArtifactId: 'artifact-1', sourceName: 'claims-triage-agent45800', targetArtifactId: 'artifact-2', targetName: 'definition-model', attributes: {} }],
        truncated: false,
      })
      .mockImplementationOnce(() => new Promise(() => undefined));

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);
    await screen.findByText('claims-triage-agent45800');
    fireEvent.click(screen.getByRole('button', { name: /^Relationships/ }));
    expect(await screen.findByText('definition-model')).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText('Show runtime activity'));
    await waitFor(() => expect(graph).toHaveBeenCalledTimes(2));
    expect(screen.getByText('definition-model')).toBeInTheDocument();
    expect(screen.queryByText('Loading connected resources…')).not.toBeInTheDocument();
  });

  it('applies runtime presets and preserves the empty definition graph when runtime is unavailable', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    const unavailable = {
      nodes: [], edges: [], truncated: false,
      runtimeOverlay: {
        status: 'UNAVAILABLE' as const, diagnostic: 'RUNTIME_OVERLAY_QUERY_FAILED',
        windowStart: '2026-09-10T00:00:00Z', windowEnd: '2026-09-17T00:00:00Z',
        executionCount: 0, resolvedCount: 0, unresolvedCount: 0, notApplicableCount: 0,
        groups: [], edges: [], truncated: false,
      },
    };
    const graph = vi.spyOn(api, 'getAiSecurityGraph')
      .mockResolvedValueOnce({ nodes: [], edges: [], truncated: false })
      .mockResolvedValue(unavailable);

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);
    await screen.findByText('claims-triage-agent45800');
    fireEvent.click(screen.getByRole('button', { name: /^Relationships/ }));
    fireEvent.click(screen.getByLabelText('Show runtime activity'));

    expect(await screen.findByText(/Runtime activity is temporarily unavailable/)).toBeInTheDocument();
    expect(screen.getByText('No active relationships observed for this asset.')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Time range'), { target: { value: '30' } });
    await waitFor(() => expect(graph).toHaveBeenCalledTimes(3));
    const runtimeRequest = graph.mock.calls[graph.mock.calls.length - 1]?.[2];
    expect(runtimeRequest).toBeDefined();
    expect((new Date(runtimeRequest!.to!).getTime() - new Date(runtimeRequest!.from!).getTime()) / 86_400_000).toBe(30);
  });

  it('builds the execution drill-down URL from the selected runtime group and overlay window', async () => {
    mockElementDimensionsForReactFlow();
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph')
      .mockResolvedValueOnce({ nodes: [buildArtifact()], edges: [], truncated: false })
      .mockResolvedValue({
        nodes: [buildArtifact()], edges: [], truncated: false,
        runtimeOverlay: {
          status: 'AVAILABLE', diagnostic: null,
          windowStart: '2026-09-10T00:00:00Z', windowEnd: '2026-09-17T00:00:00Z',
          executionCount: 5, resolvedCount: 5, unresolvedCount: 0, notApplicableCount: 0,
          groups: [{
            id: 'runtime-aggregate:abc', provider: 'AZURE', source: 'AZURE_FOUNDRY_RUNTIME',
            agentArtifactId: 'artifact-1', agentVersionArtifactId: 'version-2', executionCount: 5,
            successCount: 4, failureCount: 1, unknownCount: 0, resolvedCount: 5,
            unresolvedCount: 0, notApplicableCount: 0,
            firstEvidenceTime: '2026-09-10T00:00:00Z', lastEvidenceTime: '2026-09-17T00:00:00Z',
          }],
          edges: [], truncated: false,
        },
      });

    renderWithProviders(<><AiAssetDetailPage artifactId="artifact-1" /><LocationDisplay /></>);
    await screen.findByText('claims-triage-agent45800');
    fireEvent.click(screen.getByRole('button', { name: /^Relationships/ }));
    fireEvent.click(screen.getByLabelText('Show runtime activity'));
    fireEvent.click(await screen.findByText('5 executions'));
    fireEvent.click(await screen.findByRole('button', { name: 'View executions' }));

    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/inventory/ai/executions?'));
    const location = screen.getByTestId('location').textContent ?? '';
    expect(location).toContain('agentId=artifact-1');
    expect(location).toContain('agentVersionId=version-2');
    expect(location).toContain('source=AZURE_FOUNDRY_RUNTIME');
    expect(location).toContain('from=2026-09-10T00%3A00%3A00Z');
    expect(location).toContain('to=2026-09-17T00%3A00%3A00Z');
  });

  it('disables execution drill-down while a new runtime preset is loading', async () => {
    mockElementDimensionsForReactFlow();
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    const runtimeGraph = {
      nodes: [buildArtifact()], edges: [], truncated: false,
      runtimeOverlay: {
        status: 'AVAILABLE' as const, diagnostic: null,
        windowStart: '2026-09-10T00:00:00Z', windowEnd: '2026-09-17T00:00:00Z',
        executionCount: 5, resolvedCount: 5, unresolvedCount: 0, notApplicableCount: 0,
        groups: [{
          id: 'runtime-aggregate:abc', provider: 'AZURE', source: 'AZURE_FOUNDRY_RUNTIME',
          agentArtifactId: 'artifact-1', agentVersionArtifactId: 'version-2', executionCount: 5,
          successCount: 4, failureCount: 1, unknownCount: 0, resolvedCount: 5,
          unresolvedCount: 0, notApplicableCount: 0,
          firstEvidenceTime: '2026-09-10T00:00:00Z', lastEvidenceTime: '2026-09-17T00:00:00Z',
        }],
        edges: [], truncated: false,
      },
    };
    const graph = vi.spyOn(api, 'getAiSecurityGraph')
      .mockResolvedValueOnce({ nodes: [buildArtifact()], edges: [], truncated: false })
      .mockResolvedValueOnce(runtimeGraph)
      .mockImplementationOnce(() => new Promise(() => undefined));

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);
    await screen.findByText('claims-triage-agent45800');
    fireEvent.click(screen.getByRole('button', { name: /^Relationships/ }));
    fireEvent.click(screen.getByLabelText('Show runtime activity'));
    fireEvent.click(await screen.findByText('5 executions'));
    expect(await screen.findByRole('button', { name: 'View executions' })).toBeEnabled();

    fireEvent.change(screen.getByLabelText('Time range'), { target: { value: '30' } });
    await waitFor(() => expect(graph).toHaveBeenCalledTimes(3));
    expect(screen.getByText('5 executions')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View executions' })).toBeDisabled();
  });

  it('shows ownership details for the artifact', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact({
      ownerName: 'Data Platform',
      ownerState: 'CONFIRMED',
      ownerSource: 'Manual confirmation',
    }));
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);
    await screen.findByText('claims-triage-agent45800');

    expect(screen.getByText('Data Platform')).toBeInTheDocument();
    expect(screen.getByText('CONFIRMED')).toBeInTheDocument();
    expect(screen.getByText('Manual confirmation')).toBeInTheDocument();
  });

  it('shows a not-found state for an unknown artifact', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockRejectedValue(new Error('not found'));
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="does-not-exist" />);

    expect(await screen.findByText(/could not be found/)).toBeInTheDocument();
  });
});
