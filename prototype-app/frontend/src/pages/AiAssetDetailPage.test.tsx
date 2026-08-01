import { screen, fireEvent } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
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
    ...overrides,
  };
}

function buildPolicy(overrides: Partial<AiSecurityPolicy> = {}): AiSecurityPolicy {
  return {
    id: 'AZURE_BOT_PUBLIC_ENDPOINT',
    version: '1.0.0',
    name: 'Public bot endpoint exposed',
    severity: 'HIGH',
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

describe('AiAssetDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the asset identity and its applicable policies by default', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiSecurityPolicies').mockResolvedValue([
      buildPolicy(),
      buildPolicy({ id: 'OTHER_MODEL_POLICY', name: 'Model-only policy', artifactTypes: ['AI_MODEL'] }),
    ]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [buildFinding()], page: 0, size: 200, total: 1 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="artifact-1" />);

    expect(await screen.findByText('claims-triage-agent45800')).toBeInTheDocument();
    expect(screen.getByText('Public bot endpoint exposed')).toBeInTheDocument();
    expect(screen.queryByText('Model-only policy')).not.toBeInTheDocument();
  });

  it('shows only findings scoped to this artifact in the Findings tab', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiSecurityPolicies').mockResolvedValue([buildPolicy()]);
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
    vi.spyOn(api, 'getAiSecurityArtifact').mockResolvedValue(buildArtifact());
    vi.spyOn(api, 'listAiSecurityPolicies').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({
      nodes: [],
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
    expect(screen.getByText('INVOKES MODEL')).toBeInTheDocument();
  });

  it('shows a not-found state for an unknown artifact', async () => {
    vi.spyOn(api, 'getAiSecurityArtifact').mockRejectedValue(new Error('not found'));
    vi.spyOn(api, 'listAiSecurityPolicies').mockResolvedValue([]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    vi.spyOn(api, 'getAiSecurityGraph').mockResolvedValue({ nodes: [], edges: [], truncated: false });

    renderWithProviders(<AiAssetDetailPage artifactId="does-not-exist" />);

    expect(await screen.findByText(/could not be found/)).toBeInTheDocument();
  });
});
