import { screen, fireEvent } from '@testing-library/react';
import { Route, Routes, useParams } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiGridPolicy } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiPoliciesPage } from './AiPoliciesPage';
import { AiPolicyDetailPage } from './AiPolicyDetailPage';

function PolicyDetailRoute() {
  const params = useParams<{ policyId: string }>();
  return <AiPolicyDetailPage policyId={decodeURIComponent(params.policyId ?? '')} />;
}

function renderPoliciesPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/policies" element={<AiPoliciesPage />} />
      <Route path="/policies/:policyId" element={<PolicyDetailRoute />} />
    </Routes>,
    { route: '/policies' }
  );
}

function buildPolicy(overrides: Partial<AiGridPolicy> = {}): AiGridPolicy {
  return {
    policyId: 'AGCF-AWS-001',
    version: '1.0.0',
    name: 'Public knowledge-base S3 source',
    severity: 'CRITICAL',
    lifecycle: 'PUBLISHED',
    workflowClass: 'POSTURE_FINDING',
    selection: 'ENABLED',
    controlObjectiveId: 'AGCF-OBJ-AWS-001',
    provider: 'AWS',
    evaluationMode: 'ARTIFACT_FACTS',
    baseEvidenceTiersJson: '["E0"]',
    conditionalCapabilitiesJson: '[]',
    requiredCapabilitiesJson: '["BEDROCK_KNOWLEDGE_BASES"]',
    frameworkMappingsJson: '[]',
    readiness: 'READY',
    ...overrides,
  };
}

describe('AiPoliciesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders one row per policy with governed metadata and readiness', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicy()]);
    renderPoliciesPage();

    expect(await screen.findByText('Public knowledge-base S3 source')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('AGCF-OBJ-AWS-001')).toBeInTheDocument();
    expect(screen.getByText('Artifact Facts')).toBeInTheDocument();
    expect(screen.getByText('Ready')).toBeInTheDocument();
  });

  it('navigates to the policy detail page when a row is clicked', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([{
      id: 'AGCF-AWS-001', version: '1.0.0', name: 'Public knowledge-base S3 source', severity: 'CRITICAL',
      artifactTypes: [], requiredResourceFamilies: [], description: 'Block public access and restrict the bucket policy.',
      remediation: 'Block public access and restrict the bucket policy.', controlMappings: {}, available: true, enabled: true,
      openFindings: 0, lifetimeFindings: 0, lastEvaluatedAt: null, decisionCoverage: 1, decisionCoverageThreshold: 1,
      decisionCoverageStatus: 'PASS', evaluatedArtifacts: 1, noDecisionCount: 0,
    }]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderPoliciesPage();

    const nameCell = await screen.findByText('Public knowledge-base S3 source');
    fireEvent.click(nameCell.closest('tr')!);

    expect((await screen.findAllByText(/Block public access/)).length).toBeGreaterThan(0);
    expect(screen.getByRole('heading', { name: 'Public knowledge-base S3 source' })).toBeInTheDocument();
  });

  it('groups by provider and opens metadata in the policy overview', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([
      buildPolicy({
        policyId: 'AGCF-AWS-013', name: 'Sensitive-data agent lacks PII guardrail',
        conditionalCapabilitiesJson: '["MACIE_CLASSIFICATION"]',
        frameworkMappingsJson: JSON.stringify([{ framework: 'OWASP_GENAI_LLM_TOP_10', frameworkVersion: '2026', controlId: 'LLM02', mappingType: 'DIRECT', rationale: 'PII guardrail reduces sensitive disclosure.' }]),
      }),
      buildPolicy({ policyId: 'AGCF-AZR-001', name: 'Azure public network access', provider: 'AZURE' }),
    ]);
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([{
      id: 'AGCF-AWS-013', version: '1.0.0', name: 'Sensitive-data agent lacks PII guardrail', severity: 'CRITICAL',
      artifactTypes: [], requiredResourceFamilies: [], description: 'Require a PII guardrail.',
      remediation: 'Attach a PII guardrail.', controlMappings: {}, available: true, enabled: true,
      openFindings: 0, lifetimeFindings: 0, lastEvaluatedAt: null, decisionCoverage: 1, decisionCoverageThreshold: 1,
      decisionCoverageStatus: 'PASS', evaluatedArtifacts: 1, noDecisionCount: 0,
    }]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderPoliciesPage();

    await screen.findByText('Sensitive-data agent lacks PII guardrail');
    // Two provider groups render as separate section headings.
    expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(2);
    // A conditional-capability policy is flagged, but metadata is no longer inline.
    expect(screen.getByText(/needs capability/)).toBeInTheDocument();
    expect(screen.queryByText('Required connector capabilities')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Sensitive-data agent lacks PII guardrail').closest('tr')!);

    expect(await screen.findByText('Required connector capabilities')).toBeInTheDocument();
    expect(screen.getByText('DIRECT')).toBeInTheDocument();
    expect(screen.getByText('PII guardrail reduces sensitive disclosure.')).toBeInTheDocument();
  });

  it('filters rows by severity pill and by search text', async () => {
    vi.spyOn(api, 'listAiGridPolicies').mockResolvedValue([
      buildPolicy(),
      buildPolicy({ policyId: 'AGCF-AZR-001', name: 'Unauthenticated action-group Lambda URL', severity: 'HIGH', provider: 'AZURE' }),
    ]);
    renderPoliciesPage();

    expect(await screen.findByText('Public knowledge-base S3 source')).toBeInTheDocument();
    expect(screen.getByText('Unauthenticated action-group Lambda URL')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'High' }));
    expect(screen.queryByText('Public knowledge-base S3 source')).not.toBeInTheDocument();
    expect(screen.getByText('Unauthenticated action-group Lambda URL')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'All' }));
    fireEvent.change(screen.getByPlaceholderText('Search policies'), { target: { value: 'knowledge-base' } });
    expect(screen.getByText('Public knowledge-base S3 source')).toBeInTheDocument();
    expect(screen.queryByText('Unauthenticated action-group Lambda URL')).not.toBeInTheDocument();
  });
});
