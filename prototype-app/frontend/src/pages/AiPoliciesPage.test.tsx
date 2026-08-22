import { screen, fireEvent } from '@testing-library/react';
import { Route, Routes, useParams } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiSecurityPolicy } from '../features/ai-security/types';
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

function buildPolicy(overrides: Partial<AiSecurityPolicy> = {}): AiSecurityPolicy {
  return {
    id: 'AWS_BEDROCK_PUBLIC_KB_S3',
    version: '1.0.0',
    name: 'Public knowledge-base S3 source',
    severity: 'CRITICAL',
    artifactTypes: ['AI_MODEL'],
    requiredResourceFamilies: ['BEDROCK_KNOWLEDGE_BASES', 'S3_EXPOSURE'],
    description: 'A Bedrock knowledge base uses an S3 data source that is publicly accessible.',
    remediation: 'Block public access and restrict the bucket policy to the knowledge-base execution role.',
    controlMappings: {},
    available: true,
    enabled: true,
    openFindings: 2,
    lifetimeFindings: 5,
    lastEvaluatedAt: null,
    decisionCoverage: 0,
    decisionCoverageThreshold: 1,
    decisionCoverageStatus: 'NO_DATA',
    evaluatedArtifacts: 0,
    noDecisionCount: 0,
    ...overrides,
  };
}

describe('AiPoliciesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders one row per policy with severity, evidence, coverage and findings columns', async () => {
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    renderPoliciesPage();

    expect(await screen.findByText('Public knowledge-base S3 source')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('BEDROCK_KNOWLEDGE_BASES · S3_EXPOSURE')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('navigates to the policy detail page when a row is clicked', async () => {
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([buildPolicy()]);
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 200, total: 0 });
    renderPoliciesPage();

    const nameCell = await screen.findByText('Public knowledge-base S3 source');
    fireEvent.click(nameCell.closest('tr')!);

    expect(await screen.findByText(/Block public access/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Public knowledge-base S3 source' })).toBeInTheDocument();
  });

  it('filters rows by severity pill and by search text', async () => {
    vi.spyOn(api, 'listAiGridPolicyDetails').mockResolvedValue([
      buildPolicy(),
      buildPolicy({ id: 'AZURE_UNAUTH_LAMBDA', name: 'Unauthenticated action-group Lambda URL', severity: 'HIGH' }),
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
