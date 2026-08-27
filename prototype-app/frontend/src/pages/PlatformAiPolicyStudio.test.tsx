import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiGridControlCoverage, AiGridPolicyDistribution, AiGridPolicySelection } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { PlatformAiPolicyStudio } from './PlatformAiPolicyStudio';

function stubBaselineQueries() {
  vi.spyOn(api, 'listPlatformAiGridPolicies').mockResolvedValue([]);
  vi.spyOn(api, 'listTenants').mockResolvedValue([]);
  vi.spyOn(api, 'getPlatformAiGridPolicyCandidates').mockResolvedValue([]);
  vi.spyOn(api, 'getPlatformAiGridPhase1CertificationReadiness').mockResolvedValue({
    totalPolicies: 0, answerKeyReadyPolicies: 0, precisionReadyPolicies: 0,
    releaseReadyPolicies: 0, pendingPolicies: 0, policies: [],
  });
  vi.spyOn(api, 'getPlatformAiGridPhase1CorpusReadiness').mockResolvedValue({
    sourceManifestDigest: 'x', totalPolicies: 0, certifiedEnvironments: 0,
    draftEnvironments: 0, missingEnvironments: 0, blockedEnvironments: 0, environments: [],
  });
}

describe('PlatformAiPolicyStudio framework coverage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders coverage classification, mapped policy, mapping type and rationale', async () => {
    stubBaselineQueries();
    const coverage: AiGridControlCoverage[] = [
      { controlId: 'LLM01', coverageStatus: 'CONDITIONAL_AUTOMATED', policies: [
        { policyId: 'AGCF-AWS-002', provider: 'AWS', mappingType: 'PARTIAL',
          rationale: 'Guardrail strength reduces prompt-injection risk.', conditional: true, baseEvidenceTiersJson: '["E0"]' },
      ] },
      { controlId: 'LLM08', coverageStatus: 'NOT_COVERED', policies: [] },
    ];
    vi.spyOn(api, 'getPlatformAiGridFrameworkCoverage').mockResolvedValue(coverage);

    renderWithProviders(<PlatformAiPolicyStudio />);

    // Coverage-classification enum is surfaced (not a raw policy count).
    expect(await screen.findByText('Conditional (needs connector capability)')).toBeInTheDocument();
    expect(screen.getByText('Not covered')).toBeInTheDocument();
    // Mapped policy id, mapping type and independently-authored rationale are shown.
    expect(screen.getByText('AGCF-AWS-002')).toBeInTheDocument();
    expect(screen.getByText('PARTIAL')).toBeInTheDocument();
    expect(screen.getByText('Guardrail strength reduces prompt-injection risk.')).toBeInTheDocument();
    // An uncovered OWASP risk renders as "No mapped policy", not as coverage.
    expect(screen.getByText('No mapped policy')).toBeInTheDocument();
  });

  it('states the honesty disclaimer and avoids framework-compliance claims', async () => {
    stubBaselineQueries();
    vi.spyOn(api, 'getPlatformAiGridFrameworkCoverage').mockResolvedValue([]);

    renderWithProviders(<PlatformAiPolicyStudio />);

    const panel = (await screen.findByText(/OWASP GenAI LLM Top 10 \(2026\) coverage/)).closest('div');
    expect(panel).not.toBeNull();
    expect(within(panel as HTMLElement).getByText(/not framework certification or complete runtime protection/i))
      .toBeInTheDocument();
    expect(screen.queryByText(/OWASP compliant/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/AICM certified/i)).not.toBeInTheDocument();
  });

  it('renders the complete paused Phase 1 catalog with exact provider and default summaries', async () => {
    stubBaselineQueries();
    const ids = [
      ...Array.from({ length: 38 }, (_, index) => `AGCF-AWS-${String(index + 1).padStart(3, '0')}`),
      ...Array.from({ length: 32 }, (_, index) => `AGCF-AZR-${String(index + 1).padStart(3, '0')}`),
      ...Array.from({ length: 6 }, (_, index) => `AGCF-XSP-${String(index + 1).padStart(3, '0')}`),
    ];
    const policies: AiGridPolicyDistribution[] = ids.map((policyId, index) => {
      const defaultSelection: AiGridPolicySelection = index < 26 ? 'REQUIRED' : index < 50 ? 'ENABLED' : 'DISABLED';
      return {
        policyId, available: false, defaultSelection, rolloutStage: 'PAUSED', canaryTenantIdsJson: '[]',
        pinnedVersion: null, updatedBy: 'seed', updatedAt: '2026-08-27T00:00:00Z', version: '1.0.0',
        name: `${policyId} governed policy`, severity: 'HIGH', lifecycle: 'VALIDATED',
        provider: policyId.includes('-AWS-') ? 'AWS' : policyId.includes('-AZR-') ? 'AZURE' : 'MULTI_CLOUD',
        releaseFamily: 'AGCF_PHASE_1', releaseWave: 'PHASE_1',
      };
    });
    vi.mocked(api.listPlatformAiGridPolicies).mockResolvedValue(policies);
    vi.spyOn(api, 'getPlatformAiGridFrameworkCoverage').mockResolvedValue([]);

    renderWithProviders(<PlatformAiPolicyStudio />);

    const summary = await screen.findByRole('region', { name: 'Phase 1 out-of-box catalog summary' });
    expect(await within(summary).findAllByText('76')).toHaveLength(3);
    expect(within(summary).getByText('38')).toBeInTheDocument();
    expect(within(summary).getByText('32')).toBeInTheDocument();
    expect(within(summary).getByText('24')).toBeInTheDocument();
    expect(screen.getAllByText(/AGCF-AWS-001/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AGCF-AZR-001/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AGCF-XSP-001/).length).toBeGreaterThan(0);
    expect(screen.getAllByText('VALIDATED')).toHaveLength(76);
    expect(screen.getAllByRole('combobox', { name: /rollout$/i })).toHaveLength(76);
  });
});
