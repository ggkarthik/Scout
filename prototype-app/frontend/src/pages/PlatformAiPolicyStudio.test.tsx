import { fireEvent, screen, waitFor, within } from '@testing-library/react';
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

  it('provides three focused Policy Studio workspaces with keyboard tab navigation', () => {
    stubBaselineQueries();
    vi.spyOn(api, 'getPlatformAiGridFrameworkCoverage').mockResolvedValue([]);

    renderWithProviders(<PlatformAiPolicyStudio />);

    const navigation = screen.getByRole('tablist', { name: 'AI Policy Studio sections' });
    const overview = within(navigation).getByRole('tab', { name: /^Overview/i });
    expect(overview).toHaveAttribute('aria-selected', 'true');
    expect(within(navigation).getByRole('tab', { name: /^Policies/i })).toBeInTheDocument();
    expect(within(navigation).getByRole('tab', { name: /^Governance/i })).toBeInTheDocument();
    expect(within(navigation).queryByRole('tab', { name: /^Catalog/i })).not.toBeInTheDocument();

    fireEvent.keyDown(overview, { key: 'ArrowRight' });
    expect(within(navigation).getByRole('tab', { name: /^Policies/i })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('heading', { name: 'Policies' })).toBeVisible();
  });

  it('routes Overview attention cards to the matching workspace', async () => {
    stubBaselineQueries();
    vi.spyOn(api, 'getPlatformAiGridFrameworkCoverage').mockResolvedValue([{ controlId: 'LLM08', coverageStatus: 'NOT_COVERED', policies: [] }]);

    renderWithProviders(<PlatformAiPolicyStudio />);

    fireEvent.click(await screen.findByRole('button', { name: /framework coverage gaps/i }));
    expect(screen.getByRole('tab', { name: /^Governance/i })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('heading', { name: /OWASP GenAI LLM Top 10/i })).toBeVisible();

    fireEvent.click(screen.getByRole('tab', { name: /^Overview/i }));
    fireEvent.click(screen.getByRole('button', { name: /policies in canary/i }));
    expect(screen.getByRole('tab', { name: /^Policies/i })).toHaveAttribute('aria-selected', 'true');
  });

  it('does not misreport a request failure as a zero-policy catalog mismatch and can retry', async () => {
    stubBaselineQueries();
    vi.spyOn(api, 'getPlatformAiGridFrameworkCoverage').mockResolvedValue([]);
    vi.mocked(api.listPlatformAiGridPolicies)
      .mockRejectedValueOnce(new Error('Request failed (500)'))
      .mockResolvedValueOnce([]);

    renderWithProviders(<PlatformAiPolicyStudio />);
    fireEvent.click(screen.getByRole('tab', { name: /^Policies/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent('The governed policy catalog could not be loaded.');
    expect(screen.queryByText(/Catalog mismatch: expected 76.*received 0/i)).not.toBeInTheDocument();
    expect(screen.queryByText('No Phase 1 policies match these filters.')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Retry catalog' }));

    await waitFor(() => expect(api.listPlatformAiGridPolicies).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/Catalog mismatch: expected 76.*received 0/i)).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
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
    fireEvent.click(screen.getByRole('tab', { name: /^Governance/i }));

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
    fireEvent.click(screen.getByRole('tab', { name: /^Governance/i }));

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
    fireEvent.click(screen.getByRole('tab', { name: /^Policies/i }));

    const summary = await screen.findByRole('region', { name: 'Phase 1 out-of-box catalog summary' });
    expect(await within(summary).findAllByText('76')).toHaveLength(2);
    expect(within(summary).getByText('0')).toBeInTheDocument();
    expect(screen.getAllByText(/AGCF-AWS-001/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AGCF-AZR-001/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AGCF-XSP-001/).length).toBeGreaterThan(0);
    expect(screen.getAllByText('VALIDATED')).toHaveLength(76);
    expect(screen.getAllByRole('combobox', { name: /rollout$/i })).toHaveLength(76);
  });
});
