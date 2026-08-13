import { screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiSecurityFinding } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiFindingsPage } from './AiFindingsPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

function buildFinding(overrides: Partial<AiSecurityFinding> = {}): AiSecurityFinding {
  return {
    id: 'finding-1',
    displayId: 'AIF-101B8AF0',
    policyId: 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER',
    policyVersion: '1.0.0',
    artifactId: 'artifact-1',
    artifactName: 'Guardrails73',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'Azure RAI policy contains a non-blocking filter',
    evidence: {},
    reviewDisposition: 'UNREVIEWED',
    firstObservedAt: '2026-08-04T15:22:15Z',
    lastObservedAt: '2026-08-05T15:22:15Z',
    resolvedAt: null,
    ...overrides,
  };
}

describe('AiFindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('navigates to the AI finding detail page when a row is clicked', async () => {
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({
      items: [buildFinding()],
      page: 0,
      size: 100,
      total: 1,
    });

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai' });

    fireEvent.click(await screen.findByText('AIF-101B8AF0'));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith('/findings/ai/finding-1?returnTo=%2Ffindings%2Fai'));
  });

  it('reads severity and nativeKind filters from the URL when arriving from the severity grid', async () => {
    const listFindings = vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({
      items: [buildFinding()],
      page: 0,
      size: 100,
      total: 1,
    });

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai?severity=HIGH&nativeKind=AWS_BEDROCK_GUARDRAIL' });

    await screen.findByText('AIF-101B8AF0');

    await waitFor(() => expect(listFindings).toHaveBeenCalledWith(
      undefined,
      'OPEN',
      0,
      100,
      undefined,
      undefined,
      'HIGH',
      'AWS_BEDROCK_GUARDRAIL',
    ));
  });

  it('shows an empty state when no findings match the filters', async () => {
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 100, total: 0 });

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai' });

    expect(await screen.findByText('No matching AI findings')).toBeInTheDocument();
  });
});
