import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiAgentExecution } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiAgentExecutionsPage } from './AiAgentExecutionsPage';

const EXECUTION: AiAgentExecution = {
  id: 'execution-1',
  provider: 'AZURE',
  agentArtifactId: 'agent-1',
  agentVersionArtifactId: 'version-2',
  correlationStatus: 'RESOLVED',
  correlationDiagnostic: 'MATCHED_AGENT_VERSION',
  source: 'AZURE_FOUNDRY_RUNTIME',
  startedAt: '2026-09-16T10:00:00Z',
  completedAt: '2026-09-16T10:00:02Z',
  status: 'COMPLETED',
  outcomeCategory: 'SUCCESS',
  approvalState: null,
  policyState: null,
  classification: null,
  apiVersion: '2026-01-01',
  tokenCount: 42,
  latencyMs: 2_000,
  retryCount: 0,
  spendMicros: null,
  evidenceTime: '2026-09-16T10:00:02Z',
};

describe('AiAgentExecutionsPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('initializes drill-down filters from the URL and refetches when a filter changes', async () => {
    const list = vi.spyOn(api, 'listAiAgentExecutions').mockResolvedValue({
      items: [EXECUTION], page: 0, size: 50, total: 1,
    });

    renderWithProviders(<AiAgentExecutionsPage />, {
      route: '/inventory/ai/executions?agentId=agent-1&agentVersionId=version-2&source=AZURE_FOUNDRY_RUNTIME&from=2026-09-16T00%3A00%3A00Z&to=2026-09-17T00%3A00%3A00Z',
    });

    expect(await screen.findByText('MATCHED AGENT VERSION')).toBeInTheDocument();
    expect(screen.getByLabelText('Agent ID')).toHaveValue('agent-1');
    expect(screen.getByLabelText('Agent version ID')).toHaveValue('version-2');
    expect(screen.getByLabelText('Source')).toHaveValue('AZURE_FOUNDRY_RUNTIME');
    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.objectContaining({
      agentId: 'agent-1', agentVersionId: 'version-2', source: 'AZURE_FOUNDRY_RUNTIME',
    })));

    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'FAILED' } });
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ status: 'FAILED' })));
  });
});
