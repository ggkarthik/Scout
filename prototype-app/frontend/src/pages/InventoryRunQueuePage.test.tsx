import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { InventoryRunQueuePage } from './InventoryRunQueuePage';

describe('InventoryRunQueuePage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('shows AWS and Azure AI discovery progress with provider details and errors', async () => {
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([
      {
        id: 'aws-run',
        syncType: 'AI_SECURITY_AWS_BEDROCK',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'running',
        queuePosition: 1,
        recordsFetched: 8,
        recordsInserted: 8,
        recordsUpdated: 0,
        recordsFailed: 0,
        startedAt: '2026-07-29T09:00:00Z',
        metadataJson: JSON.stringify({
          provider: 'AWS',
          connectorId: 'aws-connector',
          accountId: '123456789012',
          regions: ['us-east-1', 'us-west-2'],
        }),
      },
      {
        id: 'azure-run',
        syncType: 'AI_SECURITY_AZURE_DISCOVERY',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'failed',
        recordsFetched: 3,
        recordsInserted: 3,
        recordsUpdated: 0,
        recordsFailed: 1,
        startedAt: '2026-07-29T08:00:00Z',
        completedAt: '2026-07-29T08:00:15Z',
        errorMessage: 'Azure AI Security discovery failed',
        metadataJson: JSON.stringify({
          provider: 'AZURE',
          connectorId: 'azure-connector',
          subscriptionId: 'sub-1',
          families: ['AZURE_AI_ACCOUNTS'],
        }),
      },
      {
        id: 'azure-cloud-run',
        syncType: 'AZURE_DISCOVERY',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'queued',
        queuePosition: 2,
        recordsFetched: 0,
        recordsInserted: 0,
        recordsUpdated: 0,
        recordsFailed: 0,
        startedAt: '2026-07-29T09:05:00Z',
        metadataJson: JSON.stringify({
          sourceSystem: 'azure',
          azureTenantId: 'tenant-1',
          subscriptionIds: ['sub-1'],
          regions: ['eastus'],
        }),
      },
      {
        id: 'aws-cloud-run',
        syncType: 'AWS_DISCOVERY',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'queued',
        queuePosition: 3,
        recordsFetched: 0,
        recordsInserted: 0,
        recordsUpdated: 0,
        recordsFailed: 0,
        startedAt: '2026-07-29T09:06:00Z',
        metadataJson: JSON.stringify({
          sourceSystem: 'aws',
          awsAccountId: '123456789012',
          regions: ['us-east-1'],
          resourceTypes: ['EC2', 'SSM'],
        }),
      },
    ]);

    renderWithProviders(<InventoryRunQueuePage />);

    const awsType = await screen.findByText('AWS AI Discovery');
    expect(awsType.closest('a')).toHaveAttribute('href', '/inventory/ai');
    const awsRow = awsType.closest('tr');
    expect(awsRow).not.toBeNull();
    expect(within(awsRow as HTMLTableRowElement).getByText('Running')).toBeInTheDocument();
    expect(within(awsRow as HTMLTableRowElement).getByText('Running now')).toBeInTheDocument();
    expect(within(awsRow as HTMLTableRowElement).getByText('8')).toBeInTheDocument();

    const azureType = screen.getByText('Azure AI Discovery');
    const azureRow = azureType.closest('tr');
    expect(azureRow).not.toBeNull();
    expect(within(azureRow as HTMLTableRowElement).getByText('Failed')).toBeInTheDocument();

    within(azureRow as HTMLTableRowElement).getByText('Details').click();
    expect(within(azureRow as HTMLTableRowElement).getByText(/Provider: AZURE/)).toBeInTheDocument();
    expect(within(azureRow as HTMLTableRowElement).getByText(/Azure subscription: sub-1/)).toBeInTheDocument();
    expect(within(azureRow as HTMLTableRowElement).getByText(
      /Error: Azure AI Security discovery failed/
    )).toBeInTheDocument();

    const azureCloudType = screen.getByText('Azure Cloud Discovery');
    const azureCloudRow = azureCloudType.closest('tr');
    expect(azureCloudRow).not.toBeNull();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText('Queued')).toBeInTheDocument();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText('#2')).toBeInTheDocument();
    within(azureCloudRow as HTMLTableRowElement).getByText('Details').click();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText(
      /Azure subscriptions: sub-1/
    )).toBeInTheDocument();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText(/Regions: eastus/)).toBeInTheDocument();

    const awsCloudType = screen.getByText('AWS Cloud Discovery');
    const awsCloudRow = awsCloudType.closest('tr');
    expect(awsCloudRow).not.toBeNull();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText('Queued')).toBeInTheDocument();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText('#3')).toBeInTheDocument();
    within(awsCloudRow as HTMLTableRowElement).getByText('Details').click();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText(
      /AWS account: 123456789012/
    )).toBeInTheDocument();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText(
      /Resource types: EC2, SSM/
    )).toBeInTheDocument();
  });
});
