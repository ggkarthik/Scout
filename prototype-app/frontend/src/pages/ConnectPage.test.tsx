import React from 'react';
import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { renderWithProviders } from '../test/test-utils';
import { ConnectPage } from './ConnectPage';

const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'tenant.admin@example.test',
  userId: 'tenant-admin',
  tenantId: 'tenant-1',
  tenantName: 'Customer One',
  roles: ['TENANT_ADMIN']
};

function renderConnectPage(actor: ActorContext) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <ConnectPage />
    </ActorContextState.Provider>
  );
}

describe('ConnectPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders inventory connector failure state from live connector status data', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue({
      sourceSystem: 'servicenow',
      configured: true,
      baseUrl: 'https://acme.service-now.example',
      authType: 'BASIC',
      username: 'admin',
      hasCredentialSecret: true,
      installTable: 'cmdb_sam_sw_install',
      discoveryModelTable: 'cmdb_sam_sw_discovery_model',
      ciTable: 'cmdb_ci',
      installQuery: '',
      discoveryQuery: '',
      installFields: 'sys_id',
      discoveryFields: 'sys_id',
      pageSize: 1000,
      enabled: true,
      autoSyncEnabled: true,
      intervalMinutes: 1440,
      lastTestStatus: 'FAILED',
      lastTestMessage: 'credential problem',
      lastTestedAt: '2026-06-07T10:00:00Z',
      lastSyncAt: '2026-06-07T10:30:00Z'
    });
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({
      sourceSystem: 'sccm',
      configured: false,
      jdbcUrl: '',
      authType: 'SQL_AUTH',
      username: '',
      hasCredential: false,
      siteCode: '',
      databaseName: 'CM_P01',
      fetchSize: 500,
      queryTimeoutSeconds: 120,
      mockMode: false,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getAwsDiscoveryConfig').mockResolvedValue({
      sourceSystem: 'aws',
      configured: false,
      authType: 'INSTANCE_METADATA',
      accessKeyId: '',
      hasCredential: false,
      crossAccountRoleArn: '',
      externalId: '',
      awsAccountId: undefined,
      regionsJson: '["us-east-1"]',
      resourceTypesJson: '["EC2"]',
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });

    renderConnectPage(TENANT_ADMIN);

    expect(await screen.findByText(/Failed/i)).toBeInTheDocument();
    expect(screen.getByText('ServiceNow CMDB')).toBeInTheDocument();
  });

  it('keeps platform-owned vulnerability connector management hidden from tenant users', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue({
      sourceSystem: 'servicenow',
      configured: false,
      baseUrl: '',
      authType: 'BASIC',
      username: '',
      hasCredentialSecret: false,
      installTable: 'cmdb_sam_sw_install',
      discoveryModelTable: 'cmdb_sam_sw_discovery_model',
      ciTable: 'cmdb_ci',
      installQuery: '',
      discoveryQuery: '',
      installFields: 'sys_id',
      discoveryFields: 'sys_id',
      pageSize: 1000,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({
      sourceSystem: 'sccm',
      configured: false,
      jdbcUrl: '',
      authType: 'SQL_AUTH',
      username: '',
      hasCredential: false,
      siteCode: '',
      databaseName: 'CM_P01',
      fetchSize: 500,
      queryTimeoutSeconds: 120,
      mockMode: false,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getAwsDiscoveryConfig').mockResolvedValue({
      sourceSystem: 'aws',
      configured: false,
      authType: 'INSTANCE_METADATA',
      accessKeyId: '',
      hasCredential: false,
      crossAccountRoleArn: '',
      externalId: '',
      awsAccountId: undefined,
      regionsJson: '["us-east-1"]',
      resourceTypesJson: '["EC2"]',
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });

    renderConnectPage(TENANT_ADMIN);

    expect(await screen.findByText(/Inventory.*CMDB & SBOM/i)).toBeInTheDocument();
    expect(screen.queryByText('Connectors')).not.toBeInTheDocument();
    expect(screen.queryByText('NVD Vulnerability Feed')).not.toBeInTheDocument();
  });
});
