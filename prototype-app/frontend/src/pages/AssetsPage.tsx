import React from 'react';
import { api } from '../api/client';
import { Asset, CmdbAssetRecord } from '../types';
import { ResizableTable } from '../components/ResizableTable';

const SAMPLE_CMDB_PAYLOAD: CmdbAssetRecord[] = [
  {
    assetType: 'APPLICATION',
    assetName: 'payments-api-prod',
    assetIdentifier: 'app:payments-api:prod',
    serviceName: 'payments-api',
    environment: 'production',
    ownerTeam: 'payments-platform',
    ownerEmail: 'payments-platform@example.com',
    businessCriticality: 'CRITICAL',
    state: 'ACTIVE'
  }
];

const SAMPLE_CSV_PAYLOAD = [
  'assetType,assetName,assetIdentifier,serviceName,environment,ownerTeam,ownerEmail,businessCriticality,state',
  'APPLICATION,payments-api-prod,app:payments-api:prod,payments-api,production,payments-platform,payments-platform@example.com,CRITICAL,ACTIVE'
].join('\n');

type CmdbMode = 'form' | 'csv' | 'json';

function parseCsvRecords(input: string): CmdbAssetRecord[] {
  const lines = input
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length < 2) {
    throw new Error('CSV requires a header and at least one data row');
  }

  const headers = lines[0].split(',').map((value) => value.trim());
  const requiredHeaders = ['assetType', 'assetName', 'assetIdentifier'];
  requiredHeaders.forEach((header) => {
    if (!headers.includes(header)) {
      throw new Error(`Missing required CSV header: ${header}`);
    }
  });

  const records: CmdbAssetRecord[] = [];
  for (let i = 1; i < lines.length; i += 1) {
    const values = lines[i].split(',').map((value) => value.trim());
    const row = Object.fromEntries(headers.map((header, index) => [header, values[index] ?? '']));

    if (!row.assetType || !row.assetName || !row.assetIdentifier) {
      throw new Error(`Row ${i + 1} is missing assetType/assetName/assetIdentifier`);
    }

    records.push({
      assetType: row.assetType as CmdbAssetRecord['assetType'],
      assetName: row.assetName,
      assetIdentifier: row.assetIdentifier,
      serviceName: row.serviceName || undefined,
      environment: row.environment || undefined,
      ownerTeam: row.ownerTeam || undefined,
      ownerEmail: row.ownerEmail || undefined,
      businessCriticality: (row.businessCriticality || undefined) as CmdbAssetRecord['businessCriticality'],
      state: (row.state || undefined) as CmdbAssetRecord['state']
    });
  }

  return records;
}

export function AssetsPage() {
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [error, setError] = React.useState('');
  const [message, setMessage] = React.useState('');
  const [loading, setLoading] = React.useState(false);

  const [cmdbMode, setCmdbMode] = React.useState<CmdbMode>('form');
  const [cmdbJson, setCmdbJson] = React.useState(JSON.stringify(SAMPLE_CMDB_PAYLOAD, null, 2));
  const [cmdbCsv, setCmdbCsv] = React.useState(SAMPLE_CSV_PAYLOAD);

  const [assetType, setAssetType] = React.useState<CmdbAssetRecord['assetType']>('APPLICATION');
  const [assetName, setAssetName] = React.useState('');
  const [assetIdentifier, setAssetIdentifier] = React.useState('');
  const [serviceName, setServiceName] = React.useState('');
  const [environment, setEnvironment] = React.useState('');
  const [ownerTeam, setOwnerTeam] = React.useState('');
  const [ownerEmail, setOwnerEmail] = React.useState('');
  const [businessCriticality, setBusinessCriticality] = React.useState<CmdbAssetRecord['businessCriticality']>('MEDIUM');
  const [assetState, setAssetState] = React.useState<CmdbAssetRecord['state']>('ACTIVE');

  const loadAssets = React.useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const rows = await api.listAssets();
      setAssets(rows);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const buildFormPayload = (): CmdbAssetRecord[] => {
    if (!assetName.trim()) {
      throw new Error('Asset Name is required');
    }
    if (!assetIdentifier.trim()) {
      throw new Error('Asset Identifier is required');
    }

    return [
      {
        assetType,
        assetName: assetName.trim(),
        assetIdentifier: assetIdentifier.trim(),
        serviceName: serviceName.trim() || undefined,
        environment: environment.trim() || undefined,
        ownerTeam: ownerTeam.trim() || undefined,
        ownerEmail: ownerEmail.trim() || undefined,
        businessCriticality,
        state: assetState
      }
    ];
  };

  const syncCmdb = async (): Promise<void> => {
    setError('');
    setMessage('');

    let payload: CmdbAssetRecord[];
    try {
      if (cmdbMode === 'form') {
        payload = buildFormPayload();
      } else if (cmdbMode === 'csv') {
        payload = parseCsvRecords(cmdbCsv);
      } else {
        const parsed = JSON.parse(cmdbJson);
        if (!Array.isArray(parsed)) {
          throw new Error('CMDB payload must be a JSON array');
        }
        payload = parsed as CmdbAssetRecord[];
      }
    } catch (e) {
      setError(`Invalid payload: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }

    setLoading(true);
    try {
      const result = await api.syncAssetsFromCmdb(payload);
      setMessage(`${result.message}. Received ${result.received}, inserted ${result.inserted}, updated ${result.updated}.`);
      await loadAssets();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Assets & CMDB</h3>
        <span className="panel-caption">Ingest asset ownership metadata and control lifecycle state</span>
      </div>

      <div className="section-block">
        <div className="mode-toggle">
          <button type="button" className={cmdbMode === 'form' ? 'mode-btn active' : 'mode-btn'} onClick={() => setCmdbMode('form')}>
            Guided Form
          </button>
          <button type="button" className={cmdbMode === 'csv' ? 'mode-btn active' : 'mode-btn'} onClick={() => setCmdbMode('csv')}>
            CSV Import
          </button>
          <button type="button" className={cmdbMode === 'json' ? 'mode-btn active' : 'mode-btn'} onClick={() => setCmdbMode('json')}>
            Raw JSON
          </button>
        </div>

        {cmdbMode === 'form' && (
          <div className="form-grid ingestion-grid">
            <label>Asset Type
              <select value={assetType} onChange={(event) => setAssetType(event.target.value as CmdbAssetRecord['assetType'])}>
                <option value="APPLICATION">Application</option>
                <option value="HOST">Host</option>
                <option value="CONTAINER_IMAGE">Container Image</option>
              </select>
            </label>
            <label>Asset Name
              <input value={assetName} onChange={(event) => setAssetName(event.target.value)} placeholder="payments-api-prod" />
            </label>
            <label>Asset Identifier
              <input value={assetIdentifier} onChange={(event) => setAssetIdentifier(event.target.value)} placeholder="app:payments-api:prod" className="mono" />
            </label>
            <label>Service
              <input value={serviceName} onChange={(event) => setServiceName(event.target.value)} placeholder="payments-api" />
            </label>
            <label>Environment
              <input value={environment} onChange={(event) => setEnvironment(event.target.value)} placeholder="production" />
            </label>
            <label>Owner Team
              <input value={ownerTeam} onChange={(event) => setOwnerTeam(event.target.value)} placeholder="payments-platform" />
            </label>
            <label>Owner Email
              <input value={ownerEmail} onChange={(event) => setOwnerEmail(event.target.value)} placeholder="team@example.com" />
            </label>
            <label>Business Criticality
              <select value={businessCriticality} onChange={(event) => setBusinessCriticality(event.target.value as CmdbAssetRecord['businessCriticality'])}>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </label>
            <label>Asset State
              <select value={assetState} onChange={(event) => setAssetState(event.target.value as CmdbAssetRecord['state'])}>
                <option value="ACTIVE">Active</option>
                <option value="INACTIVE">Inactive</option>
                <option value="RETIRED">Retired</option>
                <option value="DECOMMISSIONED">Decommissioned</option>
              </select>
            </label>
          </div>
        )}

        {cmdbMode === 'csv' && (
          <>
            <label>CMDB CSV Payload
              <textarea rows={8} value={cmdbCsv} onChange={(event) => setCmdbCsv(event.target.value)} className="mono" />
            </label>
            <div className="inline-note">Required headers: <span className="mono">assetType, assetName, assetIdentifier</span>.</div>
          </>
        )}

        {cmdbMode === 'json' && (
          <label>CMDB JSON Payload
            <textarea rows={10} value={cmdbJson} onChange={(event) => setCmdbJson(event.target.value)} className="mono" />
          </label>
        )}

        <div className="button-row form-submit-row">
          <button type="button" className="btn btn-primary" onClick={syncCmdb} disabled={loading}>
            {loading ? 'Syncing...' : 'Sync CMDB Assets'}
          </button>
          {cmdbMode === 'csv' && (
            <button type="button" className="btn btn-secondary" onClick={() => setCmdbCsv(SAMPLE_CSV_PAYLOAD)}>
              Reset CSV Sample
            </button>
          )}
          {cmdbMode === 'json' && (
            <button type="button" className="btn btn-secondary" onClick={() => setCmdbJson(JSON.stringify(SAMPLE_CMDB_PAYLOAD, null, 2))}>
              Reset JSON Sample
            </button>
          )}
        </div>
      </div>

      {message && <div className="notice">{message}</div>}
      {error && <div className="notice error">{error}</div>}

      <h4 className="section-title section-divider">Asset Inventory</h4>
      <div className="table-scroll">
        <ResizableTable storageKey="assets-cmdb-table-widths">
          <thead>
          <tr>
            <th>Name</th>
            <th>Identifier</th>
            <th>Type</th>
            <th>State</th>
            <th>Business Criticality</th>
            <th>Service</th>
            <th>Environment</th>
            <th>Owner Team</th>
            <th>Owner Email</th>
            <th>Last Inventory</th>
            <th>Last CMDB Sync</th>
          </tr>
          </thead>
          <tbody>
          {assets.map((asset) => (
            <tr key={asset.id}>
              <td>{asset.name}</td>
              <td className="mono">{asset.identifier}</td>
              <td>{asset.type}</td>
              <td><span className={`status-pill status-${asset.state.toLowerCase()}`}>{asset.state}</span></td>
              <td>{asset.businessCriticality}</td>
              <td>{asset.serviceName || '-'}</td>
              <td>{asset.environment || '-'}</td>
              <td>{asset.ownerTeam || '-'}</td>
              <td>{asset.ownerEmail || '-'}</td>
              <td>{asset.lastInventoryAt ? new Date(asset.lastInventoryAt).toLocaleString() : '-'}</td>
              <td>{asset.lastCmdbSyncAt ? new Date(asset.lastCmdbSyncAt).toLocaleString() : '-'}</td>
            </tr>
          ))}
          </tbody>
        </ResizableTable>
      </div>
    </div>
  );
}
