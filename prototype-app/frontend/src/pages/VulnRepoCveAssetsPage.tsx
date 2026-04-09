import React from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoView } from '../app/routes';
import { buildAssetRowsFromMatchedSoftware } from '../features/cve-workbench/asset-report';
import { useCveDetailQuery } from '../features/cve-workbench/queries';

const ASSET_COLUMNS: DataTableColumn[] = [
  { id: 'entity', label: 'Entity', header: 'Entity', initialSize: 220 },
  { id: 'identifier', label: 'Identifier', header: 'Identifier', initialSize: 240 },
  { id: 'assetType', label: 'Type', header: 'Type', initialSize: 120 },
  { id: 'matchedSoftwareCount', label: 'Matched Software', header: 'Matched Software', initialSize: 150 },
  { id: 'softwareSummary', label: 'Software Metadata', header: 'Software Metadata', initialSize: 420 },
];

export function VulnRepoCveAssetsPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const params = useParams<{ cveId?: string }>();
  const cveId = params.cveId ?? null;
  const detailQuery = useCveDetailQuery(cveId);
  const allAssetRows = React.useMemo(
    () => buildAssetRowsFromMatchedSoftware(detailQuery.data?.matchedSoftware ?? [], detailQuery.data?.summary.severity ?? 'Unknown'),
    [detailQuery.data?.matchedSoftware, detailQuery.data?.summary.severity]
  );
  const assetRows = React.useMemo(() => {
    const scope = searchParams.get('scope');
    const os = searchParams.get('os');
    const software = searchParams.get('software');
    return allAssetRows.filter((asset) => {
      if (scope === 'external-facing' && !asset.externalFacing) return false;
      if (scope === 'critical' && asset.criticality.toLowerCase() !== 'critical') return false;
      if (os && asset.os !== os) return false;
      if (software && !asset.matchedSoftware.some((entry) => entry.software === software)) return false;
      return true;
    });
  }, [allAssetRows, searchParams]);

  const rows = React.useMemo<DataTableRow[]>(() => (
    assetRows.map((asset) => ({
      id: asset.id,
      cells: {
        entity: { content: <span className="mono">{asset.entity}</span> },
        identifier: { content: <span className="mono">{asset.identifier}</span> },
        assetType: { content: asset.type },
        matchedSoftwareCount: { content: asset.matchedSoftware.length.toLocaleString() },
        softwareSummary: { content: asset.matchedSoftware.map((item) => `${item.software} ${item.version}`.trim()).join(', ') || '-' },
      },
    }))
  ), [assetRows]);

  return (
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header">
        <div>
          <div className="org-cve-back-link">Affected Entities</div>
          <h3>{cveId ?? 'CVE Assets'}</h3>
          <span className="panel-caption">
            {assetRows.length.toLocaleString()} assets matched to this CVE.
          </span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate(pathForVulnRepoView('org-cves', cveId))}
            disabled={!cveId}
          >
            Back to CVE
          </button>
        </div>
      </div>

      {detailQuery.isLoading || detailQuery.isFetching ? (
        <div className="notice">Loading affected entities...</div>
      ) : detailQuery.error instanceof Error ? (
        <div className="notice error">{detailQuery.error.message}</div>
      ) : assetRows.length === 0 ? (
        <div className="empty-state"><p>No affected entities were found for this CVE.</p></div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey={`vuln-repo-cve-assets:${cveId ?? 'unknown'}`}
            columns={ASSET_COLUMNS}
            rows={rows}
          />
        </div>
      )}
    </section>
  );
}
