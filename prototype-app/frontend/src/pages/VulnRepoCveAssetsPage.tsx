import React from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoView, pathForVulnRepoHostAsset } from '../app/routes';
import { buildAssetRowsFromMatchedSoftware } from '../features/cve-workbench/asset-report';
import { useCveDetailQuery } from '../features/cve-workbench/queries';

const ASSET_COLUMNS: DataTableColumn[] = [
  { id: 'entity', label: 'Entity', header: 'Entity', initialSize: 200 },
  { id: 'identifier', label: 'Identifier', header: 'Identifier', initialSize: 220 },
  { id: 'assetType', label: 'Type', header: 'Type', initialSize: 110 },
  { id: 'os', label: 'OS', header: 'OS', initialSize: 100 },
  { id: 'environment', label: 'Environment', header: 'Environment', initialSize: 130 },
  { id: 'supportGroup', label: 'Support Group', header: 'Support Group', initialSize: 150 },
  { id: 'eol', label: 'EOL', header: 'EOL', initialSize: 110 },
  { id: 'softwareSummary', label: 'Matched Software', header: 'Matched Software', initialSize: 300 },
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

  // Build EOL label from matched software EOL data via detailQuery
  const eolByAssetId = React.useMemo(() => {
    const map = new Map<string, { isEol?: boolean; eolDate?: string; supportPhase?: string }>();
    for (const sw of detailQuery.data?.matchedSoftware ?? []) {
      const key = sw.assetIdentifier ?? sw.assetId ?? sw.componentId;
      if (!map.has(key)) {
        map.set(key, { isEol: sw.isEol ?? undefined, eolDate: sw.eolDate ?? undefined, supportPhase: sw.supportPhase ?? undefined });
      } else if (sw.isEol) {
        map.set(key, { isEol: true, eolDate: sw.eolDate ?? map.get(key)?.eolDate, supportPhase: sw.supportPhase ?? map.get(key)?.supportPhase });
      }
    }
    return map;
  }, [detailQuery.data?.matchedSoftware]);

  const rows = React.useMemo<DataTableRow[]>(() => (
    assetRows.map((asset) => {
      const eol = eolByAssetId.get(asset.id);
      const eolLabel = eol?.isEol
        ? `EOL${eol.eolDate ? ' · ' + eol.eolDate.slice(0, 10) : ''}`
        : eol?.eolDate
          ? `EOL ${eol.eolDate.slice(0, 10)}`
          : eol?.supportPhase ?? '—';
      const eolColor = eol?.isEol ? '#c53030' : eol?.eolDate ? '#b7791f' : 'var(--muted)';

      return {
        id: asset.id,
        cells: {
          entity: {
            content: (
              <button
                type="button"
                style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--accent)', fontFamily: 'inherit', fontSize: 'inherit', textAlign: 'left' }}
                onClick={() => {
                  const navId = asset.assetId ?? asset.id;
                  navigate(pathForVulnRepoHostAsset(navId, `/vuln-repo/org-cves/${encodeURIComponent(cveId ?? '')}/assets`));
                }}
              >
                <span className="mono">{asset.entity}</span>
              </button>
            ),
          },
          identifier: { content: <span className="mono">{asset.identifier}</span> },
          assetType: { content: asset.type },
          os: { content: asset.os },
          environment: { content: asset.environment },
          supportGroup: { content: asset.supportGroup ?? '—' },
          eol: { content: <span style={{ color: eolColor, fontWeight: eol?.isEol ? 600 : undefined }}>{eolLabel}</span> },
          softwareSummary: { content: asset.matchedSoftware.map((item) => `${item.software} ${item.version}`.trim()).join(', ') || '—' },
        },
      };
    })
  ), [assetRows, eolByAssetId, navigate, cveId]);

  return (
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header">
        <div>
          <div className="org-cve-back-link">Affected Entities</div>
          <h3>{cveId ?? 'CVE Assets'}</h3>
          <span className="panel-caption">
            {assetRows.length.toLocaleString()} entities matched to this CVE.
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
