import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoView } from '../app/routes';
import { useCveDetailQuery } from '../features/cve-workbench/queries';
import type { CveMatchedSoftware } from '../features/cve-workbench/types';

type SoftwareRow = {
  id: string;
  software: string;
  vendor: string;
  version: string;
};

const SOFTWARE_COLUMNS: DataTableColumn[] = [
  { id: 'software', label: 'Software', header: 'Software', initialSize: 260 },
  { id: 'vendor', label: 'Vendor', header: 'Vendor', initialSize: 180 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 220 },
];

function buildSoftwareRows(matchedSoftware: CveMatchedSoftware[]): SoftwareRow[] {
  const vendorByPackage = new Map<string, string>();
  matchedSoftware.forEach((software) => {
    const pkgKey = software.packageName?.trim().toLowerCase();
    const vendor = software.vexSource?.trim() || software.ecosystem?.trim();
    if (pkgKey && vendor && !vendorByPackage.has(pkgKey)) {
      vendorByPackage.set(pkgKey, vendor);
    }
  });

  const unique = new Map<string, SoftwareRow>();
  matchedSoftware.forEach((software) => {
    const packageName = software.packageName?.trim() || 'Unknown';
    const version = software.version?.trim() || '-';
    const vendor = software.vexSource?.trim()
      || vendorByPackage.get(packageName.toLowerCase())
      || software.ecosystem?.trim()
      || 'Unknown';
    const key = `${packageName.toLowerCase()}|${version.toLowerCase()}`;
    if (!unique.has(key)) {
      unique.set(key, {
        id: key,
        software: packageName,
        vendor,
        version,
      });
    }
  });

  return Array.from(unique.values()).sort((left, right) => (
    left.software.localeCompare(right.software)
    || left.version.localeCompare(right.version)
    || left.vendor.localeCompare(right.vendor)
  ));
}

export function VulnRepoCveSoftwarePage() {
  const navigate = useNavigate();
  const params = useParams<{ cveId?: string }>();
  const cveId = params.cveId ?? null;
  const detailQuery = useCveDetailQuery(cveId);
  const softwareRows = React.useMemo(() => buildSoftwareRows(detailQuery.data?.matchedSoftware ?? []), [detailQuery.data?.matchedSoftware]);

  const rows = React.useMemo<DataTableRow[]>(() => (
    softwareRows.map((software) => ({
      id: software.id,
      cells: {
        software: { content: <span className="mono">{software.software}</span> },
        vendor: { content: software.vendor },
        version: { content: <span className="mono">{software.version}</span> },
      },
    }))
  ), [softwareRows]);

  return (
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header">
        <div>
          <div className="org-cve-back-link">Impacted Software</div>
          <h3>{cveId ?? 'CVE Software'}</h3>
          <span className="panel-caption">
            {softwareRows.length.toLocaleString()} matched software entries correlated to this CVE&apos;s CPE targets.
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
        <div className="notice">Loading impacted software...</div>
      ) : detailQuery.error instanceof Error ? (
        <div className="notice error">{detailQuery.error.message}</div>
      ) : softwareRows.length === 0 ? (
        <div className="empty-state"><p>No impacted software was found for this CVE.</p></div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey={`vuln-repo-cve-software:${cveId ?? 'unknown'}`}
            columns={SOFTWARE_COLUMNS}
            rows={rows}
          />
        </div>
      )}
    </section>
  );
}
