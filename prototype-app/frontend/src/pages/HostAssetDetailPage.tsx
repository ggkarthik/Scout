import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { pathForVulnRepoView, pathForFindingsWithFilters } from '../app/routes';
import { api } from '../api/client';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { EolBadge } from '../components/EolBadge';
import type { HostAssetDetail } from '../features/inventory/api-types';
import { useHostAssetDetailQuery } from '../features/inventory/queries';
import { readHostAssetIdFromSearch } from '../features/inventory/searchState';

type HostAssetDetailPageProps = {
  assetId?: string | null;
  onClose?: () => void;
};

type HostDetailTab = 'software' | 'applicable-cves' | 'findings' | 'aliases' | 'services';

const ALIAS_COLUMNS: DataTableColumn[] = [
  { id: 'alias', label: 'Alias', header: 'Alias', initialSize: 220 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 160 },
  { id: 'confidence', label: 'Confidence', header: 'Confidence', initialSize: 120 },
  { id: 'firstSeen', label: 'First Seen', header: 'First Seen', initialSize: 180 },
  { id: 'lastSeen', label: 'Last Seen', header: 'Last Seen', initialSize: 180 }
];

const SOFTWARE_COLUMNS: DataTableColumn[] = [
  { id: 'software', label: 'Software', header: 'Software', initialSize: 220 },
  { id: 'vendor', label: 'Vendor', header: 'Vendor', initialSize: 160 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 140 },
  { id: 'identity', label: 'Identity', header: 'Identity', initialSize: 200 },
  { id: 'applicableCves', label: 'Applicable CVEs', header: 'Applicable CVEs', initialSize: 240 },
  { id: 'eolStatus', label: 'EOL Status', header: 'EOL Status', initialSize: 200 },
  { id: 'recommendation', label: 'Recommendation', header: 'Recommendation', initialSize: 260 },
  { id: 'observed', label: 'Observed', header: 'Observed', initialSize: 180 }
];

const SERVICE_COLUMNS: DataTableColumn[] = [
  { id: 'service', label: 'Service', header: 'Service', initialSize: 260 },
  { id: 'publisher', label: 'Publisher', header: 'Publisher', initialSize: 160 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 140 },
  { id: 'source', label: 'Source System', header: 'Source System', initialSize: 180 },
  { id: 'lastActive', label: 'Last Active', header: 'Last Active', initialSize: 180 }
];

const FINDING_COLUMNS: DataTableColumn[] = [
  { id: 'vulnerability', label: 'Vulnerability', header: 'Vulnerability', initialSize: 180 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 140 },
  { id: 'decision', label: 'Decision', header: 'Decision', initialSize: 140 },
  { id: 'risk', label: 'Risk', header: 'Risk', initialSize: 120 },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 }
];

const APPLICABLE_CVE_COLUMNS: DataTableColumn[] = [
  { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 180 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'cvss', label: 'CVSS', header: 'CVSS', initialSize: 100 },
  { id: 'epss', label: 'EPSS', header: 'EPSS', initialSize: 100 },
  { id: 'software', label: 'Matched Software', header: 'Matched Software', initialSize: 220 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 160 },
  { id: 'evaluated', label: 'Last Evaluated', header: 'Last Evaluated', initialSize: 180 }
];

function formatTimestamp(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatConfidence(value?: number): string {
  if (value == null) return '-';
  return `${Math.round(value * 100)}%`;
}

function formatCount(value?: number): string {
  return (value ?? 0).toLocaleString();
}

function formatBomLabel(value?: string): string {
  if (!value) return '-';
  return value.replace(/_/g, ' ');
}

function statusClass(value?: string): string {
  return `status-pill status-${(value ?? 'unknown').toLowerCase().replace(/_/g, '-')}`;
}

function buildAliasRows(aliases: HostAssetDetail['aliases']): DataTableRow[] {
  return aliases.map((alias) => ({
    id: alias.id,
    cells: {
      alias: { content: alias.aliasName, props: { className: 'mono' } },
      source: { content: alias.sourceSystem },
      confidence: { content: formatConfidence(alias.confidence) },
      firstSeen: { content: formatTimestamp(alias.firstSeenAt) },
      lastSeen: { content: formatTimestamp(alias.lastSeenAt) }
    }
  }));
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3
};

function normalizePkgKey(s: string): string {
  return s.toLowerCase().replace(/[\s_\-.]+/g, '');
}

function matchCvesToSoftware(
  item: HostAssetDetail['software'][number],
  applicableCves: HostAssetDetail['applicableCves']
): HostAssetDetail['applicableCves'] {
  const productKey = normalizePkgKey(item.normalizedProduct ?? item.displayName ?? '');
  if (!productKey) return [];
  const swVersion = (item.version ?? item.normalizedVersion ?? '').trim();

  return applicableCves
    .filter(cve => {
      const cveKey = normalizePkgKey(cve.packageName ?? '');
      if (!cveKey) return false;
      const pkgMatch = cveKey === productKey || cveKey.includes(productKey) || productKey.includes(cveKey);
      if (!pkgMatch) return false;
      if (swVersion && cve.version) return cve.version.trim() === swVersion;
      return true;
    })
    .sort((a, b) => {
      const sa = SEVERITY_ORDER[(a.severity ?? '').toLowerCase()] ?? 4;
      const sb = SEVERITY_ORDER[(b.severity ?? '').toLowerCase()] ?? 4;
      if (sa !== sb) return sa - sb;
      return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
    });
}

type CveChipListProps = {
  cves: HostAssetDetail['applicableCves'];
  onCveClick?: (cveId: string) => void;
  onMoreClick?: () => void;
};

function CveChipList({ cves, onCveClick, onMoreClick }: CveChipListProps) {
  if (cves.length === 0) {
    return <span className="panel-caption">—</span>;
  }
  const visible = cves.slice(0, 3);
  const overflow = cves.length - visible.length;
  return (
    <div className="host-sw-cve-list">
      {visible.map(cve => {
        const cveId = cve.externalId ?? cve.vulnerabilityId;
        return onCveClick && cveId ? (
          <button
            key={cve.stateId}
            type="button"
            className={`host-sw-cve-chip host-sw-cve-chip-${(cve.severity ?? 'unknown').toLowerCase()}`}
            title={`${cveId} — CVSS ${cve.cvssScore?.toFixed(1) ?? 'N/A'} · ${cve.impactState ?? 'unknown'}`}
            onClick={() => onCveClick(cveId)}
          >
            {cveId}
          </button>
        ) : (
          <span
            key={cve.stateId}
            className={`host-sw-cve-chip host-sw-cve-chip-${(cve.severity ?? 'unknown').toLowerCase()}`}
            title={`${cveId} — CVSS ${cve.cvssScore?.toFixed(1) ?? 'N/A'} · ${cve.impactState ?? 'unknown'}`}
          >
            {cveId}
          </span>
        );
      })}
      {overflow > 0 && (
        onMoreClick ? (
          <button
            type="button"
            className="panel-caption host-sw-cve-overflow host-sw-cve-more-btn"
            onClick={onMoreClick}
          >
            +{overflow} more
          </button>
        ) : (
          <span className="panel-caption host-sw-cve-overflow">+{overflow} more</span>
        )
      )}
    </div>
  );
}

type RecommendationState = {
  loading: boolean;
  result: { recommendedVersion: string; upgradeNotes: string; urgency: string } | null;
  error: string | null;
};

const URGENCY_CLASS: Record<string, string> = {
  CRITICAL: 'upgrade-urgency-critical',
  HIGH: 'upgrade-urgency-high',
  MEDIUM: 'upgrade-urgency-medium',
  LOW: 'upgrade-urgency-low'
};

function RecommendationCell({
  software,
  matchedCveIds
}: {
  software: HostAssetDetail['software'][number];
  matchedCveIds: string[];
}) {
  const needsRecommendation = software.isEol === true || matchedCveIds.length > 0;
  const [state, setState] = React.useState<RecommendationState>({
    loading: false,
    result: null,
    error: null
  });

  if (!needsRecommendation) {
    return <span className="panel-caption">—</span>;
  }

  if (state.loading) {
    return <span className="upgrade-rec-loading">Fetching recommendation…</span>;
  }

  if (state.result) {
    const urgencyClass = URGENCY_CLASS[(state.result.urgency ?? '').toUpperCase()] ?? 'upgrade-urgency-medium';
    return (
      <div className="upgrade-rec-result">
        <div className="upgrade-rec-version">
          <span className={`upgrade-urgency-badge ${urgencyClass}`}>{state.result.urgency}</span>
          <span className="upgrade-rec-version-text">{state.result.recommendedVersion}</span>
        </div>
        <div className="upgrade-rec-notes panel-caption">{state.result.upgradeNotes}</div>
      </div>
    );
  }

  if (state.error) {
    return <span className="upgrade-rec-error panel-caption">{state.error}</span>;
  }

  const handleFetch = () => {
    setState({ loading: true, result: null, error: null });
    api.getUpgradeRecommendation({
      softwareName: software.displayName ?? software.normalizedProduct ?? '',
      vendor: software.publisher ?? software.normalizedPublisher ?? undefined,
      currentVersion: software.version ?? software.normalizedVersion ?? undefined,
      eolDate: software.eolDate ?? undefined,
      cveIds: matchedCveIds.slice(0, 10)
    })
      .then(result => setState({ loading: false, result, error: null }))
      .catch((err: unknown) => setState({
        loading: false,
        result: null,
        error: err instanceof Error ? err.message : 'Failed to fetch recommendation'
      }));
  };

  return (
    <button type="button" className="upgrade-rec-btn" onClick={handleFetch}>
      Suggest upgrade
    </button>
  );
}

type SoftwareRowCallbacks = {
  onCveClick: (cveId: string) => void;
  onMoreClick: () => void;
};

function buildSoftwareRows(
  software: HostAssetDetail['software'],
  applicableCves: HostAssetDetail['applicableCves'],
  callbacks?: SoftwareRowCallbacks
): DataTableRow[] {
  return software.map((item) => {
    const matchedCves = matchCvesToSoftware(item, applicableCves);
    return {
      id: item.id,
      cells: {
        software: {
          content: (
            <>
              <div>{item.displayName}</div>
              <div className="panel-caption mono">
                {item.normalizedPublisher}:{item.normalizedProduct}
              </div>
            </>
          )
        },
        vendor: { content: item.publisher ?? '-' },
        version: {
          content: item.version ?? item.normalizedVersion ?? 'Needs review',
          props: { className: 'mono' }
        },
        identity: {
          content: (
            <>
              <div>{item.softwareIdentity ?? '-'}</div>
              <div className="panel-caption mono">{item.cpe23 ?? '-'}</div>
            </>
          )
        },
        applicableCves: {
          content: (
            <CveChipList
              cves={matchedCves}
              onCveClick={callbacks?.onCveClick}
              onMoreClick={matchedCves.length > 3 ? callbacks?.onMoreClick : undefined}
            />
          )
        },
        recommendation: {
          content: (
            <RecommendationCell
              software={item}
              matchedCveIds={matchedCves.map(c => c.externalId ?? c.vulnerabilityId ?? '').filter(Boolean)}
            />
          )
        },
        eolStatus: {
          content: (
            <div className="host-eol-status-cell">
              <EolBadge
                isEol={item.isEol}
                daysRemaining={item.eolDaysRemaining}
                eolDate={item.eolDate}
              />
              {item.eolDate && (
                <span className="panel-caption mono">{item.eolDate}</span>
              )}
              {item.eolSlug && (
                <span className="panel-caption">
                  {item.eolSlug}{item.eolCycle ? ` / ${item.eolCycle}` : ''}
                </span>
              )}
            </div>
          )
        },
        observed: {
          content: formatTimestamp(item.lastScanned ?? item.lastUsed ?? item.installDate)
        }
      }
    };
  });
}

function buildServiceRows(software: HostAssetDetail['software']): DataTableRow[] {
  return software
    .filter(s => s.activeInstall)
    .map((s) => ({
      id: s.id,
      cells: {
        service: {
          content: (
            <>
              <div>{s.displayName}</div>
              <div className="panel-caption mono">
                {s.normalizedPublisher}:{s.normalizedProduct}
              </div>
            </>
          )
        },
        publisher: { content: s.publisher ?? '-' },
        version: {
          content: s.version ?? s.normalizedVersion ?? '-',
          props: { className: 'mono' }
        },
        source: { content: s.sourceSystem ?? '-' },
        lastActive: {
          content: formatTimestamp(s.lastScanned ?? s.lastUsed ?? s.installDate)
        }
      }
    }));
}

function buildFindingRows(findings: HostAssetDetail['findings']): DataTableRow[] {
  return findings.map((finding) => ({
    id: finding.id,
    cells: {
      vulnerability: {
        content: finding.vulnerabilityId ?? '-',
        props: { className: 'mono' }
      },
      severity: { content: finding.severity ?? '-' },
      status: {
        content: <span className={statusClass(finding.status)}>{finding.status ?? 'UNKNOWN'}</span>
      },
      decision: { content: finding.decisionState ?? '-' },
      risk: { content: finding.riskScore?.toFixed(2) ?? '-' },
      lastObserved: { content: formatTimestamp(finding.lastObservedAt) }
    }
  }));
}

function formatPercent(value?: number): string {
  if (value == null) return '-';
  return `${(value * 100).toFixed(1)}%`;
}

function buildApplicableCveRows(
  applicableCves: HostAssetDetail['applicableCves'],
  onCveClick?: (cveId: string) => void
): DataTableRow[] {
  return applicableCves.map((cve) => {
    const cveId = cve.externalId ?? cve.vulnerabilityId ?? null;
    return {
      id: cve.stateId,
      cells: {
        cve: {
          content: onCveClick && cveId ? (
            <button
              type="button"
              className="org-cve-link-btn mono"
              onClick={() => onCveClick(cveId)}
            >
              {cveId}
            </button>
          ) : (
            <span className="mono">{cveId ?? '-'}</span>
          )
        },
        severity: { content: cve.severity ?? '-' },
        cvss: { content: cve.cvssScore?.toFixed(1) ?? '-' },
        epss: { content: formatPercent(cve.epssScore) },
        software: { content: cve.packageName ?? '-' },
        version: {
          content: cve.version ?? '-',
          props: { className: 'mono' }
        },
        evaluated: { content: formatTimestamp(cve.lastEvaluatedAt) }
      }
    };
  });
}

type HostDetailSectionsProps = {
  assetId: string | null;
  hostDetail: HostAssetDetail | null;
  loadingDetail: boolean;
};

function HostDetailSections({ assetId, hostDetail, loadingDetail }: HostDetailSectionsProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = React.useState<HostDetailTab>('software');
  const [eolFilterActive, setEolFilterActive] = React.useState(false);

  const handleCveClick = React.useCallback((cveId: string) => {
    navigate(pathForVulnRepoView('org-cves', cveId), {
      state: { returnTo: location.pathname + location.search }
    });
  }, [navigate, location.pathname, location.search]);

  const handleMoreClick = React.useCallback(() => {
    setActiveTab('applicable-cves');
  }, []);

  const swCallbacks = React.useMemo<SoftwareRowCallbacks>(
    () => ({ onCveClick: handleCveClick, onMoreClick: handleMoreClick }),
    [handleCveClick, handleMoreClick]
  );

  const eolSoftwareCount = React.useMemo(
    () => (hostDetail?.software ?? []).filter(s => s.isEol === true).length,
    [hostDetail?.software]
  );

  const visibleSoftware = React.useMemo(
    () => eolFilterActive
      ? (hostDetail?.software ?? []).filter(s => s.isEol === true)
      : (hostDetail?.software ?? []),
    [hostDetail?.software, eolFilterActive]
  );

  const aliasRows = React.useMemo(() => buildAliasRows(hostDetail?.aliases ?? []), [hostDetail]);
  const softwareRows = React.useMemo(
    () => buildSoftwareRows(visibleSoftware, hostDetail?.applicableCves ?? [], swCallbacks),
    [visibleSoftware, hostDetail?.applicableCves, swCallbacks]
  );
  const serviceRows = React.useMemo(() => buildServiceRows(hostDetail?.software ?? []), [hostDetail]);
  const findingRows = React.useMemo(() => buildFindingRows(hostDetail?.findings ?? []), [hostDetail]);
  const applicableCveRows = React.useMemo(
    () => buildApplicableCveRows(hostDetail?.applicableCves ?? [], handleCveClick),
    [hostDetail?.applicableCves, handleCveClick]
  );

  React.useEffect(() => {
    if (!hostDetail || !location.hash) return;
    const targetId = location.hash.replace(/^#/, '');
    if (!targetId) return;
    if (targetId === 'applicable-cves') {
      setActiveTab('applicable-cves');
    } else if (targetId === 'host-findings') {
      setActiveTab('findings');
    }
    window.requestAnimationFrame(() => {
      document.getElementById(targetId)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }, [hostDetail, location.hash]);

  if (!assetId) {
    return <div className="empty-state"><p>Select a host to load its detail.</p></div>;
  }
  if (loadingDetail) {
    return <div className="empty-state"><p>Loading host detail...</p></div>;
  }
  if (!hostDetail) {
    return <div className="empty-state"><p>No host detail is available for the selected asset.</p></div>;
  }

  const handleEolCardClick = () => {
    setActiveTab('software');
    setEolFilterActive(true);
  };

  return (
    <>
      <div className="host-hero">
        <div className="host-hero-ident">
          <div className="host-hero-icon" aria-hidden="true">🖥</div>
          <div>
            <h2 className="host-hero-title">{hostDetail.host.name}</h2>
            <div className="host-hero-subtitle mono">{hostDetail.host.identifier}</div>
          </div>
        </div>
        <div className="host-hero-actions">
          <button type="button" className="btn btn-secondary">Refresh host</button>
          <button type="button" className="btn btn-secondary">Edit asset</button>
        </div>
      </div>

      <div className="host-summary-strip">
        <div className="host-stat-card">
          <span className="host-stat-label">Criticality</span>
          <span className="host-stat-pill host-stat-pill-warning">{hostDetail.host.businessCriticality ?? '-'}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Asset State</span>
          <span className="host-stat-pill host-stat-pill-success">{hostDetail.host.state ?? 'Active'}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Environment</span>
          <span className="host-stat-value">{hostDetail.host.environment ?? '—'}</span>
        </div>
        <div className="host-stat-card">
          <span className="host-stat-label">Open Findings</span>
          <span className="host-stat-number host-stat-number-danger">
            {formatCount(hostDetail.host.openFindingCount)}
          </span>
        </div>
        <div
          className={`host-stat-card host-stat-card-clickable${eolFilterActive ? ' host-stat-card-eol-active' : ''}`}
          role="button"
          tabIndex={0}
          aria-label={`EOL Entities: ${eolSoftwareCount}. Click to filter installed software to EOL items.`}
          onClick={handleEolCardClick}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ' ') handleEolCardClick();
          }}
        >
          <span className="host-stat-label">EOL Entities</span>
          <span className={`host-stat-number ${eolSoftwareCount > 0 ? 'host-stat-number-warning' : ''}`}>
            {formatCount(eolSoftwareCount)}
          </span>
        </div>
      </div>

      <div className="host-ownership-bar">
        <span className="host-ownership-bar-title">Ownership</span>
        <div className="host-ownership-bar-fields">
          <div className="host-ownership-bar-field">
            <span className="host-ownership-bar-label">Owner</span>
            <span className="host-ownership-bar-value">{hostDetail.host.ownerEmail ?? '—'}</span>
          </div>
          <div className="host-ownership-bar-divider" />
          <div className="host-ownership-bar-field">
            <span className="host-ownership-bar-label">Managed By</span>
            <span className="host-ownership-bar-value">{hostDetail.host.managedBy ?? '—'}</span>
          </div>
          <div className="host-ownership-bar-divider" />
          <div className="host-ownership-bar-field">
            <span className="host-ownership-bar-label">Department</span>
            <span className="host-ownership-bar-value">{hostDetail.host.department ?? '—'}</span>
          </div>
          <div className="host-ownership-bar-divider" />
          <div className="host-ownership-bar-field">
            <span className="host-ownership-bar-label">Support Group</span>
            <span className="host-ownership-bar-value">{hostDetail.host.supportGroup ?? '—'}</span>
          </div>
          <div className="host-ownership-bar-divider" />
          <div className="host-ownership-bar-field">
            <span className="host-ownership-bar-label">Assigned To</span>
            <span className="host-ownership-bar-value">{hostDetail.host.assignedTo ?? '—'}</span>
          </div>
        </div>
      </div>

      {(hostDetail.host.ssmManaged !== undefined || hostDetail.host.missingIamInstanceProfile !== undefined) && (
        <div className="host-ownership-bar">
          <span className="host-ownership-bar-title">SSM</span>
          <div className="host-ownership-bar-fields">
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Managed</span>
              <span className="host-ownership-bar-value">{hostDetail.host.ssmManaged ? 'Yes' : 'No'}</span>
            </div>
            <div className="host-ownership-bar-divider" />
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Ping</span>
              <span className="host-ownership-bar-value">{hostDetail.host.ssmPingStatus ?? '—'}</span>
            </div>
            <div className="host-ownership-bar-divider" />
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Last Ping</span>
              <span className="host-ownership-bar-value">{formatTimestamp(hostDetail.host.ssmLastPingAt)}</span>
            </div>
            <div className="host-ownership-bar-divider" />
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Software Inventory</span>
              <span className="host-ownership-bar-value">{hostDetail.host.ssmInventoryAvailable ? 'Available' : 'Not available'}</span>
            </div>
            <div className="host-ownership-bar-divider" />
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">IAM Profile</span>
              <span className="host-ownership-bar-value">{hostDetail.host.missingIamInstanceProfile ? 'Missing' : 'Present'}</span>
            </div>
          </div>
        </div>
      )}

      {hostDetail.bomEvidence.documentCount > 0 && (
        <div className="host-ownership-bar">
          <span className="host-ownership-bar-title">BOM Evidence</span>
          <div className="host-ownership-bar-fields">
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Documents</span>
              <span className="host-ownership-bar-value">{formatCount(hostDetail.bomEvidence.documentCount)}</span>
            </div>
            <div className="host-ownership-bar-divider" />
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Matched Components</span>
              <span className="host-ownership-bar-value">{formatCount(hostDetail.bomEvidence.componentCount)}</span>
            </div>
            <div className="host-ownership-bar-divider" />
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Vulnerability Links</span>
              <span className="host-ownership-bar-value">{formatCount(hostDetail.bomEvidence.vulnerabilityLinkCount)}</span>
            </div>
            <div className="host-ownership-bar-divider" />
            <div className="host-ownership-bar-field">
              <span className="host-ownership-bar-label">Workflows</span>
              <span className="host-ownership-bar-value">{formatCount(hostDetail.bomEvidence.componentsInWorkflow)}</span>
            </div>
          </div>
        </div>
      )}

      <div className="host-detail-tabs" role="tablist" aria-label="Host detail sections">
        <button
          type="button"
          className={`host-detail-tab ${activeTab === 'software' ? 'active' : ''}`}
          onClick={() => setActiveTab('software')}
        >
          Installed software
        </button>
        <button
          type="button"
          className={`host-detail-tab ${activeTab === 'services' ? 'active' : ''}`}
          onClick={() => setActiveTab('services')}
        >
          Services
        </button>
        <button
          type="button"
          className={`host-detail-tab ${activeTab === 'applicable-cves' ? 'active' : ''}`}
          onClick={() => setActiveTab('applicable-cves')}
        >
          Applicable CVEs
        </button>
        <button
          type="button"
          className={`host-detail-tab ${activeTab === 'findings' ? 'active' : ''}`}
          onClick={() => setActiveTab('findings')}
        >
          Created findings
        </button>
        <button
          type="button"
          className={`host-detail-tab ${activeTab === 'aliases' ? 'active' : ''}`}
          onClick={() => setActiveTab('aliases')}
        >
          Host aliases
        </button>
      </div>

      <div className="host-detail-surface">
        {hostDetail.bomEvidence.documentCount > 0 ? (
          <div className="inventory-section-card" style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'grid', gap: '0.75rem' }}>
              <div>
                <div className="panel-label">Latest BOM Documents</div>
                <div style={{ display: 'grid', gap: '0.5rem', marginTop: '0.5rem' }}>
                  {hostDetail.bomEvidence.documents.slice(0, 3).map((document) => (
                    <div key={document.bomId} style={{ display: 'grid', gap: '0.15rem' }}>
                      <strong>{document.documentName || document.sourceLabel || document.sourceReference || document.bomId.slice(0, 8)}</strong>
                      <span className="panel-caption">
                        {formatBomLabel(document.specFamily)} · {formatBomLabel(document.documentFormat)} · {formatBomLabel(document.sourceSystem || document.sourceType)} · {formatCount(document.componentCount)} components
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div className="panel-label">Matched BOM Components</div>
                <div style={{ display: 'grid', gap: '0.5rem', marginTop: '0.5rem' }}>
                  {hostDetail.bomEvidence.components.slice(0, 5).map((component) => (
                    <div key={component.componentId} style={{ display: 'grid', gap: '0.15rem' }}>
                      <strong>{component.name}{component.version ? ` ${component.version}` : ''}</strong>
                      <span className="panel-caption">
                        {formatCount(component.vulnerabilityCount)} vuln links · {formatCount(component.evidenceCount)} evidence rows · {formatBomLabel(component.workflowStatus)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ) : null}

        {activeTab === 'software' ? (
          <>
            {eolFilterActive && (
              <div className="host-eol-filter-banner">
                <span>Showing EOL software only ({visibleSoftware.length} item{visibleSoftware.length !== 1 ? 's' : ''})</span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setEolFilterActive(false)}
                >
                  Clear filter
                </button>
              </div>
            )}
            {softwareRows.length === 0 ? (
              <div className="empty-state">
                <p>
                  {eolFilterActive
                    ? 'No EOL software found on this host.'
                    : 'No host software has been materialized for this host yet.'}
                </p>
              </div>
            ) : (
              <div className="table-scroll">
                <DataTable
                  storageKey="host-detail-software-table-widths"
                  columns={SOFTWARE_COLUMNS}
                  rows={softwareRows}
                />
              </div>
            )}
          </>
        ) : null}

        {activeTab === 'services' ? (
          serviceRows.length === 0 ? (
            <div className="empty-state">
              <p>No active services detected on this host.</p>
            </div>
          ) : (
            <div className="table-scroll">
              <DataTable
                storageKey="host-detail-services-table-widths"
                columns={SERVICE_COLUMNS}
                rows={serviceRows}
              />
            </div>
          )
        ) : null}

        {activeTab === 'aliases' ? (
          aliasRows.length === 0 ? (
            <div className="empty-state"><p>No aliases were recorded for this host.</p></div>
          ) : (
            <div className="table-scroll">
              <DataTable
                storageKey="host-detail-aliases-table-widths"
                columns={ALIAS_COLUMNS}
                rows={aliasRows}
              />
            </div>
          )
        ) : null}

        {activeTab === 'applicable-cves' ? (
          applicableCveRows.length === 0 ? (
            <div id="applicable-cves" className="empty-state">
              <p>No applicable CVEs are currently correlated to this host.</p>
            </div>
          ) : (
            <div id="applicable-cves" className="table-scroll">
              <DataTable
                storageKey="host-detail-applicable-cves-table-widths"
                columns={APPLICABLE_CVE_COLUMNS}
                rows={applicableCveRows}
              />
            </div>
          )
        ) : null}

        {activeTab === 'findings' ? (
          findingRows.length === 0 ? (
            <div id="host-findings" className="empty-state">
              <p>No findings are currently attached to this host.</p>
            </div>
          ) : (
            <div id="host-findings">
              <div className="host-findings-actions">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate(pathForFindingsWithFilters({ assetName: hostDetail?.host.name ?? undefined }))}
                >
                  View all in Findings →
                </button>
              </div>
              <div className="table-scroll">
                <DataTable
                  storageKey="host-detail-findings-table-widths"
                  columns={FINDING_COLUMNS}
                  rows={findingRows}
                />
              </div>
            </div>
          )
        ) : null}

      </div>
    </>
  );
}

export function HostAssetDetailPage({ assetId, onClose }: HostAssetDetailPageProps = {}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const selectedAssetId = assetId ?? readHostAssetIdFromSearch(searchParams);
  const returnTo = searchParams.get('returnTo')?.trim() || (
    typeof location.state === 'object' && location.state && 'returnTo' in location.state
      ? String((location.state as { returnTo?: string }).returnTo ?? '').trim()
      : ''
  );
  const hostDetailQuery = useHostAssetDetailQuery(selectedAssetId);
  const selectedHost = hostDetailQuery.data ?? null;
  const loadingDetail = hostDetailQuery.isLoading || hostDetailQuery.isFetching;
  const error = hostDetailQuery.error instanceof Error ? hostDetailQuery.error.message : '';

  const handleClose = React.useCallback(() => {
    if (onClose) {
      onClose();
      return;
    }
    if (returnTo) {
      navigate(returnTo);
      return;
    }
    navigate(-1);
  }, [navigate, onClose, returnTo]);

  return (
    <section className="host-detail-page">
      {(onClose || returnTo) && (
        <div className="button-row host-detail-close-row">
          <button
            type="button"
            className="modal-close-btn"
            onClick={handleClose}
            aria-label="Close host detail"
          >
            x
          </button>
        </div>
      )}
      {error && <div className="notice error">{error}</div>}
      <HostDetailSections assetId={selectedAssetId} hostDetail={selectedHost} loadingDetail={loadingDetail} />
    </section>
  );
}
