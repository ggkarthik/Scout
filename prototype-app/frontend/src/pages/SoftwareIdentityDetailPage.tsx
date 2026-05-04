import { useMutation, useQuery } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import type { Finding } from '../features/findings/types';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForInventoryHostAsset, pathForInventoryView, pathForVulnRepoView } from '../app/routes';
import { api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import { useVulnRepoVulnerabilitiesQuery } from '../features/cve-workbench/queries';
import { useSoftwareIdentityDetailQuery, useSoftwareIdentityMetadataQuery } from '../features/software-identities/queries';
import type { SoftwareIdentityAsset, SoftwareIdentityDetail, SoftwareIdentityMetadata } from '../features/software-identities/types';

type Props = {
  softwareIdentityId: string;
};

type DetailTab = 'versions' | 'assets' | 'vulnerabilities' | 'findings';

const VERSION_COLUMNS: DataTableColumn[] = [
  { id: 'version', label: 'Version', header: 'Version', initialSize: 180 },
  { id: 'hosts', label: 'Installed Hosts', header: 'Installed Hosts', initialSize: 140 },
  { id: 'assets', label: 'Assets', header: 'Assets', initialSize: 110 },
  { id: 'rows', label: 'Rows', header: 'Rows', initialSize: 90 },
  { id: 'cves', label: 'CVEs', header: 'CVEs', initialSize: 90 },
  { id: 'findings', label: 'Findings', header: 'Findings', initialSize: 100 },
  { id: 'lifecycle', label: 'Lifecycle', header: 'Lifecycle', initialSize: 150 },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 170 }
];

const ASSET_COLUMNS_BASE: DataTableColumn[] = [
  { id: 'select', label: '', header: '', initialSize: 48 },
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 260 },
  { id: 'package', label: 'Package', header: 'Package', initialSize: 160 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 150 },
  { id: 'cves', label: 'CVEs', header: 'CVEs', initialSize: 90 },
  { id: 'findings', label: 'Findings', header: 'Findings', initialSize: 100 },
  { id: 'type', label: 'Type', header: 'Type', initialSize: 110 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 130 },
];

const VULNERABILITY_COLUMNS: DataTableColumn[] = [
  { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 170 },
  { id: 'title', label: 'Description', header: 'Description', initialSize: 380 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'matchedAssets', label: 'Assets', header: 'Assets', initialSize: 90 },
  { id: 'applicable', label: 'Applicable Components', header: 'Applicable Components', initialSize: 160 },
  { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 130 },
  { id: 'lastEvaluated', label: 'Last Evaluated', header: 'Last Evaluated', initialSize: 170 }
];

const FINDING_COLUMNS: DataTableColumn[] = [
  { id: 'findingId', label: 'Finding ID', header: 'Finding ID', initialSize: 120 },
  { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 170 },
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 240 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 110 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 130 },
  { id: 'package', label: 'Package', header: 'Package', initialSize: 160 },
  { id: 'dueAt', label: 'Due Date', header: 'Due Date', initialSize: 140 },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 170 },
];

function defaultMetadata(softwareIdentityId = ''): SoftwareIdentityMetadata {
  return {
    softwareIdentityId,
    owner: '',
    licensed: 'Unknown',
    licenseType: '',
    supportGroup: '',
    recommendation: ''
  };
}

function formatDateTime(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '-' : parsed.toLocaleString();
}

function lifecycleLabel(eolCount: number, nearEolCount: number, unknownCount: number): string {
  if (eolCount > 0) return `${eolCount.toLocaleString()} EOL`;
  if (nearEolCount > 0) return `${nearEolCount.toLocaleString()} near EOL`;
  if (unknownCount > 0) return `${unknownCount.toLocaleString()} unknown lifecycle`;
  return 'Supported';
}

function lifecycleClassName(detail: SoftwareIdentityDetail): string {
  if (detail.eolComponentCount > 0) return 'status-pill status-failure';
  if (detail.nearEolComponentCount > 0) return 'status-pill status-warning';
  if (detail.unknownEolComponentCount > 0) return 'status-pill status-unknown';
  return 'status-pill status-success';
}

function extractAiRecommendation(response: { recommendation?: string; data?: Record<string, unknown> }): string {
  const data = response.data;
  const bottomLine = data?.bottom_line;
  if (bottomLine && typeof bottomLine === 'object') {
    const summary = (bottomLine as { summary?: unknown }).summary;
    if (typeof summary === 'string' && summary.trim()) return summary.trim();
  }
  const immediate = data?.immediate_action;
  if (immediate && typeof immediate === 'object') {
    const action = (immediate as { action?: unknown }).action;
    if (typeof action === 'string' && action.trim()) return action.trim();
  }
  if (response.recommendation?.trim()) return response.recommendation.trim();
  return 'No recommendation was returned.';
}

function timeAgo(value?: string): string {
  if (!value) return 'unknown';
  const diff = Date.now() - new Date(value).getTime();
  if (diff < 0) return 'just now';
  const hours = Math.floor(diff / 3_600_000);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(diff / 86_400_000);
  return `${days}d ago`;
}

function buildFallbackRecommendation(detail: SoftwareIdentityDetail, vulnerabilities: OrgSpecificCveExposureRecord[]): string {
  const parts: string[] = [];
  const criticalCount = detail.assets.filter(isCriticalAsset).length;
  const eolVersions = detail.versions.filter((v) => v.isEol);
  const nearEolVersions = detail.versions.filter((v) => !v.isEol && v.eolDaysRemaining != null && v.eolDaysRemaining <= 90);
  const supportedVersions = detail.versions.filter((v) => !v.isEol && (v.eolDaysRemaining == null || v.eolDaysRemaining > 90) && v.eolSlug);

  parts.push(
    `${detail.displayName} is installed on ${detail.assetCount.toLocaleString()} asset${detail.assetCount !== 1 ? 's' : ''}` +
    (criticalCount > 0 ? `, including ${criticalCount} critical asset${criticalCount !== 1 ? 's' : ''}` : '') +
    `, with ${detail.openVulnerabilityCount.toLocaleString()} open CVE${detail.openVulnerabilityCount !== 1 ? 's' : ''}.`
  );

  const topCves = vulnerabilities.slice(0, 3).map((v) => v.externalId);
  if (topCves.length > 0) {
    parts.push(`Highest-priority vulnerabilities to remediate: ${topCves.join(', ')}.`);
  }

  if (eolVersions.length > 0) {
    const eolList = eolVersions.slice(0, 3).map((v) => v.version).join(', ');
    parts.push(`${eolVersions.length} EOL version${eolVersions.length !== 1 ? 's' : ''} detected (${eolList}) — these no longer receive security patches and must be upgraded immediately.`);
  } else if (nearEolVersions.length > 0) {
    parts.push(`${nearEolVersions.length} version${nearEolVersions.length !== 1 ? 's are' : ' is'} approaching end-of-life within 90 days — schedule upgrades promptly.`);
  }

  if (supportedVersions.length > 0) {
    parts.push(`Recommended upgrade target: version ${supportedVersions[0].version} (actively supported).`);
  } else if (detail.eolSlug) {
    parts.push(`Consult the ${detail.eolSlug} release schedule to identify the latest supported version.`);
  }

  parts.push(`After upgrading: re-run vulnerability scans, validate application functionality, update the CMDB record, and close or reassign open findings resolved by the upgrade.`);

  return parts.join(' ');
}

function buildSoftwareRecommendationPrompt(
  detail: SoftwareIdentityDetail,
  cve: Pick<OrgSpecificCveExposureRecord, 'externalId' | 'title' | 'severity' | 'cvssScore'> | null,
  affectedAssets: number,
  environmentContext: string
): string {
  const productLabel = [detail.displayName, detail.product ? `version ${detail.product}` : null].filter(Boolean).join(' ');
  const cveLine = cve
    ? `Vulnerability/CVE: ${cve.externalId} - ${cve.title}`
    : 'Vulnerability/CVE: No specific CVE selected; generate a software-level remediation recommendation.';
  const cvss = cve?.cvssScore != null ? `${cve.cvssScore.toFixed(1)}` : 'unknown';

  return [
    'You are a cybersecurity remediation advisor writing for an enterprise IT operations team. Generate a concise, actionable remediation recommendation for the following software vulnerability.',
    'Input details:',
    '',
    `Software/Product: ${productLabel || 'unknown'}`,
    cveLine,
    `Severity (CVSS): ${cve?.severity ?? 'UNKNOWN'}${cvss === 'unknown' ? '' : ` (${cvss})`}`,
    `Number of affected assets: ${affectedAssets.toLocaleString()}`,
    `Environment context (optional): ${environmentContext || 'unknown'}`,
    '',
    'Produce a recommendation with these sections:',
    '',
    'Risk summary (2–3 sentences): What the vulnerability is, what an attacker could do, and why it matters given the asset count and exposure.',
    'Primary remediation: The vendor-recommended fix (specific patch version, security update, or upgrade path). Include version numbers and links to vendor advisories where applicable.',
    'Compensating controls (if patching is delayed): Network segmentation, WAF/IPS rules, access restrictions, disabling vulnerable features, or monitoring guidance.',
    'Verification steps: How the IT team can confirm the fix was applied successfully (e.g., version check command, vulnerability rescan).',
    'Priority and SLA: Recommended urgency (Critical/High/Medium/Low) and target remediation window based on severity and exposure.',
    'Rollback considerations: Known compatibility issues, dependencies, or pre-patch testing steps.',
    '',
    'Keep the tone direct and operational. Avoid generic advice — tie every step to this specific CVE and software version. If information is unknown, state the assumption clearly rather than fabricating details.',
    'Limit the final response to 200 words or fewer.'
  ].join('\n');
}

export function SoftwareIdentityDetailPage({ softwareIdentityId }: Props) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = React.useState<DetailTab>('versions');
  const [findingMessage, setFindingMessage] = React.useState('');
  const [metadata, setMetadata] = React.useState<SoftwareIdentityMetadata>(() => defaultMetadata(softwareIdentityId));
  const [draftMetadata, setDraftMetadata] = React.useState<SoftwareIdentityMetadata>(() => defaultMetadata(softwareIdentityId));
  const [showFindingConfig, setShowFindingConfig] = React.useState(false);
  const [findingPriority, setFindingPriority] = React.useState('Medium');
  const [findingDueDate, setFindingDueDate] = React.useState(() => {
    const date = new Date();
    date.setDate(date.getDate() + 30);
    return date.toISOString().slice(0, 10);
  });
  const [findingTags, setFindingTags] = React.useState('');
  const [findingAssignment, setFindingAssignment] = React.useState('Assign to lead analyst');
  const [createServiceNowTickets, setCreateServiceNowTickets] = React.useState(true);
  const [findingNotes, setFindingNotes] = React.useState('');
  const [selectedCves, setSelectedCves] = React.useState<Set<string>>(new Set());
  const [selectedComponentIds, setSelectedComponentIds] = React.useState<Set<string>>(new Set());
  const [modalRecommendation, setModalRecommendation] = React.useState('');
  const [isEditingRec, setIsEditingRec] = React.useState(false);
  const [draftVendor, setDraftVendor] = React.useState('');

  const detailQuery = useSoftwareIdentityDetailQuery(softwareIdentityId);
  const metadataQuery = useSoftwareIdentityMetadataQuery(softwareIdentityId);
  // Omit includeAll so server returns only applicable CVEs for this software identity
  const vulnerabilitiesQuery = useVulnRepoVulnerabilitiesQuery({
    page: 0,
    size: 100,
    softwareIdentityId,
  });

  const detail = detailQuery.data ?? null;
  const vulnerabilities = React.useMemo(
    () => vulnerabilitiesQuery.data?.items ?? [],
    [vulnerabilitiesQuery.data?.items]
  );

  const findingsQuery = useQuery({
    queryKey: ['software-identity-findings', softwareIdentityId, detail?.product],
    queryFn: () => api.listFindings({ packageName: detail?.product ?? '', size: 200 }),
    enabled: Boolean(detail?.product),
  });
  const findings = React.useMemo<Finding[]>(
    () => findingsQuery.data?.items ?? [],
    [findingsQuery.data?.items]
  );

  React.useEffect(() => {
    const next = metadataQuery.data ?? defaultMetadata(softwareIdentityId);
    setMetadata(next);
    setDraftMetadata(next);
  }, [metadataQuery.data, softwareIdentityId]);

  React.useEffect(() => {
    if (detail?.vendor) setDraftVendor(detail.vendor);
  }, [detail?.vendor]);


  const saveMetadataMutation = useMutation({
    mutationFn: (next: SoftwareIdentityMetadata) => api.saveSoftwareIdentityMetadata(softwareIdentityId, {
      owner: next.owner,
      licensed: next.licensed,
      licenseType: next.licenseType,
      supportGroup: next.supportGroup,
      recommendation: next.recommendation
    }),
    onSuccess: (saved) => {
      setMetadata(saved);
      setDraftMetadata(saved);
      setFindingMessage('Software metadata saved.');
      void metadataQuery.refetch();
    },
    onError: (error) => {
      setFindingMessage(error instanceof Error ? error.message : 'Failed to save software metadata.');
    }
  });

  // Select ALL applicable CVEs by default when they load
  React.useEffect(() => {
    if (selectedCves.size === 0 && vulnerabilities.length > 0) {
      setSelectedCves(new Set(vulnerabilities.map((v) => v.externalId)));
    }
  }, [selectedCves.size, vulnerabilities]);

  const selectedAssets = React.useMemo(
    () => (detail?.assets ?? []).filter((asset) => selectedComponentIds.has(asset.componentId)),
    [detail?.assets, selectedComponentIds]
  );

  const selectedCveRecords = React.useMemo(
    () => vulnerabilities.filter((item) => selectedCves.has(item.externalId)),
    [selectedCves, vulnerabilities]
  );

  const generateRecommendationMutation = useMutation({
    mutationFn: async () => {
      if (!detail) throw new Error('Software identity is not loaded.');
      const primaryCve = vulnerabilities[0] ?? null;
      const eolVersionsList = detail.versions.filter((v) => v.isEol);
      const nearEolVersionsList = detail.versions.filter((v) => !v.isEol && v.eolDaysRemaining != null && v.eolDaysRemaining <= 90);
      const supportedVersionsList = detail.versions.filter((v) => !v.isEol && (v.eolDaysRemaining == null || v.eolDaysRemaining > 90) && v.eolSlug);
      const criticalAssetsList = detail.assets.filter(isCriticalAsset);
      const environmentContext = detail.sourceSystems.length > 0 ? detail.sourceSystems.join(', ') : 'unknown';
      const softwareRecommendationPrompt = buildSoftwareRecommendationPrompt(
        detail,
        primaryCve,
        detail.assetCount,
        environmentContext
      );
      const response = await cveWorkbenchApi.generateAiSolution(primaryCve?.externalId ?? `software-${detail.id}`, {
        softwareRecommendationPrompt,
        severity: primaryCve?.severity ?? (detail.openVulnerabilityCount > 0 ? 'MEDIUM' : 'LOW'),
        affected_assets: detail.assetCount,
        vulnerability: {
          id: primaryCve?.externalId ?? detail.canonicalKey,
          summary: primaryCve ? (primaryCve.descriptionSnippet || primaryCve.title) : `${detail.displayName} software-level recommendation`
        },
        software: {
          id: detail.id,
          name: detail.displayName,
          vendor: detail.vendor,
          product: detail.product,
          owner: metadata.owner || null,
          licensed: metadata.licensed,
          license_type: metadata.licenseType || null,
          support_group: metadata.supportGroup || null,
          lifecycle: lifecycleLabel(detail.eolComponentCount, detail.nearEolComponentCount, detail.unknownEolComponentCount),
          installed_asset_count: detail.assetCount,
          installed_software_rows: detail.componentCount,
          eol_version_count: eolVersionsList.length,
          eol_versions: eolVersionsList.slice(0, 5).map((v) => v.version),
          near_eol_version_count: nearEolVersionsList.length,
          recommended_upgrade_version: supportedVersionsList[0]?.version ?? null,
          eol_slug: detail.eolSlug ?? null,
        },
        selected_cves: vulnerabilities.map((item) => ({
          cve: item.externalId,
          severity: item.severity,
          cvss_score: item.cvssScore,
          applicable_components: item.applicableComponentCount,
          open_findings: item.openFindings
        })),
        selected_assets: detail.assets.slice(0, 20).map((asset) => ({
          name: asset.assetName,
          type: asset.assetType,
          version: asset.version,
          open_cves: asset.openVulnerabilityCount,
          open_findings: asset.openFindingCount,
          is_critical: isCriticalAsset(asset),
          is_eol: asset.isEol ?? false,
        })),
          critical_asset_count: criticalAssetsList.length,
          post_upgrade_actions: [
            'Re-run vulnerability scans after upgrade',
            'Validate application functionality and integration points',
            'Update CMDB with new version details',
          'Close or reassign open findings resolved by the upgrade',
          'Notify application owner and support group of completion',
        ],
      });
      return extractAiRecommendation(response);
    },
    onSuccess: (recommendation) => {
      // Update the draft textarea only — user must explicitly save
      setDraftMetadata((prev) => ({ ...prev, recommendation }));
    },
    onError: (error) => {
      setFindingMessage(error instanceof Error ? error.message : 'Failed to generate AI recommendation.');
    }
  });

  const createFindingsMutation = useMutation({
    mutationFn: async () => {
      if (selectedCveRecords.length === 0) throw new Error('Select at least one CVE.');
      if (selectedComponentIds.size === 0) throw new Error('Select at least one asset.');
      const recommendation = modalRecommendation.trim()
        || metadata.recommendation?.trim()
        || (detail ? buildFallbackRecommendation(detail, selectedCveRecords) : '');
      const componentIds = Array.from(selectedComponentIds);
      const results = await Promise.all(selectedCveRecords.map((record) =>
        cveWorkbenchApi.createManualFindings(record.externalId, {
          justification: [
            `Created from software record ${detail?.displayName ?? softwareIdentityId}.`,
            `Priority: ${findingPriority}`,
            `Due date: ${findingDueDate || 'Not set'}`,
            findingTags.trim() ? `Tags: ${findingTags.trim()}` : null,
            `Assignment: ${findingAssignment}`,
            `Create ServiceNow tickets: ${createServiceNowTickets ? 'Yes' : 'No'}`,
            findingNotes.trim() ? `Notes: ${findingNotes.trim()}` : null,
            recommendation ? `Recommendation: ${recommendation}` : null
          ].filter(Boolean).join('\n\n'),
          componentIds,
          componentApplicabilityDecisions: Object.fromEntries(componentIds.map((id) => [id, 'APPLICABLE'])),
          componentAnalystDispositions: Object.fromEntries(componentIds.map((id) => [id, 'IMPACTED']))
        })
      ));
      return results;
    },
    onSuccess: (responses) => {
      const created = responses.reduce((sum, response) => sum + response.createdCount + response.reopenedCount, 0);
      const alreadyOpen = responses.reduce((sum, response) => sum + response.alreadyOpenCount, 0);
      setFindingMessage(`Created or reopened ${created.toLocaleString()} findings. ${alreadyOpen.toLocaleString()} were already open.`);
      setShowFindingConfig(false);
      void vulnerabilitiesQuery.refetch();
      void detailQuery.refetch();
    },
    onError: (error) => {
      setFindingMessage(error instanceof Error ? error.message : 'Failed to create findings.');
    }
  });

  const toggleCve = React.useCallback((externalId: string) => {
    setSelectedCves((current) => {
      const next = new Set(current);
      if (next.has(externalId)) next.delete(externalId);
      else next.add(externalId);
      return next;
    });
  }, []);

  const toggleComponent = React.useCallback((componentId: string) => {
    setSelectedComponentIds((current) => {
      const next = new Set(current);
      if (next.has(componentId)) next.delete(componentId);
      else next.add(componentId);
      return next;
    });
  }, []);

  const allAssetIds = React.useMemo(() => (detail?.assets ?? []).map((a) => a.componentId), [detail?.assets]);
  const allAssetsSelected = allAssetIds.length > 0 && allAssetIds.every((id) => selectedComponentIds.has(id));
  const someAssetsSelected = !allAssetsSelected && allAssetIds.some((id) => selectedComponentIds.has(id));

  const toggleAllAssets = React.useCallback(() => {
    setSelectedComponentIds((current) => {
      const allSelected = allAssetIds.every((id) => current.has(id));
      return allSelected ? new Set() : new Set(allAssetIds);
    });
  }, [allAssetIds]);

  const assetColumns = React.useMemo<DataTableColumn[]>(() => [
    {
      ...ASSET_COLUMNS_BASE[0],
      header: (
        <input
          type="checkbox"
          checked={allAssetsSelected}
          ref={(el) => { if (el) el.indeterminate = someAssetsSelected; }}
          onChange={toggleAllAssets}
          aria-label="Select all assets"
        />
      ),
    },
    ...ASSET_COLUMNS_BASE.slice(1),
  ], [allAssetsSelected, someAssetsSelected, toggleAllAssets]);

  const versionRows = React.useMemo<DataTableRow[]>(() => (detail?.versions ?? []).map((version) => ({
    id: version.version || 'unknown-version',
    cells: {
      version: { content: version.version || '-' },
      hosts: { content: version.assetCount.toLocaleString() },
      assets: { content: version.assetCount.toLocaleString() },
      rows: { content: version.componentCount.toLocaleString() },
      cves: { content: version.openVulnerabilityCount.toLocaleString() },
      findings: { content: version.openFindingCount.toLocaleString() },
      lifecycle: {
        content: version.isEol
          ? <span className="status-pill status-failure">EOL</span>
          : version.eolDaysRemaining != null && version.eolDaysRemaining <= 90
            ? <span className="status-pill status-warning">Near EOL</span>
            : version.eolSlug
              ? <span className="status-pill status-success">Supported</span>
              : <span className="status-pill status-unknown">Unknown</span>
      },
      lastObserved: { content: formatDateTime(version.lastObservedAt) }
    }
  })), [detail?.versions]);

  const assetRows = React.useMemo<DataTableRow[]>(() => (detail?.assets ?? []).map((asset) => ({
    id: asset.componentId,
    cells: {
      select: {
        content: (
          <input
            type="checkbox"
            checked={selectedComponentIds.has(asset.componentId)}
            onChange={() => toggleComponent(asset.componentId)}
            aria-label={`Select ${asset.assetName}`}
          />
        )
      },
      asset: {
        content: (
          <>
            <button
              type="button"
              className="btn-link"
              onClick={() => navigate(pathForInventoryHostAsset(asset.assetId, `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`))}
            >
              {asset.assetName}
            </button>
            <div className="panel-caption mono">{asset.assetIdentifier}</div>
          </>
        )
      },
      type: { content: asset.assetType },
      package: { content: asset.packageName },
      version: { content: asset.version || '-' },
      source: { content: asset.sourceSystem || '-' },
      cves: { content: asset.openVulnerabilityCount.toLocaleString() },
      findings: { content: asset.openFindingCount.toLocaleString() },
      lastObserved: { content: formatDateTime(asset.lastObservedAt) }
    }
  })), [detail?.assets, navigate, selectedComponentIds, softwareIdentityId, toggleComponent]);

  const vulnerabilityRows = React.useMemo<DataTableRow[]>(() => vulnerabilities.map((item) => ({
    id: item.recordId,
    cells: {
      cve: {
        content: (
          <button type="button" className="btn-link" onClick={() => navigate(pathForVulnRepoView('org-cves', item.externalId))}>
            <span className="mono">{item.externalId}</span>
          </button>
        )
      },
      title: { content: item.descriptionSnippet?.trim() || item.title },
      severity: { content: <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span> },
      matchedAssets: { content: item.matchedAssetCount.toLocaleString() },
      applicable: { content: item.applicableComponentCount.toLocaleString() },
      openFindings: { content: item.openFindings.toLocaleString() },
      lastEvaluated: { content: formatDateTime(item.lastEvaluatedAt) }
    }
  })), [navigate, selectedCves, toggleCve, vulnerabilities]);

  const findingRows = React.useMemo<DataTableRow[]>(() => findings.map((f) => ({
    id: f.id,
    cells: {
      findingId: {
        content: <span className="mono" style={{ fontSize: '0.8rem' }}>{f.displayId || f.id.slice(0, 8)}</span>
      },
      cve: {
        content: (
          <button type="button" className="btn-link" onClick={() => navigate(pathForVulnRepoView('org-cves', f.vulnerabilityId))}>
            <span className="mono">{f.vulnerabilityId}</span>
          </button>
        )
      },
      asset: {
        content: (
          <>
            <button type="button" className="btn-link" onClick={() => navigate(pathForInventoryHostAsset(f.componentId, `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`))}>
              {f.assetName}
            </button>
            <div className="panel-caption mono">{f.assetIdentifier}</div>
          </>
        )
      },
      severity: { content: <span className={severityClassName(f.severity)}>{formatLabel(f.severity)}</span> },
      status: { content: <span className={`status-pill ${f.status === 'OPEN' ? 'status-open' : f.status === 'RESOLVED' ? 'status-success' : 'status-unknown'}`}>{formatLabel(f.status)}</span> },
      package: { content: `${f.packageName} ${f.packageVersion}`.trim() },
      dueAt: { content: formatDateTime(f.dueAt) },
      lastObserved: { content: formatDateTime(f.lastObservedAt) },
    }
  })), [findings, navigate, softwareIdentityId]);

  if (detailQuery.isLoading) {
    return <div className="notice">Loading software identity...</div>;
  }

  if (detailQuery.error instanceof Error) {
    return <div className="notice error">{detailQuery.error.message}</div>;
  }

  if (!detail) {
    return <div className="notice error">Software identity was not found.</div>;
  }

  const criticalAssets = detail.assets.filter(isCriticalAsset);
  const eolVersionCount = detail.versions.filter((version) => version.isEol || (version.eolDaysRemaining != null && version.eolDaysRemaining <= 90)).length;

  return (
    <section className="inventory-page-shell software-detail-page">
      <div className="inventory-section-card sdi-page">

        {/* Hero */}
        <div className="sdi-hero">
          <button type="button" className="btn-link sdi-back-link" onClick={() => navigate(pathForInventoryView('software-identities'))}>
            ← Back to Software Entities
          </button>
          <div className="sdi-hero-layout">
            {/* Left — title + subtitle + pill row */}
            <div className="sdi-title-block">
              <h1 className="sdi-title">
                {detail.vendor && detail.product && detail.vendor.toLowerCase() !== detail.product.toLowerCase() ? (
                  <>
                    <span className="sdi-title-vendor">{detail.vendor}</span>
                    <span className="sdi-title-sep">/</span>
                    <span className="sdi-title-product">{detail.product}</span>
                  </>
                ) : (
                  <span className="sdi-title-product">{detail.displayName}</span>
                )}
              </h1>
              <div className="sdi-subtitle">
                <span>{detail.versionCount.toLocaleString()} {detail.versionCount === 1 ? 'version' : 'versions'} observed</span>
                {detail.lastObservedAt ? (
                  <>
                    <span className="sdi-subtitle-sep">·</span>
                    <span>last seen <strong>{timeAgo(detail.lastObservedAt)}</strong></span>
                  </>
                ) : null}
                {detail.sourceSystems.length > 0 ? (
                  <>
                    <span className="sdi-subtitle-sep">·</span>
                    <span>discovered via <strong>{detail.sourceSystems[0]}</strong></span>
                  </>
                ) : null}
              </div>
              {/* Signal pills */}
              <div className="sdi-hero-pills">
                {detail.ecosystems.map((v) => (
                  <span key={v} className="sdi-hero-pill">{v}</span>
                ))}
                {detail.sourceSystems.map((v) => (
                  <span key={v} className="sdi-hero-pill sdi-hero-pill--source">{v}</span>
                ))}
                <span className={`sdi-hero-pill ${eolVersionCount > 0 ? 'sdi-hero-pill--danger' : detail.nearEolComponentCount > 0 ? 'sdi-hero-pill--warn' : 'sdi-hero-pill--ok'}`}>
                  {lifecycleLabel(detail.eolComponentCount, detail.nearEolComponentCount, detail.unknownEolComponentCount)}
                </span>
                {criticalAssets.length > 0 && vulnerabilities.length > 0 ? (
                  <button
                    type="button"
                    className="sdi-hero-pill sdi-hero-pill--danger sdi-hero-pill--link"
                    onClick={() => navigate(pathForVulnRepoView('org-cves', vulnerabilities[0].externalId))}
                  >
                    ⚠ {criticalAssets.length} critical asset{criticalAssets.length !== 1 ? 's' : ''} · top: {vulnerabilities[0].externalId}
                  </button>
                ) : null}
              </div>
            </div>

            {/* Right — metric cards */}
            <div className="sdi-hero-metrics">
              <div className={`sdi-metric-card${detail.assetCount > 0 ? ' sdi-metric-card--accent' : ''}`}>
                <div className="sdi-metric-value">{detail.assetCount.toLocaleString()}</div>
                <div className="sdi-metric-label">Assets</div>
              </div>
              <div className={`sdi-metric-card${detail.openVulnerabilityCount > 0 ? ' sdi-metric-card--critical' : ''}`}>
                <div className="sdi-metric-value">{detail.openVulnerabilityCount.toLocaleString()}</div>
                <div className="sdi-metric-label">Open CVEs</div>
              </div>
              <div className={`sdi-metric-card${detail.openFindingCount > 0 ? ' sdi-metric-card--critical' : ''}`}>
                <div className="sdi-metric-value">{detail.openFindingCount.toLocaleString()}</div>
                <div className="sdi-metric-label">Open Findings</div>
              </div>
              <div className={`sdi-metric-card${criticalAssets.length > 0 ? ' sdi-metric-card--warn' : ''}`}>
                <div className="sdi-metric-value">{criticalAssets.length.toLocaleString()}</div>
                <div className="sdi-metric-label">Critical Assets</div>
              </div>
              <div className={`sdi-metric-card${eolVersionCount > 0 ? ' sdi-metric-card--warn' : ''}`}>
                <div className="sdi-metric-value">{eolVersionCount.toLocaleString()}</div>
                <div className="sdi-metric-label">EOL Versions</div>
              </div>
            </div>
          </div>
        </div>

        {/* Section 01 — Entity detail */}
        <div className="sdi-section">
          <div className="sdi-section-heading">
            <span className="sdi-section-title">Entity detail</span>
            {metadata.updatedAt ? (
              <span className="sdi-section-meta">LAST SAVE {new Date(metadata.updatedAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase()}</span>
            ) : null}
            <button
              type="button"
              className="btn btn-primary sdi-save-btn"
              onClick={() => saveMetadataMutation.mutate(draftMetadata)}
            >
              {saveMetadataMutation.isPending ? 'Saving...' : 'Save'}
            </button>
          </div>
          <div className="sdi-table">
            <div className="sdi-table-group">POSTURE <span className="sdi-table-group-meta">LIVE SIGNALS FROM CDL</span></div>
            <div className="sdi-table-group-rows">
              <div className="sdi-table-row sdi-table-row--editable">
                <div className="sdi-table-label">VENDOR / PUBLISHER</div>
                <div className="sdi-table-value">
                  <input className="sdi-table-input" value={draftVendor} onChange={(e) => setDraftVendor(e.target.value)} placeholder="Vendor or publisher name" />
                </div>
              </div>
              <div className="sdi-table-row">
                <div className="sdi-table-label">ASSETS</div>
                <div className="sdi-table-value">{detail.assetCount.toLocaleString()}</div>
              </div>
              <div className="sdi-table-row">
                <div className="sdi-table-label">OPEN CVES</div>
                <div className={`sdi-table-value${detail.openVulnerabilityCount > 0 ? ' text-critical' : ''}`}>{detail.openVulnerabilityCount.toLocaleString()}</div>
              </div>
              <div className="sdi-table-row">
                <div className="sdi-table-label">OPEN FINDINGS</div>
                <div className={`sdi-table-value${detail.openFindingCount > 0 ? ' text-critical' : ''}`}>{detail.openFindingCount.toLocaleString()}</div>
              </div>
              <div className="sdi-table-row">
                <div className="sdi-table-label">CRITICAL ASSETS</div>
                <div className={`sdi-table-value${criticalAssets.length > 0 ? ' text-warning' : ''}`}>{criticalAssets.length.toLocaleString()}</div>
              </div>
              <div className="sdi-table-row">
                <div className="sdi-table-label">EOL VERSIONS</div>
                <div className={`sdi-table-value${eolVersionCount > 0 ? ' text-warning' : ''}`}>{eolVersionCount.toLocaleString()}</div>
              </div>
            </div>
            <div className="sdi-table-group">OWNERSHIP <span className="sdi-table-group-meta">EDITABLE · SAVED ON DEMAND</span></div>
            <div className="sdi-table-group-rows">
              <div className="sdi-table-row sdi-table-row--editable">
                <div className="sdi-table-label">OWNER</div>
                <div className="sdi-table-value">
                  <input className="sdi-table-input" value={draftMetadata.owner} onChange={(e) => setDraftMetadata({ ...draftMetadata, owner: e.target.value })} placeholder="Application owner or team" />
                </div>
              </div>
              <div className="sdi-table-row sdi-table-row--editable">
                <div className="sdi-table-label">SUPPORT GROUP</div>
                <div className="sdi-table-value">
                  <input className="sdi-table-input" value={draftMetadata.supportGroup} onChange={(e) => setDraftMetadata({ ...draftMetadata, supportGroup: e.target.value })} placeholder="Support / resolver group" />
                </div>
              </div>
              <div className="sdi-table-row sdi-table-row--editable">
                <div className="sdi-table-label">LICENSED</div>
                <div className="sdi-table-value">
                  <select className="sdi-table-input" value={draftMetadata.licensed} onChange={(e) => setDraftMetadata({ ...draftMetadata, licensed: e.target.value })}>
                    <option value="Unknown">Unknown</option>
                    <option value="Licensed">Licensed</option>
                    <option value="Unlicensed">Unlicensed</option>
                    <option value="Open source">Open source</option>
                  </select>
                </div>
              </div>
              <div className="sdi-table-row sdi-table-row--editable">
                <div className="sdi-table-label">LICENSE TYPE</div>
                <div className="sdi-table-value">
                  <input className="sdi-table-input" value={draftMetadata.licenseType} onChange={(e) => setDraftMetadata({ ...draftMetadata, licenseType: e.target.value })} placeholder="Commercial, GPL, MIT..." />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Section 02 — Remediation recommendation */}
        <div className="sdi-section">
          <div className="sdi-section-heading">
            <span className="sdi-section-title">Remediation recommendation</span>
          </div>
          <div className="sdi-briefing-card">
            <div className="sdi-briefing-header">
              <h3 className="sdi-briefing-title">What to do about this software</h3>
            </div>
            <div className="sdi-briefing-body">
              {isEditingRec ? (
                <textarea
                  className="sdi-briefing-textarea"
                  rows={6}
                  value={draftMetadata.recommendation || buildFallbackRecommendation(detail, vulnerabilities)}
                  onChange={(e) => setDraftMetadata({ ...draftMetadata, recommendation: e.target.value })}
                />
              ) : (
                <p className="sdi-briefing-text">
                  {metadata.recommendation || buildFallbackRecommendation(detail, vulnerabilities)}
                </p>
              )}
            </div>
            <div className="sdi-briefing-footer">
              <div className="sdi-briefing-meta">
                {metadata.recommendationUpdatedAt
                  ? `UPDATED · ${new Date(metadata.recommendationUpdatedAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }).toUpperCase()}`
                  : 'DRAFT · NOT YET SAVED'}
              </div>
              <div className="sdi-briefing-actions">
                {isEditingRec ? (
                  <>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={generateRecommendationMutation.isPending}
                      onClick={() => generateRecommendationMutation.mutate()}
                    >
                      {generateRecommendationMutation.isPending ? 'Generating...' : 'AI Recommendation'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => {
                        setIsEditingRec(false);
                        setDraftMetadata({ ...draftMetadata, recommendation: metadata.recommendation });
                      }}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={saveMetadataMutation.isPending}
                      onClick={() => {
                        const next = { ...draftMetadata, recommendationUpdatedAt: new Date().toISOString() };
                        setMetadata(next);
                        setIsEditingRec(false);
                        saveMetadataMutation.mutate(next);
                      }}
                    >
                      {saveMetadataMutation.isPending ? 'Saving...' : 'Save'}
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => {
                      if (!draftMetadata.recommendation) {
                        setDraftMetadata({ ...draftMetadata, recommendation: metadata.recommendation || buildFallbackRecommendation(detail, vulnerabilities) });
                      }
                      setIsEditingRec(true);
                    }}
                  >
                    Edit
                  </button>
                )}
              </div>
            </div>
          </div>
          {findingMessage ? (
            <div className={`sdi-activity-log${findingMessage.startsWith('Failed') ? ' sdi-activity-log--error' : ' sdi-activity-log--ok'}`}>
              {findingMessage}
            </div>
          ) : null}
        </div>

      </div>

      <div className="section-tab-row">
        {(['versions', 'assets', 'vulnerabilities', 'findings'] as DetailTab[]).map((tab) => (
          <button
            key={tab}
            type="button"
            className={activeTab === tab ? 'section-tab-btn active' : 'section-tab-btn'}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'versions' ? 'Versions' : tab === 'assets' ? 'Installed Assets' : tab === 'vulnerabilities' ? 'CVEs' : 'Findings'}
          </button>
        ))}
        <button
          type="button"
          className="btn btn-primary software-detail-create-findings-btn"
          disabled={selectedComponentIds.size === 0 || selectedCves.size === 0}
          onClick={() => {
            setModalRecommendation(metadata.recommendation?.trim() || (detail ? buildFallbackRecommendation(detail, vulnerabilities) : ''));
            setShowFindingConfig(true);
          }}
        >
          Create findings
        </button>
      </div>

      <div className="inventory-section-card">
        {activeTab === 'versions' ? (
          <TableOrEmpty rows={versionRows} columns={VERSION_COLUMNS} storageKey={`software-identity-versions:v2:${softwareIdentityId}`} empty="No versions are currently associated with this software identity." />
        ) : activeTab === 'assets' ? (
          <TableOrEmpty rows={assetRows} columns={assetColumns} storageKey={`software-identity-assets:v5:${softwareIdentityId}`} empty="No assets are currently associated with this software identity." />
        ) : activeTab === 'vulnerabilities' ? (
          vulnerabilitiesQuery.isLoading ? (
            <div className="notice">Loading CVEs...</div>
          ) : vulnerabilitiesQuery.error instanceof Error ? (
            <div className="notice error">{vulnerabilitiesQuery.error.message}</div>
          ) : (
            <TableOrEmpty rows={vulnerabilityRows} columns={VULNERABILITY_COLUMNS} storageKey={`software-identity-vulnerabilities:v2:${softwareIdentityId}`} empty="No CVEs are currently matched to this software identity." />
          )
        ) : findingsQuery.isLoading ? (
          <div className="notice">Loading findings...</div>
        ) : findingsQuery.error instanceof Error ? (
          <div className="notice error">{findingsQuery.error.message}</div>
        ) : (
          <TableOrEmpty rows={findingRows} columns={FINDING_COLUMNS} storageKey={`software-identity-findings:v3:${softwareIdentityId}`} empty="No findings are currently tied to this software identity." />
        )}
      </div>

      {showFindingConfig ? (
        <div className="modal-overlay" onClick={() => setShowFindingConfig(false)}>
          <div className="modal-panel" onClick={(event) => event.stopPropagation()}>
            <div className="panel-header">
              <div>
                <h3>Finding Configuration</h3>
                <p className="panel-caption">Configure due date, tags, assignment logic, CVEs, and ticket creation for selected impacted assets.</p>
              </div>
              <button type="button" className="modal-close-btn" onClick={() => setShowFindingConfig(false)} aria-label="Close">×</button>
            </div>
            <div className="form-grid">
              <label className="form-field">
                <span>Finding title</span>
                <input value={`${detail.displayName} remediation`} readOnly />
              </label>
              <label className="form-field">
                <span>Priority</span>
                <select value={findingPriority} onChange={(event) => setFindingPriority(event.target.value)}>
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </label>
              <label className="form-field">
                <span>Due date</span>
                <input type="date" value={findingDueDate} onChange={(event) => setFindingDueDate(event.target.value)} />
              </label>
              <label className="form-field">
                <span>Tags</span>
                <input value={findingTags} onChange={(event) => setFindingTags(event.target.value)} placeholder="e.g. internet-facing, patching" />
              </label>
              <label className="form-field form-field-wide">
                <span>Assignment / ownership logic</span>
                <select value={findingAssignment} onChange={(event) => setFindingAssignment(event.target.value)}>
                  <option>Assign to lead analyst</option>
                  <option>Assign to software owner</option>
                  <option>Assign to support group</option>
                  <option>Leave unassigned</option>
                </select>
              </label>
              <label className="software-detail-inline-checkbox">
                <input type="checkbox" checked={createServiceNowTickets} onChange={(event) => setCreateServiceNowTickets(event.target.checked)} />
                <span>Create tickets in ServiceNow</span>
              </label>
              <label className="form-field form-field-wide">
                <span>CVEs <em className="panel-caption" style={{ fontStyle: 'normal' }}>(applicable only — all selected by default)</em></span>
                <div className="software-detail-selection-list software-detail-selection-list-modal">
                  {vulnerabilities.length === 0 ? (
                    <p className="panel-caption" style={{ padding: '8px' }}>No applicable CVEs found for this software.</p>
                  ) : vulnerabilities.map((item) => (
                    <label key={item.externalId} className="software-detail-checkbox-row">
                      <input type="checkbox" checked={selectedCves.has(item.externalId)} onChange={() => toggleCve(item.externalId)} />
                      <span className="mono">{item.externalId}</span>
                      <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span>
                    </label>
                  ))}
                </div>
              </label>
              <label className="form-field form-field-wide">
                <span>Recommendation</span>
                <textarea
                  rows={4}
                  value={modalRecommendation}
                  onChange={(event) => setModalRecommendation(event.target.value)}
                  placeholder="Remediation recommendation for this finding..."
                />
              </label>
              <label className="form-field form-field-wide">
                <span>Notes</span>
                <textarea rows={3} value={findingNotes} onChange={(event) => setFindingNotes(event.target.value)} placeholder="Describe remediation approach or ticket creation context..." />
              </label>
            </div>
            <div className="button-row">
              <button type="button" className="btn btn-secondary" onClick={() => setShowFindingConfig(false)}>Close</button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={createFindingsMutation.isPending || selectedCves.size === 0 || selectedComponentIds.size === 0}
                onClick={() => createFindingsMutation.mutate()}
              >
                {createFindingsMutation.isPending ? 'Creating...' : `Create Findings (${selectedComponentIds.size * selectedCves.size})`}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}


function TableOrEmpty({ rows, columns, storageKey, empty }: { rows: DataTableRow[]; columns: DataTableColumn[]; storageKey: string; empty: string }) {
  if (rows.length === 0) {
    return <div className="empty-state"><p>{empty}</p></div>;
  }
  return (
    <div className="inventory-table-shell">
      <DataTable storageKey={storageKey} columns={columns} rows={rows} />
    </div>
  );
}

function isCriticalAsset(asset: SoftwareIdentityAsset): boolean {
  const searchable = `${asset.assetName} ${asset.assetIdentifier} ${asset.assetType}`.toLowerCase();
  return /\b(critical|prod|production|domain controller|dc-|database|payment|internet|external)\b/.test(searchable);
}
