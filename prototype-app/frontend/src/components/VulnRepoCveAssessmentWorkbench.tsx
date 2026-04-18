import React from 'react';
import { useNavigate } from 'react-router-dom';
import { CVEInvestigationSummary, type InvestigationSummaryInput } from './CVEInvestigationSummary';
import { ConfirmDialog } from './ConfirmDialog';
import { SegmentedControl } from './SegmentedControl';
import { pathForVulnRepoCveAssets, pathForVulnRepoCveSoftware } from '../app/routes';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { api } from '../api/client';
import { buildAssetRowsFromMatchedSoftware, type DerivedAssetRow } from '../features/cve-workbench/asset-report';
import {
  applicableSoftwareRows,
  buildFindingDisplayRows,
  buildSoftwareGroups,
  computedImpactStateOf,
  confidenceFromApplicability,
  deriveAssessmentResult,
  exactMatchMeta,
  explainApplicability,
  impactBadgeClass,
  impactLabel,
  initialApplicabilityDecision,
  latestByDate,
  matchBasisLabel,
  parseCvssVector,
  priorityFromSeverityAndImpact,
  type ApplicabilityDecision,
  type FindingDisplayRow,
  type ImpactDecision,
  type SoftwareGroup,
  vendorStatementFor,
} from '../features/cve-workbench/assessment-helpers';
import {
  formatDate,
  formatLabel,
  severityClassName,
  softwareLabel,
} from '../features/cve-workbench/formatting';
import {
  CveApplicabilityAssessment,
  CveDetail,
  CveInvestigation,
  CveMatchedSoftware,
  CveVexEvidence,
  OrgSpecificCveExposureRecord,
} from '../features/cve-workbench/types';
import {
  InvestigationPriority,
} from '../features/cve-workbench/workflow';
import type { Finding } from '../features/findings/types';
import type { SoftwareIdentityAsset } from '../features/software-identities/types';

type WorkflowStep = 1 | 2 | 3;
type InvestigationLogType = 'NOTE' | 'ACTION' | 'IOC';
type InvestigationLogEntry = {
  id: string;
  type: InvestigationLogType;
  message: string;
  actor: string;
  at: string;
};
type RunbookTask = {
  id: string;
  title: string;
  description: string;
  state: 'DONE' | 'READY';
};

type AssetInventoryCriterion = {
  id: string;
  software: string;
  version: string;
  vendor: string;
  matched: boolean;
};

type AssetInventoryResult = DerivedAssetRow;
type FalsePositiveStatusTone = 'yes' | 'no' | 'waiting' | 'na';
type FalsePositiveResult = {
  id: string;
  software: string;
  version: string;
  falsePositive: boolean;
  notImpactedAssetCount: number;
  vendorAdvisory: string;
  vendorGuidance: string;
  statusLabel: string;
  statusDetail: string;
  statusTone: FalsePositiveStatusTone;
};
type EolAnalysisCriterion = {
  id: string;
  software: string;
  version: string;
  vendor: string;
};
type EolAnalysisResult = {
  id: string;
  software: string;
  vendor: string;
  version: string;
  lifecycle: string;
  endOfSupport: string;
  endOfLife: string;
  recommendedUpgrade: string;
};

type ResolvedInventorySoftware = {
  id: string;
  software: string;
  vendor: string;
  version: string;
  assets: SoftwareIdentityAsset[];
  lifecycle: string;
  endOfSupport: string;
  endOfLife: string;
  recommendedUpgrade: string;
};

type Props = {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail | null;
  loading: boolean;
  error: string | null;
  analystId?: string;
  onBack: () => void;
  onRefreshDetail: () => Promise<void>;
};

const AV_LABELS: Record<string, string> = { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' };
const PR_LABELS: Record<string, string> = { N: 'None', L: 'Low', H: 'High' };
const UI_LABELS: Record<string, string> = { N: 'None', R: 'Required' };

function normalizeFalsePositiveToken(value?: string | null): string | null {
  if (!value) return null;
  const normalized = value.trim().toUpperCase().replace(/[\s-]+/g, '_');
  if (normalized === 'KNOWN_AFFECTED' || normalized === 'AFFECTED') return 'KNOWN_AFFECTED';
  if (normalized === 'FIXED') return 'FIXED';
  if (normalized === 'KNOWN_NOT_AFFECTED' || normalized === 'NOT_AFFECTED' || normalized === 'NOT_IMPACTED') return 'KNOWN_NOT_AFFECTED';
  if (normalized === 'UNDER_INVESTIGATION') return 'UNDER_INVESTIGATION';
  return null;
}

function vendorDisplayName(source?: string | null): string {
  const normalized = (source ?? '').trim().toLowerCase();
  if (!normalized) return 'Vendor';
  if (normalized.includes('microsoft')) return 'Microsoft';
  if (normalized.includes('redhat') || normalized.includes('red_hat') || normalized.includes('red-hat')) return 'Red Hat';
  return formatLabel(source ?? 'Vendor');
}

function extractCpeVendor(cpe?: string | null): string | null {
  if (!cpe) return null;
  const parts = cpe.split(':');
  return parts.length > 3 ? parts[3].toLowerCase() : null;
}

function cpeProductMatchesSoftware(cpe: string | undefined, software: string): boolean {
  if (!cpe) return false;
  const parts = cpe.split(':');
  const product = parts.length > 4 ? parts[4].toLowerCase() : '';
  const normalizedSoftware = software.toLowerCase();
  return Boolean(product) && (
    normalizedSoftware.includes(product)
    || product.includes(normalizedSoftware)
    || normalizedSoftware.replace(/[_\s-]+/g, '').includes(product.replace(/[_\s-]+/g, ''))
    || product.replace(/[_\s-]+/g, '').includes(normalizedSoftware.replace(/[_\s-]+/g, ''))
  );
}

function vendorCorrelationScore(
  entry: CveDetail['vendorIntelligence'][number],
  software: { packageName: string; ecosystem?: string; vendor?: string }
): number {
  const normalizedPackage = software.packageName.toLowerCase();
  const normalizedVendor = (software.vendor ?? '').toLowerCase();
  const normalizedEcosystem = (software.ecosystem ?? '').toLowerCase();
  const source = (entry.source ?? '').toLowerCase();
  const cpeVendor = extractCpeVendor(entry.cpe);
  let score = 0;

  if ((entry.packageName ?? '').toLowerCase() === normalizedPackage) score += 6;
  if (cpeProductMatchesSoftware(entry.cpe, software.packageName)) score += 4;
  if (normalizedEcosystem && (entry.ecosystem ?? '').toLowerCase() === normalizedEcosystem) score += 2;
  if (normalizedVendor) {
    if (source.includes(normalizedVendor)) score += 3;
    if (cpeVendor === normalizedVendor) score += 3;
  }
  if (!normalizedVendor && (source.includes('microsoft') || source.includes('redhat') || source.includes('red_hat') || source.includes('red-hat'))) {
    score += 1;
  }
  return score;
}

function falsePositiveStatusFromToken(statusToken: string | null): {
  falsePositive: boolean;
  statusLabel: string;
  statusDetail: string;
  statusTone: FalsePositiveStatusTone;
} {
  if (statusToken === 'KNOWN_AFFECTED') {
    return {
      falsePositive: false,
      statusLabel: 'No',
      statusDetail: 'Vendor advisory confirms the software is affected.',
      statusTone: 'no',
    };
  }
  if (statusToken === 'FIXED' || statusToken === 'KNOWN_NOT_AFFECTED') {
    return {
      falsePositive: true,
      statusLabel: 'Yes',
      statusDetail: 'Vendor advisory indicates the software is fixed or not affected.',
      statusTone: 'yes',
    };
  }
  if (statusToken === 'UNDER_INVESTIGATION') {
    return {
      falsePositive: false,
      statusLabel: 'Waiting vendor assessment',
      statusDetail: 'Vendor is still assessing impact for this software.',
      statusTone: 'waiting',
    };
  }
  return {
    falsePositive: false,
    statusLabel: 'n/a',
    statusDetail: 'No matching vendor advisory status was available for this software.',
    statusTone: 'na',
  };
}

function vendorAdvisoryLabel(source: string | undefined, statusToken: string | null): string {
  if (!source && !statusToken) return 'n/a';
  const vendor = vendorDisplayName(source);
  const status = statusToken ? formatLabel(statusToken.toLowerCase()) : 'n/a';
  return `${vendor}: ${status}`;
}

function vendorGuidanceMessage(
  source: string | undefined,
  statusToken: string | null,
  fixedVersion: string | undefined,
  fallback: string
): string {
  if (!statusToken) return fallback;
  const vendor = vendorDisplayName(source);
  if (statusToken === 'KNOWN_AFFECTED') {
    return `${vendor} advisory marks this software as known affected.`;
  }
  if (statusToken === 'FIXED') {
    return `${vendor} advisory marks this software as fixed${fixedVersion ? ` in ${fixedVersion}` : ''}.`;
  }
  if (statusToken === 'KNOWN_NOT_AFFECTED') {
    return `${vendor} advisory marks this software as known not affected.`;
  }
  if (statusToken === 'UNDER_INVESTIGATION') {
    return `${vendor} advisory says the software is under investigation.`;
  }
  return fallback;
}

function assessmentStatusLabel(item: OrgSpecificCveExposureRecord, latestAssessment: CveApplicabilityAssessment | null): string {
  if (item.impactState === 'FIXED' || item.impactState === 'NOT_IMPACTED') {
    return 'Resolved';
  }
  if (latestAssessment?.status === 'COMPLETED') {
    return formatLabel(latestAssessment.finalResult ?? latestAssessment.status);
  }
  if (latestAssessment?.status) {
    return formatLabel(latestAssessment.status);
  }
  return 'Assessment Pending';
}

function assessmentStatusTone(item: OrgSpecificCveExposureRecord, latestAssessment: CveApplicabilityAssessment | null): string {
  const label = assessmentStatusLabel(item, latestAssessment).toUpperCase();
  if (label.includes('RESOLVED') || label.includes('NOT AFFECTED')) return 'resolved';
  if (label.includes('UNDER INVESTIGATION')) return 'warning';
  return 'neutral';
}

type ProductSummary = {
  vendor: string;
  product: string;
  affectedVersions: string;
  cwe: string;
  totalAssetsImpacted: number;
};

function buildAffectedProducts(detail: CveDetail, softwareGroups: SoftwareGroup[]): ProductSummary[] {
  const products = new Map<string, ProductSummary>();

  for (const intel of detail.vendorIntelligence ?? []) {
    const product = intel.packageName?.trim();
    if (!product) continue;
    const vendor = intel.source?.trim() || 'Vendor Advisory';
    const group = softwareGroups.find((entry) => entry.software.packageName === product);
    const key = `${vendor}|${product}`;
    products.set(key, {
      vendor,
      product,
      affectedVersions: intel.affectedVersions || intel.fixedVersion || 'See advisory',
      cwe: detail.summary.cweIds || '-',
      totalAssetsImpacted: group?.assets.length ?? 0,
    });
  }

  if (products.size === 0) {
    for (const group of softwareGroups) {
      const key = `${group.software.ecosystem}|${group.software.packageName}`;
      products.set(key, {
        vendor: group.software.ecosystem || 'Inventory',
        product: group.software.packageName,
        affectedVersions: group.software.version || 'Detected in inventory',
        cwe: detail.summary.cweIds || '-',
        totalAssetsImpacted: group.assets.length,
      });
    }
  }

  return Array.from(products.values());
}

function buildReferenceLinks(detail: CveDetail): Array<{ label: string; href: string }> {
  const links = new Map<string, string>();
  if (detail.summary.sourceUrl) {
    links.set(`${detail.summary.source ?? 'Primary Advisory'}`, detail.summary.sourceUrl);
  }
  links.set('NVD Entry', `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(detail.summary.externalId)}`);
  return Array.from(links.entries()).map(([label, href]) => ({ label, href }));
}

function HeroMetric({
  value,
  label,
  sublabel,
  tone
}: {
  value: string;
  label: string;
  sublabel?: string;
  tone: 'critical' | 'accent';
}) {
  return (
    <div className={`cve-hero-metric ${tone}`}>
      <div className="cve-hero-metric-value">{value}</div>
      <div className="cve-hero-metric-label">{label}</div>
      {sublabel && <div className="cve-hero-metric-sublabel">{sublabel}</div>}
    </div>
  );
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function looksLikeIpAddress(value?: string): boolean {
  if (!value) return false;
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value.trim());
}

function normalizeAssetInventoryValue(value?: string | null): string {
  return (value ?? '').trim().toLowerCase();
}

function normalizedAssetInventorySearch(value?: string | null): string {
  return normalizeAssetInventoryValue(value).replace(/[^a-z0-9]+/g, '');
}

function findingIdentityKey(assetIdentifier?: string | null, packageName?: string | null, version?: string | null): string | null {
  const normalizedAssetIdentifier = normalizeAssetInventoryValue(assetIdentifier);
  const normalizedPackageName = normalizeAssetInventoryValue(packageName);
  if (!normalizedAssetIdentifier || !normalizedPackageName) {
    return null;
  }
  return [
    normalizedAssetIdentifier,
    normalizedPackageName,
    normalizeAssetInventoryValue(version ?? '-'),
  ].join('::');
}

function assetCriteriaStorageKey(cveId: string): string {
  return `vulnrepo:${cveId}:asset-criteria`;
}

function investigationRunbookStorageKey(cveId: string): string {
  return `vulnrepo:${cveId}:investigation-runbook`;
}

type PersistedInvestigationRunbookState = {
  leadAnalyst?: string;
  doneTaskIds?: string[];
  logEntries?: InvestigationLogEntry[];
  assetCriteria?: AssetInventoryCriterion[];
  resolvedInventory?: ResolvedInventorySoftware[];
  assetResults?: AssetInventoryResult[];
  assetAssessmentRan?: boolean;
  falsePositiveResults?: FalsePositiveResult[];
  falsePositiveRan?: boolean;
  eolCriteria?: EolAnalysisCriterion[];
  eolResults?: EolAnalysisResult[];
  eolAssessed?: boolean;
};

function loadPersistedInvestigationRunbookState(cveId: string): PersistedInvestigationRunbookState | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(investigationRunbookStorageKey(cveId));
    if (!raw) return null;
    return JSON.parse(raw) as PersistedInvestigationRunbookState;
  } catch {
    return null;
  }
}

function persistInvestigationRunbookState(
  cveId: string,
  payload: PersistedInvestigationRunbookState
): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(investigationRunbookStorageKey(cveId), JSON.stringify(payload));
}

function assetInventoryFieldMatches(actual?: string | null, expected?: string | null): boolean {
  const expectedRaw = normalizeAssetInventoryValue(expected);
  if (!expectedRaw) return true;

  const actualRaw = normalizeAssetInventoryValue(actual);
  const actualSearch = normalizedAssetInventorySearch(actual);
  const expectedSearch = normalizedAssetInventorySearch(expected);

  return actualRaw === expectedRaw
    || actualRaw.includes(expectedRaw)
    || actualSearch === expectedSearch
    || actualSearch.includes(expectedSearch);
}

function softwareSearchTerms(value?: string | null): string[] {
  const raw = (value ?? '').trim();
  if (!raw) return [];
  const variants = new Set<string>([
    raw,
    raw.toLowerCase(),
    raw.replace(/[_-]+/g, ' '),
    raw.replace(/\s+/g, '_'),
    raw.replace(/\s+/g, '-'),
  ]);
  return Array.from(variants).filter((entry) => entry.trim().length > 0);
}

function buildAssetInventoryCriteria(detail: CveDetail): AssetInventoryCriterion[] {
  const byKey = new Map<string, AssetInventoryCriterion>();

  detail.matchedSoftware.forEach((software, index) => {
    const criterion: AssetInventoryCriterion = {
      id: `criterion-${index}-${software.componentId}`,
      software: software.packageName,
      version: software.version ?? '',
      vendor: software.vexSource ?? detail.summary.source ?? software.ecosystem ?? 'NVD',
      matched: true,
    };
    const key = [
      normalizeAssetInventoryValue(criterion.software),
      normalizeAssetInventoryValue(criterion.version),
      normalizeAssetInventoryValue(criterion.vendor),
    ].join('|');
    if (!byKey.has(key)) {
      byKey.set(key, criterion);
    }
  });

  return Array.from(byKey.values());
}

function mergeAssetInventoryCriteria(
  seeded: AssetInventoryCriterion[],
  persisted: AssetInventoryCriterion[]
): AssetInventoryCriterion[] {
  const byKey = new Map<string, AssetInventoryCriterion>();
  [...seeded, ...persisted].forEach((criterion) => {
    const key = [
      normalizeAssetInventoryValue(criterion.software),
      normalizeAssetInventoryValue(criterion.version),
      normalizeAssetInventoryValue(criterion.vendor),
    ].join('|');
    if (!key.replace(/\|/g, '')) return;
    if (!byKey.has(key)) {
      byKey.set(key, criterion);
    }
  });
  return Array.from(byKey.values());
}

function loadPersistedAssetCriteria(cveId: string): AssetInventoryCriterion[] {
  const runbookState = loadPersistedInvestigationRunbookState(cveId);
  if (runbookState?.assetCriteria?.length) {
    return runbookState.assetCriteria;
  }
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(assetCriteriaStorageKey(cveId));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as Array<Partial<AssetInventoryCriterion>>;
    return parsed
      .filter((entry) => typeof entry.software === 'string' && entry.software.trim().length > 0)
      .map((entry, index) => ({
        id: typeof entry.id === 'string' ? entry.id : `criterion-persisted-${index}`,
        software: String(entry.software ?? ''),
        version: String(entry.version ?? ''),
        vendor: String(entry.vendor ?? ''),
        matched: Boolean(entry.matched),
      }));
  } catch {
    return [];
  }
}

function inferOsFromParts(...parts: Array<string | undefined | null>): string {
  const haystack = parts.filter(Boolean).join(' ').toLowerCase();
  if (haystack.includes('mac') || haystack.includes('osx') || haystack.includes('darwin')) return 'macOS';
  if (haystack.includes('windows') || haystack.includes('office_201') || haystack.includes('outlook')) return 'Windows';
  if (haystack.includes('ubuntu') || haystack.includes('debian') || haystack.includes('linux') || haystack.includes('rhel')) return 'Linux';
  return 'Unknown';
}

function inferExternalFacingFromParts(...parts: Array<string | undefined | null>): boolean {
  const haystack = parts.filter(Boolean).join(' ').toLowerCase();
  return ['public', 'internet', 'edge', 'gateway', 'vpn', 'dmz', 'web', 'api', 'proxy'].some((token) => haystack.includes(token));
}

function buildAssetRowsFromResolvedInventory(
  resolvedRows: ResolvedInventorySoftware[],
  severity: string
): AssetInventoryResult[] {
  const assets = new Map<string, AssetInventoryResult>();
  resolvedRows.forEach((row) => {
    row.assets.forEach((asset) => {
      const assetId = asset.assetIdentifier ?? asset.assetId ?? asset.componentId;
      const current = assets.get(assetId) ?? {
        id: assetId,
        entity: asset.assetName ?? asset.assetIdentifier ?? asset.componentId,
        identifier: asset.assetIdentifier ?? asset.componentId,
        type: asset.assetType ? formatLabel(asset.assetType) : 'Host',
        environment: inferExternalFacingFromParts(asset.assetName, asset.assetIdentifier, asset.packageName) ? 'External Facing' : '-',
        criticality: formatLabel(severity),
        ownerTeam: '-',
        state: 'ACTIVE',
        os: inferOsFromParts(asset.assetName, asset.assetIdentifier, asset.packageName, asset.version),
        externalFacing: inferExternalFacingFromParts(asset.assetName, asset.assetIdentifier, asset.packageName),
        matchedSoftware: [],
      };
      if (!current.matchedSoftware.some((entry) => entry.software === row.software && entry.version === row.version)) {
        current.matchedSoftware.push({ software: row.software, version: row.version });
      }
      assets.set(assetId, current);
    });
  });
  return Array.from(assets.values()).sort((left, right) => left.entity.localeCompare(right.entity));
}

function mergeAssetInventoryResults(...lists: AssetInventoryResult[][]): AssetInventoryResult[] {
  const merged = new Map<string, AssetInventoryResult>();
  lists.flat().forEach((row) => {
    const current = merged.get(row.id) ?? { ...row, matchedSoftware: [...row.matchedSoftware] };
    if (current !== row) {
      row.matchedSoftware.forEach((entry) => {
        if (!current.matchedSoftware.some((existing) => existing.software === entry.software && existing.version === entry.version)) {
          current.matchedSoftware.push(entry);
        }
      });
      current.externalFacing = current.externalFacing || row.externalFacing;
      if (current.environment === '-' && row.environment !== '-') current.environment = row.environment;
      if (current.os === 'Unknown' && row.os !== 'Unknown') current.os = row.os;
    }
    merged.set(row.id, current);
  });
  return Array.from(merged.values()).sort((left, right) => left.entity.localeCompare(right.entity));
}

async function resolveInventorySoftware(criteria: AssetInventoryCriterion[]): Promise<ResolvedInventorySoftware[]> {
  const effectiveCriteria = criteria.filter((criterion) => criterion.software.trim().length > 0);
  if (effectiveCriteria.length === 0) return [];

  const rows = new Map<string, ResolvedInventorySoftware>();

  await Promise.all(effectiveCriteria.map(async (criterion) => {
    const searchTerms = softwareSearchTerms(criterion.software);
    const searchResults = await Promise.all(
      searchTerms.map((term) => api.listSoftwareIdentities({ query: term, size: 25 }).catch(() => null))
    );
    const summaryById = new Map<string, Awaited<ReturnType<typeof api.listSoftwareIdentities>>['content'][number]>();
    searchResults.forEach((page) => {
      page?.content.forEach((summary) => summaryById.set(summary.id, summary));
    });

    const allSummaries = Array.from(summaryById.values());
    const matchingSummaries = allSummaries.filter((summary) => {
      const summaryText = [
        summary.displayName,
        summary.product,
        summary.vendor,
        summary.canonicalKey,
        summary.normalizedKey,
      ].filter(Boolean).join(' ');
      return assetInventoryFieldMatches(summaryText, criterion.software);
    });

    const candidateSummaries = (() => {
      if (!criterion.vendor.trim()) {
        return matchingSummaries;
      }
      const vendorFiltered = matchingSummaries.filter((summary) => (
        assetInventoryFieldMatches(summary.vendor, criterion.vendor)
        || assetInventoryFieldMatches(summary.displayName, criterion.vendor)
        || assetInventoryFieldMatches(summary.product, criterion.vendor)
      ));
      return vendorFiltered.length > 0 ? vendorFiltered : matchingSummaries;
    })();

    const details = await Promise.all(candidateSummaries.map(async (summary) => {
      try {
        return await api.getSoftwareIdentityDetail(summary.id);
      } catch {
        return null;
      }
    }));

    details.forEach((detailRow) => {
      if (!detailRow) return;
      const productMatchesCriterion = assetInventoryFieldMatches(detailRow.product, criterion.software)
        || assetInventoryFieldMatches(detailRow.displayName, criterion.software)
        || assetInventoryFieldMatches(detailRow.canonicalKey, criterion.software)
        || assetInventoryFieldMatches(detailRow.normalizedKey, criterion.software);

      const versionMatchedAssets = detailRow.assets.filter((asset) => (
        assetInventoryFieldMatches(asset.version, criterion.version)
      ));

      detailRow.assets.forEach((asset) => {
        const packageMatches = assetInventoryFieldMatches(asset.packageName, criterion.software)
          || assetInventoryFieldMatches(detailRow.displayName, criterion.software)
          || assetInventoryFieldMatches(detailRow.product, criterion.software);
        const versionMatches = assetInventoryFieldMatches(asset.version, criterion.version);
        const vendorMatches = !criterion.vendor.trim()
          || assetInventoryFieldMatches(detailRow.vendor, criterion.vendor)
          || assetInventoryFieldMatches(asset.ecosystem, criterion.vendor)
          || assetInventoryFieldMatches(asset.sourceSystem, criterion.vendor)
          || assetInventoryFieldMatches(asset.packageName, criterion.vendor);
        const fallbackMatch = productMatchesCriterion
          && versionMatchedAssets.some((candidate) => candidate.componentId === asset.componentId);
        if ((!packageMatches && !fallbackMatch) || !versionMatches || !vendorMatches) return;

        const software = asset.packageName || detailRow.product || detailRow.displayName;
        const version = asset.version || criterion.version || '-';
        const key = `${normalizeAssetInventoryValue(software)}::${normalizeAssetInventoryValue(version)}`;
        const lifecycle = asset.isEol
          ? 'End of Life'
          : asset.eolDaysRemaining != null && asset.eolDaysRemaining <= 90
            ? 'Near End of Life'
            : 'Supported';
        const current = rows.get(key) ?? {
          id: key,
          software,
          vendor: detailRow.vendor || asset.ecosystem || criterion.vendor || 'Inventory',
          version,
          assets: [],
          lifecycle,
          endOfSupport: '—',
          endOfLife: asset.eolDate || '—',
          recommendedUpgrade: 'Upgrade to the latest supported release',
        };
        if (!current.assets.some((existing) => existing.componentId === asset.componentId)) {
          current.assets.push(asset);
        }
        if (current.endOfLife === '—' && asset.eolDate) current.endOfLife = asset.eolDate;
        if (current.lifecycle !== 'End of Life' && lifecycle === 'End of Life') current.lifecycle = lifecycle;
        rows.set(key, current);
      });

      if (productMatchesCriterion && versionMatchedAssets.length > 0) {
        versionMatchedAssets.forEach((asset) => {
          const software = asset.packageName || detailRow.product || detailRow.displayName;
          const version = asset.version || criterion.version || '-';
          const key = `${normalizeAssetInventoryValue(software)}::${normalizeAssetInventoryValue(version)}`;
          const lifecycle = asset.isEol
            ? 'End of Life'
            : asset.eolDaysRemaining != null && asset.eolDaysRemaining <= 90
              ? 'Near End of Life'
              : 'Supported';
          const current = rows.get(key) ?? {
            id: key,
            software,
            vendor: detailRow.vendor || asset.ecosystem || criterion.vendor || 'Inventory',
            version,
            assets: [],
            lifecycle,
            endOfSupport: '—',
            endOfLife: asset.eolDate || '—',
            recommendedUpgrade: 'Upgrade to the latest supported release',
          };
          if (!current.assets.some((existing) => existing.componentId === asset.componentId)) {
            current.assets.push(asset);
          }
          rows.set(key, current);
        });
      }
    });
  }));

  return Array.from(rows.values()).sort((left, right) => left.software.localeCompare(right.software) || left.version.localeCompare(right.version));
}

function persistAssetCriteria(cveId: string, criteria: AssetInventoryCriterion[]): void {
  if (typeof window === 'undefined') return;
  const payload = criteria.map(({ id, software, version, vendor, matched }) => ({
    id,
    software,
    version,
    vendor,
    matched,
  }));
  window.localStorage.setItem(assetCriteriaStorageKey(cveId), JSON.stringify(payload));
}

function buildAssetInventoryResults(
  detail: CveDetail,
  criteria: AssetInventoryCriterion[],
  severity: string
): AssetInventoryResult[] {
  const effectiveCriteria = criteria.filter((criterion) => criterion.software.trim().length > 0);
  if (effectiveCriteria.length === 0) {
    return [];
  }

  const matchedRows = detail.matchedSoftware.filter((software) => (
    effectiveCriteria.some((criterion) => {
      const packageMatches = assetInventoryFieldMatches(software.packageName, criterion.software);
      const versionMatches = assetInventoryFieldMatches(software.version, criterion.version);
      const vendorHint = normalizeAssetInventoryValue(criterion.vendor);
      const vendorMatches = !vendorHint
        || normalizeAssetInventoryValue(software.vexSource).includes(vendorHint)
        || normalizeAssetInventoryValue(software.ecosystem).includes(vendorHint)
        || normalizeAssetInventoryValue(detail.summary.source).includes(vendorHint)
        || normalizedAssetInventorySearch(software.packageName).includes(normalizedAssetInventorySearch(criterion.vendor));
      return packageMatches && versionMatches && vendorMatches;
    })
  ));

  return buildAssetRowsFromMatchedSoftware(matchedRows, severity);
}

function buildFalsePositiveResults(detail: CveDetail, resolvedInventory: ResolvedInventorySoftware[] = []): FalsePositiveResult[] {
  const intel = detail.vendorIntelligence ?? [];
  const matched = detail.matchedSoftware ?? [];
  const rows = new Map<string, FalsePositiveResult>();

  matched.forEach((software) => {
    const version = software.version ?? '-';
    const key = `${software.packageName}::${version}`;
    if (rows.has(key)) return;
    const relatedAssets = matched.filter((entry) => (
      entry.packageName.toLowerCase() === software.packageName.toLowerCase()
      && (entry.version ?? '-') === version
    ));
    const assetKeys = new Set(
      relatedAssets.map((entry) => entry.assetId ?? entry.assetIdentifier ?? entry.assetName ?? entry.componentId)
    );

    const vendorDecision = intel
      .filter((entry) => vendorCorrelationScore(entry, {
        packageName: software.packageName,
        ecosystem: software.ecosystem,
      }) > 0)
      .sort((left, right) => (
        vendorCorrelationScore(right, {
          packageName: software.packageName,
          ecosystem: software.ecosystem,
        }) - vendorCorrelationScore(left, {
          packageName: software.packageName,
          ecosystem: software.ecosystem,
        })
      ))[0];
    const statusToken = normalizeFalsePositiveToken(vendorDecision?.vexStatus ?? software.vexStatus);
    const status = falsePositiveStatusFromToken(statusToken);

    rows.set(key, {
      id: key,
      software: software.packageName,
      version,
      falsePositive: status.falsePositive,
      notImpactedAssetCount: status.falsePositive ? assetKeys.size : 0,
      vendorAdvisory: vendorAdvisoryLabel(vendorDecision?.source ?? software.vexSource ?? software.vexProvider, statusToken),
      vendorGuidance: vendorGuidanceMessage(
        vendorDecision?.source ?? software.vexSource ?? software.vexProvider,
        statusToken,
        vendorDecision?.fixedVersion,
        'Installed software and version matched a vulnerability target in inventory correlation.'
      ),
      statusLabel: status.statusLabel,
      statusDetail: status.statusDetail,
      statusTone: status.statusTone,
    });
  });

  resolvedInventory.forEach((software) => {
    const key = `${software.software}::${software.version}`;
    if (rows.has(key)) return;
    const vendorDecision = intel
      .filter((entry) => vendorCorrelationScore(entry, {
        packageName: software.software,
        ecosystem: '',
        vendor: software.vendor,
      }) > 0)
      .sort((left, right) => (
        vendorCorrelationScore(right, {
          packageName: software.software,
          ecosystem: '',
          vendor: software.vendor,
        }) - vendorCorrelationScore(left, {
          packageName: software.software,
          ecosystem: '',
          vendor: software.vendor,
        })
      ))[0];
    const statusToken = normalizeFalsePositiveToken(vendorDecision?.vexStatus);
    const status = falsePositiveStatusFromToken(statusToken);
    rows.set(key, {
      id: key,
      software: software.software,
      version: software.version,
      falsePositive: status.falsePositive,
      notImpactedAssetCount: status.falsePositive ? software.assets.length : 0,
      vendorAdvisory: vendorAdvisoryLabel(vendorDecision?.source ?? software.vendor, statusToken),
      vendorGuidance: vendorGuidanceMessage(
        vendorDecision?.source ?? software.vendor,
        statusToken,
        vendorDecision?.fixedVersion,
        'Installed software and version matched a software inventory target and still requires analyst review.'
      ),
      statusLabel: status.statusLabel,
      statusDetail: status.statusDetail,
      statusTone: status.statusTone,
    });
  });

  return Array.from(rows.values()).sort((left, right) => {
    if (left.statusLabel !== right.statusLabel) {
      const priority = { 'No': 0, 'Waiting vendor assessment': 1, 'n/a': 2, 'Yes': 3 };
      return (priority[left.statusLabel as keyof typeof priority] ?? 99) - (priority[right.statusLabel as keyof typeof priority] ?? 99);
    }
    return left.software.localeCompare(right.software) || left.version.localeCompare(right.version);
  });
}

function buildEolCriteria(detail: CveDetail, assetCriteria: AssetInventoryCriterion[]): EolAnalysisCriterion[] {
  const seeded = assetCriteria
    .filter((criterion) => criterion.software.trim().length > 0)
    .map((criterion) => ({
      id: `eol-${criterion.id}`,
      software: criterion.software,
      version: criterion.version,
      vendor: criterion.vendor,
    }));
  if (seeded.length > 0) return seeded;

  return detail.matchedSoftware.map((software) => ({
    id: `eol-${software.componentId}`,
    software: software.packageName,
    version: software.version ?? '',
    vendor: software.vexSource ?? software.ecosystem ?? detail.summary.source ?? '',
  }));
}

function buildEolAnalysisResults(
  detail: CveDetail,
  criteria: EolAnalysisCriterion[],
  resolvedInventory: ResolvedInventorySoftware[] = []
): EolAnalysisResult[] {
  const effectiveCriteria = criteria.filter((criterion) => criterion.software.trim().length > 0);
  const rows = new Map<string, EolAnalysisResult>();

  detail.matchedSoftware.forEach((software) => {
    const matchesCriterion = effectiveCriteria.some((criterion) => {
      const packageMatches = assetInventoryFieldMatches(software.packageName, criterion.software);
      const versionMatches = assetInventoryFieldMatches(software.version, criterion.version);
      return packageMatches && versionMatches;
    });
    if (!matchesCriterion) return;

    const version = software.version ?? '-';
    const key = `${software.packageName}::${version}`;
    if (rows.has(key)) return;

    const vendorIntel = detail.vendorIntelligence.find((entry) => entry.packageName?.toLowerCase() === software.packageName.toLowerCase());
    const lifecycle = software.isEol
      ? 'End of Life'
      : software.supportPhase
        ? formatLabel(software.supportPhase)
        : software.eolDaysRemaining != null && software.eolDaysRemaining <= 90
          ? 'Near End of Life'
          : 'Supported';

    rows.set(key, {
      id: key,
      software: software.packageName,
      vendor: software.vexSource ?? vendorIntel?.source ?? software.ecosystem ?? 'Inventory',
      version,
      lifecycle,
      endOfSupport: software.eolSupportEndDate ?? '—',
      endOfLife: software.eolDate ?? '—',
      recommendedUpgrade: vendorIntel?.fixedVersion ?? software.eolCycle ?? 'Upgrade to the latest supported release',
    });
  });

  resolvedInventory.forEach((software) => {
    const matchesCriterion = effectiveCriteria.some((criterion) => {
      const packageMatches = assetInventoryFieldMatches(software.software, criterion.software);
      const versionMatches = assetInventoryFieldMatches(software.version, criterion.version);
      return packageMatches && versionMatches;
    });
    if (!matchesCriterion) return;

    const key = `${software.software}::${software.version}`;
    if (rows.has(key)) return;
    rows.set(key, {
      id: key,
      software: software.software,
      vendor: software.vendor,
      version: software.version,
      lifecycle: software.lifecycle,
      endOfSupport: software.endOfSupport,
      endOfLife: software.endOfLife,
      recommendedUpgrade: software.recommendedUpgrade,
    });
  });

  return Array.from(rows.values()).sort((left, right) => left.software.localeCompare(right.software) || left.version.localeCompare(right.version));
}

function InvestigationCanvas({
  isOpen,
  item,
  detail,
  leadAnalyst,
  runbookTasks,
  onRunTask,
  onOpenAssetList,
  logEntries,
  newLogType,
  onNewLogTypeChange,
  newLogMessage,
  onNewLogMessageChange,
  onAddLogEntry,
  onClose
}: {
  isOpen: boolean;
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail;
  leadAnalyst: string;
  runbookTasks: RunbookTask[];
  onRunTask: (taskId: string) => void;
  onOpenAssetList: (filter?: { scope?: 'external-facing' | 'critical'; os?: string; software?: string }) => void;
  logEntries: InvestigationLogEntry[];
  newLogType: InvestigationLogType;
  onNewLogTypeChange: (value: InvestigationLogType) => void;
  newLogMessage: string;
  onNewLogMessageChange: (value: string) => void;
  onAddLogEntry: () => void;
  onClose: () => void;
}) {
  const completedCount = runbookTasks.filter((task) => task.state === 'DONE').length;
  const isEolTask = (taskId: string) => taskId === 'end-of-life-analysis' || taskId === 'end-of-life';
  const persistedRunbookState = React.useMemo(
    () => loadPersistedInvestigationRunbookState(detail.summary.externalId),
    [detail.summary.externalId]
  );
  const initialCriteria = React.useMemo(
    () => mergeAssetInventoryCriteria(
      buildAssetInventoryCriteria(detail),
      persistedRunbookState?.assetCriteria ?? loadPersistedAssetCriteria(detail.summary.externalId)
    ),
    [detail, persistedRunbookState]
  );
  const initialResults = React.useMemo(
    () => persistedRunbookState?.assetResults ?? buildAssetInventoryResults(detail, initialCriteria, item.severity),
    [detail, initialCriteria, item.severity, persistedRunbookState]
  );
  const reviewTask = runbookTasks.find((task) => task.id === 'review-asset-inventory') ?? null;
  const falsePositiveTask = runbookTasks.find((task) => task.id === 'find-false-positive') ?? null;
  const eolTask = runbookTasks.find((task) => isEolTask(task.id)) ?? null;
  const initialResolvedInventory = React.useMemo(
    () => persistedRunbookState?.resolvedInventory ?? [],
    [persistedRunbookState]
  );
  const initialFalsePositiveResults = React.useMemo(
    () => persistedRunbookState?.falsePositiveResults ?? buildFalsePositiveResults(detail, initialResolvedInventory),
    [detail, initialResolvedInventory, persistedRunbookState]
  );
  const [assetCriteria, setAssetCriteria] = React.useState<AssetInventoryCriterion[]>(initialCriteria);
  const [assetResults, setAssetResults] = React.useState<AssetInventoryResult[]>(initialResults);
  const [assetResultsExpanded, setAssetResultsExpanded] = React.useState(initialResults.length > 0);
  const [assetAssessmentRan, setAssetAssessmentRan] = React.useState(
    persistedRunbookState?.assetAssessmentRan ?? initialResults.length > 0
  );
  const initialEolCriteria = React.useMemo(
    () => persistedRunbookState?.eolCriteria ?? buildEolCriteria(detail, initialCriteria),
    [detail, initialCriteria, persistedRunbookState]
  );
  const initialEolResults = React.useMemo(
    () => persistedRunbookState?.eolResults
      ?? (eolTask?.state === 'DONE' ? buildEolAnalysisResults(detail, initialEolCriteria, initialResolvedInventory) : []),
    [detail, initialEolCriteria, eolTask?.state, initialResolvedInventory, persistedRunbookState]
  );
  const [eolCriteria, setEolCriteria] = React.useState<EolAnalysisCriterion[]>(initialEolCriteria);
  const [eolResults, setEolResults] = React.useState<EolAnalysisResult[]>(initialEolResults);
  const [eolExpanded, setEolExpanded] = React.useState(
    (persistedRunbookState?.eolAssessed ?? false) || eolTask?.state === 'DONE'
  );
  const [eolAssessed, setEolAssessed] = React.useState(
    persistedRunbookState?.eolAssessed ?? eolTask?.state === 'DONE'
  );
  const [falsePositiveResults, setFalsePositiveResults] = React.useState<FalsePositiveResult[]>(initialFalsePositiveResults);
  const [falsePositiveResultsExpanded, setFalsePositiveResultsExpanded] = React.useState(
    (persistedRunbookState?.falsePositiveRan ?? false) || falsePositiveTask?.state === 'DONE'
  );
  const [falsePositiveRan, setFalsePositiveRan] = React.useState(
    persistedRunbookState?.falsePositiveRan ?? falsePositiveTask?.state === 'DONE'
  );
  const [resolvedInventory, setResolvedInventory] = React.useState<ResolvedInventorySoftware[]>(initialResolvedInventory);
  const [summaryVisible, setSummaryVisible] = React.useState(false);

  const flushRunbookState = React.useCallback(() => {
    persistInvestigationRunbookState(detail.summary.externalId, {
      leadAnalyst,
      doneTaskIds: runbookTasks.filter((task) => task.state === 'DONE').map((task) => task.id),
      logEntries,
      assetCriteria,
      resolvedInventory,
      assetResults,
      assetAssessmentRan,
      falsePositiveResults,
      falsePositiveRan,
      eolCriteria,
      eolResults,
      eolAssessed,
    });
  }, [
    assetAssessmentRan,
    assetCriteria,
    assetResults,
    detail.summary.externalId,
    eolAssessed,
    eolCriteria,
    eolResults,
    falsePositiveRan,
    falsePositiveResults,
    leadAnalyst,
    logEntries,
    resolvedInventory,
    runbookTasks,
  ]);

  React.useEffect(() => {
    // Reset local investigation state only when the user navigates to a different CVE.
    setAssetCriteria(initialCriteria);
    setAssetResults(initialResults);
    setAssetResultsExpanded(initialResults.length > 0);
    setAssetAssessmentRan(persistedRunbookState?.assetAssessmentRan ?? initialResults.length > 0);
    setEolCriteria(initialEolCriteria);
    setEolResults(initialEolResults);
    setEolExpanded((persistedRunbookState?.eolAssessed ?? false) || eolTask?.state === 'DONE');
    setEolAssessed(persistedRunbookState?.eolAssessed ?? eolTask?.state === 'DONE');
    setFalsePositiveResults(initialFalsePositiveResults);
    setFalsePositiveResultsExpanded((persistedRunbookState?.falsePositiveRan ?? false) || falsePositiveTask?.state === 'DONE');
    setFalsePositiveRan(persistedRunbookState?.falsePositiveRan ?? falsePositiveTask?.state === 'DONE');
    setResolvedInventory(initialResolvedInventory);
    setSummaryVisible(false);
  }, [detail.summary.externalId, persistedRunbookState, initialCriteria, initialResults, initialEolCriteria, initialEolResults, initialFalsePositiveResults, initialResolvedInventory, eolTask?.state, falsePositiveTask?.state]);

  React.useEffect(() => {
    if (eolTask?.state === 'DONE' && !eolAssessed) {
      setEolCriteria(initialEolCriteria);
      setEolResults(initialEolResults);
      setEolExpanded(true);
      setEolAssessed(true);
    }
  }, [eolTask?.state, eolAssessed, initialEolCriteria, initialEolResults]);

  React.useEffect(() => {
    if (falsePositiveTask?.state === 'DONE' && !falsePositiveRan) {
      setFalsePositiveResults(initialFalsePositiveResults);
      setFalsePositiveResultsExpanded(true);
      setFalsePositiveRan(true);
    }
  }, [falsePositiveTask?.state, falsePositiveRan, initialFalsePositiveResults]);

  React.useEffect(() => {
    persistAssetCriteria(detail.summary.externalId, assetCriteria);
  }, [assetCriteria, detail.summary.externalId]);
  React.useEffect(() => {
    flushRunbookState();
  }, [flushRunbookState]);
  React.useEffect(() => {
    if (!isOpen) return;
    const saved = loadPersistedInvestigationRunbookState(detail.summary.externalId);
    if (!saved) return;
    if (saved.assetCriteria?.length) setAssetCriteria(saved.assetCriteria);
    if (saved.resolvedInventory) setResolvedInventory(saved.resolvedInventory);
    if (saved.assetResults) setAssetResults(saved.assetResults);
    if (typeof saved.assetAssessmentRan === 'boolean') {
      setAssetAssessmentRan(saved.assetAssessmentRan);
      setAssetResultsExpanded(saved.assetAssessmentRan);
    }
    if (saved.falsePositiveResults) setFalsePositiveResults(saved.falsePositiveResults);
    if (typeof saved.falsePositiveRan === 'boolean') {
      setFalsePositiveRan(saved.falsePositiveRan);
      setFalsePositiveResultsExpanded(saved.falsePositiveRan);
    }
    if (saved.eolCriteria) setEolCriteria(saved.eolCriteria);
    if (saved.eolResults) setEolResults(saved.eolResults);
    if (typeof saved.eolAssessed === 'boolean') {
      setEolAssessed(saved.eolAssessed);
      setEolExpanded(saved.eolAssessed);
    }
  }, [isOpen, detail.summary.externalId]);
  const osBreakdown = React.useMemo(() => {
    const counts = new Map<string, number>();
    assetResults.forEach((asset) => counts.set(asset.os, (counts.get(asset.os) ?? 0) + 1));
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((left, right) => right.count - left.count);
  }, [assetResults]);
  const softwareBreakdown = React.useMemo(() => {
    const counts = new Map<string, number>();
    assetResults.forEach((asset) => {
      asset.matchedSoftware.forEach((entry) => {
        counts.set(entry.software, (counts.get(entry.software) ?? 0) + 1);
      });
    });
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
      .slice(0, 6);
  }, [assetResults]);
  const externalFacingCount = assetResults.filter((asset) => asset.externalFacing).length;
  const criticalAssetCount = assetResults.filter((asset) => asset.criticality.toLowerCase() === 'critical').length;
  const totalAssetCount = assetResults.length;
  const summaryInput = React.useMemo<InvestigationSummaryInput>(() => ({
    summary: {
      cveId: item.externalId,
      title: detail.summary.title,
      description: detail.summary.description,
      severity: item.severity,
      cvssScore: detail.summary.cvssScore ?? undefined,
      epssScore: detail.summary.epssScore ?? undefined,
      inKev: item.inKev,
      exploitAvailable: detail.signals.exploitAvailable,
      patchAvailable: detail.signals.patchAvailable,
      patchVersions: detail.signals.patchVersions ?? undefined,
    },
    investigation: {
      leadAnalyst,
    },
    runbookResults: runbookTasks.map((task) => ({ id: task.id, title: task.title, state: task.state })),
    affectedAssets: assetResults.map((asset) => ({
      id: asset.id,
      hostname: asset.entity,
      ipAddress: looksLikeIpAddress(asset.identifier) ? asset.identifier : undefined,
      os: asset.os,
      owner: asset.ownerTeam,
      environment: asset.environment,
      externalFacing: asset.externalFacing,
      critical: asset.criticality.toLowerCase() === 'critical',
      matchedSoftware: asset.matchedSoftware.map((sw) => ({ software: sw.software, version: sw.version })),
    })),
    falsePositiveRows: falsePositiveResults.map((row) => ({
      software: row.software,
      version: row.version,
      falsePositive: row.falsePositive,
      assetsNotImpacted: row.notImpactedAssetCount,
      vendorAdvisory: row.vendorAdvisory,
      vendorGuidance: row.vendorGuidance,
    })),
    eolRows: eolResults.map((row) => ({
      software: row.software,
      vendor: row.vendor,
      version: row.version,
      lifecycle: row.lifecycle,
      endOfSupport: row.endOfSupport,
      endOfLife: row.endOfLife,
      recommendedUpgrade: row.recommendedUpgrade,
    })),
  }), [assetResults, detail, eolResults, falsePositiveResults, item.externalId, item.inKev, item.severity, leadAnalyst, runbookTasks]);
  const osWheelStops = React.useMemo(() => {
    if (osBreakdown.length === 0) return 'conic-gradient(#273248 0deg 360deg)';
    const palette = ['#53d7ff', '#8a7dff', '#ffb24a', '#22d37f', '#ff6f91', '#9dd6ff'];
    let start = 0;
    const total = osBreakdown.reduce((sum, entry) => sum + entry.count, 0) || 1;
    const segments = osBreakdown.map((entry, index) => {
      const end = start + (entry.count / total) * 360;
      const color = palette[index % palette.length];
      const segment = `${color} ${start}deg ${end}deg`;
      start = end;
      return segment;
    });
    return `conic-gradient(${segments.join(', ')})`;
  }, [osBreakdown]);

  function updateAssetCriterion(id: string, field: keyof Omit<AssetInventoryCriterion, 'id' | 'matched'>, value: string): void {
    setAssetCriteria((current) => current.map((criterion) => (
      criterion.id === id ? { ...criterion, [field]: value } : criterion
    )));
  }

  function addAssetCriterion(): void {
    setAssetCriteria((current) => [
      ...current,
      {
        id: `criterion-manual-${Date.now()}`,
        software: '',
        version: '',
        vendor: '',
        matched: false,
      }
    ]);
  }

  function removeAssetCriterion(id: string): void {
    setAssetCriteria((current) => current.filter((criterion) => criterion.id !== id));
  }

  async function runAssetInventoryAssessment(): Promise<void> {
    const resolved = await resolveInventorySoftware(assetCriteria);
    const results = mergeAssetInventoryResults(
      buildAssetInventoryResults(detail, assetCriteria, item.severity),
      buildAssetRowsFromResolvedInventory(resolved, item.severity)
    );
    persistAssetCriteria(detail.summary.externalId, assetCriteria);
    setResolvedInventory(resolved);
    setAssetResults(results);
    setAssetResultsExpanded(true);
    setAssetAssessmentRan(true);
    onRunTask('review-asset-inventory');
  }

  async function runFalsePositiveAssessment(): Promise<void> {
    const resolved = await resolveInventorySoftware(assetCriteria);
    setResolvedInventory(resolved);
    setFalsePositiveResults(buildFalsePositiveResults(detail, resolved));
    setFalsePositiveResultsExpanded(true);
    setFalsePositiveRan(true);
    onRunTask('find-false-positive');
  }

  function runEolAnalysis(): void {
    setEolCriteria(buildEolCriteria(detail, assetCriteria));
    setEolExpanded(true);
  }

  async function assessEolAnalysis(): Promise<void> {
    const resolved = await resolveInventorySoftware(assetCriteria);
    setResolvedInventory(resolved);
    setEolResults(buildEolAnalysisResults(detail, eolCriteria, resolved));
    setEolExpanded(true);
    setEolAssessed(true);
    onRunTask('end-of-life-analysis');
  }

  function showEolResults(): void {
    if (eolResults.length === 0) {
      setEolResults(buildEolAnalysisResults(detail, eolCriteria, resolvedInventory));
    }
    setEolExpanded(true);
    setEolAssessed(true);
  }

  function handleRunbookAction(taskId: string): void {
    if (taskId === 'review-asset-inventory') {
      setAssetResultsExpanded(true);
      return;
    }
    if (isEolTask(taskId)) {
      runEolAnalysis();
      return;
    }
    if (taskId === 'find-false-positive') {
      runFalsePositiveAssessment();
      return;
    }
    onRunTask(taskId);
  }

  const triggerSummary = React.useCallback(() => {
    setSummaryVisible(true);
    onRunTask('generate-summary');
  }, [onRunTask]);

  const closeCanvas = React.useCallback(() => {
    flushRunbookState();
    onClose();
  }, [flushRunbookState, onClose]);

  function renderRunbookActions(task: RunbookTask): React.ReactNode {
    if (task.id === 'review-asset-inventory' && assetAssessmentRan) {
      return (
        <>
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={() => setAssetResultsExpanded((current) => !current)}
          >
            {assetResultsExpanded ? 'Hide Results' : 'View Results'}
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={() => {
              setAssetResultsExpanded(true);
              onOpenAssetList();
            }}
          >
            View All
          </button>
        </>
      );
    }
    if (isEolTask(task.id) && (eolAssessed || task.state === 'DONE')) {
      return (
        <>
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={() => {
              if (!eolExpanded) {
                showEolResults();
                return;
              }
              setEolExpanded(false);
            }}
          >
            {eolExpanded ? 'Hide Results' : 'View Results'}
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={runEolAnalysis}
          >
            Run Again
          </button>
        </>
      );
    }
    if (task.id === 'find-false-positive' && falsePositiveRan) {
      return (
        <>
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={() => setFalsePositiveResultsExpanded((current) => !current)}
          >
            {falsePositiveResultsExpanded ? 'Hide Results' : 'View Results'}
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={runFalsePositiveAssessment}
          >
            Run Again
          </button>
        </>
      );
    }
    if (task.state === 'DONE') {
      return <button type="button" className="btn btn-secondary btn-inline" disabled>Done</button>;
    }
    return (
      <button type="button" className="btn btn-secondary btn-inline" onClick={() => handleRunbookAction(task.id)}>
        Run
      </button>
    );
  }

  const assessmentPanel = (
    <div className="investigation-assessment-panel">
      <div className="investigation-assessment-header">
        <div>
          <h5>Assessment Criteria</h5>
          <div className="panel-caption">
            Start with the software already matched to this CVE, then add extra vendor or version criteria if needed.
          </div>
        </div>
        <button type="button" className="btn btn-secondary btn-inline" onClick={addAssetCriterion}>Add Software</button>
      </div>
      <div className="investigation-assessment-criteria-list">
        {assetCriteria.map((criterion) => (
          <div key={criterion.id} className="investigation-assessment-criteria-row">
            <span className={`investigation-criteria-badge${criterion.matched ? ' matched' : ''}`}>
              {criterion.matched ? 'Matched' : 'Added'}
            </span>
            <input
              type="text"
              value={criterion.software}
              onChange={(event) => updateAssetCriterion(criterion.id, 'software', event.target.value)}
              placeholder="Software"
            />
            <input
              type="text"
              value={criterion.version}
              onChange={(event) => updateAssetCriterion(criterion.id, 'version', event.target.value)}
              placeholder="Version"
            />
            <input
              type="text"
              value={criterion.vendor}
              onChange={(event) => updateAssetCriterion(criterion.id, 'vendor', event.target.value)}
              placeholder="Vendor"
            />
            <button type="button" className="btn btn-secondary btn-inline" onClick={() => removeAssetCriterion(criterion.id)}>
              Remove
            </button>
          </div>
        ))}
      </div>
      <div className="investigation-assessment-actions">
        <button type="button" className="btn btn-primary" onClick={runAssetInventoryAssessment}>
          Run Assessment
        </button>
        {assetAssessmentRan && (
          <div className="investigation-assessment-total">
            <strong>{assetResults.length}</strong>
            <span>Total assets matched</span>
          </div>
        )}
      </div>

      {assetAssessmentRan && (
        <div className="investigation-asset-preview">
          <div className="investigation-asset-summary-grid">
            <button type="button" className="investigation-summary-card" onClick={() => onOpenAssetList({ scope: 'external-facing' })}>
              <span>External Facing Assets</span>
              <strong>{externalFacingCount}</strong>
            </button>
            <button type="button" className="investigation-summary-card" onClick={() => onOpenAssetList()}>
              <span>Total Assets</span>
              <strong>{totalAssetCount}</strong>
            </button>
            <div className="investigation-summary-card investigation-summary-card-wheel">
              <span>Assets by OS</span>
              <div className="investigation-os-wheel">
                <div className="investigation-os-wheel-chart" style={{ backgroundImage: osWheelStops }} />
                <div className="investigation-os-wheel-legend">
                  {osBreakdown.map((entry) => (
                    <button key={entry.label} type="button" className="btn-link investigation-summary-link" onClick={() => onOpenAssetList({ os: entry.label })}>
                      {entry.label} {entry.count}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <button type="button" className="investigation-summary-card" onClick={() => onOpenAssetList({ scope: 'critical' })}>
              <span>Critical Assets</span>
              <strong>{criticalAssetCount}</strong>
            </button>
          </div>
          <div className="investigation-software-bar-panel">
            <div className="investigation-software-bar-header">
              <h5>Assets Matched by Software</h5>
            </div>
            <div className="investigation-software-bars">
              {softwareBreakdown.map((entry) => {
                const pct = totalAssetCount > 0 ? Math.max(12, Math.round((entry.count / totalAssetCount) * 100)) : 0;
                return (
                  <div key={entry.label} className="investigation-software-bar-row">
                    <span>{entry.label}</span>
                    <button type="button" className="btn-link investigation-summary-link" onClick={() => onOpenAssetList({ software: entry.label })}>
                      {entry.count}
                    </button>
                    <div className="investigation-software-bar-track">
                      <div className="investigation-software-bar-fill" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const falsePositiveDetails = falsePositiveRan && falsePositiveResultsExpanded ? (
    falsePositiveResults.length === 0 ? (
      <div className="panel-caption">No matched software is available for false-positive validation.</div>
    ) : (
      <div className="investigation-false-positive-table-wrap">
        <table className="investigation-false-positive-table">
          <thead>
            <tr>
              <th>Software</th>
              <th>Version</th>
              <th>False Positive</th>
              <th>Assets Not Impacted</th>
              <th>Vendor Advisory</th>
              <th>Vendor Guidance</th>
            </tr>
          </thead>
          <tbody>
            {falsePositiveResults.map((row) => (
              <tr key={row.id}>
                <td><strong>{row.software}</strong></td>
                <td className="mono">{row.version}</td>
                <td>
                  <strong className={`false-positive-${row.statusTone}`}>{row.statusLabel}</strong>
                  <div className="panel-caption">{row.statusDetail}</div>
                </td>
                <td>
                  <strong>{row.notImpactedAssetCount}</strong>
                </td>
                <td>{row.vendorAdvisory}</td>
                <td>{row.vendorGuidance}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  ) : null;

  const eolDetails = eolAssessed ? (
    <div className="investigation-eol-table-wrap">
      <table className="investigation-eol-table">
        <thead>
          <tr>
            <th>Software</th>
            <th>Vendor</th>
            <th>Version</th>
            <th>Lifecycle</th>
            <th>End of Support</th>
            <th>End of Life</th>
            <th>Recommended Upgrade</th>
          </tr>
        </thead>
        <tbody>
          {eolResults.map((row) => (
            <tr key={row.id}>
              <td><strong>{row.software}</strong></td>
              <td>{row.vendor}</td>
              <td className="mono">{row.version}</td>
              <td>{row.lifecycle}</td>
              <td>{row.endOfSupport}</td>
              <td>{row.endOfLife}</td>
              <td>{row.recommendedUpgrade}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : null;

  const logPanel = (
    <section className="investigation-log-panel">
      <h4>Investigation Log</h4>
      <div className="investigation-log-list">
        {logEntries.map((entry) => (
          <div key={entry.id} className={`investigation-log-entry ${entry.type.toLowerCase()}`}>
            <div className="investigation-log-message">{entry.message}</div>
            <div className="investigation-log-meta">
              <span>{entry.actor}</span>
              <span>{formatTimestamp(entry.at)}</span>
              <span>{entry.type === 'ACTION' ? 'Action Taken' : entry.type === 'IOC' ? 'IOC Found' : 'Note'}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="investigation-log-composer">
        <div className="investigation-log-type-row">
          <button type="button" className={`investigation-log-type-btn${newLogType === 'NOTE' ? ' active' : ''}`} onClick={() => onNewLogTypeChange('NOTE')}>Note</button>
          <button type="button" className={`investigation-log-type-btn${newLogType === 'ACTION' ? ' active' : ''}`} onClick={() => onNewLogTypeChange('ACTION')}>Action Taken</button>
          <button type="button" className={`investigation-log-type-btn${newLogType === 'IOC' ? ' active' : ''}`} onClick={() => onNewLogTypeChange('IOC')}>IOC Found</button>
        </div>
        <div className="investigation-log-input-row">
          <input
            type="text"
            value={newLogMessage}
            onChange={(event) => onNewLogMessageChange(event.target.value)}
            placeholder={newLogType === 'IOC' ? 'Enter IOC: IP, domain, hash, URL...' : 'Add investigation note...'}
          />
          <button type="button" className="btn btn-primary" onClick={onAddLogEntry}>+</button>
        </div>
      </div>
    </section>
  );

  if (!isOpen) {
    return null;
  }

  return (
    <div className="investigation-canvas-overlay" role="dialog" aria-modal="true" aria-label="Investigation canvas">
      <div className="investigation-canvas">
        <div className="investigation-canvas-header">
          <div className="investigation-canvas-title-wrap">
            <div className="investigation-canvas-icon" aria-hidden="true" />
            <div>
              <h3>Investigation</h3>
              <div className="panel-caption">
                {item.externalId} <span className="investigation-inline-status">In Progress</span> · {detail.summary.title}
              </div>
            </div>
          </div>
          <div className="investigation-canvas-header-actions">
            <button
              type="button"
              className="modal-close-btn"
              onClick={closeCanvas}
              aria-label="Close investigation canvas"
            >
              ×
            </button>
          </div>
        </div>

        <div className="investigation-canvas-body">
          <section className="investigation-runbook">
            <div className="investigation-runbook-header">
              <div>
                <h4>Investigation Runbook</h4>
              </div>
              <div className="investigation-runbook-progress">
                <div className="investigation-runbook-progress-bar">
                  <span style={{ width: `${runbookTasks.length > 0 ? (completedCount / runbookTasks.length) * 100 : 0}%` }} />
                </div>
                <strong>{completedCount} / {runbookTasks.length}</strong>
              </div>
            </div>
            <div className="investigation-runbook-list">
              {runbookTasks.map((task) => (
                <React.Fragment key={task.id}>
                  <div className={`investigation-runbook-item ${task.state === 'DONE' ? 'done' : ''}`}>
                    <div className="investigation-runbook-item-main">
                      <div className="investigation-runbook-item-icon" aria-hidden="true" />
                      <div>
                        <strong>{task.title}</strong>
                        <div className="panel-caption">{task.description}</div>
                      </div>
                    </div>
                    <div className="investigation-runbook-actions">
                      {renderRunbookActions(task)}
                    </div>
                  </div>
                  {task.id === 'review-asset-inventory' && (assetResultsExpanded || !assetAssessmentRan) && reviewTask && assessmentPanel}
                  {task.id === 'find-false-positive' && falsePositiveRan && falsePositiveResultsExpanded && (
                    <div className="investigation-false-positive-panel">
                      <div className="investigation-false-positive-header">
                        <div>
                          <h5>False Positive Report</h5>
                          <div className="panel-caption">
                            {falsePositiveResults.length} unique software entr{falsePositiveResults.length === 1 ? 'y was' : 'ies were'} checked against vendor VEX and advisory guidance for this CVE.
                          </div>
                        </div>
                        <button
                          type="button"
                          className="btn btn-secondary btn-inline"
                          onClick={() => setFalsePositiveResultsExpanded(false)}
                        >
                          Hide
                        </button>
                      </div>
                      {falsePositiveDetails}
                    </div>
                  )}
                  {isEolTask(task.id) && eolExpanded && (
                    <div className="investigation-eol-panel">
                      <div className="investigation-eol-header">
                        <div>
                          <h5>End-of-Life Analysis</h5>
                          <div className="panel-caption">
                            Review the applicable software already identified in asset exposure, then assess it against lifecycle inventory.
                          </div>
                        </div>
                        <button type="button" className="btn btn-primary" onClick={assessEolAnalysis}>
                          Assess
                        </button>
                      </div>
                      <div className="investigation-eol-criteria-list">
                        {eolCriteria.map((criterion) => (
                          <div key={criterion.id} className="investigation-eol-criteria-row">
                            <strong>{criterion.software}</strong>
                            <span className="mono">{criterion.version || '—'}</span>
                            <span>{criterion.vendor || 'Inventory'}</span>
                          </div>
                        ))}
                      </div>
                      {eolDetails}
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
            <button
              type="button"
              className="investigation-summary-btn"
              onClick={triggerSummary}
            >
              Generate Investigation Summary ({completedCount}/{runbookTasks.length} actions run)
            </button>
            <CVEInvestigationSummary visible={summaryVisible} input={summaryInput} />
          </section>

          {logPanel}
        </div>

        <div className="investigation-canvas-footer">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={closeCanvas}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function OverviewRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="cve-overview-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function CveOverviewExperience({
  item,
  detail,
  latestAssessment,
  latestInvestigation,
  cvssFields,
  softwareGroups,
  analystId,
  onStepChange,
  onOpenAffectedEntities,
  onOpenImpactedSoftware,
  leadAnalyst,
  onLeadAnalystChange
}: {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail;
  latestAssessment: CveApplicabilityAssessment | null;
  latestInvestigation: CveInvestigation | null;
  cvssFields: Record<string, string>;
  softwareGroups: SoftwareGroup[];
  analystId?: string;
  onStepChange: (step: WorkflowStep) => void;
  onOpenAffectedEntities: () => void;
  onOpenImpactedSoftware: () => void;
  leadAnalyst: string;
  onLeadAnalystChange: (value: string) => void;
}) {
  const affectedProducts = React.useMemo(() => buildAffectedProducts(detail, softwareGroups), [detail, softwareGroups]);
  const [productIndex, setProductIndex] = React.useState(0);
  const [activeTab, setActiveTab] = React.useState<'assets' | 'refs' | 'timeline'>('assets');

  React.useEffect(() => {
    setProductIndex(0);
  }, [detail.summary.externalId]);

  const product = affectedProducts[Math.min(productIndex, Math.max(affectedProducts.length - 1, 0))];
  const currentLeadAnalyst = leadAnalyst || latestInvestigation?.assignedTo || analystId || 'Unassigned analyst';
  const referenceLinks = buildReferenceLinks(detail);
  const remediationText = detail.signals.patchAvailable
    ? `Apply the vendor-fixed version${detail.signals.patchVersions ? ` (${detail.signals.patchVersions})` : ''} and validate the mitigation on impacted assets.`
    : 'No vendor patch is currently available. Continue investigation and apply compensating controls until remediation guidance is published.';
  const timelineItems = [
    detail.summary.publishedAt ? { label: 'CVE Published', value: formatDate(detail.summary.publishedAt), tone: 'published' } : null,
    detail.summary.modifiedAt ? { label: 'CVE Record Updated', value: formatDate(detail.summary.modifiedAt), tone: 'updated' } : null,
    detail.signals.exploitAvailable ? { label: 'Public Exploit Observed', value: detail.summary.modifiedAt ? formatDate(detail.summary.modifiedAt) : 'Observed', tone: 'exploit' } : null,
    latestAssessment?.completedAt ? { label: 'Assessment Completed', value: formatDate(latestAssessment.completedAt), tone: 'verified' } : null,
  ].filter(Boolean) as Array<{ label: string; value: string; tone: string }>;

  const cweList = React.useMemo(() =>
    (detail.summary.cweIds ?? '').split(',').map(s => s.trim()).filter(Boolean),
    [detail.summary.cweIds]
  );

  const recommendedAction = React.useMemo(() => {
    const sev = item.severity?.toLowerCase();
    if (item.inKev && detail.signals.exploitAvailable)
      return 'Investigate and patch immediately — CISA KEV confirmed with active exploitation.';
    if (sev === 'critical' || sev === 'high')
      return `${formatLabel(item.severity)} severity${detail.signals.exploitAvailable ? ' with active exploitation' : ''}. Review affected assets and apply available patches.`;
    return 'Review exposure and apply mitigations per your remediation SLA.';
  }, [item.severity, item.inKev, detail.signals.exploitAvailable]);

  const CVSS_DIMS_LOCAL = [
    { key: 'AV', label: 'Attack vector',       values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' } },
    { key: 'AC', label: 'Attack complexity',   values: { L: 'Low', H: 'High' } },
    { key: 'PR', label: 'Privileges required', values: { N: 'None', L: 'Low', H: 'High' } },
    { key: 'UI', label: 'User interaction',    values: { N: 'None', R: 'Required' } },
    { key: 'S',  label: 'Scope',               values: { U: 'Unchanged', C: 'Changed' } },
    { key: 'C',  label: 'Confidentiality',     values: { N: 'None', L: 'Low', H: 'High' } },
    { key: 'I',  label: 'Integrity',           values: { N: 'None', L: 'Low', H: 'High' } },
    { key: 'A',  label: 'Availability',        values: { N: 'None', L: 'Low', H: 'High' } },
  ] as const;

  return (
    <div className="cve-detail-page">

      {/* ── Decision Panel ──────────────────────────────── */}
      <div className="cvd-decision-panel">
        <div className="cvd-decision-top">
          <span className="cvd-section-label">Decision panel · should you act?</span>
          <span className="cvd-muted-sm">
            {item.lastEvaluatedAt ? `Last evaluated ${formatDate(item.lastEvaluatedAt)}` : ''}
          </span>
        </div>
        <div className="cvd-kv-row">
          <div className="cvd-kv">
            <span className="cvd-kv-label">Severity</span>
            <div className="cvd-kv-score-wrap">
              <span className={`cvd-kv-big cvd-sev-${item.severity?.toLowerCase()}`}>
                {detail.summary.cvssScore != null ? detail.summary.cvssScore.toFixed(1) : formatLabel(item.severity)}
              </span>
              {detail.summary.cvssScore != null && <span className="cvd-kv-denom">/10</span>}
            </div>
            <span className="cvd-kv-sub">{formatLabel(item.severity)}</span>
          </div>

          <div className="cvd-kv">
            <span className="cvd-kv-label">Exploit status</span>
            <div className="cvd-kv-status-wrap">
              <span className={`cvd-dot ${detail.signals.exploitAvailable ? 'cvd-dot-danger' : 'cvd-dot-none'}`} />
              <span className={detail.signals.exploitAvailable ? 'cvd-kv-danger' : 'cvd-kv-muted'}>
                {detail.signals.exploitAvailable ? (detail.signals.exploitReason || 'Active') : 'None known'}
              </span>
            </div>
            {detail.summary.epssScore != null && (
              <span className="cvd-kv-sub">EPSS {(detail.summary.epssScore * 100).toFixed(1)}%</span>
            )}
          </div>

          <div className="cvd-kv">
            <span className="cvd-kv-label">Your exposure</span>
            <div className="cvd-kv-score-wrap">
              <span className="cvd-kv-big">{detail.signals.assetCount}</span>
              <span className="cvd-kv-denom">assets</span>
            </div>
            <span className="cvd-kv-sub">
              <button type="button" className="cvd-link-btn" onClick={onOpenAffectedEntities}>
                {detail.signals.softwareCount} software →
              </button>
            </span>
          </div>

          <div className="cvd-kv">
            <span className="cvd-kv-label">Patch available</span>
            <div className="cvd-kv-status-wrap">
              <span className={`cvd-dot ${detail.signals.patchAvailable ? 'cvd-dot-ok' : 'cvd-dot-none'}`} />
              <span className={detail.signals.patchAvailable ? 'cvd-kv-ok' : 'cvd-kv-muted'}>
                {detail.signals.patchAvailable ? 'Yes' : 'No'}
              </span>
            </div>
            {detail.signals.patchVersions && (
              <span className="cvd-kv-sub">{detail.signals.patchVersions}</span>
            )}
          </div>

          <div className="cvd-kv">
            <span className="cvd-kv-label">Lead analyst</span>
            <div style={{ marginTop: 4 }}>
              <select
                value={leadAnalyst}
                onChange={(e) => onLeadAnalystChange(e.target.value)}
                style={{ fontSize: 12, color: 'var(--text)', background: 'transparent', border: 'none', width: '100%', cursor: 'pointer' }}
              >
                {[leadAnalyst, 'Alex Martinez', 'Sarah Chen', 'Ravi Kumar']
                  .filter((v, i, arr) => arr.indexOf(v) === i)
                  .map(name => <option key={name} value={name}>{name}</option>)}
              </select>
            </div>
            <span className="cvd-kv-sub">{currentLeadAnalyst}</span>
          </div>
        </div>

        <div className="cvd-recommend-banner">
          <div className="cvd-recommend-icon">!</div>
          <div>
            <strong>Recommended action: </strong>
            <span>{recommendedAction}</span>
          </div>
        </div>
      </div>

      {/* ── Workflow Panel ───────────────────────────────── */}
      <div className="cvd-workflow-panel">
        <div className="cvd-workflow-header">
          <div>
            <span className="cvd-section-label">Workflow</span>
            <p className="cvd-workflow-sub">Move from investigation to assessment and finding creation.</p>
          </div>
          <div className="cvd-workflow-secondary">
            <span className="cvd-section-label" style={{ marginRight: 8 }}>Secondary actions</span>
            <span className="cvd-pill-neutral">Mark Deferred</span>
            <span className="cvd-pill-neutral">Export Evidence</span>
            <span className="cvd-pill-neutral">Notify Groups</span>
            <span className="cvd-pill-neutral">AI Insights</span>
          </div>
        </div>

        <div className="cvd-wf-steps">
          <button type="button" className="cvd-wf-step active" onClick={() => onStepChange(1)}>
            <div className="cvd-wf-num">1</div>
            <div className="cvd-wf-body">
              <p className="cvd-wf-title">Investigation</p>
              <p className="cvd-wf-sub">Open the runbook and gather evidence.</p>
            </div>
          </button>
          <button type="button" className="cvd-wf-step" onClick={() => onStepChange(2)}>
            <div className="cvd-wf-num">2</div>
            <div className="cvd-wf-body">
              <p className="cvd-wf-title">Applicability</p>
              <p className="cvd-wf-sub">{formatLabel(item.applicability)} · {item.applicableComponentCount} of {item.matchedComponentCount} confirmed.</p>
            </div>
          </button>
          <button type="button" className="cvd-wf-step" onClick={() => onStepChange(3)}>
            <div className="cvd-wf-num">3</div>
            <div className="cvd-wf-body">
              <p className="cvd-wf-title">Create Finding</p>
              <p className="cvd-wf-sub">Add impacted assets to the backlog.</p>
            </div>
          </button>
        </div>
      </div>

      {/* ── CVE Detail Content ───────────────────────────── */}
      <div className="cvd-content">

        {/* Description */}
        <div className="cvd-card">
          <p className="cvd-section-label">Description</p>
          <p className="cvd-description">{detail.summary.description || 'No description available.'}</p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
            {detail.signals.exploitAvailable && <span className="cvd-flag-chip cvd-flag-critical"><span className="cvd-flag-dot" />Actively Exploited</span>}
            {item.inKev && <span className="cvd-flag-chip cvd-flag-critical"><span className="cvd-flag-dot" />CISA KEV</span>}
            {cweList.map(cwe => <span key={cwe} className="cvd-pill-neutral">{cwe}</span>)}
            <span className={`cvd-pill-neutral ${detail.signals.patchAvailable ? '' : ''}`}>
              {detail.signals.patchAvailable ? 'Patch Available' : 'Patch Pending'}
            </span>
          </div>
        </div>

        {/* Technical details / CVSS */}
        {detail.summary.cvssVector && (
          <div className="cvd-card">
            <div className="cvd-technical-hdr">
              <p className="cvd-section-label">Technical details · CVSS v3.1 vector</p>
              {detail.summary.source && <span className="cvd-src-tag">{detail.summary.source}</span>}
            </div>
            <div className="cvd-vector-bar">
              <code className="cvd-vector-code">{detail.summary.cvssVector}</code>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ padding: '4px 10px', fontSize: '11px' }}
                onClick={() => void navigator.clipboard.writeText(detail.summary.cvssVector ?? '')}
              >Copy</button>
            </div>
            <div className="cvd-cvss-grid">
              {CVSS_DIMS_LOCAL.map(({ key, label, values }) => {
                const raw = cvssFields[key];
                if (!raw) return null;
                return (
                  <div key={key} className="cvd-cvss-cell">
                    <p className="cvd-cvss-cell-label">{label}</p>
                    <p className="cvd-cvss-cell-val">{(values as Record<string, string>)[raw] ?? raw}</p>
                    <span className="cvd-cvss-cell-code">{key}:{raw}</span>
                  </div>
                );
              })}
            </div>
            <div className="cvd-cvss-meta">
              {detail.summary.publishedAt && (
                <div>
                  <p className="cvd-meta-label">Published</p>
                  <p className="cvd-meta-val">{formatDate(detail.summary.publishedAt)}</p>
                </div>
              )}
              {detail.summary.modifiedAt && (
                <div>
                  <p className="cvd-meta-label">Last modified</p>
                  <p className="cvd-meta-val">{formatDate(detail.summary.modifiedAt)}</p>
                </div>
              )}
              {detail.summary.epssScore != null && (
                <div>
                  <p className="cvd-meta-label">EPSS score</p>
                  <p className="cvd-meta-val cvd-meta-warn">{(detail.summary.epssScore * 100).toFixed(2)}%</p>
                </div>
              )}
              {detail.summary.epssScore != null && (
                <div>
                  <p className="cvd-meta-label">EPSS percentile</p>
                  <p className="cvd-meta-val">{Math.max(1, Math.round(detail.summary.epssScore * 100))}th</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Affected products + Weaknesses */}
        {(affectedProducts.length > 0 || cweList.length > 0) && (
          <div className="cvd-two-col">
            {affectedProducts.length > 0 && (
              <div className="cvd-card cvd-card-flush">
                <div className="cvd-card-inset-hdr">
                  <p className="cvd-section-label">Affected entities</p>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span className="cvd-count-badge">{affectedProducts.length} entries</span>
                    {affectedProducts.length > 1 && (
                      <button
                        type="button"
                        className="cvd-link-btn"
                        onClick={() => setProductIndex(i => (i + 1) % affectedProducts.length)}
                      >Next</button>
                    )}
                  </div>
                </div>
                {product ? (
                  <div>
                    <div className="cvd-entity-row">
                      <div className="cvd-entity-row-top">
                        <span className="cvd-entity-name">{product.product}</span>
                        <span className="cvd-src-tag">{product.vendor}</span>
                      </div>
                      <span className="cvd-entity-versions">{product.affectedVersions}</span>
                    </div>
                    <div className="cvd-entity-row">
                      <div className="cvd-entity-row-top">
                        <span className="cvd-entity-name">CWE</span>
                        <span className="cvd-entity-versions">{product.cwe}</span>
                      </div>
                    </div>
                    <div className="cvd-entity-row">
                      <div className="cvd-entity-row-top">
                        <span className="cvd-entity-name">Assets impacted</span>
                        <button type="button" className="cvd-link-btn" onClick={onOpenAffectedEntities}>
                          {product.totalAssetsImpacted.toLocaleString()} →
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="cvd-entity-row"><span className="cvd-kv-muted">No affected product data.</span></div>
                )}
              </div>
            )}

            {cweList.length > 0 && (
              <div className="cvd-card cvd-card-flush">
                <div className="cvd-card-inset-hdr">
                  <p className="cvd-section-label">Weaknesses</p>
                  <span className="cvd-count-badge">{cweList.length} CWEs</span>
                </div>
                {cweList.map(cwe => (
                  <div key={cwe} className="cvd-entity-row">
                    <span className="cvd-entity-name">{cwe}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Solution */}
        <div className="cvd-card">
          <div className="cvd-solution-hdr">
            <p className="cvd-section-label">Solution</p>
            <span className={`severity-pill ${detail.signals.patchAvailable ? 'severity-low' : 'severity-high'}`}>
              {detail.signals.patchAvailable ? '✓ Available' : '⚠ Pending'}
            </span>
          </div>
          <div className="cvd-sol-card">
            <div className="cvd-sol-top">
              <span className="cvd-sol-title">{remediationText}</span>
              {detail.summary.source && <span className="cvd-src-tag">{detail.summary.source}</span>}
            </div>
            {detail.signals.patchAvailable && (
              <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                <span className="severity-pill severity-low">Recommended</span>
                <span className="cvd-pill-neutral">Full fix</span>
              </div>
            )}
          </div>
        </div>

        {/* Tabs: Affected assets / References / Timeline */}
        <div className="cvd-card" style={{ padding: 0 }}>
          <div className="cvd-tab-bar">
            <button type="button" className={`cvd-tab-btn ${activeTab === 'assets' ? 'active' : ''}`} onClick={() => setActiveTab('assets')}>
              Affected assets · {detail.signals.assetCount}
            </button>
            <button type="button" className={`cvd-tab-btn ${activeTab === 'refs' ? 'active' : ''}`} onClick={() => setActiveTab('refs')}>
              References · {referenceLinks.length}
            </button>
            <button type="button" className={`cvd-tab-btn ${activeTab === 'timeline' ? 'active' : ''}`} onClick={() => setActiveTab('timeline')}>
              Timeline
            </button>
          </div>

          {activeTab === 'assets' && (
            <div style={{ padding: '14px 16px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {affectedProducts.slice(0, 5).map((p, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                    <div>
                      <p style={{ margin: 0, fontSize: 13, fontWeight: 500, color: 'var(--text)' }}>{p.product}</p>
                      <p style={{ margin: 0, fontSize: 11, color: 'var(--muted)' }}>{p.vendor} · {p.affectedVersions}</p>
                    </div>
                    <button type="button" className="btn btn-secondary" style={{ fontSize: 11, padding: '4px 10px' }} onClick={onOpenAffectedEntities}>
                      {p.totalAssetsImpacted} assets
                    </button>
                  </div>
                ))}
                <button type="button" className="cvd-link-btn" style={{ alignSelf: 'flex-start', marginTop: 4 }} onClick={onOpenAffectedEntities}>
                  View all affected assets →
                </button>
              </div>
            </div>
          )}

          {activeTab === 'refs' && (
            <div className="cvd-refs-list">
              {referenceLinks.length === 0 ? (
                <p className="cvd-tab-empty">No references available.</p>
              ) : (
                referenceLinks.map(ref => (
                  <div key={ref.href} className="cvd-ref-row">
                    <a href={ref.href} target="_blank" rel="noreferrer" className="cvd-ref-link">{ref.label}</a>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div style={{ padding: '14px 16px' }}>
              {timelineItems.length === 0 ? (
                <p className="cvd-tab-empty">No timeline events available.</p>
              ) : (
                timelineItems.map(entry => (
                  <div key={`${entry.label}-${entry.value}`} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                    <span className={`cve-overview-timeline-dot ${entry.tone}`} aria-hidden="true" style={{ marginTop: 4, flexShrink: 0 }} />
                    <div>
                      <p style={{ margin: 0, fontSize: 13, fontWeight: 500, color: 'var(--text)' }}>{entry.label}</p>
                      <p style={{ margin: 0, fontSize: 11, color: 'var(--muted)' }}>{entry.value}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// --- VEX Evidence Mini-Card ---

function VexEvidenceCard({ evidence }: { evidence: CveVexEvidence }) {
  const rows: Array<{ key: string; value: React.ReactNode }> = [
    { key: 'Asset', value: evidence.assetName ?? evidence.assetIdentifier ?? '—' },
    {
      key: 'Software',
      value: [evidence.packageName, evidence.installedVersion].filter(Boolean).join(' ') || '—',
    },
    {
      key: 'Provider',
      value: `${formatLabel(evidence.provider)} / ${formatLabel(evidence.status)}`,
    },
    {
      key: 'Trust',
      value: `${formatLabel(evidence.trustTier)} trust · ${formatLabel(evidence.freshness)}`,
    },
  ];
  if (evidence.documentId) {
    rows.push({ key: 'Document', value: <span className="mono">{evidence.documentId}</span> });
  }
  if (evidence.evidenceUrl) {
    rows.push({
      key: 'Source',
      value: (
        <a href={evidence.evidenceUrl} target="_blank" rel="noreferrer">
          {evidence.evidenceUrl}
        </a>
      ),
    });
  }
  return (
    <div className="vex-evidence-card">
      <div className="vex-evidence-grid">
        {rows.map(({ key, value }) => (
          <React.Fragment key={key}>
            <span className="vex-evidence-key">{key}</span>
            <span className="vex-evidence-val">{value}</span>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

// --- Applicability Decision Table (step 2, left panel) ---

type ApplicabilityTableProps = {
  matchedSoftware: CveMatchedSoftware[];
  applicabilityDecisions: Map<string, ApplicabilityDecision>;
  impactDecisions: Map<string, ImpactDecision>;
  expandedEvidenceComponentId: string | null;
  vexEvidenceByComponent: Record<string, CveVexEvidence | null>;
  vexEvidenceErrors: Record<string, string | null>;
  vexEvidenceLoadingComponentId: string | null;
  onApplicabilityDecision: (componentId: string, decision: ApplicabilityDecision) => void;
  onBulkApplicabilityDecision: (decision: ApplicabilityDecision) => void;
  onImpactDecision: (componentId: string, decision: ImpactDecision) => void;
  onToggleVexEvidence: (componentId: string) => void | Promise<void>;
};

function ApplicabilityTable({
  matchedSoftware,
  applicabilityDecisions,
  impactDecisions,
  expandedEvidenceComponentId,
  vexEvidenceByComponent,
  vexEvidenceErrors,
  vexEvidenceLoadingComponentId,
  onApplicabilityDecision,
  onBulkApplicabilityDecision,
  onImpactDecision,
  onToggleVexEvidence,
}: ApplicabilityTableProps) {
  const applicableSoftware = matchedSoftware.filter(
    (s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE'
  );

  return (
    <>
      {/* Applicability Assessment */}
      <div className="cve-decision-section">
        <div className="cve-decision-section-header">
          <h4>Applicability Assessment</h4>
          <p>Determine if the matched software is truly relevant to your environment</p>
        </div>
        {matchedSoftware.length === 0 ? (
          <div className="cve-intel-empty">No matched software to assess.</div>
        ) : (
          <>
            <div className="cve-bulk-actions">
              <span className="cve-bulk-actions-label">Mark all:</span>
              <button type="button" className="btn btn-secondary btn-inline" onClick={() => onBulkApplicabilityDecision('APPLICABLE')}>
                Applicable
              </button>
              <button type="button" className="btn btn-secondary btn-inline" onClick={() => onBulkApplicabilityDecision('NOT_APPLICABLE')}>
                Not Applicable
              </button>
              <button type="button" className="btn btn-secondary btn-inline" onClick={() => onBulkApplicabilityDecision('NEEDS_REVIEW')}>
                Needs Review
              </button>
            </div>
            <table className="cve-decision-table">
              <thead>
                <tr>
                  <th>Software</th>
                  <th>Asset</th>
                  <th>Match Basis</th>
                  <th>Confidence</th>
                  <th>Decision</th>
                </tr>
              </thead>
              <tbody>
                {matchedSoftware.map((sw) => {
                  const conf = confidenceFromApplicability(sw.applicabilityState);
                  const decision = applicabilityDecisions.get(sw.componentId) ?? 'NEEDS_REVIEW';
                  return (
                    <tr key={sw.componentId}>
                      <td>
                        <strong>{sw.packageName}</strong> <span className="cve-decision-table-muted">{sw.version}</span>
                        <div className="panel-caption">{explainApplicability(sw)}</div>
                      </td>
                      <td className="cve-decision-table-muted mono">{sw.assetName ?? sw.assetIdentifier ?? '—'}</td>
                      <td className="cve-decision-table-muted">{matchBasisLabel(sw.matchedBy)}</td>
                      <td><span className={`cve-confidence-badge ${conf}`}>{formatLabel(conf)}</span></td>
                      <td>
                        <SegmentedControl
                          ariaLabel={`Applicability for ${sw.packageName}`}
                          value={decision}
                          onChange={(v) => onApplicabilityDecision(sw.componentId, v as ApplicabilityDecision)}
                          options={[
                            { value: 'APPLICABLE', label: 'Applicable', activeClass: 'seg-applicable' },
                            { value: 'NOT_APPLICABLE', label: 'Not Applicable', activeClass: 'seg-not-applicable' },
                            { value: 'NEEDS_REVIEW', label: 'Review', activeClass: 'seg-needs-review' },
                          ]}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>

      {/* Impact Assessment */}
      <div className="cve-decision-section cve-impact-section">
        <div className="cve-decision-section-header cve-impact-section-header">
          <div className="cve-impact-title-row">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className="cve-impact-warn-icon">
              <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
              <path d="M12 9v4M12 17h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <h4>Impact Assessment</h4>
          </div>
          <p>Only applicable software shown. Analyst disposition is captured here, but computed impact stays server-driven from exact VEX evidence.</p>
        </div>
        {applicableSoftware.length === 0 ? (
          <div className="cve-intel-empty">Mark software as Applicable above to assess impact.</div>
        ) : (
          <table className="cve-decision-table">
            <thead>
              <tr>
                <th>Applicable Software</th>
                <th>Asset</th>
                <th>Exact Match</th>
                <th>Analyst Disposition</th>
              </tr>
            </thead>
            <tbody>
              {applicableSoftware.map((sw) => {
                const impact = impactDecisions.get(sw.componentId) ?? 'UNKNOWN';
                const exactMatchMetaLine = exactMatchMeta(sw);
                return (
                  <tr key={sw.componentId}>
                    <td>
                      <strong>{sw.packageName}</strong> <span className="cve-decision-table-muted">{sw.version}</span>
                      <div className="panel-caption">{explainApplicability(sw)}</div>
                    </td>
                    <td className="cve-decision-table-muted mono">{sw.assetName ?? sw.assetIdentifier ?? '—'}</td>
                    <td className="cve-decision-table-muted">
                      <div>{vendorStatementFor(sw)}</div>
                      {exactMatchMetaLine && (
                        <div className="panel-caption">{exactMatchMetaLine}</div>
                      )}
                      {sw.matchedVexAssertionId && (
                        <div className="panel-caption">
                          <button
                            type="button"
                            className="btn-link"
                            onClick={() => void onToggleVexEvidence(sw.componentId)}
                          >
                            {expandedEvidenceComponentId === sw.componentId ? 'Hide VEX evidence' : 'View VEX evidence'}
                          </button>
                        </div>
                      )}
                      {expandedEvidenceComponentId === sw.componentId && (
                        <div>
                          {vexEvidenceLoadingComponentId === sw.componentId && (
                            <div className="panel-caption">Loading VEX evidence...</div>
                          )}
                          {vexEvidenceErrors[sw.componentId] && (
                            <div className="panel-caption">{vexEvidenceErrors[sw.componentId]}</div>
                          )}
                          {vexEvidenceByComponent[sw.componentId] && (
                            <VexEvidenceCard evidence={vexEvidenceByComponent[sw.componentId]!} />
                          )}
                        </div>
                      )}
                    </td>
                    <td>
                      <SegmentedControl
                        ariaLabel={`Impact disposition for ${sw.packageName}`}
                        value={impact}
                        onChange={(v) => onImpactDecision(sw.componentId, v as ImpactDecision)}
                        options={[
                          { value: 'IMPACTED', label: 'Impacted', activeClass: 'seg-impacted' },
                          { value: 'NOT_IMPACTED', label: 'Not Impacted', activeClass: 'seg-not-impacted' },
                          { value: 'UNKNOWN', label: 'Unknown' },
                        ]}
                      />
                      {sw.analystReason && (
                        <div className="panel-caption">{sw.analystReason}</div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// --- Decision Summary Sidebar (step 2, right panel) ---

type DecisionSummaryProps = {
  matchedSoftware: CveMatchedSoftware[];
  applicabilityDecisions: Map<string, ApplicabilityDecision>;
  impactDecisions: Map<string, ImpactDecision>;
  analystRationale: string;
  onAnalystRationaleChange: (v: string) => void;
  latestAssessment: CveApplicabilityAssessment | null;
  saveBusy: boolean;
  analystId?: string;
  onSave: () => void;
  onProceed: () => void;
  onBack: () => void;
};

type CountBadgeProps = { count: number; variant?: 'green' | 'red' | 'orange' | 'grey' };

function CountBadge({ count, variant = 'grey' }: CountBadgeProps) {
  return <span className={`cve-count-badge cve-count-badge-${variant}`}>{count}</span>;
}

function DecisionSummary({
  matchedSoftware, applicabilityDecisions, impactDecisions, analystRationale, onAnalystRationaleChange,
  latestAssessment, saveBusy, analystId, onSave, onProceed, onBack,
}: DecisionSummaryProps) {
  const applicableCount = matchedSoftware.filter((s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE').length;
  const notApplicableCount = matchedSoftware.filter((s) => applicabilityDecisions.get(s.componentId) === 'NOT_APPLICABLE').length;
  const needsReviewCount = matchedSoftware.filter((s) => (applicabilityDecisions.get(s.componentId) ?? 'NEEDS_REVIEW') === 'NEEDS_REVIEW').length;

  const applicableSoftware = matchedSoftware.filter((s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE');
  const computedImpactedCount = applicableSoftware.filter((s) => {
    const state = computedImpactStateOf(s);
    return state === 'IMPACTED' || state === 'NO_PATCH';
  }).length;
  const computedNotImpactedCount = applicableSoftware.filter((s) => {
    const state = computedImpactStateOf(s);
    return state === 'NOT_IMPACTED' || state === 'FIXED';
  }).length;
  const computedUnknownCount = applicableSoftware.filter((s) => {
    const state = computedImpactStateOf(s);
    return state === 'UNKNOWN' || state === 'UNDER_INVESTIGATION';
  }).length;
  const findingEligibleCount = applicableSoftware.filter((s) => s.eligibleForFinding).length;
  const analystImpactedCount = applicableSoftware.filter((s) => impactDecisions.get(s.componentId) === 'IMPACTED').length;
  const analystNotImpactedCount = applicableSoftware.filter((s) => impactDecisions.get(s.componentId) === 'NOT_IMPACTED').length;
  const analystUnknownCount = applicableSoftware.filter((s) => (impactDecisions.get(s.componentId) ?? 'UNKNOWN') === 'UNKNOWN').length;

  const reviewedAt = latestAssessment?.completedAt ?? latestAssessment?.createdAt;
  const assessmentResult = deriveAssessmentResult(matchedSoftware, applicabilityDecisions, impactDecisions);

  const assessmentResultClass: Record<string, string> = {
    AFFECTED: 'assessment-result-affected',
    NOT_AFFECTED: 'assessment-result-not-affected',
    UNDER_INVESTIGATION: 'assessment-result-under-investigation',
    INCONCLUSIVE: 'assessment-result-inconclusive',
  };

  const assessmentResultLabel: Record<string, string> = {
    AFFECTED: 'Affected',
    NOT_AFFECTED: 'Not Affected',
    UNDER_INVESTIGATION: 'Under Investigation',
    INCONCLUSIVE: 'Inconclusive',
  };

  return (
    <aside className="cve-decision-summary-sidebar">
      <div className="cve-decision-summary-card">
        <h4>Decision Summary</h4>

        <div className="assessment-result-banner">
          <span className="assessment-result-label">Assessment Result</span>
          <span className={`assessment-result-badge ${assessmentResultClass[assessmentResult] ?? ''}`}>
            {assessmentResultLabel[assessmentResult] ?? assessmentResult}
          </span>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Applicability</div>
          <div className="cve-decision-summary-row">
            <span>Applicable</span>
            <CountBadge count={applicableCount} variant={applicableCount > 0 ? 'green' : 'grey'} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Not Applicable</span>
            <CountBadge count={notApplicableCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Needs Review</span>
            <CountBadge count={needsReviewCount} variant={needsReviewCount > 0 ? 'orange' : 'grey'} />
          </div>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Computed Impact</div>
          <div className="cve-decision-summary-row">
            <span>Impacted</span>
            <CountBadge count={computedImpactedCount} variant={computedImpactedCount > 0 ? 'red' : 'grey'} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Not Impacted</span>
            <CountBadge count={computedNotImpactedCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Unknown</span>
            <CountBadge count={computedUnknownCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Finding Eligible</span>
            <CountBadge count={findingEligibleCount} variant={findingEligibleCount > 0 ? 'green' : 'grey'} />
          </div>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Analyst Disposition</div>
          <div className="cve-decision-summary-row">
            <span>Impacted</span>
            <CountBadge count={analystImpactedCount} variant={analystImpactedCount > 0 ? 'red' : 'grey'} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Not Impacted</span>
            <CountBadge count={analystNotImpactedCount} />
          </div>
          <div className="cve-decision-summary-row">
            <span>Unknown</span>
            <CountBadge count={analystUnknownCount} />
          </div>
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Analyst Rationale</div>
          <textarea
            className="cve-notes-textarea"
            value={analystRationale}
            onChange={(e) => onAnalystRationaleChange(e.target.value)}
            placeholder="Document your assessment rationale..."
            rows={4}
          />
        </div>

        <div className="cve-decision-summary-section">
          <div className="cve-decision-summary-section-title">Audit Metadata</div>
          <div className="cve-audit-row">
            <span>Reviewed by</span>
            <span>{analystId ?? 'Current User'}</span>
          </div>
          <div className="cve-audit-row">
            <span>Reviewed at</span>
            <span>{reviewedAt ? new Date(reviewedAt).toLocaleString() : new Date().toLocaleString()}</span>
          </div>
          <div className="cve-audit-row">
            <span>Assessment Type</span>
            <span>Manual</span>
          </div>
        </div>

        <div className="cve-decision-summary-actions">
          <button type="button" className="btn btn-secondary" onClick={onSave} disabled={saveBusy}>
            {saveBusy ? 'Saving...' : 'Save Assessment'}
          </button>
          <button type="button" className="btn btn-primary" onClick={onProceed} disabled={saveBusy}>
            {saveBusy ? 'Saving...' : 'Proceed to Findings'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={onBack}>Back</button>
        </div>
      </div>
    </aside>
  );
}

// --- Findings Content (step 3) ---

type FindingsContentProps = {
  filteredSoftware: FindingDisplayRow[];
  selectedIds: Set<string>;
  showFilter: 'ALL' | 'IMPACTED_ONLY';
  searchQuery: string;
  assetTypeFilter: string;
  severity: string;
  findingIdsByComponentId: Map<string, string>;
  onToggleRow: (id: string) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
  onShowFilterChange: (v: 'ALL' | 'IMPACTED_ONLY') => void;
  onSearchQueryChange: (v: string) => void;
  onAssetTypeFilterChange: (v: string) => void;
  onOpenCreatePanel: () => void;
};

function FindingsContent({
  filteredSoftware, selectedIds, showFilter, searchQuery, assetTypeFilter, severity, findingIdsByComponentId,
  onToggleRow, onSelectAll, onClearAll, onShowFilterChange, onSearchQueryChange, onAssetTypeFilterChange, onOpenCreatePanel,
}: FindingsContentProps) {
  const selectableRows = filteredSoftware.filter((row) => row.selectable);
  const allSelected = selectableRows.length > 0 && selectableRows.every((row) => selectedIds.has(row.software.componentId));
  const someSelected = selectableRows.some((row) => selectedIds.has(row.software.componentId));
  const selectedRows = filteredSoftware.filter((row) => selectedIds.has(row.software.componentId));
  const selectedAssets = new Set(selectedRows.map((row) => row.software.assetId ?? row.software.assetIdentifier ?? row.software.componentId)).size;
  const selectedSoftwareFamilies = new Set(selectedRows.map((row) => row.software.packageName)).size;
  const impactedAssets = new Set(
    selectableRows.map((row) => row.software.assetId ?? row.software.assetIdentifier ?? row.software.assetName ?? row.software.componentId)
  ).size;
  const assetTypes = Array.from(
    new Set(
      filteredSoftware
        .map((row) => (row.software.assetType ?? '').trim())
        .filter((value) => value.length > 0)
    )
  ).sort((left, right) => left.localeCompare(right));
  return (
    <div className="cve-findings-selection-panel">
      <div className="cve-findings-filter-bar">
        <div className="cve-findings-filter-item">
          <label htmlFor="findings-search">Filter:</label>
          <input
            id="findings-search"
            type="search"
            value={searchQuery}
            onChange={(e) => onSearchQueryChange(e.target.value)}
            placeholder="Search asset, software, CI, or version"
          />
        </div>
        <div className="cve-findings-filter-item">
          <label htmlFor="findings-asset-type">Asset Type:</label>
          <select id="findings-asset-type" value={assetTypeFilter} onChange={(e) => onAssetTypeFilterChange(e.target.value)}>
            <option value="ALL">All asset types</option>
            {assetTypes.map((assetType) => (
              <option key={assetType} value={assetType}>
                {formatLabel(assetType)}
              </option>
            ))}
          </select>
        </div>
        <div className="cve-findings-filter-item">
          <label htmlFor="findings-show">Show:</label>
          <select id="findings-show" value={showFilter} onChange={(e) => onShowFilterChange(e.target.value as 'ALL' | 'IMPACTED_ONLY')}>
            <option value="IMPACTED_ONLY">Finding eligible only</option>
            <option value="ALL">Show excluded rows</option>
          </select>
        </div>
        <div className="cve-findings-filter-links">
          <button type="button" className="cve-findings-link-btn" onClick={onSelectAll}>Select All</button>
          <button type="button" className="cve-findings-link-btn secondary" onClick={onClearAll}>Clear Selection</button>
          <button type="button" className="btn btn-primary" onClick={onOpenCreatePanel} disabled={selectedIds.size === 0}>
            Review Configuration
          </button>
        </div>
      </div>

      <div className="cve-findings-summary-grid">
        <div className="cve-findings-summary-card">
          <span className="cve-findings-summary-label">Impacted assets</span>
          <strong>{impactedAssets}</strong>
          <span className="panel-caption">Eligible assets currently in scope</span>
        </div>
        <div className="cve-findings-summary-card">
          <span className="cve-findings-summary-label">Selected assets</span>
          <strong>{selectedAssets}</strong>
          <span className="panel-caption">Assets chosen for finding creation</span>
        </div>
        <div className="cve-findings-summary-card">
          <span className="cve-findings-summary-label">Software families</span>
          <strong>{selectedSoftwareFamilies}</strong>
          <span className="panel-caption">Distinct products represented in selection</span>
        </div>
      </div>

      <div className="cve-findings-asset-section">
        <div className="cve-findings-asset-section-header">
          <h4>Select Impacted Assets for Finding Creation</h4>
          <p className="panel-caption">Create findings for all impacted assets, or filter and select specific assets before opening the finding configuration panel.</p>
        </div>

        <table className="cve-findings-asset-table">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={(el) => { if (el) el.indeterminate = someSelected && !allSelected; }}
                  onChange={() => { if (allSelected) onClearAll(); else onSelectAll(); }}
                  disabled={selectableRows.length === 0}
                />
              </th>
              <th>ASSET / CI</th>
              <th>FINDING ID</th>
              <th>TYPE</th>
              <th>SOFTWARE</th>
              <th>APPLICABILITY</th>
              <th>IMPACT</th>
              <th>ELIGIBILITY REASON</th>
              <th>PRIORITY</th>
            </tr>
          </thead>
          <tbody>
            {filteredSoftware.map((row) => {
              const sw = row.software;
              const checked = selectedIds.has(sw.componentId);
              const pri = priorityFromSeverityAndImpact(severity, row.displayImpact);
              const findingId = findingIdsByComponentId.get(sw.componentId)
                ?? (() => {
                  const identityKey = findingIdentityKey(sw.assetIdentifier, sw.packageName, sw.version);
                  return identityKey ? findingIdsByComponentId.get(identityKey) : undefined;
                })()
                ?? '-';
              return (
                <tr
                  key={sw.componentId}
                  className={`cve-findings-asset-row ${checked ? 'selected' : ''}${row.selectable ? '' : ' is-disabled'}`}
                  onClick={() => { if (row.selectable) onToggleRow(sw.componentId); }}
                >
                  <td onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={!row.selectable}
                      onChange={() => { if (row.selectable) onToggleRow(sw.componentId); }}
                    />
                  </td>
                  <td>
                    <div className="cve-findings-asset-name">
                      <svg className="cve-findings-asset-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                        <rect x="1" y="2" width="14" height="10" rx="1.5" stroke="currentColor" strokeWidth="1.2" />
                        <path d="M4 12v2M12 12v2M3 14h10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                      </svg>
                      <div>
                        <span className="mono">{sw.assetName ?? sw.assetIdentifier ?? sw.componentId}</span>
                        <div className="panel-caption mono">{sw.assetIdentifier ?? sw.assetId ?? sw.componentId}</div>
                      </div>
                    </div>
                  </td>
                  <td><span className="mono">{findingId}</span></td>
                  <td>{formatLabel(sw.assetType ?? 'UNKNOWN')}</td>
                  <td>{sw.packageName} {sw.version}</td>
                  <td>
                    <span className={`cve-applicability-tag ${row.displayApplicability === 'APPLICABLE' ? 'applicable' : row.displayApplicability === 'NOT_APPLICABLE' ? 'not-applicable' : 'unknown'}`}>
                      {row.displayApplicability === 'APPLICABLE' ? 'Applicable' : row.displayApplicability === 'NOT_APPLICABLE' ? 'Not Applicable' : 'Unknown'}
                    </span>
                  </td>
                  <td>
                    <span className={`cve-impact-badge ${impactBadgeClass(row.displayImpact)}`}>
                      {impactLabel(row.displayImpact)}
                    </span>
                  </td>
                  <td>
                    <strong>{row.eligibilityLabel}</strong>
                    <div className="panel-caption">{row.eligibilityDetail}</div>
                  </td>
                  <td><span className={severityClassName(pri)}>{formatLabel(pri)}</span></td>
                </tr>
              );
            })}
            {filteredSoftware.length === 0 && (
              <tr>
                <td colSpan={9} className="cve-findings-empty-row">
                  No impacted asset rows match the current filter. Adjust the asset filter or mark software as Applicable and Impacted first.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

type FindingConfigPanelProps = {
  filteredSoftware: FindingDisplayRow[];
  selectedIds: Set<string>;
  findingTitle: string;
  findingPriority: string;
  assignmentGroup: string;
  ownershipMode: 'LEAD_ANALYST' | 'ASSIGNMENT_GROUP' | 'AUTO';
  ticketTarget: 'SERVICENOW' | 'JIRA';
  dueDate: string;
  tagsInput: string;
  findingNotes: string;
  findingBusy: boolean;
  onClose: () => void;
  onFindingTitleChange: (v: string) => void;
  onFindingPriorityChange: (v: string) => void;
  onAssignmentGroupChange: (v: string) => void;
  onOwnershipModeChange: (v: 'LEAD_ANALYST' | 'ASSIGNMENT_GROUP' | 'AUTO') => void;
  onTicketTargetChange: (v: 'SERVICENOW' | 'JIRA') => void;
  onDueDateChange: (v: string) => void;
  onTagsInputChange: (v: string) => void;
  onFindingNotesChange: (v: string) => void;
  onConfirm: () => void;
};

function FindingConfigPanel({
  filteredSoftware,
  selectedIds,
  findingTitle,
  findingPriority,
  assignmentGroup,
  ownershipMode,
  ticketTarget,
  dueDate,
  tagsInput,
  findingNotes,
  findingBusy,
  onClose,
  onFindingTitleChange,
  onFindingPriorityChange,
  onAssignmentGroupChange,
  onOwnershipModeChange,
  onTicketTargetChange,
  onDueDateChange,
  onTagsInputChange,
  onFindingNotesChange,
  onConfirm,
}: FindingConfigPanelProps) {
  const selectedSoftware = filteredSoftware
    .map((row) => row.software)
    .filter((software) => selectedIds.has(software.componentId));
  const selectedAssetCount = new Set(
    selectedSoftware.map((software) => software.assetId ?? software.assetIdentifier ?? software.componentId)
  ).size;
  const selectedSoftwareCount = new Set(selectedSoftware.map((software) => software.packageName)).size;
  const tags = tagsInput
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  return (
    <aside className="panel cve-findings-config-panel" role="region" aria-labelledby="finding-config-title">
      <div className="cve-findings-modal-header">
        <div>
          <h3 id="finding-config-title">Finding Configuration</h3>
          <p className="panel-caption">Configure due date, tags, and assignment logic for the selected impacted assets without leaving the current findings workspace.</p>
        </div>
        <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close finding configuration">
          ×
        </button>
      </div>

      <div className="cve-findings-modal-grid">
        <div className="cve-findings-modal-main">
          <div className="cve-form-field">
            <label htmlFor="finding-title">Finding Title</label>
            <input id="finding-title" type="text" value={findingTitle} onChange={(e) => onFindingTitleChange(e.target.value)} />
          </div>

          <div className="cve-findings-modal-row">
            <div className="cve-form-field">
              <label htmlFor="finding-priority">Priority</label>
              <select id="finding-priority" value={findingPriority} onChange={(e) => onFindingPriorityChange(e.target.value)}>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
            <div className="cve-form-field">
              <label htmlFor="finding-due-date">Due Date</label>
              <input id="finding-due-date" type="date" value={dueDate} onChange={(e) => onDueDateChange(e.target.value)} />
            </div>
          </div>

          <div className="cve-form-field">
            <label htmlFor="finding-tags">Tags</label>
            <input
              id="finding-tags"
              type="text"
              value={tagsInput}
              onChange={(e) => onTagsInputChange(e.target.value)}
              placeholder="e.g. internet-facing, zero-day, patching"
            />
            {tags.length > 0 && (
              <div className="cve-findings-tag-list">
                {tags.map((tag) => (
                  <span key={tag} className="cve-findings-tag-chip">{tag}</span>
                ))}
              </div>
            )}
          </div>

          <div className="cve-form-field">
            <label htmlFor="finding-ownership">Assignment / Ownership Logic</label>
            <select id="finding-ownership" value={ownershipMode} onChange={(e) => onOwnershipModeChange(e.target.value as 'LEAD_ANALYST' | 'ASSIGNMENT_GROUP' | 'AUTO')}>
              <option value="LEAD_ANALYST">Assign to lead analyst</option>
              <option value="ASSIGNMENT_GROUP">Route to assignment group</option>
              <option value="AUTO">Auto assign by ownership logic</option>
            </select>
          </div>

          <div className="cve-form-field">
            <label htmlFor="assignment-group">Assignment Group</label>
            <input
              id="assignment-group"
              type="text"
              value={assignmentGroup}
              onChange={(e) => onAssignmentGroupChange(e.target.value)}
              placeholder="e.g. IT Infrastructure"
            />
          </div>

          <div className="cve-form-field">
            <label>Ticket Target</label>
            <div className="cve-findings-ticket-target">
              <button
                type="button"
                className={`cve-findings-ticket-btn ${ticketTarget === 'SERVICENOW' ? 'selected' : ''}`}
                onClick={() => onTicketTargetChange('SERVICENOW')}
              >
                ServiceNow
              </button>
              <button
                type="button"
                className={`cve-findings-ticket-btn ${ticketTarget === 'JIRA' ? 'selected' : ''}`}
                onClick={() => onTicketTargetChange('JIRA')}
              >
                Jira
              </button>
            </div>
          </div>

          <div className="cve-form-field">
            <label htmlFor="finding-notes">Notes</label>
            <textarea
              id="finding-notes"
              rows={5}
              value={findingNotes}
              onChange={(e) => onFindingNotesChange(e.target.value)}
              placeholder="Describe the remediation approach or ticket creation context..."
            />
          </div>
        </div>

        <aside className="cve-findings-modal-summary">
          <div className="cve-decision-summary-card">
            <h4>Creation Scope</h4>
            <div className="cve-decision-summary-row">
              <span className="panel-caption">Selected Assets</span>
              <span>{selectedAssetCount}</span>
            </div>
            <div className="cve-decision-summary-row">
              <span className="panel-caption">Selected Rows</span>
              <span>{selectedSoftware.length}</span>
            </div>
            <div className="cve-decision-summary-row">
              <span className="panel-caption">Software Families</span>
              <span>{selectedSoftwareCount}</span>
            </div>
            <div className="cve-decision-summary-row">
              <span className="panel-caption">Ownership Logic</span>
              <span>{formatLabel(ownershipMode)}</span>
            </div>
          </div>
        </aside>
      </div>

      <div className="cve-findings-modal-actions">
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
        <button type="button" className="btn btn-primary" onClick={onConfirm} disabled={findingBusy || selectedIds.size === 0}>
          {findingBusy ? 'Creating...' : `Create Findings (${selectedIds.size})`}
        </button>
      </div>
    </aside>
  );
}

// --- Main Component ---

export function VulnRepoCveAssessmentWorkbench({
  item,
  detail,
  loading,
  error,
  analystId,
  onBack,
  onRefreshDetail
}: Props) {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = React.useState<WorkflowStep>(1);
  const [investigationCanvasOpen, setInvestigationCanvasOpen] = React.useState(false);
  const [actionNotice, setActionNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const latestInvestigation = React.useMemo(() => latestByDate(detail?.investigations ?? []), [detail]);
  const latestAssessment = React.useMemo(() => latestByDate(detail?.assessments ?? []), [detail]);

  // Investigation state
  const [, setInvestigationId] = React.useState<number | null>(null);
  const investigationPriority: InvestigationPriority = 'MEDIUM';
  const [investigationNotes, setInvestigationNotes] = React.useState('');
  const [investigationBusy, setInvestigationBusy] = React.useState(false);
  const [leadAnalyst, setLeadAnalyst] = React.useState('');
  const [runbookTasks, setRunbookTasks] = React.useState<RunbookTask[]>([]);
  const [investigationLogEntries, setInvestigationLogEntries] = React.useState<InvestigationLogEntry[]>([]);
  const [newInvestigationLogType, setNewInvestigationLogType] = React.useState<InvestigationLogType>('NOTE');
  const [newInvestigationLogMessage, setNewInvestigationLogMessage] = React.useState('');

  // Applicability state
  const [, setAssessmentId] = React.useState<number | null>(null);
  const [applicabilityDecisions, setApplicabilityDecisions] = React.useState<Map<string, ApplicabilityDecision>>(new Map());
  const [impactDecisions, setImpactDecisions] = React.useState<Map<string, ImpactDecision>>(new Map());
  const [analystRationale, setAnalystRationale] = React.useState('');
  const [assessmentBusy, setAssessmentBusy] = React.useState(false);
  const [expandedEvidenceComponentId, setExpandedEvidenceComponentId] = React.useState<string | null>(null);
  const [vexEvidenceByComponent, setVexEvidenceByComponent] = React.useState<Record<string, CveVexEvidence | null>>({});
  const [vexEvidenceErrors, setVexEvidenceErrors] = React.useState<Record<string, string | null>>({});
  const [vexEvidenceLoadingComponentId, setVexEvidenceLoadingComponentId] = React.useState<string | null>(null);

  // Findings state
  const [findingTitle, setFindingTitle] = React.useState(() => `${item.externalId} - ${item.title}`);
  const [findingPriority, setFindingPriority] = React.useState(() => item.severity?.toUpperCase() ?? 'MEDIUM');
  const [assignmentGroup, setAssignmentGroup] = React.useState('');
  const [ownershipMode, setOwnershipMode] = React.useState<'LEAD_ANALYST' | 'ASSIGNMENT_GROUP' | 'AUTO'>('LEAD_ANALYST');
  const [ticketTarget, setTicketTarget] = React.useState<'SERVICENOW' | 'JIRA'>('SERVICENOW');
  const [dueDate, setDueDate] = React.useState('');
  const [findingTagsInput, setFindingTagsInput] = React.useState('');
  const [findingNotes, setFindingNotes] = React.useState('');
  const [selectedFindingIds, setSelectedFindingIds] = React.useState<Set<string>>(new Set());
  const [findingShowFilter, setFindingShowFilter] = React.useState<'ALL' | 'IMPACTED_ONLY'>('IMPACTED_ONLY');
  const [findingSearchQuery, setFindingSearchQuery] = React.useState('');
  const [findingAssetTypeFilter, setFindingAssetTypeFilter] = React.useState('ALL');
  const [findingBusy, setFindingBusy] = React.useState(false);
  const [findingConfigOpen, setFindingConfigOpen] = React.useState(false);
  const [findingIdsByComponentId, setFindingIdsByComponentId] = React.useState<Map<string, string>>(new Map());

  // Unsaved-changes guard
  const seedNotesRef = React.useRef('');
  const seedRationaleRef = React.useRef('');
  const [pendingNavAction, setPendingNavAction] = React.useState<(() => void) | null>(null);

  const isDirty = investigationNotes !== seedNotesRef.current || analystRationale !== seedRationaleRef.current;

  function guardedNav(action: () => void): void {
    if (isDirty) {
      setPendingNavAction(() => action);
    } else {
      action();
    }
  }

  // Guard: track which CVE has been initialized so detail refreshes don't overwrite in-flight decisions
  const lastInitializedCveRef = React.useRef<string | null>(null);

  React.useEffect(() => {
    if (!detail) return;
    // Only reinitialize when opening a different CVE, not when detail refreshes mid-session
    if (lastInitializedCveRef.current === item.externalId) return;
    lastInitializedCveRef.current = item.externalId;

    const inv = latestInvestigation as CveInvestigation | null;
    const persistedRunbookState = loadPersistedInvestigationRunbookState(item.externalId);
    const persistedDoneTaskIds = new Set(persistedRunbookState?.doneTaskIds ?? []);
    setInvestigationId(inv?.id ?? null);
    const seedNotes = inv?.notes ?? '';
    setInvestigationNotes(seedNotes);
    seedNotesRef.current = seedNotes;
    setLeadAnalyst(persistedRunbookState?.leadAnalyst ?? inv?.assignedTo ?? analystId ?? 'Alex Martinez');
    setRunbookTasks([
      {
        id: 'review-asset-inventory',
        title: 'Review Asset Inventory',
        description: 'Correlate CVE product evidence with org inventory and confirm matching entities.',
        state: detail.matchedSoftware.length > 0 || persistedDoneTaskIds.has('review-asset-inventory') ? 'DONE' : 'READY',
      },
      {
        id: 'find-false-positive',
        title: 'Find False Positive (AI Search)',
        description: 'Cross-check the advisory, asset configuration, and software fingerprint for false positives.',
        state: persistedDoneTaskIds.has('find-false-positive') ? 'DONE' : 'READY',
      },
      {
        id: 'end-of-life-analysis',
        title: 'End-of-Life Analysis',
        description: 'Check affected product versions against vendor support and end-of-life schedules.',
        state: persistedDoneTaskIds.has('end-of-life-analysis') || persistedDoneTaskIds.has('end-of-life') ? 'DONE' : 'READY',
      },
      {
        id: 'installed-patch-info',
        title: 'Installed Patch Info',
        description: 'Retrieve patch compliance data for all impacted org entities.',
        state: detail.signals.patchAvailable || persistedDoneTaskIds.has('installed-patch-info') ? 'DONE' : 'READY',
      },
    ]);
    setInvestigationLogEntries(
      persistedRunbookState?.logEntries?.length
        ? persistedRunbookState.logEntries
        : [
            {
              id: `${item.externalId}-init`,
              type: 'NOTE',
              message: 'Investigation initiated. Beginning asset inventory review and environmental impact assessment.',
              actor: inv?.assignedTo ?? analystId ?? 'Alex Martinez',
              at: inv?.createdAt ?? new Date().toISOString(),
            },
            ...(detail.matchedSoftware.length > 0 ? [{
              id: `${item.externalId}-asset-review`,
              type: 'ACTION' as const,
              message: `Asset inventory review completed. ${detail.signals.assetCount} org entities identified with correlated software evidence.`,
              actor: inv?.assignedTo ?? analystId ?? 'Alex Martinez',
              at: new Date().toISOString(),
            }] : []),
          ]
    );
    setNewInvestigationLogType('NOTE');
    setNewInvestigationLogMessage('');

    const assess = latestAssessment as CveApplicabilityAssessment | null;
    setAssessmentId(assess?.id ?? null);
    const seedRationale = assess?.justification ?? '';
    setAnalystRationale(seedRationale);
    seedRationaleRef.current = seedRationale;

    // Initialize per-row applicability decisions from existing state
    const initialApplicability = new Map<string, ApplicabilityDecision>();
    for (const sw of detail.matchedSoftware) {
      initialApplicability.set(sw.componentId, initialApplicabilityDecision(sw.applicabilityState));
    }
    setApplicabilityDecisions(initialApplicability);

    // Initialize impact decisions — default UNKNOWN
    const initialImpact = new Map<string, ImpactDecision>();
    for (const sw of detail.matchedSoftware) {
      if (sw.applicabilityState === 'APPLICABLE') {
        const seededDecision = sw.analystDisposition
          ?? (computedImpactStateOf(sw) === 'IMPACTED' || computedImpactStateOf(sw) === 'NO_PATCH'
            ? 'IMPACTED'
            : computedImpactStateOf(sw) === 'NOT_IMPACTED' || computedImpactStateOf(sw) === 'FIXED'
              ? 'NOT_IMPACTED'
              : 'UNKNOWN');
        initialImpact.set(sw.componentId, seededDecision);
      }
    }
    setImpactDecisions(initialImpact);

    // Pre-select all eligible software for finding creation
    const eligible = detail.matchedSoftware.filter((s) => s.eligibleForFinding && s.analystDisposition !== 'NOT_IMPACTED');
    setSelectedFindingIds(new Set(eligible.map((s) => s.componentId)));
    setExpandedEvidenceComponentId(null);
    setVexEvidenceByComponent({});
    setVexEvidenceErrors({});
    setVexEvidenceLoadingComponentId(null);
  }, [detail, item.externalId, latestAssessment, latestInvestigation]);

  const loadPersistedFindingIds = React.useCallback(async (): Promise<void> => {
    try {
      const findingsPage = await api.listFindings({
        page: 0,
        size: 500,
        vulnerabilityId: item.externalId,
      });
      const next = new Map<string, string>();
      findingsPage.items.forEach((finding: Finding) => {
        if (finding.componentId) {
          next.set(finding.componentId, finding.displayId || finding.id);
        }
        const identityKey = findingIdentityKey(
          finding.assetIdentifier,
          finding.packageName,
          finding.packageVersion
        );
        if (identityKey) {
          next.set(identityKey, finding.displayId || finding.id);
        }
      });
      setFindingIdsByComponentId(next);
    } catch {
      setFindingIdsByComponentId(new Map());
    }
  }, [item.externalId]);

  React.useEffect(() => {
    let cancelled = false;

    async function loadForCurrentView(): Promise<void> {
      try {
        const findingsPage = await api.listFindings({
          page: 0,
          size: 500,
          vulnerabilityId: item.externalId,
        });
        if (cancelled) return;
        const next = new Map<string, string>();
        findingsPage.items.forEach((finding: Finding) => {
          if (finding.componentId) {
            next.set(finding.componentId, finding.displayId || finding.id);
          }
          const identityKey = findingIdentityKey(
            finding.assetIdentifier,
            finding.packageName,
            finding.packageVersion
          );
          if (identityKey) {
            next.set(identityKey, finding.displayId || finding.id);
          }
        });
        setFindingIdsByComponentId(next);
      } catch {
        if (!cancelled) {
          setFindingIdsByComponentId(new Map());
        }
      }
    }

    if (activeStep === 3) {
      void loadForCurrentView();
    }
    return () => {
      cancelled = true;
    };
  }, [item.externalId, activeStep]);

  function handleRunbookTask(taskId: string): void {
    if (taskId === 'generate-summary') {
      const completed = runbookTasks.filter((task) => task.state === 'DONE').length;
      setInvestigationLogEntries((current) => [
        ...current,
        {
          id: `summary-${Date.now()}`,
          type: 'ACTION',
          message: `Generated investigation summary based on ${completed}/${runbookTasks.length} completed runbook actions.`,
          actor: leadAnalyst || analystId || 'Alex Martinez',
          at: new Date().toISOString(),
        }
      ]);
      return;
    }

    const task = runbookTasks.find((entry) => entry.id === taskId);
    if (!task) return;
    setRunbookTasks((current) => current.map((entry) => (
      entry.id === taskId ? { ...entry, state: 'DONE' } : entry
    )));
    setInvestigationLogEntries((current) => [
      ...current,
      {
        id: `${taskId}-${Date.now()}`,
        type: 'ACTION',
        message: `${task.title} completed.`,
        actor: leadAnalyst || analystId || 'Alex Martinez',
        at: new Date().toISOString(),
      }
    ]);
  }

  function handleAddInvestigationLogEntry(): void {
    if (!newInvestigationLogMessage.trim()) return;
    setInvestigationLogEntries((current) => [
      ...current,
      {
        id: `manual-${Date.now()}`,
        type: newInvestigationLogType,
        message: newInvestigationLogMessage.trim(),
        actor: leadAnalyst || analystId || 'Alex Martinez',
        at: new Date().toISOString(),
      }
    ]);
    setNewInvestigationLogMessage('');
  }

  const toggleVexEvidence = React.useCallback(async (componentId: string) => {
    if (expandedEvidenceComponentId === componentId) {
      setExpandedEvidenceComponentId(null);
      return;
    }
    setExpandedEvidenceComponentId(componentId);
    if (vexEvidenceByComponent[componentId] || vexEvidenceLoadingComponentId === componentId) {
      return;
    }
    setVexEvidenceLoadingComponentId(componentId);
    setVexEvidenceErrors((current) => ({ ...current, [componentId]: null }));
    try {
      const evidence = await cveWorkbenchApi.getCveVexEvidence(item.externalId, componentId);
      setVexEvidenceByComponent((current) => ({ ...current, [componentId]: evidence }));
    } catch (requestError) {
      const rawMessage = requestError instanceof Error ? requestError.message : String(requestError);
      const message = rawMessage.includes('(404)') || rawMessage.includes('[NOT_FOUND]')
        ? 'No persisted VEX evidence is currently linked to this component.'
        : rawMessage;
      setVexEvidenceErrors((current) => ({ ...current, [componentId]: message }));
    } finally {
      setVexEvidenceLoadingComponentId((current) => (current === componentId ? null : current));
    }
  }, [expandedEvidenceComponentId, item.externalId, vexEvidenceByComponent, vexEvidenceLoadingComponentId]);

  const softwareGroups = React.useMemo(
    () => buildSoftwareGroups(detail?.matchedSoftware ?? []),
    [detail]
  );

  const currentApplicableSoftware = React.useMemo(
    () => applicableSoftwareRows(detail?.matchedSoftware ?? [], applicabilityDecisions),
    [detail, applicabilityDecisions]
  );

  const persistedRunbookState = React.useMemo(
    () => (detail ? loadPersistedInvestigationRunbookState(detail.summary.externalId) : null),
    [detail]
  );

  const findingRows = React.useMemo<FindingDisplayRow[]>(() => {
    const baseRows = buildFindingDisplayRows(
      currentApplicableSoftware,
      applicabilityDecisions,
      impactDecisions,
      findingShowFilter
    );
    if (!detail || !persistedRunbookState?.assetResults?.length) {
      return baseRows;
    }

    const persistedAssets = persistedRunbookState.assetResults;
    const resolvedInventory = persistedRunbookState.resolvedInventory ?? [];
    const investigationRows = new Map<string, FindingDisplayRow>();

    const assetMatchesRunbook = (software: CveMatchedSoftware): boolean => {
      const assetKeys = [
        software.assetId,
        software.assetIdentifier,
        software.assetName,
      ].filter(Boolean).map((value) => normalizeAssetInventoryValue(value));
      return persistedAssets.some((asset) => {
        const assetIdentityKeys = [asset.id, asset.identifier, asset.entity]
          .filter(Boolean)
          .map((value) => normalizeAssetInventoryValue(value));
        const softwareMatch = asset.matchedSoftware.some((entry) => (
          normalizeAssetInventoryValue(entry.software) === normalizeAssetInventoryValue(software.packageName)
          && normalizeAssetInventoryValue(entry.version) === normalizeAssetInventoryValue(software.version ?? '-')
        ));
        return softwareMatch && assetKeys.some((key) => assetIdentityKeys.includes(key));
      });
    };

    detail.matchedSoftware.forEach((software) => {
      if (!assetMatchesRunbook(software)) return;
      investigationRows.set(software.componentId, {
        software,
        selectable: true,
        eligibilityLabel: 'Impacted asset from investigation',
        eligibilityDetail: 'This asset was confirmed in the investigation asset review and is eligible for finding creation.',
        displayApplicability: 'APPLICABLE',
        displayImpact: 'IMPACTED',
      });
    });

    resolvedInventory.forEach((resolvedRow) => {
      resolvedRow.assets.forEach((asset) => {
        const rowId = asset.componentId;
        if (investigationRows.has(rowId)) return;
        const syntheticSoftware: CveMatchedSoftware = {
          componentId: asset.componentId,
          assetId: asset.assetId,
          assetName: asset.assetName,
          assetIdentifier: asset.assetIdentifier,
          assetType: asset.assetType,
          ecosystem: asset.ecosystem ?? resolvedRow.vendor ?? 'Inventory',
          packageName: resolvedRow.software,
          version: resolvedRow.version || asset.version || null,
          applicabilityState: 'APPLICABLE',
          computedImpactState: 'IMPACTED',
          impactState: 'IMPACTED',
          eligibleForFinding: true,
          findingEligibilityReason: 'analyst_override_impacted',
          findingEligibilityDetail: 'This asset was added through the investigation asset review and is eligible for finding creation.',
        };
        investigationRows.set(rowId, {
          software: syntheticSoftware,
          selectable: true,
          eligibilityLabel: 'Impacted asset from investigation',
          eligibilityDetail: 'This asset was added through the investigation asset review and is eligible for finding creation.',
          displayApplicability: 'APPLICABLE',
          displayImpact: 'IMPACTED',
        });
      });
    });

    const scopedRows = Array.from(investigationRows.values()).sort((left, right) => {
      const leftAsset = left.software.assetName ?? left.software.assetIdentifier ?? left.software.componentId;
      const rightAsset = right.software.assetName ?? right.software.assetIdentifier ?? right.software.componentId;
      return leftAsset.localeCompare(rightAsset) || left.software.packageName.localeCompare(right.software.packageName);
    });

    if (scopedRows.length === 0) {
      return baseRows;
    }
    if (findingShowFilter === 'IMPACTED_ONLY') {
      return scopedRows;
    }
    const scopedIds = new Set(scopedRows.map((row) => row.software.componentId));
    return [...scopedRows, ...baseRows.filter((row) => !scopedIds.has(row.software.componentId))];
  }, [currentApplicableSoftware, applicabilityDecisions, impactDecisions, findingShowFilter, detail, persistedRunbookState]);

  const filteredFindingSoftware = React.useMemo<FindingDisplayRow[]>(() => {
    const normalizedQuery = normalizedAssetInventorySearch(findingSearchQuery);
    return findingRows.filter((row) => {
      const assetTypeMatches = findingAssetTypeFilter === 'ALL' || (row.software.assetType ?? '') === findingAssetTypeFilter;
      if (!assetTypeMatches) return false;
      if (!normalizedQuery) return true;
      const searchBlob = [
        row.software.assetName,
        row.software.assetIdentifier,
        row.software.assetId,
        row.software.packageName,
        row.software.version,
        row.software.ecosystem,
      ].filter(Boolean).join(' ');
      return normalizedAssetInventorySearch(searchBlob).includes(normalizedQuery);
    });
  }, [findingRows, findingAssetTypeFilter, findingSearchQuery]);

  const cvssFields = React.useMemo(() => parseCvssVector(detail?.summary.cvssVector), [detail]);

  const overallConfidence = React.useMemo(() => {
    if (!detail) return { label: 'Unknown', cls: '', pct: 0 };
    const applicable = detail.matchedSoftware.filter((s) => s.applicabilityState === 'APPLICABLE').length;
    const total = detail.matchedSoftware.length;
    if (total === 0) return { label: 'Unknown', cls: '', pct: 0 };
    const pct = Math.round((applicable / total) * 100);
    if (pct >= 70) return { label: 'High', cls: 'is-high', pct };
    if (pct >= 40) return { label: 'Medium', cls: 'is-medium', pct };
    return { label: 'Low', cls: 'is-low', pct };
  }, [detail]);

  function setApplicabilityDecision(componentId: string, decision: ApplicabilityDecision): void {
    setApplicabilityDecisions((prev) => new Map(prev).set(componentId, decision));
    // If changing to non-applicable, clear impact decision
    if (decision !== 'APPLICABLE') {
      setImpactDecisions((prev) => { const next = new Map(prev); next.delete(componentId); return next; });
    } else {
      // Default to UNKNOWN when marked applicable
      setImpactDecisions((prev) => { const next = new Map(prev); if (!next.has(componentId)) next.set(componentId, 'UNKNOWN'); return next; });
    }
  }

  function setImpactDecision(componentId: string, decision: ImpactDecision): void {
    setImpactDecisions((prev) => new Map(prev).set(componentId, decision));
  }

  const currentBreadcrumbStep = activeStep === 1 ? null : activeStep === 2 ? 'Applicability' : 'Create Findings';

  async function saveInvestigationAndContinue(): Promise<boolean> {
    setInvestigationBusy(true);
    setActionError(null);
    try {
      const saved = await cveWorkbenchApi.submitCveInvestigation(item.externalId, {
        priority: investigationPriority,
        assignedTo: leadAnalyst.trim() || undefined,
        notes: investigationNotes.trim() || undefined,
      });
      setInvestigationId(saved.id);
      setActiveStep(2);
      return true;
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setInvestigationBusy(false);
    }
  }

  async function saveAssessment(proceed: boolean): Promise<void> {
    if (!detail) return;
    setAssessmentBusy(true);
    setActionError(null);
    try {
      const matchedSoftwareList = detail.matchedSoftware;
      const applicableComponents = matchedSoftwareList
        .filter((s) => applicabilityDecisions.get(s.componentId) === 'APPLICABLE')
        .map((s) => softwareLabel(s));

      const finalResult = deriveAssessmentResult(matchedSoftwareList, applicabilityDecisions, impactDecisions);
      const hasImpacted = Array.from(impactDecisions.values()).some((d) => d === 'IMPACTED');

      const componentImpactDecisions: Record<string, 'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN'> = {};
      impactDecisions.forEach((decision, componentId) => {
        componentImpactDecisions[componentId] = decision;
      });

      const saved = await cveWorkbenchApi.submitCveAssessment(item.externalId, {
        softwareDetected: applicableComponents.length > 0,
        detectionMethod: 'SOFTWARE_INVENTORY',
        affectedComponents: applicableComponents.join('\n'),
        vulnerableVersionPresent: hasImpacted || undefined,
        finalResult,
        confidenceLevel: overallConfidence.label.toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW',
        justification: analystRationale.trim(),
        recommendedAction: '',
        componentImpactDecisions,
        componentAnalystDispositions: componentImpactDecisions,
      });
      setAssessmentId(saved.id);

      if (proceed) setActiveStep(3);
      else setActionNotice('Assessment saved successfully.');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setAssessmentBusy(false);
    }
  }

  async function createFindings(): Promise<void> {
    if (selectedFindingIds.size === 0) {
      setActionError('Select at least one finding row before creating findings.');
      return;
    }
    setFindingBusy(true);
    setActionError(null);
    try {
      const tags = findingTagsInput
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
      const structuredNotes = [
        findingNotes.trim(),
        dueDate ? `Due Date: ${dueDate}` : '',
        tags.length > 0 ? `Tags: ${tags.join(', ')}` : '',
        `Ownership Logic: ${formatLabel(ownershipMode)}`,
        assignmentGroup.trim() ? `Assignment Group: ${assignmentGroup.trim()}` : '',
        `Ticket Target: ${ticketTarget}`,
      ].filter((entry) => entry.length > 0).join('\n');
      const selectedRows = findingRows.filter((row) => selectedFindingIds.has(row.software.componentId));
      const selectedApplicabilityDecisions: Record<string, 'APPLICABLE' | 'NOT_APPLICABLE' | 'NEEDS_REVIEW'> = {
        ...Object.fromEntries(applicabilityDecisions),
      };
      const selectedImpactDecisions: Record<string, 'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN'> = {
        ...Object.fromEntries(impactDecisions),
      };
      selectedRows.forEach((row) => {
        selectedApplicabilityDecisions[row.software.componentId] = row.displayApplicability;
        selectedImpactDecisions[row.software.componentId] = row.displayImpact === 'NOT_IMPACTED'
          ? 'NOT_IMPACTED'
          : row.displayImpact === 'UNKNOWN'
            ? 'UNKNOWN'
            : 'IMPACTED';
      });
      const result = await cveWorkbenchApi.createManualFindings(item.externalId, {
        justification: structuredNotes,
        componentIds: Array.from(selectedFindingIds),
        componentApplicabilityDecisions: selectedApplicabilityDecisions,
        componentAnalystDispositions: selectedImpactDecisions,
      });
      await onRefreshDetail();
      await loadPersistedFindingIds();
      setFindingConfigOpen(false);
      const parts: string[] = [result.message];
      if (result.createdCount > 0) parts.push(`Created ${result.createdCount}.`);
      if (result.reopenedCount > 0) parts.push(`Reopened ${result.reopenedCount}.`);
      if (result.alreadyOpenCount > 0) parts.push(`${result.alreadyOpenCount} already open.`);
      setActionNotice(parts.join(' '));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setFindingBusy(false);
    }
  }

  function toggleFindingRow(componentId: string): void {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(componentId)) next.delete(componentId);
      else next.add(componentId);
      return next;
    });
  }

  function selectAllFindings(): void {
    setSelectedFindingIds(new Set(filteredFindingSoftware.filter((row) => row.selectable).map((row) => row.software.componentId)));
  }

  function clearAllFindings(): void {
    setSelectedFindingIds(new Set());
  }

  return (
    <div className="cve-assessment-page">
      <div className="cve-assessment-breadcrumb">
        <button type="button" onClick={() => guardedNav(() => setActiveStep(1))}>{item.externalId}</button>
        {currentBreadcrumbStep && (
          <>
            <span aria-hidden="true">›</span>
            <span>{currentBreadcrumbStep}</span>
          </>
        )}
      </div>

      {loading ? (
        <div className="notice">Loading CVE details...</div>
      ) : error ? (
        <div className="notice error">{error}</div>
      ) : !detail ? (
        <div className="notice error">No detail available for this CVE.</div>
      ) : (
        <>
          {actionNotice && <div className="notice">{actionNotice}</div>}
          {actionError && <div className="notice error">{actionError}</div>}

          {/* Step 1 — Investigation */}
          {activeStep === 1 && (
            <CveOverviewExperience
              item={item}
              detail={detail}
              latestAssessment={latestAssessment}
              latestInvestigation={latestInvestigation}
              cvssFields={cvssFields}
              softwareGroups={softwareGroups}
              analystId={analystId}
              onOpenAffectedEntities={() => navigate(pathForVulnRepoCveAssets(item.externalId))}
              onOpenImpactedSoftware={() => navigate(pathForVulnRepoCveSoftware(item.externalId))}
              leadAnalyst={leadAnalyst || analystId || 'Alex Martinez'}
              onLeadAnalystChange={setLeadAnalyst}
              onStepChange={(step) => {
                if (step === 1) {
                  setInvestigationCanvasOpen(true);
                  return;
                }
                setActiveStep(step);
              }}
            />
          )}

          {/* Step 2 — Applicability */}
          {activeStep === 2 && (
            <div className="cve-applicability-layout">
              <div className="cve-applicability-main">
                <ApplicabilityTable
                  matchedSoftware={detail.matchedSoftware}
                  applicabilityDecisions={applicabilityDecisions}
                  impactDecisions={impactDecisions}
                  expandedEvidenceComponentId={expandedEvidenceComponentId}
                  vexEvidenceByComponent={vexEvidenceByComponent}
                  vexEvidenceErrors={vexEvidenceErrors}
                  vexEvidenceLoadingComponentId={vexEvidenceLoadingComponentId}
                  onApplicabilityDecision={setApplicabilityDecision}
                  onBulkApplicabilityDecision={(decision) => {
                    detail.matchedSoftware.forEach((sw) => setApplicabilityDecision(sw.componentId, decision));
                  }}
                  onImpactDecision={setImpactDecision}
                  onToggleVexEvidence={toggleVexEvidence}
                />
              </div>
              <DecisionSummary
                matchedSoftware={detail.matchedSoftware}
                applicabilityDecisions={applicabilityDecisions}
                impactDecisions={impactDecisions}
                analystRationale={analystRationale}
                onAnalystRationaleChange={setAnalystRationale}
                latestAssessment={latestAssessment}
                saveBusy={assessmentBusy}
                analystId={analystId}
                onSave={() => saveAssessment(false)}
                onProceed={() => saveAssessment(true)}
                onBack={() => guardedNav(() => setActiveStep(1))}
              />
            </div>
          )}

          {/* Step 3 — Create Findings */}
          {activeStep === 3 && (
            <div className={`cve-findings-workspace${findingConfigOpen ? ' cve-findings-workspace--with-config' : ''}`}>
              <FindingsContent
                filteredSoftware={filteredFindingSoftware}
                selectedIds={selectedFindingIds}
                showFilter={findingShowFilter}
                searchQuery={findingSearchQuery}
                assetTypeFilter={findingAssetTypeFilter}
                severity={item.severity}
                findingIdsByComponentId={findingIdsByComponentId}
                onToggleRow={toggleFindingRow}
                onSelectAll={selectAllFindings}
                onClearAll={clearAllFindings}
                onShowFilterChange={setFindingShowFilter}
                onSearchQueryChange={setFindingSearchQuery}
                onAssetTypeFilterChange={setFindingAssetTypeFilter}
                onOpenCreatePanel={() => setFindingConfigOpen(true)}
              />
              {findingConfigOpen ? (
                <FindingConfigPanel
                  filteredSoftware={filteredFindingSoftware}
                  selectedIds={selectedFindingIds}
                  findingTitle={findingTitle}
                  findingPriority={findingPriority}
                  assignmentGroup={assignmentGroup}
                  ownershipMode={ownershipMode}
                  ticketTarget={ticketTarget}
                  dueDate={dueDate}
                  tagsInput={findingTagsInput}
                  findingNotes={findingNotes}
                  findingBusy={findingBusy}
                  onClose={() => setFindingConfigOpen(false)}
                  onFindingTitleChange={setFindingTitle}
                  onFindingPriorityChange={setFindingPriority}
                  onAssignmentGroupChange={setAssignmentGroup}
                  onOwnershipModeChange={setOwnershipMode}
                  onTicketTargetChange={setTicketTarget}
                  onDueDateChange={setDueDate}
                  onTagsInputChange={setFindingTagsInput}
                  onFindingNotesChange={setFindingNotes}
                  onConfirm={() => void createFindings()}
                />
              ) : null}
            </div>
          )}

          {/* Footer — only for step 1 */}
          {activeStep === 1 && (
            <div className="cve-assessment-footer">
              <div className="cve-assessment-footer-left">
                <button type="button" className="btn btn-secondary" onClick={() => guardedNav(onBack)}>← Vulnerabilities</button>
              </div>
              <div className="cve-assessment-footer-right">
                <button type="button" className="btn btn-primary" onClick={() => void saveInvestigationAndContinue()} disabled={investigationBusy}>
                  {investigationBusy ? 'Saving...' : 'Continue to Applicability'}
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Unsaved-changes navigation guard */}
      <ConfirmDialog
        isOpen={pendingNavAction !== null}
        title="Unsaved Changes"
        message="You have unsaved notes or rationale. Navigating away will discard them. Continue?"
        confirmLabel="Discard & Leave"
        cancelLabel="Stay"
        onConfirm={() => {
          const action = pendingNavAction;
          setPendingNavAction(null);
          action?.();
        }}
        onCancel={() => setPendingNavAction(null)}
      />

      {detail && (
        <InvestigationCanvas
          isOpen={investigationCanvasOpen}
          item={item}
          detail={detail}
          leadAnalyst={leadAnalyst}
          runbookTasks={runbookTasks}
          onRunTask={handleRunbookTask}
          onOpenAssetList={(filter) => {
            const searchParams = new URLSearchParams();
            if (filter?.scope) searchParams.set('scope', filter.scope);
            if (filter?.os) searchParams.set('os', filter.os);
            if (filter?.software) searchParams.set('software', filter.software);
            const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
            navigate(`${pathForVulnRepoCveAssets(item.externalId)}${suffix}`);
          }}
          logEntries={investigationLogEntries}
          newLogType={newInvestigationLogType}
          onNewLogTypeChange={setNewInvestigationLogType}
          newLogMessage={newInvestigationLogMessage}
          onNewLogMessageChange={setNewInvestigationLogMessage}
          onAddLogEntry={handleAddInvestigationLogEntry}
          onClose={() => setInvestigationCanvasOpen(false)}
        />
      )}
    </div>
  );
}
