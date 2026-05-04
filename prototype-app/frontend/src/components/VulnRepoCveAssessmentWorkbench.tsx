import React from 'react';
import { useNavigate } from 'react-router-dom';
import { CveRiskScorePanel } from './CveRiskScorePanel';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';
import { computeCveRiskScore, computeOrgImpact } from '../lib/riskScoring';
import { CVEInvestigationSummary, type InvestigationSummaryInput } from './CVEInvestigationSummary';
import { ConfirmDialog } from './ConfirmDialog';
import { SegmentedControl } from './SegmentedControl';
import { pathForFindingDetail, pathForFindingsWithFilters, pathForInventoryViewWithSearch, pathForVulnRepoCveAssets, pathForVulnRepoCveSoftware, pathForVulnRepoHostAsset } from '../app/routes';
import { cveWorkbenchApi, type AiSolutionData, type AiRequiredAction } from '../features/cve-workbench/api';
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
import type { Finding } from '../features/findings/types';
import type { SoftwareIdentityAsset, SoftwareIdentitySummary } from '../features/software-identities/types';

type WorkflowStep = 1 | 2 | 3 | 4;
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
  onRefreshDetail: (options?: { includeList?: boolean }) => Promise<void>;
};

const _AV_LABELS: Record<string, string> = { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' };
const _PR_LABELS: Record<string, string> = { N: 'None', L: 'Low', H: 'High' };
const _UI_LABELS: Record<string, string> = { N: 'None', R: 'Required' };

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

function ownershipDisplayName(software: CveMatchedSoftware): string {
  return software.ownership?.displayName || 'Unassigned';
}

function ownershipSupportGroup(software: CveMatchedSoftware): string | undefined {
  return software.ownership?.supportGroup ?? software.supportGroup ?? undefined;
}

function ownershipAssignedTo(software: CveMatchedSoftware): string | undefined {
  return software.ownership?.assignedTo ?? undefined;
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

function inferVendorFromIntel(intel: CveDetail['vendorIntelligence'], packageName: string): string | null {
  for (const entry of intel) {
    if (cpeProductMatchesSoftware(entry.cpe, packageName)) {
      const vendor = extractCpeVendor(entry.cpe);
      if (vendor) return vendor;
    }
  }
  return null;
}

const DATA_FEED_SOURCES = new Set(['nvd', 'kev', 'nist']);

function vendorAdvisoryLabel(source: string | undefined, statusToken: string | null, cpeVendor?: string | null): string {
  // Data-feed sources (NVD, KEV) are not vendor advisories — always prefer CPE-derived vendor name.
  const isDataFeed = !source || DATA_FEED_SOURCES.has(source.toLowerCase());
  const effectiveSource = isDataFeed ? (cpeVendor ?? source) : source;
  const vendor = effectiveSource ? vendorDisplayName(effectiveSource) : null;
  if (!statusToken) {
    return vendor ? `${vendor}: n/a` : 'n/a';
  }
  return `${vendor ?? 'Vendor'}: ${formatLabel(statusToken.toLowerCase())}`;
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

function _assessmentStatusTone(item: OrgSpecificCveExposureRecord, latestAssessment: CveApplicabilityAssessment | null): string {
  const label = assessmentStatusLabel(item, latestAssessment).toUpperCase();
  if (label.includes('RESOLVED') || label.includes('NOT AFFECTED')) return 'resolved';
  if (label.includes('UNDER INVESTIGATION')) return 'warning';
  return 'neutral';
}

type ProductSummary = {
  vendor: string;
  product: string;
  vendorName?: string;
  affectedVersions: string;
  cwe: string;
  totalAssetsImpacted: number;
  isEol?: boolean;
  eolDate?: string;
  eolDaysRemaining?: number;
  supportPhase?: string;
  vendorAdvisory?: string;
  supportGroup?: string;
};

/** Extract and title-case the vendor from a CPE 2.3 string: cpe:2.3:a:{vendor}:{product}:... */
function cpeVendorName(cpe?: string | null): string | undefined {
  if (!cpe) return undefined;
  const parts = cpe.split(':');
  // cpe:2.3:type:vendor:product:...  → index 3 is vendor
  const raw = parts[3];
  if (!raw || raw === '*' || raw === '-') return undefined;
  return raw.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const CWE_NAMES: Record<string, string> = {
  'CWE-1': 'Location',
  'CWE-2': 'Environment',
  'CWE-15': 'External Control of System or Configuration Setting',
  'CWE-17': 'Code',
  'CWE-19': 'Data Processing Errors',
  'CWE-20': 'Improper Input Validation',
  'CWE-22': 'Path Traversal',
  'CWE-23': 'Relative Path Traversal',
  'CWE-24': 'Path Traversal: \'../filedir\'',
  'CWE-36': 'Absolute Path Traversal',
  'CWE-59': 'Improper Link Resolution Before File Access',
  'CWE-74': 'Improper Neutralization of Special Elements in Output',
  'CWE-75': 'Failure to Sanitize Special Elements into a Different Plane',
  'CWE-77': 'Command Injection',
  'CWE-78': 'OS Command Injection',
  'CWE-79': 'Cross-site Scripting',
  'CWE-80': 'Basic XSS',
  'CWE-88': 'Argument Injection',
  'CWE-89': 'SQL Injection',
  'CWE-90': 'LDAP Injection',
  'CWE-91': 'XML Injection',
  'CWE-94': 'Code Injection',
  'CWE-95': 'Eval Injection',
  'CWE-96': 'Static Code Injection',
  'CWE-97': 'Server-Side Include (SSI) Injection',
  'CWE-98': 'PHP File Inclusion',
  'CWE-99': 'Resource Injection',
  'CWE-100': 'Technology-Specific Input Validation Problems',
  'CWE-102': 'Struts: Duplicate Validation Forms',
  'CWE-113': 'HTTP Response Splitting',
  'CWE-114': 'Process Control',
  'CWE-116': 'Improper Encoding or Escaping of Output',
  'CWE-119': 'Buffer Overflow',
  'CWE-120': 'Buffer Copy without Checking Size of Input',
  'CWE-121': 'Stack-based Buffer Overflow',
  'CWE-122': 'Heap-based Buffer Overflow',
  'CWE-123': 'Write-what-where Condition',
  'CWE-124': 'Buffer Underwrite',
  'CWE-125': 'Out-of-bounds Read',
  'CWE-126': 'Buffer Over-read',
  'CWE-127': 'Buffer Under-read',
  'CWE-128': 'Wrap-around Error',
  'CWE-129': 'Improper Validation of Array Index',
  'CWE-130': 'Improper Handling of Length Parameter Inconsistency',
  'CWE-131': 'Incorrect Calculation of Buffer Size',
  'CWE-134': 'Uncontrolled Format String',
  'CWE-138': 'Improper Neutralization of Special Elements',
  'CWE-170': 'Improper Null Termination',
  'CWE-172': 'Encoding Error',
  'CWE-174': 'Double Decoding of the Same Data',
  'CWE-176': 'Improper Handling of Unicode Encoding',
  'CWE-178': 'Improper Handling of Case Sensitivity',
  'CWE-179': 'Incorrect Behavior Order: Early Validation',
  'CWE-184': 'Incomplete List of Disallowed Inputs',
  'CWE-185': 'Incorrect Regular Expression',
  'CWE-190': 'Integer Overflow or Wraparound',
  'CWE-191': 'Integer Underflow',
  'CWE-193': 'Off-by-one Error',
  'CWE-194': 'Unexpected Sign Extension',
  'CWE-195': 'Signed to Unsigned Conversion Error',
  'CWE-196': 'Unsigned to Signed Conversion Error',
  'CWE-197': 'Numeric Truncation Error',
  'CWE-200': 'Information Exposure',
  'CWE-201': 'Insertion of Sensitive Information Into Sent Data',
  'CWE-203': 'Observable Discrepancy',
  'CWE-204': 'Observable Response Discrepancy',
  'CWE-209': 'Error Message Information Exposure',
  'CWE-212': 'Improper Removal of Sensitive Information Before Storage',
  'CWE-213': 'Exposure of Sensitive Information Due to Incompatible Policies',
  'CWE-214': 'Invocation of Process Using Visible Sensitive Information',
  'CWE-215': 'Insertion of Sensitive Information Into Debugging Code',
  'CWE-222': 'Truncation of Security-relevant Information',
  'CWE-223': 'Omission of Security-relevant Information',
  'CWE-224': 'Obscured Security-relevant Information by Alternate Name',
  'CWE-228': 'Improper Handling of Syntactically Invalid Structure',
  'CWE-230': 'Improper Handling of Missing Values',
  'CWE-231': 'Improper Handling of Extra Values',
  'CWE-232': 'Improper Handling of Undefined Values',
  'CWE-233': 'Improper Handling of Parameters',
  'CWE-234': 'Failure to Handle Missing Parameter',
  'CWE-235': 'Improper Handling of Extra Parameters',
  'CWE-236': 'Improper Handling of Undefined Parameters',
  'CWE-237': 'Improper Handling of Structural Elements',
  'CWE-238': 'Improper Handling of Incomplete Structural Elements',
  'CWE-239': 'Failure to Handle Incomplete Element',
  'CWE-240': 'Improper Handling of Inconsistent Structural Elements',
  'CWE-241': 'Improper Handling of Unexpected Data Type',
  'CWE-242': 'Use of Inherently Dangerous Function',
  'CWE-243': 'Creation of chroot Jail Without Changing Working Directory',
  'CWE-244': 'Improper Clearing of Heap Memory Before Release',
  'CWE-245': 'J2EE Bad Practices: Direct Management of Connections',
  'CWE-246': 'J2EE Bad Practices: Direct Use of Sockets',
  'CWE-247': 'DEPRECATED: Reliance on DNS Lookups in a Security Decision',
  'CWE-248': 'Uncaught Exception',
  'CWE-250': 'Execution with Unnecessary Privileges',
  'CWE-252': 'Unchecked Return Value',
  'CWE-256': 'Unprotected Storage of Credentials',
  'CWE-257': 'Storing Passwords in a Recoverable Format',
  'CWE-259': 'Use of Hard-coded Password',
  'CWE-261': 'Weak Encoding for Password',
  'CWE-262': 'Not Using Password Aging',
  'CWE-263': 'Password Aging with Long Expiration',
  'CWE-264': 'Permissions, Privileges, and Access Controls',
  'CWE-266': 'Incorrect Privilege Assignment',
  'CWE-267': 'Privilege Defined With Unsafe Actions',
  'CWE-268': 'Privilege Chaining',
  'CWE-269': 'Improper Privilege Management',
  'CWE-270': 'Privilege Context Switching Error',
  'CWE-271': 'Privilege Dropping / Lowering Errors',
  'CWE-272': 'Least Privilege Violation',
  'CWE-273': 'Improper Check for Dropped Privileges',
  'CWE-274': 'Improper Handling of Insufficient Privileges',
  'CWE-276': 'Incorrect Default Permissions',
  'CWE-277': 'Insecure Inherited Permissions',
  'CWE-278': 'Insecure Preserved Inherited Permissions',
  'CWE-279': 'Incorrect Execution-Assigned Permissions',
  'CWE-280': 'Improper Handling of Insufficient Permissions or Privileges',
  'CWE-281': 'Improper Preservation of Permissions',
  'CWE-282': 'Improper Ownership Management',
  'CWE-283': 'Unverified Ownership',
  'CWE-284': 'Improper Access Control',
  'CWE-285': 'Improper Authorization',
  'CWE-286': 'Incorrect User Management',
  'CWE-287': 'Improper Authentication',
  'CWE-288': 'Authentication Bypass Using an Alternate Path or Channel',
  'CWE-289': 'Authentication Bypass by Alternate Name',
  'CWE-290': 'Authentication Bypass by Spoofing',
  'CWE-291': 'Reliance on IP Address for Authentication',
  'CWE-292': 'DEPRECATED: Trusting Self-reported DNS Name',
  'CWE-293': 'Using Referer Field for Authentication',
  'CWE-294': 'Authentication Bypass by Capture-replay',
  'CWE-295': 'Improper Certificate Validation',
  'CWE-296': 'Improper Following of a Certificate\'s Chain of Trust',
  'CWE-297': 'Improper Validation of Certificate with Host Mismatch',
  'CWE-298': 'Improper Validation of Certificate Expiration',
  'CWE-299': 'Improper Check for Certificate Revocation',
  'CWE-300': 'Channel Accessible by Non-Endpoint',
  'CWE-301': 'Reflection Attack in an Authentication Protocol',
  'CWE-302': 'Authentication Bypass by Assumed-Immutable Data',
  'CWE-303': 'Incorrect Implementation of Authentication Algorithm',
  'CWE-304': 'Missing Critical Step in Authentication',
  'CWE-305': 'Authentication Bypass by Primary Weakness',
  'CWE-306': 'Missing Authentication for Critical Function',
  'CWE-307': 'Improper Restriction of Excessive Authentication Attempts',
  'CWE-308': 'Use of Single-factor Authentication',
  'CWE-309': 'Use of Password System for Primary Authentication',
  'CWE-310': 'Cryptographic Issues',
  'CWE-311': 'Missing Encryption of Sensitive Data',
  'CWE-312': 'Cleartext Storage of Sensitive Information',
  'CWE-313': 'Cleartext Storage in a File or on Disk',
  'CWE-314': 'Cleartext Storage in the Registry',
  'CWE-315': 'Cleartext Storage of Sensitive Information in a Cookie',
  'CWE-316': 'Cleartext Storage of Sensitive Information in Memory',
  'CWE-317': 'Cleartext Storage of Sensitive Information in GUI',
  'CWE-318': 'Cleartext Storage of Sensitive Information in Executable',
  'CWE-319': 'Cleartext Transmission of Sensitive Information',
  'CWE-320': 'Key Management Errors',
  'CWE-321': 'Use of Hard-coded Cryptographic Key',
  'CWE-322': 'Key Exchange without Entity Authentication',
  'CWE-323': 'Reusing a Nonce, Key Pair in Encryption',
  'CWE-324': 'Use of a Key Past its Expiration Date',
  'CWE-325': 'Missing Required Cryptographic Step',
  'CWE-326': 'Inadequate Encryption Strength',
  'CWE-327': 'Use of a Broken or Risky Cryptographic Algorithm',
  'CWE-328': 'Use of Weak Hash',
  'CWE-329': 'Generation of Predictable IV with CBC Mode',
  'CWE-330': 'Use of Insufficiently Random Values',
  'CWE-331': 'Insufficient Entropy',
  'CWE-332': 'Insufficient Entropy in PRNG',
  'CWE-333': 'Improper Handling of Insufficient Entropy in TRNG',
  'CWE-334': 'Small Space of Random Values',
  'CWE-335': 'Incorrect Usage of Seeds in Pseudo-Random Number Generator',
  'CWE-336': 'Same Seed in Pseudo-Random Number Generator',
  'CWE-337': 'Predictable Seed in Pseudo-Random Number Generator',
  'CWE-338': 'Use of Cryptographically Weak Pseudo-Random Number Generator',
  'CWE-339': 'Small Seed Space in PRNG',
  'CWE-340': 'Generation of Predictable Numbers or Identifiers',
  'CWE-341': 'Predictable from Observable State',
  'CWE-342': 'Predictable Exact Value from Previous Values',
  'CWE-343': 'Predictable Value Range from Previous Values',
  'CWE-344': 'Use of Invariant Value in Dynamically Changing Context',
  'CWE-345': 'Insufficient Verification of Data Authenticity',
  'CWE-346': 'Origin Validation Error',
  'CWE-347': 'Improper Verification of Cryptographic Signature',
  'CWE-348': 'Use of Less Trusted Source',
  'CWE-349': 'Acceptance of Extraneous Untrusted Data with Trusted Data',
  'CWE-350': 'Reliance on Reverse DNS Resolution for a Security-Critical Action',
  'CWE-351': 'Insufficient Type Distinction',
  'CWE-352': 'Cross-Site Request Forgery',
  'CWE-353': 'Missing Support for Integrity Check',
  'CWE-354': 'Improper Validation of Integrity Check Value',
  'CWE-356': 'Product UI does not Warn User of Unsafe Actions',
  'CWE-357': 'Insufficient UI Warning of Dangerous Operations',
  'CWE-358': 'Improperly Implemented Security Check for Standard',
  'CWE-359': 'Exposure of Private Personal Information to an Unauthorized Actor',
  'CWE-360': 'Trust of System Event Data',
  'CWE-362': 'Race Condition',
  'CWE-363': 'Race Condition Enabling Link Following',
  'CWE-364': 'Signal Handler Race Condition',
  'CWE-365': 'DEPRECATED: Race Condition in Switch',
  'CWE-366': 'Race Condition within a Thread',
  'CWE-367': 'Time-of-check Time-of-use Race Condition',
  'CWE-368': 'Context Switching Race Condition',
  'CWE-369': 'Divide By Zero',
  'CWE-370': 'Missing Check for Certificate Revocation after Initial Check',
  'CWE-371': 'State Issues',
  'CWE-372': 'Incomplete Internal State Distinction',
  'CWE-373': 'DEPRECATED: State Synchronization Error',
  'CWE-374': 'Passing Mutable Objects to an Untrusted Method',
  'CWE-375': 'Returning a Mutable Object to an Untrusted Caller',
  'CWE-377': 'Insecure Temporary File',
  'CWE-378': 'Creation of Temporary File With Insecure Permissions',
  'CWE-379': 'Creation of Temporary File in Directory with Insecure Permissions',
  'CWE-382': 'J2EE Bad Practices: Use of System.exit()',
  'CWE-383': 'J2EE Bad Practices: Direct Use of Threads',
  'CWE-384': 'Session Fixation',
  'CWE-385': 'Covert Timing Channel',
  'CWE-386': 'Symbolic Name not Mapping to Correct Object',
  'CWE-390': 'Detection of Error Condition Without Action',
  'CWE-391': 'Unchecked Error Condition',
  'CWE-392': 'Missing Report of Error Condition',
  'CWE-393': 'Return of Wrong Status Code',
  'CWE-394': 'Unexpected Status Code or Return Value',
  'CWE-395': 'Use of NullPointerException Catch to Detect NULL Pointer Dereference',
  'CWE-396': 'Declaration of Catch for Generic Exception',
  'CWE-397': 'Declaration of Throws for Generic Exception',
  'CWE-400': 'Uncontrolled Resource Consumption',
  'CWE-401': 'Memory Leak',
  'CWE-402': 'Transmission of Private Resources into a New Sphere',
  'CWE-403': 'Exposure of File Descriptor to Unintended Control Sphere',
  'CWE-404': 'Improper Resource Shutdown or Release',
  'CWE-405': 'Asymmetric Resource Consumption (Amplification)',
  'CWE-406': 'Insufficient Control of Network Message Volume (Network Amplification)',
  'CWE-407': 'Inefficient Algorithmic Complexity',
  'CWE-408': 'Incorrect Behavior Order: Early Release of Resource During Expected Availability Period',
  'CWE-409': 'Improper Handling of Highly Compressed Data',
  'CWE-410': 'Insufficient Resource Pool',
  'CWE-412': 'Unrestricted Externally Accessible Lock',
  'CWE-413': 'Improper Resource Locking',
  'CWE-414': 'Missing Lock Check',
  'CWE-415': 'Double Free',
  'CWE-416': 'Use After Free',
  'CWE-417': 'Communication Channel Errors',
  'CWE-419': 'Unprotected Primary Channel',
  'CWE-420': 'Unprotected Alternate Channel',
  'CWE-421': 'Race Condition During Access to Alternate Channel',
  'CWE-422': 'Unprotected Windows Messaging Channel',
  'CWE-423': 'DEPRECATED: Proxied Trusted Channel',
  'CWE-424': 'Improper Protection of Alternate Path',
  'CWE-425': 'Direct Request (Forced Browsing)',
  'CWE-426': 'Untrusted Search Path',
  'CWE-427': 'Uncontrolled Search Path Element',
  'CWE-428': 'Unquoted Search Path or Element',
  'CWE-430': 'Deployment of Wrong Handler',
  'CWE-431': 'Missing Handler',
  'CWE-432': 'Dangerous Signal Handler not Disabled During Sensitive Functions',
  'CWE-433': 'Unparsed Raw Web Content Delivery',
  'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
  'CWE-435': 'Improper Interaction Between Multiple Correctly-Behaving Entities',
  'CWE-436': 'Interpretation Conflict',
  'CWE-437': 'Incomplete Model of Endpoint Features',
  'CWE-439': 'Behavioral Change in New Version or Environment',
  'CWE-440': 'Expected Behavior Violation',
  'CWE-441': 'Unintended Proxy or Intermediary',
  'CWE-444': 'Inconsistent Interpretation of HTTP Requests',
  'CWE-446': 'UI Discrepancy for Security Feature',
  'CWE-447': 'Unimplemented or Unsupported Feature in UI',
  'CWE-448': 'Obsolete Feature in UI',
  'CWE-449': 'The UI Performs the Wrong Action',
  'CWE-450': 'Multiple Interpretations of UI Input',
  'CWE-451': 'User Interface (UI) Misrepresentation of Critical Information',
  'CWE-453': 'Insecure Default Variable Initialization',
  'CWE-454': 'External Initialization of Trusted Variables or Data Stores',
  'CWE-455': 'Non-exit on Failed Initialization',
  'CWE-456': 'Missing Initialization of a Variable',
  'CWE-457': 'Use of Uninitialized Variable',
  'CWE-458': 'DEPRECATED: Incorrect Initialization',
  'CWE-459': 'Incomplete Cleanup',
  'CWE-460': 'Improper Cleanup on Thrown Exception',
  'CWE-462': 'Duplicate Key in Associative List',
  'CWE-463': 'Deletion of Data Structure Sentinel',
  'CWE-464': 'Addition of Data Structure Sentinel',
  'CWE-466': 'Return of Pointer Value Outside of Expected Range',
  'CWE-467': 'Use of sizeof() on a Pointer Type',
  'CWE-468': 'Incorrect Pointer Scaling',
  'CWE-469': 'Use of Pointer Subtraction to Determine Size',
  'CWE-470': 'Use of Externally-Controlled Input to Select Classes or Code',
  'CWE-471': 'Modification of Assumed-Immutable Data (MAID)',
  'CWE-472': 'External Control of Assumed-Immutable Web Parameter',
  'CWE-473': 'PHP External Variable Modification',
  'CWE-474': 'Use of Function with Inconsistent Implementations',
  'CWE-475': 'Undefined Behavior for Input to API',
  'CWE-476': 'NULL Pointer Dereference',
  'CWE-477': 'Use of Obsolete Function',
  'CWE-478': 'Missing Default Case in Multiple Condition Expression',
  'CWE-479': 'Signal Handler Use of a Non-reentrant Function',
  'CWE-480': 'Use of Incorrect Operator',
  'CWE-481': 'Assigning instead of Comparing',
  'CWE-482': 'Comparing instead of Assigning',
  'CWE-483': 'Incorrect Block Delimitation',
  'CWE-484': 'Omitted Break Statement in Switch',
  'CWE-486': 'Comparison of Classes by Name',
  'CWE-487': 'Reliance on Package-level Scope',
  'CWE-488': 'Exposure of Data Element to Wrong Session',
  'CWE-489': 'Active Debug Code',
  'CWE-491': 'Public cloneable() Method Without Final',
  'CWE-492': 'Use of Inner Class Containing Sensitive Data',
  'CWE-493': 'Critical Public Variable Without Final Modifier',
  'CWE-494': 'Download of Code Without Integrity Check',
  'CWE-495': 'Private Data Structure Returned From A Public Method',
  'CWE-496': 'Public Data Assigned to Private Array-Typed Field',
  'CWE-497': 'Exposure of Sensitive System Information to an Unauthorized Control Sphere',
  'CWE-498': 'Cloneable Class Containing Sensitive Information',
  'CWE-499': 'Serializable Class Containing Sensitive Data',
  'CWE-500': 'Public Static Field Not Marked Final',
  'CWE-501': 'Trust Boundary Violation',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-506': 'Embedded Malicious Code',
  'CWE-507': 'Trojan Horse',
  'CWE-508': 'Non-Replicating Malicious Code',
  'CWE-509': 'Replicating Malicious Code (Virus or Worm)',
  'CWE-510': 'Trapdoor',
  'CWE-511': 'Logic/Time Bomb',
  'CWE-512': 'Spyware',
  'CWE-514': 'Covert Channel',
  'CWE-515': 'Covert Storage Channel',
  'CWE-516': 'DEPRECATED: Covert Timing Channel',
  'CWE-520': '.NET Misconfiguration: Use of Impersonation',
  'CWE-521': 'Weak Password Requirements',
  'CWE-522': 'Insufficiently Protected Credentials',
  'CWE-523': 'Unprotected Transport of Credentials',
  'CWE-524': 'Use of Cache Containing Sensitive Information',
  'CWE-525': 'Use of Web Browser Cache Containing Sensitive Information',
  'CWE-526': 'Cleartext Storage of Sensitive Information in an Environment Variable',
  'CWE-527': 'Exposure of Version-Control Repository to an Unauthorized Actor',
  'CWE-528': 'Exposure of Core Dump File to an Unauthorized Actor',
  'CWE-529': 'Exposure of Access Control List Files to an Unauthorized Actor',
  'CWE-530': 'Exposure of Backup File to an Unauthorized Actor',
  'CWE-531': 'Inclusion of Sensitive Information in Test Code',
  'CWE-532': 'Insertion of Sensitive Information into Log File',
  'CWE-533': 'DEPRECATED: Information Exposure Through Server Log Files',
  'CWE-534': 'DEPRECATED: Information Exposure Through Debug Log Files',
  'CWE-535': 'Exposure of Information Through Shell Error Message',
  'CWE-536': 'Servlet Runtime Error Message Containing Sensitive Information',
  'CWE-537': 'Java Runtime Error Message Containing Sensitive Information',
  'CWE-538': 'Insertion of Sensitive Information into Externally-Accessible File or Directory',
  'CWE-539': 'Use of Persistent Cookies Containing Sensitive Information',
  'CWE-540': 'Inclusion of Sensitive Information in Source Code',
  'CWE-541': 'Inclusion of Sensitive Information in an Include File',
  'CWE-542': 'DEPRECATED: Information Exposure Through Cleanup Log Files',
  'CWE-543': 'Use of Singleton Pattern Without Synchronization in a Multithreaded Context',
  'CWE-544': 'Missing Standardized Error Handling Mechanism',
  'CWE-545': 'DEPRECATED: Use of Dynamic Class Loading',
  'CWE-546': 'Suspicious Comment',
  'CWE-547': 'Use of Hard-coded, Security-relevant Constants',
  'CWE-548': 'Exposure of Information Through Directory Listing',
  'CWE-549': 'Missing Password Field Masking',
  'CWE-550': 'Server-generated Error Message Containing Sensitive Information',
  'CWE-551': 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization',
  'CWE-552': 'Files or Directories Accessible to External Parties',
  'CWE-553': 'Command Shell in Externally Accessible Directory',
  'CWE-554': 'ASP.NET Misconfiguration: Not Using Input Validation Framework',
  'CWE-555': 'J2EE Misconfiguration: Plaintext Password in Configuration File',
  'CWE-556': 'ASP.NET Misconfiguration: Use of Identity Impersonation',
  'CWE-558': 'Use of getlogin() in Multithreaded Application',
  'CWE-560': 'Use of umask() with chmod-style Argument',
  'CWE-561': 'Dead Code',
  'CWE-562': 'Return of Stack Variable Address',
  'CWE-563': 'Assignment to Variable without Use',
  'CWE-564': 'SQL Injection: Hibernate',
  'CWE-565': 'Reliance on Cookies without Validation and Integrity Checking',
  'CWE-566': 'Authorization Bypass Through User-Controlled SQL Primary Key',
  'CWE-567': 'Unsynchronized Access to Shared Data in a Multithreaded Context',
  'CWE-568': 'finalize() Method Without super.finalize()',
  'CWE-570': 'Expression is Always False',
  'CWE-571': 'Expression is Always True',
  'CWE-572': 'Call to Thread run() instead of start()',
  'CWE-573': 'Improper Following of Specification by Caller',
  'CWE-574': 'EJB Bad Practices: Use of Synchronization Primitives',
  'CWE-575': 'EJB Bad Practices: Use of AWT Swing',
  'CWE-576': 'EJB Bad Practices: Use of Java I/O',
  'CWE-577': 'EJB Bad Practices: Use of Sockets',
  'CWE-578': 'EJB Bad Practices: Use of Class Loader',
  'CWE-579': 'J2EE Bad Practices: Non-serializable Object Stored in Session',
  'CWE-580': 'clone() Method Without super.clone()',
  'CWE-581': 'Object Model Violation: Just One of Equals and Hashcode Defined',
  'CWE-582': 'Array Declared Public, Final, and Static',
  'CWE-583': 'finalize() Method Declared Public',
  'CWE-584': 'Return Inside Finally Block',
  'CWE-585': 'Empty Synchronized Block',
  'CWE-586': 'Explicit Call to Finalize()',
  'CWE-587': 'Assignment of a Fixed Address to a Pointer',
  'CWE-588': 'Attempt to Access Child of a Non-structure Pointer',
  'CWE-589': 'Call to Non-ubiquitous API',
  'CWE-590': 'Free of Memory not on the Heap',
  'CWE-591': 'Sensitive Data Storage in Improperly Locked Memory',
  'CWE-592': 'DEPRECATED: Authentication Bypass Issues',
  'CWE-593': 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created',
  'CWE-594': 'J2EE Framework: Saving Unserializable Objects to Disk',
  'CWE-595': 'Comparison of Object References Instead of Object Contents',
  'CWE-596': 'DEPRECATED: Incorrect Semantic Object Comparison',
  'CWE-597': 'Use of Wrong Operator in String Comparison',
  'CWE-598': 'Use of GET Request Method with Sensitive Query Strings',
  'CWE-599': 'Missing Validation of OpenSSL Certificate',
  'CWE-600': 'Uncaught Exception in Servlet',
  'CWE-601': 'URL Redirection to Untrusted Site (Open Redirect)',
  'CWE-602': 'Client-Side Enforcement of Server-Side Security',
  'CWE-603': 'Use of Client-Side Authentication',
  'CWE-605': 'Multiple Binds to the Same Port',
  'CWE-606': 'Unchecked Input for Loop Condition',
  'CWE-607': 'Public Static Final Field References Mutable Object',
  'CWE-608': 'Struts: Non-private Field in ActionForm Class',
  'CWE-609': 'Double-Checked Locking',
  'CWE-610': 'Externally Controlled Reference to a Resource in Another Sphere',
  'CWE-611': 'Improper Restriction of XML External Entity Reference',
  'CWE-612': 'Improper Authorization of Index Containing Sensitive Information',
  'CWE-613': 'Insufficient Session Expiration',
  'CWE-614': 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
  'CWE-615': 'Inclusion of Sensitive Information in Source Code Comments',
  'CWE-616': 'Incomplete Identification of Uploaded File Variables in PHP',
  'CWE-617': 'Reachable Assertion',
  'CWE-618': 'Exposed Unsafe ActiveX Method',
  'CWE-619': 'Dangling Database Cursor',
  'CWE-620': 'Unverified Password Change',
  'CWE-621': 'Variable Extraction Error',
  'CWE-622': 'Improper Validation of Function Hook Arguments',
  'CWE-623': 'Unsafe ActiveX Control Marked Safe For Scripting',
  'CWE-624': 'Executable Regular Expression Error',
  'CWE-625': 'Permissive Regular Expression',
  'CWE-626': 'Null Byte Interaction Error (Poison Null Byte)',
  'CWE-627': 'Dynamic Variable Evaluation',
  'CWE-628': 'Function Call with Incorrectly Specified Arguments',
  'CWE-636': 'Not Failing Securely',
  'CWE-637': 'Unnecessary Complexity in Protection Mechanism',
  'CWE-638': 'Not Using Complete Mediation',
  'CWE-639': 'Authorization Bypass Through User-Controlled Key',
  'CWE-640': 'Weak Password Recovery Mechanism for Forgotten Password',
  'CWE-641': 'Improper Restriction of Names for Files and Other Resources',
  'CWE-642': 'External Control of Critical State Data',
  'CWE-643': 'Improper Neutralization of Data within XPath Expressions',
  'CWE-644': 'Improper Neutralization of HTTP Headers for Scripting Syntax',
  'CWE-645': 'Overly Restrictive Account Lockout Mechanism',
  'CWE-646': 'Reliance on File Name or Extension of Externally-Supplied File',
  'CWE-647': 'Use of Non-Canonical URL Paths for Authorization Decisions',
  'CWE-648': 'Incorrect Use of Privileged APIs',
  'CWE-649': 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking',
  'CWE-650': 'Trusting HTTP Permission Methods on the Server Side',
  'CWE-651': 'Exposure of WSDL File Containing Sensitive Information',
  'CWE-652': 'Improper Neutralization of Data within XQuery Expressions',
  'CWE-653': 'Improper Isolation or Compartmentalization',
  'CWE-654': 'Reliance on a Single Factor in a Security Decision',
  'CWE-655': 'Insufficient Psychological Acceptability',
  'CWE-656': 'Reliance on Security Through Obscurity',
  'CWE-657': 'Violation of Secure Design Principles',
  'CWE-662': 'Improper Synchronization',
  'CWE-663': 'Use of a Non-reentrant Function in a Concurrent Context',
  'CWE-664': 'Improper Control of a Resource Through its Lifetime',
  'CWE-665': 'Improper Initialization',
  'CWE-666': 'Operation on Resource in Wrong Phase of Lifetime',
  'CWE-667': 'Improper Locking',
  'CWE-668': 'Exposure of Resource to Wrong Sphere',
  'CWE-669': 'Incorrect Resource Transfer Between Spheres',
  'CWE-670': 'Always-Incorrect Control Flow Implementation',
  'CWE-671': 'Lack of Administrator Control over Security',
  'CWE-672': 'Operation on a Resource after Expiration or Release',
  'CWE-673': 'External Influence of Sphere Definition',
  'CWE-674': 'Uncontrolled Recursion',
  'CWE-675': 'Multiple Operations on Resource in Single-Operation Context',
  'CWE-676': 'Use of Potentially Dangerous Function',
  'CWE-680': 'Integer Overflow to Buffer Overflow',
  'CWE-681': 'Incorrect Conversion between Numeric Types',
  'CWE-682': 'Incorrect Calculation',
  'CWE-683': 'Function Call With Incorrect Order of Arguments',
  'CWE-684': 'Incorrect Provision of Specified Functionality',
  'CWE-685': 'Function Call With Incorrect Number of Arguments',
  'CWE-686': 'Function Call With Incorrect Argument Type',
  'CWE-687': 'Function Call With Incorrectly Specified Argument Value',
  'CWE-688': 'Function Call With Incorrect Variable or Reference as Argument',
  'CWE-689': 'Permission Race Condition During Resource Copy',
  'CWE-690': 'Unchecked Return Value to NULL Pointer Dereference',
  'CWE-691': 'Insufficient Control Flow Management',
  'CWE-692': 'Incomplete Denylist to Cross-Site Scripting',
  'CWE-693': 'Protection Mechanism Failure',
  'CWE-694': 'Use of Multiple Resources with Duplicate Identifier',
  'CWE-695': 'Use of Low-Level Functionality',
  'CWE-696': 'Incorrect Behavior Order',
  'CWE-697': 'Incorrect Comparison',
  'CWE-698': 'Execution After Redirect',
  'CWE-703': 'Improper Check or Handling of Exceptional Conditions',
  'CWE-704': 'Incorrect Type Conversion or Cast',
  'CWE-705': 'Incorrect Control Flow Scoping',
  'CWE-706': 'Use of Incorrectly-Resolved Name or Reference',
  'CWE-707': 'Improper Neutralization',
  'CWE-708': 'Incorrect Ownership Assignment',
  'CWE-710': 'Improper Adherence to Coding Standards',
  'CWE-732': 'Incorrect Permission Assignment for Critical Resource',
  'CWE-733': 'Compiler Optimization Removal or Modification of Security-critical Code',
  'CWE-749': 'Exposed Dangerous Method or Function',
  'CWE-754': 'Improper Check for Unusual or Exceptional Conditions',
  'CWE-755': 'Improper Handling of Exceptional Conditions',
  'CWE-756': 'Missing Custom Error Page',
  'CWE-757': 'Selection of Less-Secure Algorithm During Negotiation',
  'CWE-758': 'Reliance on Undefined, Unspecified, or Implementation-Defined Behavior',
  'CWE-759': 'Use of a One-Way Hash without a Salt',
  'CWE-760': 'Use of a One-Way Hash with a Predictable Salt',
  'CWE-761': 'Free of Pointer not at Start of Buffer',
  'CWE-762': 'Mismatched Memory Management Routines',
  'CWE-763': 'Release of Invalid Pointer or Reference',
  'CWE-764': 'Multiple Locks of a Critical Resource',
  'CWE-765': 'Multiple Unlocks of a Critical Resource',
  'CWE-766': 'Critical Data Element Declared Public',
  'CWE-767': 'Access to Critical Private Variable via Public Method',
  'CWE-768': 'Incorrect Short Circuit Evaluation',
  'CWE-769': 'DEPRECATED: Uncontrolled File Descriptor Consumption',
  'CWE-770': 'Allocation of Resources Without Limits or Throttling',
  'CWE-771': 'Missing Reference to Active Allocated Resource',
  'CWE-772': 'Missing Release of Resource after Effective Lifetime',
  'CWE-773': 'Missing Reference to Active File Descriptor or Handle',
  'CWE-774': 'Allocation of File Descriptors or Handles Without Limits or Throttling',
  'CWE-775': 'Missing Release of File Descriptor or Handle after Effective Lifetime',
  'CWE-776': 'Improper Restriction of Recursive Entity References in DTDs',
  'CWE-777': 'Regular Expression without Anchors',
  'CWE-778': 'Insufficient Logging',
  'CWE-779': 'Logging of Excessive Data',
  'CWE-780': 'Use of RSA Algorithm without OAEP',
  'CWE-781': 'Improper Address Validation in OGNL Expressions',
  'CWE-782': 'Exposed IOCTL with Insufficient Access Control',
  'CWE-783': 'Operator Precedence Logic Error',
  'CWE-784': 'Reliance on Cookies without Validation and Integrity Checking in a Security Decision',
  'CWE-785': 'Use of Path Manipulation Function without Maximum-sized Buffer',
  'CWE-786': 'Access of Memory Location Before Start of Buffer',
  'CWE-787': 'Out-of-bounds Write',
  'CWE-788': 'Access of Memory Location After End of Buffer',
  'CWE-789': 'Memory Allocation with Excessive Size Value',
  'CWE-790': 'Improper Filtering of Special Elements',
  'CWE-791': 'Incomplete Filtering of Special Elements',
  'CWE-792': 'Incomplete Filtering of One or More Instances of Special Elements',
  'CWE-793': 'Only Filtering One Instance of a Special Element',
  'CWE-794': 'Incomplete Filtering of Multiple Instances of Special Elements',
  'CWE-795': 'Only Filtering Special Elements at a Specified Location',
  'CWE-796': 'Only Filtering Special Elements Relative to a Marker',
  'CWE-797': 'Only Filtering Special Elements at an Absolute Position',
  'CWE-798': 'Use of Hard-coded Credentials',
  'CWE-799': 'Improper Control of Interaction Frequency',
  'CWE-804': 'Guessable CAPTCHA',
  'CWE-805': 'Buffer Access with Incorrect Length Value',
  'CWE-806': 'Buffer Access Using Size of Source Buffer',
  'CWE-807': 'Reliance on Untrusted Inputs in a Security Decision',
  'CWE-820': 'Missing Synchronization',
  'CWE-821': 'Incorrect Synchronization',
  'CWE-822': 'Untrusted Pointer Dereference',
  'CWE-823': 'Use of Out-of-range Pointer Offset',
  'CWE-824': 'Access of Uninitialized Pointer',
  'CWE-825': 'Expired Pointer Dereference',
  'CWE-826': 'Premature Release of Resource During Expected Lifetime',
  'CWE-827': 'Improper Control of Document Type Definition',
  'CWE-828': 'Signal Handler with Functionality that is not Asynchronous-Signal-Safe',
  'CWE-829': 'Inclusion of Functionality from Untrusted Control Sphere',
  'CWE-830': 'Inclusion of Web Functionality from an Untrusted Source',
  'CWE-831': 'Signal Handler Function Associated with Multiple Signals',
  'CWE-832': 'Unlock of a Resource that is not Locked',
  'CWE-833': 'Deadlock',
  'CWE-834': 'Excessive Iteration',
  'CWE-835': 'Loop with Unreachable Exit Condition (Infinite Loop)',
  'CWE-836': 'Use of Password Hash Instead of Password for Authentication',
  'CWE-837': 'Improper Enforcement of a Single, Unique Action',
  'CWE-838': 'Inappropriate Encoding for Output Context',
  'CWE-839': 'Numeric Range Comparison Without Minimum Check',
  'CWE-841': 'Improper Enforcement of Behavioral Workflow',
  'CWE-842': 'Placement of User into Incorrect Group',
  'CWE-843': 'Access of Resource Using Incompatible Type (Type Confusion)',
  'CWE-862': 'Missing Authorization',
  'CWE-863': 'Incorrect Authorization',
  'CWE-908': 'Use of Uninitialized Resource',
  'CWE-909': 'Missing Initialization of Resource',
  'CWE-910': 'Use of Expired File Descriptor',
  'CWE-911': 'Improper Update of Reference Count',
  'CWE-912': 'Hidden Functionality',
  'CWE-913': 'Improper Control of Dynamically-Managed Code Resources',
  'CWE-914': 'Improper Control of Dynamically-Identified Variables',
  'CWE-915': 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
  'CWE-916': 'Use of Password Hash With Insufficient Computational Effort',
  'CWE-917': 'Improper Neutralization of Special Elements used in an Expression Language Statement',
  'CWE-918': 'Server-Side Request Forgery (SSRF)',
  'CWE-920': 'Improper Restriction of Power Consumption',
  'CWE-921': 'Storage of Sensitive Data in a Mechanism without Access Control',
  'CWE-922': 'Insecure Storage of Sensitive Information',
  'CWE-923': 'Improper Restriction of Communication Channel to Intended Endpoints',
  'CWE-924': 'Improper Enforcement of Message Integrity During Transmission',
  'CWE-925': 'Improper Verification of Intent by Broadcast Receiver',
  'CWE-926': 'Improper Export of Android Application Components',
  'CWE-927': 'Use of Implicit Intent for Sensitive Communication',
  'CWE-939': 'Improper Authorization in Handler for Custom URL Scheme',
  'CWE-940': 'Improper Verification of Source of a Communication Channel',
  'CWE-941': 'Incorrectly Specified Destination in a Communication Channel',
  'CWE-942': 'Permissive Cross-domain Policy with Untrusted Domains',
  'CWE-943': 'Improper Neutralization of Special Elements in Data Query Logic',
  'CWE-1004': 'Sensitive Cookie Without HttpOnly Flag',
  'CWE-1021': 'Improper Restriction of Rendered UI Layers or Frames',
  'CWE-1022': 'Use of Web Link to Untrusted Target with window.opener Access',
  'CWE-1035': 'OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities',
  'CWE-1174': 'ASP.NET Misconfiguration: Improper Model Validation',
  'CWE-1188': 'Initialization of a Resource with an Insecure Default',
  'CWE-1236': 'Improper Neutralization of Formula Elements in a CSV File',
  'CWE-1275': 'Sensitive Cookie with Improper SameSite Attribute',
  'CWE-1284': 'Improper Validation of Specified Quantity in Input',
  'CWE-1285': 'Improper Validation of Specified Index, Position, or Offset in Input',
  'CWE-1286': 'Improper Validation of Syntactic Correctness of Input',
  'CWE-1287': 'Improper Validation of Specified Type of Input',
  'CWE-1288': 'Improper Validation of Consistency within Input',
  'CWE-1289': 'Improper Validation of Unsafe Equivalence in Input',
  'CWE-1290': 'Incorrect Decoding of Security Identifiers',
  'CWE-1291': 'Public Key Re-Use for Signing both Debug and Production Code',
  'CWE-1292': 'Incorrect Conversion of Security Identifiers',
  'CWE-1293': 'Missing Source Correlation of Multiple Independent Data',
  'CWE-1294': 'Insecure Security Identifier Mechanism',
  'CWE-1295': 'Debug Messages Revealing Unnecessary Information',
  'CWE-1296': 'Incorrect Chaining or Granularity of Debug Components',
  'CWE-1297': 'Unprotected Confidential Information on Device is Accessible to JTAG',
  'CWE-1298': 'Hardware Logic Contains Race Conditions',
  'CWE-1299': 'Missing Protection Mechanism for Alternate Hardware Interface',
  'CWE-1300': 'Improper Protection of Physical Side Channels',
  'CWE-1301': 'Insufficient or Incomplete Data Removal within Hardware Component',
  'CWE-1302': 'Missing Security Identifier',
  'CWE-1303': 'Non-Transparent Sharing of Microarchitectural Resources',
  'CWE-1304': 'Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation',
  'CWE-1310': 'Missing Ability to Patch ROM Code',
  'CWE-1311': 'Improper Translation of Security Attributes by Fabric Bridge',
  'CWE-1312': 'Missing Protection for Mirrored Regions in On-Chip Fabric Firewall',
  'CWE-1313': 'Hardware Allows Activation of Test or Debug Logic at Runtime',
  'CWE-1314': 'Missing Write Protection for Parametric Data Values',
  'CWE-1315': 'Improper Setting of Bus Controlling Capability in Fabric End-point',
  'CWE-1316': 'Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges',
  'CWE-1317': 'Improper Access Control in Fabric Bridge',
  'CWE-1318': 'Missing Support for Security Features in On-chip Fabrics or Buses',
  'CWE-1319': 'Improper Protection against Electromagnetic Fault Injection',
  'CWE-1320': 'Improper Protection for Outbound Error Messages and Alert Signals',
  'CWE-1321': 'Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)',
  'CWE-1322': 'Use of Blocking Code in Single-threaded, Non-blocking Context',
  'CWE-1323': 'Improper Management of Sensitive Trace Data',
  'CWE-1324': 'DEPRECATED: Sensitive Information Accessible by Physical Probing of JTAG Interface',
  'CWE-1325': 'Improperly Controlled Sequential Memory Allocation',
  'CWE-1326': 'Missing Immutable Root of Trust in Hardware',
  'CWE-1327': 'Binding to an Unrestricted IP Address',
  'CWE-1333': 'Inefficient Regular Expression Complexity',
  'CWE-1336': 'Improper Neutralization of Special Elements Used in a Template Engine',
  'CWE-1338': 'Improper Protections Against Hardware Overheating',
  'CWE-1339': 'Insufficient Precision or Accuracy of a Real Number',
  'CWE-1341': 'Multiple Releases of Same Resource or Handle',
  'CWE-1342': 'Information Exposure through Microarchitectural State after Transient Execution',
  'CWE-1351': 'Improper Handling of Hardware Behavior in Exceptionally Cold Environments',
  'CWE-1357': 'Reliance on Insufficiently Trustworthy Component',
  'CWE-1384': 'Improper Handling of Physical or Environmental Conditions',
  'CWE-1385': 'Missing Origin Validation in WebSockets',
  'CWE-1386': 'Insecure Operation on Windows Junction / Mount Point',
  'CWE-1387': 'Reachable Non-exit Payload',
  'CWE-1389': 'Incorrect Parsing of Numbers with Different Radices',
  'CWE-1390': 'Weak Authentication',
  'CWE-1392': 'Use of Default Credentials',
  'CWE-1393': 'Use of Default Password',
  'CWE-1394': 'Use of Default Cryptographic Key',
  'CWE-1395': 'Dependency on Vulnerable Third-Party Component',
};

function buildAffectedProducts(detail: CveDetail, softwareGroups: SoftwareGroup[]): ProductSummary[] {
  const products = new Map<string, ProductSummary>();

  for (const intel of detail.vendorIntelligence ?? []) {
    const product = intel.packageName?.trim();
    if (!product) continue;
    const vendor = intel.source?.trim() || 'Vendor Advisory';
    const group = softwareGroups.find((entry) => entry.software.packageName === product);
    const key = `${vendor}|${product}`;
    const sw = group?.software;
    products.set(key, {
      vendor,
      product,
      vendorName: cpeVendorName(intel.cpe),
      affectedVersions: intel.affectedVersions || intel.fixedVersion || 'See advisory',
      cwe: detail.summary.cweIds || '-',
      totalAssetsImpacted: group?.assets.length ?? 0,
      isEol: sw?.isEol,
      eolDate: sw?.eolDate,
      eolDaysRemaining: sw?.eolDaysRemaining,
      supportPhase: sw?.supportPhase,
      vendorAdvisory: intel.vexStatus ?? undefined,
      supportGroup: sw ? ownershipSupportGroup(sw) : undefined,
    });
  }

  if (products.size === 0) {
    for (const group of softwareGroups) {
      const key = `${group.software.ecosystem}|${group.software.packageName}`;
      const sw = group.software;
      products.set(key, {
        vendor: group.software.ecosystem || 'Inventory',
        product: group.software.packageName,
        affectedVersions: group.software.version || 'Detected in inventory',
        cwe: detail.summary.cweIds || '-',
        totalAssetsImpacted: group.assets.length,
        isEol: sw.isEol,
        eolDate: sw.eolDate,
        eolDaysRemaining: sw.eolDaysRemaining,
        supportPhase: sw.supportPhase,
        vendorAdvisory: sw.vexStatus ?? undefined,
        supportGroup: ownershipSupportGroup(sw),
      });
    }
  }

  // Sort by assets impacted descending
  return Array.from(products.values()).sort((a, b) => b.totalAssetsImpacted - a.totalAssetsImpacted);
}

function buildReferenceLinks(detail: CveDetail): Array<{ href: string; source?: string; tags?: string[] }> {
  const seen = new Set<string>();
  const out: Array<{ href: string; source?: string; tags?: string[] }> = [];

  // NVD-sourced references with source + tags
  if (detail.references && detail.references.length > 0) {
    for (const ref of detail.references) {
      if (!seen.has(ref.url)) {
        seen.add(ref.url);
        out.push({ href: ref.url, source: ref.source, tags: ref.tags });
      }
    }
  }

  // Fallback: sourceUrl advisory link if not already listed
  if (detail.summary.sourceUrl && !seen.has(detail.summary.sourceUrl)) {
    out.push({ href: detail.summary.sourceUrl, source: detail.summary.source ?? undefined });
  }

  // Always include NVD entry link
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(detail.summary.externalId)}`;
  if (!seen.has(nvdUrl)) {
    out.push({ href: nvdUrl, source: 'NVD', tags: ['Advisory'] });
  }

  return out;
}

function _HeroMetric({
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
  /** Total asset count from the last investigation assessment run (persisted for exposure display) */
  investigationAssetCount?: number;
  /** Unique software count from the last investigation assessment run */
  investigationSoftwareCount?: number;
  /** Per-software breakdown from the investigation assessment (for Affected Entities tab) */
  investigationSoftwareSummary?: Array<{
    software: string;
    vendor?: string;
    version?: string;
    assetCount: number;
  }>;
  falsePositiveResults?: FalsePositiveResult[];
  falsePositiveRan?: boolean;
  analystFpOverrides?: string[];
  analystFpEvidence?: Record<string, string>;
  eolCriteria?: EolAnalysisCriterion[];
  eolResults?: EolAnalysisResult[];
  eolAssessed?: boolean;
  solutionEntries?: Record<string, string>;
  /** ISO timestamp of when groups were notified for this CVE */
  notifiedAt?: string;
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

function safeLocalStorageSet(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch (e) {
    if (e instanceof DOMException && e.name === 'QuotaExceededError') {
      // Evict oldest vulnrepo entries to free space, then retry once
      try {
        const vulnKeys: string[] = [];
        for (let i = 0; i < window.localStorage.length; i++) {
          const k = window.localStorage.key(i);
          if (k?.startsWith('vulnrepo:')) vulnKeys.push(k);
        }
        // Remove half of them (oldest by key name sort)
        vulnKeys.sort().slice(0, Math.ceil(vulnKeys.length / 2)).forEach((k) => window.localStorage.removeItem(k));
        window.localStorage.setItem(key, value);
      } catch {
        // Give up silently — state won't persist but the app keeps running
      }
    }
  }
}

function persistInvestigationRunbookState(
  cveId: string,
  payload: PersistedInvestigationRunbookState
): void {
  if (typeof window === 'undefined') return;
  safeLocalStorageSet(investigationRunbookStorageKey(cveId), JSON.stringify(payload));
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
      vendor: (() => {
        const cpeVendor = inferVendorFromIntel(detail.vendorIntelligence, software.packageName);
        if (cpeVendor) return vendorDisplayName(cpeVendor);
        if (software.vexSource && !DATA_FEED_SOURCES.has(software.vexSource.toLowerCase())) return software.vexSource;
        if (software.ecosystem) return software.ecosystem;
        return '';
      })(),
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
  safeLocalStorageSet(assetCriteriaStorageKey(cveId), JSON.stringify(payload));
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

/**
 * Builds a basic remediation message from NVD/KEV signals when CSAF and OpenAI are both unavailable.
 */
function buildSignalsFallback(
  row: { software: string; version: string; vendor: string },
  detail: CveDetail
): string {
  const cveId = detail.summary.externalId;
  const parts: string[] = [];

  if (detail.signals.patchAvailable && detail.signals.patchVersions) {
    parts.push(`[Patch] Upgrade ${row.software} from version ${row.version} to ${detail.signals.patchVersions} or later.`);
    parts.push(`Source: NVD patch data for ${cveId}.`);
  } else if (detail.signals.patchAvailable) {
    parts.push(`[Patch] A patch is available for ${cveId}. Upgrade ${row.software} to the latest vendor-released version.`);
  } else {
    parts.push(`No patch is currently available for ${cveId} affecting ${row.software} ${row.version}.`);
  }

  if (detail.summary.inKev) {
    parts.push('This CVE is listed in the CISA Known Exploited Vulnerabilities catalog — remediate with highest priority.');
  }

  if (!detail.signals.patchAvailable) {
    parts.push('Compensating control: Isolate affected systems from untrusted networks and monitor vendor advisories for an upcoming patch.');
  }

  return parts.join('\n');
}

/**
 * Derives a remediation solution text from vendor CSAF/VEX intelligence entries.
 * Returns null when no matching vendor advisory is found (data-feed sources like NVD are excluded).
 */
function buildCsafSolutionText(
  software: string,
  intel: CveDetail['vendorIntelligence']
): string | null {
  const vendorEntries = intel.filter((entry) => {
    const src = (entry.source ?? '').toLowerCase();
    return src.length > 0 && !DATA_FEED_SOURCES.has(src);
  });

  const matching = vendorEntries.filter((entry) => {
    if (!entry.packageName) return true; // no package filter — advisory applies to this CVE broadly
    return assetInventoryFieldMatches(entry.packageName, software)
      || assetInventoryFieldMatches(software, entry.packageName);
  });

  if (matching.length === 0) return null;

  const withFix = matching.find((e) => e.fixedVersion);
  const best = withFix ?? matching[0];
  const sourceName = vendorDisplayName(best.source);
  const statusLow = (best.vexStatus ?? '').toLowerCase();

  if (statusLow.includes('not_affected') || statusLow.includes('not affected')) {
    return `${sourceName} advisory (CSAF/VEX) confirms this software version is not affected by this CVE. No remediation action required.`;
  }
  if (best.fixedVersion) {
    const lines = [
      `[Patch] Upgrade to version ${best.fixedVersion} or later.`,
      '',
      `Source: ${sourceName} Security Advisory (CSAF/VEX). The vendor has confirmed a fix in version ${best.fixedVersion}.`,
    ];
    if (best.affectedVersions) lines.push(`Affected versions: ${best.affectedVersions}.`);
    return lines.filter((l, i, a) => l !== '' || (i > 0 && a[i - 1] !== '')).join('\n');
  }
  if (statusLow.includes('workaround')) {
    return `[Workaround] Apply vendor-recommended workaround per ${sourceName} advisory. See vendor security portal for detailed mitigation steps.`;
  }
  if (statusLow.includes('fix') || statusLow.includes('patch')) {
    return `[Patch] Vendor patch available. Refer to ${sourceName} security advisory for upgrade instructions.`;
  }
  return null;
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
    const cpeVendor = extractCpeVendor(vendorDecision?.cpe) ?? inferVendorFromIntel(intel, software.packageName);

    rows.set(key, {
      id: key,
      software: software.packageName,
      version,
      falsePositive: status.falsePositive,
      notImpactedAssetCount: status.falsePositive ? assetKeys.size : 0,
      vendorAdvisory: vendorAdvisoryLabel(vendorDecision?.source, statusToken, cpeVendor),
      vendorGuidance: vendorGuidanceMessage(
        vendorDecision?.source,
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
    const cpeVendor = extractCpeVendor(vendorDecision?.cpe) ?? inferVendorFromIntel(intel, software.software);
    rows.set(key, {
      id: key,
      software: software.software,
      version: software.version,
      falsePositive: status.falsePositive,
      notImpactedAssetCount: status.falsePositive ? software.assets.length : 0,
      vendorAdvisory: vendorAdvisoryLabel(vendorDecision?.source, statusToken, cpeVendor),
      vendorGuidance: vendorGuidanceMessage(
        vendorDecision?.source,
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
      vendor: (() => {
        const cpeVendor = inferVendorFromIntel(detail.vendorIntelligence, software.packageName);
        if (cpeVendor) return vendorDisplayName(cpeVendor);
        if (software.vexSource && !DATA_FEED_SOURCES.has(software.vexSource.toLowerCase())) return software.vexSource;
        if (vendorIntel?.source && !DATA_FEED_SOURCES.has(vendorIntel.source.toLowerCase())) return vendorIntel.source;
        if (software.ecosystem) return software.ecosystem;
        return 'Inventory';
      })(),
      version,
      lifecycle,
      endOfSupport: software.eolSupportEndDate ?? '—',
      endOfLife: software.eolDate ?? '—',
      recommendedUpgrade: vendorIntel?.fixedVersion ?? software.eolCycle ?? 'Upgrade to the latest supported release',
    });
  });

  resolvedInventory.forEach((software) => {
    const matchesCriterion = effectiveCriteria.some((criterion) => {
      // Bidirectional package match: handles cases where the criterion is a compound name like
      // 'citrix_systems/xendesktop' but the resolved software is just 'xendesktop'.
      const packageMatches = assetInventoryFieldMatches(software.software, criterion.software)
        || assetInventoryFieldMatches(criterion.software, software.software);
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

  // Fallback: criteria that were not matched by either matchedSoftware or resolvedInventory
  // (manually-added entries) still appear with whatever data the analyst entered.
  // Skip if any existing row already covers the criterion via bidirectional name matching —
  // e.g. don't add 'citrix_systems/xendesktop' when 'xendesktop 2.1' and 'xendesktop 4' exist.
  effectiveCriteria.forEach((criterion) => {
    const key = `${criterion.software}::${criterion.version}`;
    if (rows.has(key)) return;
    const alreadyCovered = Array.from(rows.keys()).some((existingKey) => {
      const existingSoftware = existingKey.split('::')[0];
      return assetInventoryFieldMatches(existingSoftware, criterion.software)
        || assetInventoryFieldMatches(criterion.software, existingSoftware);
    });
    if (alreadyCovered) return;
    rows.set(key, {
      id: key,
      software: criterion.software,
      vendor: criterion.vendor || '—',
      version: criterion.version || '—',
      lifecycle: 'Unknown',
      endOfSupport: '—',
      endOfLife: '—',
      recommendedUpgrade: '—',
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
  onOpenFindingsStep,
  logEntries,
  newLogType,
  onNewLogTypeChange,
  newLogMessage,
  onNewLogMessageChange,
  onAddLogEntry,
  onClose,
  onSaveDraft: _onSaveDraft,
  createdFindings = [],
}: {
  isOpen: boolean;
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail;
  leadAnalyst: string;
  runbookTasks: RunbookTask[];
  onRunTask: (taskId: string) => void;
  onOpenAssetList: (filter?: { scope?: 'external-facing' | 'critical'; os?: string; software?: string }) => void;
  onOpenFindingsStep: (filter?: { scope?: 'external-facing' | 'critical' | 'all'; software?: string; os?: string; openConfig?: boolean }) => void;
  logEntries: InvestigationLogEntry[];
  newLogType: InvestigationLogType;
  onNewLogTypeChange: (value: InvestigationLogType) => void;
  newLogMessage: string;
  onNewLogMessageChange: (value: string) => void;
  onAddLogEntry: () => void;
  onClose: () => void;
  onSaveDraft: () => void;
  createdFindings?: InvestigationSummaryInput['createdFindings'];
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
  // tracks which manual-row fields are in free-text mode: key = `${criterionId}:vendor|software|version`
  const [manualTextMode, setManualTextMode] = React.useState<Set<string>>(new Set());
  // software inventory for cascading dropdowns
  const [inventoryIdentities, setInventoryIdentities] = React.useState<SoftwareIdentitySummary[]>([]);
  // criterionId → selected softwareIdentityId (for version lookup)
  const [criterionIdentityMap, setCriterionIdentityMap] = React.useState<Record<string, string>>({});
  // identityId → list of versions (lazy-loaded cache)
  const [versionCache, setVersionCache] = React.useState<Record<string, string[]>>({});
  const [assetResults, setAssetResults] = React.useState<AssetInventoryResult[]>(initialResults);
  const [_assetResultsExpanded, setAssetResultsExpanded] = React.useState(initialResults.length > 0);
  const [assetAssessmentRan, setAssetAssessmentRan] = React.useState(
    persistedRunbookState?.assetAssessmentRan ?? initialResults.length > 0
  );
  // eolCriteria is always derived from the current assetCriteria so EOL step stays in sync
  // when the user adds/removes software in Step 1.
  const eolCriteria = React.useMemo(
    () => buildEolCriteria(detail, assetCriteria),
    [detail, assetCriteria]
  );
  const initialEolResults = React.useMemo(
    () => persistedRunbookState?.eolResults
      ?? (eolTask?.state === 'DONE' ? buildEolAnalysisResults(detail, eolCriteria, initialResolvedInventory) : []),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [detail, eolTask?.state, initialResolvedInventory, persistedRunbookState]
  );
  const [eolResults, setEolResults] = React.useState<EolAnalysisResult[]>(initialEolResults);
  const [_eolExpanded, setEolExpanded] = React.useState(
    (persistedRunbookState?.eolAssessed ?? false) || eolTask?.state === 'DONE'
  );
  const [eolAssessed, setEolAssessed] = React.useState(
    persistedRunbookState?.eolAssessed ?? eolTask?.state === 'DONE'
  );
  const [eolAssessing, setEolAssessing] = React.useState(false);
  const [falsePositiveResults, setFalsePositiveResults] = React.useState<FalsePositiveResult[]>(initialFalsePositiveResults);
  const [analystFpOverrides, setAnalystFpOverrides] = React.useState<Set<string>>(
    new Set(persistedRunbookState?.analystFpOverrides ?? [])
  );
  const [analystFpEvidence, setAnalystFpEvidence] = React.useState<Record<string, string>>(
    persistedRunbookState?.analystFpEvidence ?? {}
  );
  const [falsePositiveResultsExpanded, setFalsePositiveResultsExpanded] = React.useState(
    (persistedRunbookState?.falsePositiveRan ?? false) || falsePositiveTask?.state === 'DONE'
  );
  const [falsePositiveRan, setFalsePositiveRan] = React.useState(
    persistedRunbookState?.falsePositiveRan ?? falsePositiveTask?.state === 'DONE'
  );
  const [resolvedInventory, setResolvedInventory] = React.useState<ResolvedInventorySoftware[]>(initialResolvedInventory);
  const [summaryVisible, setSummaryVisible] = React.useState(false);
  const [selectedTaskId, setSelectedTaskId] = React.useState<string | null>('review-asset-inventory');
  const [, setSavedAt] = React.useState<Date | null>(null);
  const [solutionEntries, setSolutionEntries] = React.useState<Record<string, string>>(
    persistedRunbookState?.solutionEntries ?? {}
  );
  const [solutionGeneratingKeys, setSolutionGeneratingKeys] = React.useState<Set<string>>(new Set());

  // Stable list of (software, version) rows for the Solutions step — derived from matched assets.
  const solutionRows = React.useMemo(() => {
    const seen = new Map<string, { software: string; version: string; vendor: string; count: number }>();
    assetResults.forEach((asset) => {
      asset.matchedSoftware.forEach((ms) => {
        const key = `${ms.software}@${ms.version}`;
        if (!seen.has(key)) {
          const resolved = resolvedInventory.find((r) =>
            assetInventoryFieldMatches(r.software, ms.software) || assetInventoryFieldMatches(ms.software, r.software)
          );
          const crit = assetCriteria.find((c) =>
            assetInventoryFieldMatches(c.software, ms.software) || assetInventoryFieldMatches(ms.software, c.software)
          );
          const vendor = resolved?.vendor || crit?.vendor || (() => {
            const v = inferVendorFromIntel(detail.vendorIntelligence, ms.software);
            return v ? vendorDisplayName(v) : '';
          })();
          seen.set(key, { software: ms.software, version: ms.version, vendor, count: 0 });
        }
        seen.get(key)!.count += 1;
      });
    });
    if (seen.size > 0) {
      return Array.from(seen.values()).sort((a, b) => b.count - a.count || a.software.localeCompare(b.software));
    }
    return assetCriteria.map((c) => ({ software: c.software, version: c.version, vendor: c.vendor, count: 0 }));
  }, [assetResults, resolvedInventory, assetCriteria, detail.vendorIntelligence]);

  const flushRunbookState = React.useCallback(() => {
    // Persist counts so the outer exposure panel can reflect investigation results.
    const investigationSoftwareCount = new Set(
      assetResults.flatMap((a) => a.matchedSoftware.map((ms) => ms.software.toLowerCase()))
    ).size;
    // Build per-software/version breakdown directly from assetResults (mirrors the "Assets Matched by Software" table)
    const swVersionCounts = new Map<string, { software: string; version: string; vendor?: string; assetCount: number }>();
    assetResults.forEach((asset) => {
      asset.matchedSoftware.forEach((ms) => {
        const key = `${normalizeAssetInventoryValue(ms.software)}::${normalizeAssetInventoryValue(ms.version)}`;
        const entry = swVersionCounts.get(key);
        if (entry) {
          entry.assetCount++;
        } else {
          // Look up vendor from assetCriteria by matching software name
          const criterion = assetCriteria.find((c) =>
            normalizeAssetInventoryValue(c.software) === normalizeAssetInventoryValue(ms.software) ||
            normalizeAssetInventoryValue(ms.software).includes(normalizeAssetInventoryValue(c.software))
          );
          swVersionCounts.set(key, {
            software: ms.software,
            version: ms.version,
            vendor: criterion?.vendor?.trim() || undefined,
            assetCount: 1,
          });
        }
      });
    });
    const investigationSoftwareSummary = Array.from(swVersionCounts.values())
      .sort((a, b) => b.assetCount - a.assetCount);
    persistInvestigationRunbookState(detail.summary.externalId, {
      leadAnalyst,
      doneTaskIds: runbookTasks.filter((task) => task.state === 'DONE').map((task) => task.id),
      logEntries,
      assetCriteria,
      assetResults,
      resolvedInventory,
      assetAssessmentRan,
      investigationAssetCount: assetResults.length,
      investigationSoftwareCount,
      investigationSoftwareSummary,
      falsePositiveRan,
      analystFpOverrides: Array.from(analystFpOverrides),
      analystFpEvidence,
      eolAssessed,
      solutionEntries,
    });
    setSavedAt(new Date());
  }, [
    assetAssessmentRan,
    assetCriteria,
    assetResults,
    detail.summary.externalId,
    eolAssessed,
    analystFpOverrides,
    analystFpEvidence,
    falsePositiveRan,
    leadAnalyst,
    logEntries,
    runbookTasks,
    solutionEntries,
  ]);

  React.useEffect(() => {
    // Reset local investigation state only when the user navigates to a different CVE.
    setSelectedTaskId('review-asset-inventory');
    setAssetCriteria(initialCriteria);
    setAssetResults(initialResults);
    setAssetResultsExpanded(initialResults.length > 0);
    setAssetAssessmentRan(persistedRunbookState?.assetAssessmentRan ?? initialResults.length > 0);
    setEolResults(initialEolResults);
    setEolExpanded((persistedRunbookState?.eolAssessed ?? false) || eolTask?.state === 'DONE');
    setEolAssessed(persistedRunbookState?.eolAssessed ?? eolTask?.state === 'DONE');
    setFalsePositiveResults(initialFalsePositiveResults);
    setFalsePositiveResultsExpanded((persistedRunbookState?.falsePositiveRan ?? false) || falsePositiveTask?.state === 'DONE');
    setFalsePositiveRan(persistedRunbookState?.falsePositiveRan ?? falsePositiveTask?.state === 'DONE');
    setResolvedInventory(initialResolvedInventory);
    setSummaryVisible(false);
  }, [detail.summary.externalId, persistedRunbookState, initialCriteria, initialResults, initialEolResults, initialFalsePositiveResults, initialResolvedInventory, eolTask?.state, falsePositiveTask?.state]);

  React.useEffect(() => {
    if (eolTask?.state === 'DONE' && !eolAssessed) {
      setEolResults(initialEolResults);
      setEolExpanded(true);
      setEolAssessed(true);
    }
  }, [eolTask?.state, eolAssessed, initialEolResults]);

  React.useEffect(() => {
    if (falsePositiveTask?.state === 'DONE' && !falsePositiveRan) {
      setFalsePositiveResults(initialFalsePositiveResults);
      setFalsePositiveResultsExpanded(true);
      setFalsePositiveRan(true);
    }
  }, [falsePositiveTask?.state, falsePositiveRan, initialFalsePositiveResults]);

  // Tracks whether the assessment criteria/results have changed since the last explicit Save
  const [assessmentDirty, setAssessmentDirty] = React.useState(false);
  // Shows the unsaved-changes warning inline (when navigating to next pill without saving)
  const [assessmentUnsavedWarning, setAssessmentUnsavedWarning] = React.useState(false);

  // Auto-save non-assessment state (tasks, log entries, notes, overrides) without overwriting
  // the assessment fields in localStorage when they haven't been explicitly saved.
  const flushNonAssessmentState = React.useCallback(() => {
    const existing = loadPersistedInvestigationRunbookState(detail.summary.externalId) ?? {};
    persistInvestigationRunbookState(detail.summary.externalId, {
      ...existing,
      leadAnalyst,
      doneTaskIds: runbookTasks.filter((task) => task.state === 'DONE').map((task) => task.id),
      logEntries,
      falsePositiveRan,
      analystFpOverrides: Array.from(analystFpOverrides),
      analystFpEvidence,
      eolAssessed,
      solutionEntries,
    });
  }, [
    detail.summary.externalId,
    leadAnalyst,
    runbookTasks,
    logEntries,
    falsePositiveRan,
    analystFpOverrides,
    analystFpEvidence,
    eolAssessed,
    solutionEntries,
  ]);

  // When assessment is dirty: auto-save only non-assessment fields so localStorage retains the
  // previously saved criteria/results until the user explicitly presses Save.
  // When assessment is clean: full flush (includes assessment fields).
  React.useEffect(() => {
    if (assessmentDirty) {
      flushNonAssessmentState();
    } else {
      flushRunbookState();
    }
  }, [assessmentDirty, flushNonAssessmentState, flushRunbookState]);

  // Persist asset criteria to separate storage only when the assessment is saved (not dirty)
  React.useEffect(() => {
    if (assessmentDirty) return;
    persistAssetCriteria(detail.summary.externalId, assetCriteria);
  }, [assessmentDirty, assetCriteria, detail.summary.externalId]);
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
    if (saved.analystFpOverrides) setAnalystFpOverrides(new Set(saved.analystFpOverrides));
    if (saved.analystFpEvidence) setAnalystFpEvidence(saved.analystFpEvidence);
    if (saved.eolResults) setEolResults(saved.eolResults);
    if (typeof saved.eolAssessed === 'boolean') {
      setEolAssessed(saved.eolAssessed);
      setEolExpanded(saved.eolAssessed);
    }
  }, [isOpen, detail.summary.externalId]);

  // When re-opening a previously-assessed investigation, silently re-fetch the resolved inventory
  // for any manually-added (non-matched) criteria so that asset counts and downstream results
  // are restored without needing to persist potentially large arrays in localStorage.
  React.useEffect(() => {
    if (!isOpen || !assetAssessmentRan) return;
    const hasManualCriteria = assetCriteria.some((c) => !c.matched && c.software.trim().length > 0);
    if (!hasManualCriteria || resolvedInventory.length > 0) return;

    let cancelled = false;
    resolveInventorySoftware(assetCriteria).then((resolved) => {
      if (cancelled) return;
      setResolvedInventory(resolved);
      const results = mergeAssetInventoryResults(
        buildAssetInventoryResults(detail, assetCriteria, item.severity),
        buildAssetRowsFromResolvedInventory(resolved, item.severity)
      );
      setAssetResults(results);
      if (falsePositiveRan) {
        const allFp = buildFalsePositiveResults(detail, resolved);
        const swWithAssets = new Set(
          results.flatMap((r) => r.matchedSoftware.map((ms) => ms.software.toLowerCase()))
        );
        setFalsePositiveResults(
          swWithAssets.size > 0 ? allFp.filter((r) => swWithAssets.has(r.software.toLowerCase())) : allFp
        );
      }
      if (eolAssessed) {
        setEolResults(buildEolAnalysisResults(detail, buildEolCriteria(detail, assetCriteria), resolved));
      }
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [isOpen, assetAssessmentRan, detail.summary.externalId]); // eslint-disable-line react-hooks/exhaustive-deps

  const osBreakdown = React.useMemo(() => {
    const counts = new Map<string, number>();
    assetResults.forEach((asset) => counts.set(asset.os, (counts.get(asset.os) ?? 0) + 1));
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((left, right) => right.count - left.count);
  }, [assetResults]);
  const softwareBreakdown = React.useMemo(() => {
    const counts = new Map<string, { software: string; version: string; count: number }>();
    assetResults.forEach((asset) => {
      asset.matchedSoftware.forEach((entry) => {
        const key = `${entry.software}::${entry.version}`;
        const existing = counts.get(key);
        if (existing) {
          existing.count += 1;
        } else {
          counts.set(key, { software: entry.software, version: entry.version, count: 1 });
        }
      });
    });
    return Array.from(counts.values())
      .sort((left, right) => right.count - left.count || left.software.localeCompare(right.software))
      .slice(0, 6);
  }, [assetResults]);
  const externalFacingCount = assetResults.filter((asset) => asset.externalFacing).length;
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
    falsePositiveRows: falsePositiveResults.map((row) => {
      // Effective FP = vendor-detected OR manually overridden by analyst
      const effectiveFp = row.falsePositive || analystFpOverrides.has(row.id);
      const analystEvidence = analystFpEvidence[row.id];
      return {
        software: row.software,
        version: row.version,
        falsePositive: effectiveFp,
        assetsNotImpacted: effectiveFp ? (row.notImpactedAssetCount || 0) : 0,
        vendorAdvisory: row.vendorAdvisory,
        vendorGuidance: analystEvidence
          ? `Analyst override: ${analystEvidence}`
          : row.vendorGuidance,
      };
    }),
    eolRows: eolResults.map((row) => ({
      software: row.software,
      vendor: row.vendor,
      version: row.version,
      lifecycle: row.lifecycle,
      endOfSupport: row.endOfSupport,
      endOfLife: row.endOfLife,
      recommendedUpgrade: row.recommendedUpgrade,
    })),
    solutionRows: solutionRows.map((row) => ({
      software: row.software,
      version: row.version,
      vendor: row.vendor,
      impactedAssets: row.count,
      solutionDetail: solutionEntries[`${row.software}@${row.version}`] ?? '',
    })),
    createdFindings,
  }), [assetResults, createdFindings, detail, eolResults, falsePositiveResults, analystFpOverrides, analystFpEvidence, item.externalId, item.inKev, item.severity, leadAnalyst, runbookTasks, solutionRows, solutionEntries]);
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
    setAssessmentDirty(true);
    setAssetCriteria((current) => current.map((criterion) => (
      criterion.id === id ? { ...criterion, [field]: value } : criterion
    )));
  }

  function addAssetCriterion(): void {
    setAssessmentDirty(true);
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
    setAssessmentDirty(true);
    setAssetCriteria((current) => current.filter((criterion) => criterion.id !== id));
  }

  async function runAssetInventoryAssessment(): Promise<void> {
    setAssessmentDirty(true);
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
    setAssessmentDirty(false);
    setAssessmentUnsavedWarning(false);

    // Cascade: keep downstream steps in sync with the updated software list.
    if (falsePositiveRan) {
      setFalsePositiveResults(buildFalsePositiveResults(detail, resolved));
    }
    if (eolAssessed) {
      // eolCriteria is derived from assetCriteria (useMemo), so just re-run results.
      setEolResults(buildEolAnalysisResults(detail, buildEolCriteria(detail, assetCriteria), resolved));
    }
  }

  async function runFalsePositiveAssessment(): Promise<void> {
    const resolved = await resolveInventorySoftware(assetCriteria);
    setResolvedInventory(resolved);
    const allFpResults = buildFalsePositiveResults(detail, resolved);
    // Only keep software that has at least one matched asset from step 1
    const softwareWithAssets = new Set(
      assetResults.flatMap((asset) => asset.matchedSoftware.map((ms) => ms.software.toLowerCase()))
    );
    const filtered = softwareWithAssets.size > 0
      ? allFpResults.filter((r) => softwareWithAssets.has(r.software.toLowerCase()))
      : allFpResults;
    setFalsePositiveResults(filtered);
    setFalsePositiveResultsExpanded(true);
    setFalsePositiveRan(true);
    onRunTask('find-false-positive');
  }

  async function generateSolutionsForRows(): Promise<void> {
    const rowsToGenerate = solutionRows.filter((row) => {
      const key = `${row.software}@${row.version}`;
      return !solutionEntries[key]?.trim(); // skip manually-entered solutions
    });
    if (rowsToGenerate.length === 0) return;

    setSolutionGeneratingKeys(new Set(rowsToGenerate.map((r) => `${r.software}@${r.version}`)));

    await Promise.all(rowsToGenerate.map(async (row) => {
      const key = `${row.software}@${row.version}`;
      let solution: string;

      // 1. Try vendor CSAF/VEX first
      const csafText = buildCsafSolutionText(row.software, detail.vendorIntelligence);
      if (csafText) {
        solution = csafText;
      } else {
        // 2. OpenAI — pass rich context so the AI can tailor the recommendation
        try {
          const context = {
            targetSoftware: row.software,
            targetVersion: row.version,
            targetVendor: row.vendor,
            cveId: detail.summary.externalId,
            severity: item.severity,
            cvssScore: detail.summary.cvssScore,
            patchAvailable: detail.signals.patchAvailable,
            patchVersions: detail.signals.patchVersions,
            description: detail.summary.description,
            inKev: detail.summary.inKev,
            affected_entities: [
              {
                software: row.software,
                version: row.version,
                vendor: row.vendor,
                asset_count: row.count,
              },
            ],
            vendor_intelligence: detail.vendorIntelligence.map((v) => ({
              source: v.source,
              vex_status: v.vexStatus,
              fixed_version: v.fixedVersion,
            })),
          };
          const result = await cveWorkbenchApi.generateAiSolution(detail.summary.externalId, context);
          if (result.success && result.data) {
            const d = result.data;
            const parts: string[] = [];
            if (d.primary_fix?.target_version) {
              parts.push(`[Patch] Upgrade ${row.software} from ${row.version} to ${d.primary_fix.target_version}.`);
            } else if (d.primary_fix?.action) {
              parts.push(`[Patch] ${d.primary_fix.action}`);
            }
            if (d.primary_fix?.patch_id) parts.push(`Patch: ${d.primary_fix.patch_id}`);
            if (d.primary_fix?.verification) parts.push(`Verification: ${d.primary_fix.verification}`);
            if (d.primary_fix?.reboot_required) parts.push('Note: Reboot required after patching.');
            if (!parts.length && d.compensating_controls?.length) {
              const c = d.compensating_controls[0];
              parts.push(`[Workaround] ${c.control}`);
              if (c.effort || c.effectiveness) parts.push(`Effort: ${c.effort} | Effectiveness: ${c.effectiveness}`);
            }
            if (d.timeline?.length) {
              const immediate = d.timeline.find((t) => t.window?.toLowerCase().includes('24'));
              if (immediate?.actions?.length) {
                parts.push('');
                parts.push('Immediate actions:');
                immediate.actions.forEach((a) => parts.push(`• ${a}`));
              }
            }
            solution = parts.length > 0 ? parts.join('\n') : buildSignalsFallback(row, detail);
          } else {
            // 3. Derive from NVD signals when OpenAI is unavailable
            solution = buildSignalsFallback(row, detail);
          }
        } catch {
          solution = buildSignalsFallback(row, detail);
        }
      }

      setSolutionEntries((prev) => {
        // Only set if still empty (user may have typed something while generation was running)
        if (prev[key]?.trim()) return prev;
        return { ...prev, [key]: solution };
      });
      setSolutionGeneratingKeys((prev) => { const next = new Set(prev); next.delete(key); return next; });
    }));

    setSolutionGeneratingKeys(new Set());
  }

  function handleRunbookAction(taskId: string): void {
    if (taskId === 'review-asset-inventory') {
      setAssetResultsExpanded(true);
      return;
    }
    if (isEolTask(taskId)) {
      onRunTask('end-of-life-analysis');
      return;
    }
    if (taskId === 'solutions') {
      onRunTask('solutions');
      return;
    }
    if (taskId === 'find-false-positive') {
      runFalsePositiveAssessment();
      return;
    }
    onRunTask(taskId);
  }

  const selectedTaskIndex = React.useMemo(
    () => runbookTasks.findIndex((task) => task.id === selectedTaskId),
    [runbookTasks, selectedTaskId]
  );

  const openTask = React.useCallback((taskId: string): void => {
    if (assessmentDirty && selectedTaskId === 'review-asset-inventory' && taskId !== 'review-asset-inventory') {
      setAssessmentUnsavedWarning(true);
      return;
    }
    if (taskId === 'find-false-positive' && !falsePositiveRan && assetAssessmentRan) {
      void runFalsePositiveAssessment();
    }
    setSelectedTaskId(taskId);
  }, [assessmentDirty, assetAssessmentRan, falsePositiveRan, selectedTaskId]);

  const moveTask = React.useCallback((direction: -1 | 1): void => {
    if (selectedTaskIndex < 0) return;
    const nextIndex = selectedTaskIndex + direction;
    if (nextIndex < 0 || nextIndex >= runbookTasks.length) return;
    const nextTask = runbookTasks[nextIndex];
    if (nextTask) openTask(nextTask.id);
  }, [openTask, runbookTasks, selectedTaskIndex]);

  const triggerSummary = React.useCallback(() => {
    setSummaryVisible(true);
    onRunTask('generate-summary');
    onRunTask('installed-patch-info');
  }, [onRunTask]);

  React.useEffect(() => {
    if (selectedTaskId === 'installed-patch-info') {
      triggerSummary();
    }
  }, [selectedTaskId, triggerSummary]);

  // Auto-run EOL analysis when the user navigates to the EOL step after completing step 1.
  React.useEffect(() => {
    if (!selectedTaskId || !isEolTask(selectedTaskId)) return;
    if (eolAssessed || eolAssessing) return;
    if (!assetAssessmentRan) return;
    let cancelled = false;
    setEolAssessing(true);
    const run = async () => {
      try {
        let resolved = resolvedInventory;
        if (resolved.length === 0) {
          resolved = await resolveInventorySoftware(assetCriteria);
          if (cancelled) return;
          setResolvedInventory(resolved);
        }
        const results = buildEolAnalysisResults(detail, buildEolCriteria(detail, assetCriteria), resolved);
        if (cancelled) return;
        setEolResults(results);
        setEolExpanded(true);
        setEolAssessed(true);
        onRunTask('end-of-life-analysis');
      } catch { /* best-effort */ } finally {
        if (!cancelled) setEolAssessing(false);
      }
    };
    void run();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedTaskId, assetAssessmentRan, detail.summary.externalId]);

  // Fetch all software identities once for cascading dropdowns
  React.useEffect(() => {
    api.listSoftwareIdentities({ size: 1000 }).then((page) => {
      setInventoryIdentities(page.content);
    }).catch(() => { /* best-effort */ });
  }, []);

  // Fetch versions for a given identity and cache them
  async function fetchVersionsForIdentity(identityId: string): Promise<void> {
    if (versionCache[identityId]) return;
    try {
      const detail = await api.getSoftwareIdentityDetail(identityId);
      setVersionCache((prev) => ({ ...prev, [identityId]: detail.versions.map((v) => v.version).filter(Boolean) }));
    } catch { /* best-effort */ }
  }

  const closeCanvas = React.useCallback(() => {
    // When assessment is dirty (unsaved), preserve the previously-saved assessment
    // by only flushing non-assessment state. The unsaved criteria/results are discarded.
    if (assessmentDirty) {
      flushNonAssessmentState();
    } else {
      flushRunbookState();
    }
    setAssessmentDirty(false);
    setAssessmentUnsavedWarning(false);
    onClose();
  }, [assessmentDirty, flushNonAssessmentState, flushRunbookState, onClose]);

  function renderRunbookActions(task: RunbookTask): React.ReactNode {
    if (task.id === 'review-asset-inventory' && assetAssessmentRan) {
      return null;
    }
    if (isEolTask(task.id)) {
      if (eolAssessed && task.state !== 'DONE') {
        return (
          <button type="button" className="btn btn-secondary btn-inline" onClick={() => handleRunbookAction(task.id)}>
            Mark Done
          </button>
        );
      }
      return null;
    }
    if (task.id === 'find-false-positive' && falsePositiveRan) {
      return null;
    }
    if (task.id === 'solutions') {
      const isGenerating = solutionGeneratingKeys.size > 0;
      return (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-primary btn-inline"
            disabled={isGenerating}
            onClick={() => void generateSolutionsForRows()}
          >
            {isGenerating ? 'Generating…' : 'Generate Solutions'}
          </button>
          {task.state !== 'DONE' && (
            <button type="button" className="btn btn-secondary btn-inline" onClick={() => handleRunbookAction(task.id)}>
              Mark Done
            </button>
          )}
          {task.state === 'DONE' && (
            <button
              type="button"
              className="btn btn-primary btn-inline"
              onClick={() => onOpenFindingsStep({ scope: 'all', openConfig: true })}
            >
              Create Findings
            </button>
          )}
        </div>
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

  const vendorDropdownOptions = React.useMemo(() => {
    const vendors = new Set<string>();
    inventoryIdentities.forEach((id) => { if (id.vendor) vendors.add(id.vendor); });
    return Array.from(vendors).sort((a, b) => a.localeCompare(b));
  }, [inventoryIdentities]);

  function softwareOptionsForVendor(vendorName: string): SoftwareIdentitySummary[] {
    if (!vendorName) return [];
    return inventoryIdentities
      .filter((id) => id.vendor?.toLowerCase() === vendorName.toLowerCase())
      .sort((a, b) => a.displayName.localeCompare(b.displayName));
  }

  function versionsForCriterion(criterionId: string): string[] {
    const identityId = criterionIdentityMap[criterionId];
    if (!identityId) return [];
    return versionCache[identityId] ?? [];
  }

  function toggleManualText(criterionId: string, field: string): void {
    setManualTextMode((prev) => {
      const next = new Set(prev);
      const key = `${criterionId}:${field}`;
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  function isManualText(criterionId: string, field: string): boolean {
    return manualTextMode.has(`${criterionId}:${field}`);
  }

  const assessmentPanel = (
    <div className="investigation-assessment-panel">
      <div className="investigation-assessment-criteria-list">
        {assetCriteria.map((criterion) => {
          if (criterion.matched) {
            // Auto-populated from CVE CPE — show as read-only
            return (
              <div key={criterion.id} className="investigation-assessment-criteria-row">
                <span className="criteria-readonly-field">{criterion.vendor || '—'}</span>
                <span className="criteria-readonly-field">{criterion.software || '—'}</span>
                <span className="criteria-readonly-field">{criterion.version || '—'}</span>
                <button type="button" className="investigation-criteria-remove-btn" title="Remove" onClick={() => removeAssetCriterion(criterion.id)}>✕</button>
              </div>
            );
          }
          // Manually added — show dropdowns with "Other…" free-text fallback
          const softwareOpts = softwareOptionsForVendor(criterion.vendor);
          const versionOpts = versionsForCriterion(criterion.id);
          return (
            <div key={criterion.id} className="investigation-assessment-criteria-row">
              {/* Vendor */}
              {isManualText(criterion.id, 'vendor') ? (
                <div className="criteria-field-wrap">
                  <input
                    type="text"
                    className="criteria-text-input"
                    value={criterion.vendor}
                    onChange={(e) => updateAssetCriterion(criterion.id, 'vendor', e.target.value)}
                    placeholder="Enter vendor"
                    autoFocus
                  />
                  <button type="button" className="criteria-back-btn" title="Back to dropdown" onClick={() => toggleManualText(criterion.id, 'vendor')}>↩</button>
                </div>
              ) : (
                <select
                  className="criteria-select"
                  value={criterion.vendor}
                  onChange={(e) => {
                    if (e.target.value === '__other__') {
                      toggleManualText(criterion.id, 'vendor');
                      updateAssetCriterion(criterion.id, 'vendor', '');
                    } else {
                      // reset downstream on vendor change
                      updateAssetCriterion(criterion.id, 'vendor', e.target.value);
                      updateAssetCriterion(criterion.id, 'software', '');
                      updateAssetCriterion(criterion.id, 'version', '');
                      setCriterionIdentityMap((prev) => { const n = { ...prev }; delete n[criterion.id]; return n; });
                    }
                  }}
                >
                  <option value="">Select vendor…</option>
                  {vendorDropdownOptions.map((v) => <option key={v} value={v}>{v}</option>)}
                  <option value="__other__">Other (type manually)…</option>
                </select>
              )}
              {/* Software — enabled only after vendor is chosen */}
              {isManualText(criterion.id, 'software') ? (
                <div className="criteria-field-wrap">
                  <input
                    type="text"
                    className="criteria-text-input"
                    value={criterion.software}
                    onChange={(e) => updateAssetCriterion(criterion.id, 'software', e.target.value)}
                    placeholder="Enter software"
                    autoFocus
                  />
                  <button type="button" className="criteria-back-btn" title="Back to dropdown" onClick={() => toggleManualText(criterion.id, 'software')}>↩</button>
                </div>
              ) : (
                <select
                  className="criteria-select"
                  value={criterion.software}
                  disabled={!criterion.vendor && !isManualText(criterion.id, 'vendor')}
                  onChange={(e) => {
                    if (e.target.value === '__other__') {
                      toggleManualText(criterion.id, 'software');
                      updateAssetCriterion(criterion.id, 'software', '');
                      updateAssetCriterion(criterion.id, 'version', '');
                      setCriterionIdentityMap((prev) => { const n = { ...prev }; delete n[criterion.id]; return n; });
                    } else {
                      const identity = softwareOpts.find((s) => s.displayName === e.target.value || s.canonicalKey === e.target.value);
                      updateAssetCriterion(criterion.id, 'software', identity?.displayName ?? e.target.value);
                      updateAssetCriterion(criterion.id, 'version', '');
                      if (identity) {
                        setCriterionIdentityMap((prev) => ({ ...prev, [criterion.id]: identity.id }));
                        void fetchVersionsForIdentity(identity.id);
                      }
                    }
                  }}
                >
                  <option value="">Select software…</option>
                  {softwareOpts.map((s) => <option key={s.id} value={s.displayName}>{s.displayName}</option>)}
                  <option value="__other__">Other (type manually)…</option>
                </select>
              )}
              {/* Version — enabled only after software is chosen */}
              {isManualText(criterion.id, 'version') ? (
                <div className="criteria-field-wrap">
                  <input
                    type="text"
                    className="criteria-text-input"
                    value={criterion.version}
                    onChange={(e) => updateAssetCriterion(criterion.id, 'version', e.target.value)}
                    placeholder="Enter version"
                    autoFocus
                  />
                  <button type="button" className="criteria-back-btn" title="Back to dropdown" onClick={() => toggleManualText(criterion.id, 'version')}>↩</button>
                </div>
              ) : (
                <select
                  className="criteria-select"
                  value={criterion.version}
                  disabled={!criterion.software && !isManualText(criterion.id, 'software')}
                  onChange={(e) => {
                    if (e.target.value === '__other__') {
                      toggleManualText(criterion.id, 'version');
                      updateAssetCriterion(criterion.id, 'version', '');
                    } else {
                      updateAssetCriterion(criterion.id, 'version', e.target.value);
                    }
                  }}
                >
                  <option value="">Select version…</option>
                  {versionOpts.map((v) => <option key={v} value={v}>{v}</option>)}
                  <option value="__other__">Other (type manually)…</option>
                </select>
              )}
              <button type="button" className="investigation-criteria-remove-btn" title="Remove" onClick={() => removeAssetCriterion(criterion.id)}>✕</button>
            </div>
          );
        })}
        <button type="button" className="investigation-criteria-add-btn" onClick={addAssetCriterion}>
          <span>+</span> Add software
        </button>
      </div>
      <div className="investigation-assessment-actions">
        <button type="button" className="btn btn-primary" onClick={runAssetInventoryAssessment}>
          Run Assessment
        </button>
        {assessmentDirty && (
          <button
            type="button"
            className="btn btn-success"
            onClick={() => {
              flushRunbookState();
              setAssessmentDirty(false);
              setAssessmentUnsavedWarning(false);
            }}
          >
            Save
          </button>
        )}
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
            <button type="button" className="investigation-summary-card" onClick={() => onOpenFindingsStep({ scope: 'external-facing' })}>
              <span>External Facing Assets</span>
              <strong>{externalFacingCount}</strong>
            </button>
            <button type="button" className="investigation-summary-card" onClick={() => onOpenFindingsStep({ scope: 'all' })}>
              <span>Total Assets</span>
              <strong>{totalAssetCount}</strong>
            </button>
            <div className="investigation-summary-card investigation-summary-card-wheel">
              <span>Assets by OS</span>
              <div className="investigation-os-wheel">
                <div className="investigation-os-wheel-chart" style={{ backgroundImage: osWheelStops }} />
                <div className="investigation-os-wheel-legend">
                  {osBreakdown.map((entry) => (
                    <button key={entry.label} type="button" className="btn-link investigation-summary-link" onClick={() => onOpenFindingsStep({ os: entry.label })}>
                      {entry.label} {entry.count}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
          <div className="investigation-software-bar-panel">
            <div className="investigation-software-bar-header">
              <h5>Assets Matched by Software</h5>
              <button type="button" className="btn-link investigation-summary-link" onClick={() => onOpenFindingsStep({ scope: 'all' })}>
                Total Impacted Assets: {totalAssetCount} →
              </button>
            </div>
            <div className="investigation-software-bar-col-header">
              <span>Software</span>
              <span>Version</span>
              <span></span>
              <span></span>
            </div>
            <div className="investigation-software-bars">
              {softwareBreakdown.map((entry) => {
                const key = `${entry.software}::${entry.version}`;
                const pct = totalAssetCount > 0 ? Math.max(12, Math.round((entry.count / totalAssetCount) * 100)) : 0;
                return (
                  <div key={key} className="investigation-software-bar-row">
                    <span title={entry.software}>{entry.software}</span>
                    <span className="investigation-software-bar-version" title={entry.version}>{entry.version || '—'}</span>
                    <button type="button" className="btn-link investigation-summary-link" onClick={() => onOpenAssetList({ software: entry.software })}>
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
              <th>Assets Impacted</th>
              <th>False Positive</th>
              <th>Evidence</th>
              <th>Vendor Advisory</th>
            </tr>
          </thead>
          <tbody>
            {falsePositiveResults.map((row) => {
              const hasVersion = row.version && row.version !== '-';
              const impactedCount = assetResults.filter((asset) =>
                asset.matchedSoftware.some((ms) =>
                  ms.software.toLowerCase() === row.software.toLowerCase()
                  && (!hasVersion || ms.version === row.version)
                )
              ).length;
              const vendorSaysFp = row.falsePositive;
              const analystSaysFp = analystFpOverrides.has(row.id);
              const isFp = vendorSaysFp || analystSaysFp;
              return (
                <tr key={row.id} className={isFp ? 'fp-row-marked' : ''}>
                  <td><strong>{row.software}</strong></td>
                  <td className="mono">{row.version}</td>
                  <td className="fp-asset-count">{impactedCount}</td>
                  <td>
                    <label className="fp-checkbox-label">
                      <input
                        type="checkbox"
                        className="fp-checkbox"
                        checked={isFp}
                        onChange={() => {
                          setAnalystFpOverrides((prev) => {
                            const next = new Set(prev);
                            if (isFp && !vendorSaysFp) {
                              next.delete(row.id);
                            } else if (!isFp) {
                              next.add(row.id);
                            }
                            return next;
                          });
                        }}
                        disabled={vendorSaysFp && !analystSaysFp}
                      />
                      {vendorSaysFp
                        ? <span className="fp-label-vendor">VEX: Not Affected</span>
                        : analystSaysFp
                          ? <span className="fp-label-analyst">Analyst: False Positive</span>
                          : <span className="fp-label-none">—</span>
                      }
                    </label>
                  </td>
                  <td>
                    <input
                      type="text"
                      className="fp-evidence-input"
                      placeholder="URL or notes…"
                      value={analystFpEvidence[row.id] ?? ''}
                      onChange={(e) => {
                        const val = e.target.value;
                        setAnalystFpEvidence((prev) => {
                          if (!val) {
                            const next = { ...prev };
                            delete next[row.id];
                            return next;
                          }
                          return { ...prev, [row.id]: val };
                        });
                      }}
                    />
                  </td>
                  <td>{row.vendorAdvisory}</td>
                </tr>
              );
            })}
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

  const _logPanel = (
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
    <div className="investigation-page">
      <div className="investigation-page-header">
        <div className="investigation-header-top">
          <nav className="investigation-breadcrumb" aria-label="breadcrumb">
            <button type="button" className="investigation-breadcrumb-link" onClick={closeCanvas}>
              {item.externalId}
            </button>
            <span className="investigation-breadcrumb-sep">›</span>
            <span className="investigation-breadcrumb-current">Investigation</span>
            <span className="investigation-breadcrumb-sep">·</span>
            <span className={`investigation-inline-status${completedCount === runbookTasks.length ? ' investigation-inline-status-completed' : ''}`}>
              {completedCount === runbookTasks.length ? 'Completed' : 'In Progress'}
            </span>
          </nav>
        </div>
      </div>

        <div className="investigation-page-body">
          <section className="investigation-runbook">
            {/* Unsaved assessment warning — shown between header and pills */}
            {assessmentUnsavedWarning && (
              <div className="investigation-unsaved-warning">
                <span>⚠ You have unsaved assessment changes. Save before navigating to the next step, or your changes will be discarded when you close.</span>
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <button
                    type="button"
                    className="btn btn-success"
                    onClick={() => {
                      flushRunbookState();
                      setAssessmentDirty(false);
                      setAssessmentUnsavedWarning(false);
                    }}
                  >
                    Save now
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setAssessmentUnsavedWarning(false)}
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            )}
            {/* Step breadcrumb bar */}
            <div className="inv-steps-bar">
              {runbookTasks.map((task, index) => {
                const isSummaryTask = task.id === 'installed-patch-info';
                const isDone = task.state === 'DONE' || (isSummaryTask && summaryVisible);
                const prevTask = index > 0 ? runbookTasks[index - 1] : null;
                const isUnlocked = index === 0 || prevTask?.state === 'DONE';
                const stepStatus = isDone ? 'done' : isUnlocked ? 'pending' : 'locked';
                const isSelected = selectedTaskId === task.id;
                return (
                  <button
                    key={task.id}
                    type="button"
                    className={`inv-step inv-step-${stepStatus}${isSelected ? ' inv-step-selected' : ''}`}
                    disabled={!isUnlocked}
                    onClick={() => {
                      if (!isUnlocked) return;
                      openTask(task.id);
                    }}
                  >
                    <span className="inv-step-icon" aria-hidden="true">
                      {stepStatus === 'done' ? '✓' : index + 1}
                    </span>
                    <span className="inv-step-label">{task.title}</span>
                  </button>
                );
              })}
            </div>
            <div className="inv-steps-nav">
              {selectedTaskIndex > 0 && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => moveTask(-1)}
                  title="Previous step"
                >
                  ←
                </button>
              )}
              {selectedTaskIndex >= 0 && selectedTaskIndex < runbookTasks.length - 1 && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => moveTask(1)}
                  title="Next step"
                >
                  →
                </button>
              )}
            </div>

            {/* Detail panel for the selected step */}
            {selectedTaskId && (() => {
              const task = runbookTasks.find(t => t.id === selectedTaskId);
              if (!task) return null;
              return (
                <div className="inv-step-detail">
                  {task.id !== 'installed-patch-info' && task.id !== 'find-false-positive' && !isEolTask(task.id) && (
                    <div className="inv-step-detail-header">
                      <div>
                        <h4 className="inv-step-detail-title">{task.title}</h4>
                        <p className="inv-step-detail-desc">{task.description}</p>
                      </div>
                      <div className="inv-step-detail-actions">
                        {renderRunbookActions(task)}
                      </div>
                    </div>
                  )}
                  {(task.id === 'find-false-positive' || isEolTask(task.id)) && (
                    <div className="inv-step-detail-header">
                      <div />
                      <div className="inv-step-detail-actions">
                        {renderRunbookActions(task)}
                      </div>
                    </div>
                  )}
                  {task.id === 'review-asset-inventory' && reviewTask && assessmentPanel}
                  {task.id === 'find-false-positive' && falsePositiveRan && (
                    <div className="investigation-false-positive-panel">
                      <div className="investigation-false-positive-header">
                        <div>
                          <h5>False Positive Report</h5>
                          <div className="panel-caption">
                            {falsePositiveResults.length} unique software entr{falsePositiveResults.length === 1 ? 'y was' : 'ies were'} checked against vendor VEX and advisory guidance for this CVE.
                          </div>
                        </div>
                        <div className="fp-total-badge">
                          Total assets with False positive: <strong>{
                            (() => {
                              const fpSoftwareNames = new Set(
                                falsePositiveResults
                                  .filter((r) => r.falsePositive || analystFpOverrides.has(r.id))
                                  .map((r) => r.software.toLowerCase())
                              );
                              return assetResults.filter((asset) =>
                                asset.matchedSoftware.some((ms) => fpSoftwareNames.has(ms.software.toLowerCase()))
                              ).length;
                            })()
                          }</strong>
                        </div>
                      </div>
                      {falsePositiveDetails}
                    </div>
                  )}
                  {isEolTask(task.id) && eolAssessing && !eolAssessed && (
                    <div className="investigation-eol-panel investigation-eol-loading">
                      <span className="eol-loading-spinner" />
                      <span>Analyzing end-of-life status…</span>
                    </div>
                  )}
                  {isEolTask(task.id) && eolAssessed && (
                    <div className="investigation-eol-panel">
                      {eolDetails}
                    </div>
                  )}
                  {task.id === 'solutions' && (
                    <div className="inv-solutions-panel">
                      <table className="inv-solutions-table">
                        <thead>
                          <tr>
                            <th>Software</th>
                            <th>Version</th>
                            <th>Vendor</th>
                            <th>Impacted Assets</th>
                            <th>Solution</th>
                          </tr>
                        </thead>
                        <tbody>
                          {solutionRows.map((row) => {
                            const key = `${row.software}@${row.version}`;
                            const isRowGenerating = solutionGeneratingKeys.has(key);
                            return (
                              <tr key={key}>
                                <td className="inv-solutions-software">{row.software}</td>
                                <td className="inv-solutions-version">{row.version || '—'}</td>
                                <td className="inv-solutions-vendor">{row.vendor || '—'}</td>
                                <td className="inv-solutions-count">{row.count}</td>
                                <td className="inv-solutions-input-cell">
                                  {isRowGenerating ? (
                                    <span className="solutions-generating">Generating…</span>
                                  ) : (
                                    <textarea
                                      className="inv-solutions-input"
                                      rows={3}
                                      value={solutionEntries[key] ?? ''}
                                      onChange={(e) => setSolutionEntries((prev) => ({ ...prev, [key]: e.target.value }))}
                                      placeholder="Describe the remediation solution..."
                                    />
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                  {task.id === 'installed-patch-info' && (
                    <CVEInvestigationSummary visible={summaryVisible} input={summaryInput} />
                  )}
                </div>
              );
            })()}
          </section>

        </div>
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
  analystId: _analystId,
  onStepChange,
  onOpenAffectedEntities,
  onOpenImpactedSoftware,
  onOpenExternalFacingAssets,
  leadAnalyst: _leadAnalyst,
  onLeadAnalystChange: _onLeadAnalystChange,
  persistedRunbookState,
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
  onOpenExternalFacingAssets: () => void;
  leadAnalyst: string;
  onLeadAnalystChange: (value: string) => void;
  persistedRunbookState?: PersistedInvestigationRunbookState | null;
}) {
  const navigate = useNavigate();
  const riskPolicyQuery = useRiskPolicyQuery();
  const riskResult = React.useMemo(
    () => computeCveRiskScore(item, riskPolicyQuery.data),
    [item, riskPolicyQuery.data],
  );
  const riskJourney = riskResult.journey.filter(ev => !ev.isNote);
  const affectedProducts = React.useMemo(() => buildAffectedProducts(detail, softwareGroups), [detail, softwareGroups]);
  const [activeTab, setActiveTab] = React.useState<'assets' | 'refs' | 'timeline'>('assets');
  const [aiSolutionData, setAiSolutionData] = React.useState<AiSolutionData | null>(null);
  const [aiSolutionGeneratedAt, setAiSolutionGeneratedAt] = React.useState<string | null>(null);
  const [aiSolutionFallback, setAiSolutionFallback] = React.useState<string | null>(null);
  const [aiSolutionLoading, setAiSolutionLoading] = React.useState(false);
  const [aiSolutionError, setAiSolutionError] = React.useState<string | null>(null);
  const [aiTraceOpen, setAiTraceOpen] = React.useState(false);
  const [solutionCollapsed, setSolutionCollapsed] = React.useState(false);

  const [aiActions, setAiActions] = React.useState<AiRequiredAction[] | null>(null);
  const [aiActionsLoading, setAiActionsLoading] = React.useState(false);
  const [aiActionsError, setAiActionsError] = React.useState<string | null>(null);
  const [, setAiActionsGeneratedAt] = React.useState<string | null>(null);

  // Load persisted AI actions on mount
  React.useEffect(() => {
    cveWorkbenchApi.getSavedAiActions(detail.summary.externalId)
      .then(res => {
        if (res.success && res.data?.actions?.length) {
          setAiActions(res.data.actions);
          if (res.generatedAt) setAiActionsGeneratedAt(res.generatedAt);
        }
      })
      .catch(() => { /* no saved actions — normal */ });
  }, [detail.summary.externalId]);

  const generateAiActions = React.useCallback(() => {
    setAiActionsLoading(true);
    setAiActionsError(null);
    const context = {
      cve_id: detail.summary.externalId,
      title: detail.summary.title,
      severity: item.severity,
      cvss_score: detail.summary.cvssScore,
      epss_score: detail.summary.epssScore ?? item.epssScore,
      in_kev: detail.summary.inKev,
      kev_due_date: detail.summary.kevDueDate,
      kev_required_action: detail.summary.kevRequiredAction,
      exploit_available: detail.signals.exploitAvailable,
      exploit_reason: detail.signals.exploitReason,
      patch_available: detail.signals.patchAvailable,
      patch_versions: detail.signals.patchVersions,
      asset_count: detail.signals.assetCount,
      software_count: detail.signals.softwareCount,
      open_findings: item.openFindings,
      impact_state: item.impactState,
      applicability: item.applicability,
      investigation_status: latestInvestigation?.status ?? null,
      investigation_assigned_to: latestInvestigation?.assignedTo ?? null,
      investigation_updated_at: latestInvestigation?.updatedAt ?? null,
      assessment_result: latestAssessment?.finalResult ?? null,
      assessment_completed_at: latestAssessment?.completedAt ?? null,
      published_at: detail.summary.publishedAt,
      modified_at: detail.summary.modifiedAt,
      description: detail.summary.description,
      cwe_ids: detail.summary.cweIds,
      affected_software_groups: softwareGroups.map(g => ({ name: g.software.packageName, version: g.software.version, ecosystem: g.software.ecosystem })),
    };
    cveWorkbenchApi.generateAiRequiredActions(detail.summary.externalId, context)
      .then(res => {
        if (res.success && res.data?.actions?.length) {
          setAiActions(res.data.actions);
          if (res.generatedAt) setAiActionsGeneratedAt(res.generatedAt);
        } else {
          setAiActionsError(res.error ?? 'No actions returned');
        }
      })
      .catch(err => setAiActionsError(err?.message ?? 'Failed to generate actions'))
      .finally(() => setAiActionsLoading(false));
  }, [detail, item, latestInvestigation, latestAssessment, softwareGroups]);

  React.useEffect(() => {
    cveWorkbenchApi.getSavedAiSolution(detail.summary.externalId)
      .then(res => {
        if (res.success && res.data) {
          setAiSolutionData(res.data);
          if (res.generatedAt) setAiSolutionGeneratedAt(res.generatedAt);
        }
      })
      .catch(() => { /* no saved solution — normal */ });
  }, [detail.summary.externalId]);
  const referenceLinks = buildReferenceLinks(detail);
  const remediationText = detail.signals.patchAvailable
    ? `Apply the vendor-fixed version${detail.signals.patchVersions ? ` (${detail.signals.patchVersions})` : ''} and validate the mitigation on impacted assets.`
    : 'No vendor patch is currently available. Continue investigation and apply compensating controls until remediation guidance is published.';
  const timelineItems = [
    detail.summary.publishedAt ? { label: 'CVE Record Created', value: formatDate(detail.summary.publishedAt), tone: 'published', sublabel: 'NVD Published Date' } : null,
    detail.summary.modifiedAt ? { label: 'CVE Record Updated', value: formatDate(detail.summary.modifiedAt), tone: 'updated', sublabel: 'NVD Last Modified' } : null,
    detail.summary.inKev && detail.summary.kevDateAdded ? { label: 'Added to CISA KEV', value: formatDate(detail.summary.kevDateAdded), tone: 'exploit', sublabel: 'Known Exploited Vulnerability' } : null,
    detail.summary.inKev && detail.summary.kevDueDate ? { label: 'CISA Remediation Due', value: formatDate(detail.summary.kevDueDate), tone: 'danger', sublabel: detail.summary.kevRequiredAction ?? 'Patch or mitigate per vendor guidance' } : null,
    detail.signals.exploitAvailable && !detail.summary.inKev ? { label: 'Public Exploit Observed', value: detail.signals.exploitReason || 'Active exploit known', tone: 'exploit', sublabel: undefined } : null,
    latestAssessment?.completedAt ? { label: 'Assessment Completed', value: formatDate(latestAssessment.completedAt), tone: 'verified', sublabel: undefined } : null,
    latestInvestigation
      ? ((latestInvestigation.status === 'CLOSED' || latestInvestigation.status === 'PENDING_REVIEW') && latestInvestigation.updatedAt
          ? { label: 'Investigation Completed', value: formatDate(latestInvestigation.updatedAt), tone: 'verified', sublabel: latestInvestigation.assignedTo ? `Completed by ${latestInvestigation.assignedTo}` : undefined }
          : { label: 'Investigation', value: formatLabel(latestInvestigation.status), tone: 'updated', sublabel: latestInvestigation.assignedTo ? `Assigned to ${latestInvestigation.assignedTo}` : undefined })
      : { label: 'Investigation', value: 'Not done', tone: 'muted', sublabel: undefined },
  ].filter(Boolean) as Array<{ label: string; value: string; tone: string; sublabel?: string }>;

  const cweList = React.useMemo(() =>
    (detail.summary.cweIds ?? '').split(',').map(s => s.trim()).filter(Boolean),
    [detail.summary.cweIds]
  );

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

      {/* ── Overview Card ── */}
      {(() => {
        const epss = detail.summary.epssScore ?? item.epssScore;
        const nowMs = Date.now();
        const publishedMs = detail.summary.publishedAt ? new Date(detail.summary.publishedAt).getTime() : null;
        const kevMs = detail.summary.kevDueDate ? new Date(detail.summary.kevDueDate).getTime() : null;
        const daysAgo = publishedMs != null ? Math.floor((nowMs - publishedMs) / 86400000) : null;
        const kevOverdue = kevMs != null && kevMs < nowMs;

        // Derive a unified display status from available signals
        // Mirror the same invDone logic used by the Workflow badge below
        const invDoneForStatus =
          (persistedRunbookState?.assetAssessmentRan ?? false) ||
          latestInvestigation?.status === 'CLOSED' ||
          latestInvestigation?.status === 'PENDING_REVIEW';

        const isNotApplicable =
          item.applicability === 'NOT_APPLICABLE' ||
          (item.matchedAssetCount === 0 && item.applicableComponentCount === 0);
        // No Impact: S.AI score < 1 and all findings are closed
        const isNoImpact =
          !isNotApplicable &&
          riskResult.score < 1 &&
          item.openFindings === 0;
        // Reviewed: investigation workflow marked done
        const isReviewed =
          !isNotApplicable &&
          !isNoImpact &&
          invDoneForStatus;
        // Applicable = matched but not yet reviewed / no-impact
        const isApplicable = !isNotApplicable && !isNoImpact && !isReviewed;

        const statusPillLabel = isNotApplicable
          ? 'Not Applicable'
          : isNoImpact
            ? 'No Impact'
            : isReviewed
              ? 'Reviewed'
              : 'Applicable';

        const statusPillClass = isNotApplicable
          ? 'cvd-status-pill cvd-status-neutral'
          : isNoImpact
            ? 'cvd-status-pill cvd-status-ok'
            : isReviewed
              ? 'cvd-status-pill cvd-status-investigating'
              : isApplicable
                ? 'cvd-status-pill cvd-status-impacted'
                : 'cvd-status-pill cvd-status-neutral';

        const externalFacingTokens = ['public', 'internet', 'edge', 'gateway', 'vpn', 'dmz', 'web', 'api', 'proxy'];
        const externalFacingCount = softwareGroups.reduce((sum, g) => {
          const uniqueAssetIds = new Set<string>();
          g.assets.forEach(a => {
            const haystack = [a.assetName, a.assetIdentifier, a.packageName].filter(Boolean).join(' ').toLowerCase();
            if (externalFacingTokens.some(t => haystack.includes(t))) {
              uniqueAssetIds.add(a.assetIdentifier ?? a.assetId ?? a.componentId);
            }
          });
          return sum + uniqueAssetIds.size;
        }, 0);

        const invRan = persistedRunbookState?.assetAssessmentRan ?? false;
        const displayAssetCount = invRan
          ? (persistedRunbookState?.investigationAssetCount ?? detail.signals.assetCount)
          : detail.signals.assetCount;
        const displaySoftwareCount = invRan
          ? (persistedRunbookState?.investigationSoftwareCount ?? detail.signals.softwareCount)
          : detail.signals.softwareCount;

        return (
          <div className="cvd-overview-card">
            {/* ── Left column ── */}
            <div className="cvd-ov-left">
              {/* Status + last evaluated */}
              <div className="cvd-ov-meta">
                <span className={statusPillClass}>{statusPillLabel}</span>
                {item.lastEvaluatedAt && (
                  <span className="cvd-ov-meta-eval">· Last evaluated {formatDate(item.lastEvaluatedAt)}</span>
                )}
              </div>
              {publishedMs != null && daysAgo != null && (
                <div className="cvd-ov-first-seen">
                  First seen {formatDate(detail.summary.publishedAt!)}
                  {kevMs != null && (
                    <span className={kevOverdue ? ' cvd-ov-kev-overdue' : ''}>
                      {' '}· CISA KEV {kevOverdue
                        ? `overdue by ${Math.floor((nowMs - kevMs) / 86400000)}d`
                        : `due in ${Math.ceil((kevMs - nowMs) / 86400000)}d`}
                    </span>
                  )}
                </div>
              )}

              {/* Large CVE ID */}
              <h1 className="cvd-ov-cve-id">{item.externalId}</h1>

              {/* Badge pills */}
              <div className="cvd-ov-badges">
                <div className="cvd-score-wrap">
                  <div className="cvd-score-badge" style={{ background: riskResult.color }}>
                    <span className="cvd-score-num">{riskResult.score.toFixed(1)}</span>
                    <span className="cvd-score-label">{riskResult.label}</span>
                    <span className="cvd-score-symbol">✦</span>
                  </div>
                  <div className="cvd-score-tooltip" role="tooltip">
                    <div className="cvd-score-tooltip-heading">Why this score?</div>
                    {riskJourney.length > 0 && (
                      <div className="cvd-score-tooltip-journey">
                        {riskJourney.map((ev, i) => (
                          <div key={i} className="cvd-score-tooltip-row">
                            <span className="cvd-score-tooltip-stage">{ev.stage}</span>
                            {ev.delta !== 0 && (
                              <span className={`cvd-score-tooltip-delta${ev.delta > 0 ? ' up' : ' down'}`}>
                                {ev.delta > 0 ? '+' : ''}{ev.delta.toFixed(1)}
                              </span>
                            )}
                            <span className="cvd-score-tooltip-val">→ {ev.score.toFixed(1)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {riskResult.topReasons.length > 0 && (
                      <>
                        <div className="cvd-score-tooltip-divider" />
                        <div className="cvd-score-tooltip-heading">Key drivers</div>
                        {riskResult.topReasons.map((r, i) => (
                          <div key={i} className="cvd-score-tooltip-reason">· {r}</div>
                        ))}
                      </>
                    )}
                  </div>
                </div>
                {item.cvssScore != null && (
                  <span className="cvd-signal-pill">
                    CVSS {item.cvssScore.toFixed(1)}{item.severity ? ` · ${item.severity.toLowerCase()}` : ''}
                  </span>
                )}
                {epss != null && (
                  <span className="cvd-signal-pill">EPSS {(epss * 100).toFixed(1)}%</span>
                )}
                {item.matchedAssetCount > 0 && (
                  <span className="cvd-signal-pill">{item.matchedAssetCount} assets impacted</span>
                )}
                <span className="cvd-signal-pill">
                  Exploit: {detail.signals.exploitAvailable
                    ? (item.inKev ? 'in KEV' : 'active')
                    : 'none known'}
                </span>
                {item.inKev && <span className="cvd-signal-pill cvd-signal-pill--kev">CISA KEV</span>}
                {(() => {
                  const impact = computeOrgImpact(item, riskResult.score, externalFacingCount);
                  const impactStyle: React.CSSProperties =
                    impact === 'HIGH'
                      ? { background: '#9b233522', color: '#9b2335', border: '1px solid #9b233544' }
                      : impact === 'MEDIUM'
                        ? { background: '#b7791f22', color: '#b7791f', border: '1px solid #b7791f44' }
                        : impact === 'LOW'
                          ? { background: '#2d6a4f22', color: '#2d6a4f', border: '1px solid #2d6a4f44' }
                          : { background: 'var(--panel-muted)', color: 'var(--muted)', border: '1px solid var(--border)' };
                  const impactLabel = impact === 'NONE' ? 'No' : impact.charAt(0) + impact.slice(1).toLowerCase();
                  return (
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4,
                      padding: '2px 10px', borderRadius: 12,
                      fontSize: 12, fontWeight: 700, letterSpacing: '0.04em',
                      ...impactStyle,
                    }}>
                      Impact: {impactLabel}
                    </span>
                  );
                })()}
              </div>

              {/* Description */}
              <p className="cvd-ov-description">{detail.summary.description || 'No description available.'}</p>

              <div className="cvd-ov-divider" />

              {/* Links row */}
              <div className="cvd-ov-links">
                <button type="button" className="cvd-ov-link"
                  onClick={() => navigate(pathForVulnRepoCveAssets(item.externalId))}>
                  {displayAssetCount} assets →
                </button>
                <button type="button" className="cvd-ov-link"
                  onClick={() => navigate(pathForVulnRepoCveSoftware(item.externalId))}>
                  {displaySoftwareCount} software →
                </button>
                {externalFacingCount > 0 && (
                  <button type="button" className="cvd-ov-link"
                    onClick={() => navigate(pathForInventoryViewWithSearch('hosts', { quickFilter: 'external-with-cves' }))}>
                    {externalFacingCount} external facing →
                  </button>
                )}
                <button type="button" className="cvd-ov-link"
                  onClick={() => navigate(pathForFindingsWithFilters({ vulnerabilityId: item.externalId }))}>
                  {item.openFindings} open findings →
                </button>
                {aiActionsError && !aiActionsLoading && (
                  <span className="cvd-ov-err">{aiActionsError}</span>
                )}
              </div>
            </div>

            {/* ── Right column: S.AI mini chart ── */}
            <div className="cvd-ov-right">
              <CveRiskScorePanel item={item} mini />
            </div>
          </div>
        );
      })()}

      {/* ── Workflow Panel ───────────────────────────────── */}
      {(() => {
        const invRan = persistedRunbookState?.assetAssessmentRan ?? false;
        const invAssetCount = invRan ? (persistedRunbookState?.investigationAssetCount ?? detail.signals.assetCount) : detail.signals.assetCount;
        const invSwCount = invRan ? (persistedRunbookState?.investigationSoftwareCount ?? detail.signals.softwareCount) : detail.signals.softwareCount;
        const matchedByBackend = detail.matchedSoftware.length;
        const needsAssessment = detail.matchedSoftware.filter((s) => s.applicabilityState === 'UNKNOWN').length;
        const openFindings = item.openFindings;
        const findingsToCreate = invAssetCount > openFindings ? invAssetCount - openFindings : 0;
        const hasSummaryReport = item.hasInvestigationSummary;
        const notifiedAt = persistedRunbookState?.notifiedAt as string | undefined;

        // Investigation status: Done if asset assessment ran OR investigation closed/pending-review
        const invDone = invRan || latestInvestigation?.status === 'CLOSED' || latestInvestigation?.status === 'PENDING_REVIEW';
        const invInProgress = !invDone && (latestInvestigation != null || matchedByBackend > 0);
        const invStatus: 'done' | 'in-progress' | 'not-started' = invDone ? 'done' : invInProgress ? 'in-progress' : 'not-started';

        // Findings status
        const findingsDone = openFindings > 0 && findingsToCreate === 0;
        const findingsPartial = openFindings > 0 && findingsToCreate > 0;
        const findingsStatus: 'done' | 'partial' | 'not-created' = findingsDone ? 'done' : findingsPartial ? 'partial' : 'not-created';

        // Notify status
        const notifyStatus: 'communicated' | 'not-communicated' = notifiedAt ? 'communicated' : 'not-communicated';

        return (
          <div className="cvd-workflow-panel">
            <div className="cvd-workflow-header">
              <div>
                <span className="cvd-section-label">Workflow</span>
                <p className="cvd-workflow-sub">Move from investigation to finding creation and group notification.</p>
              </div>
            </div>

            <div className="cvd-wf-steps">
              {/* Step 1 — Investigation */}
              <button type="button" className="cvd-wf-step active" onClick={() => onStepChange(1)}>
                <div className="cvd-wf-num">1</div>
                <div className="cvd-wf-body">
                  <div className="cvd-wf-title-row">
                    <p className="cvd-wf-title">Investigation</p>
                    <div className="cvd-wf-badges">
                      {invStatus === 'done' && <span className="cvd-wf-badge cvd-wf-badge--done">✓ Done</span>}
                      {invStatus === 'in-progress' && <span className="cvd-wf-badge cvd-wf-badge--progress">● In Progress</span>}
                      {invStatus === 'not-started' && <span className="cvd-wf-badge cvd-wf-badge--pending">○ Not Started</span>}
                      {hasSummaryReport && (
                        <span className="cvd-wf-badge cvd-wf-badge--report" title="Investigation summary report generated">
                          📋 Report
                        </span>
                      )}
                    </div>
                  </div>
                  {invRan ? (
                    <p className="cvd-wf-sub">
                      {invSwCount} software · {invAssetCount} assets confirmed via asset inventory.
                    </p>
                  ) : (
                    <p className="cvd-wf-sub">
                      {matchedByBackend > 0
                        ? `${matchedByBackend} software matched${needsAssessment > 0 ? ` · ${needsAssessment} need asset inventory review` : ''}.`
                        : 'Open the runbook and confirm impacted assets via asset inventory.'}
                    </p>
                  )}
                  {!invRan && matchedByBackend > 0 && (
                    <p className="cvd-wf-insight">
                      Run asset inventory in the runbook to confirm exact impacted hosts.
                    </p>
                  )}
                </div>
              </button>

              {/* Step 2 — Create Findings */}
              <button type="button" className="cvd-wf-step" onClick={() => onStepChange(3)}>
                <div className="cvd-wf-num">2</div>
                <div className="cvd-wf-body">
                  <div className="cvd-wf-title-row">
                    <p className="cvd-wf-title">Create Findings</p>
                    <div className="cvd-wf-badges">
                      {findingsStatus === 'done' && <span className="cvd-wf-badge cvd-wf-badge--done">✓ Created</span>}
                      {findingsStatus === 'partial' && <span className="cvd-wf-badge cvd-wf-badge--progress">◑ Partial</span>}
                      {findingsStatus === 'not-created' && <span className="cvd-wf-badge cvd-wf-badge--pending">○ Not Created</span>}
                    </div>
                  </div>
                  {openFindings > 0 || invRan ? (
                    <p className="cvd-wf-sub">
                      {openFindings > 0 ? `${openFindings} finding${openFindings !== 1 ? 's' : ''} created` : '0 findings created'}
                      {findingsToCreate > 0 ? ` · ${findingsToCreate} to be created` : ' · up to date'}
                    </p>
                  ) : (
                    <p className="cvd-wf-sub">Add impacted assets to the backlog.</p>
                  )}
                </div>
              </button>

              {/* Step 3 — Notify Groups */}
              <button type="button" className="cvd-wf-step" onClick={() => onStepChange(4)}>
                <div className="cvd-wf-num">3</div>
                <div className="cvd-wf-body">
                  <div className="cvd-wf-title-row">
                    <p className="cvd-wf-title">Notify Groups</p>
                    <div className="cvd-wf-badges">
                      {notifyStatus === 'communicated'
                        ? <span className="cvd-wf-badge cvd-wf-badge--done">✓ Communicated</span>
                        : <span className="cvd-wf-badge cvd-wf-badge--pending">○ Not Communicated</span>}
                    </div>
                  </div>
                  <p className="cvd-wf-sub">
                    {notifiedAt ? `Notified on ${formatDate(notifiedAt)}.` : 'Alert remediation owners and assignment groups.'}
                  </p>
                </div>
              </button>
            </div>
          </div>
        );
      })()}

      {/* ── CVE Detail Content ───────────────────────────── */}
      <div className="cvd-content">

        {/* Technical details / CVSS  +  Weaknesses — side by side */}
        {(detail.summary.cvssVector || cweList.length > 0) && (() => {
          // Collect all unique sources referenced in this CVE
          const allSources = Array.from(new Set([
            ...(detail.summary.source ? [detail.summary.source] : []),
            ...detail.vendorIntelligence.map(v => v.source).filter(Boolean),
          ]));
          const multiSource = allSources.length > 1;

          // Per-source CVSS scores: primary from summary; secondary from vendorIntelligence if present
          const altScores = detail.vendorIntelligence.reduce<Array<{ source: string; score: number }>>((scores, intel) => {
            if (intel.source && intel.source !== detail.summary.source && typeof intel.cvssScore === 'number') {
              scores.push({ source: intel.source, score: intel.cvssScore });
            }
            return scores;
          }, []);

          return (
            <div className="cvd-tech-weakness-row">
              {detail.summary.cvssVector && (
                <div className="cvd-card cvd-tech-col">
                  <div className="cvd-technical-hdr">
                    <p className="cvd-section-label">Technical details · CVSS v3.1 vector</p>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {allSources.map(src => (
                        <span key={src} className="cvd-src-tag">{src}</span>
                      ))}
                    </div>
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
                  <div className="cvd-kv-table">
                    {CVSS_DIMS_LOCAL.map(({ key, label, values }) => {
                      const raw = cvssFields[key];
                      if (!raw) return null;
                      return (
                        <div key={key} className="cvd-kv-row">
                          <span className="cvd-kv-label">{label}</span>
                          <span className="cvd-kv-value">{(values as Record<string, string>)[raw] ?? raw}</span>
                        </div>
                      );
                    })}
                    {detail.summary.cvssScore != null && (
                      <div className="cvd-kv-row">
                        <span className="cvd-kv-label">CVSS score</span>
                        <span className="cvd-kv-value">
                          {detail.summary.cvssScore.toFixed(1)}
                          {multiSource && detail.summary.source && (
                            <span className="cvd-kv-src-inline">{detail.summary.source}</span>
                          )}
                          {altScores.map(alt => (
                            <React.Fragment key={alt.source}>
                              {' '}
                              <span className="cvd-kv-alt-val">
                                {alt.score.toFixed(1)}
                                <span className="cvd-kv-src-inline">{alt.source}</span>
                              </span>
                            </React.Fragment>
                          ))}
                        </span>
                      </div>
                    )}
                    {detail.summary.epssScore != null && (
                      <div className="cvd-kv-row">
                        <span className="cvd-kv-label">EPSS score</span>
                        <span className="cvd-kv-value">{(detail.summary.epssScore * 100).toFixed(2)}%</span>
                      </div>
                    )}
                    {detail.summary.publishedAt && (
                      <div className="cvd-kv-row">
                        <span className="cvd-kv-label">Published</span>
                        <span className="cvd-kv-value">{formatDate(detail.summary.publishedAt)}</span>
                      </div>
                    )}
                    {detail.summary.modifiedAt && (
                      <div className="cvd-kv-row">
                        <span className="cvd-kv-label">Last modified</span>
                        <span className="cvd-kv-value">{formatDate(detail.summary.modifiedAt)}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {cweList.length > 0 && (
                <div className="cvd-card cvd-card-flush cvd-weakness-col">
                  <div className="cvd-card-inset-hdr">
                    <p className="cvd-section-label">Weaknesses</p>
                    <span className="cvd-count-badge">{cweList.length} CWEs</span>
                  </div>
                  {cweList.map(cwe => (
                    <div key={cwe} className="cvd-entity-row">
                      <span className="cvd-entity-name">{cwe}</span>
                      {CWE_NAMES[cwe] && (
                        <span className="cvd-entity-versions">{CWE_NAMES[cwe]}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })()}

        {/* Solution */}
        <div className="cvd-card">
          <div className="cvd-solution-hdr">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button
                type="button"
                className="cvd-collapse-btn"
                onClick={() => setSolutionCollapsed(c => !c)}
                aria-label={solutionCollapsed ? 'Expand solution' : 'Collapse solution'}
              >
                {solutionCollapsed ? '▸' : '▾'}
              </button>
              <p className="cvd-section-label" style={{ margin: 0 }}>Solution</p>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {aiSolutionData && <span className="cvd-src-tag cvd-src-tag-ai">AI</span>}
              <span className={`severity-pill ${detail.signals.patchAvailable ? 'severity-low' : 'severity-high'}`}>
                {detail.signals.patchAvailable ? '✓ Available' : '⚠ Pending'}
              </span>
              <button
                type="button"
                className="cvd-ai-btn"
                disabled={aiSolutionLoading}
                onClick={async () => {
                  setAiSolutionLoading(true);
                  setAiSolutionError(null);
                  try {
                    const impactedProducts = affectedProducts.filter(p => p.totalAssetsImpacted > 0);
                    const advisoryUrls = referenceLinks
                      .filter(r =>
                        (r.tags && (r.tags.includes('Patch') || r.tags.includes('Vendor Advisory') || r.tags.includes('Mitigation'))) ||
                        (r.href && (
                          r.href.includes('msrc.microsoft.com') ||
                          r.href.includes('portal.msrc.microsoft.com') ||
                          r.href.includes('security.microsoft.com') ||
                          r.href.includes('access.redhat.com/security') ||
                          r.href.includes('ubuntu.com/security') ||
                          r.href.includes('security.gentoo.org') ||
                          r.href.includes('support.apple.com') ||
                          r.href.includes('cert.org')
                        ))
                      )
                      .map(r => r.href)
                      .slice(0, 5);
                    const context = {
                      cve_id: detail.summary.externalId,
                      severity: detail.summary.severity,
                      cvss_score: detail.summary.cvssScore,
                      title: detail.summary.title,
                      description: detail.summary.description,
                      in_kev: detail.summary.inKev,
                      kev_due_date: detail.summary.kevDueDate,
                      kev_required_action: detail.summary.kevRequiredAction,
                      patch_available: detail.signals.patchAvailable,
                      patch_versions: detail.signals.patchVersions,
                      exploit_available: detail.signals.exploitAvailable,
                      impacted_only: true,
                      affected_entities: impactedProducts.map(p => ({
                        product: p.product,
                        vendor: p.vendorName || p.vendor,
                        asset_count: p.totalAssetsImpacted,
                        affected_versions: p.affectedVersions,
                        is_eol: p.isEol,
                        eol_date: p.eolDate,
                      })),
                      vendor_intelligence: detail.vendorIntelligence?.map(v => ({
                        source: v.source,
                        package_name: v.packageName,
                        affected_versions: v.affectedVersions,
                        fixed_version: v.fixedVersion,
                        vex_status: v.vexStatus,
                      })),
                      advisory_urls: advisoryUrls,
                    };
                    const res = await cveWorkbenchApi.generateAiSolution(detail.summary.externalId, context);
                    if (res.success && res.data) {
                      setAiSolutionData(res.data);
                      setAiSolutionFallback(null);
                      setAiSolutionGeneratedAt(new Date().toISOString());
                      setSolutionCollapsed(false);
                    } else if (res.success && res.recommendation) {
                      setAiSolutionFallback(res.recommendation);
                    } else {
                      setAiSolutionError(res.recommendation ?? 'AI generation failed.');
                    }
                  } catch {
                    setAiSolutionError('Failed to generate AI recommendation. Please try again.');
                  } finally {
                    setAiSolutionLoading(false);
                  }
                }}
              >
                {aiSolutionLoading ? <span className="cvd-ai-btn-spinner" /> : '✦ Generate AI Recommendation'}
              </button>
            </div>
          </div>

          {!solutionCollapsed && <>
          {/* Default static card — shown when no AI data */}
          {!aiSolutionData && !aiSolutionFallback && (
            <div className="cvd-sol-card">
              <div className="cvd-sol-top">
                <span className="cvd-sol-title">{remediationText}</span>
                {detail.summary.source && <span className="cvd-src-tag">{detail.summary.source}</span>}
              </div>
              {aiSolutionError && (
                <p style={{ fontSize: 12, color: 'var(--danger, #d9534f)', marginTop: 6 }}>{aiSolutionError}</p>
              )}
              {detail.signals.patchAvailable && (
                <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                  <span className="severity-pill severity-low">Recommended</span>
                  <span className="cvd-pill-neutral">Full fix</span>
                </div>
              )}
            </div>
          )}

          {/* Fallback plain text */}
          {!aiSolutionData && aiSolutionFallback && (
            <div className="cvd-sol-card">
              <div className="cvd-sol-top">
                <span className="cvd-sol-title">{aiSolutionFallback}</span>
                <span className="cvd-src-tag cvd-src-tag-ai">AI</span>
              </div>
              <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                <span className="severity-pill severity-low">Recommended</span>
                <span className="cvd-pill-neutral">AI-generated</span>
              </div>
            </div>
          )}

          {/* Rich AI panel */}
          {aiSolutionData && (() => {
            const d = aiSolutionData;
            const phaseColor = (c: string) =>
              c === 'red' ? '#e53e3e' : c === 'amber' ? '#d97706' : '#16a34a';
            const dotColor = phaseColor;
            return (
              <div className="cvd-ai-panel">
                {/* Header with generated-at timestamp */}
                {(d.title || aiSolutionGeneratedAt) && (
                  <div className="cvd-ai-panel-hdr">
                    {d.title && <p className="cvd-ai-panel-title">{d.title}</p>}
                    {aiSolutionGeneratedAt && (
                      <span className="cvd-ai-panel-ts">
                        Generated {new Date(aiSolutionGeneratedAt).toLocaleString()}
                      </span>
                    )}
                  </div>
                )}
                {d.affected_scope && (
                  <p className="cvd-ai-scope">{d.affected_scope}</p>
                )}

                {/* Bottom Line */}
                {d.bottom_line && (
                  <div className="cvd-ai-bottom-line">
                    <p className="cvd-ai-section-hdr">The Bottom Line</p>
                    <div className="cvd-ai-bl-badges">
                      <span className={`severity-pill severity-${(d.bottom_line.severity || '').toLowerCase()}`}>{d.bottom_line.severity}</span>
                      {d.bottom_line.cvss && <span className="cvd-ai-bl-badge">CVSS {d.bottom_line.cvss}</span>}
                      {d.bottom_line.kev_status && <span className="cvd-ai-bl-badge">{d.bottom_line.kev_status}</span>}
                      {d.bottom_line.patch_status && (
                        <span className={`cvd-ai-bl-badge ${d.bottom_line.patch_status.includes('Available') ? 'cvd-ai-bl-badge-green' : 'cvd-ai-bl-badge-red'}`}>
                          {d.bottom_line.patch_status}
                        </span>
                      )}
                    </div>
                    {d.bottom_line.summary && <p className="cvd-ai-narrative">{d.bottom_line.summary}</p>}
                  </div>
                )}

                {/* What's Happening */}
                {d.what_is_happening && (
                  <div className="cvd-ai-section">
                    <p className="cvd-ai-section-hdr">What's Happening</p>
                    <p className="cvd-ai-narrative">{d.what_is_happening.description}</p>
                    {d.what_is_happening.attack_steps && d.what_is_happening.attack_steps.length > 0 && (
                      <ol className="cvd-ai-attack-steps">
                        {d.what_is_happening.attack_steps.map((s, i) => <li key={i}>{s}</li>)}
                      </ol>
                    )}
                    {d.what_is_happening.interaction_note && (
                      <p className="cvd-ai-interaction-note">{d.what_is_happening.interaction_note}</p>
                    )}
                  </div>
                )}

                {/* Primary Fix */}
                {d.primary_fix && (() => {
                  const val = (v: string | null | undefined) => (!v || v === 'null' || v === 'N/A') ? null : v;
                  const patchId = val(d.primary_fix.patch_id);
                  const targetVer = val(d.primary_fix.target_version);
                  const appliesTo = val(d.primary_fix.applies_to);
                  const verification = val(d.primary_fix.verification);
                  const action = val(d.primary_fix.action) ?? 'Apply';
                  return (
                    <div className="cvd-ai-primary-rec">
                      <p className="cvd-ai-primary-rec-label">Primary Fix</p>
                      <p className="cvd-ai-primary-rec-title">
                        {action}{patchId ? ` — ${patchId}` : ''}
                      </p>
                      {(targetVer || appliesTo || d.primary_fix.reboot_required != null) && (
                        <p className="cvd-ai-primary-rec-build">
                          {targetVer && <>Target version: <code className="cvd-ai-mono">{targetVer}</code></>}
                          {appliesTo && <span style={{ color: 'var(--muted)', marginLeft: targetVer ? 6 : 0 }}>· {appliesTo}</span>}
                          {d.primary_fix.reboot_required != null && (
                            <span style={{ color: 'var(--muted)', marginLeft: 6 }}>
                              · Reboot: {d.primary_fix.reboot_required ? 'Required' : 'Not required'}
                            </span>
                          )}
                        </p>
                      )}
                      {verification && (
                        <div className="cvd-ai-dep-row" style={{ marginTop: 6 }}>
                          <span className="cvd-ai-dep-badge" style={{ background: '#d1fae5', color: '#065f46', borderColor: '#6ee7b7' }}>✓ Verify</span>
                          <code className="cvd-ai-mono" style={{ marginLeft: 6 }}>{verification}</code>
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* Recommended Timeline */}
                {d.timeline && d.timeline.length > 0 && (
                  <div className="cvd-ai-section">
                    <p className="cvd-ai-seq-intro">Recommended Timeline</p>
                    <div className="cvd-ai-steps">
                      {d.timeline.map((t, i) => (
                        <div key={i} className="cvd-ai-step">
                          <div className="cvd-ai-step-dot" style={{ background: dotColor(t.color) }} />
                          <div className="cvd-ai-step-body">
                            <p className="cvd-ai-step-header">
                              <span style={{ color: phaseColor(t.color), fontWeight: 600 }}>{t.window}</span>
                              <span className="cvd-ai-step-dash"> — </span>
                              <span style={{ color: phaseColor(t.color) }}>{t.label}</span>
                            </p>
                            {t.actions && (
                              <ul className="cvd-ai-timeline-actions">
                                {t.actions.map((a, j) => <li key={j}>{a}</li>)}
                              </ul>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Compensating Controls */}
                {d.compensating_controls && d.compensating_controls.length > 0 && (
                  <div className="cvd-ai-section">
                    <p className="cvd-ai-section-hdr">Compensating Controls</p>
                    <table className="cvd-ai-ctrl-table">
                      <thead>
                        <tr>
                          <th>Control</th>
                          <th>Effort</th>
                          <th>Effectiveness</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.compensating_controls.map((c, i) => (
                          <tr key={i}>
                            <td>{c.control}</td>
                            <td><span className="cvd-ai-ctrl-badge">{c.effort}</span></td>
                            <td><span className="cvd-ai-ctrl-badge">{c.effectiveness}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Rollback Plan */}
                {d.rollback_plan && d.rollback_plan.length > 0 && (
                  <div className="cvd-ai-section">
                    <p className="cvd-ai-section-hdr">Rollback Plan</p>
                    <ol className="cvd-ai-rollback">
                      {d.rollback_plan.map((s, i) => <li key={i}>{s}</li>)}
                    </ol>
                  </div>
                )}

                {/* Lifecycle Warning */}
                {d.lifecycle_warning && (d.lifecycle_warning.is_eol || d.lifecycle_warning.upgrade_recommendation) && (
                  <div className="cvd-ai-lifecycle-warn">
                    <span className="cvd-ai-lifecycle-icon">⚠</span>
                    <div>
                      <p className="cvd-ai-lifecycle-title">
                        Lifecycle Warning{d.lifecycle_warning.product ? ` — ${d.lifecycle_warning.product}` : ''}
                      </p>
                      {d.lifecycle_warning.eol_date && (
                        <p className="cvd-ai-lifecycle-text">
                          End of Life: <strong>{d.lifecycle_warning.eol_date}</strong>
                          {d.lifecycle_warning.lifecycle_status && <> · {d.lifecycle_warning.lifecycle_status}</>}
                        </p>
                      )}
                      {d.lifecycle_warning.upgrade_recommendation && (
                        <p className="cvd-ai-lifecycle-upgrade">{d.lifecycle_warning.upgrade_recommendation}</p>
                      )}
                    </div>
                  </div>
                )}

                {/* Reasoning trace */}
                {d.reasoning_trace && d.reasoning_trace.length > 0 && (
                  <>
                    <div className="cvd-ai-trace" onClick={() => setAiTraceOpen(o => !o)} role="button" tabIndex={0} onKeyDown={e => e.key === 'Enter' && setAiTraceOpen(o => !o)}>
                      <span className="cvd-ai-trace-chevron">{aiTraceOpen ? '▾' : '▸'}</span>
                      <span className="cvd-ai-trace-label">Reasoning trace — {d.reasoning_trace.length} steps</span>
                    </div>
                    {aiTraceOpen && (
                      <ol className="cvd-ai-trace-list">
                        {d.reasoning_trace.map((step, i) => <li key={i}>{step}</li>)}
                      </ol>
                    )}
                  </>
                )}

                {/* Evidence gaps */}
                {d.evidence_gaps && (
                  <div className="cvd-ai-gaps">
                    <span className="cvd-ai-gaps-icon">ⓘ</span>
                    <div>
                      <p className="cvd-ai-gaps-title">Evidence Gaps</p>
                      <p className="cvd-ai-gaps-text">{d.evidence_gaps}</p>
                    </div>
                  </div>
                )}

                {/* Confidence */}
                {d.confidence_score != null && (
                  <div className="cvd-ai-confidence">
                    <div className="cvd-ai-conf-left">
                      <p className="cvd-ai-conf-label">Confidence</p>
                      <p className="cvd-ai-conf-score">{d.confidence_score}%</p>
                      <div className="cvd-ai-conf-bar">
                        <div className="cvd-ai-conf-fill" style={{ width: `${d.confidence_score}%` }} />
                      </div>
                    </div>
                    {d.confidence_rationale && <p className="cvd-ai-conf-rationale">{d.confidence_rationale}</p>}
                  </div>
                )}
              </div>
            );
          })()}
          </>}
        </div>

        {/* Tabs: Affected assets / References / Timeline */}
        <div className="cvd-card" style={{ padding: 0 }}>
          <div className="cvd-tab-bar">
            <button type="button" className={`cvd-tab-btn ${activeTab === 'assets' ? 'active' : ''}`} onClick={() => setActiveTab('assets')}>
              {persistedRunbookState?.assetAssessmentRan
                ? `Affected Entities · ${persistedRunbookState.investigationAssetCount ?? detail.signals.assetCount}`
                : `Affected Entities · ${detail.signals.assetCount}`}
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
              {/* Investigation assessment banner */}
              {persistedRunbookState?.assetAssessmentRan && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', marginBottom: 12,
                  background: 'color-mix(in srgb, var(--accent) 8%, var(--panel-muted))',
                  border: '1px solid color-mix(in srgb, var(--accent) 22%, var(--border))',
                  borderRadius: 8, fontSize: 12, color: 'var(--accent)',
                }}>
                  <span style={{ fontWeight: 700 }}>✓ Investigation assessment completed</span>
                  <span style={{ color: 'var(--muted)' }}>—</span>
                  <span style={{ color: 'var(--text)' }}>
                    {persistedRunbookState.investigationAssetCount ?? '—'} assets matched across{' '}
                    {persistedRunbookState.investigationSoftwareCount ?? (persistedRunbookState.assetCriteria?.filter(c => c.software.trim()).length ?? '—')} software
                  </span>
                  {persistedRunbookState.assetCriteria && persistedRunbookState.assetCriteria.filter(c => c.software.trim()).length > 0 && (
                    <span style={{ marginLeft: 'auto', color: 'var(--muted)' }}>
                      Assessed: {persistedRunbookState.assetCriteria.filter(c => c.software.trim()).map(c => [c.vendor, c.software, c.version].filter(Boolean).join('/') || c.software).join(', ')}
                    </span>
                  )}
                </div>
              )}
              {(() => {
                // When investigation has run, show the assessed software with their entity counts.
                // Otherwise fall back to the backend vendor-intelligence product list.
                const invRan = persistedRunbookState?.assetAssessmentRan ?? false;
                // Use persisted summary if available; otherwise build from assetCriteria (entity counts will be 0
                // until the user re-runs the assessment with the latest code that persists counts).
                const invSoftwareList: Array<{ software: string; vendor?: string; version?: string; assetCount: number }> =
                  persistedRunbookState?.investigationSoftwareSummary ??
                  (persistedRunbookState?.assetCriteria ?? [])
                    .filter((c) => c.software.trim().length > 0)
                    .map((c) => ({
                      software: c.software,
                      vendor: c.vendor?.trim() || undefined,
                      version: c.version?.trim() || '-',
                      assetCount: 0,
                    }));
                const useInvestigationList = invRan && invSoftwareList.length > 0;
                const viewAllHandler = invRan ? () => onStepChange(3) : onOpenAffectedEntities;
                const viewAllLabel = invRan ? 'View all impacted assets →' : 'View all affected entities →';

                return (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                    {/* Column headers */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '0 0 6px 0', borderBottom: '2px solid var(--border)' }}>
                      <div style={{ flex: '1 1 0', minWidth: 0 }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Software</span>
                      </div>
                      <div style={{ flexShrink: 0, minWidth: 100, textAlign: 'center' }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Vendor</span>
                      </div>
                      <div style={{ flexShrink: 0, minWidth: 110, textAlign: 'center' }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>EOL</span>
                      </div>
                      <div style={{ flexShrink: 0, minWidth: 120, textAlign: 'center' }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Vendor Advisory</span>
                      </div>
                      <div style={{ flexShrink: 0, minWidth: 120, textAlign: 'center' }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Support Group</span>
                      </div>
                      <div style={{ flexShrink: 0, width: 80, textAlign: 'right' }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Entities</span>
                      </div>
                    </div>

                    {useInvestigationList ? (
                      // Investigation-derived rows: one row per assessed software criterion
                      invSoftwareList.map((sw, i) => {
                        const count = sw.assetCount;
                        // Try to match EOL / VEX / support info from existing affectedProducts
                        const existing = affectedProducts.find(
                          (p) => normalizeAssetInventoryValue(p.product) === normalizeAssetInventoryValue(sw.software)
                        );
                        return (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '9px 0', borderBottom: '1px solid var(--border)' }}>
                            <div style={{ flex: '1 1 0', minWidth: 0 }}>
                              <p style={{ margin: 0, fontSize: 13, fontWeight: 500, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{sw.software}</p>
                              <p style={{ margin: 0, fontSize: 11, color: 'var(--muted)' }}>
                                {sw.version && sw.version !== '-' ? `Version · ${sw.version}` : 'All versions'}
                              </p>
                            </div>
                            <div style={{ flexShrink: 0, minWidth: 100, textAlign: 'center' }}>
                              {sw.vendor ? (
                                <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text)' }}>{sw.vendor}</span>
                              ) : existing?.vendorName ? (
                                <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text)' }}>{existing.vendorName}</span>
                              ) : (
                                <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                              )}
                            </div>
                            <div style={{ flexShrink: 0, minWidth: 110, textAlign: 'center' }}>
                              {existing?.isEol ? (
                                <span style={{ fontSize: 11, fontWeight: 600, color: '#e53e3e', background: '#fff5f5', border: '1px solid #feb2b2', borderRadius: 4, padding: '2px 6px' }}>
                                  EOL{existing.eolDate ? ` · ${existing.eolDate.slice(0, 10)}` : ''}
                                </span>
                              ) : existing?.supportPhase ? (
                                <span style={{ fontSize: 11, color: 'var(--muted)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px' }}>
                                  {existing.supportPhase}
                                </span>
                              ) : (
                                <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                              )}
                            </div>
                            <div style={{ flexShrink: 0, minWidth: 120, textAlign: 'center' }}>
                              {existing?.vendorAdvisory ? (
                                <span style={{
                                  fontSize: 11, fontWeight: 500, borderRadius: 4, padding: '2px 6px',
                                  background: existing.vendorAdvisory.toUpperCase().includes('NOT') ? '#f0fff4' : existing.vendorAdvisory.toUpperCase().includes('FIXED') ? '#ebf8ff' : '#fffff0',
                                  color: existing.vendorAdvisory.toUpperCase().includes('NOT') ? '#276749' : existing.vendorAdvisory.toUpperCase().includes('FIXED') ? '#2b6cb0' : '#744210',
                                  border: `1px solid ${existing.vendorAdvisory.toUpperCase().includes('NOT') ? '#9ae6b4' : existing.vendorAdvisory.toUpperCase().includes('FIXED') ? '#90cdf4' : '#f6e05e'}`,
                                }}>
                                  {existing.vendorAdvisory.replace(/_/g, ' ')}
                                </span>
                              ) : (
                                <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                              )}
                            </div>
                            <div style={{ flexShrink: 0, minWidth: 120, textAlign: 'center' }}>
                              {existing?.supportGroup ? (
                                <span style={{ fontSize: 11, color: 'var(--text)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px', display: 'inline-block', maxWidth: 116, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={existing.supportGroup}>
                                  {existing.supportGroup}
                                </span>
                              ) : (
                                <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => onStepChange(3)}
                              style={{
                                flexShrink: 0, width: 80, fontSize: 11, fontWeight: 600,
                                padding: '4px 0', borderRadius: 4, border: 'none', cursor: 'pointer', textAlign: 'center',
                                background: count > 20 ? '#fff5f5' : count > 5 ? '#fffbeb' : count > 0 ? '#f0fff4' : 'var(--surface)',
                                color: count > 20 ? '#c53030' : count > 5 ? '#b7791f' : count > 0 ? '#276749' : 'var(--muted)',
                              }}
                            >
                              {count} {count === 1 ? 'entity' : 'entities'}
                            </button>
                          </div>
                        );
                      })
                    ) : (
                      // Fallback: backend vendor-intelligence product list
                      affectedProducts.slice(0, 5).map((p, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '9px 0', borderBottom: '1px solid var(--border)' }}>
                          <div style={{ flex: '1 1 0', minWidth: 0 }}>
                            <p style={{ margin: 0, fontSize: 13, fontWeight: 500, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.product}</p>
                            <p style={{ margin: 0, fontSize: 11, color: 'var(--muted)' }}>Affected versions · {p.affectedVersions}</p>
                          </div>
                          <div style={{ flexShrink: 0, minWidth: 100, textAlign: 'center' }}>
                            {p.vendorName ? (
                              <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text)' }}>{p.vendorName}</span>
                            ) : (
                              <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                            )}
                          </div>
                          <div style={{ flexShrink: 0, minWidth: 110, textAlign: 'center' }}>
                            {p.isEol ? (
                              <span style={{ fontSize: 11, fontWeight: 600, color: '#e53e3e', background: '#fff5f5', border: '1px solid #feb2b2', borderRadius: 4, padding: '2px 6px' }}>
                                EOL{p.eolDate ? ` · ${p.eolDate.slice(0, 10)}` : ''}
                              </span>
                            ) : p.eolDate ? (
                              <span style={{ fontSize: 11, color: '#d97706', background: '#fffbeb', border: '1px solid #fcd34d', borderRadius: 4, padding: '2px 6px' }}>
                                EOL {p.eolDate.slice(0, 10)}
                              </span>
                            ) : p.supportPhase ? (
                              <span style={{ fontSize: 11, color: 'var(--muted)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px' }}>
                                {p.supportPhase}
                              </span>
                            ) : (
                              <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                            )}
                          </div>
                          <div style={{ flexShrink: 0, minWidth: 120, textAlign: 'center' }}>
                            {p.vendorAdvisory ? (
                              <span style={{
                                fontSize: 11, fontWeight: 500, borderRadius: 4, padding: '2px 6px',
                                background: p.vendorAdvisory.toUpperCase().includes('NOT') ? '#f0fff4' : p.vendorAdvisory.toUpperCase().includes('FIXED') ? '#ebf8ff' : '#fffff0',
                                color: p.vendorAdvisory.toUpperCase().includes('NOT') ? '#276749' : p.vendorAdvisory.toUpperCase().includes('FIXED') ? '#2b6cb0' : '#744210',
                                border: `1px solid ${p.vendorAdvisory.toUpperCase().includes('NOT') ? '#9ae6b4' : p.vendorAdvisory.toUpperCase().includes('FIXED') ? '#90cdf4' : '#f6e05e'}`,
                              }}>
                                {p.vendorAdvisory.replace(/_/g, ' ')}
                              </span>
                            ) : (
                              <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                            )}
                          </div>
                          <div style={{ flexShrink: 0, minWidth: 120, textAlign: 'center' }}>
                            {p.supportGroup ? (
                              <span style={{ fontSize: 11, color: 'var(--text)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px', display: 'inline-block', maxWidth: 116, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={p.supportGroup}>
                                {p.supportGroup}
                              </span>
                            ) : (
                              <span style={{ fontSize: 11, color: 'var(--muted)' }}>—</span>
                            )}
                          </div>
                          <button
                            type="button"
                            onClick={onOpenAffectedEntities}
                            style={{
                              flexShrink: 0, width: 80, fontSize: 11, fontWeight: 600,
                              padding: '4px 0', borderRadius: 4, border: 'none', cursor: 'pointer', textAlign: 'center',
                              background: p.totalAssetsImpacted > 20 ? '#fff5f5' : p.totalAssetsImpacted > 5 ? '#fffbeb' : '#f0fff4',
                              color: p.totalAssetsImpacted > 20 ? '#c53030' : p.totalAssetsImpacted > 5 ? '#b7791f' : p.totalAssetsImpacted > 0 ? '#276749' : 'var(--muted)',
                            }}
                          >
                            {p.totalAssetsImpacted} {p.totalAssetsImpacted === 1 ? 'entity' : 'entities'}
                          </button>
                        </div>
                      ))
                    )}

                    <button type="button" className="cvd-link-btn" style={{ alignSelf: 'flex-start', marginTop: 6 }} onClick={viewAllHandler}>
                      {viewAllLabel}
                    </button>
                  </div>
                );
              })()}
            </div>
          )}

          {activeTab === 'refs' && (
            <div className="cvd-refs-list">
              {referenceLinks.length === 0 ? (
                <p className="cvd-tab-empty">No references available.</p>
              ) : (
                referenceLinks.map(ref => (
                  <div key={ref.href} className="cvd-ref-row">
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <a href={ref.href} target="_blank" rel="noreferrer" className="cvd-ref-link"
                        style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ref.href}
                      </a>
                      {ref.source && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(ref.source) && (
                        <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, display: 'block' }}>{ref.source}</span>
                      )}
                    </div>
                    {ref.tags && ref.tags.length > 0 && (
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', flexShrink: 0 }}>
                        {ref.tags.map(tag => (
                          <span key={tag} className="cvd-src-tag">{tag}</span>
                        ))}
                      </div>
                    )}
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
                      {entry.sublabel && <p style={{ margin: '2px 0 0', fontSize: 11, color: 'var(--muted)', fontStyle: 'italic' }}>{entry.sublabel}</p>}
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
  searchQuery: string;
  severity: string;
  findingIdsByComponentId: Map<string, string>;
  findingsByDisplayId?: Map<string, Finding>;
  analystFpOverrides: Set<string>;
  onToggleRow: (id: string) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
  onSearchQueryChange: (v: string) => void;
  onOpenCreatePanel: () => void;
  onOpenAsset: (sw: CveMatchedSoftware) => void;
  onOpenFinding?: (displayId: string, finding?: Finding) => void;
  onBulkFpMark?: (softwareKeys: string[]) => void;
  onBulkFpUnmark?: (softwareKeys: string[]) => void;
};

function FindingsContent({
  filteredSoftware, selectedIds, searchQuery: _searchQuery, severity, findingIdsByComponentId,
  findingsByDisplayId,
  analystFpOverrides,
  onToggleRow, onSelectAll: _onSelectAll, onClearAll, onSearchQueryChange: _onSearchQueryChange, onOpenCreatePanel, onOpenAsset,
  onOpenFinding,
  onBulkFpMark, onBulkFpUnmark,
}: FindingsContentProps) {
  // Total impacted assets (unfiltered)
  const impactedAssets = new Set(
    filteredSoftware.filter((row) => row.selectable).map((row) => row.software.assetId ?? row.software.assetIdentifier ?? row.software.assetName ?? row.software.componentId)
  ).size;

  // Column-level filter state
  const [colFilterAsset, setColFilterAsset] = React.useState('');
  const [colFilterFindingId, setColFilterFindingId] = React.useState('');
  const [colFilterSoftware, setColFilterSoftware] = React.useState('');
  const [colFilterFp, setColFilterFp] = React.useState<'ALL' | 'YES' | 'NO'>('ALL');
  const [colFilterSupportGroup, setColFilterSupportGroup] = React.useState('');
  const [colFilterPriority, setColFilterPriority] = React.useState('ALL');
  const [bulkEditOpen, setBulkEditOpen] = React.useState(false);

  const columnFilteredRows = React.useMemo(() => {
    return filteredSoftware.filter((row) => {
      const sw = row.software;
      const fpKey = `${sw.packageName}::${sw.version ?? '-'}`;
      const isFp = analystFpOverrides.has(sw.componentId) || analystFpOverrides.has(fpKey);
      const pri = priorityFromSeverityAndImpact(severity, row.displayImpact);
      if (colFilterAsset && !`${sw.assetName ?? ''} ${sw.assetIdentifier ?? ''} ${sw.componentId}`.toLowerCase().includes(colFilterAsset.toLowerCase())) return false;
      if (colFilterFindingId) {
        const fid = findingIdsByComponentId.get(sw.componentId) ?? findingIdsByComponentId.get(`${sw.assetIdentifier}::${sw.packageName}::${sw.version}`) ?? '-';
        if (!fid.toLowerCase().includes(colFilterFindingId.toLowerCase())) return false;
      }
      if (colFilterSoftware && !`${sw.packageName} ${sw.version ?? ''}`.toLowerCase().includes(colFilterSoftware.toLowerCase())) return false;
      if (colFilterFp === 'YES' && !isFp) return false;
      if (colFilterFp === 'NO' && isFp) return false;
      if (colFilterSupportGroup && !(ownershipSupportGroup(sw) ?? '').toLowerCase().includes(colFilterSupportGroup.toLowerCase())) return false;
      if (colFilterPriority !== 'ALL' && pri !== colFilterPriority) return false;
      return true;
    });
  }, [filteredSoftware, analystFpOverrides, colFilterAsset, colFilterFindingId, colFilterSoftware, colFilterFp, colFilterSupportGroup, colFilterPriority, severity, findingIdsByComponentId]);

  // Selection state derived from the post-filter visible rows
  const selectableRows = columnFilteredRows.filter((row) => row.selectable);
  const allSelected = selectableRows.length > 0 && selectableRows.every((row) => selectedIds.has(row.software.componentId));
  const someSelected = selectableRows.some((row) => selectedIds.has(row.software.componentId));
  const selectedRows = columnFilteredRows.filter((row) => selectedIds.has(row.software.componentId));

  return (
    <div className="cve-findings-selection-panel">
      <div className="cve-findings-asset-section">
        {/* Bulk Edit toolbar */}
        <div className="cve-findings-bulk-bar">
          <span className="cve-findings-bulk-stat">Total Assets: <strong>{impactedAssets}</strong></span>
          <span className="cve-findings-bulk-stat">Selected Assets: <strong>{selectedRows.length}</strong></span>
          <div style={{ flex: 1 }} />
          <div style={{ position: 'relative' }}>
            <button
              type="button"
              className="btn btn-secondary cve-findings-bulk-btn"
              onClick={() => setBulkEditOpen((v) => !v)}
              disabled={selectedIds.size === 0}
            >
              Bulk Edit
              <svg viewBox="0 0 10 6" width="10" height="6" style={{ marginLeft: 6 }} aria-hidden="true">
                <path d="M1 1l4 4 4-4" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" />
              </svg>
            </button>
            {bulkEditOpen && (
              <div className="cve-findings-bulk-menu">
                <button
                  type="button"
                  className="cve-findings-bulk-menu-item"
                  onClick={() => {
                    const keys = selectedRows.map((r) => `${r.software.packageName}::${r.software.version ?? '-'}`);
                    onBulkFpMark?.(keys);
                    setBulkEditOpen(false);
                  }}
                >
                  Mark as False Positive
                </button>
                <button
                  type="button"
                  className="cve-findings-bulk-menu-item"
                  onClick={() => {
                    const keys = selectedRows.map((r) => `${r.software.packageName}::${r.software.version ?? '-'}`);
                    onBulkFpUnmark?.(keys);
                    setBulkEditOpen(false);
                  }}
                >
                  Unmark False Positive
                </button>
                <div className="cve-findings-bulk-menu-divider" />
                <button
                  type="button"
                  className="cve-findings-bulk-menu-item"
                  onClick={() => { onClearAll(); setBulkEditOpen(false); }}
                >
                  Clear Selection
                </button>
              </div>
            )}
          </div>
          <button type="button" className={`btn ${selectedIds.size > 0 ? 'btn-primary' : 'btn-secondary'}`} onClick={onOpenCreatePanel} disabled={selectedIds.size === 0}>
            Create Findings
          </button>
        </div>

        <table className="cve-findings-asset-table">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={(el) => { if (el) el.indeterminate = someSelected && !allSelected; }}
                  onChange={() => {
                    if (allSelected) {
                      selectableRows.forEach((row) => {
                        if (selectedIds.has(row.software.componentId)) onToggleRow(row.software.componentId);
                      });
                    } else {
                      selectableRows.forEach((row) => {
                        if (!selectedIds.has(row.software.componentId)) onToggleRow(row.software.componentId);
                      });
                    }
                  }}
                  disabled={selectableRows.length === 0}
                />
              </th>
              <th>ASSET / CI</th>
              <th>FINDING ID</th>
              <th>SOFTWARE</th>
              <th>FALSE POSITIVE</th>
              <th>SUPPORT GROUP</th>
              <th>OWNER</th>
              <th>PRIORITY</th>
              <th>INCIDENT ID</th>
            </tr>
            {/* Inline column filters */}
            <tr className="cve-findings-col-filter-row">
              <th />
              <th>
                <input
                  type="search"
                  className="cve-findings-col-filter-input"
                  placeholder="Filter asset…"
                  value={colFilterAsset}
                  onChange={(e) => setColFilterAsset(e.target.value)}
                />
              </th>
              <th>
                <input
                  type="search"
                  className="cve-findings-col-filter-input"
                  placeholder="Filter ID…"
                  value={colFilterFindingId}
                  onChange={(e) => setColFilterFindingId(e.target.value)}
                />
              </th>
              <th>
                <input
                  type="search"
                  className="cve-findings-col-filter-input"
                  placeholder="Filter software…"
                  value={colFilterSoftware}
                  onChange={(e) => setColFilterSoftware(e.target.value)}
                />
              </th>
              <th>
                <select
                  className="cve-findings-col-filter-select"
                  value={colFilterFp}
                  onChange={(e) => setColFilterFp(e.target.value as 'ALL' | 'YES' | 'NO')}
                >
                  <option value="ALL">All</option>
                  <option value="YES">Yes</option>
                  <option value="NO">No</option>
                </select>
              </th>
              <th>
                <input
                  type="search"
                  className="cve-findings-col-filter-input"
                  placeholder="Filter group…"
                  value={colFilterSupportGroup}
                  onChange={(e) => setColFilterSupportGroup(e.target.value)}
                />
              </th>
              <th />
              <th>
                <select
                  className="cve-findings-col-filter-select"
                  value={colFilterPriority}
                  onChange={(e) => setColFilterPriority(e.target.value)}
                >
                  <option value="ALL">All</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </th>
              <th />
            </tr>
          </thead>
          <tbody>
            {columnFilteredRows.map((row) => {
              const sw = row.software;
              const checked = selectedIds.has(sw.componentId);
              const pri = priorityFromSeverityAndImpact(severity, row.displayImpact);
              const findingId = findingIdsByComponentId.get(sw.componentId)
                ?? (() => {
                  const identityKey = findingIdentityKey(sw.assetIdentifier, sw.packageName, sw.version);
                  return identityKey ? findingIdsByComponentId.get(identityKey) : undefined;
                })()
                ?? '-';
              const fpSoftwareKey = `${sw.packageName}::${sw.version ?? '-'}`;
              const isFalsePositive = analystFpOverrides.has(sw.componentId) || analystFpOverrides.has(fpSoftwareKey);
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
                        <button
                          type="button"
                          className="cve-findings-asset-link"
                          onClick={(e) => { e.stopPropagation(); onOpenAsset(sw); }}
                        >
                          {sw.assetName ?? sw.assetIdentifier ?? sw.componentId}
                        </button>
                        <div className="panel-caption mono">{sw.assetIdentifier ?? sw.assetId ?? sw.componentId}</div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                          <span
                            style={{
                              fontSize: 11,
                              color: 'var(--text)',
                              background: 'var(--surface)',
                              border: '1px solid var(--border)',
                              borderRadius: 999,
                              padding: '2px 8px',
                              display: 'inline-block',
                              maxWidth: 180,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}
                            title={ownershipDisplayName(sw)}
                          >
                            {ownershipDisplayName(sw)}
                          </span>
                          {ownershipSupportGroup(sw) && (
                            <span
                              style={{
                                fontSize: 11,
                                color: 'var(--muted)',
                                background: 'var(--panel)',
                                border: '1px solid var(--border)',
                                borderRadius: 999,
                                padding: '2px 8px',
                                display: 'inline-block',
                                maxWidth: 180,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}
                              title={ownershipSupportGroup(sw)}
                            >
                              {ownershipSupportGroup(sw)}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {findingId !== '-' && onOpenFinding
                      ? (
                        <button
                          type="button"
                          className="finding-id-link mono"
                          onClick={() => onOpenFinding(findingId, findingsByDisplayId?.get(findingId))}
                        >
                          {findingId}
                        </button>
                      )
                      : <span className="mono">{findingId !== '-' ? findingId : '—'}</span>
                    }
                  </td>
                  <td>{sw.packageName}{sw.version ? ` ${sw.version}` : ''}</td>
                  <td>
                    {isFalsePositive
                      ? <span className="cve-fp-yes-badge">Yes</span>
                      : <span style={{ color: 'var(--muted)', fontSize: 12 }}>—</span>}
                  </td>
                  <td><span style={{ fontSize: 13 }}>{ownershipSupportGroup(sw) ?? '—'}</span></td>
                  <td><span style={{ fontSize: 13 }}>{sw.analystReason ?? '—'}</span></td>
                  <td><span className={severityClassName(pri)}>{formatLabel(pri)}</span></td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {(() => {
                      const finding = findingId !== '-' ? findingsByDisplayId?.get(findingId) : undefined;
                      return finding?.incidentId
                        ? <span className="mono" style={{ fontSize: 12 }}>{finding.incidentId}</span>
                        : <span style={{ color: 'var(--muted)', fontSize: 12 }}>—</span>;
                    })()}
                  </td>
                </tr>
              );
            })}
            {columnFilteredRows.length === 0 && (
              <tr>
                <td colSpan={9} className="cve-findings-empty-row">
                  No impacted asset rows match the current filter. Save your investigation assessment first, then navigate here.
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
  availableGroups: string[];
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
  availableGroups,
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
  const _selectedAssetCount = new Set(
    selectedSoftware.map((software) => software.assetId ?? software.assetIdentifier ?? software.componentId)
  ).size;
  const _selectedSoftwareCount = new Set(selectedSoftware.map((software) => software.packageName)).size;
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

          {ownershipMode === 'ASSIGNMENT_GROUP' && (
            <div className="cve-form-field">
              <label htmlFor="assignment-group">Assignment Group</label>
              <input
                id="assignment-group"
                type="text"
                list="assignment-groups-list"
                value={assignmentGroup}
                onChange={(e) => onAssignmentGroupChange(e.target.value)}
                placeholder={availableGroups.length > 0 ? 'Select or type a group…' : 'e.g. IT Infrastructure'}
              />
              {availableGroups.length > 0 && (
                <datalist id="assignment-groups-list">
                  {availableGroups.map((g) => (
                    <option key={g} value={g} />
                  ))}
                </datalist>
              )}
            </div>
          )}

          <label className="cve-findings-snow-checkbox-label">
            Create tickets in ServiceNow
            <input
              type="checkbox"
              checked={ticketTarget === 'SERVICENOW'}
              onChange={(e) => onTicketTargetChange(e.target.checked ? 'SERVICENOW' : 'JIRA')}
            />
          </label>

          <div className="cve-form-field">
            <label htmlFor="finding-notes">Notes</label>
            <textarea
              id="finding-notes"
              rows={3}
              value={findingNotes}
              onChange={(e) => onFindingNotesChange(e.target.value)}
              placeholder="Describe the remediation approach or ticket creation context..."
            />
          </div>

          <div className="cve-findings-modal-actions">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Close
            </button>
            <button type="button" className="btn btn-primary" onClick={onConfirm} disabled={findingBusy || selectedIds.size === 0}>
              {findingBusy ? 'Creating...' : `Create Findings (${selectedIds.size})`}
            </button>
          </div>
        </div>
      </div>
    </aside>
  );
}

// --- Notify Groups Panel ---

type NotifyTemplate = 'kev-urgent' | 'standard-patch' | 'advisory-only' | 'exception-follow-up';
type NotifyView = 'compose' | 'preview' | 'per-team';

const NOTIFY_TEMPLATES: Record<NotifyTemplate, { label: string; subject: string; body: string }> = {
  'kev-urgent': {
    label: 'KEV urgent',
    subject: '[Action required · KEV] Patch {{cve_id}} by {{due_date}}',
    body: `Hi {{owner_name}},

Scout has identified {{asset_count}} asset(s) on your team affected by {{cve_id}} — a {{severity}}, actively-exploited vulnerability listed in the CISA Known Exploited Vulnerabilities catalog.

Your affected assets:
{{asset_list}}

What we need from you by {{due_date}}:
• Apply the available patch immediately
• Confirm remediation in the security ticketing system
• Escalate any blockers to the security team

Please reach out if you need assistance.

Regards,
Security Operations`,
  },
  'standard-patch': {
    label: 'Standard patch',
    subject: '[Patch required] {{cve_id}} affects {{asset_count}} asset(s) – remediate by {{due_date}}',
    body: `Hi {{owner_name}},

This is a routine patch notification. {{asset_count}} asset(s) managed by your team are affected by {{cve_id}} ({{severity}}).

Affected assets:
{{asset_list}}

Please apply available patches by {{due_date}} and confirm remediation via the security portal.

Regards,
Security Operations`,
  },
  'advisory-only': {
    label: 'Advisory only',
    subject: '[Advisory] {{cve_id}} – informational notice for your team',
    body: `Hi {{owner_name}},

This is an informational advisory. {{asset_count}} asset(s) on your team may be affected by {{cve_id}} ({{severity}}). No immediate action is required at this time.

Potentially affected assets:
{{asset_list}}

We will follow up if the risk posture changes. Please review at your convenience.

Regards,
Security Operations`,
  },
  'exception-follow-up': {
    label: 'Exception follow-up',
    subject: '[Follow-up] {{cve_id}} – remediation status update required',
    body: `Hi {{owner_name}},

This is a follow-up regarding {{cve_id}}. We still show {{asset_count}} open finding(s) for assets on your team:

{{asset_list}}

If remediation is complete, please update the ticket status. If you have an approved exception, please document it in the security portal by {{due_date}}.

Thank you,
Security Operations`,
  },
};

type NotifyGroupInfo = {
  name: string;
  assetNames: string[];
  packageNames: string[];
  impactedCount: number;
  isImpacted: boolean;
};

function buildNotifyGroupInfo(detail: CveDetail): Map<string, NotifyGroupInfo> {
  const map = new Map<string, NotifyGroupInfo>();
  for (const sw of detail.matchedSoftware) {
    const group = ownershipSupportGroup(sw);
    if (!group) continue;
    const isImpacted = sw.impactState === 'IMPACTED' || sw.computedImpactState === 'IMPACTED';
    const existing = map.get(group);
    if (existing) {
      if (sw.assetName && !existing.assetNames.includes(sw.assetName)) existing.assetNames.push(sw.assetName);
      if (sw.assetIdentifier && !existing.assetNames.includes(sw.assetIdentifier)) {
        // prefer assetName already handled
      }
      if (!existing.packageNames.includes(sw.packageName)) existing.packageNames.push(sw.packageName);
      if (isImpacted) { existing.impactedCount++; existing.isImpacted = true; }
    } else {
      map.set(group, {
        name: group,
        assetNames: sw.assetName ? [sw.assetName] : (sw.assetIdentifier ? [sw.assetIdentifier] : []),
        packageNames: [sw.packageName],
        impactedCount: isImpacted ? 1 : 0,
        isImpacted,
      });
    }
  }
  return map;
}

function applyNotifyTokens(template: string, tokens: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => tokens[key] ?? `{{${key}}}`);
}

type NotifyGroupsPanelProps = {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail;
  availableGroups: string[];
  dueDate: string;
  onNotified: (at: string) => void;
};

function NotifyGroupsPanel({ item, detail, availableGroups, dueDate, onNotified }: NotifyGroupsPanelProps) {
  const groupInfoFromSoftware = React.useMemo(() => buildNotifyGroupInfo(detail), [detail]);

  const allGroupNames = React.useMemo(() => {
    const fromSoftware = Array.from(groupInfoFromSoftware.keys());
    const extras = availableGroups.filter((g) => !groupInfoFromSoftware.has(g));
    return [...fromSoftware, ...extras];
  }, [groupInfoFromSoftware, availableGroups]);

  const [selectedGroups, setSelectedGroups] = React.useState<Set<string>>(
    () => new Set(Array.from(groupInfoFromSoftware.entries()).filter(([, info]) => info.isImpacted).map(([name]) => name))
  );

  const initialTemplate: NotifyTemplate = item.inKev ? 'kev-urgent' : 'standard-patch';
  const [template, setTemplate] = React.useState<NotifyTemplate>(initialTemplate);
  const [view, setView] = React.useState<NotifyView>('compose');
  const [subject, setSubject] = React.useState(() => NOTIFY_TEMPLATES[initialTemplate].subject);
  const [msgBody, setMsgBody] = React.useState(() => NOTIFY_TEMPLATES[initialTemplate].body);
  const [sending, setSending] = React.useState(false);
  const [sent, setSent] = React.useState(false);

  const totalAssets = React.useMemo(() => {
    const names = new Set<string>();
    for (const name of selectedGroups) {
      const info = groupInfoFromSoftware.get(name);
      if (info) info.assetNames.forEach((a) => names.add(a));
    }
    return names.size;
  }, [selectedGroups, groupInfoFromSoftware]);

  function applyTemplate(t: NotifyTemplate): void {
    setTemplate(t);
    setSubject(NOTIFY_TEMPLATES[t].subject);
    setMsgBody(NOTIFY_TEMPLATES[t].body);
  }

  function toggleGroup(name: string): void {
    setSelectedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }

  function insertToken(tok: string): void {
    setMsgBody((prev) => `${prev}{{${tok}}}`);
  }

  function getTokens(groupName?: string): Record<string, string> {
    const info = groupName ? groupInfoFromSoftware.get(groupName) : undefined;
    const assetList = info
      ? info.assetNames.join('\n')
      : Array.from(selectedGroups).flatMap((g) => groupInfoFromSoftware.get(g)?.assetNames ?? []).join('\n');
    return {
      owner_name: groupName ?? (selectedGroups.size === 1 ? Array.from(selectedGroups)[0] : 'Team'),
      asset_count: String(info ? info.assetNames.length : totalAssets),
      asset_list: assetList || '(no matched assets)',
      cve_id: item.externalId,
      severity: item.severity ?? 'Critical',
      due_date: dueDate || 'TBD',
    };
  }

  async function handleSend(): Promise<void> {
    setSending(true);
    await new Promise<void>((r) => setTimeout(r, 900));
    setSending(false);
    setSent(true);
    onNotified(new Date().toISOString());
  }

  return (
    <div className="notify-panel">
      {/* ── Left: Recipients ── */}
      <aside className="notify-panel__left">
        <div className="notify-panel__col-header">
          <h3 className="notify-panel__col-title">Recipients</h3>
          <span className="notify-panel__col-meta">{selectedGroups.size} group{selectedGroups.size !== 1 ? 's' : ''} · {totalAssets} asset{totalAssets !== 1 ? 's' : ''}</span>
        </div>

        <div className="notify-filter-chips">
          <button type="button" className="notify-filter-chip notify-filter-chip--active" onClick={() => setSelectedGroups(new Set(allGroupNames))}>All teams</button>
          <button type="button" className="notify-filter-chip" onClick={() => setSelectedGroups(new Set(Array.from(groupInfoFromSoftware.entries()).filter(([, i]) => i.isImpacted).map(([n]) => n)))}>Impacted only</button>
          <button type="button" className="notify-filter-chip" onClick={() => setSelectedGroups(new Set())}>Clear</button>
        </div>

        <ul className="notify-group-list">
          {allGroupNames.map((name) => {
            const info = groupInfoFromSoftware.get(name);
            const checked = selectedGroups.has(name);
            return (
              <li key={name} className={`notify-group-item${checked ? ' notify-group-item--checked' : ''}`}>
                <label className="notify-group-item__label">
                  <input type="checkbox" checked={checked} onChange={() => toggleGroup(name)} />
                  <div className="notify-group-item__body">
                    <div className="notify-group-item__name-row">
                      <span className="notify-group-item__name">{name}</span>
                      {info?.isImpacted && <span className="notify-group-badge">Primary</span>}
                    </div>
                    <div className="notify-group-item__meta">
                      {info ? (
                        <>
                          {info.assetNames.length} asset{info.assetNames.length !== 1 ? 's' : ''}
                          {info.packageNames.length > 0 && (
                            <> · {info.packageNames.slice(0, 2).join(', ')}{info.packageNames.length > 2 ? `, +${info.packageNames.length - 2}` : ''}</>
                          )}
                        </>
                      ) : 'No matched assets for this CVE'}
                    </div>
                  </div>
                </label>
              </li>
            );
          })}
          {allGroupNames.length === 0 && (
            <li className="notify-group-empty">No assignment groups found. Sync CMDB to populate groups.</li>
          )}
        </ul>
      </aside>

      {/* ── Right: Compose / Preview ── */}
      <div className="notify-panel__right">
        <div className="notify-panel__col-header">
          <div className="notify-view-tabs">
            {(['compose', 'preview', 'per-team'] as NotifyView[]).map((v) => (
              <button key={v} type="button" className={`notify-view-tab${view === v ? ' notify-view-tab--active' : ''}`} onClick={() => setView(v)}>
                {v === 'compose' ? 'Compose' : v === 'preview' ? 'Preview' : 'Per team'}
              </button>
            ))}
          </div>
        </div>

        <div className="notify-template-row">
          <span className="notify-template-label">Template:</span>
          {(Object.keys(NOTIFY_TEMPLATES) as NotifyTemplate[]).map((t) => (
            <button key={t} type="button" className={`notify-template-chip${template === t ? ' notify-template-chip--active' : ''}`} onClick={() => applyTemplate(t)}>
              {NOTIFY_TEMPLATES[t].label}
            </button>
          ))}
        </div>

        {view === 'compose' && (
          <div className="notify-compose">
            <div className="notify-compose__field">
              <label className="notify-compose__label">Subject</label>
              <input className="notify-compose__subject" type="text" value={subject} onChange={(e) => setSubject(e.target.value)} />
            </div>
            <div className="notify-compose__field">
              <label className="notify-compose__label">Message</label>
              <textarea className="notify-compose__body" rows={14} value={msgBody} onChange={(e) => setMsgBody(e.target.value)} />
            </div>
            <div className="notify-compose__tokens">
              <span className="notify-compose__tokens-label">Insert:</span>
              {['owner_name', 'asset_count', 'asset_list', 'cve_id', 'due_date', 'severity'].map((tok) => (
                <button key={tok} type="button" className="notify-token-chip" onClick={() => insertToken(tok)}>{`{{${tok}}}`}</button>
              ))}
            </div>
          </div>
        )}

        {view === 'preview' && (
          <div className="notify-preview">
            <div className="notify-preview__field">
              <span className="notify-preview__field-label">Subject</span>
              <p className="notify-preview__subject">{applyNotifyTokens(subject, getTokens())}</p>
            </div>
            <div className="notify-preview__field">
              <span className="notify-preview__field-label">Message</span>
              <pre className="notify-preview__body">{applyNotifyTokens(msgBody, getTokens())}</pre>
            </div>
          </div>
        )}

        {view === 'per-team' && (
          <div className="notify-per-team">
            {selectedGroups.size === 0 && (
              <p className="notify-per-team__empty">Select at least one group to see per-team previews.</p>
            )}
            {Array.from(selectedGroups).map((groupName) => {
              const tokens = getTokens(groupName);
              return (
                <details key={groupName} className="notify-per-team__group" open>
                  <summary className="notify-per-team__group-header">
                    <span className="notify-per-team__group-name">{groupName}</span>
                    <span className="notify-per-team__group-meta">{tokens.asset_count} asset{Number(tokens.asset_count) !== 1 ? 's' : ''}</span>
                  </summary>
                  <div className="notify-per-team__group-body">
                    <p className="notify-per-team__subject-line"><strong>Subject:</strong> {applyNotifyTokens(subject, tokens)}</p>
                    <pre className="notify-preview__body">{applyNotifyTokens(msgBody, tokens)}</pre>
                  </div>
                </details>
              );
            })}
          </div>
        )}

        <div className="notify-panel__actions">
          {sent ? (
            <span className="notify-sent-badge">✓ Email queued for {selectedGroups.size} group{selectedGroups.size !== 1 ? 's' : ''}</span>
          ) : (
            <button type="button" className="btn btn-primary" disabled={sending || selectedGroups.size === 0} onClick={() => void handleSend()}>
              {sending ? 'Sending…' : `Send email to ${selectedGroups.size} group${selectedGroups.size !== 1 ? 's' : ''}`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// --- Main Component ---

export function VulnRepoCveAssessmentWorkbench({
  item,
  detail,
  loading,
  error,
  analystId,
  onBack: _onBack,
  onRefreshDetail
}: Props) {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = React.useState<WorkflowStep>(1);
  const [investigationCanvasOpen, setInvestigationCanvasOpen] = React.useState(false);
  const [actionNotice, setActionNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const latestInvestigation = React.useMemo(() => latestByDate(detail?.investigations ?? []), [detail]);
  const latestAssessment = React.useMemo(() => latestByDate(detail?.assessments ?? []), [detail]);

  const riskPolicyQuery = useRiskPolicyQuery();
  const riskResult = React.useMemo(
    () => computeCveRiskScore(item, riskPolicyQuery.data),
    [item, riskPolicyQuery.data],
  );

  // Investigation state
  const [, setInvestigationId] = React.useState<number | null>(null);
  const [investigationNotes, setInvestigationNotes] = React.useState('');
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
  const [findingTitle, setFindingTitle] = React.useState(() => item.externalId);
  const [findingPriority, setFindingPriority] = React.useState(() => item.severity?.toUpperCase() ?? 'MEDIUM');
  const [assignmentGroup, setAssignmentGroup] = React.useState('');
  const [availableGroups, setAvailableGroups] = React.useState<string[]>([]);
  const [ownershipMode, setOwnershipMode] = React.useState<'LEAD_ANALYST' | 'ASSIGNMENT_GROUP' | 'AUTO'>('LEAD_ANALYST');
  const [ticketTarget, setTicketTarget] = React.useState<'SERVICENOW' | 'JIRA'>('SERVICENOW');
  const [dueDate, setDueDate] = React.useState(() => {
    const d = new Date();
    d.setDate(d.getDate() + 7);
    return d.toISOString().slice(0, 10);
  });
  const [findingTagsInput, setFindingTagsInput] = React.useState('');
  const [findingNotes, setFindingNotes] = React.useState('');
  const [selectedFindingIds, setSelectedFindingIds] = React.useState<Set<string>>(new Set());
  const [findingShowFilter] = React.useState<'ALL' | 'IMPACTED_ONLY'>('IMPACTED_ONLY');
  const [findingSearchQuery, setFindingSearchQuery] = React.useState('');
  const [findingExternalFacingOnly, setFindingExternalFacingOnly] = React.useState(false);
  const [findingAssetTypeFilter] = React.useState('ALL');
  const [findingBusy, setFindingBusy] = React.useState(false);
  const [findingConfigOpen, setFindingConfigOpen] = React.useState(false);
  const [findingIdsByComponentId, setFindingIdsByComponentId] = React.useState<Map<string, string>>(new Map());
  const [findingsByDisplayId, setFindingsByDisplayId] = React.useState<Map<string, Finding>>(new Map());
  const createdFindings = React.useMemo(() => Array.from(findingsByDisplayId.values()).map((finding) => ({
    displayId: finding.displayId || finding.id,
    assetName: finding.assetName,
    assetIdentifier: finding.assetIdentifier,
    packageName: finding.packageName,
    packageVersion: finding.packageVersion,
    severity: finding.severity,
    status: finding.status,
    decisionState: finding.decisionState,
    assignedTo: finding.assignedTo,
    dueAt: finding.dueAt,
    incidentId: finding.incidentId,
  })), [findingsByDisplayId]);

  React.useEffect(() => {
    if ((!findingConfigOpen && activeStep !== 4) || availableGroups.length > 0) return;
    cveWorkbenchApi.listAssignmentGroups()
      .then((groups) => setAvailableGroups(groups))
      .catch(() => { /* best-effort */ });
  }, [findingConfigOpen, activeStep]);

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
        title: 'Find False Positive',
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
        id: 'solutions',
        title: 'Solutions',
        description: 'Document remediation solutions for each impacted software version.',
        state: persistedDoneTaskIds.has('solutions') ? 'DONE' : 'READY',
      },
      {
        id: 'installed-patch-info',
        title: 'Summary Report',
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
      const nextByDisplayId = new Map<string, Finding>();
      findingsPage.items.forEach((finding: Finding) => {
        const did = finding.displayId || finding.id;
        nextByDisplayId.set(did, finding);
        if (finding.componentId) {
          next.set(finding.componentId, did);
        }
        const identityKey = findingIdentityKey(
          finding.assetIdentifier,
          finding.packageName,
          finding.packageVersion
        );
        if (identityKey) {
          next.set(identityKey, did);
        }
      });
      setFindingIdsByComponentId(next);
      setFindingsByDisplayId(nextByDisplayId);
    } catch {
      setFindingIdsByComponentId(new Map());
      setFindingsByDisplayId(new Map());
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
        const nextByDisplayId = new Map<string, Finding>();
        findingsPage.items.forEach((finding: Finding) => {
          const did = finding.displayId || finding.id;
          nextByDisplayId.set(did, finding);
          if (finding.componentId) {
            next.set(finding.componentId, did);
          }
          const identityKey = findingIdentityKey(
            finding.assetIdentifier,
            finding.packageName,
            finding.packageVersion
          );
          if (identityKey) {
            next.set(identityKey, did);
          }
        });
        setFindingIdsByComponentId(next);
        setFindingsByDisplayId(nextByDisplayId);
      } catch {
        if (!cancelled) {
          setFindingIdsByComponentId(new Map());
          setFindingsByDisplayId(new Map());
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

    // When Solutions is marked Done and assets are matched, persist applicability as AFFECTED
    if (taskId === 'solutions' && item.matchedAssetCount > 0 && item.applicability !== 'APPLICABLE') {
      void (async () => {
        try {
          await cveWorkbenchApi.submitCveAssessment(item.externalId, {
            finalResult: 'AFFECTED',
            confidenceLevel: 'MEDIUM',
            softwareDetected: true,
            vulnerableVersionPresent: true,
          });
          await onRefreshDetail({ includeList: true });
        } catch { /* best-effort */ }
      })();
    }
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
    // Also refresh when the investigation canvas closes so exposure counts update immediately
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [detail, investigationCanvasOpen]
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

    // Fallback: if neither detail.matchedSoftware nor resolvedInventory produced rows,
    // build synthetic rows directly from assetResults (DerivedAssetRow).
    // Each asset row has matchedSoftware entries with software+version; use those.
    if (investigationRows.size === 0) {
      persistedAssets.forEach((asset) => {
        asset.matchedSoftware.forEach((ms) => {
          const rowId = `inv::${normalizeAssetInventoryValue(asset.id)}::${normalizeAssetInventoryValue(ms.software)}::${normalizeAssetInventoryValue(ms.version)}`;
          if (investigationRows.has(rowId)) return;
          const syntheticSoftware: CveMatchedSoftware = {
            componentId: rowId,
            assetId: asset.assetId,
            assetName: asset.entity,
            assetIdentifier: asset.identifier,
            ecosystem: 'Inventory',
            packageName: ms.software,
            version: ms.version === '-' ? null : ms.version,
            applicabilityState: 'APPLICABLE',
            computedImpactState: 'IMPACTED',
            impactState: 'IMPACTED',
            eligibleForFinding: true,
            findingEligibilityReason: 'analyst_override_impacted',
            findingEligibilityDetail: 'This asset was identified in the investigation asset review.',
          };
          investigationRows.set(rowId, {
            software: syntheticSoftware,
            selectable: true,
            eligibilityLabel: 'Impacted asset from investigation',
            eligibilityDetail: 'This asset was identified in the investigation asset review.',
            displayApplicability: 'APPLICABLE',
            displayImpact: 'IMPACTED',
          });
        });
      });
    }

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

  const extFacingTokens = ['public','internet','edge','gateway','vpn','dmz','web','api','proxy'];
  const filteredFindingSoftware = React.useMemo<FindingDisplayRow[]>(() => {
    const normalizedQuery = normalizedAssetInventorySearch(findingSearchQuery);
    return findingRows.filter((row) => {
      const assetTypeMatches = findingAssetTypeFilter === 'ALL' || (row.software.assetType ?? '') === findingAssetTypeFilter;
      if (!assetTypeMatches) return false;
      if (findingExternalFacingOnly) {
        const haystack = [row.software.assetName, row.software.assetIdentifier, row.software.packageName]
          .filter(Boolean).join(' ').toLowerCase();
        if (!extFacingTokens.some(t => haystack.includes(t))) return false;
      }
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
  }, [findingRows, findingAssetTypeFilter, findingSearchQuery, findingExternalFacingOnly]);

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

  const currentBreadcrumbStep = investigationCanvasOpen ? null : activeStep === 1 ? null : activeStep === 2 ? 'Applicability' : activeStep === 4 ? 'Notify Groups' : 'Impacted Assets';

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
      await onRefreshDetail({ includeList: true });
      await loadPersistedFindingIds();
      setFindingConfigOpen(false);
      const parts: string[] = [result.message];
      if (result.createdCount > 0) parts.push(`Created ${result.createdCount}.`);
      if (result.reopenedCount > 0) parts.push(`Reopened ${result.reopenedCount}.`);
      if (result.alreadyOpenCount > 0) parts.push(`${result.alreadyOpenCount} already open.`);

      // Create ServiceNow incidents if the checkbox is checked
      if (ticketTarget === 'SERVICENOW') {
        try {
          // Build solution info from CVE signals — always populated
          const solutionInfo = (() => {
            if (detail?.signals.patchAvailable && detail.signals.patchVersions) {
              return `Upgrade to version ${detail.signals.patchVersions} or later to remediate ${item.externalId}. Validate the patch on all impacted assets after deployment.`;
            }
            if (detail?.signals.patchAvailable) {
              return `A vendor patch is available for ${item.externalId}. Upgrade to the latest vendor-released version and validate the mitigation on impacted assets.`;
            }
            // No patch signal — always provide guidance
            return `No vendor patch is currently available for ${item.externalId}. Apply compensating controls (e.g. network isolation, privilege restrictions) and monitor vendor advisories for remediation guidance.`;
          })();

          const snowPayload = {
            findingTitle: findingTitle,
            severity: item.severity,
            cvssScore: item.cvssScore,
            epssScore: item.epssScore,
            inKev: item.inKev,
            priority: findingPriority,
            dueDate: dueDate || undefined,
            notes: findingNotes.trim() || undefined,
            solutionInfo,
            taskSlaDueDate: dueDate || undefined,
            affectedAssets: selectedRows.map((row) => ({
              componentId: row.software.componentId,
              assetName: row.software.assetName,
              assetIdentifier: row.software.assetIdentifier,
              assetType: row.software.assetType,
              packageName: row.software.packageName,
              packageVersion: row.software.version ?? undefined,
              // Per-asset assignment group: from CMDB ownership (supportGroup) or
              // the panel-level group when ownershipMode is ASSIGNMENT_GROUP
              assignmentGroup: ownershipSupportGroup(row.software)
                ?? (ownershipMode === 'ASSIGNMENT_GROUP' && assignmentGroup.trim() ? assignmentGroup.trim() : undefined),
              assignedTo: ownershipAssignedTo(row.software),
            })),
          };
          const snowRaw = await cveWorkbenchApi.createServiceNowIncident(item.externalId, snowPayload);
          const snowResults = Array.isArray(snowRaw) ? snowRaw : [snowRaw];
          if (snowResults.length === 1) {
            parts.push(`ServiceNow incident ${snowResults[0].incidentNumber} created.`);
          } else {
            parts.push(`${snowResults.length} ServiceNow incidents created: ${snowResults.map((r) => r.incidentNumber).join(', ')}.`);
          }
          // Refresh findings so the Incident ID / Status columns reflect the newly linked incidents
          await loadPersistedFindingIds();
        } catch (snowErr) {
          parts.push(`ServiceNow ticket failed: ${snowErr instanceof Error ? snowErr.message : String(snowErr)}`);
        }
      }

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

  function handleNotified(at: string): void {
    const existing = loadPersistedInvestigationRunbookState(item.externalId);
    persistInvestigationRunbookState(item.externalId, { ...(existing ?? {}), notifiedAt: at });
    onRefreshDetail();
  }

  const riskJourney = riskResult.journey.filter(ev => !ev.isNote);

  return (
    <div className="cve-assessment-page">

      {/* ── CVE headline: shown only on sub-steps (breadcrumb) ── */}
      {currentBreadcrumbStep && <div className="cvd-headline">
        <div className="cvd-headline-id-row">
          {currentBreadcrumbStep ? (
            <>
              <button type="button" className="cvd-headline-cve-id cvd-headline-cve-link" onClick={() => guardedNav(() => setActiveStep(1))}>
                {item.externalId}
              </button>
              <span className="cvd-headline-sep" aria-hidden="true">›</span>
              <span className="cvd-headline-step">{currentBreadcrumbStep}</span>
            </>
          ) : (
            <span className="cvd-headline-cve-id">{item.externalId}</span>
          )}
        </div>

        <div className="cvd-headline-badges">
          {/* S.AI score badge — hover reveals score reasoning tooltip */}
          <div className="cvd-score-wrap">
            <div className="cvd-score-badge" style={{ background: riskResult.color }}>
              <span className="cvd-score-num">{riskResult.score.toFixed(1)}</span>
              <span className="cvd-score-label">{riskResult.label}</span>
              <span className="cvd-score-symbol">✦</span>
            </div>
            {/* Hover tooltip */}
            <div className="cvd-score-tooltip" role="tooltip">
              <div className="cvd-score-tooltip-heading">Why this score?</div>
              {riskJourney.length > 0 && (
                <div className="cvd-score-tooltip-journey">
                  {riskJourney.map((ev, i) => (
                    <div key={i} className="cvd-score-tooltip-row">
                      <span className="cvd-score-tooltip-stage">{ev.stage}</span>
                      {ev.delta !== 0 && (
                        <span className={`cvd-score-tooltip-delta${ev.delta > 0 ? ' up' : ' down'}`}>
                          {ev.delta > 0 ? '+' : ''}{ev.delta.toFixed(1)}
                        </span>
                      )}
                      <span className="cvd-score-tooltip-val">→ {ev.score.toFixed(1)}</span>
                    </div>
                  ))}
                </div>
              )}
              {riskResult.topReasons.length > 0 && (
                <>
                  <div className="cvd-score-tooltip-divider" />
                  <div className="cvd-score-tooltip-heading">Key drivers</div>
                  {riskResult.topReasons.map((r, i) => (
                    <div key={i} className="cvd-score-tooltip-reason">· {r}</div>
                  ))}
                </>
              )}
            </div>
          </div>

          {/* CVSS · EPSS */}
          {item.cvssScore != null && (
            <span className="cvd-signal-pill">
              CVSS {item.cvssScore.toFixed(1)}{item.severity ? ` · ${item.severity.toLowerCase()}` : ''}
            </span>
          )}
          {item.epssScore != null && (
            <span className="cvd-signal-pill">EPSS {(item.epssScore * 100).toFixed(1)}%</span>
          )}
          {item.matchedAssetCount > 0 && (
            <span className="cvd-signal-pill">
              {item.matchedAssetCount} asset{item.matchedAssetCount !== 1 ? 's' : ''} impacted
            </span>
          )}
          {item.inKev && <span className="cvd-signal-pill cvd-signal-pill--kev">CISA KEV</span>}
          {(() => {
            const impact = computeOrgImpact(item, riskResult.score, 0);
            const impactStyle: React.CSSProperties =
              impact === 'HIGH'
                ? { background: '#9b233522', color: '#9b2335', border: '1px solid #9b233544' }
                : impact === 'MEDIUM'
                  ? { background: '#b7791f22', color: '#b7791f', border: '1px solid #b7791f44' }
                  : { background: '#2d6a4f22', color: '#2d6a4f', border: '1px solid #2d6a4f44' };
            return (
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '2px 10px', borderRadius: 12,
                fontSize: 12, fontWeight: 700, letterSpacing: '0.04em',
                ...impactStyle,
              }}>
                Impact: {impact.charAt(0) + impact.slice(1).toLowerCase()}
              </span>
            );
          })()}
        </div>
      </div>}

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

          {/* Investigation page — full page, replaces step content */}
          {investigationCanvasOpen && detail && (
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
              onOpenFindingsStep={(filter) => {
                setFindingExternalFacingOnly(filter?.scope === 'external-facing');
                if (filter?.software) setFindingSearchQuery(filter.software);
                setInvestigationCanvasOpen(false);
                setActiveStep(3);
                setFindingConfigOpen(Boolean(filter?.openConfig));
              }}
              logEntries={investigationLogEntries}
              newLogType={newInvestigationLogType}
              onNewLogTypeChange={setNewInvestigationLogType}
              newLogMessage={newInvestigationLogMessage}
              onNewLogMessageChange={setNewInvestigationLogMessage}
              onAddLogEntry={handleAddInvestigationLogEntry}
              onClose={() => setInvestigationCanvasOpen(false)}
              onSaveDraft={() => {
                /* flushRunbookState is called inside InvestigationCanvas via useEffect */
              }}
              createdFindings={createdFindings}
            />
          )}

          {/* Step 1 — Investigation */}
          {!investigationCanvasOpen && activeStep === 1 && (
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
              onOpenExternalFacingAssets={() => {
                setFindingExternalFacingOnly(true);
                setActiveStep(3);
              }}
              leadAnalyst={leadAnalyst || analystId || 'Alex Martinez'}
              onLeadAnalystChange={setLeadAnalyst}
              persistedRunbookState={persistedRunbookState}
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
          {!investigationCanvasOpen && activeStep === 2 && (
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

          {/* Step 4 — Notify Groups */}
          {!investigationCanvasOpen && activeStep === 4 && detail && (
            <NotifyGroupsPanel
              item={item}
              detail={detail}
              availableGroups={availableGroups}
              dueDate={dueDate}
              onNotified={handleNotified}
            />
          )}

          {/* Step 3 — Create Findings */}
          {!investigationCanvasOpen && activeStep === 3 && (
            <div className="cve-findings-workspace">
              <FindingsContent
                filteredSoftware={filteredFindingSoftware}
                selectedIds={selectedFindingIds}
                searchQuery={findingSearchQuery}
                severity={item.severity}
                findingIdsByComponentId={findingIdsByComponentId}
                findingsByDisplayId={findingsByDisplayId}
                analystFpOverrides={new Set(persistedRunbookState?.analystFpOverrides ?? [])}
                onToggleRow={toggleFindingRow}
                onSelectAll={selectAllFindings}
                onClearAll={clearAllFindings}
                onSearchQueryChange={setFindingSearchQuery}
                onOpenCreatePanel={() => setFindingConfigOpen(true)}
                onOpenAsset={(sw) => {
                  const assetId = sw.assetId ?? sw.assetIdentifier ?? sw.componentId;
                  navigate(pathForVulnRepoHostAsset(assetId, `/vuln-repo/org-cves/${encodeURIComponent(item.externalId)}/assets`));
                }}
                onOpenFinding={(displayId, finding) => {
                  const returnTo = `/vuln-repo/org-cves/${encodeURIComponent(item.externalId)}`;
                  navigate(pathForFindingDetail(displayId, returnTo), { state: finding ? { finding } : undefined });
                }}
                onBulkFpMark={(softwareKeys) => {
                  const existing = loadPersistedInvestigationRunbookState(item.externalId);
                  if (!existing) return;
                  const current = new Set(existing.analystFpOverrides ?? []);
                  softwareKeys.forEach((k) => current.add(k));
                  persistInvestigationRunbookState(item.externalId, { ...existing, analystFpOverrides: Array.from(current) });
                }}
                onBulkFpUnmark={(softwareKeys) => {
                  const existing = loadPersistedInvestigationRunbookState(item.externalId);
                  if (!existing) return;
                  const current = new Set(existing.analystFpOverrides ?? []);
                  softwareKeys.forEach((k) => current.delete(k));
                  persistInvestigationRunbookState(item.externalId, { ...existing, analystFpOverrides: Array.from(current) });
                }}
              />
              {findingConfigOpen && (
                <FindingConfigPanel
                  filteredSoftware={filteredFindingSoftware}
                  selectedIds={selectedFindingIds}
                  findingTitle={findingTitle}
                  findingPriority={findingPriority}
                  assignmentGroup={assignmentGroup}
                  availableGroups={availableGroups}
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
              )}
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

    </div>
  );
}
