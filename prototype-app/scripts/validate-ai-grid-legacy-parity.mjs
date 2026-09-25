import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('.', import.meta.url)), '..');
const parity = JSON.parse(readFileSync(resolve(root, 'policy-packages/legacy-policy-parity.json'), 'utf8'));
const packageRoot = resolve(root, 'policy-packages/agcf');
const platformV1 = readFileSync(resolve(root, 'backend/src/main/resources/db/migration/postgres_reset/V1__platform_schema.sql'), 'utf8');
const packageIds = new Set(readdirSync(packageRoot, { withFileTypes: true })
  .filter((entry) => entry.isDirectory()).map((entry) => entry.name));
const copyStart = platformV1.indexOf('COPY platform.ai_grid_policy_versions ');
const copyHeaderEnd = platformV1.indexOf(' FROM stdin;', copyStart);
const headerStart = platformV1.indexOf('(', copyStart) + 1;
const headerEnd = platformV1.lastIndexOf(')', copyHeaderEnd);
const columnsByName = platformV1.slice(headerStart, headerEnd).split(',').map((column) => column.trim());
const policyIdColumn = columnsByName.indexOf('policy_id');
const versionColumn = columnsByName.indexOf('version');
const releaseFamilyColumn = columnsByName.indexOf('release_family');
if ([policyIdColumn, versionColumn, releaseFamilyColumn].some((index) => index < 0)) {
  throw new Error('Policy-version COPY header is missing required columns');
}
const dataStart = platformV1.indexOf('\n', copyStart) + 1;
const dataEnd = platformV1.indexOf('\n\\.\n', dataStart);
if (copyStart < 0 || dataStart === 0 || dataEnd < 0) throw new Error('Could not locate the policy-version COPY block');
const installedLegacy = new Map(platformV1.slice(dataStart, dataEnd).split('\n').map((row) => row.split('\t'))
  .filter((columns) => columns[releaseFamilyColumn] === '\\N')
  .map((columns) => [columns[policyIdColumn], columns[versionColumn]]));
if (parity.policies.length !== installedLegacy.size) {
  throw new Error(`Expected ${installedLegacy.size} parity entries, found ${parity.policies.length}`);
}
const legacyIds = new Set();
for (const policy of parity.policies) {
  if (!policy.legacyPolicyId || !policy.legacyVersion || !policy.rationale) throw new Error('Legacy parity entries require identity and rationale');
  if (legacyIds.has(policy.legacyPolicyId)) throw new Error(`Duplicate legacy policy ${policy.legacyPolicyId}`);
  legacyIds.add(policy.legacyPolicyId);
  if (!installedLegacy.has(policy.legacyPolicyId)) throw new Error(`Parity entry is not an installed legacy policy: ${policy.legacyPolicyId}`);
  if (installedLegacy.get(policy.legacyPolicyId) !== policy.legacyVersion) {
    throw new Error(`Legacy version mismatch for ${policy.legacyPolicyId}`);
  }
  if (!['RETIRE_AFTER_PARITY', 'NO_SUCCESSOR'].includes(policy.disposition)) throw new Error(`Invalid disposition for ${policy.legacyPolicyId}`);
  const verification = { ...parity.defaultVerification, ...(policy.verification ?? {}) };
  for (const field of ['selectionState', 'predicateEvidenceParity', 'findingFingerprintMigration', 'parityStatus', 'blocker']) {
    if (!verification[field]) throw new Error(`Legacy parity verification is missing ${field} for ${policy.legacyPolicyId}`);
  }
  if (verification.parityStatus === 'VERIFIED'
      && (verification.predicateEvidenceParity !== 'VERIFIED'
        || verification.findingFingerprintMigration === 'NOT_ASSESSED'
        || verification.selectionState === 'CAPTURE_FROM_INSTALLED_DISTRIBUTION')) {
    throw new Error(`Verified parity is incomplete for ${policy.legacyPolicyId}`);
  }
  if (policy.disposition === 'RETIRE_AFTER_PARITY' && (!policy.successorPolicyIds?.length
      || policy.successorPolicyIds.some((id) => !packageIds.has(id)))) {
    throw new Error(`Unknown or missing successor for ${policy.legacyPolicyId}`);
  }
}
for (const id of installedLegacy.keys()) {
  if (!legacyIds.has(id)) throw new Error(`Installed legacy policy has no parity disposition: ${id}`);
}
const verified = parity.policies.filter((policy) => ({ ...parity.defaultVerification, ...(policy.verification ?? {}) }).parityStatus === 'VERIFIED').length;
console.log(`Legacy parity contract valid: ${legacyIds.size} installed policies, ${verified} verified for retirement`);
