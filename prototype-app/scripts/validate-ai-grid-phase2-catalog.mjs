import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const source = process.argv[2] ?? new URL('../policy-packages/agcf/phase-2-catalog-contract.json', import.meta.url);
const contract = JSON.parse(readFileSync(source, 'utf8'));
const packageRoot = fileURLToPath(new URL('../policy-packages/agcf/', import.meta.url));
const appRoot = fileURLToPath(new URL('..', import.meta.url));
const fail = (message) => { throw new Error(`Invalid Phase 2 catalog contract: ${message}`); };
const id = (prefix, value) => `${prefix}-${String(value).padStart(3, '0')}`;
const frameworkVersions = new Map([
  ['OWASP_GENAI_LLM_TOP_10', '2026'],
  ['OWASP_AGENTIC_TOP_10', '2026'],
  ['CSA_AICM', '1.1'],
]);

if (contract.release !== 'AGCF_PHASE_2') fail('release must be AGCF_PHASE_2');
if (contract.catalogVersion !== 1) fail('catalogVersion must be 1');
if (contract.technicalVersion !== '1.0.0') fail('all Phase 2 packages must be 1.0.0');
if (!Array.isArray(contract.newPolicyRanges) || !Array.isArray(contract.replacements)) fail('ranges and replacements are required');
if (JSON.stringify(contract).includes('"digest"')) fail('catalog contract must not contain package digests');
if (!Array.isArray(contract.policies) || contract.policies.length !== 83) fail('exactly 83 explicit policy entries are required');

const certificationWave = contract.certificationWave;
const expectedCertificationIds = new Set([
  'AGCF-AWS-039', 'AGCF-AWS-040', 'AGCF-AWS-041', 'AGCF-AWS-042',
  'AGCF-AZR-033', 'AGCF-AZR-034', 'AGCF-AZR-035', 'AGCF-AZR-036',
  'AGCF-AZR-037', 'AGCF-AZR-038', 'AGCF-AZR-039',
  'AGCF-AWS-048', 'AGCF-AWS-049', 'AGCF-AWS-050',
  'AGCF-AWS-071', 'AGCF-AWS-072',
]);
if (!certificationWave || certificationWave.id !== 'PHASE2_EVIDENCE_CERTIFICATION_1'
    || !Array.isArray(certificationWave.policyIds)
    || certificationWave.policyIds.length !== expectedCertificationIds.size
    || new Set(certificationWave.policyIds).size !== expectedCertificationIds.size
    || certificationWave.policyIds.some((policyId) => !expectedCertificationIds.has(policyId))) {
  fail('certification wave must declare the 16 evidence-backed policies exactly once');
}
if (!Array.isArray(certificationWave.requiredGates)
    || !['ANSWER_KEY', 'PRECISION_REVIEW', 'INDEPENDENT_MAPPING_REVIEW', 'APPROVAL', 'CANARY_ROLLOUT']
      .every((gate) => certificationWave.requiredGates.includes(gate))) {
  fail('certification wave must retain all validation and rollout gates');
}

const expectedRanges = new Map([
  ['AGCF-AWS', [39, 68]],
  ['AGCF-AZR', [33, 69]]
]);
const newIds = new Set();
for (const range of contract.newPolicyRanges) {
  const expected = expectedRanges.get(range.prefix);
  if (!expected || range.from !== expected[0] || range.to !== expected[1] || range.from > range.to) {
    fail(`unexpected range ${range.prefix}:${range.from}-${range.to}`);
  }
  for (let value = range.from; value <= range.to; value += 1) newIds.add(id(range.prefix, value));
}
for (const [prefix, [from, to]] of expectedRanges) {
  for (let value = from; value <= to; value += 1) {
    if (!newIds.has(id(prefix, value))) fail(`missing new policy ${id(prefix, value)}`);
  }
}

const expectedSuccessors = new Set([
  ...Array.from({ length: 4 }, (_, index) => id('AGCF-AWS', 69 + index)),
  ...Array.from({ length: 6 }, (_, index) => id('AGCF-AZR', 70 + index)),
  ...Array.from({ length: 6 }, (_, index) => id('AGCF-XSP', 7 + index))
]);
if (contract.replacements.length !== 16) fail('exactly 16 replacements are required');
const predecessors = new Set();
const successors = new Set();
for (const replacement of contract.replacements) {
  if (!replacement.predecessorPolicyId || !replacement.successorPolicyId) fail('replacement IDs are required');
  if (predecessors.has(replacement.predecessorPolicyId)) fail(`duplicate predecessor ${replacement.predecessorPolicyId}`);
  if (successors.has(replacement.successorPolicyId)) fail(`duplicate successor ${replacement.successorPolicyId}`);
  if (!expectedSuccessors.has(replacement.successorPolicyId)) fail(`unexpected successor ${replacement.successorPolicyId}`);
  predecessors.add(replacement.predecessorPolicyId);
  successors.add(replacement.successorPolicyId);
}
if (successors.size !== expectedSuccessors.size) fail('replacement successor set is incomplete');
const total = newIds.size + successors.size;
if (total !== 83) fail(`expected 83 Phase 2 packages, found ${total}`);
const entries = new Map(contract.policies.map((policy) => [policy.policyId, policy]));
if (entries.size !== 83) fail('explicit policy IDs must be unique');
for (const policy of entries.values()) {
  if (policy.version !== '1.0.0' || policy.lifecycle !== 'VALIDATED' || policy.releaseStatus !== 'PAUSED') fail(`${policy.policyId} must be 1.0.0 VALIDATED/PAUSED`);
  if (policy.releaseFamily !== 'AGCF_PHASE_2' || !policy.provider || !policy.name || !policy.description) fail(`${policy.policyId} is missing package metadata`);
  if (!policy.requiredCapabilities?.length || !policy.requiredFacts || !policy.evaluationDefinition || !policy.frameworkMappings?.length) fail(`${policy.policyId} is missing executable contract metadata`);
  for (const mapping of policy.frameworkMappings) {
    if (frameworkVersions.get(mapping.framework) !== mapping.frameworkVersion
        || !['DIRECT', 'PARTIAL', 'SUPPORTING'].includes(mapping.mappingType)
        || !mapping.controlId || !mapping.rationale) fail(`${policy.policyId} has an invalid framework mapping`);
  }
}
for (const policyId of expectedCertificationIds) {
  const file = resolve(packageRoot, policyId, '1.0.1.json');
  if (!existsSync(file)) fail(`${policyId} certification package is missing`);
  const policy = JSON.parse(readFileSync(file, 'utf8'));
  const directOwasp = policy.frameworkMappings?.filter((mapping) =>
    mapping.framework === 'OWASP_GENAI_LLM_TOP_10' && mapping.mappingType === 'DIRECT') ?? [];
  if (policy.version !== '1.0.1' || directOwasp.length !== 1
      || policy.releaseStatus !== 'PAUSED' || policy.defaultSelection !== 'DISABLED') {
    fail(`${policyId} must have one direct OWASP mapping while remaining PAUSED/DISABLED pending certification`);
  }
}
const certificationManifestFile = resolve(packageRoot, 'phase-2-certification-wave-1-manifest.json');
if (!existsSync(certificationManifestFile)) fail('certification manifest is missing');
const certificationManifest = JSON.parse(readFileSync(certificationManifestFile, 'utf8'));
if (certificationManifest.release !== 'AGCF_PHASE_2_EVIDENCE_CERTIFICATION_1'
    || certificationManifest.certificationWave !== certificationWave.id
    || certificationManifest.policies?.length !== expectedCertificationIds.size
    || !certificationWave.requiredGates.every((gate) => certificationManifest.requiredGates?.includes(gate))) {
  fail('certification manifest does not match the governed wave');
}
for (const entry of certificationManifest.policies) {
  if (!expectedCertificationIds.has(entry.policyId) || entry.version !== '1.0.1') {
    fail('certification manifest contains an unexpected package');
  }
  const bytes = readFileSync(resolve(packageRoot, entry.policyId, `${entry.version}.json`));
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (entry.digest !== digest) fail(`${entry.policyId} certification manifest digest mismatch`);
}
const bundledCertificationManifest = resolve(appRoot, 'backend/src/main/resources/ai-grid/phase-2-certification-wave-1-manifest.json');
if (!existsSync(bundledCertificationManifest)
    || readFileSync(bundledCertificationManifest, 'utf8') !== readFileSync(certificationManifestFile, 'utf8')) {
  fail('bundled certification manifest is missing or differs from the package manifest');
}
for (const replacement of contract.replacements) {
  if (entries.get(replacement.successorPolicyId)?.predecessorPolicyId !== replacement.predecessorPolicyId) fail(`replacement metadata mismatch for ${replacement.successorPolicyId}`);
}
console.log(`Phase 2 catalog contract valid: ${newIds.size} new + ${successors.size} replacements = ${total}`);
