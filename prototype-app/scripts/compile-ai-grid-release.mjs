import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const key = process.argv[index];
  const next = process.argv[index + 1];
  args.set(key, next && !next.startsWith('--') ? next : true);
  if (next && !next.startsWith('--')) index += 1;
}
const required = (key) => {
  const value = args.get(key);
  if (!value) throw new Error(`${key} is required`);
  return resolve(value);
};
const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));
const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const policyId = (prefix, value) => `${prefix}-${String(value).padStart(3, '0')}`;
const writableMappingTypes = new Set(['DIRECT', 'PARTIAL', 'SUPPORTING']);
const frameworkVersions = new Map([
  ['OWASP_GENAI_LLM_TOP_10', '2026'],
  ['OWASP_AGENTIC_TOP_10', '2026'],
  ['CSA_AICM', '1.1'],
]);

const manifestFile = required('--manifest');
const packageRoot = required('--package-root');
const output = args.get('--output') ? resolve(args.get('--output')) : null;
const phase2 = args.has('--phase2');
const source = readJson(manifestFile);
let expected;

if (phase2) {
  if (source.release !== 'AGCF_PHASE_2' || source.technicalVersion !== '1.0.0') {
    throw new Error('Phase 2 compilation requires the Phase 2 catalog contract at technical version 1.0.0');
  }
  const ranges = source.newPolicyRanges.flatMap(({ prefix, from, to }) =>
    Array.from({ length: to - from + 1 }, (_, index) => policyId(prefix, from + index)));
  const replacements = source.replacements.map(({ successorPolicyId }) => successorPolicyId);
  expected = [...ranges, ...replacements].sort();
  if (expected.length !== 83 || new Set(expected).size !== 83) throw new Error('Phase 2 contract must resolve to 83 unique policy IDs');
  if (!Array.isArray(source.policies) || source.policies.length !== 83) {
    throw new Error('Phase 2 catalog contract must contain exactly 83 explicit policy entries');
  }
  if (JSON.stringify(source.policies.map(({ policyId: id }) => id).sort()) !== JSON.stringify(expected)) {
    throw new Error('Phase 2 explicit policy entries do not match the governed ID set');
  }
  const replacementBySuccessor = new Map(source.replacements.map((replacement) => [replacement.successorPolicyId, replacement.predecessorPolicyId]));
  const objectives = new Set();
  for (const entry of source.policies) {
    if (entry.version !== '1.0.0' || entry.lifecycle !== 'VALIDATED' || entry.releaseStatus !== 'PAUSED'
        || entry.releaseFamily !== 'AGCF_PHASE_2') throw new Error(`Invalid Phase 2 source state: ${entry.policyId}`);
    if (!entry.controlObjectiveId || objectives.has(entry.controlObjectiveId)) throw new Error(`Duplicate or missing control objective: ${entry.policyId}`);
    objectives.add(entry.controlObjectiveId);
    const predecessor = replacementBySuccessor.get(entry.policyId);
    if (predecessor && entry.predecessorPolicyId !== predecessor) throw new Error(`Replacement predecessor mismatch: ${entry.policyId}`);
    if (!predecessor && entry.predecessorPolicyId) throw new Error(`Unexpected predecessor on non-replacement: ${entry.policyId}`);
  }
} else {
  expected = source.policies.map((policy) => policy.policyId).sort();
}

const compiled = expected.map((id) => {
  const file = resolve(packageRoot, id, '1.0.0.json');
  if (!existsSync(file)) throw new Error(`Missing package: ${file}`);
  const policy = readJson(file);
  if (policy.policyId !== id || policy.version !== '1.0.0') throw new Error(`Package identity mismatch: ${file}`);
  if (phase2 && (policy.lifecycle !== 'VALIDATED' || policy.releaseStatus !== 'PAUSED' || policy.releaseFamily !== 'AGCF_PHASE_2')) {
    throw new Error(`Phase 2 source must install as VALIDATED/PAUSED in AGCF_PHASE_2: ${id}`);
  }
  if (phase2) {
    const declared = source.policies.find((entry) => entry.policyId === id);
    if (!declared) throw new Error(`Missing declared source entry: ${id}`);
    if (declared.predecessorPolicyId !== policy.predecessorPolicyId) throw new Error(`Package predecessor mismatch: ${id}`);
  }
  if (!policy.controlObjectiveId || !policy.provider || !policy.evaluationMode || !policy.evaluationDefinition) {
    throw new Error(`Package is missing executable policy metadata: ${id}`);
  }
  if (!Array.isArray(policy.requiredCapabilities) || policy.requiredCapabilities.length === 0) {
    throw new Error(`Package has no required capability: ${id}`);
  }
  if (!Array.isArray(policy.requiredFacts) || (policy.evaluationMode === 'CORRELATION_PATH' && policy.requiredFacts.length !== 0)) {
    throw new Error(`Package has an invalid fact contract: ${id}`);
  }
  if (policy.evaluationMode === 'CORRELATION_PATH' && !policy.evaluationDefinition.correlationPath) {
    throw new Error(`Correlation package has no correlation contract: ${id}`);
  }
  const runtimeMode = ['RUNTIME_FACTS', 'RUNTIME_SEQUENCE', 'RUNTIME_AGGREGATE', 'RUNTIME_COVERAGE']
    .includes(policy.evaluationMode);
  if (policy.evaluationMode !== 'CORRELATION_PATH' && !runtimeMode
      && !policy.evaluationDefinition.artifactFacts?.predicate) {
    throw new Error(`Posture package has no bounded predicate: ${id}`);
  }
  if (runtimeMode && policy.evaluationDefinition.mode !== policy.evaluationMode) {
    throw new Error(`Runtime package has no matching evaluation contract: ${id}`);
  }
  if (!Array.isArray(policy.frameworkMappings) || policy.frameworkMappings.length === 0) {
    throw new Error(`Package has no framework mappings: ${id}`);
  }
  for (const mapping of policy.frameworkMappings) {
    if (frameworkVersions.get(mapping.framework) !== mapping.frameworkVersion
        || !mapping.controlId || !mapping.rationale || !writableMappingTypes.has(mapping.mappingType)) {
      throw new Error(`Package has an invalid framework mapping: ${id}`);
    }
    if (mapping.framework === 'OWASP_GENAI_LLM_TOP_10' && !/^LLM(0[1-9]|10)$/.test(mapping.controlId)) {
      throw new Error(`Package has an invalid OWASP LLM control: ${id}`);
    }
    if (mapping.framework === 'OWASP_AGENTIC_TOP_10' && !/^ASI(0[1-9]|10)$/.test(mapping.controlId)) {
      throw new Error(`Package has an invalid OWASP Agentic control: ${id}`);
    }
  }
  return {
    policyId: id,
    version: '1.0.0',
    digest: sha256(file),
    provider: policy.provider,
    controlObjectiveId: policy.controlObjectiveId,
    evaluationMode: policy.evaluationMode,
    defaultSelection: policy.defaultSelection,
    releaseFamily: policy.releaseFamily,
    wave: policy.wave,
    packageSourceRef: `policy-packages/agcf/${id}/1.0.0.json`
  };
});

const result = { release: source.release, policies: compiled };
if (!phase2 && source.policies.length !== compiled.length) throw new Error('Manifest policy count changed during compilation');
if (!output) {
  console.log(JSON.stringify(result, null, 2));
} else {
  writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`Compiled ${compiled.length} packages to ${output}`);
}
