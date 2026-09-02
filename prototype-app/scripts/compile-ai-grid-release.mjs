import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const args = new Map(process.argv.slice(2).filter((_, i, all) => i % 2 === 0)
  .map((key, i) => [key, process.argv.slice(2)[i * 2 + 1]]));
const required = (key) => {
  const value = args.get(key);
  if (!value) throw new Error(`${key} is required`);
  return resolve(value);
};
const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));
const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const policyId = (prefix, value) => `${prefix}-${String(value).padStart(3, '0')}`;

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
} else {
  expected = source.policies.map((policy) => policy.policyId).sort();
}

const compiled = expected.map((id) => {
  const file = resolve(packageRoot, id, '1.0.0.json');
  if (!existsSync(file)) throw new Error(`Missing package: ${file}`);
  const policy = readJson(file);
  if (policy.policyId !== id || policy.version !== '1.0.0') throw new Error(`Package identity mismatch: ${file}`);
  if (phase2 && (policy.lifecycle === 'PUBLISHED' || policy.releaseStatus === 'GENERAL_AVAILABILITY')) {
    throw new Error(`Phase 2 source must install paused and validated, not published: ${id}`);
  }
  if (!Array.isArray(policy.frameworkMappings) || policy.frameworkMappings.length === 0) {
    throw new Error(`Package has no framework mappings: ${id}`);
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
