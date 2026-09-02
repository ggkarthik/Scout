import { readFileSync } from 'node:fs';

const source = process.argv[2] ?? new URL('../policy-packages/agcf/phase-2-catalog-contract.json', import.meta.url);
const contract = JSON.parse(readFileSync(source, 'utf8'));
const fail = (message) => { throw new Error(`Invalid Phase 2 catalog contract: ${message}`); };
const id = (prefix, value) => `${prefix}-${String(value).padStart(3, '0')}`;

if (contract.release !== 'AGCF_PHASE_2') fail('release must be AGCF_PHASE_2');
if (contract.catalogVersion !== 1) fail('catalogVersion must be 1');
if (contract.technicalVersion !== '1.0.0') fail('all Phase 2 packages must be 1.0.0');
if (!Array.isArray(contract.newPolicyRanges) || !Array.isArray(contract.replacements)) fail('ranges and replacements are required');
if (JSON.stringify(contract).includes('"digest"')) fail('catalog contract must not contain package digests');

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
console.log(`Phase 2 catalog contract valid: ${newIds.size} new + ${successors.size} replacements = ${total}`);
