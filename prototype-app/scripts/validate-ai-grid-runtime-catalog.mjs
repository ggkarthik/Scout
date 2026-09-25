import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const contractFile = process.argv[2]
  ?? fileURLToPath(new URL('../policy-packages/agcf/runtime-wave-contract.json', import.meta.url));
const contract = JSON.parse(readFileSync(contractFile, 'utf8'));
const packageRoot = resolve(dirname(contractFile), '..', '..');
const fail = (message) => { throw new Error(`Invalid runtime wave contract: ${message}`); };

const frameworkVersions = new Map([
  ['OWASP_GENAI_LLM_TOP_10', '2026'],
  ['OWASP_AGENTIC_TOP_10', '2026'],
  ['CSA_AICM', '1.1'],
]);
const runtimeModes = new Set(['RUNTIME_FACTS', 'RUNTIME_SEQUENCE', 'RUNTIME_AGGREGATE', 'RUNTIME_COVERAGE']);
const sequenceOperators = new Set(['EQ', 'NE', 'IN', 'NOT_IN', 'EXISTS']);
const factOperators = new Set([...sequenceOperators, 'ABSENT']);
const aggregateMetrics = new Set([
  'RETRIES', 'REPEATED_ACTION_SIGNATURE', 'TOKEN_TOTAL', 'LATENCY_MS', 'SPEND_MICROS', 'EVENT_COUNT']);
const aggregateOperators = new Set(['EQ', 'NE', 'GT', 'GTE', 'LT', 'LTE']);
// Grouping keys must resolve to a UUID execution column so a breach names a real subject.
const groupingKeys = new Set(['execution.agent_artifact_id', 'execution.agent_version_artifact_id']);

if (contract.release !== 'AGCF_PHASE_2_RUNTIME') fail('release must be AGCF_PHASE_2_RUNTIME');
if (contract.catalogVersion !== 1) fail('catalogVersion must be 1');
if (contract.technicalVersion !== '1.0.0') fail('technicalVersion must be 1.0.0');

const declared = new Set(contract.waves.flatMap(({ wave, policyIds }) => {
  if (!['WAVE_2A', 'WAVE_2B'].includes(wave)) fail(`unexpected wave ${wave}`);
  if (!Array.isArray(policyIds) || policyIds.length === 0) fail(`wave ${wave} declares no policies`);
  return policyIds;
}));
if (declared.size !== contract.policies.length) fail('wave membership and policy list disagree');

for (const entry of contract.policies) {
  if (!declared.has(entry.policyId)) fail(`${entry.policyId} is not a member of any wave`);
  if (entry.releaseStatus !== 'PAUSED') fail(`${entry.policyId} must ship PAUSED`);
  // A runtime package that shipped ENABLED would evaluate on distribution alone.
  if (entry.defaultSelection !== 'PREVIEW') fail(`${entry.policyId} must default to PREVIEW`);

  const body = JSON.parse(readFileSync(resolve(packageRoot, entry.packageSourceRef), 'utf8'));
  if (body.policyId !== entry.policyId || body.version !== entry.version) {
    fail(`${entry.policyId} package identity does not match the contract`);
  }
  if (body.defaultSelection !== 'PREVIEW' || body.releaseStatus !== 'PAUSED') {
    fail(`${entry.policyId} package selection or release status drifted from the contract`);
  }
  if (body.workflowClass !== 'RUNTIME_FINDING' || body.evaluationSubject !== 'EXECUTION') {
    fail(`${entry.policyId} must be an execution-subject runtime finding`);
  }
  if (!runtimeModes.has(body.evaluationMode)
      || body.evaluationDefinition?.mode !== body.evaluationMode) {
    fail(`${entry.policyId} has an invalid runtime evaluation mode`);
  }
  if (!body.requiredCapabilities?.length) fail(`${entry.policyId} must declare required capabilities`);
  if (!body.frameworkMappings?.length) fail(`${entry.policyId} must declare framework mappings`);
  for (const map of body.frameworkMappings) {
    if (frameworkVersions.get(map.framework) !== map.frameworkVersion
        || !['DIRECT', 'PARTIAL', 'SUPPORTING'].includes(map.mappingType)
        || !map.controlId || !map.rationale) {
      fail(`${entry.policyId} has an invalid framework mapping`);
    }
  }
  if (body.parameterDefinitions?.length && !body.certificationParameterProfile?.immutable) {
    fail(`${entry.policyId} is parameterized and needs an immutable certification profile`);
  }
  validateDefinition(entry.policyId, body);
}

function validateDefinition(id, body) {
  if (body.evaluationMode === 'RUNTIME_COVERAGE') {
    const coverage = body.evaluationDefinition.runtimeCoverage;
    if (!(coverage?.lookbackSeconds > 0 && coverage.lookbackSeconds <= 1209600)
        || !(coverage.windowSeconds > 0 && coverage.windowSeconds <= 86400)
        || !(coverage.maximumRowsExamined > 0 && coverage.maximumRowsExamined <= 10000)
        || !(coverage.sampleSize > 0 && coverage.sampleSize <= 20)) {
      fail(`${id} runtime coverage bounds are missing or out of range`);
    }
    if (body.findingAggregationGrain !== 'PROVIDER_WINDOW_CAPABILITY_FAMILY') {
      fail(`${id} runtime coverage must declare PROVIDER_WINDOW_CAPABILITY_FAMILY aggregation`);
    }
    return;
  }
  if (body.evaluationMode === 'RUNTIME_FACTS') {
    const conditions = body.evaluationDefinition.runtimeFacts?.conditions;
    if (!Array.isArray(conditions) || conditions.length === 0 || conditions.length > 16) {
      fail(`${id} runtime facts conditions must be a bounded non-empty list`);
    }
    for (const condition of conditions) {
      if (!condition.field?.startsWith('execution.') || !factOperators.has(condition.operator)) {
        fail(`${id} runtime facts conditions must be execution-scoped with a closed operator`);
      }
    }
    return;
  }
  if (body.evaluationMode === 'RUNTIME_SEQUENCE') {
    const sequence = body.evaluationDefinition.runtimeSequence;
    const steps = sequence?.steps;
    if (!Array.isArray(steps) || steps.length === 0 || steps.length > 16) {
      fail(`${id} runtime sequence steps must be a bounded non-empty list`);
    }
    for (const step of steps) {
      const predicates = Array.isArray(step.conditions) ? step.conditions : [step];
      if (predicates.length === 0 || predicates.length > 16) {
        fail(`${id} runtime sequence step conditions must be bounded and non-empty`);
      }
      for (const predicate of predicates) {
        // Only event-scoped fields can establish ordering; an execution field is constant.
        if (!predicate.field?.startsWith('event.') || !sequenceOperators.has(predicate.operator)) {
          fail(`${id} runtime sequence predicates must be event-scoped with a closed operator`);
        }
      }
    }
    if (!(sequence.maximumDurationSeconds > 0 && sequence.maximumDurationSeconds <= 86400)
        || !(sequence.allowedLatenessSeconds >= 0 && sequence.allowedLatenessSeconds <= 3600)
        || !(sequence.maximumEventsExamined > 0 && sequence.maximumEventsExamined <= 10000)
        || !sequence.deduplicationKey) {
      fail(`${id} runtime sequence bounds are missing or out of range`);
    }
    return;
  }
  const aggregate = body.evaluationDefinition.runtimeAggregate;
  if (!aggregateMetrics.has(aggregate?.metric) || !aggregateOperators.has(aggregate?.operator)
      || aggregate.threshold === undefined) {
    fail(`${id} runtime aggregate metric, operator or threshold is invalid`);
  }
  if (!groupingKeys.has(aggregate.groupingKey)) {
    fail(`${id} runtime aggregate grouping key must be a UUID execution field`);
  }
  if (!(aggregate.lookbackSeconds > 0 && aggregate.lookbackSeconds <= 1209600)
      || !(aggregate.maximumRowsExamined > 0 && aggregate.maximumRowsExamined <= 10000)
      || !(aggregate.maximumEventsExamined > 0 && aggregate.maximumEventsExamined <= 100000)) {
    fail(`${id} runtime aggregate bounds are missing or out of range`);
  }
}

// Wave 2C stays breadth-only: declared, named, and explicitly paused pending an evidence family.
for (const paused of contract.pausedPendingEvidence ?? []) {
  if (!paused.policyId || !paused.name || !paused.blockingCapability
      || paused.reasonCode !== 'POLICY_PAUSED_PENDING_EVIDENCE') {
    fail(`paused control ${paused.policyId ?? '(unnamed)'} is missing its evidence gate`);
  }
  if (declared.has(paused.policyId)) {
    fail(`${paused.policyId} cannot be both released and paused pending evidence`);
  }
}

const certification = contract.certificationRequirement;
if (!certification || certification.minimumTotalCertifications < 5
    || certification.minimumBehaviouralCertifications < 2) {
  fail('certification requirement must name at least 5 policies including 2 behavioural');
}
const behavioural = new Set(contract.waves.find((wave) => wave.wave === 'WAVE_2B')?.policyIds ?? []);
for (const candidate of certification.behaviouralPolicyCandidates ?? []) {
  if (!behavioural.has(candidate)) fail(`${candidate} is not a Wave 2B behavioural policy`);
}
if ((certification.behaviouralPolicyCandidates ?? []).length
    < certification.minimumBehaviouralCertifications) {
  fail('behavioural candidate list is smaller than the required number of certifications');
}

const manifestFile = resolve(dirname(contractFile), 'runtime-manifest.json');
const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
if (manifest.policies.length !== contract.policies.length) {
  fail('runtime manifest and contract policy counts disagree');
}
for (const entry of manifest.policies) {
  const digest = createHash('sha256')
    .update(readFileSync(resolve(packageRoot, entry.packageSourceRef)))
    .digest('hex');
  if (digest !== entry.digest) fail(`${entry.policyId} package digest does not match the manifest`);
}

console.log(`Runtime wave contract is valid: ${contract.policies.length} released, `
  + `${(contract.pausedPendingEvidence ?? []).length} paused pending evidence`);
