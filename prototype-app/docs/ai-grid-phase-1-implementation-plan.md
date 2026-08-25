# AI Grid Phase 1 — execution implementation plan

**Status:** Revised execution contract  
**Normative catalog:** [`ai-grid-phase-1-policy-plan.md`](./ai-grid-phase-1-policy-plan.md)  
**Target:** 38 AWS posture adapters, 32 Azure posture adapters, and 6 multi-resource exposure adapters  
**Delivery target:** 22 weeks with two engineering squads, dedicated QA automation, and two available security reviewers

## 1. Completion contract

Phase 1 is complete only when all 76 entries in the normative catalog are installed, governed, certified, visible out of the box, and published at `GENERAL_AVAILABILITY`. The expected default split is exactly 26 `REQUIRED`, 24 `ENABLED`, and 26 `DISABLED`.

`DISABLED` means that the policy ships and has passed the same release qualification as the rest of the catalog, but the tenant must configure and enable it. It does not mean preview, uncertified, or absent.

Every applicable evaluation must end in one of these evidence-safe outcomes:

- `PASS`: all required scopes, capabilities, relationships, and facts were available and the undesirable-state predicate was false.
- `FAIL`: all required evidence was available and the undesirable-state predicate was true.
- `NO_DECISION`: required evidence was missing, stale, unsupported, disabled, unauthorized, partial, or below the required confidence.
- `ERROR`: the collector or evaluator failed in a way that is distinct from evidence absence.
- `NOT_APPLICABLE`: the artifact is outside policy scope or a required relationship is authoritatively absent.

Missing or incomplete evidence must never become PASS.

The repository currently seeds 21 posture-policy IDs across V50, V51, V58, and V72 and three published correlations in V63. `ai_grid_control_objectives` and connector capability observations are net-new. Phase 1 must also author three new correlation definitions and place all six correlations behind the same governance and distribution envelope as posture policies.

## 2. Target architecture and data contracts

### 2.1 Objective-to-adapter model

Create `platform.ai_grid_control_objectives` as the stable provider-neutral intent layer:

| Column | Contract |
|---|---|
| `objective_id` | Immutable AGCF objective identifier and primary key |
| `name` | Provider-neutral control objective name |
| `intent` | Independently authored security intent |
| `remediation_intent` | Provider-neutral remediation outcome |
| `lifecycle` | `ACTIVE`, `RETIRED` |
| `owner` | Accountable product/security owner |
| `created_at`, `updated_at` | Audit timestamps |

Each AWS, Azure, or multi-resource policy remains an independently versioned adapter in `platform.ai_grid_policy_versions`. Add:

- `control_objective_id`, referencing the objective table.
- `provider`: `AWS`, `AZURE`, or `MULTI_CLOUD`.
- `evaluation_mode`: `ARTIFACT_FACTS`, `DIRECT_RELATIONSHIP`, or `CORRELATION_PATH`.
- `evaluation_definition_json`, a tagged union described below.
- `base_evidence_tiers_json`, a non-empty set containing `E0`, `E1`, and/or `E2`.
- `conditional_capabilities_json`, a set of optional source capabilities such as Macie or Purview.
- `certification_parameters_json`, the immutable parameter profiles used by release qualification.

Do not use a scalar `evidence_tier`. The catalog contains composite profiles such as `E0/E1`, `E1/E2`, `E0+C`, and `E1+C`. A policy records every base tier it consumes plus the exact optional capabilities that make it conditional.

The tagged `evaluation_definition_json` has exactly one of these shapes:

```json
{"mode":"ARTIFACT_FACTS","predicate":{}}
```

```json
{
  "mode":"DIRECT_RELATIONSHIP",
  "edgeTypes":["USES_MODEL"],
  "direction":"OUTBOUND",
  "sourcePredicate":{},
  "targetPredicate":{},
  "targetCardinality":"ANY"
}
```

```json
{
  "mode":"CORRELATION_PATH",
  "correlationId":"AGCF-XSP-001",
  "correlationVersion":"1.0.0"
}
```

The catalog linter rejects an entry when the stored `evaluation_mode` and tagged mode disagree, when more than one mode-specific payload is populated, or when the referenced correlation version does not exist.

Existing `predicate_json` and `required_relationships_json` are backfilled into the tagged definition during migration and retained as read compatibility fields for one release. All new evaluation uses the tagged definition.

### 2.2 Graph evaluation boundary

Both graph modes must use a shared `AiGridGraphEvidenceResolver` for snapshot selection, edge direction, fact binding, scope completeness, evidence freshness, and traversal limits. This prevents fixes to graph evidence semantics from diverging between posture and exposure evaluation.

The invariant separating the modes is:

- `DIRECT_RELATIONSHIP` is exactly one hop, begins with one artifact, produces one artifact-scoped posture assessment, cannot aggregate independent branches, and cannot create `EXPOSURE_HYPOTHESIS` or `VALIDATED_EXPOSURE`.
- `CORRELATION_PATH` is system-scoped, traverses one to six declared hops, may bind multiple nodes and branches, records path confidence, and is the only mode allowed to create an exposure hypothesis or validated exposure.

The direct evaluator may be implemented as a one-hop restricted profile of the shared resolver. It must not reimplement graph loading or fact-readiness rules.

### 2.3 Framework mapping extension

`framework_mappings_json` is already a structured JSONB column and remains the authoritative storage field. This is a shape extension, not a string-to-structure migration.

Migrate from:

```json
{"OWASP_LLM_TOP_10":["LLM01"]}
```

to:

```json
{
  "mappings":[
    {
      "framework":"OWASP_GENAI_LLM_TOP_10",
      "frameworkVersion":"2026",
      "controlId":"LLM01",
      "mappingType":"PARTIAL",
      "rationale":"Independently authored rationale"
    }
  ]
}
```

Use typed Java records for validation and API serialization while continuing to persist JSONB. Phase 1 accepts only:

- `CSA_AICM` version `1.1`.
- `OWASP_GENAI_LLM_TOP_10` version `2026`.
- Mapping types `DIRECT`, `PARTIAL`, and `INFORMATIVE`.

Every policy must have at least one valid AICM or OWASP mapping. OWASP is optional because valid AICM-only policies exist, including the owner-tag and required-tag Azure controls.

The UI and API must label these as mappings, not certifications.

### 2.4 Policy package source of truth

Place one immutable package at `policy-packages/agcf/<policy-id>/<version>.json` and one digest manifest at `policy-packages/agcf/phase-1-manifest.json`.

The manifest records:

- Policy ID and version.
- Package SHA-256 digest.
- Provider and objective ID.
- Evaluation mode.
- Default selection.
- Release family and wave.

The manifest is digest-verified but not cryptographically signed in Phase 1. Product and release material must not call it a signed manifest.

The package importer must persist all currently omitted fields, including `required_capabilities_json` and `required_relationships_json`. The package DTO may use typed Java records, but no database column rewrite is required solely because the existing controller currently receives JSON fields as strings.

The compiler/linter fails CI unless:

- There are exactly 76 unique policy IDs: 38 AWS, 32 Azure, and 6 multi-resource.
- Defaults equal 26 `REQUIRED`, 24 `ENABLED`, and 26 `DISABLED`.
- Every adapter references an active objective.
- Every fact, resource family, relationship type, capability, parameter, and correlation reference is registered.
- `base_evidence_tiers_json` is non-empty and every conditional capability is declared.
- Every mapping has a supported version, type, control ID, and non-empty rationale.
- Every evaluation definition satisfies the exactly-one-shape invariant.
- Every parameterized policy has at least one immutable certification profile.

## 3. Connector capability workstream

Capability gating is a standalone platform and connector workstream. It is not complete when the importer merely persists `required_capabilities_json`.

### 3.1 Capability model

Add a platform capability definition table and a tenant/run-scoped observation table.

Each capability observation records:

- Tenant, connector, provider, account/subscription, region where applicable, run ID, and resource family.
- Capability ID and connector implementation version.
- Provider API versions attempted.
- Status: `COMPLETE`, `DISABLED`, `UNAUTHORIZED`, `UNSUPPORTED_API`, `PARTIAL`, `ERROR`, or `STALE`.
- Permission or API error code with a sanitized detail.
- Observation time, valid-until time, and source scope record.

Initial AWS capability IDs:

- `AWS_BEDROCK_AGENTS`
- `AWS_BEDROCK_GUARDRAILS`
- `AWS_BEDROCK_KNOWLEDGE_BASES`
- `AWS_BEDROCK_MODELS_JOBS`
- `AWS_BEDROCK_INVOCATION_LOGGING`
- `AWS_IAM_ROLE_POLICIES`
- `AWS_LAMBDA_URLS`
- `AWS_AGENTCORE_GATEWAYS`
- `AWS_AGENTCORE_TARGETS`
- `AWS_SAGEMAKER_DOMAINS`
- `AWS_SAGEMAKER_MODELS_ENDPOINTS`
- `AWS_MACIE_CLASSIFICATION`

Initial Azure capability IDs:

- `AZURE_AI_ACCOUNTS`
- `AZURE_DIAGNOSTIC_SETTINGS`
- `AZURE_FOUNDRY_DEPLOYMENTS_RAI`
- `AZURE_FOUNDRY_AGENTS_TOOLS`
- `AZURE_ML_WORKSPACES_ENDPOINTS`
- `AZURE_SEARCH_CONTROL_PLANE`
- `AZURE_SEARCH_DATA_PLANE`
- `AZURE_BOT_CONFIGURATION`
- `AZURE_RBAC_ASSIGNMENTS`
- `AZURE_PURVIEW_CLASSIFICATION`

`AWS_BASE` and `AZURE_BASE` may be exposed as derived connector-health summaries, but no policy may depend on them. Policy requirements use resource-family capabilities so a missing SageMaker permission cannot block unrelated Bedrock guardrail decisions.

### 3.2 Producer and evaluation behavior

Each collector writes one capability observation per attempted family even when the family is disabled, unsupported, or unauthorized. Absence of the observation itself is `MISSING_CAPABILITY_OBSERVATION`, not COMPLETE.

Before evaluating facts, `AiGridAssessmentService` must:

1. Resolve every required capability for the artifact account/subscription, region, and run.
2. Continue only when every mandatory capability is `COMPLETE` and fresh.
3. Persist `NO_DECISION` with a specific reason for disabled, unauthorized, unsupported, partial, stale, error, or missing capability evidence.
4. Open or update a setup action with the capability ID and concrete permission/configuration remediation.
5. Avoid evaluating the predicate with an incomplete fact set.

Add equivalent capability checks to impact preview and readiness computation so preview, runtime assessment, and setup guidance cannot disagree.

Conditional capabilities remain visible on installed policies. Macie-, Purview-, Foundry-Agent-, and Search-data-plane-dependent policies still ship, but their framework status is `CONDITIONAL_AUTOMATED` until the tenant has a complete capability observation.

## 4. Fact and predicate implementation

### 4.1 Normalization

Replace the growing centralized attribute switch with registered fact producers grouped by provider and resource family. Each producer declares the facts and connector attributes it owns.

Every fact must preserve:

- `KNOWN`, `UNKNOWN`, `ERROR`, or `STALE` state.
- Evidence class and provenance.
- Source API/resource family and snapshot manifest.
- Observed time, freshness contract, schema version, and derivation inputs.
- Confidence and confidence method where relevant.

Missing provider fields must never be normalized to false. Unsupported API versions produce UNKNOWN/UNSUPPORTED evidence and an associated capability status.

Implement all E1 facts in the 76-policy evidence matrix from metadata already persisted by the AWS and Azure connectors. Do not add new cloud permissions for an E1 fact unless the normative catalog explicitly classifies it as a conditional source.

### 4.2 Predicate changes

Retain the existing logical operators, positive `in`, ordered numeric comparisons, and strength comparison.

Add only the missing catalog primitives:

- Parameter-backed `in`, composable with `not` for negated allowlists.
- `empty` and `non_empty` for strings, arrays, and objects.
- Collection `count_gt`, `count_gte`, `count_lt`, `count_lte`, and `count_eq`.
- `age_seconds_gt` and `age_seconds_gte` for ISO-8601 timestamp facts and numeric parameter thresholds.

All new operators remain subject to the existing depth and node limits. Type mismatch is a validation error during import and an evaluator ERROR for corrupt stored evidence, never a false predicate result.

## 5. Existing policy migration, replacement, and deprecation

### 5.1 Replacement path

For a seeded policy that has an equivalent Phase 1 adapter:

- Populate `replaces_policy_id` and `replaces_version`.
- Carry its tenant selection, scope, parameters, and artifact overrides forward unless the new package has an incompatible parameter schema.
- Use the stable objective ID plus subject ID as the finding reconciliation identity.
- Reconcile an existing open finding to the replacement adapter instead of opening a duplicate.
- Retire the old version only after the replacement passes certification and is published.
- Record selection and finding lineage in audit history.

### 5.2 Deprecation path

Seeded preview policies that cannot receive authoritative evidence and have no Phase 1 replacement must be deliberately deprecated. This includes the current public-MCP-reachability and Azure Search non-identity-auth concepts until their connector enhancements exist.

For each deprecated policy:

1. Set distribution to unavailable and `RETIRED`.
2. Retire its current policy version with a machine-readable deprecation reason and successor candidate ID where one exists.
3. Copy active tenant selection to history and remove it from current selections.
4. Close open findings with resolution reason `POLICY_RETIRED_INSUFFICIENT_EVIDENCE`; do not mark them remediated.
5. Resolve related coverage gaps with the same reason.
6. Preserve assessments, findings, reviews, and evidence as immutable historical records.
7. Display a historical-detail banner explaining that the detector was withdrawn because the connector could not produce authoritative evidence.
8. Create a `CONNECTOR_CAPABILITY` backlog candidate containing the missing metadata and reactivation criteria.

Fact definitions such as source ACL, retrieval mode, and MCP private endpoint that are not produced remain registered for historical readability but move to lifecycle `RETIRED` or `PLANNED`; they are excluded from shipped coverage.

No migration may delete tenant evidence, findings, assessments, or selection history.

## 6. Exposure implementation

The existing repository has three published correlation templates. Phase 1 must:

- Migrate those three definitions into the shared governance envelope.
- Author three additional correlation definitions to reach the six-entry target.
- Give every correlation an objective ID, framework mappings, package digest, distribution state, capability requirements, and certification profile.
- Continue storing bounded execution definitions in `ai_grid_correlation_versions`.
- Make the policy envelope the authoritative catalog, distribution, and framework-coverage record.
- Use the correlation reference in `evaluation_definition_json` to bind the envelope to its executable version.

Every exposure observation must include the exact artifact IDs, fact IDs, relationship IDs, coverage epoch, correlation digest, and confidence method. Proximity-only paths are invalid.

Posture and exposure findings may coexist. De-duplication means grouping and linking related evidence in the UI and action queue, not deleting the underlying posture finding.

## 7. Certification strategy and QA capacity

Certification is the program critical path and begins as soon as the first adapter compiles.

### 7.1 Mandatory answer keys

Every one of the 76 adapters requires at least these five certified cases:

- True positive / expected FAIL.
- True negative / expected PASS.
- Missing evidence / expected NO_DECISION.
- Stale evidence / expected NO_DECISION.
- Permission or capability failure / expected NO_DECISION or ERROR according to the contract.

This creates a minimum of 380 answer-key cases before parameter variants, multi-native-kind cases, and correlation paths. Plan QA automation capacity for approximately 450–500 fixtures and results.

### 7.2 Parameterized and DISABLED policies

Every parameterized package contains immutable `certification_parameters_json` profiles. An allowlist policy must include at least:

- A secure profile whose allowlist contains the observed fixture value.
- An insecure profile whose allowlist excludes the observed fixture value.
- An unset/invalid profile that proves configuration validation or NO_DECISION behavior.

Release qualification runs against these profiles and records their digest in the answer-key and precision-review material. Runtime tenant defaults remain `DISABLED`; certification parameters never become tenant defaults.

All 76 policies, including `DISABLED` policies, must pass answer-key and precision governance before publication. This prevents parameterized controls from reaching GA through a reduced release path.

### 7.3 Precision and review

- Use the existing independent author/approver rule.
- Update `AiGridValidationGovernanceService.publishPolicy` and `releaseReadiness` to require a fresh passing precision review for every Phase 1 package digest; remove the current HIGH/CRITICAL-only lookup condition for this release manifest.
- Require precision review for every Phase 1 policy version, not only HIGH/CRITICAL or default-enabled entries.
- Retain two independent reviewers and Wilson lower-bound requirements for HIGH and CRITICAL policies.
- For parameterized policies, bind samples and labels to the certification-profile digest.
- For correlations, bind samples to the correlation material digest and require both hypothesis and validated-exposure cases.
- A package, fact contract, evaluation definition, mapping, parameter profile, or correlation change invalidates prior certification through the material digest.

### 7.4 Non-functional gates

- Fully enabled golden connectors must produce at least 95% decisive assessments for eligible assets; every remainder needs an enumerated reason.
- Missing evidence must produce zero PASS decisions across the complete test suite.
- Every exposure result must have a direct evidence path.
- Full-catalog assessment time and database writes may regress by no more than 20% against the frozen pre-Phase-1 baseline.
- AWS and Azure permission manifests must cover all implemented provider calls and must contain no write or content-reading permission introduced by Phase 1.
- Rollback through `PAUSED` distribution plus version pinning must be demonstrated for AWS, Azure, and multi-resource families.

## 8. API and product changes

Extend the platform catalog response with objective ID, provider, evaluation mode, base evidence tiers, conditional capabilities, framework mappings, and release family.

Add or extend:

- `GET /api/platform/ai-grid/policies` for the unified 76-entry governed catalog.
- `GET /api/platform/ai-grid/policies/{id}/versions/{version}` for complete package metadata.
- `GET /api/platform/ai-grid/policies/portfolio/frameworks?framework=&version=` for per-control coverage, policy IDs, mapping types, and evidence status.
- `GET /api/ai-connector-capabilities` for tenant capability status by connector/resource family.
- `GET /api/ai-policies` to include objective, evidence profile, required capabilities, structured mappings, and readiness.
- Existing readiness and run-metrics responses to include eligible assets, decisive assessments, PASS/FAIL/NO_DECISION counts, reason, provider, native kind, capability, and evidence freshness.

All tenant capability, catalog, policy, readiness, and coverage endpoints must resolve the tenant and call `AiSecurityAccessService.assertEntitled`. Frontend routing must also continue to fail closed through the `ai.security` entitlement. Platform-owner governance endpoints remain platform-scoped.

Retain `/portfolio/owasp` for one compatibility release, implement it from the new mapping shape, and mark it deprecated.

The UI must display:

- All 76 entries, grouped by provider, objective, evaluation mode, and readiness.
- Selection independently from evidence readiness.
- Resource-family capability gaps without blocking unrelated families.
- Framework status as `AUTOMATED`, `CONDITIONAL_AUTOMATED`, `PREVENTIVE_ONLY`, `REQUIRES_RUNTIME_OR_TEST`, or `NOT_COVERED`.
- Framework version, mapping type, mapping rationale, and the policy evidence behind the status.
- Historical deprecation banners and non-remediation closure reasons.

## 9. Delivery sequence

### Weeks 1–3 — catalog and migration foundation

- Freeze the 76-row manifest and objective/adaptor assignments.
- Add objective, evaluation-definition, evidence-profile, certification-profile, and framework-shape migrations.
- Implement the compiler/linter and digest manifest.
- Map the 21 seeded posture policies and three correlations to replacement or deprecation outcomes.

**Exit:** 76 schema-valid draft packages and an approved legacy migration ledger.

### Weeks 1–7 — capability workstream

- Implement capability definitions, run observations, AWS/Azure producers, evaluation gating, readiness, impact preview, and setup actions.
- Add resource-family permission/API-version fixtures.
- Retire the obsolete AWS permission sample or redirect it to the maintained manifest.

**Exit:** capability-disabled, unauthorized, partial, unsupported, stale, and missing states produce deterministic NO_DECISION without affecting unrelated families.

### Weeks 4–13 — AWS adapters

- Release agent/IAM/Lambda and guardrail families first.
- Continue with knowledge/data, model lifecycle, AgentCore/MCP, and SageMaker.
- Keep Macie-dependent controls conditional.

**Exit:** 38 AWS adapters pass package, answer-key, precision, permission, performance, and canary gates.

### Weeks 4–15 — Azure adapters

- Release network/auth/logging and RAI controls first.
- Continue with models, Foundry Agents/tools, Search, ML, Bot, RBAC, and data relationships.
- Keep Purview, Foundry Agents, and Search data plane capability-gated.

**Exit:** 32 Azure adapters pass the same gates, with explicit unsupported-API behavior.

### Weeks 12–18 — correlations and portfolio UX

Exposure implementation begins only after the shared graph resolver and the E2 relationship/fact contracts freeze at the end of week 11.

- Author three new correlations and govern all six through policy envelopes.
- Add evidence-path rendering and related-finding grouping.
- Deliver versioned AICM and OWASP coverage views.

**Exit:** 6 multi-resource adapters pass hypothesis, validation, replay, demotion, and path-integrity certification.

### Weeks 3–21 — continuous certification

- Build fixtures, run answer keys, perform precision sampling and review, measure connector economics, and certify permission failures as adapters land.
- Do not defer the 380+ mandatory cases to the final wave.

**Exit:** all package digests have fresh passing qualification artifacts.

### Weeks 19–22 — canary and GA

- Canary internal tenants, then AWS design tenants, Azure design tenants, and combined-cloud tenants.
- Observe decisive rate, NO_DECISION reasons, false-positive disposition, scan cost, and database load.
- Demonstrate family rollback and version pinning.
- Promote all 76 entries to `GENERAL_AVAILABILITY` only after the release board accepts every quantitative gate.

**Exit:** 76/76 PUBLISHED and GA, with exact 26/24/26 defaults.

The 22-week target is aggressive and assumes the stated staffing. With one engineering squad or shared part-time QA, plan 32–36 weeks.

## 10. Next-target connector backlog

Create one or more `CONNECTOR_CAPABILITY` candidates from every AWS and Azure enhancement row in the normative policy plan. Each candidate records missing metadata, provider APIs, permission delta, safe persisted fields, privacy constraints, policies unlocked, owner, and evidence maturity.

Prioritize:

1. Effective AWS IAM and Azure RBAC decisions.
2. Referenced S3, Storage, Search, and vector-store network/encryption/authentication metadata.
3. Secret-safe Search and MCP authentication classification, source ACL enforcement, retrieval mode, and authoritative private-endpoint evidence.
4. Bedrock and Azure consumption, quotas, budgets, and alert telemetry.
5. Model/data provenance, signatures, registry lineage, SBOM/AI-BOM, and vulnerability evidence.
6. Explicitly consented runtime prompt-injection, content-safety, output-handling, and reachability evidence.

A candidate may become a policy package only after its capability observation, permission delta, sanitized fact contract, fixtures, answer keys, precision review, and NO_DECISION behavior are certified.

## 11. Final release checklist

- [ ] 76 unique packages: 38 AWS, 32 Azure, 6 multi-resource.
- [ ] Default split is 26 REQUIRED, 24 ENABLED, 26 DISABLED.
- [ ] 21 seeded posture policies and 3 seeded correlations have an approved replace-or-deprecate outcome.
- [ ] Three new correlation definitions exist and all six have governance envelopes.
- [ ] Every package has at least one valid AICM or OWASP mapping; AICM-only packages are accepted.
- [ ] Every evaluation definition satisfies the exactly-one-shape invariant.
- [ ] Composite evidence profiles and conditional capabilities are preserved.
- [ ] Resource-family capability gating works in assessment, preview, readiness, and setup actions.
- [ ] Deprecated policies close findings as insufficient-evidence retirements, not remediations.
- [ ] At least 380 mandatory answer-key cases pass; parameter and correlation variants also pass.
- [ ] All 76 policies pass precision governance, including fixed-profile certification for DISABLED policies.
- [ ] Missing, stale, unsupported, disabled, partial, and unauthorized evidence produce zero false PASS decisions.
- [ ] Every exposure contains a direct evidence path.
- [ ] Permission parity, entitlement, performance, rollback, and canary gates pass.
- [ ] Digest manifest, changelog, permission delta, framework statement, capability guide, and deprecation ledger are published.
