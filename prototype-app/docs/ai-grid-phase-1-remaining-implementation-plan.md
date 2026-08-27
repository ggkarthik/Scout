# AI Grid Phase 1 — remaining implementation and release plan

**Status:** Execution plan for work remaining after the Phase 1 catalog seed  
**Status date:** 2026-08-27  
**Normative catalog:** [`ai-grid-phase-1-policy-plan.md`](./ai-grid-phase-1-policy-plan.md)  
**Package manifest:** [`phase-1-manifest.json`](../policy-packages/agcf/phase-1-manifest.json)  
**Target release:** 76 out-of-box policies: 38 AWS posture, 32 Azure posture, and 6 multi-resource exposure policies  
**Default split:** 26 `REQUIRED`, 24 `ENABLED`, and 26 `DISABLED`

## 1. Outcome and release principle

Phase 1 is complete only when the exact 76-policy catalog is:

1. Visible to platform owners in AI Policy Studio, including policies that are still `VALIDATED` or `PAUSED`.
2. Backed by real AWS/Azure connector facts or executable correlation evidence.
3. Certified by platform-run answer keys and independent precision review.
4. Published and available to entitled tenants at `GENERAL_AVAILABILITY`.
5. Presented to tenants with the exact 26/24/26 default split.
6. Migrated from the legacy policy set without duplicate findings or lost history.

Engineering waves may be implemented and canaried incrementally. Phase 1 must not be marketed or declared generally available as a 15–20-policy subset. General availability is the complete 76-policy catalog.

`DISABLED` means shipped, visible, certified, and available for tenant configuration, but not selected by default. It does not mean absent, paused, preview, or uncertified.

## 2. Verified starting state

| Area | Current state | Remaining conclusion |
|---|---:|---|
| Governed package files | 76/76 | Catalog shape exists |
| Provider split | 38 AWS / 32 Azure / 6 multi-resource | Correct |
| Default split | 26 required / 24 enabled / 26 disabled | Correct |
| Package compiler | Present and currently passes | Must be strengthened and enforced in CI |
| Permission manifest validation | Passes | Must remain tied to implemented provider calls |
| Concrete catalog fact contracts | 39/76 | Must be verified end to end |
| Synthetic placeholder fact contracts | 37/76 | Must be replaced before release |
| Phase 1 lifecycle | 76 `VALIDATED` | None published |
| Phase 1 distribution | 76 `PAUSED`, unavailable | None tenant-visible |
| Approved release decisions | 0 | 76 required |
| Release-board evidence | No completed seven-gate release | All gates required |
| Tenant-visible legacy catalog | 18 policies | Expected safety fallback until cutover |

The platform-owner endpoint is intended to show governed distributions regardless of tenant availability. If AI Policy Studio does not show the 76 paused Phase 1 entries, that is a P0 deployment, migration, API, or UI defect. It must not be worked around by publishing uncertified policies.

## 3. Exact out-of-box catalog contract

The release contains every entry in the normative catalog:

- AWS posture: `AGCF-AWS-001` through `AGCF-AWS-038`.
- Azure posture: `AGCF-AZR-001` through `AGCF-AZR-032`.
- Multi-resource exposure: `AGCF-XSP-001` through `AGCF-XSP-006`.

The exact names, evidence tiers, defaults, OWASP mappings, and CSA AICM mappings are defined in [`ai-grid-phase-1-policy-plan.md`](./ai-grid-phase-1-policy-plan.md). The package manifest is the digest-bound deployable inventory. Neither source may be silently filtered by lifecycle, default selection, capability readiness, or provider availability in the platform-owner catalog view.

## 4. Remaining workstreams

### WP0 — Restore complete Platform Studio visibility

**Priority:** P0  
**Goal:** Platform owners can inspect the complete planned catalog before it is released to tenants.

Work:

1. Trace the deployed request from AI Policy Studio through `GET /api/platform/ai-grid/policies` to the platform database.
2. Verify that migrations V75–V87 ran in the deployed environment and that all 76 AGCF distributions exist.
3. Make the platform endpoint return governed policies in every lifecycle and rollout stage, including `VALIDATED/PAUSED`.
4. Add release-family and lifecycle filters without applying a hidden default that removes paused policies.
5. Add an explicit **Phase 1 out-of-box catalog** summary showing:
   - 76 total;
   - 38 AWS, 32 Azure, 6 multi-resource;
   - 26 required, 24 enabled, 26 disabled;
   - counts by `VALIDATED`, `PUBLISHED`, `PAUSED`, `CANARY`, and GA.
6. Show readiness and distribution as separate columns. A policy may be catalog-visible while unavailable to tenants.
7. Display legacy policies in a separately labelled legacy/replacement view so they cannot be mistaken for the Phase 1 catalog.
8. Add API integration tests against both a fresh database and an upgraded pre-Phase-1 database.
9. Add a frontend end-to-end test asserting that all 76 IDs render for a platform owner.
10. Add a deployment smoke check that fails when the manifest count, database count, API count, and UI count disagree.

**WP0 Definition of Done**

- AI Policy Studio displays exactly 76 Phase 1 rows when filtered to `AGCF_PHASE_1`, including all paused rows.
- Provider counts are exactly 38/32/6 and defaults are exactly 26/24/26.
- `AGCF-AWS-001`, `AGCF-AZR-001`, and `AGCF-XSP-001` detail pages show package metadata, readiness blockers, mappings, and rollout state.
- Fresh-install and upgrade-path integration tests return the same 76-entry catalog.
- Tenant policy APIs continue to exclude paused policies.
- No direct database edit or manual lifecycle change is needed to make the catalog visible.

### WP1 — Harden the catalog compiler and contracts

**Priority:** P0  
**Goal:** A package cannot compile unless the runtime can bind and type its evidence.

Work:

1. Reject any required fact with an `agcf.<policy-id>.evidence` placeholder key.
2. Reject generic posture artifact binding such as `AI_ARTIFACT`.
3. Require a concrete `nativeKinds` or typed artifact binding for every posture policy.
4. Generate fact-definition value types from `requiredFacts.valueType`; remove the current unconditional boolean seed behavior.
5. Validate every predicate operator against its fact type.
6. Validate that every required fact is declared by a registered producer.
7. Validate that every required capability maps to a connector attempt and observation.
8. Reject generic security intent, description, remediation, or framework rationale templates.
9. Keep the manifest, SQL seed, answer-key corpus, capability guide, framework statement, permission delta, and changelog reproducible from source.
10. Run compilation and zero-diff generation in CI.

**WP1 Definition of Done**

- The compiler reports zero placeholder facts and zero generic posture artifact bindings.
- Every seeded fact has the same type as the package contract and predicate.
- Every package fact maps to exactly one registered producer or a governed correlation output.
- Re-running generation produces no repository diff.
- Hand-edited generated SQL fails CI.

### WP2 — Complete AWS connector evidence and policy adapters

**Priority:** P0  
**Goal:** All 38 AWS policies make evidence-safe decisions from real connector metadata.

The 20 policies already carrying concrete catalog contracts must be verified from provider fixture through decision:

`AGCF-AWS-001–006`, `009–010`, `012`, `018–020`, `027`, `029–033`, `036`, and `038`.

The following 18 placeholder policies require concrete connector/fact implementations:

`AGCF-AWS-007`, `008`, `011`, `013–017`, `021–026`, `028`, `034–035`, and `037`.

For every AWS policy:

1. Name the exact AWS API response field and read-only IAM action.
2. Persist only the minimum sanitized metadata required by the policy.
3. Emit a typed canonical fact with source, scope, observed time, freshness, and confidence.
4. Emit resource-family capability observations for complete, unauthorized, unsupported, partial, stale, and error states.
5. Bind the policy to concrete AWS native kinds and relationships.
6. Add secure, insecure, missing, stale, permission-failure, and proxy/verified fixtures.
7. Verify `PASS`, `FAIL`, `NO_DECISION`, `ERROR`, and `NOT_APPLICABLE` semantics.

Macie-dependent policies remain conditional, but still ship. Without a complete Macie capability they must return a specific `NO_DECISION`, never PASS.

**WP2 Definition of Done**

- 38/38 AWS policies have real fact producers or governed graph/correlation inputs.
- 38/38 bind to discovered AWS native kinds without generic artifact matching.
- Every AWS provider call appears in the maintained read-only permission manifest.
- Missing or denied AWS permissions produce a capability-specific `NO_DECISION` and setup remediation.
- All mandatory AWS engine-backed answer-key cases pass.

### WP3 — Complete Azure connector evidence and policy adapters

**Priority:** P0  
**Goal:** All 32 Azure policies make evidence-safe decisions from real connector metadata.

The 19 policies already carrying concrete catalog contracts must be verified end to end:

`AGCF-AZR-001–008`, `010–012`, `017–019`, `022`, and `025–028`.

The following 13 placeholder policies require concrete connector/fact implementations:

`AGCF-AZR-009`, `013–016`, `020–021`, `023–024`, and `029–032`.

For every Azure policy:

1. Name the exact Resource Graph, ARM, or approved data-plane field and API version.
2. Name the read-only action or role permission required to collect it.
3. Persist a sanitized, typed fact with provenance and freshness.
4. Record resource-family capability status independently so one unavailable family does not block unrelated policies.
5. Bind to concrete Azure resource types and relationships.
6. Test secure, insecure, missing, stale, permission-failure, unsupported-API, and proxy/verified cases.

Purview-, Foundry-Agent-, and Search-data-plane-dependent policies remain conditional but must be installed, visible, and certifiable. Incomplete capability evidence produces `NO_DECISION` with setup guidance.

**WP3 Definition of Done**

- 32/32 Azure policies have real fact producers or governed graph/correlation inputs.
- 32/32 bind to discovered Azure resource types without generic artifact matching.
- Every Azure provider call appears in the maintained read-only permission contract.
- Unsupported API versions and denied permissions are distinguishable from secure configuration.
- All mandatory Azure engine-backed answer-key cases pass.

### WP4 — Complete the six exposure correlations

**Priority:** P0  
**Goal:** All six multi-resource policies execute real bounded graph definitions and produce explainable paths.

Work:

1. Bind `AGCF-XSP-001–006` to their six correlation versions through the governance envelope.
2. Remove any synthetic `agcf.*.evidence` dependency from exposure packages.
3. Reuse one snapshot, fact index, and relationship index across all applicable posture and correlation evaluations in a run.
4. Enforce path length, direction, scope completeness, freshness, confidence, and traversal limits.
5. Persist exact artifact IDs, fact IDs, relationship IDs, correlation digest, coverage epoch, and confidence method.
6. Test hypothesis creation, validation, replay, evidence invalidation, demotion, and related-finding grouping.

**WP4 Definition of Done**

- 6/6 exposure policies execute a registered correlation definition.
- Every exposure includes a direct, renderable evidence path; proximity-only results are rejected.
- A changed or stale edge/fact invalidates or demotes the exposure deterministically.
- Correlations do not re-traverse or reload the same run snapshot per policy.
- All mandatory correlation cases and path-integrity tests pass.

### WP5 — Execute certification and precision governance

**Priority:** P0  
**Goal:** Replace draft corpus metadata with actual platform-run evidence.

Work:

1. Execute all 456 corpus cases through the real engine:
   - secure;
   - insecure;
   - missing evidence;
   - stale evidence;
   - capability failure;
   - proxy versus verified evidence.
2. Persist run IDs, catalog/package digests, artifacts, facts, relationships, decisions, findings, gaps, and closure transitions.
3. Add parameter-profile variants for all 26 default-disabled policies.
4. Add multi-native-kind variants and correlation path variants.
5. Collect precision samples from golden connectors and canary tenants.
6. Require an independent reviewer for every one of the 76 policies.
7. Invalidate certification whenever material package or correlation digests change.

**WP5 Definition of Done**

- 456/456 mandatory cases have completed platform-run results matching expected outcomes.
- Missing, stale, partial, unauthorized, unsupported, and proxy-only evidence produce zero false PASS decisions.
- 76/76 current package digests have a passing precision review.
- Author and approver are different people.
- All 26 disabled-by-default policies are certified against immutable parameter profiles.
- Release readiness reports 76/76 ready with no unresolved blocker.

### WP6 — Prove performance, rollback, and operational safety

**Priority:** P0  
**Goal:** Demonstrate that scaling from the legacy catalog to 76 policies is operationally safe.

Work:

1. Freeze the pre-Phase-1 21-policy performance baseline.
2. Benchmark 70 posture policies and the complete 70+6 catalog.
3. Add a dedicated benchmark proving capability checks short-circuit before graph and fact evaluation.
4. Measure a fully capable tenant and a mostly-missing-capability tenant.
5. Cache capability resolution, artifact binding, fact indexes, and graph edges once per run/snapshot.
6. Compare wall time, CPU, memory, database queries/writes, fact reads, and graph traversals.
7. Demonstrate `PAUSED` rollback and version pinning for AWS, Azure, and multi-resource families.
8. Verify restart/replay idempotency and no duplicate findings during rollback.

**WP6 Definition of Done**

- Full-catalog assessment cost regresses by no more than 20% against the frozen baseline.
- A missing-capability decision performs no policy fact query or graph traversal.
- Shared run evidence is resolved once and reused across policies and correlations.
- AWS, Azure, and multi-resource rollback tests pass with preserved history.
- Performance and rollback evidence is recorded in the release-board store.

### WP7 — Governed canary, migration, and GA cutover

**Priority:** P0  
**Goal:** Replace the legacy tenant catalog with the complete Phase 1 catalog safely.

Work:

1. Record passing evidence for all seven release gates:
   - `CANARY_AWS`;
   - `CANARY_AZURE`;
   - `CANARY_MULTI_CLOUD`;
   - `PERFORMANCE`;
   - `ROLLBACK_AWS`;
   - `ROLLBACK_AZURE`;
   - `ROLLBACK_MULTI_CLOUD`.
2. Publish only current, certified package digests.
3. Canary internal tenants, then AWS design tenants, Azure design tenants, and combined-cloud tenants.
4. Monitor decision rates, `NO_DECISION` reasons, false-positive dispositions, errors, scan cost, and database load.
5. Apply the approved migration ledger only after replacement policies are published and available.
6. Reconcile findings by objective and subject identity instead of creating duplicates.
7. Retire replaced legacy policies and close the two insufficient-evidence policies with the explicit non-remediation reason.
8. Promote the complete 76-policy catalog to GA after release-board approval.

**WP7 Definition of Done**

- Seven of seven release gates have current passing evidence.
- 76/76 package versions have approved release decisions.
- 76/76 policies are `PUBLISHED`, available, and `GENERAL_AVAILABILITY`.
- Tenant catalog displays all 76 policies, including the 26 disabled-by-default entries.
- Tenant defaults are exactly 26 required, 24 enabled, and 26 disabled.
- Replaced legacy findings retain lineage and do not duplicate.
- Retired insufficient-evidence findings are closed as `POLICY_RETIRED_INSUFFICIENT_EVIDENCE`, never remediated.
- The 18-policy fallback no longer determines the tenant catalog after successful cutover.

## 5. Delivery sequence and capacity assumption

The following forecast assumes two delivery squads, one dedicated QA automation engineer, and two available security reviewers:

- Squad A: three connector/backend engineers.
- Squad B: two backend/platform engineers and one frontend engineer.
- QA: one automation engineer.
- Security: two reviewers with reserved review capacity.
- Each two-week sprint provides about 70 gross engineering/QA person-days; reserve 20%, leaving approximately 56 planned person-days plus security review capacity.

Historical velocity was not supplied, so story points are intentionally not invented. Reforecast after the first sprint using observed throughput. With one squad or part-time QA/security review, expect the duration to expand materially.

| Sprint | Primary outcome | Workstreams |
|---|---|---|
| 1 — weeks 1–2 | All 76 Phase 1 policies visible in Platform Studio; compiler blocks placeholder/type defects | WP0, WP1 |
| 2 — weeks 3–4 | First half of missing AWS/Azure facts implemented; certification harness executes real engine runs | WP2, WP3, WP5 |
| 3 — weeks 5–6 | Remaining posture fact producers implemented and concrete resource binding complete | WP2, WP3 |
| 4 — weeks 7–8 | Six correlation paths complete; 456-case execution underway | WP4, WP5 |
| 5 — weeks 9–10 | 76/76 answer-key results and precision reviews complete | WP5 |
| 6 — weeks 11–12 | Performance, rollback, and internal canary gates pass | WP6, WP7 |
| 7 — weeks 13–14 | Design-tenant canary completes; complete catalog promoted to GA and legacy migration applied | WP7 |

**Forecast:** 14 weeks under the stated staffing and reviewer availability. Do not compress the release by deleting policies from the GA target; adjust staffing or schedule instead.

## 6. Dependencies and critical path

Critical path:

`Platform visibility and compiler integrity` → `real connector facts and bindings` → `engine-backed answer keys` → `precision review` → `performance/rollback` → `canary` → `approved GA promotion` → `legacy migration`

External dependencies:

- AWS and Azure fixture accounts/subscriptions with representative AI resources.
- Read-only connector permissions for every implemented metadata call.
- Macie and Purview test environments for conditional evidence.
- At least one AWS, one Azure, and one combined-cloud canary tenant.
- Two independent security reviewers with scheduled capacity.
- Product approval of descriptions, remediation guidance, mappings, and default selection.

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Placeholder policies reveal connector metadata that is not safely obtainable | Mark the exact policy blocked, document the connector enhancement, and do not substitute a synthetic PASS/FAIL signal |
| Platform catalog and tenant catalog are conflated | Maintain separate catalog visibility and tenant distribution acceptance tests |
| Certification becomes a final-sprint bottleneck | Execute answer keys continuously as each producer lands; reserve reviewers from sprint 2 |
| 76-policy evaluation exceeds the 20% ceiling | Enforce capability short-circuit and one-run evidence indexes before broad performance tuning |
| Legacy migration creates duplicate findings | Reconcile by stable objective ID plus subject ID and test replay/rollback |
| Conditional capabilities reduce decisive rate | Show capability-specific readiness and setup actions; do not hide the installed policy |
| Generated seed diverges from packages | Make zero-diff compilation a required CI check |

## 8. Phase 1 Definition of Done

Phase 1 is done only when every statement below is true.

### Catalog and platform view

- [ ] Platform Studio shows exactly 76 Phase 1 policies: 38 AWS, 32 Azure, and 6 multi-resource.
- [ ] Platform Studio shows paused/validated policies before release and clearly distinguishes catalog presence from tenant availability.
- [ ] Exact defaults are 26 required, 24 enabled, and 26 disabled.
- [ ] Every policy has an accessible detail view with objective, provider, evaluation mode, evidence profile, capabilities, mappings, package digest, readiness, and rollout status.
- [ ] Fresh-install and upgrade-path tests prove identical catalog visibility.

### Package and evidence integrity

- [ ] There are zero `agcf.<policy-id>.evidence` placeholder facts.
- [ ] There are zero generic posture `AI_ARTIFACT` bindings.
- [ ] Every required fact has a typed, registered producer and source API contract.
- [ ] Every policy has a concrete capability, resource family/native kind, freshness contract, and provenance path.
- [ ] Missing or incomplete evidence never becomes PASS.

### Functional qualification

- [ ] 38/38 AWS posture policies pass end-to-end qualification.
- [ ] 32/32 Azure posture policies pass end-to-end qualification.
- [ ] 6/6 exposure policies pass correlation and path-integrity qualification.
- [ ] 456/456 mandatory answer-key scenarios execute through the real engine and match expected results.
- [ ] 76/76 current package digests pass independent precision review.
- [ ] All parameter, multi-native-kind, and correlation variants pass.

### Non-functional and governance qualification

- [ ] Full-catalog performance is within 20% of the frozen pre-Phase-1 baseline.
- [ ] Capability checks demonstrably short-circuit before fact and graph evaluation.
- [ ] Shared snapshot, fact, artifact, and relationship indexes are reused across policies.
- [ ] AWS and Azure permission manifests exactly cover implemented read-only calls and add no write/content-reading permission.
- [ ] Seven of seven canary, performance, and rollback gates pass.
- [ ] 76/76 release decisions are approved for the exact current digests.

### Tenant shipment and migration

- [ ] 76/76 policies are published, available, and GA.
- [ ] Entitled tenants see all 76 policies, including disabled-by-default controls.
- [ ] Default tenant selection is exactly 26/24/26.
- [ ] Legacy selections, parameters, scopes, overrides, findings, and history are migrated according to the approved ledger.
- [ ] Replaced legacy policies do not create duplicate findings.
- [ ] Insufficient-evidence retirements are explicitly labelled and never presented as remediation.
- [ ] Rollback has been demonstrated without loss of evidence or history.

If any checkbox remains incomplete, the release status is **Phase 1 in progress**, not shipped.
