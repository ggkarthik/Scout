# AI Grid Tenant Policy Implementation and GA Plan

**Status:** Follow-on execution plan after the platform-owned policy catalog implementation  
**Target:** Tenant policy configuration, assessment, migration, and General Availability (GA)  
**Normative references:** [`ai-grid-phase-1-policy-plan.md`](./ai-grid-phase-1-policy-plan.md), [`ai-grid-phase-1-remaining-implementation-plan.md`](./ai-grid-phase-1-remaining-implementation-plan.md), [`ai-grid-phase-1-migration-ledger.md`](./ai-grid-phase-1-migration-ledger.md)

## 1. Purpose and release principle

This plan describes how to move from a platform-owned, versioned AI Grid catalog to tenant policy rollout and GA.

The previous plan establishes the governed catalog and release controls. It does **not** by itself mean that policies are ready for tenant use or GA. Tenant shipment is allowed only after policy versions are certified, published, available to the correct rollout cohort, and proven safe through assessment, migration, rollback, and isolation testing.

GA means the complete Phase 1 catalog, not a reduced preview subset:

| Provider/family | Target count |
|---|---:|
| AWS posture | 38 |
| Azure posture | 32 |
| Multi-resource exposure | 6 |
| **Total** | **76** |

The default tenant selection split is **26 REQUIRED, 24 ENABLED, and 26 DISABLED**. `DISABLED` means shipped and available for tenant configuration, but not selected by default; it does not mean hidden or uncertified.

## 2. Baseline after the previous implementation

The implementation is ready to enter tenant rollout only when these foundations are present:

- The platform catalog contains the exact Phase 1 identifiers: `AGCF-AWS-001` through `AGCF-AWS-038`, `AGCF-AZR-001` through `AGCF-AZR-032`, and `AGCF-XSP-001` through `AGCF-XSP-006`.
- Policy versions are immutable, digest-bound, and have objective, provider, lifecycle, evaluation mode, evidence profile, capabilities, framework mappings, and release metadata.
- Platform owners can see governed policies even when they are `VALIDATED` or `PAUSED` and unavailable to tenants.
- Tenant users cannot see or assess paused, retired, unavailable, or unassigned canary policies.
- Tenant policy reads and writes are executed in the authenticated tenant context.
- Tenant findings, evidence, assets, scopes, parameters, and overrides are never used by the platform catalog view.
- Missing, stale, partial, unauthorized, or unsupported evidence produces `NO_DECISION`, never `PASS`.

The current all-catalog database view may include legacy or retired entries. The Phase 1 release-family view must produce exactly 76 entries when filtered to `AGCF_PHASE_1`; do not use a larger unfiltered count as the GA target.

## 3. Lifecycle and visibility contract

Policy lifecycle and tenant availability are separate controls.

```text
DRAFT
  -> VALIDATED
  -> PUBLISHED
  -> CANARY (assigned cohort only)
  -> GENERAL_AVAILABILITY (all entitled tenants)
  -> PAUSED or RETIRED
```

### Platform-owner visibility

Platform owners may inspect all governed distributions, including validated and paused policies, to review metadata, readiness blockers, package digests, release decisions, and rollout state.

Expected platform surfaces:

- `/vuln-repo/policies`: platform-owned catalog and policy metadata view.
- `/platform/ai-policies`: governance, distribution, rollout, and release-control view.

Neither platform surface should load tenant findings, tenant assets, tenant coverage, tenant selections, or tenant policy parameters.

### Tenant visibility

An entitled tenant may see a policy only when all applicable conditions are true:

1. The tenant has the `ai.security` entitlement.
2. The policy version is published and available.
3. The distribution is GA, or the tenant is explicitly included in the canary cohort.
4. The policy is not paused or retired.
5. The request is evaluated in that tenant's authenticated context.

The tenant policy surface is `/policies`. Tenant visibility must not be implemented by trusting a client-supplied tenant ID, provider filter, or policy ID.

## 4. Tenant implementation steps

### Step 1 — Verify the platform catalog before tenant enablement

Before enabling any tenant, the platform owner and release board should verify:

- 76 Phase 1 rows are present in the platform catalog.
- Provider counts are exactly 38 AWS, 32 Azure, and 6 multi-resource.
- Default metadata is exactly 26 REQUIRED, 24 ENABLED, and 26 DISABLED.
- Every policy detail page exposes objective, version, digest, evidence tiers, required connector capabilities, native resource kinds, framework mappings, lifecycle, readiness, availability, and rollout state.
- No placeholder facts such as `agcf.<policy-id>.evidence` remain.
- No generic posture binding such as `AI_ARTIFACT` is used for a concrete policy.
- All package, SQL seed, manifest, answer-key, permission, capability, framework, migration, and changelog artifacts are reproducible.

If paused policies are absent from the platform view, treat that as a deployment, migration, API, or UI defect. Do not publish uncertified policies to make the tenant view appear complete.

### Step 2 — Certify evidence and connector capability

For every policy, document:

- required fact names and value types;
- source connector and provider API;
- native resource kinds and relationship requirements;
- freshness limit and provenance;
- required connector capabilities;
- behavior for missing, stale, partial, denied, unsupported, and proxy-only evidence;
- expected PASS, FAIL, and `NO_DECISION` answer-key results.

Azure capabilities must be treated explicitly because Azure discovery, Foundry Agents, Search data plane, and Purview are optional or less battle-tested in the current implementation. A tenant without a required capability remains policy-visible when appropriate, but assessment must report readiness or `NO_DECISION` rather than infer a pass.

### Step 3 — Enable the tenant entitlement

Enable `ai.security` for the tenant through the platform entitlement workflow. Record:

- tenant identifier;
- approving platform owner;
- effective time;
- enabled connector capabilities;
- rollout cohort and pinned policy release;
- audit event and change ticket.

Do not enable the entitlement by directly editing tenant tables in production. The entitlement operation must be authorized, audited, idempotent, and scoped to one tenant.

### Step 4 — Seed tenant selections using the approved baseline

For a new GA tenant, seed the exact Phase 1 baseline:

- 26 policies selected as `REQUIRED`;
- 24 policies selected as `ENABLED`;
- 26 policies available but not selected by default as `DISABLED`.

Selections are tenant configuration, not platform catalog metadata. The platform owner may govern the release and default classification, but a tenant administrator owns tenant-specific selection changes unless a documented platform baseline explicitly overrides that authority.

Seed operations must be:

- idempotent;
- version-aware;
- tenant-scoped;
- safe to retry;
- audited with actor, reason, old value, new value, and release digest.

### Step 5 — Configure tenant scopes, parameters, and exceptions

Before the first assessment, the tenant administrator reviews:

- cloud accounts/subscriptions and regions in scope;
- approved model, provider, tool, MCP, channel, and resource allowlists;
- guardrail, retention, logging, network, identity, and encryption baselines;
- required connector capabilities;
- policy-specific parameters;
- approved exclusions and expiration dates.

Every scope, parameter, and override must belong to the current tenant. A tenant must not be able to reference another tenant's asset, connector, policy selection, parameter profile, or exception by ID.

### Step 6 — Run the first tenant discovery and assessment

Run a fresh snapshot and assessment after connector configuration. Verify the complete pipeline:

```text
tenant snapshot
  -> immutable artifacts and relationships
  -> normalized facts
  -> ownership and grouping
  -> policy assessment
  -> exposure correlation
  -> readiness/coverage
  -> canonical tenant findings
```

Review at minimum:

- policies evaluated and policies skipped;
- PASS, FAIL, and `NO_DECISION` counts;
- `NO_DECISION` reasons by capability, freshness, authorization, unsupported scope, and missing evidence;
- finding subjects and tenant ownership;
- duplicate or replayed findings;
- assessment duration, database writes, connector calls, and errors;
- evidence and package digests attached to the run.

Do not interpret an empty finding set as success without confirming that the policies actually evaluated and that evidence was available.

### Step 7 — Migrate legacy tenant configuration and findings

Apply the approved migration ledger only after replacement policies are published and available to the tenant.

Migration must preserve:

- tenant selections;
- scopes and parameter profiles;
- approved overrides and exclusions;
- finding identity and status history;
- first-seen, last-seen, and closure timestamps;
- links to source runs and evidence;
- replacement and retirement lineage.

Reconcile findings by stable policy objective and subject identity. Never create a second finding merely because the replacement policy has a new internal version or package digest.

Insufficient-evidence policies must be retired with the explicit reason `POLICY_RETIRED_INSUFFICIENT_EVIDENCE`; that closure is not remediation and must not be reported as a tenant fix.

### Step 8 — Canary the tenant rollout

Roll out in this order:

1. Internal platform test tenant.
2. AWS design-partner tenants.
3. Azure design-partner tenants.
4. Combined AWS/Azure tenants.
5. Broader entitled tenant cohort.

Pin the exact certified package digest for each cohort. Monitor decision rates, `NO_DECISION` reasons, false-positive dispositions, connector errors, assessment latency, database load, scan cost, and duplicate finding rates.

### Step 9 — Perform rollback and replay drills

For each provider family:

1. Pause the distribution or remove availability for the canary cohort.
2. Revert to the last known-good pinned version.
3. Replay an identical snapshot/run.
4. Confirm no duplicate findings or lost evidence.
5. Confirm tenant selections and overrides remain intact.
6. Confirm platform audit history records the release and rollback.
7. Restore the canary only after the release board accepts the evidence.

Rollback is a control-plane change. Do not delete immutable policy versions, evidence, assessment runs, findings, or audit history.

### Step 10 — Promote to GA

After all release gates pass, the platform owner:

1. Records approval against the exact package digests.
2. Publishes all approved policy versions.
3. Changes distribution state to `GENERAL_AVAILABILITY` and availability to true.
4. Removes the canary-only restriction while retaining the pinned release.
5. Runs the tenant catalog smoke test for a new tenant and an upgraded tenant.
6. Applies the approved legacy migration to the GA cohort.
7. Announces the release with known limitations, connector requirements, and rollback instructions.

## 5. Mandatory release gates

All seven gates from the Phase 1 release plan require current passing evidence:

| Gate | Required proof |
|---|---|
| `CANARY_AWS` | AWS design-tenant canary passes assessment, isolation, precision, and operational checks. |
| `CANARY_AZURE` | Azure design-tenant canary passes the same checks, including optional-capability behavior. |
| `CANARY_MULTI_CLOUD` | Cross-cloud exposure policies produce correct results without cross-tenant or cross-account contamination. |
| `PERFORMANCE` | Full-catalog cost is within 20% of the frozen pre-Phase-1 baseline; shared evidence indexes are reused. |
| `ROLLBACK_AWS` | AWS pause, pin reversal, replay, and finding deduplication succeed with history preserved. |
| `ROLLBACK_AZURE` | Azure pause, pin reversal, replay, and finding deduplication succeed with history preserved. |
| `ROLLBACK_MULTI_CLOUD` | Multi-resource rollback does not leave orphaned correlations, duplicate findings, or stale exposure state. |

The release board must also confirm catalog completeness, connector contract integrity, authorization/isolation, migration lineage, and operational readiness. A passing gate is tied to the exact package and correlation digests tested; changing a material digest invalidates the certification.

## 6. Isolation requirements and verification

### Platform versus tenant

- Platform catalog queries use platform schema/data only.
- Platform-owner pages do not query tenant findings, assets, coverage, selections, parameters, or tenant evidence.
- Tenant policy queries cannot expose platform-only distribution administration fields unless explicitly classified as safe metadata.
- Platform lifecycle operations are not callable through tenant endpoints.
- Tenant configuration cannot change global policy definitions, package digests, release decisions, or another tenant's rollout.

### Tenant versus tenant

- Every tenant request derives tenant context from authenticated identity and server-side authorization.
- Every tenant read and write is filtered by the current tenant context.
- Repository, connector, asset, snapshot, fact, relationship, finding, selection, scope, parameter, override, and audit lookups are tenant-scoped.
- Cross-tenant IDs supplied by a client return not-found or forbidden without revealing existence.
- Background jobs carry an explicit tenant context and cannot reuse mutable state from another tenant.
- Caches, temporary files, queues, and outbox events include tenant identity in their key or payload and are authorization-checked on consumption.
- PostgreSQL search path and RLS controls are verified for the runtime production role, not only the application test role.

Required isolation tests include:

- tenant A cannot read or mutate tenant B policy selections;
- tenant A cannot see tenant B findings, assets, evidence, or connector errors;
- a platform owner sees governed catalog metadata but no tenant data through the platform catalog;
- paused, retired, or unassigned canary policies are hidden from tenant A;
- a canary assignment for tenant A does not make the policy visible to tenant B;
- identical policy/objective IDs across tenants remain separate by tenant and subject identity;
- replaying tenant A cannot create or modify tenant B findings;
- direct SQL access through the application role cannot bypass tenant isolation.

## 7. Test and verification matrix

| Area | Required scenarios |
|---|---|
| Catalog | Fresh database and upgraded database both resolve the exact 76 Phase 1 entries. |
| Platform UI/API | Paused/validated policies are visible to platform owners; provider and lifecycle filters do not hide governed rows. |
| Tenant UI/API | Entitled GA tenant sees all 76, including disabled-by-default policies; unentitled tenant does not. |
| Canary | Assigned tenant sees canary policies; unassigned tenant does not. |
| Evidence | PASS, FAIL, stale, missing, denied, partial, unsupported, and proxy-only evidence produce expected decisions. |
| Configuration | Selection, scope, parameter, exception, and entitlement operations are idempotent and audited. |
| Assessment | Fresh run creates canonical findings, preserves `NO_DECISION`, and does not duplicate findings on replay. |
| Migration | Legacy selections, scopes, overrides, findings, and history retain lineage and tenant ownership. |
| Rollback | AWS, Azure, and multi-resource pause/pin/replay paths preserve evidence and history. |
| Isolation | Platform/tenant and tenant/tenant negative tests pass at API, service, SQL, cache, job, and UI layers. |
| Quality | Frontend lint, typecheck, build, tests; backend `mvn -q verify`; SpotBugs; integration/failsafe tests; secret scanning. |

## 8. Ownership and operating model

| Role | Responsibility |
|---|---|
| Platform owner | Owns catalog, release decisions, distribution, cohorts, GA approval, and rollback authorization. |
| AI Grid engineering | Owns policy compiler, assessment engine, evidence contracts, migrations, and isolation controls. |
| Connector engineering | Owns provider collection, permissions, capability declarations, freshness, and source provenance. |
| Tenant administrator | Owns entitlement request, selections, scopes, parameters, exceptions, and remediation workflow. |
| Security reviewer | Independently reviews policy intent, answer keys, mappings, precision, and release risk. |
| SRE/DBA | Owns deployment, migrations, RLS/runtime-role verification, performance, monitoring, backup, and recovery. |

## 9. GA definition of done

GA may be declared only when every item is true:

- [ ] Platform catalog shows exactly 76 Phase 1 policies: 38 AWS, 32 Azure, and 6 multi-resource.
- [ ] All 76 current package digests have approved release decisions and independent precision review.
- [ ] All 76 policies are `PUBLISHED`, available, and `GENERAL_AVAILABILITY`.
- [ ] Entitled tenants see all 76 policies, including the 26 disabled-by-default entries.
- [ ] Tenant defaults are exactly 26 REQUIRED, 24 ENABLED, and 26 DISABLED.
- [ ] Seven of seven canary, performance, and rollback gates pass.
- [ ] There are no unresolved P0/P1 defects and no open platform/tenant or tenant/tenant isolation findings.
- [ ] Real connector facts and correlation evidence replace all placeholder contracts.
- [ ] Missing or insufficient evidence never produces PASS.
- [ ] Legacy selections, parameters, scopes, overrides, findings, and history are migrated according to the approved ledger.
- [ ] Replaced policies do not create duplicate findings.
- [ ] Insufficient-evidence retirements use the explicit non-remediation reason.
- [ ] Rollback has been demonstrated without loss of evidence, history, or tenant configuration.
- [ ] Monitoring, audit events, incident ownership, and the rollback runbook are deployed.
- [ ] CI is green, including backend integration tests, frontend tests, static analysis, migration guards, and secret scanning.

If any item remains incomplete, the release status is **Phase 1 in progress**, not GA.

## 10. Known risks and explicit blockers to revalidate

- Azure is newer and less battle-tested in the current implementation. Azure canary evidence must be reviewed separately rather than inferred from AWS results.
- Full tenant RLS enforcement and production-role verification remain release-critical. Passing tests under an elevated or test-only database role is insufficient.
- Optional Macie, Purview, Foundry Agent, and Search data-plane evidence must remain clearly conditional. Unavailable optional evidence must produce `NO_DECISION`.
- Known migration anomalies documented in `CLAUDE.md` must be revalidated against the current branch before GA; do not assume stale notes are current defects or current fixes.
- A larger unfiltered policy count may include legacy or retired distributions. GA completeness is measured against the exact `AGCF_PHASE_1` 76-policy catalog.

## 11. Suggested execution sequence

1. Close catalog, compiler, and evidence-contract gaps.
2. Complete the seven release gates with exact digest-bound evidence.
3. Verify tenant entitlement, selection, scope, parameter, and override APIs with negative isolation tests.
4. Run fresh-install and upgrade-path tenant migration tests.
5. Canary internal, AWS, Azure, and combined-cloud tenants.
6. Execute pause, rollback, replay, and duplicate-finding drills.
7. Obtain independent security and release-board approval.
8. Promote all 76 policies to GA.
9. Apply legacy migration to the approved tenant cohort.
10. Monitor post-GA decision quality, `NO_DECISION` rates, latency, cost, connector errors, and isolation alerts.

