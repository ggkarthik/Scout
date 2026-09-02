# AI Grid Phase 2 — Implementation Plan

> **Reconciled with [`ai-grid-phase-2-lifecycle-decision-record.md`](./ai-grid-phase-2-lifecycle-decision-record.md).** The original draft of this plan described the 16 changed controls as `1.1.0` version revisions of their existing policy IDs. That conflicted with the separately-developed lifecycle model, which treats them as explicit new-ID replacements with the predecessor deprecated. The decision record resolves the conflict in favor of the new-ID replacement model; every section below reflects that resolution. Sections marked "Reconciled" were edited from the original draft — see the decision record for the full rationale.

## Summary

Phase 2 expands AI Grid from the 76-policy Phase 1 catalog to evidence-backed effective access, backing-store security, Search/MCP controls, consumption monitoring, and model/data provenance.

Locked decisions:

- Runtime prompt, content-safety, groundedness, DLP, and active reachability collection move to Phase 3.
- Policies install as `VALIDATED/PAUSED`; installation never publishes them.
- Every package version requires independent, digest-bound approval.
- Approved policies roll out through explicit, tenant-scoped `CANARY` distributions. The no-body compatibility form defaults to the production **Default Workspace**.
- Policy publication never closes findings by itself.
- **(Reconciled)** Every one of the 16 changed controls is implemented as an explicit new policy ID at technical version `1.0.0`, with its predecessor explicitly deprecated — never as a version revision of the existing ID. No `1.1.0` package exists anywhere in Phase 2.
- **(Reconciled)** Deprecating a predecessor and publishing its successor are independent operations. Neither implicitly triggers, blocks, or waits on the other; deprecation is what closes the predecessor's findings (via `AUTO_POLICY_PLATFORM_DEPRECATED`), not publication of the successor.
- **(Reconciled)** Exactly one publish API surface exists: policy-ID keyed. See Plan 4.
- No Governance or Policy Portfolio product is reintroduced.
- Historical migrations remain immutable.

Target catalog **(Reconciled)**:

- 67 new logical policies: 30 AWS (`AGCF-AWS-039`–`068`) and 37 Azure (`AGCF-AZR-033`–`069`).
- 16 new-ID replacements, each a distinct policy at `1.0.0` that deprecates its predecessor: 4 AWS (`AGCF-AWS-069`–`072`, replacing `017`/`024`/`031`/`032`), 6 Azure (`AGCF-AZR-070`–`075`, replacing `001`/`002`/`019`/`030`/`031`/`032`), and 6 Exposure (`AGCF-XSP-007`–`012`, replacing `001`–`006`).
- 83 Phase 2 package versions, all technical version `1.0.0`. No `1.1.0` packages exist.
- 143 logical policies visible in the Default Workspace after completion: 68 AWS, 69 Azure, and 6 cross-resource. The 16 deprecated predecessor policies remain stored as historical records — visible only in platform audit views, excluded from evaluation and tenant selection.

## Implementation Plans

### Plan 0 — Lifecycle and release foundation

Before Phase 2 catalog work:

- Complete, test, and merge the approval-lifecycle implementation represented by V92–V94, built exactly to the [Phase 2 Policy Identity & Lifecycle Decision Record](./ai-grid-phase-2-lifecycle-decision-record.md): automatic-publish cancellation, digest-bound immutable approvals, release bindings and revocation, deprecation jobs and workers, distinct deprecated-finding closure reasons, and approval-record immutability triggers. Verify both a fresh installation and a V91→V94 upgrade before starting connector work.
- **(Reconciled)** Implement the single, policy-ID-keyed publish endpoint and the deprecate endpoint per the decision record. Do not implement or retain any version-keyed publish/readiness/digest endpoint — remove it or make it return an explicit migration error (AC3).
- Remove automatic version discovery and `AUTO_POLICY_VERSION_SUPERSEDED` from active code and tests.
- Refactor the Phase 1-only compiler into a release-aware compiler accepting release configuration, package root, manifest path, expected IDs, framework versions, capability registry, and output migration.
- Retain a Phase 1 wrapper so existing reproducibility checks continue to work.
- Maintain the checked-in catalog contract as the initial authority for the 83 IDs, versions, replacement mappings, and provider ranges. Generate `phase-2-manifest.json` only from the compiled packages; it becomes the immutable digest authority once packages exist. Also generate the runtime manifest, capability guide, framework statement, changelog, permission delta, and answer-key corpus.
- Generate a forward-only V94+ platform migration that installs facts, objectives, packages, and paused distributions. It must not insert approvals, publish packages, create rollouts, or deprecate any predecessor policy.
- Add these capability identifiers:
  - `AWS_EFFECTIVE_ACCESS`
  - `AWS_LINKED_DATA_STORES`
  - `AWS_CONSUMPTION_TELEMETRY`
  - `AWS_MODEL_DATA_PROVENANCE`
  - `AZURE_EFFECTIVE_ACCESS`
  - `AZURE_LINKED_DATA_STORES`
  - `AZURE_SEARCH_MCP_SECURITY`
  - `AZURE_CONSUMPTION_TELEMETRY`
  - `AZURE_MODEL_DATA_PROVENANCE`
- Fail compilation for undeclared facts, missing OWASP mappings, unsupported predicates, unknown native kinds, write permissions, missing sanitization rules, or packages marked published/GA in source.

Exit: the V92–V94 lifecycle is migration-safe and fully tested (including idempotency/concurrency and the explicit 410 legacy-route contract); then a reproducible 83-package Phase 2 manifest installs entirely as `VALIDATED/PAUSED`, and each of the 16 replacement mappings satisfies acceptance criteria AC1–AC4 of the decision record.

### Plan 1 — AWS connector and policy expansion

Implement only directly referenced-resource enrichment; do not perform unbounded account-wide traversal.

Effective access:

- Use bounded IAM simulation and Access Analyzer evidence.
- Resolve effective actions against explicit action/resource matrices.
- Account for permission boundaries, resource policies and available organization restrictions.
- Store normalized decisions and reason codes, not complete IAM policy bodies.

Backing stores and MCP:

- Collect S3 Public Access Block, encryption, policy-status, cross-account principal and TLS-enforcement metadata.
- Enrich referenced OpenSearch Serverless, Aurora, Redis or other supported Bedrock vector stores.
- Collect AgentCore/MCP network configuration and TLS posture.
- Unsupported third-party vector stores return `NO_DECISION`; Phase 2 does not add third-party connector credentials.

Consumption:

- Collect Bedrock invocation, token, throttle and latency counters.
- Collect Service Quotas, quota utilization, AWS Budgets and CloudWatch alarm inventory.
- Store counters and configuration, never invocation bodies.

Provenance:

- Collect model/dataset versions, checksums, ingestion lineage and deployment references.
- Resolve referenced SageMaker/ECR artifacts.
- Associate Inspector or existing vulnerability evidence with referenced artifacts.
- Reuse existing AI-BOM/SBOM ingestion rather than implementing a second BOM parser.

Create `AGCF-AWS-039` through `AGCF-AWS-068`, in this order:

1. Effective agent permissions exceed the approved action/resource matrix.
2. Effective agent permissions allow cross-account sensitive-resource access.
3. Agent can pass or assume an unapproved privileged role.
4. Boundaries or organization controls fail to restrict consequential actions.
5. AI-linked S3 effective Block Public Access is incomplete.
6. AI-linked S3 default encryption is absent.
7. AI-linked S3 lacks a required customer-managed key.
8. AI-linked S3 permits unapproved cross-account principals.
9. AI-linked S3 does not enforce TLS.
10. Referenced vector store permits public network access.
11. Referenced vector store lacks required encryption.
12. Vector-store access policy lacks an approved tenant/principal boundary.
13. Bedrock consumption budget is absent.
14. Bedrock quota-utilization alarm is absent.
15. Bedrock quota utilization exceeds the configured threshold.
16. Bedrock throttling exceeds threshold without an effective alarm.
17. Bedrock token or invocation consumption exceeds threshold.
18. Deployed model artifact lacks signature or attestation.
19. Deployed model lacks approved registry lineage.
20. Deployed model lacks AI-BOM/SBOM coverage.
21. Referenced model-serving artifact has high/critical vulnerabilities.
22. Training or retrieval dataset version/checksum is not pinned.
23. Dataset provenance or ingestion lineage is missing.
24. Referenced dataset changed after approved ingestion.
25. AgentCore/MCP endpoint is publicly configured without adequate authentication.
26. MCP endpoint does not meet the configured TLS baseline.
27. SageMaker network isolation is disabled.
28. SageMaker storage lacks a required customer-managed key.
29. SageMaker root access is enabled.
30. SageMaker image integrity or vulnerability baseline fails.

**(Reconciled)** Deprecate the following predecessor policies and publish their `1.0.0` replacements once the signed manifest confirms the mapping and digests:

- `AGCF-AWS-017` → `AGCF-AWS-069`
- `AGCF-AWS-024` → `AGCF-AWS-070`
- `AGCF-AWS-031` → `AGCF-AWS-071`
- `AGCF-AWS-032` → `AGCF-AWS-072`

Each replacement consumes authoritative Phase 2 public-access and authentication facts. Deprecation and publication are independent operations, each following the [decision record](./ai-grid-phase-2-lifecycle-decision-record.md): the predecessor is deprecated (lifecycle `DEPRECATED`, distribution paused/unavailable, open findings closed with `AUTO_POLICY_PLATFORM_DEPRECATED`) and the successor is separately approved and published. Neither operation depends on completion of the other (AC2).

### Plan 2 — Azure connector and policy expansion

Effective access:

- Collect role definitions, `actions`, `dataActions`, assignment scopes and deny assignments.
- Resolve effective access for principals associated with discovered AI resources.
- Collect PIM and access-review evidence only through separately consented Microsoft Graph permissions.
- Missing Graph consent affects only PIM/access-review policies.

Storage, Search and MCP:

- Enrich directly linked Storage and OneLake resources with public-access, shared-key, TLS, encryption, network ACL and private-endpoint state.
- Read Search definitions without reading index documents or listing keys.
- Classify Search/MCP authentication in memory as `MANAGED_IDENTITY`, `KEY_OR_SAS`, `SECRET`, or `UNKNOWN`.
- Persist only the classification and identity reference.
- Collect permission filters, document-authorization fields, retrieval mode, tenant partitioning, CMK and shared-private-link state.
- Collect Foundry MCP network and private-endpoint configuration.

Consumption:

- Collect Azure Monitor counters, deployment quota/capacity, Cost Management budgets and alert-rule inventory.
- Store aggregated metrics only.

Provenance:

- Collect Azure ML registry and MLflow lineage, versions and checksums.
- Associate referenced ACR images with Defender/vulnerability evidence.
- Link existing AI-BOM/SBOM records to AI artifacts.

Create `AGCF-AZR-033` through `AGCF-AZR-069`, in this order:

1. Effective AI principal permissions exceed the approved matrix.
2. Effective AI principal reaches sensitive resources outside approved scope.
3. AI principal can create role assignments or elevate access.
4. Custom AI role contains high-impact wildcard permissions.
5. AI-linked role assignment is stale beyond the baseline.
6. Required PIM activation is absent.
7. Required access review is absent or stale.
8. Search data source uses key, SAS or secret authentication.
9. Search connection lacks required CMK protection.
10. Search index lacks required permission filtering.
11. Search index lacks document-level authorization.
12. Search index lacks tenant partitioning.
13. Search retrieval mode is outside the approved baseline.
14. Search service or object lacks required CMK encryption.
15. Search outbound shared-private-link control is absent.
16. AI-linked Storage permits public blob access.
17. AI-linked Storage permits shared-key access.
18. AI-linked Storage fails secure-transfer or minimum-TLS requirements.
19. AI-linked Storage lacks required CMK encryption.
20. AI-linked Storage uses default-allow networking without a private endpoint.
21. Azure AI consumption budget is absent.
22. Quota-utilization alert is absent.
23. Quota utilization exceeds threshold.
24. Throttling or capacity saturation exceeds threshold.
25. Token or request consumption exceeds threshold.
26. Deployed model lacks signature or attestation.
27. Deployed model lacks approved registry lineage.
28. Deployed model lacks AI-BOM/SBOM coverage.
29. Referenced deployment image has high/critical vulnerabilities.
30. Training or retrieval dataset version/checksum is not pinned.
31. MLflow or dataset lineage is missing.
32. Azure ML workspace managed network is absent.
33. Azure ML deployment has unrestricted outbound egress.
34. Bot endpoint is publicly exposed without strong authentication.
35. Bot uses secret-based credentials where managed identity is required.
36. Bot endpoint fails the configured TLS baseline.
37. Foundry MCP lacks the required private endpoint.

(The database and manifest IDs are sequential `AGCF-AZR-033`–`069`; the original draft's accidental "20/20H" label on item 21 is corrected above — there is no split item.)

**(Reconciled)** Deprecate the following predecessor policies and publish their `1.0.0` replacements once the signed manifest confirms the mapping and digests:

- `AGCF-AZR-001` → `AGCF-AZR-070`
- `AGCF-AZR-002` → `AGCF-AZR-071`
- `AGCF-AZR-019` → `AGCF-AZR-072`
- `AGCF-AZR-030` → `AGCF-AZR-073`
- `AGCF-AZR-031` → `AGCF-AZR-074`
- `AGCF-AZR-032` → `AGCF-AZR-075`

Deprecation and publication follow the same independent-operations model described in Plan 1.

### Plan 3 — Facts, policy evaluation and exposures

- Add normalized fact producers for every new connector field, with source, evidence class, timestamp, maximum age and capability status.
- Represent missing permission, unsupported API, disabled optional integration, partial scope and stale evidence separately.
- Capability checks must execute before fact queries or graph traversal.
- Keep structural indicators and effective decisions separate; for example, a wildcard policy observation must not masquerade as a simulated effective permission.
- Add a tenant V69 migration only if an explicit AI-artifact-to-BOM association cannot be represented safely through current artifact relationships. Use one association model; do not duplicate BOM contents.

**(Reconciled)** Deprecate the six existing exposure packages and publish their `1.0.0` replacements, each consuming Phase 2 correlation facts in place of the Phase 1 structural indicators:

- `AGCF-XSP-001` → `AGCF-XSP-007`: use effective public access and authoritative sensitive-store facts.
- `AGCF-XSP-002` → `AGCF-XSP-008`: use effective consequential permissions and authoritative sensitive-data paths.
- `AGCF-XSP-003` → `AGCF-XSP-009`: use effective IAM/RBAC decisions while retaining wildcard indicators as hypotheses.
- `AGCF-XSP-004` → `AGCF-XSP-010`: use authoritative MCP approval, network and sensitive-data evidence.
- `AGCF-XSP-005` → `AGCF-XSP-011`: use secret-safe MCP authentication classification and effective tool permissions.
- `AGCF-XSP-006` → `AGCF-XSP-012`: use ACL, tenant-isolation, retrieval-mode and sensitive-data evidence.

As with Plans 1 and 2, deprecating a predecessor and publishing its successor are independent operations; finding identity does not transfer between them.

Correlation requirements:

- Reuse the snapshot, fact index, relationship index and graph traversal cache across all six policies.
- Allow only declared edge types, path directions, maximum depth and fan-out.
- A validated exposure requires exact, fresh decisive facts.
- Structural or stale evidence may create a potential-exposure state but never a validated exposure or canonical exposure finding.
- **(Reconciled)** Publication of a correlation successor performs no finding mutation on its predecessor's findings; only deprecating the predecessor closes them, via `AUTO_POLICY_PLATFORM_DEPRECATED`.
- Reevaluation, evidence expiry, resource disappearance, tenant disablement or logical deprecation drives exposure lifecycle changes.
- **(Reconciled)** Finding identity remains logical-policy-plus-subject based. Because each replacement is a distinct policy ID rather than a revision of the same ID, the predecessor's open findings are closed via deprecation (not merged or rekeyed), and the successor establishes its own independent finding identity from its first evaluation.

Exposure UI:

- Replace raw JSON-first presentation with typed path nodes, edges and decisive facts.
- Show entry point, affected system, sensitive/consequential target, root cause, breakpoint, freshness, linked posture findings and OWASP mappings.
- Retain raw evidence JSON in a collapsed technical section.
- Tenant screens continue hiding package versions and digests, and show deprecated predecessors (if surfaced at all) as `Deprecated`, never as an older version of the active policy.

### Plan 4 — Approval and tenant-scoped canary rollout

**(Reconciled)** Use the single policy-ID-keyed publish endpoint established by the [decision record](./ai-grid-phase-2-lifecycle-decision-record.md) — `POST /api/platform/ai-grid/policies/{policyId}/publish` — not any version-keyed route. It accepts an optional command:

```json
{
  "rolloutTarget": "DEFAULT_WORKSPACE",
  "rolloutStage": "CANARY"
}
```

Behavior:

- `DEFAULT_WORKSPACE` resolves server-side using the canonical default tenant record.
- Reject publishing if any requested canary tenant is absent, inactive, schema-incompatible or lacks a complete snapshot.
- Lock the package, recompute its digest and validate release evidence.
- Require approver identity to differ from package author.
- Persist the exact approval before changing lifecycle.
- Publish and pin only that logical policy.
- Set distribution to `CANARY` containing exactly the requested tenant IDs.
- Create exactly one rollout and one tenant task carrying the approval ID and digest.
- Recheck lifecycle, digest, unrevoked approval, distribution and rollout bindings before evaluation.
- Treat integrity mismatches as terminal; retry only transient snapshot or tenant failures.
- **(Reconciled)** Preserve the no-body request form for compatibility, but only on the policy-ID-keyed endpoint; it resolves server-side to the canonical `DEFAULT_WORKSPACE`/`CANARY`. Explicit caller-selected active-tenant cohorts are first-class and are never restricted to that workspace. Any pre-existing version-keyed publish/readiness/digest route is removed or returns an explicit migration error — it must never silently resolve to a different policy or version (AC3).
- Return approval ID, approved digest, rollout ID and rollout status in the platform response. Tenant APIs continue omitting revisions and digests.

Release evidence:

- Every package digest receives controlled PASS and FAIL engine cases from Default Workspace fixtures.
- Missing, stale, denied and unsupported behavior is certified once per fact producer/capability contract rather than duplicated for every policy.
- `ARTIFACT_FACTS` policies using direct provider configuration require answer-key approval.
- Effective-access derivations, vulnerability/provenance joins, direct-relationship policies and all correlation packages additionally require independent precision review.
- No evidence from another tenant is required.

## Framework and Default Behavior

Required framework mappings:

| Family | OWASP 2026 | Primary AICM areas |
|---|---|---|
| Effective IAM/RBAC | LLM03; LLM02 where sensitive access is involved | IAM-05, IAM-18, DSP-17 |
| Storage/network/encryption | LLM02, LLM09 | DSP-17, I&S-03 and applicable encryption controls |
| Search/MCP | LLM01, LLM02, LLM03, LLM09 | AIS-11, IAM-13, IAM-18, DSP-17 |
| Consumption | LLM06 | LOG-14 and applicable resilience/cost controls |
| Model provenance | LLM04 | MDS-02, MDS-08, MDS-09, STA-09 |
| Data provenance | LLM05 | MDS-02, MDS-08, MDS-09 |
| Exposure correlations | Corresponding risks above | Direct mappings inherited from decisive controls |

Mapping rules:

- Every package must include at least one OWASP mapping and rationale.
- Mappings indicate risk reduction, not OWASP certification.
- Use `DIRECT` only when the policy directly evaluates the stated control; otherwise use `PARTIAL`.
- The compiler generates the consolidated framework statement consumed by Policy Studio.

Defaults:

- Packages install `VALIDATED/PAUSED`.
- Objective controls use `ENABLED`.
- Policies requiring tenant-specific allowlists, CMK mandates, PIM, access reviews, budgets or thresholds use `DISABLED` with an immutable validation parameter profile.
- During Default Workspace validation, explicitly configure and enable every disabled policy through tenant policy settings.
- General availability and customer defaults remain a separate post-Phase-2 decision.

## Test Plan and Definition of Done

Automated verification:

- Fresh database and V91/V92/V93 upgrade paths reach the new platform target.
- Existing migration checksums remain unchanged.
- Phase 2 compiler output is byte-for-byte reproducible.
- **(Reconciled)** The manifest contains exactly 83 Phase 2 package versions: 67 new and 16 new-ID replacements — all at technical version `1.0.0`. No `1.1.0` package exists.
- Permission-contract tests reject write, key-listing, document-content and secret-retrieval permissions.
- Connector fixtures cover complete, partial, denied, unsupported, stale and empty results.
- Each new policy covers PASS, FAIL and applicability.
- Each fact producer covers missing, stale, permission-denied and unsupported behavior.
- All six correlations cover valid path, wrong direction, excessive depth/fan-out, proximity-only, stale evidence, replay and demotion.
- **(Reconciled)** Deprecating a predecessor never publishes its successor, and publishing a successor never deprecates or otherwise mutates its predecessor. Each of the 16 mappings is verified independently against acceptance criteria AC1–AC4 of the decision record — not inferred from aggregate policy or package counts, which pass under either identity model.
- Revoked or mismatched approvals prevent rollout.
- Repeated rollout and scan execution creates no duplicate findings.
- Platform deprecation and tenant disablement retain their distinct non-remediation closure reasons (`AUTO_POLICY_PLATFORM_DEPRECATED` and the tenant-disablement equivalent).
- Backend unit/PostgreSQL integration suites, frontend unit/typecheck/build suites and browser E2E pass.

Performance gates:

- With Phase 2 capabilities unavailable, short-circuiting keeps assessment CPU/database work within 20% of the frozen Phase 1 evaluator baseline.
- With Phase 2 enabled, evaluation uses one fact load and one relationship/graph load per snapshot, not per policy.
- Enrichment calls are bounded by directly referenced resources and existing connector budgets.
- No N+1 provider call, database fact query or graph traversal is permitted.

Phase 2 is done when:

- The approval-lifecycle prerequisites are present and active, built to the decision record.
- All five in-scope connector families produce sanitized, freshness-bound facts.
- All 83 Phase 2 package versions are installed, all at `1.0.0`.
- All 83 digests have exact unrevoked approvals.
- All 83 explicit initial rollout tasks complete for the selected canary cohort.
- The Default Workspace shows exactly 143 logical policies: 68 AWS, 69 Azure and 6 cross-resource, with the 16 deprecated predecessors visible only as historical records excluded from evaluation.
- All new policies show OWASP mappings in Policy Studio.
- The six exposure successor policies (`AGCF-XSP-007`–`012`) produce deterministic, explainable paths.
- At least one PASS, FAIL and `NO_DECISION` is demonstrated for every connector capability.
- At least one exposure is created, displayed, reevaluated and closed from changed evidence.
- No tenant receives a Phase 2 policy automatically; only an explicitly selected active-tenant canary cohort receives a policy.
- No policy is published, distributed or rolled out automatically; no predecessor is deprecated automatically.
- **(Reconciled)** Each of the 16 replacement mappings satisfies acceptance criteria AC1–AC4 of the [decision record](./ai-grid-phase-2-lifecycle-decision-record.md).

## Assumptions and Exclusions

- V92/V93 and the attached lifecycle implementation are completed before Phase 2 publication; current uncommitted work is preserved and verified rather than overwritten.
- Default Workspace is the bootstrap canary target when none is explicitly supplied; explicit active tenant cohorts are supported.
- Phase 1 reapproval is tracked separately and does not consume Phase 2 package IDs.
- Runtime prompt/output collection, active reachability tests, groundedness, DLP and content-safety telemetry are Phase 3.
- Third-party vector-store connectors, customer GA, bulk promotion, Policy Portfolio, standalone Governance UI and automatic policy replacement are out of scope.
- Existing policy and correlation revisions remain historically visible; Phase 2 does not delete prior package, approval, rollout, finding or evidence records.
- **(Reconciled)** Policy identity and lifecycle semantics for the 16 changed controls follow the [Phase 2 Policy Identity & Lifecycle Decision Record](./ai-grid-phase-2-lifecycle-decision-record.md) — new-ID replacement, `1.0.0`-only, single policy-ID-keyed publish endpoint. This supersedes any "`1.1.0` revision" framing from earlier drafts of this plan.
