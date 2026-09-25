# AI Grid Phase 2 runtime security implementation plan

**Updated:** 2026-09-25
**Status:** Local implementation complete and gate-green; live provider activation, two-provider readiness, answer-key certification and governed rollout remain operational exit gates
**Purpose:** Turn privacy-minimised agent runtime metadata into deterministic, explainable AI Grid findings.

## 1. Outcome and product boundary

Phase 2 must let a security team distinguish what an agent **could do** from what it **actually did**. It connects runtime executions to the existing agent, version, identity, tool, MCP, model, data and policy graph.

Phase 2 is not a log lake. It accepts bounded security metadata and ordered security-relevant events, not arbitrary logs or business payloads.

Included:

- execution, agent and version correlation;
- observed tool, MCP, action and target metadata;
- acting and delegated identity references;
- approval, policy and outcome decisions;
- bounded retry, token, latency and spend aggregates;
- memory and handoff metadata only when an authoritative source exists.

Excluded by default:

- raw prompts and responses;
- tool arguments and results;
- documents, message bodies and business records;
- credentials, tokens and secrets;
- unrestricted diagnostic logs;
- prevention claims unless an enforcement point confirms the result.

High-volume sources must filter or aggregate upstream. AI Grid accepts only the governed fields required for correlation, evaluation and explanation. Oversized, untrusted or out-of-contract batches are rejected or quarantined.

## 2. Current implementation baseline

The following foundation is complete and must be reused rather than rebuilt:

- Platform and tenant migration heads on this branch are V3, with V2-to-V3 upgrade, clean V1-to-V3 install and tenant structural-fingerprint verification.
- All 159 currently governed AGCF policies are available to the default tenant. Their platform defaults are 103 `DISABLED`, 24 `ENABLED` and 32 `REQUIRED`; tenant seeding now preserves those defaults verbatim, resolves one baseline version per policy and realigns only `PLATFORM_DEFAULT` rows. `TENANT_OVERRIDE` rows survive reseeding.
- Runtime execution, event, participant, receipt and cursor tables exist with forced tenant RLS.
- Provider identifiers are stored as tenant-scoped HMAC digests with key versions.
- Ingestion provides idempotency, overlap/lookback cursors, event-count limits, metadata-size limits and pagination/API-call budgets.
- Runtime records are separate from findings and do not become violations merely because they were observed.
- Approval and policy states use closed, uppercase vocabularies; invalid values fail ingestion.
- Runtime retention uses bounded batch deletion, with child events removed by cascade.
- Azure Foundry and Copilot Studio metadata collectors, feature flags and kill switches exist.
- Execution list, timeline and relationship APIs exist.
- Approved agent-version manifests and component allowlists exist in tenant V2.
- The readiness API measures consequential-event decision coverage over a 14-day provider window, enforces the 100-execution and 50-version-applicable floors, and enumerates configured providers and governed adapters.
- Framework coverage, legacy-policy separation and tenant visibility use governed reporting rules.

Implementation record:

- Tenant and platform V3, the governed adapter, per-tenant event/byte quotas, runtime field registry, decision-scope rules, bounded evaluators and runtime finding lifecycle are implemented.
- Runtime evaluation supports `RUNTIME_FACTS`, `RUNTIME_SEQUENCE`, `RUNTIME_AGGREGATE` and the bounded `RUNTIME_COVERAGE` meta-policy used by AGCF-RT-004.
- AGCF-RT-001 through AGCF-RT-009 are executable preview packages. Five Wave 2C controls remain explicitly paused pending authoritative evidence.
- The investigation surface links a runtime finding to its execution and exact ordered events, labels source/class in the list, and reports volume, duplicate/quarantine rate, lag, API/evaluator budget alerts, capability health, retention backlog, quotas and estimated storage cost.
- Provider collectors publish explicit runtime capability observations. Where the configured provider endpoint cannot supply authoritative action/decision/tool/data events, the capability is `UNSUPPORTED_API`; inventory proximity is never promoted to observed use.
- Local verification is green: 947 backend tests with the JaCoCo floor and SpotBugs checks, 615 frontend unit tests, frontend typecheck/lint, catalog validators, and PostgreSQL V2-to-V3 plus clean V1-to-V3 migration parity.

Operational gaps (not satisfiable from source code alone):

- The current tenant has no Foundry runtime endpoint and no Copilot Studio configuration, so no runtime pilot is active and no 14-day evidence window exists.
- The configured Azure and Copilot metadata APIs do not expose authoritative action-level decision records. Those families therefore remain explicitly unsupported until a qualified provider export or governed telemetry producer is configured.
- No representative customer answer-key corpus has been supplied, so the five named policy certifications and any per-producer promotion to `AUTHORITATIVE` remain pending.
- The runtime pack has not been promoted through DEV/CANARY/GA; distribution remains gated by live readiness, certification and operational sign-off.

## 3. Delivery program

### Work package 0 — tenant default-selection repair (prerequisite)

No runtime policy may be distributed until this lands. `AiGridTenantPolicyDefaultsService` maps every non-`REQUIRED` platform default to `ENABLED`, so a `PREVIEW` or `DISABLED` runtime package would auto-enable in every tenant on seeding.

1. Preserve the platform default verbatim: `REQUIRED` → `REQUIRED`, `ENABLED` → `ENABLED`, `PREVIEW` → `PREVIEW`, `DISABLED` → `DISABLED`. Only an explicit tenant override may enable a `PREVIEW` or `DISABLED` package.
2. Make version selection explicit rather than incidental. Resolve exactly one baseline row per policy — the pinned version when the distribution pins one, otherwise the highest visible version — and insert only that row. The current implementation iterates every visible version against a `policy_id` conflict target; with unpinned distributions the last-written metadata is the lowest version. No tenant is known to be mispinned today because seeded entries are unique per policy and active distributions are normally pinned, but the loop must not depend on that.
3. Repair the conflict path. The existing `on conflict` refreshes `platform_policy_version` and `platform_default_selection` but never `selection`, so fixing the mapping alone leaves already-seeded tenants wrong.
4. Decide and record the backfill policy for existing tenants: realign rows whose `configuration_source` is `PLATFORM_DEFAULT` to the corrected platform default, and leave `TENANT_OVERRIDE` rows untouched. Emit an audit record per realigned policy, and report the count of policies that move from `ENABLED` to `DISABLED`/`PREVIEW` before the backfill runs.
5. Add a test asserting that a `PREVIEW` platform default seeds as `PREVIEW`, that a `TENANT_OVERRIDE` survives a re-seed, and that a `REQUIRED` package cannot be downgraded.

Work package 0 exit: for a tenant seeded from the current catalog, tenant selections equal platform defaults for every `PLATFORM_DEFAULT` row, and the AGCF slice reports 103 `DISABLED`, 24 `ENABLED` and 32 `REQUIRED`.

### Work package A — pilot activation and measurement

Use Azure Foundry as the first pilot because an Azure connector and credential profile already exist. Add Copilot Studio only after the Azure path produces valid evidence.

1. Configure the Azure connector's allowlisted Foundry endpoint and verify credentials and runtime permissions.
2. Approve the pilot agent-version manifest and component digests before enabling runtime collection.
3. Enable `AZURE_FOUNDRY_RUNTIME` for the pilot tenant through the existing connector feature-flag API. Set the tenant `kill_switch` to false for the pilot while retaining the environment-level switch as the platform-wide emergency stop.
4. Run collection in metadata-only mode and monitor ingestion rejections, duplicate rate, lag and correlation status.
5. Collect at least 100 executions over a rolling 14-day window.
6. Do not release behavioral policies until Azure reaches:
   - `approval_state` fill rate at least 95% **measured over consequential events**, not executions;
   - `policy_state` fill rate at least 95% over consequential events;
   - `action_outcome` fill rate at least 95% over consequential events;
   - execution-to-agent correlation at least 90%;
   - version correlation at least 80% over version-applicable executions, with at least 50 such executions in the window;
   - zero raw-payload or secret-handling violations.
7. Configure Copilot Studio and repeat the same gate. Two passing providers are required before Wave 2B can leave preview.

A **consequential event** is one whose `action_category` is `WRITE`, `DELETE`, `SEND`, `EXECUTE`, `ADMIN`, `PAYMENT` or `PUBLISH`. Restricting the decision metrics to this set is the point of the change: Wave 2B predicates are event-scoped, so an execution-level fill rate can pass at 100% while no consequential action carries a decision. Execution-level fill rates remain reported for continuity but no longer gate release.

The version-correlation metric returns 100% when no execution carries a provider version key. The 50-execution applicable-sample floor exists so a provider that rarely emits version keys — Azure's current behavior — cannot pass that criterion vacuously. Below the floor the criterion reports `VERSION_SAMPLE_INSUFFICIENT` rather than passing.

Readiness for an unconfigured provider is `NOT_CONFIGURED`, not an error. A configured provider with insufficient data reports explicit blockers such as `MINIMUM_EXECUTIONS_NOT_MET`, `CONSEQUENTIAL_EVENT_SAMPLE_INSUFFICIENT`, `APPROVAL_STATE_FILL_BELOW_THRESHOLD`, `POLICY_STATE_FILL_BELOW_THRESHOLD`, `ACTION_OUTCOME_FILL_BELOW_THRESHOLD`, `AGENT_CORRELATION_BELOW_THRESHOLD`, `VERSION_CORRELATION_BELOW_THRESHOLD` or `VERSION_SAMPLE_INSUFFICIENT`.

Readiness must enumerate evidence sources from configuration rather than a fixed two-provider list, so that each governed telemetry adapter producer reports its own readiness row alongside Azure and Copilot. The overall gate requires two passing **provider** connectors; adapter rows are reported and certified separately under work package D and do not substitute for a provider connector.

### Work package B — runtime contract V2 and governed ingestion

Create tenant migration V3 to extend runtime records with typed, policy-addressable fields. Keep free-form diagnostics separate and non-addressable by policy predicates.

Execution additions:

- environment and deployment references;
- HMAC-safe acting and delegated identity digests plus key version;
- termination reason, evidence source, evidence class and confidence;
- step count and normalized spend currency/unit metadata;
- collection time, provider event time and delivery latency.

Event additions:

- provider event digest and ingestion time;
- `action_category`: `READ`, `WRITE`, `DELETE`, `SEND`, `EXECUTE`, `ADMIN`, `PAYMENT`, `PUBLISH`, `OTHER`;
- `target_class`: `INTERNAL`, `EXTERNAL`, `PUBLIC`, `SENSITIVE_STORE`, `CODE_RUNTIME`, `IDENTITY_SYSTEM`, `FINANCIAL_SYSTEM`, `UNKNOWN`;
- HMAC-safe tool, tool-version, target and action-correlation digests;
- data sensitivity and data operation;
- approval state, policy state, decision reason and enforcement point;
- action outcome and evidence class.

Add the new typed fields to the authoritative runtime-field registry. Package validation must reject runtime predicates that reference JSONB diagnostics or unregistered fields.

#### Decision authority: execution versus event

`execution.approval_state` and `execution.policy_state` already exist and are already registered as predicate-eligible. This work package introduces same-named fields at event scope, so precedence must be explicit rather than inferred:

- The **event** record is authoritative for the decision governing that action. Every Wave 2B predicate binds at event scope.
- The **execution** record carries the decision governing the run as a whole — session-level approval, run-level policy verdict — and is never derived by collapsing event decisions. If a provider supplies only an execution-level decision, it stays at execution scope and does not populate event fields.
- Registry keys stay fully qualified (`execution.approval_state` versus `event.approval_state`). Package validation rejects an unqualified `approval_state` or `policy_state` reference rather than resolving it to a default scope.
- A policy that requires event-scoped decisions and finds only execution-scoped ones returns `NOT_ASSESSED` with reason `DECISION_SCOPE_UNSUPPORTED`. It must not fall back to the execution field.
- Each scope declares its own capability entry so a provider can be fresh at one scope and unsupported at the other.

Extend ingestion validation with:

- closed enums and strict lengths for every governed field;
- event ordering by `(event_time, sequence, provider_event_digest)`;
- idempotency on tenant, producer, provider event digest and digest-key version;
- deterministic late and out-of-order handling;
- quarantine reason codes for invalid schema, tenant mismatch, bad signature, untrusted producer and privacy-rule violation;
- no automatic promotion of customer-provided evidence to `AUTHORITATIVE`.

### Work package C — connector enrichment

#### Azure Foundry

- Keep the existing metadata endpoint for execution identity, agent/version reference, status, timestamps and usage.
- Add adapters for supported trace/diagnostic sources that expose tool calls, action outcome, actual model/version, identity, approval and policy decisions.
- Accept a decision only when it shares a stable provider correlation key with the execution or action.
- Publish capabilities per workspace and API version, including permission, freshness and delivery-latency state.
- Correlate data operations to existing Search, Storage, OneLake and Purview artifacts without ingesting content.

Azure exit: an execution can be reconstructed from agent/version to observed action and outcome, and every populated decision field has a qualified source.

#### Copilot Studio

- Keep Dataverse transcript collection limited to selected metadata columns; never select transcript content.
- Add bot-version correlation and component participation from supported Dataverse or telemetry-export records.
- Normalize initiating identity, environment, channel and trigger class.
- Correlate consequential connector actions with approval, policy decision and outcome records where stable IDs exist.
- Match observed component digests against the approved manifest and component allowlist.
- Report licensing, API and environment limitations as capability gaps.

Copilot exit: an observed action resolves to one bot and, where supported, one version and declared component; unavailable decision context yields `NOT_ASSESSED`.

#### AWS AgentCore

- Retain the current control-plane runtime, version, endpoint, execution-role and workload-identity posture.
- Add capability states for unsupported runtime action, attachment, identity, approval, policy and outcome families.
- Add a provider adapter only when AWS exposes authoritative events; otherwise use the governed customer telemetry adapter.
- Do not infer browser, Code Interpreter, memory, gateway or tool use from inventory proximity.

AWS exit: runtime posture is fresh, and observed-use edges exist only when supported by qualified runtime evidence.

### Work package D — governed customer telemetry adapter

Add `POST /api/internal/ai-grid/runtime/{producerId}/v1/batches` for frameworks, gateways and enforcement points when provider APIs cannot supply required evidence.

**Identity and authorization.** The authority is `ROLE_SERVICE_ACCOUNT`, matching the existing `/api/internal/ai-grid/evidence/{producerId}` contract. `RUNTIME_EVIDENCE_PRODUCER` is a **producer type recorded on the service account, not a Spring role** — it does not introduce a new granted authority and does not modify `SecurityConfig`. Authorization is therefore three checks, in order:

1. `hasRole('SERVICE_ACCOUNT')` at the controller.
2. `producerId` equals the authenticated principal name.
3. The producer's registered type is `RUNTIME_EVIDENCE_PRODUCER` and its status is active.

**Tenant binding.** The existing evidence endpoint resolves the tenant from the workspace and checks only the `ai.security` entitlement; it does not bind the service account to a tenant. That binding is new work, not a reused pattern: register each runtime producer against exactly one tenant and reject the request when the registered tenant differs from the resolved request tenant. Revocation and deactivation take effect on the next request with no cached grace period.

**Limits, and which one binds first.** The caps are layered and need not be simultaneously reachable; they are evaluated in this order, and the first breach rejects the batch:

1. 2 MiB uncompressed request body — the binding limit in practice, and the only one a producer must size against.
2. 100 executions per batch.
3. The existing per-execution event ceiling (1000) and 16 KiB per-execution metadata limit, applied per record.

A batch that satisfies the byte limit will normally sit well under the execution and event ceilings; those exist to bound single-record cost, not to advertise batch capacity. Document the byte limit as the producer-facing contract.

**Evidence trust.** Adapter evidence is admissible, not second-class: a policy declares the evidence classes it accepts, and an adapter-sourced batch satisfies a policy whose declared classes include it. What is forbidden is *automatic* promotion to `AUTHORITATIVE`. Promotion requires an explicit certification of that producer against an answer-key corpus, recorded per producer and per evidence family, with the same precision bar as a provider connector. Until certified, adapter evidence carries its submitted class, participates in evaluation only for policies that accept that class, and is labelled by source in every finding explanation.

Remaining interface and behavior:

- Accept a versioned, metadata-only batch.
- Return `202 Accepted` with a receipt ID, accepted count, duplicate count and quarantined count.
- Process through the existing ingestion-job infrastructure; return `429` with `Retry-After` when capacity is exhausted.
- Require producer ID, schema version, evidence class, provider execution reference and execution-level event time on every record. Require a provider event reference **per event record**; do not require one on an execution that carries no events.
- Accept an empty event list as a valid metadata-only execution. Reject a null or omitted event list with an explicit schema error rather than treating it as empty, so a truncated payload is never silently accepted as a complete execution.
- HMAC provider identifiers before persistence and never return clear provider identifiers from read APIs.
- Rotate producer credentials through identity administration, audit every configuration change and reject inactive accounts immediately.
- Do not accept raw prompt/response, argument/result, credential, document or message-body fields. Reject the entire record when forbidden fields are present.

**Per-tenant quotas and overload behavior.** Per-request limits bound a single call but not sustained volume. Add, wired to the existing budget infrastructure:

- a per-tenant rolling event and byte quota per window, with configured defaults and a platform-owner override;
- a soft threshold that emits a capability-degradation signal and an operator alert while continuing to accept;
- a hard threshold that returns `429` with `Retry-After` and a `TENANT_QUOTA_EXHAUSTED` reason, recorded on the receipt;
- explicit behavior on breach: reject, never sample and never silently truncate, because a silently sampled window makes every coverage and fill-rate metric unsound;
- a quota-exhaustion window marked as such in readiness, so a provider cannot pass a fill-rate gate on a partially rejected window.

The adapter is not a bulk log endpoint. Producers must extract only the governed event schema and aggregate noisy telemetry before submission.

### Work package E — runtime evaluator

Create platform migration V3 to add `RUNTIME_SEQUENCE` and `RUNTIME_AGGREGATE` to the policy evaluation-mode constraint.

A third mode, `RUNTIME_FACTS`, was added during implementation. Wave 2A packages 1–3 are execution-attribute checks — correlation quality, approved version, retired version — and neither an ordered event sequence nor a numeric aggregate can express them: a sequence step needs event-scoped ordering, and an aggregate needs a numeric metric over a group. Without a third mode Wave 2A would not be executable, so `RUNTIME_FACTS` binds a bounded conjunction (at most 16) of execution-scoped conditions with subject `EXECUTION`.

`RUNTIME_FACTS` definition:

- execution-scoped conditions only, operators `EQ`, `NE`, `IN`, `NOT_IN`, `EXISTS`, `ABSENT`;
- all conditions must hold for the violation to be established;
- evidence fields retained for explanation.

`RUNTIME_SEQUENCE` definition:

- ordered steps with typed event-field predicates;
- one execution as the grouping boundary;
- maximum sequence duration and allowed lateness;
- explicit deduplication key;
- maximum events examined;
- evidence fields retained for explanation.

`RUNTIME_AGGREGATE` definition:

- registered metric such as retries, repeated action signature, token total, latency or spend;
- fixed lookback window;
- allowlisted grouping key;
- comparison operator and threshold;
- tenant override bounds;
- maximum rows and events examined.

Evaluation semantics:

- `PASS`: required capabilities are fresh and the violation condition is false.
- `FAIL`: required capabilities are fresh and the deterministic condition is true.
- `NOT_ASSESSED`: required evidence is unsupported, unavailable by contract or the policy is paused pending an evidence family.
- `UNKNOWN`: evidence was expected but collection failed, is stale, ambiguous or incomplete.

Evaluators must be read-only, tenant-scoped and bounded. Missing fields can never become `PASS`. Runtime observations remain separate from findings until an enabled policy returns `FAIL`.

### Work package F — Phase 2 policy pack

Publish packages in this order:

Wave 2A foundations:

1. Execution cannot resolve to exactly one agent/version.
2. Endpoint serves an unhealthy or unapproved version.
3. Agent executed a retired or unapproved version.
4. Consequential telemetry is incomplete.

Package 4 is a coverage meta-policy and must declare a bounded subject and aggregation grain, because its condition is true wherever collection is partial — which during pilot is most of the estate. It emits **one finding per provider, workspace, capability family and window**, never one per execution or per event, and carries the affected execution count plus a representative sample as evidence rather than enumerating subjects. The other three Wave 2A packages keep per-execution subjects.

Wave 2B behavioral detections:

5. Consequential action succeeded without required approval.
6. Policy-denied action succeeded.
7. Sensitive read was followed by an external write or send without approved declassification.
8. Runtime used an undeclared tool, version or definition digest.
9. Retry, repeated tool call, token, latency or spend threshold was exceeded.

Wave 2C remains breadth-only until authoritative evidence exists:

- unconstrained agent-to-agent handoff;
- unsafe durable-memory write;
- memory isolation or retention failure;
- tool, plugin or MCP integrity-provenance failure;
- missing stop or containment control for high-impact autonomy.

Every package must declare its required capabilities, evidence classes, age, lateness, limits, parameters, explanation fields, feature flag and kill switch. Wave 2C controls report `POLICY_PAUSED_PENDING_EVIDENCE`; they do not create fictional per-subject assessments.

New runtime packages start at `PREVIEW`, which requires work package 0 to have landed first. Required policies remain non-downgradable.

### Work package G — investigation and operations

- Extend the execution timeline UI with action, target, tool, identity, decision, approval, outcome and evidence-source labels.
- Link runtime findings to the exact execution and ordered events used by the evaluator.
- Add provider dashboards for event volume, duplicate rate, quarantine rate, lag, API-budget exhaustion, fill rates, correlation rates and estimated storage cost.
- Alert on collection failure, stale capability, HMAC key-version mismatch, quarantine spikes, retention backlog and evaluator budget exhaustion.
- Keep observations, hypotheses and violations visually distinct.
- Label every runtime finding with its evidence source and class, so provider-sourced and adapter-sourced conclusions are distinguishable without opening the finding.
- Refresh the documentation that describes runtime state as part of the V3 PR: migration heads, the runtime field registry, the evaluation-mode vocabulary, the adapter contract, and the seeding semantics changed by work package 0. `prototype-app/CLAUDE.md` is current at platform V2 / tenant V2; other runtime and policy docs have not been audited against this plan and should be swept in the same change.

## 4. Public APIs and compatibility

Keep existing APIs stable:

- `GET /api/ai-security/executions`
- `GET /api/ai-security/executions/{executionId}/timeline`
- `GET /api/ai-security/executions/{executionId}/relationships`
- `GET /api/ai-runtime-telemetry-readiness`
- manifest, component-allowlist and connector feature-flag APIs.

Add only additive response fields to existing execution and timeline APIs. Old clients may ignore them.

Add:

- `POST /api/internal/ai-grid/runtime/{producerId}/v1/batches`
- `GET /api/ai-security/runtime-ingestion/receipts/{receiptId}`
- readiness response fields for consequential-event decision fill rates, the version-applicable execution sample size, agent correlation, version correlation, delivery lag, quarantine rate, quota state and provider configuration state.
- a readiness row per configured evidence source, including governed telemetry adapter producers, each with its own evidence class and certification state. The overall gate still requires two passing provider connectors.

Use UTC timestamps, uppercase closed enums and opaque UUIDs externally. Never expose provider identifiers or HMAC source material.

## 5. Test and certification plan

Schema and isolation:

- V2-to-V3 is the **upgrade-compatibility gate** — every existing tenant and the platform schema are at V2, so this is the path production takes.
- Fresh V1-to-V3 is the **clean-install gate**, asserting a new tenant provisioned from baseline reaches the same structural state.
- `MigrationCatalogTest` pins both heads and must be bumped to platform V3 / tenant V3 in the same PR.
- Tenant structural-fingerprint parity and RLS cross-tenant denial.
- Digest rotation, uniqueness and distribution-binding stability.
- Work package 0: default-selection preservation, `TENANT_OVERRIDE` survival across re-seed, single-baseline-row version selection with and without a pinned distribution, and backfill idempotency.

Ingestion:

- Valid, duplicate, late, out-of-order and overlapping-window inputs.
- Invalid enum, oversized batch, event-budget overflow and API-budget exhaustion.
- Forbidden raw payload fields, secret-like content and tenant mismatch.
- Producer revocation, invalid credential, replay and quarantine behavior.
- Bounded retention batches with execution-event cascade.

Connectors:

- Success, permission denied, unsupported API, stale source and partial page fixtures.
- Stable correlation, ambiguous correlation and no-match cases.
- Verify that Azure and Copilot clients never request or persist transcript, prompt or response content.

Evaluators:

- Positive, negative, stale, missing, ambiguous and unsupported evidence for every policy.
- Deterministic duplicate, late-event and out-of-order results.
- Window, event, row and graph-hop limits.
- Cross-tenant isolation and performance at the configured maximum batch size.

Certification:

- At least five runtime policies certified on representative answer-key corpora, **named rather than counted**: Wave 2A packages 1 and 3, and at least two of Wave 2B packages 5, 6 and 8. A count alone can be satisfied entirely by Wave 2A correlation-quality checks, which are materially easier to certify and are not what Phase 2 exists to deliver; at least two certified behavioral detections are required.
- High/Critical precision at least 95%, computed per named policy rather than pooled across the set.
- At least 90% of runtime findings contain the complete evidence path required by their policy.
- Required-field absence incorrectly evaluated as `PASS`: zero.
- Raw payload fields collected by default: zero.
- Any producer whose evidence is promoted to `AUTHORITATIVE` is certified separately, per producer and per evidence family, at the same precision bar.

## 6. Rollout and exit gates

1. Land work package 0, run the existing-tenant backfill and confirm the AGCF slice reports 103 `DISABLED`, 24 `ENABLED`, 32 `REQUIRED` with `TENANT_OVERRIDE` rows intact. No runtime package may be distributed before this step passes.
2. Deploy tenant and platform V3 with runtime features off.
3. Run schema fingerprint, isolation, privacy and digest-stability checks.
4. Configure the Azure pilot, approve manifests and enable `AZURE_FOUNDRY_RUNTIME` for one tenant.
5. Pass the numeric 14-day Azure gate — consequential-event decision fill rates, not execution-level — then add Copilot Studio.
6. Pass the same gate for Copilot before enabling Wave 2B preview.
7. Deploy policies to `DEV` through validation governance, then `CANARY` through distribution governance, then GA only after certification and operational sign-off.
8. Roll back by disabling the policy distribution or tenant connector flag; use the platform kill switch for immediate provider-wide shutdown. Retain already collected metadata under the normal retention policy.

Phase 2 is complete only when:

- work package 0 has shipped and no tenant carries a `PLATFORM_DEFAULT` selection that diverges from its platform default;
- two provider connectors emit qualified agent/version, action, target, identity, approval, policy and outcome metadata;
- agent correlation is at least 90%, and version correlation at least 80% over a version-applicable sample of at least 50 executions;
- consequential-event decision context is at least 90% complete or has an explicit `NOT_ASSESSED` reason, with execution-scoped decisions counted separately and never substituted for event-scoped ones;
- sequence and aggregate evaluators pass correctness, boundedness, isolation and performance tests;
- the five named policies meet the certification gates, including at least two Wave 2B behavioral detections;
- per-tenant quotas, defined overload behavior, privacy, retention, deletion, audit, lag, health and cost controls are operational.

## 7. Assumptions and dependencies

- Azure Foundry is the first pilot; Copilot Studio is the second qualified connector.
- AWS remains posture-first until an authoritative action/decision source or governed adapter is available.
- Governed telemetry adapter evidence is admissible against policies that declare its evidence class. It substitutes for a provider connector only for policy evaluation, never for the two-provider readiness gate, and reaches `AUTHORITATIVE` only through per-producer certification.
- Work package 0 is a prerequisite for the whole program, not a parallel track; if its backfill decision is deferred, runtime policy distribution is deferred with it.
- The existing ingestion-job, tenant execution, audit, entitlement, feature-flag and validation-governance mechanisms are reused.
- PostgreSQL remains the system of record; no new event-bus dependency is required for the first pilot.
- If sustained load cannot meet the batch API's latency and backpressure targets, queue partitioning is introduced as a separately measured scaling change, not by weakening privacy or boundedness controls.

Dependencies:

- [AI Grid customer security roadmap](./AI_GRID_CUSTOMER_SECURITY_ROADMAP.md)
- [AI Grid policy coverage expansion plan](./AI_GRID_POLICY_COVERAGE_EXPANSION_PLAN.md)
- [AI Grid graph security strategy](./AI_GRID_GRAPH_SECURITY_STRATEGY.md)
- [AgentCore API evidence matrix](./prototype-app/docs/agentcore-api-evidence-matrix.md)
