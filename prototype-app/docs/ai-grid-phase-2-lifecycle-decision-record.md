# AI Grid Phase 2 — Policy Identity & Lifecycle Decision Record

**Status:** Accepted for development — this record is the engineering contract for Phase 2 implementation.

## Context

Two Phase 2 planning documents exist — "AI Grid Phase 2 — Implementation Plan" (connectors, 83 new packages, correlation, UI) and "Phase 2 policy-ID replacement lifecycle" (schema, approval, deprecation, rollout mechanics). They describe the same 16 changed controls under two different, incompatible identity models:

- The implementation plan treats them as **version revisions**: existing policy IDs (e.g. `AGCF-AWS-017`) stay the same, gain a `1.1.0` package.
- The lifecycle document treats them as **ID replacements**: the old ID is explicitly deprecated, a distinct new ID at `1.0.0` (e.g. `AGCF-AWS-069`) is separately approved and published.

Both models produce the same aggregate arithmetic — 143 active policies, 83 package versions — because the replacement IDs (AWS `069–072`, Azure `070–075`, Exposure `007–012`) slot in as contiguous continuations of each provider's brand-new ID range rather than colliding with it. **This means count-based validation cannot distinguish which model was actually built.** The two models produce materially different behavior for finding history, approvals, rollout bindings, audit trail, and UI, and cannot both be implemented.

## Decision

The lifecycle document is authoritative for policy identity and lifecycle semantics. The implementation plan is amended to match it (see "Amendments" below) before any Phase 2 code is written.

### Locked decisions

1. **New-ID replacement, not version revision**, for each of the 16 changed controls, per the manifest's old→new mapping.
2. **All 83 Phase 2 package versions are `1.0.0`.** No `1.1.0` packages are created under Phase 2.
3. **No automatic retirement, migration, rekeying, or closure-by-publication.** Deprecating the old ID and publishing the new ID are independent operations; neither implicitly triggers, blocks, or waits on the other.
4. **Exactly one publish API surface after this change: policy-ID keyed** (`POST /api/platform/ai-grid/policies/{policyId}/publish`). It accepts an explicit active canary cohort; any pre-existing version-keyed publish/readiness/digest route is removed or returns an explicit migration error. The no-body compatibility request form defaults to `default-workspace` only; it is not preserved on any version-keyed route.
5. **The signed Phase 2 manifest is the sole authority** for IDs, digests, ID-range gaps, and the 16 replacement mappings. No package, digest, or mapping is finalized in code before the manifest confirms it.

### Acceptance criteria (gates — each requires a specific automated test, not inferred from aggregate counts)

- **AC1 — Identity, per mapping:** for each of the 16 manifest entries, assert the old policy ID's lifecycle is `DEPRECATED`, it is excluded from evaluation and tenant selection, its open findings are closed with `AUTO_POLICY_PLATFORM_DEPRECATED`, and the successor is a distinct policy ID at `1.0.0` with no inherited finding identity — no finding references both IDs, no rekeying.
- **AC2 — Independence:** deprecating the old ID succeeds and is independently verifiable even when the successor policy does not yet exist, is not yet approved, or is not yet published. Deprecation must not check for, wait on, or be gated by successor state.
- **AC3 — Single API surface:** exactly one publish endpoint exists, policy-ID keyed. Any prior version-keyed publish/readiness/digest route is removed or returns a typed migration error.
- **AC4 — Compatibility scope:** explicit requests support any active canary cohort; the no-body form works only on the policy-ID endpoint and defaults to `CANARY`/`default-workspace`.

## Amendments to "AI Grid Phase 2 — Implementation Plan"

- **Plan 1 (AWS):** "Publish revised `1.1.0` packages for `AGCF-AWS-017/024/031/032`" → deprecate each of those four IDs; publish new `1.0.0` policies `AGCF-AWS-069–072` per the manifest mapping.
- **Plan 2 (Azure):** "Publish revised `1.1.0` packages for `AGCF-AZR-001/002/019/030/031/032`" → deprecate those six IDs; publish new `1.0.0` policies `AGCF-AZR-070–075`.
- **Plan 3 (Exposure):** "Revise the six existing exposure packages ... to `1.1.0`" → deprecate `AGCF-XSP-001–006`; publish new `1.0.0` policies `AGCF-XSP-007–012`.
- **Plan 4 (Approval and Default Workspace rollout):** "the existing per-policy publish operation" it extends is the policy-ID-keyed endpoint defined by the lifecycle document, not any current version-keyed route; the no-body compatibility behavior it preserves is scoped exactly as AC4 states.
- **Framework/Defaults and Test Plan/Definition of Done sections:** every reference to "16 revisions" / "`1.1.0`" is read as "16 replacements" / "`1.0.0` successor, deprecated predecessor."

## Sequencing (unchanged)

Lifecycle foundation (schema, digest algorithm, deprecate API/worker, publish/release-binding API, docs) ships first, alone, and is fully testable against the existing Phase 1 catalog without the manifest. The compiler refactor and connector fact-producers proceed in parallel, against fixtures. No policy IDs, replacement mappings, or the package-install migration are written until the signed manifest is available and validated. The install migration is the final step, over already-approved content.

## Note

The reconciled implementation plan is checked in alongside this record at [`ai-grid-phase-2-implementation-plan.md`](./ai-grid-phase-2-implementation-plan.md), with the amendments above applied inline and marked `(Reconciled)`. The lifecycle document referenced throughout this record ("Phase 2 policy-ID replacement lifecycle") still lives outside the repo — check it in as the Plan 0 foundation work lands, so the schema/API implementation and its source spec stay in sync.
