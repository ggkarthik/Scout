# Phase 0 — Entitlement Resolution Cutover Runbook

This runbook covers rolling out the corrected entitlement resolver safely. It is a prerequisite
for the AI Security module: the `ai.security` entitlement is the pilot kill switch, and it only
works once entitlement resolution actually honors plan values and tenant overrides.

## Background

Before this change, `TenantEntitlementService.resolve()`/`resolveAll()` returned `enabled=true`
for every key regardless of plan or tenant override — the resolver's precedence logic was never
wired in. Correcting it changes runtime authorization, so the rollout is staged behind a
three-state mode rather than flipped at once.

## Modes (`app.entitlements.mode`)

| Mode | `isEnabled` / snapshot enforce | Corrected computed? | Mismatch telemetry |
|---|---|---|---|
| `LEGACY` | legacy (always enabled) | no | no |
| `SHADOW` | legacy (always enabled) | yes | yes |
| `ENFORCE` | corrected for allowlisted tenants; legacy for the rest | yes | yes |

Corrected precedence: **active tenant override → plan value → disabled default**. Expired
overrides are ignored and fall through to the plan value (they never force-disable). Platform/null
context returns an empty snapshot and fails closed under `ENFORCE`. An invalid mode value fails
startup (a typo must not silently defeat a cutover).

## Configuration

| Property | Env var | Default (base) | Default (preprod) |
|---|---|---|---|
| `app.entitlements.mode` | `APP_ENTITLEMENTS_MODE` | `LEGACY` | `SHADOW` |
| `app.entitlements.enforce-tenant-allowlist` | `APP_ENTITLEMENTS_ENFORCE_TENANT_ALLOWLIST` | *(empty)* | *(empty)* |
| `app.entitlements.shadow-sweep-cron` | `APP_ENTITLEMENTS_SHADOW_SWEEP_CRON` | `0 */30 * * * *` | inherited |

The allowlist is a comma-separated list of tenant UUIDs; `*` enforces every tenant.

## Telemetry to watch

- **Counter** `entitlement.resolution.mismatch{key,source,corrected}` — increments whenever the
  corrected result differs from legacy. `key` is bounded to the seven known keys or `UNKNOWN`;
  tenant id is never a label.
- **Structured log** (from the leader-locked shadow sweep only, bounded to one line per
  tenant/key per run): `entitlement shadow mismatch tenant=… key=… legacy=true corrected=… source=…`.
  Per-request evaluation only increments the counter; it does not log, to avoid replica noise.

Expected steady-state mismatches: `ai.security` is disabled at the plan level for every plan, so a
mismatch on `ai.security` for tenants that have not been granted it is **expected** (legacy would
have shown it enabled; corrected correctly shows it disabled). Any mismatch on one of the six
existing `ai.*` keys is **not** expected — investigate before cutover, because it means a plan or
override would disable a shipped feature.

## Rollout sequence

1. **Deploy in `SHADOW`** (preprod default). No enforcement change; corrected results are computed
   and mismatch telemetry accrues. Leave running **≥ 7 days**.
2. **Explain every mismatch.** For each `(tenant, key)` mismatch, confirm it is the intended
   `ai.security`-disabled case or a deliberate plan/override. Resolve any unexpected existing-`ai.*`
   mismatch (usually a stray plan row) before proceeding.
3. **Canary ENFORCE for the internal tenant.** Set `APP_ENTITLEMENTS_MODE=ENFORCE` and
   `APP_ENTITLEMENTS_ENFORCE_TENANT_ALLOWLIST=<internal-tenant-uuid>`. Only that tenant switches to
   corrected; everyone else stays on legacy. Verify the internal tenant behaves correctly.
4. **Expand** the allowlist tenant by tenant as each is verified.
5. **Global enforcement** (optional, end state): set the allowlist to `*`.

Grant `ai.security` to a pilot tenant at any point with a tenant entitlement override (enabled),
independent of the mode rollout.

## Rollback

Set `APP_ENTITLEMENTS_MODE=SHADOW` (or `LEGACY`) and redeploy — enforcement reverts immediately
with no data change. The V47 migration is additive (idempotent seed + one new key); no migration
rollback is required for an application rollback.

## Coordinated change set (this PR)

Backend resolver + compat seed, `/api/auth/context` snapshot, frontend fail-closed consumption,
leader-locked shadow sweep, and tests ship together so backend enforcement, the auth-context
snapshot, and frontend gating never disagree. The `ai.security` key is seeded disabled for all
plans; connector and policy administration are gated by authorization roles, not entitlements.
