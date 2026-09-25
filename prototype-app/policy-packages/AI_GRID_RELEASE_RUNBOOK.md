# AI Grid policy release runbook

Policy rollout is digest-bound and uses the validation-governance API for every exposure-increasing transition. The catalog distribution endpoint is limited to pausing, retiring, or otherwise reducing exposure; it intentionally rejects `DEV`, `available=true`, and direct version pinning.

## DEV

Call `POST /api/platform/ai-grid/validation/policies/{policyId}/dev-deploy` with a non-empty `targetTenantIds` cohort and a test note. This path checks the current approved package and writes the pinned `DEV` distribution required by `require_ai_grid_distribution_approval`.

Do not call `PUT /api/platform/ai-grid/policies/{policyId}/distribution` for this transition. `AiGridPolicyCatalogService.updateDistribution` rejects `DEV` and any request that increases exposure.

## CANARY

After answer-key, precision, approval, and tenant test gates pass, call `POST /api/platform/ai-grid/validation/policies/{policyId}/publish` with `publishAll=false` and the intended `targetTenantIds`. The service creates the digest-bound release binding, pins the approved version, and moves the distribution to `CANARY`.

Every target tenant must be active and have either a complete snapshot or a recorded DEV deployment. For Wave A, the tenant must also report tenant schema V2 as `CURRENT` before it is admitted to the cohort.

## GENERAL_AVAILABILITY

Call the same publish endpoint with `publishAll=true`. The service records all active tenants in the release binding, clears the canary cohort in distribution metadata, and moves the policy to `GENERAL_AVAILABILITY`.

Wave A cannot move to general availability until tenant schema V2 has completed its template fingerprint verification, canary, and batches-of-10 rollout for every active target tenant. A tenant still on V1 is reported by framework coverage as `NOT_ASSESSED` with blocker `TENANT_SCHEMA_VERSION_UNAVAILABLE`; this is readiness state, not a request error.

## Rollback

Use `PUT /api/platform/ai-grid/policies/{policyId}/distribution` only for a reducing transition such as `PAUSED` or `RETIRED`, with `available=false` and no pinned version. Runtime execution events are removed by bounded parent batches; child events are removed through the existing `ON DELETE CASCADE` foreign key.

## Program 2 pilot entry gate

1. Enable `AZURE_FOUNDRY_RUNTIME` and/or `COPILOT_RUNTIME` for the pilot tenants without setting the tenant kill switch.
2. Run the existing connector runtime collection paths for at least the selected pilot window. Null, `UNKNOWN`, and `NOT_EVALUATED` decision states do not count as populated evidence.
3. Read `GET /api/ai-runtime-telemetry-readiness?windowDays=14&minimumFillRate=0.95&minimumExecutionsPerProvider=100`.
4. Do not enable runtime-sequence or runtime-aggregate policy modes unless `program2EntryGateMet=true` for every pilot tenant.

The gate is fail-closed. Every enabled runtime feature contributes an expected provider even when it has collected zero executions. Each expected provider must have at least 100 observations and at least 95% useful population for both `approval_state` and `policy_state`. Providers observed without an enabled pilot feature are reported for diagnosis but do not silently expand the approved pilot cohort.
