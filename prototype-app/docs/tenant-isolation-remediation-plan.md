# Tenant Isolation Remediation Plan

Status: proposed · Owner: TBD · Last updated: 2026-06-24

This plan addresses the findings from the tenant-isolation architecture review. It is ordered to
**stop active leaks first, prevent recurrence second, and install the fail-closed backstop last** — so
the backstop does not turn pre-existing application-layer bugs into outages.

## Background

VulnWatch isolates tenants with **schema-per-tenant** Postgres: a thread-local `TenantContext` drives
`TenantAwareDataSource`, which pins a connection's `search_path` (and `app.current_tenant_id`) at
connection-acquire time. The review found that isolation rests on this single mechanism, that the
mechanism's core invariant is violated in ~10 background-processing sites, and that there is no
database-level backstop (Row-Level Security is dead code).

### Two root causes

1. **No defense in depth.** Isolation rests entirely on `search_path`. RLS is aspirational
   (no `CREATE POLICY` / `ENABLE ROW LEVEL SECURITY` anywhere; nothing reads `app.current_tenant_id`),
   the app uses one DB role with access to all schemas, and `search_path` is set once at acquire-time,
   reset best-effort on close. Any single app-layer mistake is a true cross-tenant leak with no second gate.
2. **The "set tenant context before the transaction opens" invariant is convention-only and pervasively
   violated off the HTTP request path.** Two failure shapes recur: (a) a background job does not iterate
   tenants → only `tenant_default` is processed; (b) a `@Transactional` method calls
   `tenantSchemaExecutionService.run(...)` internally → the connection binds the default schema before
   context switches → silently wrong schema.

## Findings reference

| # | Severity | Where | Issue |
|---|----------|-------|-------|
| 1 | Critical | `OrgCveRecordService.refreshForTenantAndVulnerabilities(UUID)` `:101`; `FindingRecomputeService` CVE/CVE_METADATA/VEX (`:88/117/145`); `FindingDeltaQueueService.processVulnerabilityEntries`/`processVexEntries` | CVE/VEX delta recompute fans out to multiple tenants under one bound connection → tenant B/C's `org_cve_records` written into tenant A's schema. Genuine cross-tenant **write** leak, triggered by routine NVD/GHSA syncs. |
| 2 | Critical | `TenantAwareDataSource`; all per-tenant tables | RLS absent → no DB-level isolation backstop; missing-context defaults to live `tenant_default` instead of failing closed. |
| 3 | Critical | `db/migration/postgres_reset/` (~18 of ~20 per-tenant migrations target `tenant_default.` only); `TenantSchemaService` clone-from-default model | Schema drift: tenants cloned before a migration permanently lack its tables/columns. |
| 4 | Critical (availability) | `FindingWorkflowService.reopenExpiredSuppressions` `:330`, `autoCloseFindingsByPolicy` `:356`; `SuppressionRuleService.runAllApprovedRulesNightly` `:174`; `FindingIncidentSyncService.syncAll` `:55`; `EolRefreshService.denormalizeEolStatus` `:391`; `AssetLifecycleService.markStaleAssetsInactive` `:149` | Six scheduled jobs run against `tenant_default` only — non-default tenants never get suppression reopen, auto-close, incident sync, EOL flags, stale-asset sweeps. |
| 5 | High | `JwtTenantAuthenticationService.java:142-156` | `PLATFORM_OWNER` presenting a `tenant_id`/`tenant_slug` claim (production OIDC shape) gets arbitrary tenant context with no support-grant and no membership check. |
| 6 | High | `TenantSupportGrantService.requireActiveGrantForWrite` `:162` (dead code); `SensitiveTenantActionInterceptor` | READ_ONLY vs WRITE_ENABLED on support grants is never enforced; the only PO write gate is path-based and grant-blind. |
| 7 | High | `TenantService.listTenants()` `:65` | Returns all statuses → scheduled jobs keep processing SUSPENDED/EXPIRED/PURGING tenants; `TenantStatusFilter` only blocks HTTP. |
| 8 | Medium | `VulnerabilityIntelMaintenanceService.scheduledVexStalenessRecompute` `:139`; `LegacyGithubSyncRunBackfillService` `:68` | Same context-before-tx bug; per-tenant reads collapse to default. |
| 9 | Medium | `JwtTenantAuthenticationService:131` vs `WorkspaceService.getWorkspace` | PO switch-in via `active_tenant_id` resolves to null tenant → feature inert/self-inconsistent. |

Already fixed this cycle (reference pattern for the rest): the async ingestion worker
(`IngestionJobService` / `IngestionJobWorkerService`), the finding-delta drain (`FindingDeltaQueueService`),
the scheduler-death gap (`SchedulingConfig`), and the missing entitlement-table migrations (V1 + V27).

---

## Phase 0 — Guardrails & detection (no behavior change) · ~1–2 days

1. **Shared per-tenant work helper** `TenantWorkRunner`:
   - `forEachTenant(Consumer<Tenant>)` — lists tenants, runs each inside
     `tenantSchemaExecutionService.run(tenant, …)` **before** any transaction, per-tenant try/catch,
     top-level guard so a throw cannot unschedule a `@Scheduled` caller.
   - `runScoped(tenant, Supplier)` = `run(tenant, () -> transactionTemplate.execute(...))` for the
     context-first-then-tx pattern. This becomes the only sanctioned way to do background per-tenant work.
2. **Detection-mode instrumentation (ships dark):** in `TenantAwareDataSource.applyTenantContext`,
   sampled `WARN` + metric `tenant.context.missing` when a connection binds with empty/sentinel context
   outside a known platform path. Sizes the problem without changing behavior.
3. **CI gates (build-fail only):**
   - ArchUnit: no `@Transactional` method may reference `tenantSchemaExecutionService.run`.
   - Migration grep gate: reject new `postgres_reset/` files with `tenant_default.`-qualified or
     unqualified per-tenant DDL unless they use the `information_schema.tables` loop pattern.
4. **Datasource resource hardening:** wrap `applyTenantContext` so a failure closes the borrowed
   connection instead of leaking an un-reset one back to the pool (`TenantAwareDataSource.java:44-55`).

**Exit:** helper + gates merged; detection metric live; no behavior change; tests green.

## Phase 1 — Fix confirmed background wrong-schema bugs · ~3–5 days

Migrate each site to the context-first pattern / `TenantWorkRunner`, each with a multi-tenant regression
test (the job's effect must land in a non-default tenant, not `tenant_default`).

| Order | Finding | Site | Change |
|---|---|---|---|
| 1 | #1 (cross-tenant write) | `OrgCveRecordService.refreshForTenantAndVulnerabilities(UUID)`; `FindingRecomputeService` CVE/CVE_METADATA/VEX; `FindingDeltaQueueService` vuln/vex paths | Group fan-out by tenant; wrap each tenant's unit of work in `runScoped(tenantId, …)`; drop method-level `@Transactional`, open tx inside `run()`. Do first — it is the leak. |
| 2 | #4 | `FindingWorkflowService.reopenExpiredSuppressions`, `autoCloseFindingsByPolicy` | `forEachTenant` + inner tx. |
| 3 | #4 | `SuppressionRuleService.runAllApprovedRulesNightly` | Remove method-level `@Transactional`; `forEachTenant` + inner tx. |
| 4 | #4 | `FindingIncidentSyncService.syncAll` | `forEachTenant`; read/write findings in per-tenant context. |
| 5 | #4 | `EolRefreshService.denormalizeEolStatus` (+ triggers) | Run the per-tenant `UPDATE`s inside `run(tenant, …)`. |
| 6 | #4 | `AssetLifecycleService.markStaleAssetsInactive` | Remove method-level `@Transactional`; `forEachTenant` + inner tx. |
| 7 | #8 | `VulnerabilityIntelMaintenanceService.scheduledVexStalenessRecompute`; `LegacyGithubSyncRunBackfillService` | Same pattern. |

Test template: `IngestionJobTenantScopingPostgresIntegrationTest`. ITs depend on the fresh-DB migration
fix already landed (V1 + V27).

**Exit:** all sites migrated; `tenant.context.missing` ≈ 0 for these jobs; ArchUnit gate passes.

## Phase 2 — Authorization model repair · ~3–4 days (parallel with Phase 1)

1. **#5 / #9** — In `JwtTenantAuthenticationService.resolveTenant`, the `tenant_id`/`tenant_slug` branches
   must apply the same support-grant + accessibility checks as the `active_tenant_id` path; reconcile the
   `active_tenant_id` → null behavior so switch-in yields a usable, grant-checked tenant.
2. **#6** — Invoke `requireActiveGrantForWrite` on the tenant-write path; make
   `SensitiveTenantActionInterceptor` grant-aware (READ_ONLY vs WRITE_ENABLED); re-review
   `PlatformAdminRequestPaths` and remove tenant-data-touching prefixes.
3. **#7** — Add `tenantService.listActiveTenants()` (filters SUSPENDED/EXPIRED/PURGING/DELETED) and make
   `TenantWorkRunner.forEachTenant` use it by default.

**Blocking input needed:** production OIDC claim shape (`APP_JWT_TENANT_ID_CLAIM` vs `active_tenant_id`) —
determines whether #5 is reachable in prod and how to gate it.

## Phase 3 — Schema-drift remediation · ~2–3 days (parallel with Phase 1)

1. **#3** — Repair existing tenant schemas. Preferred: startup reconciliation that replays per-tenant DDL
   across all `tenant_%` schemas (idempotent `IF NOT EXISTS`). Alternative: Flyway-per-schema.
2. Drift-diff script: compare each `tenant_%` schema's tables/columns against `tenant_default`; produce the
   repair set (suspects: `bom_components`, `campaigns`, `ingestion_jobs`, `cbom_*`, post-V1 added columns).
3. Fix `provisionTenantSchema` so future clones copy everything (and, after Phase 4, RLS policies — which
   `LIKE INCLUDING` does not copy).
4. The Phase 0 CI gate prevents new drift.

**Exit:** drift-diff reports zero divergence; gate active.

## Phase 4 — RLS + fail-closed defaults (backstop) · ~4–6 days

Done last, after Phases 1 and 3, so enforcement does not cause outages.

1. **#2** — Enable RLS on every per-tenant table (all-schemas loop migration):
   ```sql
   ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
   ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
   CREATE POLICY tenant_isolation ON <t>
     USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
     WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
   ```
   - Apply to per-tenant-schema tables and per-`tenant_id` tables in `platform`
     (`personal_finding_queues`, `finding_queue_preferences`). Exclude genuinely global `platform.*`.
   - `WITH CHECK` catches finding #1's cross-tenant write at the DB.
   - Update `provisionTenantSchema` to (re)create policies on clone.
2. **#2** — Fail-closed default: missing context resolves to a non-existent/empty schema (not
   `tenant_default`); the sentinel `app.current_tenant_id` matches no rows.
3. **Staged rollout:** permissive/logging posture or staging clone first → run full scheduled-job + e2e
   suite under RLS → flip to `FORCE` in prod. Documented fast rollback (drop policies; mind `flyway:repair`).
4. Remove the now-accurate "enables RLS" Javadoc caveat; document the model.

**Exit:** RLS `FORCE` on all per-tenant tables; a deliberate cross-tenant write is rejected by the DB;
contextless query fails closed; full job suite green under RLS.

---

## Sequencing & dependencies

```
Phase 0 (guardrails) ──┬──► Phase 1 (fix bugs) ──────────────┐
                       ├──► Phase 2 (authz)  [parallel]       ├──► Phase 4 (RLS backstop)
                       └──► Phase 3 (drift)  [parallel]───────┘
```

- Phase 0 first (everything builds on the helper + gates).
- Phases 1/2/3 parallelizable.
- Phase 4 must follow 1 and 3 (RLS needs correct context everywhere + `tenant_id` populated on all rows).

## Effort & risk

- ~12–18 engineer-days; Phases 1 and 4 are the heavy ones.
- Highest risk: Phase 4 RLS rollout (mitigated by staging + permissive posture). Highest value: Phase 4 + Phase 1 item 1.
- Low-risk immediate wins: Phase 0 datasource hardening, Phase 2 item 3 (status filtering).

## Cross-cutting verification

- The `tenant.context.missing` metric (Phase 0) is the objective signal the effort is working — it should
  trend to zero by end of Phase 1 and stay there.
- Standing multi-tenant e2e: provision tenant B, drive ingestion + a vuln sync, assert B's
  findings/projections recompute and no B data appears in A.
