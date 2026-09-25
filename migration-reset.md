# Migration reset — 2026-09-04

The pre-customer migration history was consolidated into independent platform and tenant V1 baselines. The reset covers only local, demo, and staging databases containing test data.

Before deploying this revision, export each non-production database, stop workers, and drop the schemas and Flyway history tables together. Run the privileged schema bootstrap, verify tenant checksums/RLS/control-plane status, then reseed approved demo data and restart workers. Never delete Flyway history separately from its schema.

Routine migrations are append-only. Existing migration files must not be edited, renamed, or deleted. CI compares each pull request with its base branch and the required merge-queue run checks the combined catalog for duplicate versions.

The reset baselines are no longer the catalog heads. Both independent lines now have append-only V2 and V3 migrations:

- `postgres_reset/V2__ai_grid_framework_coverage.sql` adds the AI Grid framework/control registry, the shared tenant-visibility SQL function, and the typed runtime-field registry. It is platform-only and does not rewrite existing policy packages or distribution bindings.
- `tenant/V2__ai_grid_approved_manifests.sql` adds RLS-protected approved agent manifests and component allowlists plus normalized runtime decision constraints. It is applied per tenant through the schema control plane (template fingerprint, canary, then batches of 10).
- `postgres_reset/V3__ai_grid_runtime_policy_contract.sql` adds the `RUNTIME_FACTS`/`RUNTIME_SEQUENCE`/`RUNTIME_AGGREGATE`/`RUNTIME_COVERAGE` evaluation modes, the `EXECUTION` evaluation subject, the runtime evidence-family/capability rows, and ~19 more `execution.*`/`event.*` runtime field-registry entries.
- `tenant/V3__ai_grid_runtime_policy_contract.sql` adds the typed runtime execution/event contract, the `ai_runtime_evidence_producers`/`ai_runtime_source_configurations`/`ai_runtime_quota_windows`/`ai_runtime_ingestion_receipts` tables (all RLS-forced), runtime quota columns on `ai_grid_budget_config`, and the `AI_RUNTIME` finding kind. It is applied per tenant through the same schema control plane as V2.

`PackagedMigrationCatalog` therefore resolves platform target 3 and tenant target 3. The configured minimum-compatible tenant schema remains 1 during rollout; compatibility floor and packaged target are intentionally different concepts.
