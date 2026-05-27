# Schema-Per-Tenant Ownership Audit

## Status

This audit reflects the current `prototype-app/backend` branch after the schema-per-tenant reset work already in progress. It classifies the main persistence boundaries so the remaining compatibility cleanup can stay deliberate.

---

## How Schema-Per-Tenant Isolation Works

The runtime uses PostgreSQL `search_path` to isolate tenant data. `TenantAwareDataSource` wraps a HikariCP pool. On every connection checkout, it calls `SET search_path TO <tenant_schema>, public` and `SET LOCAL app.current_tenant_id = '<tenantId>'`. On connection return (close), the search path is reset to prevent leakage.

The sentinel `NO_TENANT_SENTINEL = "00000000-0000-0000-0000-000000000000"` is used in production contexts where no tenant is in scope (platform owner operations).

`TenantResolutionFilter` runs early in the filter chain and populates `TenantContext` (thread-local) from one of three sources, in priority order:
1. JWT claim `tenant_id` (primary in production)
2. `X-Tenant-ID` header (only when `APP_ALLOW_HEADER_TENANT_SELECTION=true` — local dev only)
3. Default tenant fallback (legacy single-tenant mode)

`TenantStatusFilter` follows and blocks requests with HTTP 403 if the resolved tenant is `SUSPENDED` or `EXPIRED`.

`TenantIsolationConfig` wires the above components and enforces that the tenant is always resolved before any JPA repository call executes.

---

## Ownership Classification

### Platform Shared-Plane

These remain in the `platform` schema because they coordinate identity, workspace selection, support access, or cross-tenant administration.

- `tenants`
- `app_users`
- `tenant_memberships`
- `app_user_global_roles`
- `tenant_support_grants`
- `demo_invites`
- `demo_requests`
- `audit_events` (written from tenant-scoped requests but stored platform-side for support/export/reporting)

### Tenant-Schema Local

These are tenant-owned operational records and use schema selection as the primary isolation boundary.

**Findings and workbench:**
`findings`, `finding_events`, `finding_comments`, `finding_delta_queue`, `fix_records`, `investigations`, `investigation_activities`, `investigation_attachments`, `applicability_assessments`, `org_cve_records`, `org_cve_ai_artifacts`, `vex_assertions`

**Inventory and correlation:**
`assets`, `cis`, `ci_aliases`, `inventory_components`, `inventory_component_cpe_map`, `component_vulnerability_states`, `software_inventory_items`, `software_instances`, `software_identities`, `software_identifiers`, `software_identity_summary`, `software_identity_cluster_link`

**Policies and quality:**
`risk_policies`, `suppression_rules`, `ownership_rules`, `vulnerability_source_filter_configs`, `quality_issue_projection`, `normalization_cluster_overrides`, `manual_normalization_overrides`

**Connector and ingestion state:**
`aws_discovery_configs`, `aws_discovery_targets`, `github_sbom_sources`, `servicenow_cmdb_configs`, `sccm_cmdb_configs`, `sync_runs`, `discovery_models`, `sbom_uploads`

**EOL and software mapping:**
`software_eol_mappings`

**Other tenant operational records:**
`service_accounts`

### Hybrid Flows

These cross the platform/tenant boundary and retain compatibility metadata where admin, audit, or orchestration use cases still rely on it.

- `Tenant` on tenant-local entities: keep for now where JPA mappings, audit trails, or admin-plane lookups still rely on it.
- `audit_events`: written from tenant-scoped requests but stored in `platform` for support/export/reporting.
- Support access flows: `tenant_support_grants` stays platform-plane while enabling temporary reads/writes against tenant schemas.
- Bootstrap and purge flows: `TenantBootstrapService`, `TenantSchemaService`, `DemoTenantPurgeService`, and reset/integration tooling operate from the platform plane while creating or deleting tenant-local objects.

---

## Ownership Rule System

`OwnershipRule` entities are stored in the `ownership_rules` table (introduced in V1094) and managed via `OwnershipRuleController` (`GET /api/ownership-rules`, `POST /api/ownership-rules`, `PUT /api/ownership-rules/{id}`, `DELETE /api/ownership-rules/{id}`).

Each rule defines:
- `name` — human-readable label
- `conditions` — JSONB array of match criteria (field, operator, value) evaluated against finding attributes
- `assignee` — the user or group to assign matching findings to
- `priority` — execution order when multiple rules match
- `enabled` — whether the rule participates in evaluation

Rules are evaluated by `OwnershipRuleEvaluationService` when findings are created or updated. The first matching rule (by priority) assigns ownership. If no rule matches, ownership is unset.

---

## Active Compatibility Tail

The runtime sweep showed only a small number of tenant-owned active paths still expressing schema-local work as `tenant_id` filters.

**Fixed:** AWS discovery target inventory counts now use schema-local asset repository methods.

**Fixed:** Dashboard CVE inventory map now loads impacted component-vulnerability states without a redundant tenant-id qualifier.

**Intentionally left as platform-plane:** membership, audit-event, and support-grant repository methods that are genuinely keyed from the shared `platform` schema.

---

## `tenant_id` Retention Guidance

### Safe to keep for now

- Tenant-local entities where `tenant_id` is still part of unique constraints, indexes, import backfills, or admin/support compatibility code.
- Any table still referenced by platform-plane SQL or reset compatibility checks.

### Candidate future removals

- Tenant-local repositories that are always executed inside `TenantSchemaExecutionService` and no longer need tenant-qualified query methods.
- Tenant-local unique/index definitions that duplicate schema isolation and are no longer needed for migration/backfill compatibility.

---

## Bootstrap Gaps

The reset line is functional but not yet fully migration-owned.

- `spring.jpa.hibernate.ddl-auto` is still `update`, so table/column/index creation is still Hibernate-assisted after `postgres_reset/V1`.
- `postgres_reset` currently creates schemas only: `platform` and `tenant_default`.
- `TenantSchemaService` clones tenant-local tables, sequences, defaults, and foreign keys from `tenant_default`, but only after Hibernate has materialized the default tenant schema shape.

### Recommended Next Step

Before switching `ddl-auto` away from `update`, add explicit reset-line DDL for the critical default tenant objects that tests already assert must exist:

- `findings`
- `risk_policies`
- `fix_records`
- the rest of the tenant-local core tables those objects depend on

Once that baseline exists in `postgres_reset`, switch to `validate` in shared config and keep `update` only in explicitly local/dev overrides.

---

## Audit Considerations for Multi-Tenant Data Access

All state-changing operations on tenant-owned data that cross the platform boundary (support grants, bootstrap, purge) should be recorded in `audit_events` with the platform actor identity and the target tenant ID. `AuditEvent` captures: `tenantId`, `actorId`, `action`, `resourceType`, `resourceId`, `timestamp`, and a free-form `detail` JSONB field.

The `RequestCorrelationFilter` injects `X-Request-ID` and `X-Trace-ID` into the MDC for every request. Structured log output in production carries `traceId`, `requestId`, `tenantId`, and `actorId` on every log line, enabling full request attribution across the audit trail.

`TenantSupportGrant` records are time-bounded. The support-grant filter checks for an active grant before allowing a platform-owner actor to read or write a tenant's schema. No support grant is required for platform-plane tables (the actor's JWT already authorizes those).
