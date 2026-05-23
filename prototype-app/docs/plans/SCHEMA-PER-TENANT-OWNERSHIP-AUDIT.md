# Schema-Per-Tenant Ownership Audit

## Status

This audit reflects the current `prototype-app/backend` branch after the schema-per-tenant reset work already in progress. It classifies the main persistence boundaries so the remaining compatibility cleanup can stay deliberate.

## Ownership Classification

### Platform shared-plane

These remain shared in `platform` because they coordinate identity, workspace selection, support access, or cross-tenant administration.

- `tenants`
- `app_users`
- `tenant_memberships`
- `tenant_support_grants`
- `demo_invites`
- `audit_events`

### Tenant-schema local

These are tenant-owned operational records and should treat schema selection, not `tenant_id`, as the primary isolation boundary.

- Findings and workbench:
  `findings`, `finding_events`, `fix_records`, `investigations`, `investigation_activities`,
  `applicability_assessments`, `org_cve_records`, `org_cve_ai_artifacts`, `vex_assertions`
- Inventory and correlation:
  `assets`, `cis`, `ci_aliases`, `inventory_components`, `inventory_component_cpe_maps`,
  `component_vulnerability_states`, `software_inventory_items`, `software_instances`,
  `software_identities`, `software_identifiers`, `software_identity_metadata`
- Policies and quality:
  `risk_policies`, `suppression_rules`, `ownership_rules`, `quality_issue_*`,
  `normalization_cluster_overrides`, `manual_normalization_overrides`
- Connector and ingestion state:
  `aws_discovery_configs`, `aws_discovery_targets`, `github_sbom_sources`,
  `service_now_cmdb_configs`, `sccm_cmdb_configs`, `sync_runs`, `discovery_models`
- EOL and software mapping data that is tenant-managed:
  `software_eol_mappings`
- Other tenant operational records:
  `service_accounts`

### Hybrid flows

These cross the platform/tenant boundary and should keep compatibility metadata where it still supports admin, audit, or orchestration use cases.

- `Tenant` on tenant-local entities:
  Keep for now where JPA mappings, audit trails, or admin-plane lookups still rely on it.
- `audit_events`:
  Written from tenant-scoped requests but stored in `platform` for support/export/reporting.
- Support access flows:
  `tenant_support_grants` stays platform-plane while enabling temporary reads/writes against tenant schemas.
- Bootstrap and purge flows:
  `TenantBootstrapService`, `TenantSchemaService`, `DemoTenantPurgeService`, and reset/integration tooling operate from the platform plane while creating or deleting tenant-local objects.

## Active Compatibility Tail

The runtime sweep showed only a small number of tenant-owned active paths still expressing schema-local work as `tenant_id` filters.

- Fixed in this pass:
  AWS discovery target inventory counts now use schema-local asset repository methods.
- Fixed in this pass:
  Dashboard CVE inventory map now loads impacted component-vulnerability states without a redundant tenant-id qualifier.
- Intentionally left as platform-plane:
  membership, audit-event, and support-grant repository methods that are genuinely keyed from the shared `platform` schema.

## `tenant_id` Retention Guidance

### Safe to keep for now

- Tenant-local entities where `tenant_id` is still part of unique constraints, indexes, import backfills, or admin/support compatibility code.
- Any table still referenced by platform-plane SQL or reset compatibility checks.

### Candidate future removals

- Tenant-local repositories that are already always executed inside `TenantSchemaExecutionService` and no longer need tenant-qualified query methods.
- Tenant-local unique/index definitions that duplicate schema isolation and are no longer needed for migration/backfill compatibility.

## Bootstrap Gaps

The reset line is functional but not yet fully migration-owned.

- `spring.jpa.hibernate.ddl-auto` is still `update`, so table/column/index creation is still being Hibernate-assisted after `postgres_reset/V1`.
- `postgres_reset` currently creates schemas only:
  `platform` and `tenant_default`.
- `TenantSchemaService` clones tenant-local tables, sequences, defaults, and foreign keys from `tenant_default`, but only after Hibernate has materialized the default tenant schema shape.

## Recommended Next Step

Before switching `ddl-auto` away from `update`, add explicit reset-line DDL for the critical default tenant objects that tests already assert must exist:

- `findings`
- `risk_policies`
- `fix_records`
- the rest of the tenant-local core tables those objects depend on

Once that baseline exists in `postgres_reset`, we can move to `validate` in shared config and keep `update` only in explicitly local/dev overrides if still needed.
