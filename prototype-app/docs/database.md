# VulnWatch Database

Last updated: 2026-07-17

The runtime database is PostgreSQL, with Flyway-managed reset-line bootstrap under `backend/src/main/resources/db/migration/postgres_reset`. The legacy numbered migration history has been removed from the active development line — a prior drift-repair effort reset and renumbered the whole migration line, consolidating everything up to that point into the `V1__platform_and_default_tenant_schemas.sql` baseline (60+ tables). Current latest platform-line migration is `V45__tenant_access_membership_provenance.sql`. As of V42, per-tenant schema DDL (including RLS enforcement) has moved to a second, independent Flyway line under `db/migration/tenant/`, applied once per tenant schema by `TenantSchemaMigrationService` / `ProductionBootstrapCli` rather than by the application's own startup Flyway run — see [Tenant Schema Control Plane](#tenant-schema-control-plane). H2 is retained only as an offline archive format for legacy data snapshots.

---

## Overview

- **Database name (local):** `vulnwatch`
- **JDBC URL default:** `jdbc:postgresql://localhost:5432/vulnwatch`
- **Migration directories:** `backend/src/main/resources/db/migration/postgres_reset/` (platform/`public` schema) and `backend/src/main/resources/db/migration/tenant/` (per-tenant schema, applied by the tenant schema control plane, not by the application's own startup Flyway run)
- **Flyway baseline migration:** `V1__platform_and_default_tenant_schemas.sql`
- **All statements:** `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` (idempotent replay via psql is safe)
- **`ddl-auto`:** `none` (Flyway owns all DDL; Hibernate never creates or alters tables)

---

## Schema Structure

The database is split into two PostgreSQL schemas:

| Schema | Purpose |
|---|---|
| `platform` | Shared, cross-tenant data: tenants, users, global vulnerabilities, software identities, EOL catalog |
| `tenant_default` | Template for per-tenant operational data: assets, inventory, findings, org CVE records, connectors, policies |

At runtime, `TenantAwareDataSource` sets PostgreSQL session variables on every connection:
```sql
SELECT set_config('app.current_tenant_id', '<uuid>', FALSE);
SELECT set_config('search_path', '<tenant_schema>,platform', FALSE);
```

JPA queries reference tables without schema prefixes and always land in the correct tenant schema via `search_path`.

New tenant schemas are created by `TenantSchemaService` by cloning `tenant_default`.

---

## Platform Schema Tables

### `platform.tenants`

Stores every registered tenant (organization).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `name` | `varchar(255)` | NOT NULL; unique |
| `schema_name` | `varchar(255)` | NOT NULL; unique |
| `slug` | `varchar(255)` | unique |
| `status` | `varchar(255)` | NOT NULL |
| `plan_code` | `varchar(255)` | NOT NULL |
| `billing_ref` | `varchar(255)` | |
| `max_connector_count` | `integer` | NOT NULL |
| `max_daily_exposure_refreshes` | `integer` | NOT NULL |
| `max_daily_sbom_uploads` | `integer` | NOT NULL |
| `max_export_rows` | `integer` | NOT NULL |
| `max_service_account_count` | `integer` | NOT NULL |
| `demo_created_by` / `demo_owner_email` / `demo_source` | `varchar(255)` | |
| `demo_expires_at` | `timestamptz` | |
| `expired_at` / `suspended_at` | `timestamptz` | |
| `purge_status` / `purge_error` | `varchar(255)` | |
| `purge_started_at` / `purged_at` / `deleted_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `platform.app_users`

Platform-level user accounts. Supports both OAuth (`external_subject`) and local password auth.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `external_subject` | `varchar(255)` | NOT NULL; unique |
| `email` | `varchar(255)` | |
| `display_name` | `varchar(255)` | |
| `platform_owner` | `boolean` | NOT NULL |
| `status` | `varchar(255)` | NOT NULL |
| `password_hash` | `varchar(255)` | bcrypt hash for local credential auth |
| `password_set_at` | `timestamptz` | |
| `password_setup_token_hash` | `varchar(255)` | one-time setup token (hashed) |
| `password_setup_token_expires_at` | `timestamptz` | |
| `last_seen_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `platform.tenant_memberships`

Links users to tenants with a role.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK → `platform.tenants(id)` |
| `user_id` | `uuid` | FK → `platform.app_users(id)` |
| `invited_by` | `uuid` | FK → `platform.app_users(id)` |
| `role` | `varchar(255)` | NOT NULL |
| `status` | `varchar(255)` | NOT NULL |
| `provenance` | `varchar(32)` | NOT NULL; `MANUAL`, `TENANT_INVITE`, or `PLAYGROUND_BOOTSTRAP` |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique index: `(user_id, tenant_id)`.

---

### `platform.app_user_global_roles`

Platform-wide roles for users (e.g., PLATFORM_OWNER).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `app_user_id` | `uuid` | FK → `platform.app_users(id)` |
| `role` | `varchar(64)` | NOT NULL |
| `created_at` | `timestamptz` | NOT NULL |

Unique constraint: `(app_user_id, role)`. Index: `idx_app_user_global_roles_role` on `(role)`.

---

### `platform.tenant_support_grants`

Platform-owner support access grants with expiry and audit trail.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK → `platform.tenants(id)` |
| `granted_by` | `uuid` | FK → `platform.app_users(id)`, NOT NULL |
| `accepted_by` / `revoked_by` | `uuid` | FK → `platform.app_users(id)` |
| `invited_platform_subject` | `varchar(255)` | NOT NULL |
| `access_mode` | `varchar(255)` | NOT NULL |
| `scope` / `reason` | `varchar(255)` | |
| `status` | `varchar(255)` | NOT NULL |
| `expires_at` | `timestamptz` | NULL only when non-expiring support access is explicitly enabled |
| `requested_at` | `timestamptz` | NOT NULL |
| `accepted_at` / `revoked_at` / `updated_at` | `timestamptz` | |

Indexes: `idx_tenant_support_grants_subject_status_expires` on `(invited_platform_subject, status, expires_at)`, `idx_tenant_support_grants_tenant_requested` on `(tenant_id, requested_at)`.

---

### `platform.tenant_entitlement_overrides`

Per-tenant overrides of default entitlements (e.g. enable a beta feature, adjust a plan limit). Added in V38.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |
| `entitlement_key` | `varchar(128)` | NOT NULL |
| `enabled` | `boolean` | NOT NULL |
| `config_json` | `jsonb` | Feature-specific configuration |
| `reason` | `varchar(500)` | Admin note explaining the override |
| `expires_at` | `timestamptz` | NULL = permanent |
| `created_by` | `uuid` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, entitlement_key)`. Index: `(tenant_id)`.

---

### `platform.tenant_schema_versions`

Operational projection of each tenant's per-schema Flyway state, populated by `TenantSchemaMigrationService` / `ProductionBootstrapCli`. The `tenant` migration line's own `<schema>.tenant_schema_history` table (one per tenant schema) remains the authoritative Flyway record; this table is a queryable rollup across all tenants for the platform console and the readiness health indicator. Added in V42, target-version default advanced in V43/V44.

| Column | Type | Notes |
|---|---|---|
| `tenant_id` | `uuid` | PK; FK → `platform.tenants(id)` ON DELETE CASCADE |
| `schema_name` | `varchar(120)` | NOT NULL, UNIQUE |
| `current_version` | `integer` | NOT NULL DEFAULT 0 |
| `target_version` | `integer` | NOT NULL; advanced by each new control-plane migration (44 as of V44) |
| `status` | `varchar(24)` | `PENDING`, `MIGRATING`, `CURRENT`, `FAILED`, `DRIFTED`, `PROVISIONING_FAILED` |
| `structural_checksum` | `varchar(64)` | SHA-256 of the schema's normalized column/constraint/index/sequence/RLS-policy fingerprint |
| `migration_started_at` / `migration_completed_at` | `timestamptz` | |
| `last_successful_version` | `integer` | NOT NULL DEFAULT 0; never regresses |
| `failure_code` / `failure_message` | `varchar` | Set on `FAILED`/`DRIFTED`/`PROVISIONING_FAILED`; message is sanitized (secrets redacted, truncated to 1000 chars) |
| `migration_run_id` | `uuid` | Correlates rows written by the same migration run |

Index: `(status, current_version)`. See [Tenant Schema Control Plane](#tenant-schema-control-plane) below.

---

### `platform.vulnerabilities`

Master vulnerability (CVE) catalog. Platform-wide; shared across all tenants.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `external_id` | `varchar(50)` | NOT NULL; unique (CVE ID) |
| `source` | `varchar(20)` | NOT NULL (NVD, GHSA, etc.) |
| `title` | `varchar(500)` | NOT NULL |
| `description_snippet` | `varchar(500)` | |
| `description_archive_key` | `varchar(200)` | S3/local archive key for full description |
| `cvss_score` | `double precision` | |
| `severity` | `varchar(20)` | NOT NULL |
| `epss_score` | `double precision` | |
| `in_kev` | `boolean` | NOT NULL |
| `cvss_vector` | `varchar(300)` | |
| `cvss_version` | `varchar(20)` | |
| `attack_vector` / `attack_complexity` / `privileges_required` / `user_interaction` / `cvss_scope` | `varchar(20)` | |
| `exploitability_score` / `impact_score` | `double precision` | |
| `cwe_ids` | `varchar(200)` | |
| `source_identifier` | `varchar(255)` | |
| `vuln_status` | `varchar(80)` | |
| `kev_date_added` / `kev_due_date` | `date` | |
| `kev_required_action` | `varchar(500)` | |
| `references_json` | `text` | |
| `raw_payload_archive_key` | `varchar(200)` | |
| `published_at` / `last_modified_at` / `epss_updated_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_vulnerabilities_severity`, `idx_vulnerabilities_in_kev`, `idx_vulnerabilities_epss`, `idx_vulnerabilities_published`, `idx_vulnerabilities_external_cvss_lastmod_updated`, `idx_vulnerabilities_cvss_lastmod_updated`.

---

### `platform.software_identities`

Canonical software product identities (deduplicated across all tenants).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `canonical_key` | `varchar(400)` | NOT NULL; unique |
| `display_name` | `varchar(300)` | NOT NULL |
| `vendor` / `product` | `varchar(255)` | |
| `product_hash` | `varchar(255)` | |
| `purl` | `varchar(1200)` | |
| `cpe23` | `varchar(1200)` | |
| `vendor_product_id` | `varchar(255)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Index: `idx_software_identity_key` on `(canonical_key)`.

---

### `platform.software_identifiers`

Alternative identifier records (CPE, PURL, SWID, etc.) attached to a software identity.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `id_type` | `varchar(40)` | NOT NULL |
| `normalized_value` | `varchar(1000)` | NOT NULL |
| `raw_value` | `varchar(1000)` | |
| `source` | `varchar(80)` | NOT NULL |
| `confidence` | `double precision` | |
| `provenance_note` | `varchar(500)` | |
| `verified` | `boolean` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(software_identity_id, id_type, normalized_value)`. Indexes: `idx_software_identifier_type_value` on `(id_type, normalized_value)`, `idx_software_identifier_identity` on `(software_identity_id)`.

---

### `platform.cpe_dim`

Parsed/normalized CPE dimension table. One row per unique CPE string.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `raw_cpe` | `varchar(1200)` | NOT NULL |
| `normalized_cpe` | `varchar(1200)` | NOT NULL; unique |
| `part` / `vendor` / `product` | `varchar(500)` | NOT NULL |
| `version` / `update` / `edition` / `language` / `sw_edition` / `target_sw` / `target_hw` / `other` | `varchar(500)` | |
| `cpe_key` | `varchar(1000)` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_cpe_dim_key` on `(cpe_key)`, `idx_cpe_dim_normalized` on `(normalized_cpe)`.

---

### `platform.vulnerability_intel_summary`

Read-model projection: one row per vulnerability. Backs the Vulnerability Intelligence feed UI (`/vuln-repo/vulnerabilities`).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)`; unique |
| `external_id` | `varchar(255)` | NOT NULL |
| `title` | `varchar(255)` | NOT NULL |
| `description_snippet` | `varchar(220)` | |
| `severity` | `varchar(255)` | NOT NULL |
| `cvss_score` / `epss_score` | `double precision` | |
| `in_kev` | `boolean` | NOT NULL |
| `vuln_status` | `varchar(255)` | |
| `source_count` | `integer` | NOT NULL |
| `published_at` / `last_modified_at` / `summary_updated_at` / `updated_at` / `created_at` | `timestamptz` | |

Indexes: `idx_vintel_summary_external_id`, `idx_vintel_summary_severity`, `idx_vintel_summary_in_kev`, `idx_vintel_summary_vuln_status`, `idx_vintel_summary_external_cvss_lastmod_updated`.

---

### `platform.vulnerability_intel_summary_sources`

Which source systems contributed data to each `vulnerability_intel_summary` row.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | NOT NULL |
| `source_system` | `varchar(80)` | NOT NULL |

Unique: `(vulnerability_id, source_system)`.

---

### `platform.vulnerability_intel_observations`

Raw observation records from each source system (NVD, GHSA, CSAF, etc.) for a given CVE.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `source_system` | `varchar(80)` | NOT NULL |
| `source_record_id` | `varchar(255)` | NOT NULL |
| `source_url` | `varchar(1200)` | |
| `title` / `description` / `severity` | various | |
| `cvss_score` / `cvss_vector` / `epss_score` | various | |
| `in_kev` | `boolean` | |
| `vuln_status` | `varchar(120)` | |
| `cwe_ids` | `varchar(2000)` | |
| `references_json` / `raw_payload` | `text` | |
| `payload_hash` | `varchar(128)` | |
| `published_at` / `last_modified_at` / `observed_at` / `last_seen_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(source_system, source_record_id)`. Indexes: `idx_vuln_intel_obs_vulnerability`, `idx_vuln_intel_obs_source`, `idx_vuln_intel_obs_last_seen`.

---

### `platform.vulnerability_intel_relations`

Relationships between observations (e.g., CSAF document → CVE observation).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `from_observation_id` / `to_observation_id` | `uuid` | FK → `platform.vulnerability_intel_observations(id)` |
| `relation_type` | `varchar(80)` | NOT NULL |
| `source_system` | `varchar(80)` | NOT NULL |
| `confidence` | `double precision` | |
| `verified` | `boolean` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(from_observation_id, to_observation_id, relation_type, source_system)`.

---

### `platform.vulnerability_targets`

Affected software targets for each vulnerability (CPE nodes, package ranges, version bounds).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `cpe_id` | `uuid` | FK → `platform.cpe_dim(id)` |
| `target_type` | `varchar(40)` | NOT NULL |
| `raw_target` | `varchar(1200)` | |
| `normalized_target_key` | `varchar(500)` | NOT NULL |
| `ecosystem` / `namespace` / `package_name` | various | |
| `version_exact` / `version_start` / `version_end` / `fixed` / `introduced` | `varchar(255)` | |
| `start_inclusive` / `end_inclusive` | `boolean` | |
| `version_scheme` | `varchar(40)` | NOT NULL |
| `constraint_type` | `varchar(40)` | |
| `cpe` | `varchar(1200)` | |
| `cpe_wildcard_score` | `integer` | |
| `qualifier_*` fields (part, vendor, product, etc.) | `varchar(255)` | |
| `qualifiers_json` | `text` | |
| `source` | `varchar(80)` | NOT NULL |
| `kb_version` | `varchar(120)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_vuln_target_vuln`, `idx_vuln_target_type_key`, `idx_vuln_target_package`, `idx_vuln_target_identity`, `idx_vuln_target_cpe_id`, `idx_vuln_target_type_cpe_id`.

---

### `platform.vex_assertions`

VEX (Vulnerability Exploitability eXchange) statements from vendors (Microsoft CSAF, Red Hat CSAF). Governs applicability overrides.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `observation_id` | `uuid` | FK → `platform.vulnerability_intel_observations(id)` |
| `target_id` | `uuid` | FK → `platform.vulnerability_targets(id)`; unique |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `cpe_id` | `uuid` | FK → `platform.cpe_dim(id)` |
| `source_system` | `varchar(80)` | NOT NULL |
| `provider` | `varchar(120)` | NOT NULL |
| `document_id` | `varchar(255)` | NOT NULL |
| `statement_key` | `varchar(512)` | NOT NULL |
| `status` | `varchar(64)` | NOT NULL |
| `trust_tier` | `varchar(40)` | NOT NULL |
| `freshness` | `varchar(40)` | NOT NULL |
| `normalized_product_key` | `varchar(500)` | NOT NULL |
| `version_exact` / `version_start` / `version_end` / `fixed_version` | `varchar(255)` | |
| `ecosystem` / `namespace` / `package_name` | various | |
| `raw_target` / `evidence_json` | `text` | |
| `published_at` / `last_seen_at` / `created_at` / `updated_at` | `timestamptz` | |

Unique: `(vulnerability_id, source_system, document_id, statement_key)`. Indexes: `idx_vex_assertions_vulnerability`, `idx_vex_assertions_source`, `idx_vex_assertions_target`, `idx_vex_assertions_identity`, `idx_vex_assertions_cpe`.

---

### `platform.vulnerability_rules`

Simplified matching rules derived from NVD/GHSA configuration nodes.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `ecosystem` / `package_name` | `varchar(255)` | NOT NULL |
| `cpe` / `cpe_product` / `cpe_vendor` | `varchar(255)` | |
| `version_exact` / `version_start` / `version_end` | `varchar(255)` | |
| `version_start_inclusive` / `version_end_inclusive` | `boolean` | |
| `created_at` | `timestamptz` | NOT NULL |

Indexes: `idx_vuln_rules_vulnerability`, `idx_vuln_rules_ecosystem_package`.

---

### `platform.vulnerability_config_expr`

NVD CPE configuration expression tree nodes.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `config_index` / `node_path` / `parent_path` | various | NOT NULL |
| `operator` | `varchar(32)` | |
| `negate` | `boolean` | NOT NULL |
| `child_node_count` / `match_criteria_count` | `integer` | |
| `expr_json` | `text` | |
| `source` | `varchar(40)` | NOT NULL |
| `created_at` | `timestamptz` | NOT NULL |

---

### `platform.eol_product_catalog`

End-of-life product catalog from endoflife.date API.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `slug` | `varchar(200)` | NOT NULL; unique |
| `cpe_vendor` / `cpe_product` | `varchar(200)` | |
| `purl_type` / `purl_namespace` | `varchar(200)` | |
| `display_name` | `varchar(200)` | |
| `aliases` | `text` | |
| `last_modified` | `varchar(50)` | |
| `last_fetched_at` / `created_at` / `updated_at` | `timestamptz` | |

Indexes: `idx_eol_catalog_cpe` on `(cpe_vendor, cpe_product)`, `idx_eol_catalog_purl` on `(purl_type, purl_namespace)`.

---

### `platform.eol_release`

Per-product release cycle data from endoflife.date.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `product_slug` | `varchar(200)` | NOT NULL |
| `cycle` | `varchar(100)` | NOT NULL |
| `release_date` / `eol_date` / `support_end_date` / `extended_support_date` / `latest_release_date` / `security_support_date` | `date` | |
| `eol_boolean` | `boolean` | |
| `latest_version` | `varchar(100)` | |
| `is_lts` / `is_eol` | `boolean` | NOT NULL |
| `is_eoas` / `is_eoes` | `boolean` | |
| `official_source_url` | `varchar(500)` | |
| `support_phase` | `varchar(30)` | |
| `discontinued` | `boolean` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(product_slug, cycle)`. Index: `idx_eol_release_product_slug`, `idx_eol_release_is_eol`.

---

### `platform.software_eol_mapping`

Resolved mapping between a software identity canonical key and an EOL product slug.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `software_identity_id` | `uuid` | |
| `normalized_key` | `varchar(500)` | NOT NULL; unique |
| `eol_slug` | `varchar(200)` | |
| `match_confidence` | `varchar(20)` | |
| `match_method` | `varchar(50)` | |
| `confirmed` | `boolean` | NOT NULL |
| `confirmed_by` / `confirmed_at` | various | |
| `previous_slug` | `varchar(200)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_software_eol_mapping_identity`, `idx_software_eol_mapping_slug`.

---

### `platform.identity_links`

Graph edges connecting `software_identifier` nodes across identity resolution.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `from_identifier_id` / `to_identifier_id` | `uuid` | FK → `platform.software_identifiers(id)` |
| `link_type` | `varchar(80)` | NOT NULL |
| `match_rule` | `varchar(40)` | |
| `source` | `varchar(80)` | NOT NULL |
| `confidence` | `double precision` | |
| `verified` | `boolean` | NOT NULL |
| `verified_at` | `timestamptz` | |
| `last_seen_at` / `created_at` / `updated_at` | `timestamptz` | |

Unique: `(from_identifier_id, to_identifier_id, link_type, source)`. Indexes: `idx_identity_links_from`, `idx_identity_links_to`.

---

## Tenant Schema Tables (`tenant_default`)

All tables below live in `tenant_default` (or the active tenant's schema). All have `tenant_id uuid NOT NULL FK → platform.tenants(id)`.

---

### `assets`

Every discoverable asset (application, host, container image, cloud resource).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `identifier` | `varchar(255)` | NOT NULL; unique with `tenant_id` |
| `name` | `varchar(255)` | NOT NULL |
| `type` | `varchar(255)` | NOT NULL; CHECK IN (`APPLICATION`, `HOST`, `CONTAINER_IMAGE`, `CLOUD_RESOURCE`) |
| `state` | `varchar(255)` | NOT NULL; CHECK IN (`ACTIVE`, `INACTIVE`, `RETIRED`, `DECOMMISSIONED`) |
| `business_criticality` | `varchar(255)` | NOT NULL; CHECK IN (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `environment` / `owner_email` / `owner_team` / `department` | `varchar(255)` | |
| `cloud_provider` / `cloud_region` / `cloud_account_id` / `cloud_arn` / `cloud_resource_type` | `varchar(255)` | |
| `cloud_instance_type` / `cloud_subnet_id` / `cloud_vpc_id` | `varchar(255)` | |
| `cloud_launch_time` | `timestamptz` | |
| `cloud_tags_json` | `varchar(255)` | |
| `image_digest` / `image_tag` / `image_repository` | `varchar(255)` | Container image fields |
| `ssm_managed` | `boolean` | AWS SSM managed flag |
| `ssm_ping_status` | `varchar(255)` | |
| `ssm_last_ping_at` / `ssm_inventory_last_captured_at` | `timestamptz` | |
| `ssm_inventory_available` / `missing_iam_instance_profile` | `boolean` | |
| `last_cmdb_sync_at` / `last_inventory_at` | `timestamptz` | |
| `created_at` | `timestamptz` | NOT NULL |

Index: `idx_assets_tenant_id`.

---

### `sbom_uploads`

Tracks every SBOM document ingestion attempt.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `asset_id` | `uuid` | FK → `assets(id)` |
| `tenant_id` | `uuid` | FK |
| `format` | `varchar(255)` | CHECK IN (`CYCLONEDX`, `SPDX`, `HOST_INVENTORY`, `UNKNOWN`) |
| `status` | `varchar(255)` | CHECK IN (`IN_PROGRESS`, `SUCCESS`, `FAILURE`) |
| `original_filename` | `varchar(255)` | NOT NULL |
| `content_sha256` | `varchar(255)` | |
| `component_count` / `findings_generated` / `fetch_status_code` | `integer` | |
| `source_endpoint` / `source_reference` / `ingestion_source_system` / `ingestion_source_type` | `varchar(255)` | |
| `evidence_json` | `text` | |
| `uploaded_at` | `timestamptz` | NOT NULL |

Indexes: `idx_sbom_upload_asset_uploaded`, `idx_sbom_upload_tenant_uploaded`.

---

### `inventory_components`

Individual software components discovered within an asset's SBOM.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `asset_id` | `uuid` | FK → `assets(id)` |
| `sbom_upload_id` | `uuid` | FK → `sbom_uploads(id)` |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `manual_identity_id` | `uuid` | FK (for manually overridden identity) |
| `tenant_id` | `uuid` | FK |
| `purl` | `varchar(255)` | NOT NULL |
| `normalized_purl` | `varchar(255)` | |
| `package_name` | `varchar(255)` | NOT NULL |
| `normalized_name` / `version` / `normalized_version` | `varchar(255)` | |
| `ecosystem` | `varchar(255)` | NOT NULL |
| `coord_key` / `component_digest` | `varchar(255)` | |
| `component_status` | `varchar(255)` | CHECK IN (`ACTIVE`, `RETIRED`) |
| `is_eol` | `boolean` | |
| `eol_slug` / `eol_cycle` | `varchar(255)` | |
| `eol_date` / `eol_support_end_date` | `date` | |
| `eol_checked_at` | `timestamptz` | |
| `support_phase` | `varchar(255)` | |
| `manual_identity_reason` | `varchar(400)` | |
| `manual_identity_confirmed_by` | `varchar(255)` | |
| `manual_identity_confirmed_at` | `timestamptz` | |
| `ingested_at` / `last_observed_at` | `timestamptz` | NOT NULL |
| `retired_at` | `timestamptz` | |

Indexes: `idx_inventory_tenant_asset`, `idx_inventory_sbom_upload`, `idx_inventory_software_identity`, `idx_inventory_component_digest`, `idx_inventory_coord_key_tenant`, `idx_inventory_norm_purl_tenant`.

---

### `inventory_component_cpe_map`

Maps each inventory component to one or more CPE dimension rows (drives CPE-based correlation).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `component_id` | `uuid` | FK → `inventory_components(id)` |
| `cpe_id` | `uuid` | FK → `platform.cpe_dim(id)` |
| `tenant_id` | `uuid` | FK |
| `observed_version` | `varchar(255)` | |
| `first_seen_at` / `last_seen_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, component_id, cpe_id)`. Indexes: `idx_iccm_tenant_cpe`, `idx_iccm_tenant_component`.

---

### `component_vulnerability_states`

**Central correlation truth table.** One row per `(component, vulnerability)` pair per tenant.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `component_id` | `uuid` | FK → `inventory_components(id)` |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `applicability_state` | `varchar(40)` | NOT NULL |
| `applicability_reason` / `applicability_reason_detail` | text | |
| `impact_state` | `varchar(40)` | NOT NULL |
| `impact_reason` / `impact_reason_detail` | text | |
| `eligible_for_finding` | `boolean` | NOT NULL |
| `confidence_score` | `double precision` | |
| `matched_by` | `varchar(120)` | |
| `matched_vex_assertion_id` | `uuid` | |
| `vex_status` / `vex_freshness` / `vex_provider` / `vex_source` | `varchar(*)` | |
| `vex_target_id` | `uuid` | |
| `analyst_disposition` | `varchar(40)` | |
| `analyst_reason` | `text` | |
| `analyst_updated_at` / `analyst_updated_by` | various | |
| `precedence_reason` | `varchar(120)` | |
| `trace_json` | `text` | |
| `last_evaluated_at` / `state_changed_at` | `timestamptz` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, component_id, vulnerability_id)`. Indexes: `idx_comp_vuln_state_tenant_component_vuln`, `idx_comp_vuln_state_tenant_applicability`, `idx_comp_vuln_state_tenant_eligible`, `idx_comp_vuln_state_tenant_impact`.

---

### `findings`

Analyst-visible finding records. One row per `(component, vulnerability)` pair that passes eligibility.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `asset_id` | `uuid` | FK → `assets(id)`; nullable as of V44 — a finding may link a component without a resolved asset |
| `component_id` | `uuid` | FK → `inventory_components(id)`; nullable as of V44 — supports findings linked directly to an asset with no component |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `display_id` | `varchar(16)` | NOT NULL (e.g. `F-001234`) |
| `status` | `varchar(255)` | CHECK IN (`OPEN`, `RESOLVED`, `SUPPRESSED`, `AUTO_CLOSED`) |
| `decision_state` | `varchar(255)` | NOT NULL |
| `creation_source` | `varchar(255)` | CHECK IN (`MANUAL`, `AUTOMATIC`) |
| `matched_by` | `varchar(255)` | NOT NULL |
| `confidence_score` | `double precision` | |
| `risk_score` | `double precision` | NOT NULL |
| `severity_override` | `varchar(16)` | |
| `due_at` | `timestamptz` | |
| `assigned_to` / `assigned_by` | `varchar(255)` | |
| `assigned_at` | `timestamptz` | |
| `owner_group` | `varchar(255)` | |
| `evidence` | `jsonb` | |
| `first_observed_at` / `last_observed_at` | `timestamptz` | |
| `incident_id` / `incident_status` | `varchar(64)` | ServiceNow integration |
| `suppressed_by_rule_id` | `uuid` | |
| `suppressed_by_rule_name` / `suppression_reason` | various | |
| `suppressed_until` | `timestamptz` | |
| `vex_freshness` / `vex_provider` / `vex_status` | `varchar(*)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(component_id, vulnerability_id)`. Indexes: `idx_findings_tenant_status_updated`, `idx_findings_tenant_component_vuln`, `idx_findings_asset_id`, `idx_findings_vulnerability_id`, `idx_findings_vulnerability_status`.

---

### `finding_list_projection` / `finding_workspace_projection_status`

Added in V44 (tenant migration line). Legacy migrations V3/V4 had created equivalent projection tables in the shared `public` schema; V44 repairs that by giving every tenant its own schema-local, RLS-protected copy (`FORCE ROW LEVEL SECURITY` + a `tenant_isolation` policy on `tenant_id`), rebuildable from `findings` at any time. `finding_list_projection` is a flattened, index-heavy read model of open/tracked findings (severity, status, owner, SLA due date, VEX status, incident linkage) built for the Findings table UI; `finding_workspace_projection_status` tracks the last rebuild (timestamp, row counts, duration) per tenant.

| Column (`finding_list_projection`) | Type | Notes |
|---|---|---|
| `finding_id` | `uuid` | PK |
| `display_id`, `severity`, `status`, `decision_state`, `creation_source`, `match_method` | `varchar` | |
| `vex_status` / `vex_freshness` / `vex_provider` | `varchar` | |
| `confidence_score` / `risk_score` | `double precision` | `risk_score` NOT NULL |
| `vulnerability_id`, `package_name`, `ecosystem` | `varchar` | |
| `owner_group`, `assigned_to`, `incident_id`, `asset_name`, `support_group` | `varchar` | |
| `due_at`, `suppressed_until` | `timestamptz` | |
| `patch_available` | `boolean` | NOT NULL |
| `created_at` / `updated_at` / `first_observed_at` | `timestamptz` | |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |

Indexes cover `(status, due_at)`, `(assigned_to, status)`, `(owner_group, status)`, `(incident_id, status)`, `(suppressed_until, status)`, `(updated_at, finding_id)`, `(severity, status)`, `(support_group, status)`, `(patch_available, status)`.

---

### `finding_events`

Immutable audit trail for all finding state changes.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `finding_id` | `uuid` | FK → `findings(id)` |
| `event_type` | `varchar(255)` | NOT NULL |
| `summary` | `varchar(255)` | NOT NULL |
| `actor` | `varchar(255)` | NOT NULL |
| `details_json` | `jsonb` | |
| `created_at` | `timestamptz` | NOT NULL |

Index: `idx_finding_events_finding_created`.

---

### `finding_comments`

User-authored comments on findings.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `finding_id` | `uuid` | FK → `findings(id)` |
| `author` | `varchar(255)` | NOT NULL |
| `body` | `varchar(255)` | NOT NULL |
| `created_at` | `timestamptz` | NOT NULL |

---

### `finding_delta_queue`

Async work queue driving incremental finding recomputation. Drained every 2 seconds in batches of 100.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `dedupe_key` | `varchar(700)` | NOT NULL |
| `event_type` | `varchar(30)` | NOT NULL |
| `status` | `varchar(20)` | NOT NULL; DEFAULT `PENDING` |
| `tenant_id` / `component_id` / `vulnerability_id` | `uuid` | |
| `source_key` / `source_tag` | `varchar(*)` | |
| `attempt_count` / `max_attempts` | `integer` | NOT NULL; defaults 0 / 3 |
| `enqueued_at` / `visible_after` | `timestamptz` | NOT NULL; DEFAULT `now()` |
| `processing_started_at` / `completed_at` | `timestamptz` | |
| `error_message` | `text` | |

Indexes: `idx_fdq_dedupe_pending` (unique partial WHERE `status = 'PENDING'`), `idx_fdq_pending_visible` (partial WHERE `status = 'PENDING'`).

---

### `org_cve_records`

**CVE Assessment Workbench backing table.** One row per `(tenant, vulnerability)`. Backs `/vuln-repo/org-cves`.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `external_id` | `varchar(255)` | NOT NULL |
| `applicability_state` | `varchar(255)` | CHECK IN (`APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`) |
| `impact_state` | `varchar(255)` | |
| `org_impact` | `varchar(255)` | CHECK IN (`NONE`, `LOW`, `MEDIUM`, `HIGH`) |
| `impacted` | `boolean` | NOT NULL |
| `cvss_score` / `epss_score` | `double precision` | |
| `severity` | `varchar(255)` | NOT NULL |
| `in_kev` | `boolean` | NOT NULL |
| `matched_asset_count` / `matched_component_count` / `matched_software_count` | `bigint` | NOT NULL |
| `applicable_component_count` / `impacted_component_count` / `fixed_component_count` | `bigint` | NOT NULL |
| `not_affected_component_count` / `under_investigation_component_count` / `unknown_component_count` / `no_patch_component_count` | `bigint` | NOT NULL |
| `eol_component_count` / `eos_component_count` | `bigint` | NOT NULL |
| `suppressed_at` | `timestamptz` | |
| `suppressed_by` / `suppressed_by_rule_id` / `suppressed_by_rule_name` | various | |
| `suppressed_until` / `suppression_reason` | various | |
| `last_evaluated_at` | `timestamptz` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, vulnerability_id)`. Indexes: `idx_org_cve_record_tenant_applicability`, `idx_org_cve_record_tenant_external_id`, `idx_org_cve_record_tenant_impacted`, `idx_org_cve_record_tenant_vulnerability`.

---

### `org_cve_ai_artifacts`

Persisted AI-generated outputs for a CVE record.

| Column | Type | Notes |
|---|---|---|
| `org_cve_record_id` | `uuid` | PK; FK → `org_cve_records(id)` |
| `ai_actions_json` | `jsonb` | |
| `ai_actions_generated_at` | `timestamptz` | |
| `ai_solution_json` | `jsonb` | |
| `ai_solution_generated_at` | `timestamptz` | |
| `investigation_summary_output_json` / `investigation_summary_input_json` | `jsonb` | |
| `investigation_summary_mode` | `varchar(255)` | |
| `investigation_summary_generated_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `risk_policies`

One row per tenant. Controls finding generation mode, SLA, auto-close, triage weights, and custom scoring.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK; unique |
| `finding_generation_mode` | `varchar(20)` | CHECK IN (`AUTO`, `MANUAL`) |
| `critical_threshold` / `high_threshold` | `double precision` | NOT NULL |
| `critical_sla_days` / `high_sla_days` / `medium_sla_days` / `low_sla_days` | `integer` | NOT NULL |
| `asset_critical_sla_multiplier` / `asset_high_sla_multiplier` / `asset_medium_sla_multiplier` / `asset_low_sla_multiplier` | `double precision` | NOT NULL |
| `auto_close_enabled` | `boolean` | NOT NULL |
| `auto_close_after_days` | `integer` | NOT NULL |
| `auto_close_asset_identifier` | `varchar(255)` | |
| `findings_score_config` | `jsonb` | Custom attribute-based scoring rules |
| `updated_at` | `timestamptz` | NOT NULL |

---

### `suppression_rules`

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `name` | `varchar(255)` | NOT NULL |
| `record_type` | `varchar(255)` | CHECK IN (`CVE`, `FINDING`) |
| `state` | `varchar(255)` | CHECK IN (`DRAFT`, `APPROVED`, `IN_REVIEW`, `REJECTED`, `EXPIRED`) |
| `condition_logic` | `varchar(255)` | NOT NULL |
| `conditions_json` | `jsonb` | NOT NULL |
| `reason` | `varchar(255)` | |
| `valid_from` / `valid_to` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `ownership_rules`

Rule-based finding ownership assignment.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `name` | `varchar(255)` | NOT NULL |
| `user_group` | `varchar(255)` | NOT NULL |
| `condition_json` | `text` | NOT NULL |
| `execution_order` | `integer` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `vulnerability_source_filter_configs`

Per-tenant, per-source configuration for which feeds participate in correlation.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `source_system` | `varchar(255)` | NOT NULL |
| `enabled_for_correlation` | `boolean` | NOT NULL |
| `filters_json` | `text` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, source_system)`.

---

### `aws_discovery_configs` / `aws_discovery_targets`

AWS EC2 discovery connector configuration and multi-account targets.

`aws_discovery_configs`: one row per tenant. Fields include `auth_type` (CHECK IN `INSTANCE_METADATA`, `ACCESS_KEY`, `CROSS_ACCOUNT_ROLE`), `aws_account_id`, `access_key_id`, `credential_secret` (encrypted), `cross_account_role_arn`, `external_id`, `regions_json`, `resource_types_json`, `enabled`, `auto_sync_enabled`, `interval_minutes`.

`aws_discovery_targets`: sub-entries per config for multi-account discovery. Fields include `account_id`, `account_name`, `role_arn`, `external_id`, `regions_json`, `resource_types_json`, `enabled`.

---

### `azure_discovery_configs` / `azure_discovery_targets`

Azure cloud discovery connector configuration and multi-subscription targets. Added in V40/V41 — mirrors the AWS discovery tables; newer and less exercised in production.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |
| `source_system` | `varchar(80)` | NOT NULL; default `'azure'` |
| `auth_type` | `varchar(32)` | NOT NULL; CHECK IN (`CLIENT_SECRET`, `MANAGED_IDENTITY`) |
| `azure_tenant_id` | `varchar(128)` | Azure AD tenant ID |
| `client_id` | `varchar(255)` | Service principal client ID |
| `client_secret` | `text` | Encrypted service principal secret |
| `subscription_ids_json` | `text` | NOT NULL; default `'[]'` |
| `regions_json` | `text` | NOT NULL; default `'["eastus2"]'` |
| `enabled` / `auto_sync_enabled` | `boolean` | NOT NULL |
| `interval_minutes` | `integer` | NOT NULL; default `1440` |
| `last_test_status` / `last_test_message` | various | |
| `last_tested_at` / `last_sync_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

`azure_discovery_targets`: per-subscription sub-entries. Fields: `config_id` (FK), `subscription_id`, `subscription_name`, `enabled`, `regions_json`, `last_test_status`/`message`/`tested_at`, `last_sync_at`.

Unique: `azure_discovery_configs(tenant_id, source_system)`; `azure_discovery_targets(config_id, subscription_id)`.

---

### `sccm_cmdb_configs`

SCCM/MECM CMDB connector configuration.

Fields: `auth_type` (CHECK IN `SQL_AUTH`, `WINDOWS_AUTH`), `database_name`, `jdbc_url`, `username`, `credential_secret` (encrypted), `site_code`, `fetch_size`, `interval_minutes`, `query_timeout_seconds`, `enabled`, `auto_sync_enabled`, `mock_mode`.

---

### `servicenow_cmdb_configs`

ServiceNow CMDB connector configuration.

Fields: `auth_type` (CHECK IN `BASIC`, `BEARER`), `base_url`, `username`, `credential_secret` (encrypted), `ci_table`, `discovery_model_table`, `install_table`, `discovery_fields`, `install_fields`, `discovery_query`, `install_query`, `page_size`, `interval_minutes`, `enabled`, `auto_sync_enabled`.

---

### `github_sbom_sources`

Scheduled GitHub SBOM ingestion jobs.

Fields: `name`, `owner`, `repo`, `path`, `asset_identifier`, `asset_name`, `asset_type`, `frequency`, `interval_minutes`, `enabled`, `last_run_at`, `last_run_status`, `last_error`.

---

### `cis` / `ci_aliases`

`cis`: Configuration Items synced from ServiceNow CMDB. FK → `assets(id)`. Fields include `sys_id` (unique with `tenant_id`), `display_name`, `business_criticality`, `environment`, CMDB sync timestamps.

`ci_aliases`: Alternative names for a CI. Unique: `(tenant_id, normalized_alias_name, source_system)`.

---

### `software_instances`

Software installed on a CI (from ServiceNow/SCCM discovery). Links CI → SoftwareIdentity → InventoryComponent.

---

### `software_identity_metadata`

Custom per-tenant metadata attached to a software identity (owner, licensing, support group, recommendation). Added in V39.

| Column | Type | Notes |
|---|---|---|
| `tenant_id` | `uuid` | NOT NULL; part of composite PK; FK → `platform.tenants(id)` |
| `software_identity_id` | `uuid` | NOT NULL; part of composite PK; FK → `platform.software_identities(id)` |
| `owner` | `text` | Software owner/team |
| `licensed` | `text` | NOT NULL; default `'Unknown'` |
| `license_type` | `text` | e.g. `MIT`, `Commercial` |
| `support_group` | `text` | Internal support/SRE group |
| `recommendation` | `text` | Custom recommendation text |
| `recommendation_updated_at` | `timestamptz` | |
| `updated_at` | `timestamptz` | NOT NULL |

PK: `(tenant_id, software_identity_id)`.

---

### `discovery_models`

Software discovery model records from SCCM/ServiceNow. Fields: `primary_key` (unique with `tenant_id`), `normalized_product` / `publisher` / `version`, `ml_model_version`, `normalization_status`, `product_hash` / `version_hash`, `approved`.

---

### `software_inventory_items`

Flattened inventory view for reporting. One row per unique component per asset. Fields: `purl`, `package_name`, `version`, `ecosystem`, `component_status`, `first_seen_at`, `last_observed_at`, `synced_at`.

---

### `sync_runs`

Audit log for all sync job executions.

Fields: `sync_type`, `run_scope`, `status`, `records_fetched` / `inserted` / `updated` / `failed`, `started_at`, `completed_at`, `error_message`, `metadata_json`. Moved to the `platform` schema in a later migration (`move_sync_runs_to_platform`) — despite living alongside tenant tables in this doc for grouping purposes, confirm current schema location before writing cross-schema queries.

---

### `ingestion_jobs`

Tracks asynchronous ingestion job status (SBOM uploads, config imports, asset discovery runs). Backs `IngestionJobController` (`/api/ingestion-jobs`).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |
| `job_type` | `varchar(80)` | NOT NULL; e.g. `SBOM_INGESTION`, `CONFIG_IMPORT` |
| `source_type` | `varchar(80)` | NOT NULL; e.g. `GITHUB`, `ARTIFACTORY` |
| `asset_identifier` | `varchar(500)` | NOT NULL |
| `status` | `varchar(32)` | NOT NULL; CHECK IN (`QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`) |
| `requested_by` | `varchar(255)` | |
| `requested_at` / `started_at` / `completed_at` | `timestamptz` | |
| `attempt_count` | `integer` | NOT NULL; default `0` |
| `dedupe_key` | `varchar(700)` | NOT NULL |
| `payload_json` / `result_json` | `text` | |
| `failure_code` / `failure_message` | various | |
| `visible_at` | `timestamptz` | NOT NULL; default `now()` |
| `sbom_upload_id` | `uuid` | FK → `sbom_uploads(id)` if SBOM-related |

Unique (partial): `dedupe_key` WHERE `status IN ('QUEUED','RUNNING')`. Indexes: `(status, visible_at, id)`, `(requested_at DESC, id DESC)`, `(asset_identifier, status)`.

---

### `service_accounts`

API service accounts scoped to a tenant.

Fields: `key_id` (unique), `name`, `role`, `status`, `last_used_at`.

---

### `audit_events`

Platform-wide audit log. Every security-relevant action appended here.

Fields: `actor_user_id`, `occurred_at`, `actor_subject`, `actor_role`, `action`, `target_type`, `target_id`, `request_id`, `source_ip`, `outcome`, `details_json` (jsonb).

---

### `fix_records`

AI-generated or analyst-authored remediation recommendations for a CVE.

Fields: `cve_id`, `fix_type`, `recommendation_source`, `summary`, `description`, `os_hint`, `related_cve_ids` / `software_entities` / `source_urls` (jsonb), `generated_at`.

---

### Remediation Campaigns

Backs `CampaignController` (`/api/campaigns`) and the `/vuln-repo/campaigns` frontend. Not covered in earlier drafts of this doc.

**`campaigns`** — one row per campaign. Fields: `tenant_id`, `name`, `summary`, `status` (DRAFT/ACTIVE/PAUSED/BLOCKED/IN_REVIEW/CLOSED/CANCELLED), `created_by`, `due_at`, `started_at`, `paused_at`, `closed_at`, `created_at`/`updated_at`. Index: `(tenant_id, status, updated_at DESC)`.

**`campaign_vulnerabilities`** — CVEs linked to a campaign. FK `campaign_id` → `campaigns(id)` ON DELETE CASCADE, FK `vulnerability_id` → `platform.vulnerabilities(id)`, `external_id`, `title`, `severity` snapshot. Unique: `(campaign_id, external_id)`.

**`campaign_exceptions`** — per-finding/asset exception requests within a campaign. Fields: `campaign_id` (FK, cascade), `finding_display_id`, `asset_name`, `package_name`, `title`, `reason`, `status` (PENDING/APPROVED/REJECTED), `requested_by`/`requested_at`, `decision_due_at`, `decisioned_by`/`decisioned_at`.

**`campaign_notify_groups`** — notification subscriptions. Fields: `campaign_id` (FK, cascade), `group_name`, `role_label`, `trigger_summary`, `group_email`, `notifications_paused`.

**`campaign_watchlist_entries`** — manual watchlist subscribers. Fields: `campaign_id` (FK, cascade), `entry_type` (INDIVIDUAL/GROUP/POLICY), `label`, `email`, `trigger_policy`, `active`.

**`campaign_notes`** — free-form discussion notes. Fields: `campaign_id` (FK, cascade), `author`, `body`, `created_at`.

**`campaign_activities`** — system-generated activity log. Fields: `campaign_id` (FK, cascade), `activity_type`, `actor`, `body`, `metadata_json`, `created_at`.

**`campaign_delivery_attempts`** — notification delivery audit log. Fields: `campaign_id` (FK, cascade), `target_type`, `target_label`/`target_address`, `subject`, `delivery_state` (QUEUED/SENT/FAILED/BOUNCED), `provider_message_id`, `detail`.

---

### BOM / CBOM

Backs `BomController` (`/api/bom`) and `CbomController` (`/api/bom/cbom`). Not covered in earlier drafts of this doc.

**`bom_ingestion_records`** — one row per ingested BOM document. Key fields: `tenant_id`, `sbom_upload_id`/`asset_id` (optional links), `bom_type` (SBOM/CBOM/HBOM), `format`/`format_version`/`spec_family`, `serial_number`, `supplier`, `source_type` (URL/UPLOAD/API)/`source_system`/`source_reference`, `component_count`, `status` (ACTIVE/SUPERSEDED/ARCHIVED), `superseded_by`/`previous_bom_id` (self-referencing), `checksum_sha256`, `ingested_at`/`ingested_by`. Indexes on `(tenant_id, bom_type, status)`, `(tenant_id, ingested_at DESC)`, `(tenant_id, source_system)`.

**`bom_components`** — components extracted from a BOM. Fields: `bom_id` (FK), `tenant_id`, `name`/`version`/`purl`/`cpe`/`license`/`supplier`, `component_type`, `category` (MATCHED/UNMATCHED), `is_active`, `bom_ref`, `group_name`, `hashes`/`properties`/`external_references` (jsonb), `workflow_status` (DISCOVERED/INVESTIGATING/RESOLVED). Indexes on `purl` and `cpe` (partial, WHERE NOT NULL).

**`bom_component_evidence`** — provenance for a component's presence. Fields: `bom_component_id`/`bom_id` (FK, cascade), `evidence_type` (MANIFEST/SCAN/DECLARATION), `evidence_key`/`evidence_value`, `source_system`/`source_reference`.

**`bom_component_vulnerability_links`** — matches a BOM component to a known vulnerability. Fields: `bom_component_id`/`bom_id` (FK, cascade), `vulnerability_key` (CVE/GHSA ID), `vulnerability_source`, `relation_type`, `match_source`, `match_confidence` (0–100), `direct_match`, `correlation_evidence_json`.

**`bom_component_workflows`** — remediation/investigation workflow per component-vulnerability pair. Fields: `bom_component_id`/`vulnerability_link_id` (FK, cascade), `workflow_type` (INVESTIGATION/REMEDIATION), `workflow_status` (DISCOVERED/IN_PROGRESS/RESOLVED/REJECTED), `workflow_reason`, `investigation_key`, `finding_id`, `started_at`/`updated_at`/`closed_at`.

---

### Read-Model Projections (Tenant Schema)

| Table | Purpose |
|---|---|
| `software_identity_summary` | Per-identity aggregation (asset/component/version counts, EOL breakdown) — backs Software Identities view |
| `quality_issue_projection` | Data quality issues by domain/severity — backs Operations Quality view |
| `dashboard_noise_reduction_projection` | Single-row-per-tenant CVE noise reduction counts |
| `software_identity_cluster_link` | Bulk normalization override links (source_type + source_key → canonical identity) |

---

### `applicability_assessments`

Manual applicability assessment records attached to a CVE. Fields include `vulnerability_id`, `status`, `final_result`, `assessed_by`, `detection_method`, `confidence_level`, `software_detected`, `vulnerable_version_present`, `current_version`, `fixed_version`, `justification`, `completed_at`.

---

### `investigations` / `investigation_activities` / `investigation_attachments`

Investigation lifecycle for a CVE within a tenant. Activities are append-only event log entries. Attachments reference `storage_path` for uploaded files.

---

### `demo_requests` / `demo_invites`

`demo_requests`: public demo access requests. Fields: company, email, full_name, company_size, role_title, use_case, notes, status, decided_at/by, rejection_reason, tenant_id.

`demo_invites`: unique token (96 chars), email, status, expires_at, accepted_at, last_sent_at, request_id FK, tenant_id FK.

---

## Migration Conventions

- File pattern: `V{next}__short_snake_case.sql` in `backend/src/main/resources/db/migration/postgres_reset/` (platform line) or `backend/src/main/resources/db/migration/tenant/` (per-tenant line — see below)
- **Never edit an already-applied migration file.** Add a new migration instead. The one existing exception: `V14__github_sbom_source_token.sql` and `V23__default_risk_policy_presets.sql` were later edited to be schema-qualified/search-path-independent, a correctness fix required once tenant migrations stopped implicitly inheriting the request's `search_path` — a deliberate, reviewed exception for a search-path-safety bug, not precedent for editing applied migrations generally.
- All DDL uses `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` — idempotent when replayed via psql.
- `flyway.validate-on-migrate: true` in all profiles; `out-of-order: false`.
- `flyway.baseline-on-migrate: true` only in the `local` profile; `false` in production.

To repair Flyway history after schema drift:
```bash
cd backend
mvn -q \
  -Dflyway.url=jdbc:postgresql://localhost:5432/vulnwatch \
  -Dflyway.user="$USER" \
  -Dflyway.password= \
  -Dflyway.schemas=tenant_default \
  -Dflyway.locations=filesystem:src/main/resources/db/migration/postgres_reset \
  flyway:repair
```

`-Dflyway.schemas=tenant_default` is required — `flyway_schema_history` lives in `tenant_default`, not `public`. Omitting it silently repairs the wrong table.

---

## Tenant Schema Control Plane

As of V42, there are **two independent Flyway migration lines**, never applied by the same Flyway instance:

| Line | Location | Applies to | History table | Notes |
|---|---|---|---|---|
| Platform/reset | `postgres_reset/` | `public` schema only (plus the `tenant_default` template, which lives under `public` for baselining purposes) | `public.flyway_schema_history` | Each file must open with a `-- migration-guard: platform-only` comment; `PostgresResetMigrationGuardTest` enforces this so tenant-schema DDL can't leak into the shared line by accident. |
| Tenant | `tenant/` | Every tenant schema (`tenant_default` and each `tenant_<id>`), one Flyway run per schema | `<schema>.tenant_schema_history` | Files may reference `${tenantId}` / `${tenantSchema}` Flyway placeholders, validated by `TenantSchemaMigrationService`/`ProductionBootstrapCli` before substitution. Baselined at version 41 (the version at which the tenant line was split out) so pre-existing tenant schemas don't try to replay history that predates the split. |

Current latest: `postgres_reset/V45__tenant_access_membership_provenance.sql` and `tenant/V44__tenant_finding_workspace_projection.sql`.

**Rollout mechanics** (`TenantSchemaMigrationService.migrateAll()`, mirrored by `ProductionBootstrapCli` for the standalone production bootstrap path):
1. Hold a Postgres advisory lock (`scout-tenant-schema-migrator` / `scout-production-bootstrap`, 30s timeout) so only one migration run proceeds at a time.
2. Migrate the `tenant_default` template schema first and compute its **structural fingerprint** — a SHA-256 hash over a normalized, schema-name-and-tenant-id-scrubbed dump of every column, constraint, index, sequence, and RLS policy definition (`information_schema` + `pg_catalog` introspection).
3. Migrate one canary tenant, then remaining tenants in batches of 10; each tenant's post-migration fingerprint is compared against the template's — any mismatch fails that tenant as `DRIFTED` and halts the batch rather than silently diverging.
4. Every step (start, success, failure) is recorded to `platform.tenant_schema_versions` via `TenantSchemaStatusService`, which also serves `GET /api/platform/tenant-schema-status` (backing the Platform Console's tenant schema status view) and `TenantSchemaReadinessHealthIndicator` (an actuator health contributor gated behind `app.tenancy.enforce-schema-version=true`, `/actuator/health` reports `DOWN` if any `ACTIVE` tenant is below `app.tenancy.minimum-compatible-schema-version`, default 44).
5. A `report-only` mode (`reportOnly=true` / `BOOTSTRAP_REPORT_ONLY=true`) runs the same fingerprint comparison read-only, for verifying a restored production clone before committing to a real migration.

**RLS enforcement is driven from the tenant line, not the platform line.** `tenant/V42__enforce_tenant_rls.sql` runs once per tenant schema (via the rollout above) and, for every table in that schema: adds a `tenant_id` column if missing (backfilled to the tenant's own id, `NOT NULL` with a per-tenant default), fails loudly if it finds rows with a *conflicting* `tenant_id`, and enables `FORCE ROW LEVEL SECURITY` with a `tenant_isolation` policy pinned to `app.current_tenant_id`. `tenant/V43__repair_tenant_id_nullability.sql` and `tenant/V44__tenant_finding_workspace_projection.sql` carry follow-up fixes (e.g. `demo_requests` and `audit_events` are explicitly exempted/given nullable-tenant policies because they hold pre-tenant-existence rows). This is the mechanism referenced by "RLS rollout status" in `architecture.md` — `V29__tenant_rls_rollout_gate.sql` (platform line) remains the pre-flight gate confirming the runtime DB role is non-superuser/non-BYPASSRLS before this per-tenant enforcement is allowed to run in production.

**Standalone production bootstrap:** `ProductionBootstrapCli` (`com.prototype.vulnwatch.migration`) is a `main()` entry point that does **not** start Spring/JPA — it runs platform migrations, reconciles the platform-owner identity, registers/migrates the default tenant, migrates all other tenants (canary + batches of 10, drift-checked the same way), provisions/rotates the least-privilege `scout_runtime` Postgres role, verifies the full control-plane invariants (RLS coverage, role privileges, no unsafe attributes, DDL actually denied at runtime), and optionally emails a platform-owner password-setup link via Resend. See `docs/p0-production-runbook.md` for the operational procedure and `backend/scripts/run-render-migration.sh` / `backend/scripts/provision-runtime-role.sql` for the scripts that wrap it in a temporary Render deploy.

---

## Connection Pool (HikariCP)

| Parameter | Default | Production override |
|---|---|---|
| `maximum-pool-size` | 20 | `${DB_MAX_POOL_SIZE:30}` |
| `minimum-idle` | 5 | `${DB_MIN_IDLE:5}` |
| `connection-timeout` | 30,000 ms | |
| `idle-timeout` | 600,000 ms | |
| `max-lifetime` | 1,800,000 ms | |

---

## Dashboard Cache (Caffeine)

- **Cache name:** `dashboard`
- **Maximum size:** 100 entries
- **TTL:** 60 seconds after write (`expireAfterWrite=60s`)
