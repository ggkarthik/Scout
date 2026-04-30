# VulnWatch Database

Last updated: 2026-04-29

The runtime database is PostgreSQL, with Flyway-managed migrations under `backend/src/main/resources/db/migration/postgres`. H2 is retained only as an offline archive format for legacy data snapshots.

## Engine

- Runtime: PostgreSQL at `jdbc:postgresql://localhost:5432/vulnwatch`
- Schema strategy: Flyway-owned PostgreSQL migrations with `ddl-auto=none`

## Tenant Model

The schema is tenant-aware even though the current runtime mostly uses one default tenant.

Tenant-scoped tables include:

- `assets`
- `sbom_uploads`
- `inventory_components`
- `inventory_component_cpe_map`
- `software_inventory_items`
- `component_vulnerability_states`
- `org_cve_records`
- `findings`
- `risk_policies`
- `audit_events` for tenant-visible administration, tenant exposure refresh usage counting, and workflow audit trails

Global or mostly global intelligence tables include:

- `vulnerabilities`
- `vulnerability_intel_observations`
- `vulnerability_intel_summary`
- `vulnerability_intel_summary_sources`
- `vulnerability_targets`
- `vulnerability_rules`
- `vulnerability_config_expr`

Identity and administration tables include:

- `app_users`
- `tenant_memberships`
- `service_accounts`
- tenant lifecycle metadata on `tenants`

## Major Table Groups

### Inventory and Identity

- `tenants`
  - production lifecycle fields include slug, status, plan code, billing reference, suspension/deletion timestamps, quota limits, and updated timestamp
- `app_users`
  - one row per authenticated external subject
- `tenant_memberships`
  - maps users to tenants and roles
- `service_accounts`
  - tenant-scoped machine identities for automation and future API access
- `assets`
  - unique key on `(tenant_id, identifier)`
  - stores asset type, owner metadata, and lifecycle state
- `sbom_uploads`
  - immutable ingestion evidence and counts
- `inventory_components`
  - tenant asset components, active/retired lifecycle, normalized package fields
- `software_identities`
  - canonical normalized software product records; extended by V1030 with `vendor`, `product`, `product_hash`, `purl`, `cpe23`, `vendor_product_id` columns for deterministic CMDB-to-CPE linkage
- `software_identifiers`
- `identity_links`
  - extended by V1030 with `source_type`, `source_id`, `target_type`, `target_id`, `match_rule`, `last_seen_at` for flexible cross-domain identity resolution
- `software_inventory_items`
  - flattened software inventory projection used by read/reporting paths

### Host Inventory (CMDB)

Added by V1030–V1033:

- `cis`
  - one row per CMDB Configuration Item per tenant; links to `assets`
  - stores `sys_id`, `display_name`, `business_criticality`, `environment`, `owner_email`, and sync timestamps
  - unique index on `(tenant_id, sys_id)`
- `ci_aliases`
  - hostname/FQDN variants for a CI; supports fuzzy host resolution
  - stores `alias_name` and `normalized_alias_name`
- `discovery_models`
  - normalized software product metadata rows from `cmdb_sam_sw_discovery_model`
  - stores `primary_key`, `normalized_product`, `normalized_publisher`, `product_hash`, `version_hash`, `platform`, `normalization_status`
- `software_instances`
  - one row per installed software per CI
  - links `ci_id` and `software_identity_id`
  - stores install date, last scanned, last used, active/unlicensed flags
- `servicenow_cmdb_configs`
  - one config row per `(tenant_id, source_system)`
  - stores `base_url`, `auth_type`, credential secret (encrypted at rest), table names, field selection overrides, `page_size`, `enabled`, `auto_sync_enabled`, `interval_minutes`, and last test status/timestamp

### Correlation Inputs

- `cpe_dim`
  - canonical normalized CPE dimension
- `inventory_component_cpe_map`
  - bridge from component to normalized CPE
- `vulnerability_targets`
  - normalized target rows with version bounds, qualifiers, and optional `cpe_id`
- `vulnerability_rules`
- `vulnerability_config_expr`

### Vulnerability Intelligence

- `vulnerabilities`
  - canonical vulnerability record keyed by `external_id`
  - stores severity, CVSS, EPSS, KEV, title, snippet, archive keys, timestamps
- `vulnerability_intel_observations`
  - source-specific raw observations
- `vulnerability_intel_summary`
  - list/read-model projection
- `vulnerability_intel_summary_sources`
  - projected source list per summary row

### Exposure and Findings

- `component_vulnerability_states`
  - component-level applicability and impact projection
  - stores matched method, selected target source, VEX fields, confidence, eligibility, and trace JSON
- `org_cve_records`
  - tenant-level rollup for one row per CVE per tenant
  - stores applicability, impact state, matched component count, and software count
- `findings`
  - tenant-scoped workflow records
  - unique key on `(component_id, vulnerability_id)`
- `finding_events`
- `finding_comments`
- `risk_policies`

### End-of-Life Tracking

Added by V1034–V1042:

- `eol_product_catalog`
  - one row per endoflife.date product slug
  - stores `slug`, `display_name`, `cpe_vendor`, `cpe_product`, `purl_type`, `purl_namespace`, `aliases`, `last_modified`, `last_fetched_at`
  - unique index on `slug`
- `eol_releases`
  - one row per release cycle per product slug
  - stores `product_slug`, `cycle`, `release_date`, `eol_date`, `eol_boolean`, `support_end_date`, `extended_support_date`, `security_support_date`, `latest_version`, `latest_release_date`, `lts`, `is_eol`, `eoas`, `eoes`, `discontinued`, `official_source_url`, `support_phase`
  - unique index on `(product_slug, cycle)`
- `software_eol_mapping`
  - maps a `software_identity_id` (or `normalized_key` string) to an EOL slug
  - stores `normalized_key`, `eol_slug`, `match_confidence`, `match_method`, `confirmed`, `software_identity_id`
  - `confirmed = true` for analyst-reviewed mappings; `match_method = MANUAL` for those set via the UI

EOL denormalized columns added to `inventory_components` and `software_instances` (V1036, V1038–V1041):
- `eol_slug`, `eol_cycle`, `eol_date`, `is_eol`, `eol_support_end_date`, `support_phase`, `latest_supported_version`, `eol_checked_at`

EOL summary columns added to `org_cve_records` (V1040):
- `eol_component_count`, `eos_component_count`

### Operational and Workflow Support

- `finding_delta_queue`
  - durable background projection queue for workbench freshness
  - stores `event_type`, tenant/component/vulnerability scope, source metadata, dedupe key, retry state, visibility timestamps, completion timestamps, and failure text

## Production Isolation Controls

`APP_REQUIRE_TENANT_CONTEXT=true` hardens the tenant-aware datasource for production. When a request or worker path reaches the normal datasource without a resolved tenant, the datasource sets `app.current_tenant_id` to `00000000-0000-0000-0000-000000000000`. Existing tenant-scoped RLS policies then match no tenant rows instead of using the legacy unset-tenant fallback.

The platform still needs deliberate cross-tenant paths for administration and feed maintenance. Those should use a separate platform datasource or job role rather than the normal request datasource.
  - active event types are `SOFTWARE_DELTA`, `CVE_DELTA`, `CVE_METADATA_DELTA`, `VEX_DELTA`, `LIFECYCLE_DELTA`, and `NOISE_REDUCTION_REFRESH`
- `sync_runs`
  - extended by V1029 with `metadata_json` for structured run metrics
  - `run_domain` column distinguishes `INVENTORY` runs (ServiceNow CMDB, GitHub SBOM/GHCR) from `VULNERABILITY` runs (NVD, KEV, GHSA, CSAF/VEX)
- `github_sbom_sources`
- `investigations`
- `investigation_activities`
- `investigation_attachments`
- `applicability_assessments`

### Read-Model Projections (V1043–V1045)

Added to support the Software Identities inventory view and the Operations Quality dashboard:

- `software_identity_summary` (V1043)
  - one row per `(tenant_id, software_identity_id)`
  - stores `display_name`, `canonical_key`, `vendor`, `product`, `normalized_key`, `purl`, `cpe23`
  - aggregates: `asset_count`, `component_count`, `version_count`, `eol_component_count`, `near_eol_component_count`, `unknown_eol_component_count`
  - EOL fields: `eol_slug`, `mapping_confirmed`, `needs_eol_mapping`, `last_observed_at`, `summary_updated_at`
  - `asset_types`, `ecosystems`, `source_systems` (arrays) for filtering
  - indexes on `(tenant_id, component_count DESC)`, `(tenant_id, needs_eol_mapping)`, EOL lifecycle counts, and `normalized_key`

- `quality_issue_projection` (V1044)
  - one row per `(tenant_id, issue_key)` — deterministic keying allows upsert on recompute
  - stores `domain`, `issue_type`, `severity`, `reason_code`, `source_object_type`
  - cross-domain foreign references: `asset_id`, `component_id`, `software_identity_id`, `vulnerability_id`, `sync_run_id`
  - labels: `title`, `primary_label`, `secondary_label`
  - filter facets: `asset_type`, `source_system`, `ecosystem`
  - impact counts: `affects_active_findings`, `affected_asset_count`, `affected_component_count`, `open_finding_count`, `open_vulnerability_count`
  - structured payloads: `evidence_json`, `drilldown_json`
  - timestamps: `first_seen_at`, `last_seen_at`, `last_computed_at`
  - indexes on domain+severity, filter facets, and cross-domain reference columns

- `dashboard_noise_reduction_projection` (V1045)
  - one row per tenant
  - stores `never_opened_not_applicable`, `deferred_under_investigation`, `category_counts_json`, and `last_computed_at`
  - powers the executive dashboard noise-reduction widget without re-running correlation logic on read

### Schema Evolution V1046–V1072

The current Flyway watermark is **V1072** (`tenant_exposure_refresh_quota`). The next migration must be `V1073__*.sql`.

New tables added in this range:

- `vulnerability_source_filter_configs` (V1046)
  - per-tenant source feed filter rules
  - stores `tenant_id`, `source_system`, `filters_json`
- `software_identity_cluster_link` (V1059)
  - cluster-level normalization overrides with audit trail
  - stores `source_type`, `source_key`, `target_identity_id`, `apply_to_future`, `reason`, `confirmed_by`, `confirmed_at`, `revoked_at`, `revoked_by`
- `sccm_cmdb_configs` (V1060)
  - SCCM/MECM CMDB connector configuration
  - stores `jdbc_url`, `auth_type`, `credential_secret`, `site_code`, `database_name`, `fetch_size`, `query_timeout_seconds`, `mock_mode`, scheduling fields, last test status, and `last_sync_at` (V1062)
- `aws_discovery_configs` (V1063)
  - AWS Cloud Discovery connector settings
  - stores `auth_type`, `access_key_id`, `credential_secret`, `cross_account_role_arn`, `external_id`, `aws_account_id`, `regions_json`, `resource_types_json`, scope fields, scheduling, and last sync status
- `aws_discovery_targets` (V1067)
  - cross-account / multi-region AWS discovery targets
  - paired with an `ssm_readiness` column on `assets` for SSM-based EC2 discovery health
- `app_users` (V1070)
  - first-class user identity table backing `tenant_memberships`
  - stores external subject, email, display name, status, and lifecycle timestamps

New columns added in this range, grouped by target table:

- **`org_cve_records`** — V1047 added `investigation_summary_input_json`, `investigation_summary_output_json`, `investigation_summary_mode`, `investigation_summary_generated_at`. V1052 added `ai_solution_json`, `ai_solution_generated_at`. V1053 added `ai_actions_json`, `ai_actions_generated_at`. These power the AI investigation summary, AI solution, and AI actions panels in the workbench (gated by `OPENAI_ENABLED`).
- **`findings`** — V1048 added `display_id` backed by a sequence (analyst-friendly IDs). V1054 added `incident_id` and `incident_status` (ServiceNow incident tracking).
- **`assets`** — V1049 added ServiceNow ownership fields `managed_by`, `department`, `support_group`, `assigned_to`. V1064 added cloud-asset metadata `cloud_provider`, `cloud_region`, `cloud_availability_zone`, `cloud_account_id`, `cloud_resource_type`, `cloud_instance_type`, `cloud_vpc_id`, `cloud_subnet_id`, `cloud_arn`, `cloud_tags_json`. V1067 added `ssm_readiness`.
- **`cis`** — V1049 mirrored the ServiceNow ownership fields onto CMDB CIs.
- **`vulnerabilities`** — V1050/V1051 added `kev_date_added`, `kev_due_date`, `kev_required_action`.
- **`inventory_components`** — V1056 added manual identity override fields: `manual_identity_id`, `manual_identity_reason`, `manual_identity_confirmed_by`, `manual_identity_confirmed_at`. V1058 is an idempotent backstop.
- **`software_instances`** — V1057 mirrored the manual identity override fields.
- **`software_eol_mapping`** — V1055 added `confirmed_by`, `confirmed_at`, `previous_slug`.
- **`servicenow_cmdb_configs`** — V1061 added `last_sync_at`. V1066 is an idempotent repair.
- **`tenants`** — V1070 added `slug`, `status`, `plan_code`, `billing_ref`, `suspended_at`, `deleted_at`, `updated_at`. V1071 added `max_connector_count`, `max_service_account_count`, `max_daily_sbom_uploads`, `max_export_rows` with CHECK constraints. V1072 added `max_daily_exposure_refreshes`.

Other notable migrations in this range:

- V1065 — `cloud_asset_summary` view backing the cloud-asset overview panel
- V1068 — drop AWS tag filter scope columns
- V1069 — narrow AWS discovery to EC2-only (RDS/Lambda/S3/ECS/EKS scope removed)

## Key Relationships

- `tenants` 1->N inventory, findings, org-CVE, policy, and CMDB config records
- `assets` 1->N `sbom_uploads`, `inventory_components`, `software_inventory_items`, and `findings`
- `assets` 1->1 `cis` (host assets only)
- `cis` 1->N `ci_aliases`, `software_instances`
- `software_identities` 1->N `software_instances`, `software_identifiers`, `identity_links`
- `discovery_models` resolves into `software_identities` during CMDB ingestion
- `inventory_components` 1->N `inventory_component_cpe_map`, `component_vulnerability_states`, and `findings`
- `cpe_dim` 1->N `inventory_component_cpe_map` and `vulnerability_targets`
- `vulnerabilities` 1->N `vulnerability_targets`, `vulnerability_intel_observations`, `component_vulnerability_states`, `org_cve_records`, and `findings`
- `vulnerabilities` 1->1 `vulnerability_intel_summary` via unique `vulnerability_id`

## Important Write Paths

### SBOM Ingestion

1. upsert asset and upload evidence
2. upsert component rows and retire missing components
3. maintain software identity and software inventory projections
4. normalize CPEs and bridge them to components
5. enqueue component recomputation

### Vulnerability Ingestion

1. upsert source observations
2. merge canonical vulnerability records
3. refresh vulnerability summary projections
4. upsert targets, rules, and config expressions
5. enqueue CVE-level recomputation
6. enqueue tenant-scoped noise-reduction refresh after correlation-affecting work completes

### Exposure Projection

The current backend writes two important projection tables before or alongside finding updates:

- `component_vulnerability_states` for component-level truth
- `org_cve_records` for tenant/CVE rollups

This is a major change from the older documentation set and is now the correct place to look for current applicability and org-CVE exposure state.

### EOL Pipeline

1. batch-upsert product slugs into `eol_product_catalog` (stage 1)
2. conditional fetch and upsert release cycles into `eol_releases` (stage 2)
3. in-memory slug resolution writes `software_eol_mapping` rows (stage 3)
4. set-based `UPDATE ... FROM (SELECT DISTINCT ON (...))` denormalizes EOL status onto `inventory_components` and `software_instances` (stage 4)
5. scoped `LIFECYCLE_DELTA` events refresh `org_cve_records` after denormalization instead of tenant-wide foreground rebuild
6. daily `EOL_DATE_SWEEP` updates date-driven lifecycle transitions and enqueues `LIFECYCLE_DELTA` even when no feed changed

### Workflow Operations

- investigations and applicability assessments are persisted directly from `/api/cve-detail/*`
- finding events/comments capture audit trail around status and suppression changes
- scheduled jobs mutate asset state, suppression expiry, and policy-based auto-close behavior

## Optimization and Archive Notes

The vulnerability archival work is partially realized in the active schema:

- `vulnerabilities` includes `description_snippet`, `description_archive_key`, and `raw_payload_archive_key`
- legacy columns such as expanded CVSS fields, `source_identifier`, and `vuln_status` still remain in the `Vulnerability` entity for compatibility

That means the database is still somewhat broader than a fully slimmed final form, even though PostgreSQL and Flyway now own the live runtime path cleanly.

## Cutover Validation

The backend includes a parity validator for comparing an archived H2 source snapshot with a PostgreSQL target:

```bash
cd backend
./tools/run-database-parity.sh
```

Default inputs:

- H2: `jdbc:h2:file:./data/archive/h2-archive-20260308-postgres-cutover/vulnwatch;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH`
- PostgreSQL: `jdbc:postgresql://localhost:5432/vulnwatch`
- PostgreSQL user: the current OS user

Overridable properties:

- `-Dh2.url=...`
- `-Dh2.user=...`
- `-Dh2.password=...`
- `-Dpostgres.url=...`
- `-Dpostgres.user=...`
- `-Dpostgres.password=...`
- `H2_JAR=/path/to/h2-*.jar`
- `POSTGRES_JAR=/path/to/postgresql-*.jar`

The validator is intentionally outside Maven so H2 does not remain in the normal build or test dependency graph.

## Determinism and Auditability

The data model preserves explainability rather than only final status:

- `component_vulnerability_states.trace_json` stores component-level reasoning
- `findings.evidence` and `findings.precedence_trace` preserve decision traces
- `finding_events` records workflow changes
- `sync_runs` records ingest execution history

## Current Caveats

- Flyway owns the PostgreSQL startup path and normal runtime no longer relies on startup schema mutation.
- Because schema evolution was compatibility-oriented, some tables and columns reflect transitional states rather than a clean-room final design.
