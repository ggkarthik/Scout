# VulnWatch Database

Last updated: 2026-03-15

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

Global or mostly global intelligence tables include:

- `vulnerabilities`
- `vulnerability_intel_observations`
- `vulnerability_intel_summary`
- `vulnerability_intel_summary_sources`
- `vulnerability_targets`
- `vulnerability_rules`
- `vulnerability_config_expr`

## Major Table Groups

### Inventory and Identity

- `tenants`
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
  - stores matched method, VEX fields, confidence, eligibility, and trace JSON
- `org_cve_records`
  - tenant-level rollup for one row per CVE per tenant
  - stores applicability, impact state, matched component count, and software count
- `findings`
  - tenant-scoped workflow records
  - unique key on `(component_id, vulnerability_id)`
- `finding_events`
- `finding_comments`
- `risk_policies`

### Operational and Workflow Support

- `sync_runs`
  - extended by V1029 with `metadata_json` for structured run metrics
  - `run_domain` column distinguishes `INVENTORY` runs (ServiceNow CMDB, GitHub SBOM/GHCR) from `VULNERABILITY` runs (NVD, KEV, GHSA, CSAF/VEX)
- `github_sbom_sources`
- `investigations`
- `investigation_activities`
- `investigation_attachments`
- `applicability_assessments`

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

### Exposure Projection

The current backend writes two important projection tables before or alongside finding updates:

- `component_vulnerability_states` for component-level truth
- `org_cve_records` for tenant/CVE rollups

This is a major change from the older documentation set and is now the correct place to look for current applicability and org-CVE exposure state.

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
