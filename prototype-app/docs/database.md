# VulnWatch Database

Last updated: 2026-03-08

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
- `software_identifiers`
- `identity_links`
- `software_inventory_items`
  - flattened software inventory projection used by read/reporting paths

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
- `github_sbom_sources`
- `investigations`
- `investigation_activities`
- `investigation_attachments`
- `applicability_assessments`

## Key Relationships

- `tenants` 1->N inventory, findings, org-CVE, and policy records
- `assets` 1->N `sbom_uploads`, `inventory_components`, `software_inventory_items`, and `findings`
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

- `software_models` is no longer part of the active code model. Older docs that described `software_models` as a core table are obsolete.
- Flyway owns the PostgreSQL startup path and normal runtime no longer relies on startup schema mutation.
- Because schema evolution was compatibility-oriented, some tables and columns reflect transitional states rather than a clean-room final design.
