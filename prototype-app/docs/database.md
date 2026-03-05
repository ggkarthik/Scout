# VulnWatch Database Documentation

Last updated: 2026-03-03

This schema is generated from JPA entities (`spring.jpa.hibernate.ddl-auto=update`).

## Engine And Profiles

- Default runtime: H2 file database (`./data/vulnwatch`)
- Optional profile: PostgreSQL (`--spring.profiles.active=postgres`)
- Migration model: entity-first (no Flyway/Liquibase in this prototype)

## Tenancy And Data Boundaries

- Tenant boundary exists in schema (`tenants` + tenant foreign keys).
- Runtime API currently resolves one default workspace via `TenantService`.

Boundary intent:

- Global vulnerability intelligence:
  - `vulnerabilities`
  - `vulnerability_intel_observations`
  - `vulnerability_intel_summary`
  - `vulnerability_intel_summary_sources`
- Tenant-scoped inventory/projection:
  - `assets`
  - `sbom_uploads`
  - `inventory_components`
  - `inventory_component_cpe_map`
  - `findings`
  - workflow/audit tables (`finding_events`, `finding_comments`)

## Major Table Groups

### Inventory And Asset Model

- `assets`
  - unique: `uk_assets_tenant_identifier (tenant_id, identifier)`
  - stores type, ownership metadata, business criticality, lifecycle state
- `sbom_uploads`
  - ingestion evidence (source type/system, endpoint, status, hash, counts)
- `inventory_components`
  - component records by asset/upload
  - lifecycle: `ACTIVE` / `RETIRED`
  - normalized identity/model fields
- `software_identities`, `software_identifiers`, `identity_links`, `software_models`
  - normalization and canonical identity/model graph

### Correlation Model

- `cpe_dim`
  - canonical CPE dimension
  - unique `normalized_cpe`
  - indexes: `idx_cpe_dim_key`, `idx_cpe_dim_normalized`
- `inventory_component_cpe_map`
  - bridge: tenant component -> CPE
  - unique `uk_inventory_component_cpe (tenant_id, component_id, cpe_id)`
  - indexes: `idx_iccm_tenant_cpe`, `idx_iccm_tenant_component`
- `vulnerability_targets`
  - normalized target rows from NVD/GHSA/CSAF/VEX/advisory ingest
  - includes version constraints + qualifiers
  - CPE linkage via `cpe_id` to `cpe_dim`
  - indexes include `idx_vuln_target_cpe_id`, `idx_vuln_target_type_cpe_id`

### Vulnerability Intelligence Model

- `vulnerabilities`
  - canonical vulnerability row by `external_id` (unique)
  - CVSS/severity/status/reference fields
  - indexes for list and filter paths (external id + score/time, severity, status, kev)
- `vulnerability_intel_observations`
  - source-specific observations per vulnerability
  - unique `(vulnerability_id, source_system, source_record_id)`
- `vulnerability_intel_summary`
  - read model for list performance and filtering
  - includes `description_snippet`, `source_count`, summary timestamps
- `vulnerability_intel_summary_sources`
  - source system list projected per vulnerability summary row

### Finding And Workflow Model

- `findings`
  - unique: `uk_findings_component_vulnerability`
  - stores risk/confidence/decision/status and JSON evidence
  - indexes for tenant/status/time and vulnerability lookups
- `finding_events`, `finding_comments`
  - workflow trail and human/operator notes
- `risk_policies`
  - per-tenant scoring and SLA policy (single row per tenant)

### Operational Integration Model

- `sync_runs`
  - run diagnostics for NVD/KEV/GHSA/CSAF/advisory jobs
- `github_sbom_sources`
  - scheduled GitHub SBOM source configs and last-run status

## Key Relationships

- `tenants` 1->N `assets`, `inventory_components`, `inventory_component_cpe_map`, `sbom_uploads`, `findings`
- `assets` 1->N `sbom_uploads`, `inventory_components`, `findings`
- `inventory_components` 1->N `inventory_component_cpe_map`, 1->N `findings`
- `cpe_dim` 1->N `inventory_component_cpe_map`, 1->N `vulnerability_targets`
- `vulnerabilities` 1->N `vulnerability_targets`, 1->N `findings`, 1->N `vulnerability_intel_observations`
- `vulnerabilities` 1->1 `vulnerability_intel_summary` (enforced by `vulnerability_id` uniqueness in summary)

## Write Paths

### SBOM ingestion (`/api/sbom-*`)

1. Upsert asset + create `sbom_uploads` evidence row.
2. Upsert `inventory_components`; retire missing components.
3. Normalize CPEs into `cpe_dim`.
4. Sync `inventory_component_cpe_map`.
5. Trigger component-scoped finding recompute.

### Vulnerability ingestion (`/api/ingestion/*`)

1. Upsert source observations in `vulnerability_intel_observations`.
2. Merge canonical `vulnerabilities`.
3. Refresh `vulnerability_intel_summary` and `vulnerability_intel_summary_sources`.
4. Upsert `vulnerability_rules`, `vulnerability_config_expr`, `vulnerability_targets`.
5. Run vulnerability-scoped recompute and VEX overlay updates.

### CMDB and asset lifecycle (`/api/assets/cmdb-sync`, schedulers)

1. Upsert asset metadata/state.
2. On non-active asset transitions, resolve/suppress open findings accordingly.
3. Scheduled stale-asset job marks assets inactive based on `last_inventory_at`.

## Determinism And Auditability

`findings.evidence` stores:

- selected match method and confidence breakdown
- applicability trace (version + VEX policy outcomes)
- precedence resolution trace
- target metadata including CPE linkage
- risk breakdown context

This enables replayable, explainable decisions from persisted inputs.

## Known Current Behavior

Correlation recompute creates and updates findings from deterministic CPE matching (`matchedBy` starts with `cpe-`). Additional matcher families remain disabled for finding creation until explicitly enabled.
