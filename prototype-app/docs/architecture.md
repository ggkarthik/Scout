# VulnWatch Architecture

Last updated: 2026-03-19

## Why This Fourth Document Exists

`frontend.md`, `backend.md`, and `database.md` cover implementation details by layer. This file is the cross-cutting view: system behavior, operational shape, major feature boundaries, and the important caveats that used to be spread across design notes, migration guides, and report cards.

## System Overview

VulnWatch is an internal security operations prototype with four primary responsibilities:

1. ingest asset and software inventory from SBOM sources and CMDB-like inputs
2. ingest vulnerability intelligence from external feeds
3. correlate inventory to vulnerabilities using deterministic CPE-based matching
4. project tenant-scoped exposure into org-CVE records and findings workflows

Runtime shape:

- React SPA in `frontend/`
- Spring Boot API in `backend/`
- PostgreSQL as the only live application database
- scheduled feed synchronization plus async queue processing

## End-to-End Flow

### 1. Inventory In

**SBOM path:** Users upload or fetch SBOMs, or configure GitHub-generated SBOM pulls. The backend writes `assets`, `sbom_uploads`, `inventory_components`, identity records, `software_inventory_items`, and normalized CPE links.

**ServiceNow CMDB path:** Users configure a live connector (base URL, auth, table names) via `AssetsPage`. The backend paginates ServiceNow Table APIs, resolves or creates `cis` and `ci_alias` rows, normalizes software via `discovery_models` and `software_identities`, upserts `software_instances`, mirrors each CI as an `inventory_component`, and records the run in `sync_runs` with `run_domain=INVENTORY`.

### 2. Vulnerability Intelligence In

- The backend syncs NVD, KEV, GHSA, Microsoft CSAF/VEX, Red Hat CSAF/VEX, and advisory imports.
- Canonical vulnerability rows and summary/read-model tables are refreshed.
- Normalized target records are built for later matching.

### 3. Deterministic Correlation

- Active correlation is CPE-first.
- Candidate generation is based on `cpe_id` joins.
- Applicability is resolved through version bounds and VEX/precedence logic.
- Component-level truth is stored in `component_vulnerability_states`.

### 4. Org-CVE Projection

- Component states are rolled up into `org_cve_records`.
- The frontend uses this view for the Org CVEs table and drawer workflow.

### 5. Findings and Workflow

- Findings are created, reopened, resolved, suppressed, or auto-closed according to policy and recomputation logic.
- Analysts can create investigations, run applicability assessments, and manually create findings from the CVE workflow APIs.

### 6. Operational Maintenance

- Scheduled jobs keep external feeds fresh, expire suppressions, auto-close findings by policy, and age stale assets inactive.

### 7. EOL Pipeline

A 4-stage weekly pipeline tracks software end-of-life status for all active inventory:

1. **Catalog refresh** — fetches all product slugs and CPE/PURL identifiers from endoflife.date into `eol_product_catalog`
2. **Release data refresh** — conditionally fetches release cycles for tracked slugs (respects `If-Modified-Since`) into `eol_releases`
3. **Slug resolution** — maps `SoftwareIdentity` rows to EOL slugs via `EolSlugResolverService` into `software_eol_mapping`
4. **Denormalization** — set-based `DISTINCT ON` update writes `eol_slug`, `eol_cycle`, `eol_date`, `is_eol`, `eol_support_end_date`, `support_phase`, and `latest_supported_version` onto both `inventory_components` and `software_instances`; then refreshes `org_cve_records` EOL counts

Each stage can also be triggered manually from the Connect UI via `/api/eol/admin/refresh/*`. Near-EOL threshold is 90 days.

## Current Product Surface

What is actively exposed in the UI today:

- dashboard metrics (with EOL risk widget)
- findings management
- operational metrics (Quality, Pipeline, Platform Health sub-views)
- vulnerability intelligence list/detail
- org-CVE exposure list with CVE Assessment Workbench drawer
- inventory component views (Software Identities, Hosts, Container Images, Repositories)
- host asset detail page with CI metadata, aliases, software instances, and findings
- ServiceNow CMDB live connector setup, connection testing, and live sync trigger
- Inventory Run Queue showing all host/container/SBOM ingestion run history
- risk policy and GitHub pipeline configuration
- End-of-Life component tracking (EolPage) with filter tabs, CSV export, and unresolved-mapping review
- EOL source panel in Connect UI for manual pipeline stage triggers

What exists in code but is not fully surfaced or is still transitional:

- standalone `CveDetailPage.tsx`
- archive migration endpoints and manual SQL migration support
- several conceptual inventory categories without dedicated backend models

## Major Architectural Decisions

### Deterministic Matching First

The backend deliberately centers on deterministic evidence rather than fuzzy package matching. The current production path is CPE-based with version checks and source precedence.

### Tenant-Aware Schema, Single-Tenant Runtime

Most tables carry tenant boundaries, but many controllers still resolve one default tenant. The system is multi-tenant in schema design, not yet in runtime behavior.

### Projection Tables Matter

The current architecture relies on materialized projection-style tables, not only raw domain entities:

- `vulnerability_intel_summary`
- `software_inventory_items`
- `component_vulnerability_states`
- `org_cve_records`

Those tables are now central to read performance and workflow UX.

### Compatibility-Oriented Schema History

The schema evolved through a compatibility-heavy migration period. PostgreSQL and Flyway now own the live runtime path, but some tables and columns still reflect that transitional history.

## Current Limitations and Risks

### CVE Suppression

`/api/cve-detail/{cveId}/suppress` is fully implemented. The controller calls `OrgCveRecordService.suppress()` to persist suppression state and `FindingService.suppressFindingsForVulnerability()` to suppress related findings. Suppression expiry is handled by the every-15-minutes reopen job.

### Schema Cleanup Is Still Transitional

The repo now boots PostgreSQL through Flyway without runtime schema mutation, but archive-oriented helpers and some compatibility-era columns still remain.

### Frontend Scope Is Ahead of Backend Shape in Places

The UI presents a broader inventory taxonomy than the backend currently models with distinct APIs. Some sections are filtered views over the same component endpoint rather than truly separate domains.

### Release Hygiene Is Still Prototype-Level

The repository has strong feature breadth, but the delivery model is still prototype-oriented:

- schema changes are not migration-managed end to end
- frontend quality gates are minimal
- many docs had become milestone snapshots instead of maintained references

## Operational Timers

Important built-in jobs:

- daily feed syncs starting at `01:00`
- stale asset inactivation at `02:05`
- nightly VEX freshness sweep at `02:30`
- GitHub SBOM source execution every `5` minutes
- suppression expiry reopening every `15` minutes
- hourly policy-based auto-close sweep
- weekly EOL pipeline (Sunday): catalog `02:00`, releases `03:00`, slug resolution `03:30`, denormalization `04:00`

## Documentation Boundaries

Use the docs like this:

- `frontend.md`: UI shell, pages, API client behavior, and frontend caveats
- `backend.md`: controllers, services, schedules, auth, and backend caveats
- `database.md`: schema groups, write paths, projections, and migration notes
- `architecture.md`: cross-cutting behavior, current status, and known system-level gaps

Any new feature documentation should extend one of those four files instead of creating a new standalone markdown document unless the feature genuinely needs its own long-lived specification.
