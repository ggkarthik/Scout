# VulnWatch Backend

Last updated: 2026-05-22

## Purpose

The backend ingests software inventory and vulnerability intelligence, correlates them using deterministic CPE-based matching, projects exposure state at component and organization level, and manages finding workflows.

## Runtime Stack

- Java 17
- Spring Boot 3.3.2
- Spring Web
- Spring Data JPA
- Spring Security
- Spring Validation
- PostgreSQL at `jdbc:postgresql://localhost:5432/vulnwatch`
- Flyway-managed PostgreSQL schema with reset-line migrations under `db/migration/postgres_reset`
- Hibernate schema mutation is disabled; the reset-line catalog is expected to come from Flyway `postgres_reset/V1`

## Package Layout (`com.prototype.vulnwatch`)

| Package | Contents |
|---------|----------|
| `controller/` | REST controllers under `/api/**` |
| `service/` | Business-logic services |
| `domain/` | JPA entities (assets, inventory, vulns, findings, policies, CMDB, EOL, SCCM, AWS) |
| `dto/` | API request/response objects |
| `repo/` | Spring Data JPA repositories |
| `client/` | External API clients (NVD, GHSA, CSAF, EPSS, GitHub, ServiceNow, SCCM, endoflife.date, AWS, OpenAI) |
| `config/` | Spring beans and security configuration |
| `security/` | `SensitiveTenantAction` annotation and `SensitiveTenantActionInterceptor` for sensitive cross-tenant operations |
| `util/` | CPE handling, version comparison, SBOM parsing |

## Security Model

- `ApiKeyAuthenticationFilter` authenticates every `/api/**` request through `X-API-Key`.
- The same filter accepts bearer JWTs when `APP_JWT_ISSUER_URI`, `APP_JWT_JWK_SET_URI`, or `APP_JWT_HMAC_SECRET` is configured.
- JWT requests upsert `app_users`, resolve an active tenant membership from `tenant_id`, `tenant_slug`, or the user's first active membership, and set `TenantContext` from the authenticated identity.
- `X-Creator-Key` grants `ROLE_CREATOR` when it matches the configured creator key.
- Creator callers are also granted production-readiness bootstrap roles: `ROLE_PLATFORM_OWNER`, `ROLE_TENANT_ADMIN`, and `ROLE_INVENTORY_ADMIN`.
- `/api/operations/**` requires `ROLE_CREATOR`.
- `/api/platform/**` requires `ROLE_PLATFORM_OWNER`.
- `/actuator/health` and `/actuator/info` are open.
- CORS allow-list is driven by `app.cors.allowed-origins`.
- Production startup can reject unsafe local defaults when `APP_REQUIRE_PRODUCTION_SECRETS=true`.

The UI also sends `X-Tenant-ID` and `X-User-ID`; several newer workflow endpoints depend on those headers directly.
`APP_ALLOW_HEADER_TENANT_SELECTION=true` keeps that local compatibility mode available. It must be disabled for production once tenant context is derived from verified identity claims.

## Schema Ownership

The backend is mid-migration to a shared database with a shared `platform` schema plus one schema per tenant.

| Ownership | Tables / entities |
|---------|----------|
| `platform` | `Tenant`, `AppUser`, `TenantMembership`, `TenantSupportGrant`, central vulnerability/reference/intelligence entities such as `Vulnerability`, `VulnerabilityIntelSummary`, `VulnerabilityIntelObservation`, `CpeDim`, `EolProductCatalog`, `EolRelease` |
| tenant-local | assets, inventory components, software instances, findings, finding events/comments, risk policy, org CVE records, component vulnerability states, suppression rules, ownership rules, fix records, connector configs, SBOM uploads, service accounts, quality projections |
| hybrid | sync history, audit history, demo lifecycle/admin/support paths, and services that read `platform` vulnerability data but write tenant-local findings or projections |

Current default:

- keep `tenant_id` on existing entities and tables for compatibility unless removal is required for correctness
- prefer `TenantSchemaExecutionService` plus schema-local repository methods for tenant-owned runtime paths
- keep explicit `platform.*` access for true shared-plane data
- `ServiceLayerSchemaIsolationTest` guards against reintroducing tenant-qualified shared-schema repository access inside `service/`

## Reset-Line Bootstrap Status

Current reset-line foundation:

- Flyway uses `db/migration/postgres_reset`
- `V1__platform_and_default_tenant_schemas.sql` bootstraps `platform` and `tenant_default`
- `TenantSchemaService` / `TenantBootstrapService` provision additional tenant schemas
- `DatabaseResetCompatibilityGuardService` fails fast on unsupported legacy shared-schema layouts

Current reset-line contract:

- `spring.jpa.hibernate.ddl-auto=none` is the expected mode
- `postgres_reset/V1__platform_and_default_tenant_schemas.sql` now includes the runtime catalog used by the current branch:
  - `platform`: tenant registry, software identity/reference, CPE, vulnerability-intel summary/observation/target, VEX, and EOL catalog tables
  - `tenant_default`: demo, audit, investigation, assets, inventory, CI, software-instance, software-inventory, CPE-map, findings, policies, org-CVE, connector-config, sync, service-account, and GitHub SBOM source tables

Practical rule for the remaining reset work:

- keep new schema changes explicit in Flyway reset SQL
- do not reintroduce Hibernate-driven schema mutation
- `ResetLineBootstrapPostgresIntegrationTest` is the current source of truth for the minimum platform and tenant-default catalog that must exist after boot

## Local Database Runtime

Default local runtime:

```bash
cd backend
mvn spring-boot:run
```

For GitHub-backed repo SBOM and GHCR image SBOM ingestion, the backend resolves a token in this order:

- `GITHUB_API_TOKEN_FILE`
- local fallback file `backend/secrets/github-api-token`
- `GITHUB_API_TOKEN`

The local fallback file is gitignored and is intended for developer machines. For GHCR discovery,
the token needs at least package-read access.
The same resolved token is shared by GitHub repo SBOM fetches, GHCR image SBOM ingestion,
and GHSA advisory syncs.

If an existing local PostgreSQL `vulnwatch` database was created before the reset-line baseline landed, do not repair it in place. Recreate the database from the `postgres_reset` baseline instead.

```bash
cd backend
dropdb vulnwatch
createdb vulnwatch
mvn -q test -Dtest=SchemaMigrationStartupPostgresIntegrationTest
```

To validate PostgreSQL data against an archived H2 source snapshot:

```bash
cd backend
./tools/run-database-parity.sh
```

If the JDBC jars are not already present under `~/.m2/repository`, set `H2_JAR=/path/to/h2-*.jar` and `POSTGRES_JAR=/path/to/postgresql-*.jar` when invoking the script.

## Main API Groups

### Dashboard and Auth

- `GET /api/auth/context`
- `GET /api/me`
- `GET /api/tenants`
- `POST /api/platform/tenants`
- `PATCH /api/platform/tenants/{tenantId}/status`
- `GET /api/tenants/{tenantId}/members`
- `POST /api/tenants/{tenantId}/members`
- `GET /api/service-accounts`
- `POST /api/service-accounts`
- `GET /api/audit-events`
- `GET /api/audit-events/export`
- `GET /api/audit-events/support-bundle`
- `GET /api/dashboard`
- `GET /api/dashboard/applicable-software`
- `GET /api/dashboard/impacted-cves`
- `GET /api/dashboard/cve-inventory-map`
- `GET /api/operations/dashboard`
- `GET /api/operations/normalization-quality`
- `GET /api/operations/quality/summary` — quality issue counts by domain/severity
- `GET /api/operations/quality/issues` — paged quality issue list (filterable by domain, severity, asset type, source system)
- `GET /api/operations/quality/issues/{issueId}` — single quality issue detail
- `GET /api/operations/quality/filters` — available filter values for quality issues

### Findings and Policy

- `GET /api/findings`
- `GET /api/findings/filters`
- `GET /api/risk-policy`
- `POST /api/risk-policy`
- `POST /api/configurations/clean-all`

### Inventory and Assets

- `GET /api/inventory/components`
- `GET /api/inventory/components/filters`
- `GET /api/inventory/software-identities` — paged software identity summary with lifecycle and mapping-state filters
- `GET /api/inventory/software-identities/{softwareIdentityId}` — single software identity detail
- `GET /api/assets`
- `POST /api/assets/cmdb-sync`
- `GET /api/assets/hosts/{assetId}` — host CI detail with aliases, software instances, and findings
- `GET /api/sbom-uploads`

### ServiceNow CMDB Connector

- `GET /api/connectors/servicenow-cmdb` — retrieve saved connector config for the default tenant
- `PUT /api/connectors/servicenow-cmdb` — create or update connector config (URL, auth type, tables, sync schedule)
- `POST /api/connectors/servicenow-cmdb/test` — save config then run a live connection test against all three ServiceNow tables
- `POST /api/connectors/servicenow-cmdb/sync` — enqueue a live CMDB inventory pull via `ServiceNowCmdbSyncService`

### SCCM CMDB Connector

- `GET /api/connectors/sccm-cmdb` — retrieve saved SCCM/MECM connector config
- `PUT /api/connectors/sccm-cmdb` — create or update config (JDBC URL, auth, site code, database, fetch size, scheduling)
- `POST /api/connectors/sccm-cmdb/test` — save and run a live JDBC connection test
- `POST /api/connectors/sccm-cmdb/sync` — enqueue a SCCM sync via `SccmCmdbSyncService`

### AWS Cloud Discovery Connector

- `GET /api/connectors/aws-discovery` — retrieve AWS discovery config (auth, account, regions)
- `PUT /api/connectors/aws-discovery` — save AWS discovery config; supports IAM access keys or cross-account role assumption
- `POST /api/connectors/aws-discovery/test` — live AWS authentication probe
- `POST /api/connectors/aws-discovery/sync` — trigger an EC2 discovery sweep via `AwsDiscoverySyncService`
- `GET /api/connectors/aws-discovery/targets` — list cross-account / multi-region targets
- `POST /api/connectors/aws-discovery/targets` — create a target
- `PUT /api/connectors/aws-discovery/targets/{id}` — update a target
- `DELETE /api/connectors/aws-discovery/targets/{id}` — delete a target
- `POST /api/connectors/aws-discovery/targets/{id}/test` — per-target connection probe
- `POST /api/connectors/aws-discovery/targets/{id}/sync` — per-target sync run

Scope is currently EC2-only via SSM (V1069). RDS/Lambda/S3/ECS/EKS scope was removed.

### Vulnerability Source Filter Config

- `GET /api/connectors/vulnerability-sources` — get tenant feed-filter rules
- `PUT /api/connectors/vulnerability-sources` — save tenant feed-filter rules (V1046 schema)

### Vulnerability Intelligence

- `GET /api/vulnerability-intelligence`
- `GET /api/vulnerability-intelligence/filters`
- `GET /api/vulnerability-intelligence/sources`
- `GET /api/vulnerability-intelligence/{externalId}`
- `GET /api/vulnerability-intelligence/org-cves`
- `GET /api/vulnerability-intelligence/org-cves/status`
- `POST /api/vulnerability-intelligence/org-cves/refresh` — tenant-scoped exposure refresh from the current central vulnerability repository
- `POST /api/vulnerability-intelligence/org-cves/recompute` — platform-owner repair/backfill endpoint
- `GET /api/vulnerabilities/{externalId}`

### Ingestion and Automation

- `POST /api/sbom-upload`
- `POST /api/sbom-fetch`
- `POST /api/ingestion/nvd-sync`
- `POST /api/ingestion/nvd-full-sync`
- `POST /api/ingestion/kev-sync`
- `POST /api/ingestion/ghsa-sync`
- `POST /api/ingestion/csaf/microsoft-sync`
- `POST /api/ingestion/csaf/redhat-sync`
- `POST /api/ingestion/advisories`
- `GET /api/sync-runs`
- `GET /api/github-sbom-sources`
- `POST /api/github-sbom-sources`
- `PUT /api/github-sbom-sources/{id}`
- `POST /api/github-sbom-sources/repository/run`
- `POST /api/github-sbom-sources/ghcr/run`
- `POST /api/github-sbom-sources/{id}/run`
- `POST /api/demo/seed`

### EOL (End-of-Life)

- `GET /api/eol/status/summary` — EOL/near-EOL/supported/unknown counts for active inventory
- `GET /api/eol/status/components` — paged component list with EOL status; `filter` param: `eol | near-eol | ok | unknown`
- `GET /api/eol/products` — full EOL product catalog (slugs + CPE/PURL identifiers)
- `GET /api/eol/products/{slug}/releases` — all release cycles for a product slug
- `POST /api/eol/mappings/confirm` — manually confirm or override an EOL slug mapping for a normalized product key
- `GET /api/eol/mappings/unresolved` — software identities with no EOL slug mapping (up to 200, for analyst review)
- `POST /api/eol/admin/refresh/catalog` — trigger stage 1: catalog refresh
- `POST /api/eol/admin/refresh/releases` — trigger stage 2: release data refresh
- `POST /api/eol/admin/refresh/mappings` — trigger stage 3: slug resolution
- `POST /api/eol/admin/refresh/denormalize` — trigger stage 4: denormalization
- `POST /api/eol/admin/refresh/full` — trigger all 4 stages in sequence

### CVE Drill-Down and Archive Operations

- `GET /api/cve-detail/{cveId}`
- `POST /api/cve-detail/{cveId}/investigation`
- `PUT /api/cve-detail/investigation/{investigationId}`
- `POST /api/cve-detail/{cveId}/applicability-assessment`
- `PUT /api/cve-detail/applicability-assessment/{assessmentId}`
- `POST /api/cve-detail/applicability-assessment/{assessmentId}/complete`
- `POST /api/cve-detail/{cveId}/manual-finding`
- `POST /api/cve-detail/{cveId}/suppress`
- `POST /api/cve-detail/{cveId}/export`
- `POST /api/cve-detail/{cveId}/servicenow-incident` — opens a ServiceNow incident; writes `incident_id`/`incident_status` onto the underlying findings (V1054)
- `POST /api/cve-detail/{cveId}/ai-investigation-summary`, `/ai-solution`, `/ai-actions` — AI-assisted writers; persist results in `org_cve_ai_artifacts` so subsequent reads do not re-call OpenAI

## Flyway rollout audit

Before promoting a migration-bearing build, inspect `flyway_schema_history` in every active environment and verify:

- no row exists for version `1073`
- versions `1090` and `1092` either both exist or both do not exist
- versions `1091` and `1093` either both exist or both do not exist
- no rows are marked failed
- no rows were applied out of order
- any manually repaired entries are documented in the deployment record

Migration review policy for new changes:

- one version, one file
- no comment-only or whitespace-only migrations
- idempotence is allowed for compatibility and repair, not as a substitute for root-cause analysis
- new structured payload columns default to typed storage such as `jsonb`, not JSON-in-`TEXT`
- `POST /api/operations/vulnerability-archive/migrate`
- `GET /api/operations/vulnerability-archive/status`
- `GET /api/operations/vulnerability-archive/{externalId}/description`
- `GET /api/operations/vulnerability-archive/{externalId}/raw-payload`
- `POST /api/operations/normalization-overrides` / `DELETE` — manual normalization-cluster overrides (V1056–V1059)
- `POST /api/operations/correlation-overrides` / `DELETE` — manual correlation overrides
- `GET /api/upgrade-recommendation` — version-upgrade-path recommendations
- `GET /api/slo` — service level objective status snapshot

## Core Flows

### 1. SBOM Ingestion

The ingestion controllers hand off to `SbomIngestionService` and related services to:

1. validate payload size and host rules
2. upsert assets and write `sbom_uploads`
3. parse CycloneDX/SPDX components
4. upsert `inventory_components`
5. maintain software identity metadata and `software_inventory_items`
6. normalize CPEs into `cpe_dim`
7. sync `inventory_component_cpe_map`
8. enqueue component-scoped recomputation

GitHub-backed SBOM ingestion now supports two modes:

- repository dependency-graph SBOM queueing via `POST /api/github-sbom-sources/repository/run`
- GHCR owner-wide image attestation queueing via `POST /api/github-sbom-sources/ghcr/run`
- saved GitHub source execution via `POST /api/github-sbom-sources/{id}/run`

The GHCR batch path enumerates container packages and image versions in GHCR for a GitHub owner,
looks up each image digest in GitHub artifact attestations, and feeds every discovered SBOM
through the same parsing and correlation pipeline used for uploaded SBOM files.

**Canonical-tag filter:** The GitHub Packages API returns every stored version for a package,
including untagged platform-specific sub-manifests (linux/amd64, linux/arm64 layers inside a
multi-arch index) and OCI referrer entries created by `actions/attest-sbom` or cosign
(these are tagged `sha256-{64-hex-chars}` with no human-readable tag). The backend now skips
any version whose tags are all in the `sha256-{digest}` referrer format or whose tag list is
empty. Only versions with at least one canonical tag (e.g. `main-*`, `latest`, `v1.2.3`) are
processed for attestation lookup. This prevents false failure counts from non-image registry
artifacts.

Current trust model:

- the backend filters GitHub attestations to `predicate_type=sbom`
- it matches the attestation subject against the requested image digest and repository
- it does not yet perform cryptographic signature or trusted-publisher verification of the DSSE bundle

That means this endpoint is ready for automated ingestion, but it should not yet be treated as a hard provenance gate for policy enforcement. The next trust-stage improvement is a verification step against GitHub/Sigstore identity before marking the attestation as verified.

### 2. Vulnerability Intelligence Ingestion

`VulnerabilityIngestionService` pulls data from NVD, KEV, GHSA, CSAF, VEX, and advisory feeds. The ingest path:

1. stores source observations
2. merges canonical vulnerability rows
3. refreshes the vulnerability read model
4. builds normalized target rows and config expressions
5. transactionally enqueues projection deltas into `finding_delta_queue`
6. lets the background projector update component exposure and org-CVE projections
7. enqueues tenant-scoped noise-reduction projection refreshes when correlation-affecting work completes

Production ownership boundary:

- central vulnerability feed mutations under `/api/ingestion/*` are platform-owner operations
- tenant users refresh exposure through `/api/vulnerability-intelligence/org-cves/refresh` or `/api/vuln-repo/org-cves/refresh`, which recomputes tenant projections from already-ingested central data
- `/org-cves/recompute` remains a platform-owner repair/backfill endpoint

Tenant quota boundary:

- service account creation checks `tenants.max_service_account_count`
- ServiceNow, SCCM, AWS discovery config, and AWS discovery target creation check `tenants.max_connector_count`
- tenant exposure refresh checks `tenants.max_daily_exposure_refreshes` against successful `tenant.org_cves.refresh` audit events from the previous 24 hours
- audit/support export row counts check `tenants.max_export_rows`
- quota failures return HTTP `429` with `code=QUOTA_EXCEEDED` and a stable `quotaCode`

Tenant lifecycle boundary:

- suspended or deleted tenants receive `423` with `code=TENANT_SUSPENDED` for normal tenant API routes
- `/api/platform/**`, `/api/auth/**`, and `/api/me` remain available so platform owners can inspect or restore tenant state

Connector credential boundary:

- ServiceNow, SCCM, and AWS access-key secrets are encrypted before save
- runtime services decrypt credentials only at outbound connector boundaries
- API responses expose only `hasCredentialSecret`
- legacy plaintext secret values remain readable for migration compatibility, but newly written values use `enc:v1:` envelopes

Request correlation boundary:

- every backend response includes `X-Request-ID`
- safe caller-provided request IDs are echoed; unsafe values are replaced with generated UUIDs
- MDC includes `requestId`, `tenantId`, `actorId`, `actorRoles`, `httpMethod`, and `httpPath`
- audit events persist the active `requestId`

Delta producers are now split by change type:

- inventory changes enqueue `SOFTWARE_DELTA`
- vulnerability/advisory target changes enqueue `CVE_DELTA`
- metadata-only changes such as KEV and EPSS enqueue `CVE_METADATA_DELTA`
- exact vendor impact changes enqueue `VEX_DELTA`
- EOL/EOS mapping and date-driven lifecycle changes enqueue `LIFECYCLE_DELTA`
- dashboard refreshes enqueue `NOISE_REDUCTION_REFRESH`

### 3. Correlation and Exposure Projection

The active correlation model is deterministic and CPE-first, but the workbench itself is now projection-driven:

- candidates are generated by joining `inventory_component_cpe_map` with `vulnerability_targets.cpe_id`
- version checks are applied by `ApplicabilityDecisionService`
- precedence is resolved across NVD, GHSA, CSAF/advisories, and VEX overlays
- component-level state is projected into `component_vulnerability_states`
- tenant-level CVE rollups are projected into `org_cve_records`
- finding creation/update logic is managed by `FindingService`
- `recomputeOnSoftwareDeltaBatch(...)` is the sole owner of org-CVE refresh for component recompute scope; CVE/VEX delta wrappers only do metadata-only fallback refresh for tenants with no affected component recompute in that batch
- the queue worker batches deltas by event type instead of processing one row at a time
- normal analyst freshness comes from the queue worker, not from `POST /org-cves/recompute`

### 3a. Dashboard Noise Reduction Projection

The dashboard noise-reduction widget is now projection-backed instead of re-running correlation preview logic on every read.

- `DashboardNoiseReductionProjectionService` reads persisted `component_vulnerability_states`
- it excludes tuples that already have a finding for the same tenant/component/CVE
- it stores tenant-scoped totals and category buckets in `dashboard_noise_reduction_projection`
- `DashboardService` reads that projection and keeps only auto-resolved counts and the 30-day trend as lightweight read-time queries
- `OperationalDashboardService` exposes projection readiness, age, failures, and refresh p95 in Platform Health

Observed `matchedBy` evidence values are CPE-based, such as:

- `cpe-indexed-direct+version`
- `cpe-indexed-fallback+version`

### 4. ServiceNow CMDB Host Inventory Ingestion

`ServiceNowCmdbSyncService` drives live host inventory pulls from ServiceNow Table APIs:

1. reads connector config from `servicenow_cmdb_configs` via `ServiceNowCmdbConfigService`
2. paginates the install table (`cmdb_sam_sw_install`) using the configured page size, field list, and optional query override
3. paginates the discovery model table (`cmdb_sam_sw_discovery_model`) and resolves normalized software metadata
4. resolves or creates CI rows in the `cis` table via `CiResolutionService`, matching by `sys_id` or `cmdb_ci` lookup
5. upserts CI aliases from hostname/FQDN variants
6. normalizes software names/publishers via `HostSoftwareNormalizationService`
7. resolves or creates `SoftwareIdentity` rows via `SoftwareIdentityService`
8. upserts `SoftwareInstance` rows linking CIs to software identities
9. mirrors each CI as an `InventoryComponent` via `CmdbIngestionService` and enqueues `SOFTWARE_DELTA`
10. records a `SyncRun` row with `runDomain=INVENTORY` and detailed metadata JSON

`SyncRunHistoryService` reads persisted `sync_runs` history and is the single point of truth for API history responses across inventory and vulnerability-intelligence run types. Run lifecycle creation/update happens in the owning ingestion services and sync-run helpers, and legacy GitHub inventory evidence is backfilled into `sync_runs` on startup or via the dedicated tool.

### 5. CVE Workflow Layer

The newer CVE workflow APIs add:

- investigations
- applicability assessments
- manual finding creation
- export/report responses
- org-level CVE drill-down data assembly

These APIs depend on `X-Tenant-ID` and `X-User-ID`, and are currently consumed by the org-CVE drawer in the frontend.

### 5. EOL Pipeline

`EolRefreshService` runs a 4-stage pipeline to track software end-of-life status:

1. **Catalog refresh** — calls `EolApiClient.fetchAllProducts()` and batch-upserts product slugs, CPE/PURL identifiers into `eol_product_catalog` (100-row JDBC batches, `ON CONFLICT (slug) DO UPDATE`)
2. **Release data refresh** — fetches release cycles per tracked slug using `If-Modified-Since` headers to avoid redundant downloads; upserts into `eol_releases`; computes `support_phase` (`active | lts | extended | eol | discontinued`) per cycle
3. **Slug resolution** — `EolSlugResolverService.resolveAll()` maps `SoftwareIdentity` rows to EOL slugs in-memory; writes or updates `software_eol_mapping` rows
4. **Denormalization** — two set-based `UPDATE ... FROM (SELECT DISTINCT ON ...)` statements write EOL status onto `inventory_components` and `software_instances`; then enqueues `LIFECYCLE_DELTA` for the affected component set so `org_cve_records` refresh in the background
5. **Date sweep** — a daily `EOL_DATE_SWEEP` job marks components as effectively EOL when dates roll over and enqueues `LIFECYCLE_DELTA` for components that crossed the EOL/EOS threshold even if no source feed changed

All stages record a `SyncRun` row with `run_domain` matching the stage name. Each stage is also callable on-demand from the Connect UI via `POST /api/eol/admin/refresh/*`.

## Scheduling and Async Execution

Scheduled jobs currently defined in code:

- `01:00` daily: NVD incremental sync plus KEV sync
- `01:15` daily: GHSA sync
- `01:45` daily: Microsoft and Red Hat CSAF/VEX sync
- `02:05` daily: mark stale assets inactive
- `02:30` daily: VEX staleness sweep enqueues `SOFTWARE_DELTA`
- `03:15` daily: EPSS score refresh (`EpssRefreshService`)
- `00:15` daily: lifecycle date sweep (`EOL_DATE_SWEEP`)
- `07:00` daily: ServiceNow incident status sync (`FindingIncidentSyncService`) — pulls `incident_status` changes back onto findings
- every `5` minutes: run enabled GitHub SBOM sources, ServiceNow CMDB syncs, SCCM CMDB syncs, AWS Discovery syncs
- every `15` minutes: reopen expired suppressions
- every `2` seconds: drain `finding_delta_queue` (configurable, batches up to 100)
- hourly: auto-close findings by policy
- `02:00` Sunday: EOL catalog refresh (stage 1 — `EolRefreshService.fullCatalogRefresh`)
- `03:00` Sunday: EOL release data refresh (stage 2 — `EolRefreshService.releaseDataRefresh`)
- `03:30` Sunday: EOL slug mapping resolution (stage 3 — `EolRefreshService.resolveInstanceMappings`)
- `04:00` Sunday: EOL denormalization (stage 4 — `EolRefreshService.denormalizeEolStatus`)

All EOL jobs are configurable via `app.eol.*-cron` properties and can be disabled entirely with `app.eol.enabled=false`. Each job writes a `SyncRun` row for queue visibility.

Executors:

- `ingestionExecutor`: concurrent ingest and GitHub source execution
- `integrationQueueExecutor`: serialized integration/read-model work
- the durable delta queue itself is polled every 2 seconds and batches up to 100 pending rows per pass

## Key Configuration

- Security: `APP_API_KEY`, `APP_CREATOR_KEY`, `APP_CREDENTIAL_ENCRYPTION_KEY`, `APP_REQUIRE_PRODUCTION_SECRETS`, `APP_REQUIRE_TENANT_CONTEXT`, `APP_ALLOW_HEADER_TENANT_SELECTION`, `APP_JWT_*`
- Feature flags: `FEATURE_VEX_POLICY_ENABLED`, `FEATURE_VEX_RISK_MODIFIERS_ENABLED`, `FEATURE_VEX_ROLLOUT_CONTROLS_ENABLED`, `FEATURE_VEX_ROLLOUT_BACKFILL_ENABLED`, `FEATURE_SOFTWARE_MODEL_ENABLED`
- EOL: `app.eol.enabled` (default `true`), `app.eol.catalog-refresh-cron`, `app.eol.release-refresh-cron`, `app.eol.resolve-mappings-cron`, `app.eol.denormalize-cron`, `app.eol.lifecycle-date-sweep-cron`
- NVD: `NVD_API_KEY`, `NVD_API_KEY_FILE`, `NVD_*`
- GitHub: `GITHUB_API_TOKEN`, `GITHUB_API_TOKEN_FILE`, `GITHUB_*`
- SBOM fetch: `SBOM_FETCH_MAX_PAYLOAD_BYTES`, `SBOM_FETCH_ALLOWED_HOSTS`, `SBOM_FETCH_ALLOW_USER_AUTH_HEADER`
- CSAF/GHSA/HTTP tuning: `CSAF_*`, `GHSA_*`, `HTTP_*`
- Asset lifecycle: `ASSET_STALE_DAYS_TO_INACTIVE`
- Archive storage: `ARCHIVE_LOCAL_PATH`
- CMDB: `CMDB_SERVICENOW_*`, `CMDB_SCCM_*` (JDBC URL, credentials, mock mode)
- AWS Discovery: configured per-tenant via `aws_discovery_configs` (no global env)
- OpenAI: `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL` (default `gpt-4o-mini`), `OPENAI_ENABLED`

## Current Caveats

- Runtime workspace handling is currently single-workspace. `WorkspaceService` resolves and caches the active workspace at startup, request-scoped tenant context is derived from that cached workspace, and controllers should depend on `WorkspaceService` rather than request-time tenant fallback while the broader multi-tenant runtime rollout continues.
- `POST /api/cve-detail/{cveId}/suppress` is fully implemented: persists suppression via `OrgCveRecordService.suppress()` and suppresses related findings via `FindingService.suppressFindingsForVulnerability()`.
- Flyway owns the PostgreSQL startup path. Remaining schema cleanup is now mostly historical normalization rather than runtime compatibility work.
- The vulnerability optimization is only partially landed: archive/snippet fields exist, but legacy CVSS/source/status fields are still present on `Vulnerability` for compatibility.

## Local Run

```bash
cd backend
mvn spring-boot:run
```
