# VulnWatch Backend

Last updated: 2026-03-08

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
- Flyway-managed PostgreSQL schema with `spring.jpa.hibernate.ddl-auto=none`

## Security Model

- `ApiKeyAuthenticationFilter` authenticates every `/api/**` request through `X-API-Key`.
- `X-Creator-Key` grants `ROLE_CREATOR` when it matches the configured creator key.
- `/api/operations/**` requires `ROLE_CREATOR`.
- `/actuator/health` and `/actuator/info` are open.
- CORS allow-list is driven by `app.cors.allowed-origins`.

The UI also sends `X-Tenant-ID` and `X-User-ID`; several newer workflow endpoints depend on those headers directly.

## Local Database Runtime

Default local runtime:

```bash
cd backend
mvn spring-boot:run
```

If an existing local PostgreSQL `vulnwatch` database was created before the Flyway migration files stabilized, repair the Flyway history once:

```bash
cd backend
mvn -q \
  -Dflyway.url=jdbc:postgresql://localhost:5432/vulnwatch \
  -Dflyway.user="$USER" \
  -Dflyway.password= \
  -Dflyway.locations=filesystem:src/main/resources/db/migration/postgres \
  flyway:repair
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
- `GET /api/dashboard`
- `GET /api/dashboard/applicable-software`
- `GET /api/dashboard/impacted-cves`
- `GET /api/dashboard/cve-inventory-map`
- `GET /api/operations/dashboard`

### Findings and Policy

- `GET /api/findings`
- `GET /api/findings/filters`
- `GET /api/risk-policy`
- `POST /api/risk-policy`
- `POST /api/configurations/clean-all`

### Inventory and Assets

- `GET /api/inventory/components`
- `GET /api/inventory/components/filters`
- `GET /api/assets`
- `POST /api/assets/cmdb-sync`
- `GET /api/sbom-uploads`

### Vulnerability Intelligence

- `GET /api/vulnerability-intelligence`
- `GET /api/vulnerability-intelligence/filters`
- `GET /api/vulnerability-intelligence/sources`
- `GET /api/vulnerability-intelligence/{externalId}`
- `GET /api/vulnerability-intelligence/org-cves`
- `POST /api/vulnerability-intelligence/org-cves/recompute`
- `GET /api/vulnerabilities/{externalId}`

### Ingestion and Automation

- `POST /api/sbom-upload`
- `POST /api/sbom-fetch`
- `POST /api/sbom-fetch/github`
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
- `POST /api/github-sbom-sources/{id}/run`
- `POST /api/demo/seed`

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
- `POST /api/operations/vulnerability-archive/migrate`
- `GET /api/operations/vulnerability-archive/status`
- `GET /api/operations/vulnerability-archive/{externalId}/description`
- `GET /api/operations/vulnerability-archive/{externalId}/raw-payload`

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

### 2. Vulnerability Intelligence Ingestion

`VulnerabilityIngestionService` pulls data from NVD, KEV, GHSA, CSAF, VEX, and advisory feeds. The ingest path:

1. stores source observations
2. merges canonical vulnerability rows
3. refreshes the vulnerability read model
4. builds normalized target rows and config expressions
5. triggers CVE delta recomputation
6. updates org-CVE and component exposure projections

### 3. Correlation and Exposure Projection

The active correlation model is deterministic and CPE-first:

- candidates are generated by joining `inventory_component_cpe_map` with `vulnerability_targets.cpe_id`
- version checks are applied by `ApplicabilityDecisionService`
- precedence is resolved across NVD, GHSA, CSAF/advisories, and VEX overlays
- component-level state is projected into `component_vulnerability_states`
- tenant-level CVE rollups are projected into `org_cve_records`
- finding creation/update logic is managed by `FindingService`

Observed `matchedBy` evidence values are CPE-based, such as:

- `cpe-indexed-direct+version`
- `cpe-indexed-fallback+version`

### 4. CVE Workflow Layer

The newer CVE workflow APIs add:

- investigations
- applicability assessments
- manual finding creation
- export/report responses
- org-level CVE drill-down data assembly

These APIs depend on `X-Tenant-ID` and `X-User-ID`, and are currently consumed by the org-CVE drawer in the frontend.

## Scheduling and Async Execution

Scheduled jobs currently defined in code:

- `01:00` daily: NVD incremental sync plus KEV sync
- `01:15` daily: GHSA sync
- `01:45` daily: Microsoft and Red Hat CSAF/VEX sync
- `02:05` daily: mark stale assets inactive
- `02:30` daily: VEX staleness recompute sweep
- every `5` minutes: run enabled GitHub SBOM sources
- every `15` minutes: reopen expired suppressions
- hourly: auto-close findings by policy

Executors:

- `ingestionExecutor`: concurrent ingest and GitHub source execution
- `integrationQueueExecutor`: serialized integration/read-model work
- `findingDeltaExecutor`: serialized finding delta queue processing

## Key Configuration

- Security: `APP_API_KEY`, `APP_CREATOR_KEY`
- Feature flags: `FEATURE_VEX_POLICY_ENABLED`, `FEATURE_VEX_RISK_MODIFIERS_ENABLED`, `FEATURE_SOFTWARE_MODEL_ENABLED`
- NVD: `NVD_API_KEY`, `NVD_API_KEY_FILE`, `NVD_*`
- GitHub: `GITHUB_API_TOKEN`, `GITHUB_API_TOKEN_FILE`, `GITHUB_*`
- SBOM fetch: `SBOM_FETCH_MAX_PAYLOAD_BYTES`, `SBOM_FETCH_ALLOWED_HOSTS`, `SBOM_FETCH_ALLOW_USER_AUTH_HEADER`
- CSAF/GHSA/HTTP tuning: `CSAF_*`, `GHSA_*`, `HTTP_*`
- Asset lifecycle: `ASSET_STALE_DAYS_TO_INACTIVE`
- Archive storage: `ARCHIVE_STORAGE_BACKEND`, `ARCHIVE_LOCAL_PATH`, `ARCHIVE_S3_BUCKET`

## Current Caveats

- Runtime tenant handling is still effectively single-tenant even though the schema is tenant-aware. Most controllers resolve `TenantService.getDefaultTenant()`.
- `POST /api/cve-detail/{cveId}/suppress` currently returns a suppression response but does not persist suppression fields. The controller still contains a `TODO` for that write path.
- Inventory APIs currently expose component pages and filter values only. Older documentation around software-model endpoints no longer matches the codebase.
- Flyway owns the PostgreSQL startup path. Remaining schema cleanup is now mostly historical normalization rather than runtime compatibility work.
- The vulnerability optimization is only partially landed: archive/snippet fields exist, but legacy CVSS/source/status fields are still present on `Vulnerability` for compatibility.

## Local Run

```bash
cd backend
mvn spring-boot:run
```
