# VulnWatch Backend Documentation

Last updated: 2026-03-03

## What The Backend Does

The backend ingests SBOMs and vulnerability intelligence, correlates them using deterministic CPE-based matching, and projects tenant risk outcomes into findings.

Current behavior in code:

- Correlation candidates are generated from CPE only (`cpe_id` joins).
- Version applicability checks are deterministic (`exact`, `introduced/fixed`, ranged bounds).
- VEX/CSAF data is used as an overlay and precedence input.
- New finding row creation is intentionally disabled; recomputes update/resolve existing findings.

## Runtime Stack

- Java 17
- Spring Boot 3.3
- Spring Web + Spring Data JPA + Spring Security
- H2 file DB by default (`./data/vulnwatch`)
- Optional PostgreSQL profile (`--spring.profiles.active=postgres`)
- Entity-first schema evolution (`spring.jpa.hibernate.ddl-auto=update`)

## Security Model

- All `/api/**` routes require `X-API-Key`.
- `/api/operations/**` requires creator access (`ROLE_CREATOR`), derived from `X-Creator-Key`.
- If `APP_CREATOR_KEY` is not set, creator routes are accessible in local mode.
- CORS for `/api/**` is controlled by `app.cors.allowed-origins`.

## Core Services And Flows

### 1) SBOM Ingestion

Entry points:

- `POST /api/sbom-upload`
- `POST /api/sbom-fetch`
- `POST /api/sbom-fetch/github`

Flow:

1. Validate payload size and source constraints.
2. Upsert asset and create `sbom_uploads` evidence row.
3. Parse CycloneDX/SPDX components.
4. Upsert `inventory_components` as `ACTIVE`; retire removed components as `RETIRED`.
5. Resolve software identity/model metadata.
6. Normalize CPEs into `cpe_dim`.
7. Sync bridge rows in `inventory_component_cpe_map`.
8. Trigger per-component incremental recompute (`recomputeOnSoftwareDelta`).

### 2) Vulnerability Ingestion

Entry points:

- `POST /api/ingestion/nvd-sync`
- `POST /api/ingestion/nvd-full-sync`
- `POST /api/ingestion/kev-sync`
- `POST /api/ingestion/ghsa-sync`
- `POST /api/ingestion/csaf/microsoft-sync`
- `POST /api/ingestion/csaf/redhat-sync`
- `POST /api/ingestion/advisories`

Flow:

1. Ingest source payloads and upsert observations.
2. Merge canonical vulnerability rows (`vulnerabilities`).
3. Maintain read model (`vulnerability_intel_summary`, `vulnerability_intel_summary_sources`).
4. Upsert normalized targets (`vulnerability_targets`), including CPE targets linked to `cpe_dim`.
5. Trigger incremental recompute by changed vulnerability IDs (`recomputeOnCveDelta`).
6. For VEX profile updates, apply overlay deltas (`applyVexDeltaForVulnerability`).

### 3) Correlation And Decisioning

Main path:

- `CorrelationCandidateService` builds candidate sets from `inventory_component_cpe_map` + `vulnerability_targets(cpe_id)`.
- Candidate methods in evidence:
  - `cpe-indexed-direct+version`
  - `cpe-indexed-fallback+version`
- `ApplicabilityDecisionService` evaluates version constraints and VEX policy/freshness/trust logic.
- `PrecedenceResolverService` resolves by source priority (`vex` > `csaf/advisory/ghsa` > `nvd` > `kev`).
- `FindingService` updates existing findings, resolves stale ones, and writes audit evidence.

## API Surface (Grouped)

General:

- `GET /api/auth/context`
- `GET /api/dashboard`
- `GET /api/operations/dashboard` (creator)

Vulnerability intelligence:

- `GET /api/vulnerability-intelligence`
- `GET /api/vulnerability-intelligence/filters`
- `GET /api/vulnerability-intelligence/sources`
- `GET /api/vulnerability-intelligence/{externalId}`
- `GET /api/vulnerabilities/{externalId}`

Inventory and assets:

- `GET /api/inventory/components`
- `GET /api/inventory/components/filters`
- `GET /api/inventory/software-models`
- `GET /api/assets`
- `POST /api/assets/cmdb-sync`

Policy and automation:

- `GET /api/risk-policy`
- `POST /api/risk-policy`
- `GET /api/github-sbom-sources`
- `POST /api/github-sbom-sources`
- `PUT /api/github-sbom-sources/{id}`
- `POST /api/github-sbom-sources/{id}/run`

Operational ingestion:

- `GET /api/sync-runs`
- `GET /api/sbom-uploads`
- `POST /api/demo/seed`
- Ingestion endpoints listed earlier.

## Scheduling And Async Execution

Scheduled jobs:

- Daily 01:00: NVD incremental + KEV sync.
- Daily 02:05: mark stale assets inactive.
- Every 5 minutes: execute enabled GitHub SBOM sources.

Executors:

- `ingestionExecutor`: concurrent ingestion workers.
- `integrationQueueExecutor`: serialized queue for integration work/read-model maintenance.

## Key Configuration Variables

- `APP_API_KEY`, `APP_CREATOR_KEY`
- `FEATURE_VEX_POLICY_ENABLED`, `FEATURE_VEX_RISK_MODIFIERS_ENABLED`
- `NVD_API_KEY` or `NVD_API_KEY_FILE`
- `GITHUB_API_TOKEN` or `GITHUB_API_TOKEN_FILE`
- `SBOM_FETCH_MAX_PAYLOAD_BYTES`, `SBOM_FETCH_ALLOWED_HOSTS`, `SBOM_FETCH_ALLOW_USER_AUTH_HEADER`
- `CSAF_*`, `GHSA_*`, `HTTP_*`, `ASSET_STALE_DAYS_TO_INACTIVE`

## Local Run

```bash
cd backend
mvn spring-boot:run
```
