# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Backend

```bash
cd backend
mvn spring-boot:run          # start the API server (port 8080)
mvn test                     # unit tests
mvn -Ppostgres-it test       # unit + PostgreSQL integration tests
```

To repair Flyway history after schema drift:
```bash
cd backend
mvn -q \
  -Dflyway.url=jdbc:postgresql://localhost:5432/vulnwatch \
  -Dflyway.user="$USER" \
  -Dflyway.password= \
  -Dflyway.locations=filesystem:src/main/resources/db/migration/postgres \
  flyway:repair
```

### Frontend

```bash
cd frontend
npm install
npm run dev      # dev server on port 5173
npm run build    # tsc -b --force && vite build
npm run test:unit  # vitest run (non-watch)
```

There is no lint script in `package.json`.

## Architecture

### System Shape

VulnWatch is a security operations prototype: SBOM ingestion → vulnerability intelligence ingestion → deterministic CPE-based correlation → finding projection and workflow.

- `frontend/` — React 18 + TypeScript + Vite SPA
- `backend/` — Java 17 + Spring Boot 3.3.2, Spring Data JPA, Spring Security
- Database — PostgreSQL at `jdbc:postgresql://localhost:5432/vulnwatch`
- Schema — Flyway-owned migrations in `backend/src/main/resources/db/migration/postgres/` (`ddl-auto=none`)

### Backend Package Layout (`com.prototype.vulnwatch`)

| Package | Contents |
|---|---|
| `controller/` | ~20 REST controllers under `/api/**` |
| `service/` | ~54 business-logic services |
| `domain/` | JPA entities (assets, inventory, vulns, findings, policies, CMDB, EOL, SCCM) |
| `dto/` | API request/response objects |
| `repo/` | Spring Data JPA repositories |
| `client/` | External API clients (NVD, GHSA, CSAF, EPSS, GitHub, ServiceNow, SCCM, endoflife.date) |
| `config/` | Spring beans and security configuration |
| `util/` | CPE handling, version comparison, SBOM parsing |

### Core Data Flow

1. **Inventory in** — SBOMs (upload, endpoint fetch, GitHub repo/GHCR) or ServiceNow/SCCM CMDB sync write `assets`, `inventory_components`, `software_identities`, `software_instances`, and normalize CPEs into `cpe_dim` + `inventory_component_cpe_map`.
2. **Vulnerability intel in** — NVD, KEV, GHSA, Microsoft/Red Hat CSAF/VEX, advisory imports populate `vulnerabilities`, `vulnerability_targets`, and read-model projections.
3. **Correlation** — CPE joins between `inventory_component_cpe_map` and `vulnerability_targets`, version-checked by `ApplicabilityDecisionService`, write `component_vulnerability_states`.
4. **Projection** — States roll up to `org_cve_records` (one row per CVE per tenant). `FindingService` drives finding create/reopen/resolve.
5. **EOL pipeline** — 4-stage async job: catalog refresh → release cycles → slug resolution → denormalization into `inventory_components.is_eol / eol_days_remaining`.

### Projection Tables (Central to Read Performance)

- `component_vulnerability_states` — component-level CPE applicability truth
- `org_cve_records` — tenant/CVE rollup used by CVE Assessment Workbench UI
- `vulnerability_intel_summary` — vuln list read model (all CVEs, not org-filtered)
- `software_inventory_items` — flattened software inventory for reporting
- `software_identity_summary` — per-identity aggregation (asset/component/version counts, EOL breakdown) for Software Identities view
- `quality_issue_projection` — data quality issues by domain/severity for Operations Quality view

### Security Model

- Every `/api/**` request requires `X-API-Key`.
- `X-Creator-Key` grants `ROLE_CREATOR`; required for `/api/operations/**`.
- `X-Tenant-ID` and `X-User-ID` are used directly by CVE workflow endpoints.
- Local defaults: API key `change-me-in-prod`, creator key `local-creator`, tenant `1`, user `local-analyst`.

### Frontend Navigation

`src/App.tsx` uses **React Router v6** with path-based routing. `src/app/routes.ts` owns all typed path-builder helpers. Legacy query-param URLs (e.g. `?tab=inventory`) are redirected via `buildLegacyCompatiblePath()` on first render.

Top-level sections and their paths: Overview (`/`) → Findings (`/findings`) → Operational Dashboard (`/operations/*`) → Vulnerability Repository (`/vuln-repo/*`) → Inventory (`/inventory/*`) → End-of-Life (`/end-of-life`) → Connect (`/connect/*`) → Configurations (`/configurations`).

Overview is reserved for risk metrics and risk-focused summaries only. Do not place operational, pipeline, quality, freshness, correlation-efficiency, or CSAF/VEX analytics panels on Overview; those belong under Operational Dashboard.
Correlation Efficiency and CSAF/VEX Quality Analytics live under Operations → Pipeline.

All API calls go through `src/api/client.ts`. Base URL defaults to `http://localhost:8080/api` (via `VITE_API_BASE`). Auth headers are injected on every request.

### TypeScript Types

Types are **feature-colocated**, not centralised. `src/types/index.ts` re-exports them but the source of truth is in each feature directory:

- `src/features/findings/types.ts` — `Finding` and related
- `src/features/cve-workbench/types.ts` — `OrgSpecificCveExposureRecord`, `CveDetail`, etc.
- `src/features/configurations/types.ts` — `RiskPolicy` (includes 6 triage weight fields)
- `src/features/inventory/types.ts` — inventory-specific types
- `src/features/connect/types.ts` — connector and CMDB config types
- `src/types/ownership.ts` — `OwnershipSummary` and related

Always edit the source file in the feature directory, not the re-export in `types/index.ts`.

### Two Distinct CVE Views

These are separate pages backed by separate API endpoints — do not confuse them:

- **`/vuln-repo/org-cves`** → `VulnRepoOrgCvePage` — **"Unified Vulnerability Records"**
  Queries `org_cve_records` via `useOrgSpecificCvesQuery`. Shows only CVEs correlated
  to the org's software inventory. Primary analyst triage and investigation workflow.
  CVEs here always have a CPE match; `matchedAssetCount` / `matchedSoftwareCount`
  reflect the extent of that match.

- **`/vuln-repo/vulnerabilities`** → `VulnRepoVulnerabilitiesPage` — **"Vulnerability Intelligence"**
  Queries `vulnerability_intel_summary` via `useVulnRepoVulnerabilitiesQuery`. Shows
  ALL CVEs ingested from NVD/GHSA/KEV regardless of inventory match. CVEs with
  `matchedSoftwareCount = 0` are expected here — they exist in the global feed but
  have no org inventory correlation.

The Vulnerability Repository sub-nav shows: **Dashboard | Unified Records | Intelligence**.

### S.AI Scoring Layer (`src/lib/riskScoring.ts`)

Pure TypeScript module — no React, no API calls. Computes two frontend-only scores entirely from data already returned by existing API endpoints:

- **`computeCveRiskScore(item, policy?)`** → S.AI Risk Score (0–10, CVE level)
  Stages: CVE Published (CVSS + EPSS) → In CISA KEV → Org Exposure (blast radius) →
  EOL Risk → No Patch → Applicability decision → Findings Created.
  Displayed as a horizontal left-to-right phase timeline via `CveRiskScorePanel`
  injected at the top of the CVE Assessment Workbench.

- **`computeFindingPriorityScore(finding, policy?)`** → S.AI Priority (0–10, finding level)
  Signals: exploitability (KEV/EPSS weight), SLA breach proximity, missing owner,
  EOL component, severity boost, VEX confirmed affected.
  Shown as a column in the Findings table and a row in Finding Detail.

Both functions accept an optional `PolicyWeights` parameter — the 6 triage fields from
`RiskPolicy`. Call sites fetch these via `useRiskPolicyQuery()` and pass `policyQuery.data`
in. `DEFAULT_POLICY` (all weights = 1.0) preserves original behavior when policy is
unavailable. The `PolicyWeights` type mirrors the 6 `triage*` fields on `RiskPolicy`:
`triageExploitabilityWeight`, `triageBlastRadiusWeight`, `triageEolRiskWeight`,
`triageSlaBreachWeight`, `triageMissingOwnerBoost`, `triagePatchGapBoost`.

### Configurations Page (`/configurations`)

Sidebar-nav layout. Sections in order (leftmost first):

| # | Tab | Content |
|---|---|---|
| 1 | **SLA & Remediation** | Remediation deadlines per severity + asset criticality SLA multipliers |
| 2 | **Vulnerability Scoring** | CVSS/EPSS/KEV weights, VEX modifiers, critical/high score thresholds |
| 3 | **S.AI Prioritization** `AI` | 6 triage urgency signal weight sliders + live Triage Score Simulator |
| 4 | **Workflow Automation** | Auto-close rules (enabled/days), finding generation mode (AUTO/MANUAL) |
| 5 | **Developer Tools** | Prototype data reset — wipes all inventory, findings, and vuln intel |

All sections persist to a single `RiskPolicy` record via `PUT /api/risk-policy`.
`applyTriageDefaults()` normalises API responses for backends that predate the V1062 migration
(fills missing triage fields with sensible defaults rather than crashing).

### Connect Page Architecture

`ConnectPage` (`/connect/:connectView?`) is a two-category connector catalog with three views:
`sources` (default), `integration-run-queue`, and `processing-jobs`.

**Connector categories:**

- **Vulnerability Intelligence** — `nvd-api`, `cisa-kev`, `ghsa-feed`, `microsoft-csaf-vex`, `redhat-csaf-vex`, `advisory-feed`
- **Inventory Sources** — `sbom-endpoint`, `sbom-github`, `servicenow-cmdb`, `sccm-cmdb`, `endoflife-date`

Clicking a connector card renders `ConnectorDetailContent` which delegates to a focused component per connector. Adding a new connector requires: add to `ConnectorId` union, `CONNECTORS` array, the appropriate category list (`VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS` or `INVENTORY_SOURCE_CONNECTOR_IDS`), and a `ConnectorDetailContent` case.

Key connector components:
- `SccmConnectorPage` — SCCM/MECM CMDB sync (discovery, auth, field mapping, sync schedule)
- `VulnIntelConnectorPage` / `VulnIntelConfigPage` — NVD, GHSA, KEV, CSAF source configuration
- `IntegrationRunQueuePage` — live run queue for all connector sync jobs
- `GithubPipelineManager` — GitHub SBOM source management
- `IngestionPage` — SBOM endpoint / file upload

### Adding a Database Migration

Create `backend/src/main/resources/db/migration/postgres/V{next}__description.sql`. Flyway applies migrations in version order on startup. Never edit an already-applied migration file.

**Current watermark: V1062** (`sccm_cmdb_last_sync_at`). The next migration must be **V1063**.

### Scheduled Jobs

| Time | Job |
|---|---|
| `00:15` daily | Lifecycle date sweep (EOL/EOS transitions) |
| `01:00` daily | NVD incremental + KEV sync |
| `01:15` daily | GHSA sync |
| `01:45` daily | Microsoft + Red Hat CSAF/VEX sync |
| `02:05` daily | Mark stale assets inactive |
| `02:30` daily | VEX staleness recompute |
| `03:15` daily | EPSS score refresh |
| `02:00` Sunday | EOL catalog refresh (stage 1) |
| `03:00` Sunday | EOL release data refresh (stage 2) |
| `03:30` Sunday | EOL slug resolution (stage 3) |
| `04:00` Sunday | EOL denormalization (stage 4) |
| Every 5 min | Run enabled GitHub SBOM sources |
| Every 15 min | Reopen expired suppressions |
| Hourly | Policy-based auto-close findings |

### Known Limitations

- `POST /api/cve-detail/{cveId}/suppress` persists suppression state via `OrgCveRecordService.suppress()` and returns a `SuppressionResponse`. Suppression expiry is handled by the 15-minute reopen job.
- Schema is tenant-aware but runtime is effectively single-tenant; most controllers call `TenantService.getDefaultTenant()`.
- The live CVE workflow is the CVE Assessment Workbench at `/vuln-repo/org-cves`. `CveDetailPage.tsx` exists but is not mounted in the router.
- GHCR attestation ingestion does not yet perform cryptographic signature verification.
- AI-assisted features (investigation summary, AI solution, AI actions) call OpenAI and are gated by `OPENAI_ENABLED`. Results are persisted on `org_cve_records` so subsequent reads do not re-call the API.
- ServiceNow incident creation (`POST /api/cve-detail/{cveId}/servicenow-incident`) is one-way — changes in ServiceNow are not reflected back.
- S.AI Risk Score and S.AI Priority are computed entirely in the browser from existing API data — they are not stored in the database and recalculate on every render.
- SCCM sync (`SccmCmdbSyncService`) performs asset discovery and field mapping but does not yet support incremental delta sync — each run is a full sweep.

### GitHub Token

For GitHub SBOM / GHCR / GHSA features, place a token in `backend/secrets/github-api-token` (gitignored). Resolution order: `GITHUB_API_TOKEN_FILE` → `backend/secrets/github-api-token` → `GITHUB_API_TOKEN`.
