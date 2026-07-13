# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Backend

```bash
cd backend
mvn spring-boot:run                                    # start the API server (port 8080, default profile)
mvn spring-boot:run -Dspring-boot.run.profiles=local   # local profile: enables JWT auth + header tenant selection
mvn test                                               # unit tests (Surefire) + JaCoCo report at target/site/jacoco/index.html
mvn -Ppostgres-it verify                               # unit + Postgres integration tests (Failsafe, requires Postgres)
mvn test -Dtest=MyServiceTest                          # run a single unit test class
mvn -Ppostgres-it verify -Dit.test=MyServicePostgresIntegrationTest  # run a single IT class
```

Surefire excludes `**/*PostgresIntegrationTest.java`; Failsafe picks them up at the `integration-test` / `verify` phase. `mvn -Ppostgres-it test` runs unit tests only — use `verify` to also run the Postgres ITs.

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

`-Dflyway.schemas=tenant_default` is required — the `flyway_schema_history` table lives in `tenant_default`, not the public schema. Omitting it silently repairs the wrong table and the mismatch persists.

If the error is `Found more than one migration with version N` (after a migration file is renamed/replaced), run `mvn clean` first to purge stale copies from `target/classes/` before restarting.

### Frontend

```bash
cd frontend
npm install
npm run dev           # dev server on port 5173 (strictly)
npm run lint          # eslint .
npm run typecheck     # tsc -b --noEmit
npm run build         # tsc -b --force && vite build
npm run test:unit     # vitest run (non-watch)
npm run test:coverage # vitest run --coverage (enforces line/branch thresholds)
npx vitest run src/pages/FindingsPage.test.tsx  # run a single test file
```

Frontend CI gates: `npm run lint` → `npm run typecheck` → `npm run build` → `npm run test:coverage` (vitest with coverage thresholds enforced).

Backend CI gates: `mvn -q verify` runs Surefire + Failsafe + JaCoCo `check` (line-coverage floor) + SpotBugs.

## Architecture

### System Shape

VulnWatch is a security operations prototype: SBOM ingestion → vulnerability intelligence ingestion → deterministic CPE-based correlation → finding projection and workflow.

- `frontend/` — React 18 + TypeScript + Vite SPA
- `backend/` — Java 17 + Spring Boot 3.3.2, Spring Data JPA, Spring Security
- Database — PostgreSQL at `jdbc:postgresql://localhost:5432/vulnwatch`
- Schema — Flyway-owned migrations in `backend/src/main/resources/db/migration/postgres_reset/` (`ddl-auto=none`)

See `backend/CLAUDE.md` and `frontend/CLAUDE.md` for directory-specific runtime detail.

### Backend Package Layout (`com.prototype.vulnwatch`)

| Package | Contents |
|---|---|
| `controller/` | 41 REST controllers under `/api/**` |
| `service/` | 236 business-logic services |
| `domain/` | 121 JPA entities (assets, inventory, vulns, findings, policies, CMDB, EOL, SCCM, AWS/Azure discovery, campaigns, BOM/CBOM) |
| `dto/` | 257 API request/response objects |
| `repo/` | 77 Spring Data JPA repositories |
| `client/` | 21 external API clients (NVD, EUVD, JVN, GHSA, CSAF, EPSS, GitHub, ServiceNow, SCCM, endoflife.date, AWS, Azure, OpenAI, Resend) |
| `config/` | Spring beans and security configuration (`SecurityConfig`, `ApiKeyAuthenticationFilter`, `TenantAwareDataSource`, `ProductionSafetyValidator`) |
| `security/` | `SensitiveTenantAction` annotation and interceptor for sensitive cross-tenant operations |
| `util/` | CPE handling, version comparison, SBOM parsing |

Two controllers are new and undocumented until now: `CampaignController` (`/api/campaigns` — remediation campaign lifecycle, see below) and `CbomController` (`/api/bom/cbom` — cloud bill-of-materials posture), alongside `BomController` (`/api/bom`) for general BOM ingestion and `AzureDiscoveryController` (`/api/connectors/azure-discovery`).

### Core Data Flow

1. **Inventory in** — SBOMs (upload, endpoint fetch, GitHub repo/GHCR), BOM/CBOM uploads, or ServiceNow/SCCM CMDB sync write `assets`, `inventory_components`, `software_identities`, `software_instances`, and normalize CPEs into `cpe_dim` + `inventory_component_cpe_map`. AWS and Azure Discovery connectors add cloud-resource assets via SSM / subscription APIs respectively.
2. **Vulnerability intel in** — NVD, KEV, GHSA, Microsoft/Red Hat CSAF/VEX, EUVD, JVN, advisory imports populate `vulnerabilities`, `vulnerability_targets`, and read-model projections.
3. **Correlation** — CPE joins between `inventory_component_cpe_map` and `vulnerability_targets`, version-checked by `ApplicabilityDecisionService`, write `component_vulnerability_states`.
4. **Projection** — States roll up to `org_cve_records` (one row per CVE per tenant). `FindingService` drives finding create/reopen/resolve.
5. **EOL pipeline** — 4-stage async job: catalog refresh → release cycles → slug resolution → denormalization into `inventory_components.is_eol / eol_days_remaining`.
6. **Remediation Campaigns** — `CampaignController`/`CampaignService` group findings/CVEs into a tracked remediation effort with lifecycle states (DRAFT, ACTIVE, PAUSED, BLOCKED, IN_REVIEW, CLOSED, CANCELLED), per-item exceptions, notify groups, and a watchlist. Frontend at `/vuln-repo/campaigns`.

### Projection Tables (Central to Read Performance)

- `component_vulnerability_states` — component-level CPE applicability truth
- `org_cve_records` — tenant/CVE rollup used by CVE Assessment Workbench UI
- `vulnerability_intel_summary` — vuln list read model (all CVEs, not org-filtered)
- `software_inventory_items` — flattened software inventory for reporting
- `software_identity_summary` — per-identity aggregation (asset/component/version counts, EOL breakdown) for Software Identities view
- `quality_issue_projection` — data quality issues by domain/severity for Operations Quality view

### Security Model

Two authentication paths, handled by `ApiKeyAuthenticationFilter`:

**API key** (`X-API-Key` header, enabled when `APP_ALLOW_API_KEY_AUTH=true`):
- Grants `ROLE_OPERATOR` + `ROLE_SECURITY_ANALYST` to all callers.
- `X-Creator-Key` additionally grants `ROLE_CREATOR`, `ROLE_PLATFORM_OWNER`, `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN`.
- `X-User-ID` sets the user identity (defaults to `APP_DEFAULT_USER_ID` / `local-analyst`).
- Local defaults: api-key `change-me-in-prod`, no creator-key configured (all callers get creator-level access).

**JWT Bearer** (`Authorization: Bearer <token>`):
- Active only when `APP_JWT_ISSUER_URI` is set (wires a `JwtDecoder` bean).
- Token decoded and passed to `JwtTenantAuthenticationService`, which resolves roles from the configured claim (default `roles`; namespaced claims ending in `/roles` also work).
- Roles from JWT are mapped to Spring `GrantedAuthority` values.

Authorization rules: `/api/platform/**` and `/api/operations/**` require `ROLE_PLATFORM_OWNER`. `/api/operations/quality/**` also permits `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN`, `ROLE_SECURITY_ANALYST`, and `ROLE_READ_ONLY_AUDITOR`. All other `/api/**` require authentication. Public: OPTIONS, `/actuator/health`, `/actuator/info`, `POST /api/auth/login`, `POST /api/demo-requests`, `/api/demo-invites/**`.

`APP_ALLOW_HEADER_TENANT_SELECTION=true` enables local header-based tenant selection via `X-Tenant-ID`; must be disabled in production.

### Multi-Tenancy Status

Schema-per-tenant isolation is fully implemented, not aspirational: `TenantAwareDataSource` sets `search_path` + `app.current_tenant_id` per connection checkout (reset on return), `TenantSchemaService` clones `tenant_default` (tables, sequences, defaults, FKs, and RLS policies) to provision new tenant schemas, and `ProductionSafetyValidator` runs 11+ startup checks gating unsafe config in production. `TenantService.getDefaultTenant()` is no longer called from any controller or service — that single-tenant fallback pattern has been removed. Row-level security policies are created on each tenant schema at provisioning time, but full RLS *enforcement* rollout across existing production tenants is intentionally gated behind `V29__tenant_rls_rollout_gate.sql` pending verification that the production/preprod database runtime role is non-superuser and lacks `BYPASSRLS`.

### Frontend Navigation

`src/App.tsx` uses **React Router v7** (`react-router-dom` 7.x) with path-based routing. `src/app/routes.ts` owns all typed path-builder helpers. Legacy query-param URLs (e.g. `?tab=inventory`) and the older `/vulnerability-intelligence/*` paths are redirected to their current equivalents on first render.

Top-level routes and their paths:

| Path | Component | Purpose |
|------|-----------|---------|
| `/` | Role-based redirect | → `/exposure`, `/configurations`, or `/platform/tenants` depending on actor role |
| `/exposure` | `ExposureDashboardPage` | Risk-focused overview (Overview) |
| `/findings` | `FindingsPage` | Active findings |
| `/findings/:displayId` | `FindingDetailPage` | Single finding detail |
| `/operations/:operationsView?` | `OperationalDashboardPage` | Default `pipeline`; sub-views `pipeline`, `platform-health` (`quality` and older keys alias to `pipeline`) |
| `/vuln-repo` | `VulnRepoDashboardPage` | Vulnerability Repository dashboard |
| `/vuln-repo/org-cves/:cveId?` | `VulnRepoOrgCvePage` | **Unified Records** — org-correlated CVEs (CVE Assessment Workbench) |
| `/vuln-repo/vulnerabilities` | `VulnRepoVulnerabilitiesPage` | **Intelligence** — all ingested CVEs (global feed) |
| `/vuln-repo/org-cves/:cveId/assets` | `VulnRepoCveAssetsPage` | Per-CVE affected asset breakdown |
| `/vuln-repo/org-cves/:cveId/software` | `VulnRepoCveSoftwarePage` | Per-CVE affected software breakdown |
| `/vuln-repo/campaigns` | `CampaignsPage` | Remediation campaign list |
| `/vuln-repo/campaigns/:id` | `CampaignDetailPage` | Campaign detail — lifecycle, exceptions, notify groups, watchlist |
| `/vuln-repo/software-assets` | `VulnRepoSoftwareAssetsPage` | Software-centric asset breakdown |
| `/vuln-repo/host-assets/:assetId` | `VulnRepoHostAssetRoute` | Host asset detail from vuln-repo context |
| `/vuln-repo/intel/:externalId` | `PlatformVulnIntelDetailPage` | Platform-scoped intel detail |
| `/inventory/:inventoryView?` | `InventoryPage` (dispatches sub-views) | Default `overview` |
| `/inventory/hosts/:assetId` | `InventoryHostAssetRoute` | Host asset detail |
| `/inventory/software-identities/:softwareIdentityId` | `SoftwareIdentityDetailRoute` | Software identity detail |
| `/connect/:connectView?` | `ConnectPage` | Default `sources`; also `connectors`, `run-history`, `processing-jobs` |
| `/admin/:adminView?` | `UserManagementPage` | Default `users`; tenant + service-account administration |
| `/platform/:platformView?` | `PlatformConsolePage` | Default `tenants`; platform-owner console |
| `/configurations/:configView?` | `ConfigurationsPage` | Default `sla`; risk policy, SLA, scoring, automation |
| `/login` | `LoginPage` | Credential login |

**`/end-of-life` no longer renders a dedicated EOL page** — it redirects to `/platform/eol` for platform-scope owners, or `/exposure` otherwise. **Legacy redirects:** `/vulnerability-intelligence*` paths redirect to their `/vuln-repo/*` equivalents.

Demo/public routes (outside auth boundary): `/demo`, `/demo/request`, `/demo/request/success`, `/demo/expired`, `/invite/:token`, `/tenant-invite/:token`.

Overview (`/exposure`) is reserved for risk metrics and risk-focused summaries only. Do not place operational, pipeline, quality, freshness, correlation-efficiency, or CSAF/VEX analytics panels on Overview; those belong under Operational Dashboard.
Correlation Efficiency and CSAF/VEX Quality Analytics live under Operations → Pipeline.

All API calls go through `src/api/client.ts`. Base URL defaults to `http://localhost:8080/api` (via `VITE_API_BASE`). Auth headers are injected on every request.

### TypeScript Types

Types are **feature-colocated**, not centralised. `src/types/index.ts` re-exports them but the source of truth is in each feature directory:

- `src/features/findings/types.ts` — `Finding` and related
- `src/features/cve-workbench/types.ts` — `OrgSpecificCveExposureRecord`, `CveDetail`, etc.
- `src/features/configurations/types.ts` — `RiskPolicy` (includes 6 triage weight fields), `OwnershipRuleResponse`, `OwnershipRuleRequest`, `SuppressionRule`
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

| # | Tab key | Label | Content |
|---|---------|-------|---------|
| 1 | `sla` | **SLA & Remediation** | Risk score thresholds (critical/high), remediation deadlines per severity, asset criticality SLA multipliers |
| 2 | `triage` | **S.AI Prioritization** `AI` | 6 triage urgency signal weight sliders + live Triage Score Simulator |
| 3 | `automation` | **Workflow Automation** | Auto-close rules (enabled/days), finding generation mode (AUTO/MANUAL) |
| 4 | `ownership` | **Ownership** | Rule-based user/group assignment; conditions stored in `ownership_rules` table (V1 baseline) |
| 5 | `vulnerability-sources` | **Vulnerability Sources** | Per-tenant feed filter rules; which sources participate in tenant correlation (`vulnerability_source_filter_configs`, V1 baseline) |
| 6 | `findings-score` | **Findings Score** | Custom attribute-based scoring rules (table + column + operator + value + weight); live simulator; max 10 columns; weights sum to 1.0; stored as `findings_score_config` JSONB in `risk_policies`; evaluated at query time by `FindingsScoreService`; returned as `findingsScore` (0–10) on every `FindingResponse`; `POST /api/risk-policy/recompute-findings-scores` triggers `FindingsScoreRecomputeService.recomputeAll()` for all OPEN findings |
| 7 | `suppress` | **Suppression Rules** | Create rules that suppress CVE or Finding records when matching conditions are met; each rule has name, state (DRAFT/APPROVED/IN_REVIEW/REJECTED/EXPIRED), record type (CVE/FINDING), valid from/to, execution order, and free-form reason; persisted to `suppression_rules` table via `GET/POST/PUT/DELETE /api/suppression-rules` |
| 8 | `auto-findings` | **Auto-Finding Rules** | Automatically create findings based on CVE, software, and asset criteria |

All sections except Ownership and Vulnerability Sources persist to a single `RiskPolicy` record via `PUT /api/risk-policy`.
`applyTriageDefaults()` normalises API responses for older backends that predate the 6 triage weight fields
(fills missing triage fields with sensible defaults rather than crashing).

### Connect Page Architecture

`ConnectPage` (`/connect/:connectView?`) is a multi-category connector catalog with views:
`sources` (default), `connectors`, `run-history`, and `processing-jobs`.

**Connector categories:**

- **Vulnerability Intelligence** — `nvd-api`, `cisa-kev`, `ghsa-feed`, `microsoft-csaf-vex`, `redhat-csaf-vex`, `advisory-feed`, `endoflife-date`, `euvd-feed` (ENISA EU Vulnerability Database), `jvn-feed` (Japan Vulnerability Notes)
- **CMDB / Inventory Sources** — `sbom-endpoint`, `sbom-github`, `bom-management` (SBOM/AI-BOM/CBOM/Vendor-BOM via URL or upload), `servicenow-cmdb`, `sccm-cmdb`
- **Cloud Discovery** — `aws-discovery`, `azure-discovery`

Clicking a connector card renders `ConnectorDetailContent` which delegates to a focused component per connector. Adding a new connector requires: add to `ConnectorId` union, `CONNECTORS` array, the appropriate category list, and a `ConnectorDetailContent` case.

Key connector components:
- `SccmConnectorPage` — SCCM/MECM CMDB sync (discovery, auth, field mapping, sync schedule)
- `AwsDiscoveryConnectorPage` — AWS EC2 discovery via SSM, multi-account via `aws_discovery_targets`
- `AzureDiscoveryConnectorPage` — Azure compute/platform resource discovery across subscriptions (mirrors the AWS connector; `CLIENT_SECRET` or `MANAGED_IDENTITY` auth)
- `VulnIntelConnectorPage` / `VulnIntelConfigPage` — NVD, GHSA, KEV, CSAF source configuration
- `NvdConnectorPage`, `KevConnectorPage`, `GhsaConnectorPage`, `MicrosoftCsafConnectorPage`, `RedhatCsafConnectorPage`, `AdvisoryConnectorPage` — per-feed configuration pages
- `IntegrationRunQueuePage` / `InventoryRunQueuePage` — live run queue surfaces
- `GithubPipelineManager` — GitHub SBOM source management
- `IngestionPage` — SBOM endpoint / file upload

### Adding a Database Migration

Create `backend/src/main/resources/db/migration/postgres_reset/V{next}__description.sql`. Flyway applies migrations in version order on startup. Never edit an already-applied migration file.

The migration directory is `postgres_reset/` (configured in `application.yml` as `classpath:db/migration/postgres_reset`). The baseline migration is `V1__platform_and_default_tenant_schemas.sql` — a large consolidated baseline (60+ tables) created when a prior drift-repair effort reset and renumbered the whole migration line; do not expect V1 to look like a "day one" schema. All statements use `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`, making the schema idempotent if replayed directly via psql. The current latest migration is `V41__azure_discovery_targets.sql`.

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
| `07:00` daily | ServiceNow incident status sync (`FindingIncidentSyncService`) |
| `02:00` Sunday | EOL catalog refresh (stage 1) |
| `03:00` Sunday | EOL release data refresh (stage 2) |
| `03:30` Sunday | EOL slug resolution (stage 3) |
| `04:00` Sunday | EOL denormalization (stage 4) |
| Every 5 min | Run enabled GitHub SBOM sources |
| Every 5 min | Run enabled ServiceNow / SCCM / AWS Discovery / Azure Discovery scheduled syncs |
| Every 15 min | Reopen expired suppressions |
| Every 2 sec | Drain `finding_delta_queue` (batches of 100) |
| Hourly | Policy-based auto-close findings |
| Hourly | Demo tenant expiry check |
| Midnight | Nightly re-run of all approved suppression rules |

A handful of additional infra-level jobs also run (ingestion job polling every 2s, finding-projection maintenance and BOM-projection reconciliation every 5 min, vulnerability queued-run polling every 5s, performance telemetry snapshot every 30s) — see `docs/backend.md` for the full list.

### Known Limitations

- `POST /api/cve-detail/{cveId}/suppress` persists suppression state via `OrgCveRecordService.suppress()` and returns a `SuppressionResponse`. Suppression expiry is handled by the 15-minute reopen job.
- Multi-tenant schema-per-tenant isolation is implemented (see "Multi-Tenancy Status" above); `TenantService.getDefaultTenant()` is no longer used. Full RLS enforcement across production tenants remains gated behind `V29__tenant_rls_rollout_gate.sql`.
- The live CVE workflow is the CVE Assessment Workbench at `/vuln-repo/org-cves`. `CveDetailPage.tsx` exists but is not mounted in the router.
- GHCR attestation ingestion does not yet perform cryptographic signature verification.
- AI-assisted features (investigation summary, AI solution, AI actions) call OpenAI and are gated by `OPENAI_ENABLED`. Results are persisted on `org_cve_records` / `org_cve_ai_artifacts` so subsequent reads do not re-call the API.
- ServiceNow incident creation (`POST /api/cve-detail/{cveId}/servicenow-incident`) writes `incident_id` / `incident_status` onto findings. The `FindingIncidentSyncService` daily 07:00 job pulls incident state changes back, so the integration is no longer fully one-way — but it is read-only on the ServiceNow side.
- S.AI Risk Score and S.AI Priority are computed entirely in the browser from existing API data — they are not stored in the database and recalculate on every render.
- SCCM sync (`SccmCmdbSyncService`) performs asset discovery and field mapping but does not yet support incremental delta sync — each run is a full sweep.
- AWS Discovery (`aws-discovery` connector) is scoped to EC2 instances via SSM; multi-account/region support via `aws_discovery_targets` with cross-account role ARN + external ID.
- Azure Discovery (`azure-discovery` connector, `V40`/`V41`) mirrors the AWS Discovery architecture (config + per-subscription targets, `CLIENT_SECRET` or `MANAGED_IDENTITY` auth) but is newer and less exercised in production than AWS Discovery.
- Remediation Campaigns (`CampaignController`, `/vuln-repo/campaigns`) and CBOM/cloud-posture tracking (`CbomController`, `/api/bom/cbom`) are shipped but not yet covered by `docs/business-logic-guide.md` in the same depth as the core finding/CVE workflow — read the controllers/DTOs directly for full field-level detail.

### GitHub Token

For GitHub SBOM / GHCR / GHSA features, place a token in `backend/secrets/github-api-token` (gitignored). Resolution order: `GITHUB_API_TOKEN_FILE` → `backend/secrets/github-api-token` → `GITHUB_API_TOKEN`.

## Conventions

These are prescriptive. PRs that violate them will be rejected.

### What counts as "done"

A change is done when **all** of these are true:

1. **Behavior is verified.** Backend: at least one test exercises the changed code path (unit, controller IT via `@PostgresControllerIntegrationTest`, or service IT). Frontend: at least one vitest test exercises the changed page or hook. "Verified by manual testing" is not done.
2. **CI is green.** All gates above pass: lint, typecheck, build, coverage thresholds, JaCoCo line floor, SpotBugs, Failsafe ITs.
3. **No new warnings introduced.** ESLint or `tsc` warnings on touched files block merge — fix them in the same PR.
4. **PR template is filled in.** Scope, why, repro, test added/changed, blast radius, rollback. Empty sections = reject.
5. **For UI changes, a screenshot is attached.** Type-check passing is not the same as feature working — see the global guidance on UI changes.

### When to add a test

| Change | Test required |
|---|---|
| Bug fix | Yes — a regression test that fails before the fix and passes after. |
| New API endpoint | Controller IT covering happy path + at least one auth/error case. |
| New service method called from a controller | Service-layer IT or a controller IT that exercises it end-to-end. |
| New frontend page / new top-level component | Vitest page test asserting render + at least one interaction. |
| Refactor with no behavior change | No new test, but existing tests must still pass. If they don't exist, that's a separate gap — file it as an issue, don't silently leave the code uncovered. |
| Migration-only PR | A repo IT that asserts the new schema state, OR a service IT that exercises the new column. |
| Frontend-only style/copy change | No test required if no logic changed. |

### When to refactor vs. leave alone

- **Bug fix scope is the bug.** Don't refactor surrounding code in the same PR even if it's tempting. File a follow-up issue.
- **If you must refactor to fix the bug**, keep the refactor and the fix in **separate commits** so the fix is reviewable without the noise.
- **Don't migrate old code to new patterns opportunistically.** The scaffolding READMEs (`backend/src/test/java/com/prototype/vulnwatch/support/README.md`, `frontend/src/test/README.md`) explicitly say: migrate when you're already in the file for another reason. Otherwise, leave it.
- **Premature abstraction is rejected.** Three similar lines is fine. Don't introduce a helper for two callers, an interface for one implementation, or a feature flag for hypothetical future configurability.

### Naming and commit conventions

- **Migrations**: `V<next>__short_snake_case.sql` in `backend/src/main/resources/db/migration/postgres_reset/`.
- **Tests**: backend Postgres ITs end with `PostgresIntegrationTest.java` (Surefire-excluded, Failsafe-included). Frontend page tests live next to the page as `<Page>.test.tsx`.
- **Commits**: imperative subject ≤72 chars. Body explains the *why*, not the *what* — the diff already shows the what.
- **Branch names**: `<type>/<short-slug>` where type is `fix`, `feat`, `refactor`, `chore`, `docs`. Example: `fix/correlation-applicable-state-filter`.

### Never-touch list (require explicit approval before changing)

- **Already-applied Flyway migrations** (`backend/src/main/resources/db/migration/postgres_reset/V*.sql`). Add a new migration; never edit an applied one.
- **Security config** (`com.prototype.vulnwatch.config.SecurityConfig`, `ApiKeyFilter`, anything that decides who's authenticated or authorized).
- **Tenant scoping** (`TenantService`, `TenantContext`, multi-tenant filter logic). Cross-tenant leaks are the worst class of bug.
- **Deploy infra** (`infra/`, `Dockerfile`, `.github/workflows/`). Changes here affect deploy/build for everyone — flag in PR description.
- **Golden contract fixtures** (`backend/src/test/resources/fixtures/golden/*.sha256`). Changing a hash means the canonicalized output changed — that's an API contract change. Justify in the PR.
- **`scripts/`** — operator scripts that touch the running database or production-like state.

### Things that get rejected on sight

- Edits to applied migrations (re-edit V21 instead of writing V42).
- New `console.log` / `System.out.println` left in shipped code.
- `// TODO` comments without an owner or linked issue.
- Mocking the database in integration tests instead of using `@PostgresIntegrationTest`.
- Adding `--no-verify` / `--no-gpg-sign` to git commands in CI or scripts.
- Coverage thresholds lowered — floors only move up, never down. Raise them as new tests are added.
- New `any` types in TypeScript or `@SuppressWarnings("unchecked")` in Java without a comment explaining why.
- New external HTTP calls without a corresponding `MockRestServiceServer` test (see `ApiContractGoldenPostgresIntegrationTest`).
- Files added to `frontend/src/components/` larger than ~300 lines — split into a feature directory under `frontend/src/features/<feature>/`.
