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
| `domain/` | JPA entities (assets, inventory, vulns, findings, policies, CMDB, EOL) |
| `dto/` | API request/response objects |
| `repo/` | Spring Data JPA repositories |
| `client/` | External API clients (NVD, GHSA, CSAF, EPSS, GitHub, ServiceNow, endoflife.date) |
| `config/` | Spring beans and security configuration |
| `util/` | CPE handling, version comparison, SBOM parsing |

### Core Data Flow

1. **Inventory in** — SBOMs (upload, endpoint fetch, GitHub repo/GHCR) or ServiceNow CMDB live sync write `assets`, `inventory_components`, `software_identities`, `software_instances`, and normalize CPEs into `cpe_dim` + `inventory_component_cpe_map`.
2. **Vulnerability intel in** — NVD, KEV, GHSA, Microsoft/Red Hat CSAF/VEX, advisory imports populate `vulnerabilities`, `vulnerability_targets`, and read-model projections.
3. **Correlation** — CPE joins between `inventory_component_cpe_map` and `vulnerability_targets`, version-checked by `ApplicabilityDecisionService`, write `component_vulnerability_states`.
4. **Projection** — States roll up to `org_cve_records` (one row per CVE per tenant). `FindingService` drives finding create/reopen/resolve.
5. **EOL pipeline** — 4-stage async job: catalog refresh → release cycles → slug resolution → denormalization into `inventory_components.is_eol / eol_days_remaining`.

### Projection Tables (Central to Read Performance)

- `component_vulnerability_states` — component-level CPE applicability truth
- `org_cve_records` — tenant/CVE rollup used by Org CVEs UI
- `vulnerability_intel_summary` — vuln list read model
- `software_inventory_items` — flattened software inventory for reporting

### Security Model

- Every `/api/**` request requires `X-API-Key`.
- `X-Creator-Key` grants `ROLE_CREATOR`; required for `/api/operations/**`.
- `X-Tenant-ID` and `X-User-ID` are used directly by CVE workflow endpoints.
- Local defaults: API key `change-me-in-prod`, creator key `local-creator`, tenant `1`, user `local-analyst`.

### Frontend Navigation

`src/App.tsx` is a sidebar shell with query-param state (`tab`, `inventoryView`, `vulnIntelView`). There is no React Router — all navigation is URL query params. Drill-downs happen in drawers and modals, not separate pages.

Top-level sections: Overview → Findings → Operational Dashboard → Vulnerability Intelligence → Inventory → Connect → Configurations.

All API calls go through `src/api/client.ts`. Base URL defaults to `http://localhost:8080/api` (via `VITE_API_BASE`). Auth headers are injected on every request.

All TypeScript types live in `src/types/index.ts`.

### Connect Page Architecture

`ConnectPage` is a connector catalog. Clicking a source card opens a modal rendering `ConnectorDetailContent`, which delegates to a focused component per connector (e.g., `IngestionPage`, `GithubPipelineManager`, `AssetsPage`, `SourcesPage`, `EolSourcePanel`). Adding a new connector means: add to `ConnectorId` union, `CONNECTORS` array, the appropriate category list, and a `ConnectorDetailContent` case.

### Adding a Database Migration

Create `backend/src/main/resources/db/migration/postgres/V{next}__description.sql`. Flyway applies migrations in version order on startup. Never edit an already-applied migration file.

### Scheduled Jobs

| Time | Job |
|---|---|
| `01:00` daily | NVD incremental + KEV sync |
| `01:15` daily | GHSA sync |
| `01:45` daily | Microsoft + Red Hat CSAF/VEX sync |
| `02:05` daily | Mark stale assets inactive |
| `02:30` daily | VEX staleness recompute |
| Every 5 min | Run enabled GitHub SBOM sources |
| Every 15 min | Reopen expired suppressions |
| Hourly | Policy-based auto-close findings |

### Known Limitations

- `POST /api/cve-detail/{cveId}/suppress` persists suppression state via `OrgCveRecordService.suppress()` and returns a `SuppressionResponse`.
- Schema is tenant-aware but runtime is effectively single-tenant; most controllers call `TenantService.getDefaultTenant()`.
- `CveDetailPage.tsx` exists but is not mounted in `App.tsx`; the live CVE workflow is the org-CVE drawer.
- GHCR attestation ingestion does not yet perform cryptographic signature verification.

### GitHub Token

For GitHub SBOM / GHCR / GHSA features, place a token in `backend/secrets/github-api-token` (gitignored). Resolution order: `GITHUB_API_TOKEN_FILE` → `backend/secrets/github-api-token` → `GITHUB_API_TOKEN`.
