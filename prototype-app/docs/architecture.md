# VulnWatch Architecture

Last updated: 2026-05-27

---

## System Shape

VulnWatch is a security operations prototype: SBOM ingestion → vulnerability intelligence ingestion → deterministic CPE-based correlation → finding projection and workflow.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser — React 18 + TypeScript + Vite (port 5173 local)           │
│  Nginx (port 8080 container) ← static SPA                           │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ REST API (http://localhost:8080/api)
┌─────────────────────────────▼───────────────────────────────────────┐
│  Spring Boot 3.3.2 — Java 17 (port 8080)                            │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────────┐ │
│  │ Controllers  │  │   Services     │  │  Scheduled Jobs          │ │
│  │ (37 REST)    │  │   (180+)       │  │  (daily + hourly + 2s)   │ │
│  └──────┬───────┘  └───────┬────────┘  └──────────────────────────┘ │
│         │                  │                                         │
│  ┌──────▼──────────────────▼──────┐   ┌────────────────────────────┐│
│  │  Spring Data JPA / HikariCP    │   │  OutboundHttpClient        ││
│  │  TenantAwareDataSource         │   │  (retry + circuit breaker) ││
│  └──────────────┬─────────────────┘   └──────────┬─────────────────┘│
└─────────────────┼──────────────────────────────────┼────────────────┘
                  │ JDBC                             │ HTTPS
┌─────────────────▼──────────────────┐  ┌───────────▼────────────────┐
│  PostgreSQL — schema-per-tenant    │  │  External APIs             │
│  platform schema (shared)          │  │  NVD, KEV, GHSA, CSAF      │
│  tenant_<id> schema (per tenant)   │  │  EPSS, EOL, GitHub         │
│  Flyway migrations (postgres_reset)│  │  ServiceNow, SCCM, AWS     │
└────────────────────────────────────┘  │  OpenAI, Resend            │
                                        └────────────────────────────┘
```

---

## Core Data Flow

### 1. Inventory In

Three ingestion paths populate the inventory:

**SBOM ingestion** (CycloneDX / SPDX):
- File upload or configured endpoint fetch → `SbomIngestionService` → parse → normalize CPEs → write `inventory_components` + `inventory_component_cpe_map`
- GitHub repos or GHCR images → `GithubSbomIngestionService` → same normalization pipeline
- Runs every 5 minutes for configured sources; on-demand via upload

**CMDB sync:**
- ServiceNow CMDB → `ServiceNowCmdbSyncService` → CI records → `Asset`, `Ci`, `CiAlias`
- SCCM/MECM → `SccmCmdbSyncService` → device inventory → `Asset`, `SoftwareInstance`, `DiscoveryModel`
- Runs every 5 minutes for scheduled syncs

**AWS Discovery:**
- `AwsDiscoveryClient` → SSM `DescribeInstanceInformation` → EC2 instances → `Asset`, `DiscoveryModel`
- Runs every 5 minutes for configured targets

All paths normalize software identities into `software_identities` and `software_instances`, and resolve CPEs into `cpe_dim` + `inventory_component_cpe_map`.

### 2. Vulnerability Intelligence In

Daily scheduled jobs pull from external feeds:

| Feed | Time | Tables written |
|------|------|----------------|
| NVD + CISA KEV | 01:00 | `vulnerabilities`, `vulnerability_targets`, `vulnerability_intel_observations` |
| GHSA | 01:15 | `vulnerabilities`, `vulnerability_targets` |
| Microsoft + Red Hat CSAF/VEX | 01:45 | `vex_assertions`, `vulnerability_intel_relations` |
| EPSS | 03:15 | `vulnerability_intel_observations` |

The `vulnerability_intel_summary` table is a read-model projection aggregating all intel signals per CVE.

### 3. Correlation

CPE-based matching runs after each inventory or intel update:

1. Join `inventory_component_cpe_map` × `vulnerability_targets` on CPE vendor + product
2. `ApplicabilityDecisionService` evaluates version range constraints using `VersionScheme`-aware comparison
3. Result written to `component_vulnerability_states` (one row per component × vulnerability, with `applicabilityState`)
4. States roll up to `org_cve_records` (one row per CVE per tenant): `matchedAssetCount`, `matchedSoftwareCount`, `maxSeverity`, `hasKev`, `epssScore`

### 4. Finding Projection

`FindingService` watches `component_vulnerability_states` via the delta queue:

1. When a state flips to APPLICABLE: create `Finding` (if in AUTO generation mode)
2. When a state flips to NOT_APPLICABLE: auto-resolve linked findings
3. Suppression rules evaluated at creation; matching rules suppress immediately
4. Delta queue (`finding_delta_queue`) batches changes; drain job processes 100 per 2 seconds

### 5. EOL Pipeline

Runs weekly (Sunday), 4 stages:

1. Catalog refresh (02:00) → `eol_product_catalog`
2. Release data (03:00) → `eol_release`
3. Slug resolution (03:30) → `software_eol_mapping` (OpenAI-assisted for unmatched)
4. Denormalization (04:00) → `inventory_components.is_eol`, `eol_days_remaining`, `eol_date`

Daily sweep (00:15) catches components that crossed their EOL date between weekly runs.

---

## Multi-Tenant Architecture

### Schema-Per-Tenant

Each tenant gets a dedicated PostgreSQL schema. Connection-level `search_path` isolation means:
- Tenant A queries can never reach Tenant B's tables
- All JPA entities are schema-agnostic — they just use table names, and the schema is set at the connection level

**TenantAwareDataSource** wraps HikariCP:
- On checkout: `SET search_path = tenant_<id>, public`; `SET LOCAL app.current_tenant_id = '<id>'`
- On return: reset to prevent leakage

**Platform schema** holds: `tenants`, `app_users`, `tenant_memberships`, `tenant_support_grants`, `demo_invites`, `audit_events`, and the global vulnerability intel tables.

**Per-tenant schemas** hold: all operational data — `findings`, `assets`, `inventory_components`, `org_cve_records`, `risk_policies`, `suppression_rules`, etc.

### Tenant Context Flow

```
HTTP Request
  → ApiKeyAuthenticationFilter (API key or JWT Bearer)
  → TenantResolutionFilter (populate TenantContext from JWT or X-Tenant-ID header)
  → TenantStatusFilter (block SUSPENDED/EXPIRED tenants)
  → Controller → Service → Repository (correct schema via HikariCP connection)
```

### New Tenant Bootstrap

`TenantSchemaService` creates new tenant schemas by cloning `tenant_default` (tables, sequences, defaults, foreign keys). This happens on `Tenant` creation.

---

## Security Model

### Authentication Paths

**API Key** (local/ops): `X-API-Key` header → `ApiKeyAuthenticationFilter` → injects OPERATOR + ANALYST roles. `X-Creator-Key` additionally grants PLATFORM_OWNER, TENANT_ADMIN, INVENTORY_ADMIN, CREATOR. Only active when `APP_ALLOW_API_KEY_AUTH=true`.

**JWT Bearer** (production): OIDC token validated against `APP_JWT_ISSUER_URI`. Tenant and roles resolved from claims by `JwtTenantAuthenticationService`.

**Credential login** (validation/preprod): `POST /api/auth/login` validates against bcrypt hash in config. Issues HS256 JWT signed with `APP_JWT_HMAC_SECRET`.

### Role Hierarchy

| Role | Access |
|------|--------|
| `PLATFORM_OWNER` | `/api/platform/**`, `/api/operations/**`, all tenant data via support grants |
| `TENANT_ADMIN` | Full tenant admin — users, connectors, all settings |
| `INVENTORY_ADMIN` | Connector configuration, CMDB/SBOM management |
| `SECURITY_ANALYST` | Finding triage, investigation workflow, CVE workbench |
| `READ_ONLY_AUDITOR` | Read-only across all tenant data |
| `OPERATOR` | API key default — read/write operations, no admin |
| `CREATOR` | Creator key default — includes all platform-level operations |

### Security Filters (in order)

1. `ApiKeyAuthenticationFilter` — API key / JWT resolution
2. `RequestCorrelationFilter` — inject `X-Request-ID`, `X-Trace-ID` into MDC
3. `TenantResolutionFilter` — populate `TenantContext`
4. `TenantStatusFilter` — block suspended tenants

### Production Safety Checks

`ProductionSafetyValidator` runs at startup and fails if (when `require-production-secrets=true`):
- `APP_ALLOW_API_KEY_AUTH=true`
- `APP_CREATOR_KEY` is set
- No JWT issuer or JWK URI configured
- `APP_ALLOW_HEADER_TENANT_SELECTION=true`
- `APP_REQUIRE_TENANT_CONTEXT=false`
- `APP_CREDENTIAL_ENCRYPTION_KEY` is weak/default
- `APP_CORS_ALLOWED_ORIGINS` is `*`
- `APP_TEST_PERSONAS_ENABLED=true`

---

## Projection Tables

Six read-model projections are central to performance:

| Table | Purpose |
|-------|---------|
| `component_vulnerability_states` | Component-level CPE applicability truth — drives all downstream work |
| `org_cve_records` | Per-tenant CVE rollup — backs the CVE Assessment Workbench UI |
| `vulnerability_intel_summary` | Global CVE read model — backs the Intelligence view |
| `software_inventory_items` | Flattened software inventory — backs reporting |
| `software_identity_summary` | Per-identity aggregation (asset count, version count, EOL status) |
| `quality_issue_projection` | Data quality issues by domain/severity — backs Operations Quality view |

These tables are never the authoritative source; they are rebuilt from the underlying entities when the source changes.

---

## Outbound HTTP Infrastructure

All external HTTP calls use `OutboundHttpClient` (wraps Spring `RestClient`):

- `OutboundPolicy` — per-service config (timeout, max retries, circuit-breaker threshold)
- `OutboundPolicyFactory` — creates policies with `OutboundPolicyDefaults`
- `OutboundFailureClassifier` — distinguishes transient vs. permanent failures
- `OutboundFailureDecision` — controls retry vs. circuit-break behavior
- `OutboundResponseHandler` — parses and validates responses

`AdvisoryFetchService` handles bulk advisory fetching (CSAF/VEX sources with large document sets).

---

## Frontend Architecture

### Tech Stack

React 18 + TypeScript + Vite + React Router v6 + TanStack Query (React Query).

### Routing

All routes defined in `src/App.tsx` with typed helpers in `src/app/routes.ts`. Legacy query-param URLs redirected via `buildLegacyCompatiblePath()` on first render.

### Key Architectural Decisions

**Feature-colocated types:** TypeScript types live in the feature directory that owns them (`src/features/findings/types.ts`, etc.). `src/types/index.ts` re-exports them for convenience but is not the source of truth.

**Two distinct CVE views:**
- `/vuln-repo/org-cves` → **Unified Vulnerability Records** — CVEs correlated to the org's inventory (query: `org_cve_records`)
- `/vuln-repo/vulnerabilities` → **Vulnerability Intelligence** — all ingested CVEs regardless of inventory match (query: `vulnerability_intel_summary`)

**S.AI Scoring (browser-side only):** `src/lib/riskScoring.ts` computes CVE Risk Score and Finding Priority Score from data already returned by the API. Not stored in the database. Recalculates on every render. Accepts optional `PolicyWeights` from the tenant's risk policy.

**ExposureDashboard vs. OperationalDashboard:** `/exposure` is risk-focused (CVE counts, SLA status, risk score). `/operations` is pipeline-focused (correlation efficiency, CSAF/VEX analytics, quality issues). Do not add operational/pipeline panels to the Exposure Dashboard.

### API Layer

All API calls go through `src/api/client.ts`. Base URL: `VITE_API_BASE` (defaults to `http://localhost:8080/api`). Auth headers injected on every request. TanStack Query provides caching, deduplication, and background refresh.

---

## Deployment (Validation Environment)

- **Backend container:** `eclipse-temurin:17-jre`, non-root user, port 8080, JVM flags: `-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError`
- **Frontend container:** `nginx:1.27-alpine`, port 8080, `try_files $uri $uri/ /index.html` for SPA routing
- **AWS (validation):** ECS Fargate (public subnet, assign_public_ip=true), ALB, RDS PostgreSQL db.t4g.small (private subnet), S3 + CloudFront OAC for frontend

For deployment-facing environment variables and operational endpoints, see [Backend](backend.md).

---

## Key Constraints and Design Decisions

1. **CPE-based correlation only** — matching uses normalized CPE strings. No fuzzy name matching. This makes false positives rare but requires good CPE coverage in the vulnerability feeds.

2. **Deterministic correlation** — `ApplicabilityDecisionService` applies version constraints mechanically. The system does not use AI for correlation — AI is used only for EOL slug suggestion and investigation summaries.

3. **Schema-per-tenant over row-level isolation** — row-level security with a `tenant_id` column was rejected because it requires every query to include a filter, which is easy to miss. Schema-level isolation via `search_path` enforces isolation at the database connection level.

4. **Projection tables over on-the-fly joins** — the `org_cve_records` rollup and `vulnerability_intel_summary` exist because joining `component_vulnerability_states × vulnerabilities × inventory_components` at query time is too slow at scale. The projections trade storage for query speed.

5. **Delta queue over synchronous writes** — `finding_delta_queue` decouples correlation (high-write bursts) from finding creation (requires policy evaluation, suppression checks). The 2-second drain window batches work and avoids thundering-herd under large SBOM ingestion events.

6. **`ddl-auto=update` (temporary)** — Hibernate currently creates tenant schema tables via schema validation/update mode. The goal is to switch to `validate` once the reset-line DDL explicitly creates all tables. Don't add logic that depends on `update` behavior; it will be removed.
