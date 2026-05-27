# VulnWatch Backend

Last updated: 2026-05-27

## Tech Stack

| Component | Version / Detail |
|-----------|-----------------|
| Java | 17 |
| Spring Boot | 3.3.2 |
| Spring Security | JWT Bearer + API key dual-auth |
| Spring Data JPA | PostgreSQL via HikariCP |
| Database | PostgreSQL (Flyway migrations in `postgres_reset/`) |
| Build | Maven, JaCoCo coverage, SpotBugs, Failsafe ITs |
| External HTTP | Custom `OutboundHttpClient` with circuit-breaker + retry |

Package root: `com.prototype.vulnwatch`

---

## Authentication

Two paths, handled by `ApiKeyAuthenticationFilter`:

### API Key (dev/ops)

Enabled when `APP_ALLOW_API_KEY_AUTH=true`.

| Header | Role granted |
|--------|-------------|
| `X-API-Key: <key>` | `ROLE_OPERATOR`, `ROLE_SECURITY_ANALYST` |
| `X-Creator-Key: <key>` | additionally: `ROLE_CREATOR`, `ROLE_PLATFORM_OWNER`, `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN` |
| `X-User-ID: <id>` | sets actor identity (defaults to `APP_DEFAULT_USER_ID`) |

Default local api-key: `change-me-in-prod`. No creator-key configured locally means all callers get creator-level access.

### JWT Bearer (production)

Active when `APP_JWT_ISSUER_URI` is set. Token decoded by `JwtTenantAuthenticationService`. Roles resolved from the `roles` JWT claim (or any namespaced claim ending in `/roles`). Tenant ID resolved from `tenant_id` claim.

### Tenant Resolution

`TenantResolutionFilter` populates thread-local `TenantContext` from:
1. JWT `tenant_id` claim (production)
2. `X-Tenant-ID` header (only when `APP_ALLOW_HEADER_TENANT_SELECTION=true` — local dev only)
3. Default tenant fallback

`TenantStatusFilter` follows and rejects requests with HTTP 403 if tenant is `SUSPENDED` or `EXPIRED`.

### Local Credential Auth

`LocalAuthController` / `AuthLoginController` (`POST /api/auth/login`, `POST /api/auth/setup-password`) provides bcrypt-based login for platform owner and tenant admins in validation/preprod environments.

---

## Authorization Rules

| Path prefix | Required |
|-------------|---------|
| `OPTIONS /*` | Public |
| `GET /actuator/health`, `GET /actuator/info` | Public |
| `POST /api/auth/login`, `POST /api/auth/setup-password` | Public |
| `POST /api/demo-requests` | Public |
| `/api/demo-invites/**` | Public |
| `/api/platform/**` | `ROLE_PLATFORM_OWNER` |
| `/api/operations/**` | `ROLE_PLATFORM_OWNER` |
| All other `/api/**` | Authenticated |

---

## REST Controllers

### AssetController — `/api/assets`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/assets` | List assets for tenant (paginated, filterable) |
| GET | `/api/assets/{id}` | Get single asset |
| POST | `/api/assets` | Create asset manually |
| PUT | `/api/assets/{id}` | Update asset |
| DELETE | `/api/assets/{id}` | Delete asset |

Asset domain: `Asset` entity. Types: `AssetType` enum. States: `AssetState` enum (ACTIVE, INACTIVE). Criticality: `BusinessCriticality` enum.

### IngestionController — `/api/ingestion`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/ingestion/sbom` | Upload SBOM file (multipart) |
| POST | `/api/ingestion/sbom/endpoint` | Trigger SBOM fetch from a configured endpoint URL |
| GET | `/api/ingestion/sbom/uploads` | List SBOM upload history |
| GET | `/api/ingestion/sbom/uploads/{id}` | Get upload status and result |

Supported SBOM formats (`SbomFormat` enum): CycloneDX, SPDX. Processing is async — status tracked via `SbomUpload` entity (`SbomIngestionStatus` enum: PENDING, PROCESSING, COMPLETE, FAILED).

### GithubSbomSourceController — `/api/github-sbom-sources`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/github-sbom-sources` | List configured GitHub SBOM sources |
| POST | `/api/github-sbom-sources` | Add GitHub repo or GHCR source |
| PUT | `/api/github-sbom-sources/{id}` | Update source config |
| DELETE | `/api/github-sbom-sources/{id}` | Remove source |
| POST | `/api/github-sbom-sources/{id}/run` | Trigger manual run |

`GithubSbomSource` entity. Frequency: `GithubIngestionFrequency` enum (EVERY_5_MIN, HOURLY, DAILY).

### InventoryController — `/api/inventory`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/inventory` | List inventory components (paginated) |
| GET | `/api/inventory/{id}` | Get inventory component detail |
| GET | `/api/inventory/software-identities` | List software identities |
| GET | `/api/inventory/software-identities/{id}` | Get software identity |

`InventoryComponent` entity. Status: `InventoryComponentStatus` enum. CPE mappings via `InventoryComponentCpeMap`.

### VulnerabilityController — `/api/vulnerabilities`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/vulnerabilities` | List all vulnerabilities in intel store |
| GET | `/api/vulnerabilities/{id}` | Get vulnerability detail |
| GET | `/api/vulnerabilities/{cveId}/targets` | Get CPE targets for a CVE |
| GET | `/api/vulnerabilities/{cveId}/config-expr` | Get configuration expressions |

`Vulnerability` entity. `VulnerabilityTarget` entities link CVEs to CPE patterns.

### VulnerabilityIntelligenceController — `/api/vuln-intel`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/vuln-intel` | Paginated vulnerability intel summary |
| GET | `/api/vuln-intel/{cveId}` | Get intel for specific CVE |
| GET | `/api/vuln-intel/{cveId}/observations` | Get intel observations (KEV, CSAF, EPSS) |

Backed by `vulnerability_intel_summary` + `vulnerability_intel_observations` projections.

### FindingController — `/api/findings`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/findings` | List findings (paginated, filterable) |
| GET | `/api/findings/{id}` | Get finding detail |
| PUT | `/api/findings/{id}` | Update finding (status, assignee, etc.) |
| POST | `/api/findings/{id}/comments` | Add comment to finding |
| GET | `/api/findings/{id}/events` | Get finding event history |
| DELETE | `/api/findings/{id}` | Delete finding |

`Finding` entity. Status: `FindingStatus` enum (OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, SUPPRESSED, FALSE_POSITIVE, RISK_ACCEPTED). Decision state: `FindingDecisionState`. Creation source: `FindingCreationSource` enum.

### CveDetailController — `/api/cve-detail`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/cve-detail/{cveId}` | Full CVE detail including org impact |
| GET | `/api/cve-detail/{cveId}/applicable-software` | Affected software for org |
| GET | `/api/cve-detail/{cveId}/inventory-mappings` | CPE-to-inventory mappings |
| POST | `/api/cve-detail/{cveId}/suppress` | Suppress CVE org-wide |
| POST | `/api/cve-detail/{cveId}/investigate` | Start investigation |
| POST | `/api/cve-detail/{cveId}/ai-summary` | Generate AI investigation summary (OpenAI) |
| POST | `/api/cve-detail/{cveId}/servicenow-incident` | Create ServiceNow incident for CVE |

`OrgCveRecord` entity stores per-tenant CVE state. `OrgCveAiArtifact` stores persisted AI outputs.

### DashboardController — `/api/dashboard`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard` | Main dashboard metrics |
| GET | `/api/dashboard/noise-reduction` | Noise reduction analytics |
| GET | `/api/dashboard/correlation-efficiency` | Correlation efficiency metrics |
| GET | `/api/dashboard/cve-inventory-map` | CVE-to-inventory mapping summary |
| GET | `/api/dashboard/csaf-vex-analytics` | CSAF/VEX analytics |

Results are cached in memory (Caffeine) for the dashboard queries.

### VulnRepoDashboardController — `/api/vuln-repo-dashboard`

Dashboard metrics for the Vulnerability Repository view.

### EolController — `/api/eol`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/eol/products` | EOL product catalog |
| GET | `/api/eol/releases` | EOL release data |
| GET | `/api/eol/mappings` | Component → EOL product mappings |
| POST | `/api/eol/mappings/confirm` | Confirm/reject a suggested EOL mapping |
| GET | `/api/eol/slug-suggestions` | AI-suggested EOL slugs for unmatched components |

`EolProductCatalog`, `EolRelease`, `SoftwareEolMapping` entities. Data sourced from endoflife.date API.

### RiskPolicyController — `/api/risk-policy`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/risk-policy` | Get tenant risk policy |
| PUT | `/api/risk-policy` | Update risk policy |
| POST | `/api/risk-policy/recompute-findings-scores` | Recompute all finding scores |

`RiskPolicy` entity. Fields include: `sla*`, `triage*` (6 weight fields), `autoClose*`, `findingGenerationMode`, `findingsScoreConfig` (JSONB).

### SuppressionRuleController — `/api/suppression-rules`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/suppression-rules` | List suppression rules |
| POST | `/api/suppression-rules` | Create suppression rule |
| PUT | `/api/suppression-rules/{id}` | Update rule |
| DELETE | `/api/suppression-rules/{id}` | Delete rule |

`SuppressionRule` entity. States: DRAFT, APPROVED, IN_REVIEW, REJECTED, EXPIRED. Types: CVE, FINDING.

### OwnershipRuleController — `/api/ownership-rules`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ownership-rules` | List ownership rules |
| POST | `/api/ownership-rules` | Create rule |
| PUT | `/api/ownership-rules/{id}` | Update rule |
| DELETE | `/api/ownership-rules/{id}` | Delete rule |

`OwnershipRule` entity. Conditions stored as JSONB. Evaluated by priority to auto-assign findings.

### VulnerabilitySourceFilterConfigController — `/api/vuln-source-filter`

Per-tenant configuration of which vulnerability intelligence sources participate in correlation.

### ServiceNowCmdbConfigController — `/api/servicenow-cmdb`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/servicenow-cmdb/config` | Get CMDB config |
| POST | `/api/servicenow-cmdb/config` | Create/update config |
| POST | `/api/servicenow-cmdb/sync` | Trigger CMDB sync |
| GET | `/api/servicenow-cmdb/sync/status` | Get sync status |

`ServiceNowCmdbConfig` entity. Auth type: `ServiceNowAuthType` enum.

### ServiceNowIncidentController — `/api/servicenow-incidents`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/servicenow-incidents` | Create ServiceNow incident |
| GET | `/api/servicenow-incidents/{id}` | Get incident |

### SccmCmdbController — `/api/sccm-cmdb`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sccm-cmdb/config` | Get SCCM config |
| POST | `/api/sccm-cmdb/config` | Create/update config |
| POST | `/api/sccm-cmdb/sync` | Trigger sync |

`SccmCmdbConfig` entity. Auth type: `SccmAuthType` enum.

### AwsDiscoveryController — `/api/aws-discovery`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/aws-discovery/config` | Get discovery config |
| POST | `/api/aws-discovery/config` | Create/update config |
| POST | `/api/aws-discovery/targets` | Add discovery target (account + region) |
| DELETE | `/api/aws-discovery/targets/{id}` | Remove target |
| POST | `/api/aws-discovery/test` | Test AWS credentials |
| POST | `/api/aws-discovery/run` | Trigger discovery run |

`AwsDiscoveryConfig`, `AwsDiscoveryTarget` entities. Auth types: `AwsAuthType` enum (IAM_ROLE, ACCESS_KEY, INSTANCE_PROFILE). Discovery scoped to EC2 instances via SSM.

### SyncController — `/api/sync`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sync/runs` | List sync run history |
| GET | `/api/sync/runs/{id}` | Get sync run detail |
| POST | `/api/sync/trigger` | Trigger manual sync |

`SyncRun` entity tracks each connector sync job.

### AuthContextController — `/api/me`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/me` | Get current user auth context |
| PUT | `/api/me/tenant` | Switch tenant context |

Returns `AuthContextResponse` with roles, tenant, user details.

### LocalAuthController / AuthLoginController — `/api/auth`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Credential login (email + password) |
| POST | `/api/auth/setup-password` | Set password via one-time setup token |

### TestPersonaController — `/api/dev/test-personas`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dev/test-personas` | List available personas |
| POST | `/api/dev/test-personas/{personaKey}/token` | Issue JWT for persona |

Only registered when `app.test-personas.enabled=true`.

### TenantAdministrationController — `/api/platform/tenants`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/platform/tenants` | List all tenants |
| GET | `/api/platform/tenants/{id}` | Get tenant |
| PUT | `/api/platform/tenants/{id}` | Update tenant |
| POST | `/api/platform/tenants` | Provision tenant |

Requires `ROLE_PLATFORM_OWNER`.

### TenantSupportGrantController — `/api/platform/support-grants`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/platform/support-grants` | Grant support access to a tenant |
| DELETE | `/api/platform/support-grants/{tenantId}` | Revoke support grant |

### DemoController — `/api/demo-requests`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/demo-requests` | Submit a demo request (public) |
| GET | `/api/platform/demo-requests` | List demo requests (platform owner) |
| POST | `/api/platform/demo-requests/{id}/decision` | Approve or decline |

### DemoLifecycleController — `/api/demo-invites`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/demo-invites/{token}` | Validate invite token |
| POST | `/api/demo-invites/{token}/accept` | Accept invite (returns setupToken) |

### AuditEventController — `/api/audit-events`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/audit-events` | List audit events for tenant |

### ServiceAccountController — `/api/service-accounts`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/service-accounts` | List service accounts |
| POST | `/api/service-accounts` | Create service account |
| DELETE | `/api/service-accounts/{id}` | Delete service account |

### SloController — `/api/slo`

SLO metrics and configuration.

### OperationalDashboardController — `/api/operations`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/operations/metrics` | Operational pipeline metrics |
| GET | `/api/operations/quality` | Data quality metrics |
| GET | `/api/operations/platform-health` | Platform health status |

Requires `ROLE_PLATFORM_OWNER`.

### PlatformVulnRepoController — `/api/platform/vuln-repo`

Platform-level vulnerability repository management (ROLE_PLATFORM_OWNER).

### PlatformInventoryConnectorHealthController — `/api/platform/connector-health`

Health status for all tenant connectors, visible to platform owners.

### UpgradeRecommendationController — `/api/upgrade-recommendations`

Upgrade recommendations based on EOL and vulnerability data.

### VulnerabilityArchiveController — `/api/vulnerability-archive`

Archive management for resolved/closed vulnerabilities.

### OperationsOverrideController — `/api/operations/override`

Platform-owner operations overrides.

### ApiExceptionHandler

`@RestControllerAdvice` providing consistent error responses for all controllers.

---

## External Integrations (Clients)

### NVD API (`NvdApiClient`)

Fetches CVE data from NIST National Vulnerability Database. Used in daily incremental sync (`01:00` UTC) and on-demand CVE lookups. API key via `NVD_API_KEY`.

### EUVD API (`EuvdApiClient`)

European Union Vulnerability Database — alternative CVE source.

### JVN API (`JvnApiClient`)

Japan Vulnerability Notes — Japanese CVE database.

### GitHub API (`GithubApiClient`)

SBOM ingestion from GitHub repos (dependency graph export) and GHCR (container image attestations). Also GHSA (GitHub Security Advisory) feed sync. Token via file `backend/secrets/github-api-token` or `GITHUB_API_TOKEN`.

### EOL API (`EolApiClient`)

Fetches product lifecycle data from endoflife.date. Drives the 4-stage EOL pipeline (Sunday, stages 1–4).

### AWS (`AwsDiscoveryClient`, `AwsCredentialProvider`)

Discovers EC2 instances via AWS SSM. Supports IAM role assumption, access keys, and instance profile auth. Multi-account via cross-account role ARN + external ID in `AwsDiscoveryTarget`.

### OpenAI (`OpenAiClient`)

AI investigation summaries, CVE triage, and AI-assisted actions. Gated by `OPENAI_ENABLED`. Results persisted in `org_cve_ai_artifacts` to avoid redundant API calls.

### Resend (`ResendEmailClient`)

Transactional email (invite delivery, notifications). API key via `RESEND_API_KEY`.

### Outbound HTTP Infrastructure

All outbound HTTP calls go through `OutboundHttpClient` which wraps Spring's `RestClient`. Configured via `OutboundPolicy` / `OutboundPolicyFactory`. `OutboundFailureClassifier` categorizes failures. `OutboundFailureDecision` controls retry vs. circuit-break behavior. `OutboundPolicyDefaults` provides sensible per-service defaults. `AdvisoryFetchService` handles bulk advisory fetching for CSAF/VEX sources.

---

## Service Layer

### SBOM Ingestion (`service/sbomingestion/`)

Parses CycloneDX and SPDX SBOMs, normalizes component names and versions, resolves CPEs against `cpe_dim`, writes `inventory_components` and `inventory_component_cpe_map`. Deduplicates components within a tenant by normalized identity.

### CMDB Ingestion (`service/cmdbingestion/`)

ServiceNow CMDB sync: pulls CI records, resolves identity via `IdentityMatchRule`, writes `assets` and `cis`. SCCM sync performs full sweep of device records. Both write to `software_instances` and `discovery_models`.

### Vulnerability Ingestion (`service/vulningestion/`)

Processes NVD CVE JSON, GHSA advisories, CISA KEV list, and Microsoft/Red Hat CSAF/VEX documents. Writes `vulnerabilities`, `vulnerability_targets`, and `vex_assertions`. `ApplicabilityDecisionService` re-evaluates component states after new intel arrives.

### Finding Service

`FindingService` drives finding lifecycle: create when `component_vulnerability_state` flips to applicable, reopen when suppression expires or VEX assertion is withdrawn, resolve when component is patched or suppressed. Delta queue (`finding_delta_queue`) batches state changes, drained every 2 seconds in batches of 100.

### EOL Pipeline

Four-stage weekly pipeline (Sunday):
1. Catalog refresh — fetch product list from endoflife.date
2. Release data — fetch release cycles per product
3. Slug resolution — match `inventory_components` to EOL catalog slugs (AI-assisted via OpenAI)
4. Denormalization — write `is_eol`, `eol_days_remaining`, `eol_date` onto `inventory_components`

### Ownership Rule Evaluation

`OwnershipRuleEvaluationService` evaluates `ownership_rules` by priority when findings are created or updated. First matching rule assigns ownership. Evaluated server-side, not stored as a trigger.

### Findings Score

`FindingsScoreService` evaluates the `findings_score_config` JSONB from `risk_policies` against each finding's attributes. Score (0–10) returned as `findingsScore` on every `FindingResponse`. `FindingsScoreRecomputeService.recomputeAll()` is triggered by `POST /api/risk-policy/recompute-findings-scores`.

### Suppression

Suppression rules evaluated at finding creation and on the 15-minute reopen sweep. `SuppressionRuleService` handles expiry, transitions, and finding state changes triggered by rule changes.

---

## Configuration Properties

| Property | Env var | Default | Description |
|----------|---------|---------|-------------|
| `app.api-key` | `APP_API_KEY` | `change-me-in-prod` | API key for `X-API-Key` auth |
| `app.creator-key` | `APP_CREATOR_KEY` | (none) | Creator key for elevated access |
| `app.allow-api-key-auth` | `APP_ALLOW_API_KEY_AUTH` | `false` | Enable API key auth path |
| `app.allow-header-tenant-selection` | `APP_ALLOW_HEADER_TENANT_SELECTION` | `false` | Allow `X-Tenant-ID` header |
| `app.require-tenant-context` | `APP_REQUIRE_TENANT_CONTEXT` | `true` | Reject requests without tenant |
| `app.test-personas.enabled` | `APP_TEST_PERSONAS_ENABLED` | `false` | Enable test persona endpoints |
| `app.jwt.hmac-secret` | `APP_JWT_HMAC_SECRET` | — | HMAC secret for HS256 JWT signing |
| `app.jwt.issuer-uri` | `APP_JWT_ISSUER_URI` | — | OIDC issuer for RS256 JWT validation |
| `app.security.platform-owner-email` | `APP_PLATFORM_OWNER_EMAIL` | — | Platform owner email for credential login |
| `app.security.platform-owner-password-hash` | `APP_PLATFORM_OWNER_PASSWORD_HASH` | — | Bcrypt hash for platform owner password |
| `app.cors.allowed-origins` | `APP_CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | Comma-separated CORS origins |
| `app.credential-encryption-key` | `APP_CREDENTIAL_ENCRYPTION_KEY` | — | AES-256 key (base64) for credential storage |
| `spring.datasource.url` | `DB_URL` | `jdbc:postgresql://localhost:5432/vulnwatch` | Database URL |
| `openai.enabled` | `OPENAI_ENABLED` | `false` | Enable OpenAI integration |
| `openai.api-key` | `OPENAI_API_KEY` | — | OpenAI API key |
| `nvd.api-key` | `NVD_API_KEY` | — | NVD API key (higher rate limit) |
| `resend.api-key` | `RESEND_API_KEY` | — | Resend email API key |
| `github.api-token` | `GITHUB_API_TOKEN` | — | GitHub personal access token |

---

## Scheduled Jobs

| Time | Job |
|------|-----|
| `00:15` daily | Lifecycle date sweep (EOL/EOS transitions) |
| `01:00` daily | NVD incremental + KEV sync |
| `01:15` daily | GHSA sync |
| `01:45` daily | Microsoft + Red Hat CSAF/VEX sync |
| `02:05` daily | Mark stale assets inactive |
| `02:30` daily | VEX staleness recompute |
| `03:15` daily | EPSS score refresh |
| `07:00` daily | ServiceNow incident status sync |
| `02:00` Sunday | EOL catalog refresh (stage 1) |
| `03:00` Sunday | EOL release data (stage 2) |
| `03:30` Sunday | EOL slug resolution (stage 3) |
| `04:00` Sunday | EOL denormalization (stage 4) |
| Every 5 min | GitHub SBOM sources |
| Every 5 min | ServiceNow / SCCM / AWS Discovery scheduled syncs |
| Every 15 min | Reopen expired suppressions |
| Every 2 sec | Drain `finding_delta_queue` (batches of 100) |
| Hourly | Policy-based auto-close findings |
| Hourly | Demo tenant expiry check |

---

## Actuator Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /actuator/health` | Overall health |
| `GET /actuator/health/readiness` | Readiness probe |
| `GET /actuator/health/liveness` | Liveness probe (prod only) |
| `GET /actuator/info` | Build info |

---

## Operational Metrics

`OperationalMetricsInterceptor` tracks response time (ms) for 23 monitored endpoints. Metrics are exposed for query via `OperationalDashboardController`.
