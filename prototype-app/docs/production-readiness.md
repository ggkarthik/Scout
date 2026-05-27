# VulnWatch Production Readiness

Last updated: 2026-05-27

---

## Runtime Components

| Component | Image / Stack | Port | Notes |
|-----------|---------------|------|-------|
| Backend API | `eclipse-temurin:17-jre` | 8080 | Non-root user (`vulnwatch:vulnwatch`), JVM heap-controlled via `MaxRAMPercentage` |
| Frontend | `nginx:1.27-alpine` | 8080 | Static SPA; `try_files $uri $uri/ /index.html` for SPA routing |
| Database | PostgreSQL | 5432 | Schema-per-tenant; HikariCP pool of 20; Flyway-managed migrations |

---

## Backend Environment Variables

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_URL` | `jdbc:postgresql://localhost:5432/vulnwatch` | JDBC connection URL |
| `DB_USERNAME` | `$USER` (system user) | Database username |
| `DB_PASSWORD` | _(empty)_ | Database password |

HikariCP pool settings (not overridable via env; set in `application.yml`):

| Setting | Value |
|---------|-------|
| `maximum-pool-size` | 20 |
| `minimum-idle` | 5 |
| `connection-timeout` | 30,000 ms |
| `idle-timeout` | 600,000 ms |
| `max-lifetime` | 1,800,000 ms |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_API_KEY` | `change-me-in-prod` | Value of the `X-API-Key` header (API key auth path) |
| `APP_CREATOR_KEY` | _(empty)_ | Value of the `X-Creator-Key` header; grants PLATFORM_OWNER + CREATOR roles |
| `APP_ALLOW_API_KEY_AUTH` | `true` | Enable/disable the API key auth path entirely |
| `APP_CREDENTIAL_ENCRYPTION_KEY` | `AAAA…A=` (44-char placeholder) | 256-bit base64 AES key for encrypting stored connector credentials |
| `APP_DEFAULT_USER_ID` | `local-analyst` | Identity used when `X-User-ID` is absent (API key auth only) |
| `APP_REQUIRE_PRODUCTION_SECRETS` | `false` | When `true`, `ProductionSafetyValidator` runs startup checks and crashes on any unsafe config |

### JWT / OIDC

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_JWT_ISSUER_URI` | _(empty)_ | OIDC issuer URI; setting this enables the JWT auth path |
| `APP_JWT_JWK_SET_URI` | _(empty)_ | JWK set URI (alternative to issuer-based discovery) |
| `APP_JWT_HMAC_SECRET` | _(empty)_ | HMAC secret for signing HS256 JWTs (local credential login) |
| `APP_SECURITY_JWT_AUDIENCE` | _(empty)_ | Expected `aud` claim value |
| `APP_JWT_TOKEN_TTL_MINUTES` | `480` | Local login token TTL (8 hours) |
| `APP_SECURITY_JWT_SUBJECT_CLAIM` | `sub` | JWT claim for the user subject |
| `APP_JWT_ACTIVE_TENANT_ID_CLAIM` | `active_tenant_id` | JWT claim for the active tenant ID |
| `APP_JWT_TENANT_ID_CLAIM` | `tenant_id` | JWT claim for tenant ID |
| `APP_JWT_TENANT_SLUG_CLAIM` | `tenant_slug` | JWT claim for tenant slug |
| `APP_JWT_EMAIL_CLAIM` | `email` | JWT claim for user email |
| `APP_JWT_NAME_CLAIM` | `name` | JWT claim for user display name |
| `APP_JWT_ROLES_CLAIM` | `roles` | JWT claim for roles array (also accepts namespaced claims ending in `/roles`) |

### Local Credential Login

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_PLATFORM_OWNER_EMAIL` | _(empty)_ | Email for the `POST /api/auth/login` credential path |
| `APP_PLATFORM_OWNER_PASSWORD_HASH` | _(empty)_ | bcrypt hash of the platform owner password |

### Tenancy

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ALLOW_HEADER_TENANT_SELECTION` | `false` | Trust `X-Tenant-ID` header for tenant resolution (must be `false` in production) |
| `APP_REQUIRE_TENANT_CONTEXT` | `true` | Require a resolved tenant context on every authenticated request |
| `APP_DEFAULT_TENANT_SCHEMA` | `tenant_default` | Schema name used as the tenant_default template |

### Test Personas (non-production only)

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_TEST_PERSONAS_ENABLED` | `false` | Enable `POST /api/dev/test-personas/{personaKey}/token` endpoint |
| `APP_TEST_PERSONA_TOKEN_TTL_MINUTES` | `60` | TTL for test persona tokens |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_CORS_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,...` | Comma-separated list of allowed CORS origins; `*` is blocked in production mode |

### Security Response Headers

| Variable | Default |
|----------|---------|
| `APP_CONTENT_SECURITY_POLICY` | `default-src 'none'; frame-ancestors 'none'` |
| `APP_PERMISSIONS_POLICY` | `camera=(), microphone=(), geolocation=(), payment=()` |

### Multipart / SBOM

| Variable | Default | Description |
|----------|---------|-------------|
| `spring.servlet.multipart.max-file-size` | `5MB` | Max SBOM upload file size |
| `spring.servlet.multipart.max-request-size` | `5MB` | Max SBOM upload request size |
| `SBOM_FETCH_MAX_PAYLOAD_BYTES` | `5242880` | Max bytes for SBOM endpoint fetch (5 MB) |
| `SBOM_FETCH_ALLOW_USER_AUTH_HEADER` | `false` | Allow user-supplied `Authorization` header in SBOM endpoint fetch |
| `SBOM_FETCH_ALLOWED_HOSTS` | _(empty)_ | Comma-separated allowlist of hosts for SBOM fetch; empty = all hosts allowed |

### NVD (National Vulnerability Database)

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | _(empty)_ | NVD API key (unauthenticated if absent, strict rate limits apply) |
| `NVD_API_KEY_FILE` | _(empty)_ | Path to file containing NVD API key |
| `NVD_CVE_DELTA_RECOMPUTE_PAGE_INTERVAL` | `5` | Recompute correlations every N pages during NVD sync |
| `NVD_RESULTS_PER_PAGE` | `2000` | Page size for NVD API queries |
| `NVD_MIN_REQUEST_INTERVAL_MS` | `700` | Rate-limit pause between NVD requests (ms) |
| `NVD_MAX_RETRIES` | `5` | Max retries on NVD API failures |
| `NVD_RETRY_BASE_BACKOFF_MS` | `1000` | Base backoff for NVD retries (ms) |

### GitHub / GHSA

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_API_TOKEN` | _(empty)_ | GitHub personal access token; also resolved from `backend/secrets/github-api-token` or `GITHUB_API_TOKEN_FILE` |
| `GITHUB_API_TOKEN_FILE` | _(empty)_ | Path to file containing the GitHub token |
| `GITHUB_ALLOWLIST_ENABLED` | `true` | Restrict GitHub SBOM fetch to `GITHUB_ALLOWED_REPOS` / `GITHUB_ALLOWED_PACKAGES` |
| `GITHUB_ALLOWED_REPOS` | _(empty)_ | Comma-separated allowlist of GitHub repos |
| `GITHUB_ALLOWED_PACKAGES` | _(empty)_ | Comma-separated allowlist of GHCR packages |
| `GITHUB_MAX_RETRIES` | `4` | Max retries on GitHub API failures |
| `GITHUB_RETRY_BASE_BACKOFF_MS` | `1000` | Base backoff for GitHub retries (ms) |
| `GITHUB_MAX_PAGES_PER_COLLECTION` | `250` | Max pages per GitHub SBOM collection run |
| `GITHUB_MIN_RATE_LIMIT_REMAINING` | `25` | Stop paginating when GitHub rate limit remaining drops below this |
| `GHSA_API_URL` | `https://api.github.com/advisories` | GHSA advisory API endpoint |
| `GHSA_DEFAULT_LOOKBACK_DAYS` | `7` | Lookback window for incremental GHSA sync |
| `GHSA_PER_PAGE` | `100` | GHSA page size |
| `GHSA_MAX_PAGES_PER_SYNC` | `40` | Max pages per GHSA sync |

### CSAF / VEX

| Variable | Default | Description |
|----------|---------|-------------|
| `CSAF_MAX_DOCUMENTS_PER_SYNC` | `300` | Max CSAF documents to fetch per sync run |
| `CSAF_DOCUMENT_FETCH_MAX_ATTEMPTS` | `3` | Per-document retry attempts |
| `CSAF_DOCUMENT_RETRY_BACKOFF_MS` | `300` | Backoff between document retries (ms) |
| `MICROSOFT_CSAF_PROVIDER_METADATA_URL` | `https://msrc.microsoft.com/csaf/provider-metadata.json` | Microsoft CSAF provider metadata |
| `MICROSOFT_CSAF_ADVISORIES_DISTRIBUTION_URL` | `https://msrc.microsoft.com/csaf/advisories` | Microsoft advisories |
| `MICROSOFT_CSAF_VEX_DISTRIBUTION_URL` | `https://msrc.microsoft.com/csaf/vex` | Microsoft VEX documents |
| `REDHAT_CSAF_PROVIDER_METADATA_URL` | `https://security.access.redhat.com/data/csaf/v2/provider-metadata.json` | Red Hat CSAF provider metadata |
| `REDHAT_CSAF_ADVISORIES_DISTRIBUTION_URL` | `https://security.access.redhat.com/data/csaf/v2/advisories` | Red Hat advisories |
| `REDHAT_CSAF_VEX_DISTRIBUTION_URL` | `https://security.access.redhat.com/data/csaf/v2/vex` | Red Hat VEX documents |

### EPSS

| Variable | Default | Description |
|----------|---------|-------------|
| `EPSS_BASE_URL` | `https://api.first.org/data/v1/epss` | EPSS API base URL |
| `EPSS_ENABLED` | `true` | Enable EPSS score refresh |
| `EPSS_BATCH_SIZE` | `100` | CVEs per EPSS API request |
| `EPSS_REFRESH_CRON` | `0 15 3 * * *` | Cron for daily EPSS refresh (03:15) |

### EOL (endoflife.date)

| Variable | Default | Description |
|----------|---------|-------------|
| `EOL_BASE_URL` | `https://endoflife.date/api/v1` | endoflife.date API base URL |
| `EOL_ENABLED` | `true` | Enable EOL pipeline |
| `EOL_MIN_REQUEST_INTERVAL_MS` | `200` | Rate-limit pause between EOL requests (ms) |
| `EOL_MAX_RETRIES` | `5` | Max retries on EOL API failures |
| `EOL_RETRY_BASE_BACKOFF_MS` | `2000` | Base backoff for EOL retries (ms) |
| `EOL_CATALOG_REFRESH_CRON` | `0 0 2 * * SUN` | Stage 1: product catalog refresh (02:00 Sunday) |
| `EOL_RELEASE_REFRESH_CRON` | `0 0 3 * * SUN` | Stage 2: release cycle data (03:00 Sunday) |
| `EOL_RESOLVE_MAPPINGS_CRON` | `0 30 3 * * SUN` | Stage 3: slug resolution (03:30 Sunday) |
| `EOL_DENORMALIZE_CRON` | `0 0 4 * * SUN` | Stage 4: denormalization (04:00 Sunday) |

### EUVD (EU Vulnerability Database)

| Variable | Default | Description |
|----------|---------|-------------|
| `EUVD_API_URL` | `https://euvdservices.enisa.europa.eu/api/search` | EUVD API endpoint |
| `EUVD_PER_PAGE` | `100` | EUVD page size |
| `EUVD_MAX_PAGES_PER_SYNC` | `200` | Max pages per EUVD sync |
| `EUVD_MIN_REQUEST_INTERVAL_MS` | inherits `HTTP_OUTBOUND_MIN_REQUEST_INTERVAL_MS` | Rate-limit pause (ms) |
| `EUVD_MAX_RETRIES` | inherits `HTTP_OUTBOUND_MAX_RETRIES` | Max retries |
| `EUVD_RETRY_BASE_BACKOFF_MS` | inherits `HTTP_OUTBOUND_RETRY_BASE_BACKOFF_MS` | Base backoff (ms) |

### OpenAI

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | _(empty)_ | OpenAI API key; AI features are disabled when absent |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI API base URL |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model name for AI-generated content |
| `OPENAI_ENABLED` | `true` | Feature gate for all OpenAI calls |

### Email (Resend)

| Variable | Default | Description |
|----------|---------|-------------|
| `RESEND_BASE_URL` | `https://api.resend.com` | Resend API base URL |
| `RESEND_API_KEY` | _(empty)_ | Resend API key |
| `RESEND_FROM_EMAIL` | _(empty)_ | Sender address for outgoing email |

### CMDB / ServiceNow

| Variable | Default | Description |
|----------|---------|-------------|
| `CMDB_SERVICENOW_BASE_URL` | _(empty)_ | ServiceNow instance URL (e.g. `https://tenant.service-now.com`) |
| `CMDB_SERVICENOW_USERNAME` | _(empty)_ | ServiceNow API username |
| `CMDB_SERVICENOW_PASSWORD` | _(empty)_ | ServiceNow API password |

### SCCM / MECM

| Variable | Default | Description |
|----------|---------|-------------|
| `SCCM_JDBC_URL` | _(empty)_ | JDBC URL for the SCCM MSSQL database |
| `SCCM_USERNAME` | _(empty)_ | SCCM database username |
| `SCCM_PASSWORD` | _(empty)_ | SCCM database password |
| `SCCM_MOCK_MODE` | `false` | Use mock data instead of a live SCCM connection |

### Outbound HTTP (global defaults)

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_CONNECT_TIMEOUT_MS` | `5000` | TCP connect timeout for all outbound HTTP clients |
| `HTTP_READ_TIMEOUT_MS` | `30000` | Read timeout for all outbound HTTP clients |
| `HTTP_OUTBOUND_MIN_REQUEST_INTERVAL_MS` | `0` | Rate-limit floor between outbound requests |
| `HTTP_OUTBOUND_MAX_RETRIES` | `3` | Default max retries |
| `HTTP_OUTBOUND_RETRY_BASE_BACKOFF_MS` | `500` | Default base backoff (ms) |
| `HTTP_OUTBOUND_MAX_BACKOFF_MS` | `60000` | Default max backoff cap (ms) |
| `HTTP_OUTBOUND_HONOR_RETRY_AFTER` | `true` | Respect `Retry-After` response headers |
| `HTTP_OUTBOUND_RETRY_ON_NETWORK_ERRORS` | `true` | Retry on connection/timeout errors |

### Correlation Queue

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_CORRELATION_DELTA_QUEUE_CAPACITY` | `500` | Max in-flight entries in the finding delta queue |
| `APP_CORRELATION_DELTA_QUEUE_ENQUEUE_TIMEOUT_MS` | `2000` | Timeout waiting to enqueue a delta entry (ms) |
| `APP_CORRELATION_DELTA_QUEUE_POLL_INTERVAL_MS` | `2000` | Drain job poll interval (ms) |

### Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `FEATURE_VEX_POLICY_ENABLED` | `true` | Enable VEX policy evaluation in correlation |
| `FEATURE_VEX_RISK_MODIFIERS_ENABLED` | `true` | Apply VEX assertions as risk score modifiers |
| `FEATURE_VEX_ROLLOUT_CONTROLS_ENABLED` | `true` | Show VEX rollout controls in the UI |
| `FEATURE_VEX_ROLLOUT_BACKFILL_ENABLED` | `true` | Run VEX backfill on startup |
| `FEATURE_SOFTWARE_MODEL_ENABLED` | `false` | Enable experimental software model features |

### SLO Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `SLO_SBOM_SUCCESS_RATE_MIN_PCT` | `95.0` | Minimum SBOM ingestion success rate (%) |
| `SLO_QUEUE_MAX_PENDING` | `100` | Max pending correlation queue entries before SLO alert |
| `SLO_QUEUE_STALE_THRESHOLD_MINUTES` | `10` | Age threshold for a stale queue entry |
| `SLO_QUEUE_STALE_MAX_COUNT` | `0` | Max stale entries allowed before SLO alert |

### Asset Lifecycle

| Variable | Default | Description |
|----------|---------|-------------|
| `ASSET_STALE_DAYS_TO_INACTIVE` | `30` | Days without a sync before an asset is marked inactive |

### Vulnerability Archive

| Variable | Default | Description |
|----------|---------|-------------|
| `ARCHIVE_LOCAL_PATH` | `./data/vulnerability-archives` | Local filesystem path for downloaded advisory archives |

### Cache (Caffeine)

Configured in `application.yml` (not env-overridable):

| Setting | Value |
|---------|-------|
| `maximumSize` | 100 entries |
| `expireAfterWrite` | 60 seconds |
| Cache names | `dashboard` |

---

## Frontend Environment Variables

All variables are prefixed `VITE_`. Copy `.env.example` to `.env.local` to configure for local development.

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE` | `http://localhost:8080/api` | Backend API base URL |
| `VITE_API_KEY` | `change-me-in-prod` | Value injected as `X-API-Key` header (local dev only) |
| `VITE_CREATOR_KEY` | `local-creator` | Value injected as `X-Creator-Key` (grants PLATFORM_OWNER in local dev) |
| `VITE_AUTH_TOKEN` | _(empty)_ | Static bearer token (overrides stored token from `localStorage`) |
| `VITE_SENTRY_DSN` | _(empty)_ | Sentry DSN for error reporting; disabled when absent |
| `VITE_ENABLE_TEST_PERSONAS` | `false` | Enable the persona switcher UI (non-production only) |
| `VITE_AUTH0_DOMAIN` | _(empty)_ | Auth0 tenant domain |
| `VITE_AUTH0_CLIENT_ID` | _(empty)_ | Auth0 application client ID |
| `VITE_AUTH0_SCOPE` | _(empty)_ | Auth0 requested scopes (e.g. `openid profile email`) |
| `VITE_AUTH0_AUDIENCE` | _(empty)_ | Auth0 API audience |

---

## Docker Build Details

### Backend

```
FROM maven:3.9.9-eclipse-temurin-17 AS build
  mvn -q -DskipTests dependency:go-offline
  mvn -q -DskipTests package

FROM eclipse-temurin:17-jre
  addgroup --system vulnwatch
  adduser --system --ingroup vulnwatch vulnwatch
  USER vulnwatch:vulnwatch
  EXPOSE 8080
```

JVM flags (set via `JAVA_OPTS` env var in the image):

```
-XX:MaxRAMPercentage=60.0
-XX:InitialRAMPercentage=10.0
-XX:MaxMetaspaceSize=192m
-XX:+ExitOnOutOfMemoryError
```

`JAVA_TOOL_OPTIONS` is also available for appending JVM agent flags (e.g. APM agents) without overriding `JAVA_OPTS`.

### Frontend

```
FROM node:20-alpine AS build
  npm ci
  npm run build

FROM nginx:1.27-alpine
  COPY nginx.conf /etc/nginx/conf.d/default.conf
  COPY dist → /usr/share/nginx/html
  EXPOSE 8080
```

Nginx is configured with `try_files $uri $uri/ /index.html` to support SPA client-side routing.

---

## `ProductionSafetyValidator` Startup Checks

`ProductionSafetyValidator` runs at `ApplicationReadyEvent`. It is **activated only when `APP_REQUIRE_PRODUCTION_SECRETS=true`**. When active, the application refuses to start if any of the following conditions are true:

| Condition | Error thrown |
|-----------|-------------|
| `APP_ALLOW_API_KEY_AUTH=true` | API key auth must be disabled |
| `APP_CREATOR_KEY` is set (non-blank) | Creator key must be unset |
| Neither `APP_JWT_ISSUER_URI` nor `APP_JWT_JWK_SET_URI` is set | JWT issuer or JWK URI must be configured |
| `APP_ALLOW_HEADER_TENANT_SELECTION=true` | Header tenant selection must be disabled |
| `APP_REQUIRE_TENANT_CONTEXT=false` | Tenant context must be required |
| `APP_CREDENTIAL_ENCRYPTION_KEY` is absent, blank, fewer than 24 chars, matches the placeholder `AAAA…A=`, or contains the string `replace-with` | Must be a non-default 256-bit base64 key |
| `APP_CORS_ALLOWED_ORIGINS` is blank or contains `*` | Must be set to explicit production origins |
| `APP_TEST_PERSONAS_ENABLED=true` | Test personas must be disabled |

---

## Authorization Rules by Endpoint

| Pattern | Required role / access |
|---------|----------------------|
| `OPTIONS /**` | Public (no auth) |
| `GET /actuator/health` | Public |
| `GET /actuator/info` | Public |
| `POST /api/auth/login` | Public |
| `POST /api/demo-requests` | Public |
| `/api/demo-invites/**` | Public |
| `/api/platform/**` | `ROLE_PLATFORM_OWNER` |
| `/api/operations/**` | `ROLE_PLATFORM_OWNER` |
| All other `/api/**` | Authenticated (any valid principal) |

---

## Security Response Headers

The following headers are injected on all responses by the backend:

| Header | Default value |
|--------|--------------|
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` |
| `X-Content-Type-Options` | `nosniff` (Spring Security default) |
| `X-Frame-Options` | `DENY` (Spring Security default) |

Override CSP and Permissions-Policy via `APP_CONTENT_SECURITY_POLICY` and `APP_PERMISSIONS_POLICY`.

---

## Credential Encryption

Stored connector credentials (ServiceNow passwords, SCCM passwords, etc.) are encrypted at rest using AES with the key from `APP_CREDENTIAL_ENCRYPTION_KEY`. The key must be a 256-bit value encoded as base64 (44 characters). The default placeholder `AAAA…A=` is blocked by `ProductionSafetyValidator` in production mode.

To generate a new key:

```bash
openssl rand -base64 32
```

---

## Multi-Tenancy Isolation

`TenantAwareDataSource` runs the following on every connection checkout:

```sql
SELECT set_config('app.current_tenant_id', '<uuid>', FALSE);
SELECT set_config('search_path', '<tenant_schema>,platform', FALSE);
```

On connection return, both settings are reset to prevent leakage between requests.

Tenant resolution order (per request):
1. `TenantResolutionFilter` — extracts tenant ID from JWT claim (`active_tenant_id` → `tenant_id` → `tenant_slug`) or `X-Tenant-ID` header (when `APP_ALLOW_HEADER_TENANT_SELECTION=true`)
2. `TenantStatusFilter` — blocks requests from `SUSPENDED` or `EXPIRED` tenants with HTTP 403

---

## Scheduled Jobs

| Schedule | Cron / Interval | Job |
|----------|----------------|-----|
| 00:15 daily | `0 15 0 * * *` | EOL lifecycle date sweep (catch components that crossed EOL since last Sunday run) |
| 01:00 daily | `0 0 1 * * *` | NVD incremental sync + CISA KEV sync |
| 01:15 daily | `0 15 1 * * *` | GHSA advisory sync |
| 01:45 daily | `0 45 1 * * *` | Microsoft + Red Hat CSAF/VEX sync |
| 02:05 daily | `0 5 2 * * *` | Mark stale assets inactive |
| 02:30 daily | `0 30 2 * * *` | VEX staleness recompute |
| 03:15 daily | `0 15 3 * * *` | EPSS score refresh (override via `EPSS_REFRESH_CRON`) |
| 07:00 daily | `0 0 7 * * *` | ServiceNow incident status sync (`FindingIncidentSyncService`) |
| 02:00 Sunday | `0 0 2 * * SUN` | EOL catalog refresh — stage 1 (override via `EOL_CATALOG_REFRESH_CRON`) |
| 03:00 Sunday | `0 0 3 * * SUN` | EOL release data refresh — stage 2 (override via `EOL_RELEASE_REFRESH_CRON`) |
| 03:30 Sunday | `0 30 3 * * SUN` | EOL slug resolution — stage 3 (override via `EOL_RESOLVE_MAPPINGS_CRON`) |
| 04:00 Sunday | `0 0 4 * * SUN` | EOL denormalization — stage 4 (override via `EOL_DENORMALIZE_CRON`) |
| Every 5 min | Fixed delay | Run enabled GitHub SBOM sources |
| Every 5 min | Fixed delay | Run enabled ServiceNow / SCCM / AWS Discovery scheduled syncs |
| Every 15 min | Fixed delay | Reopen findings whose suppression rules have expired |
| Every 2 sec | Fixed delay | Drain `finding_delta_queue` (batches of 100) |
| Hourly | Fixed rate | Policy-based auto-close for OPEN findings |
| Hourly | Fixed rate | Demo tenant expiry check (`DemoTenantExpiryJob`) |

---

## Actuator Endpoints

| Endpoint | Access |
|----------|--------|
| `GET /actuator/health` | Public — returns `{"status":"UP"}` |
| `GET /actuator/info` | Public — returns build/version info |

All other actuator endpoints are not exposed (configured via `management.endpoints.web.exposure.include: health,info`).

---

## CI Gates

### Backend

```
mvn -q verify
```

Runs in order:
1. **Surefire** — unit tests (excludes `*PostgresIntegrationTest.java`)
2. **Failsafe** (`-Ppostgres-it`) — Postgres integration tests (requires running PostgreSQL)
3. **JaCoCo `check`** — fails build if line coverage drops below the configured floor
4. **SpotBugs** — static analysis; fails on HIGH bugs

### Frontend

```
npm run lint        # ESLint; zero-warning policy on touched files
npm run typecheck   # tsc -b --noEmit
npm run build       # tsc -b --force && vite build
npm run test:coverage  # vitest run --coverage; enforces line/branch thresholds
```

Gates run in order; each gate must pass before the next runs.

---

## Known Limitations

- `ddl-auto=update` (Hibernate) is temporary; the goal is to switch to `validate` once the `postgres_reset/` DDL explicitly creates all tenant schema tables. Do not add logic that depends on Hibernate's `update` behavior.
- Multi-tenant hardening is in progress; most controllers currently resolve to a single default tenant via `TenantService.getDefaultTenant()`. Full multi-tenant operation requires completing the `tenant_id` compatibility tail (V1094–V1097 and forward).
- GHCR attestation ingestion does not perform cryptographic signature verification.
- SCCM sync is a full sweep on every run — no incremental delta sync.
- AWS Discovery is scoped to EC2 instances via SSM only (RDS, Lambda, S3, ECS, EKS were removed in V1069).
- S.AI Risk Score and S.AI Priority are computed entirely in the browser from existing API data — not stored in the database, not available via API.
- ServiceNow incident integration is not event-driven: Scout creates incidents and polls for status updates (`FindingIncidentSyncService` daily at 07:00), but does not push finding state changes back to ServiceNow.
- AI features (`OPENAI_ENABLED`) call OpenAI on first invocation; results are persisted in `org_cve_ai_artifacts` so subsequent reads do not re-call the API.

---

## Production Deployment Checklist

- [ ] `APP_REQUIRE_PRODUCTION_SECRETS=true`
- [ ] `APP_ALLOW_API_KEY_AUTH=false`
- [ ] `APP_CREATOR_KEY` unset
- [ ] `APP_JWT_ISSUER_URI` or `APP_JWT_JWK_SET_URI` set to OIDC provider
- [ ] `APP_ALLOW_HEADER_TENANT_SELECTION=false`
- [ ] `APP_REQUIRE_TENANT_CONTEXT=true`
- [ ] `APP_CREDENTIAL_ENCRYPTION_KEY` set to a fresh 256-bit base64 key (`openssl rand -base64 32`)
- [ ] `APP_CORS_ALLOWED_ORIGINS` set to explicit production domain(s)
- [ ] `APP_TEST_PERSONAS_ENABLED=false`
- [ ] `VITE_ENABLE_TEST_PERSONAS=false` (or absent) in frontend build
- [ ] `NVD_API_KEY` set (avoids strict unauthenticated rate limits)
- [ ] `GITHUB_API_TOKEN` or `GITHUB_API_TOKEN_FILE` set for SBOM / GHSA features
- [ ] `RESEND_API_KEY` and `RESEND_FROM_EMAIL` set for email notifications
- [ ] `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` point to a production PostgreSQL instance
- [ ] Flyway migrations applied cleanly (`validate-on-migrate: true` will block startup on mismatch)
- [ ] `ARCHIVE_LOCAL_PATH` points to a durable volume (not ephemeral container filesystem)
- [ ] Container memory allocation ≥ 1 GB (backend `MaxRAMPercentage=60.0` uses up to 60% of container memory)
- [ ] PostgreSQL connection pool (`maximum-pool-size: 20`) matches RDS/instance `max_connections`
