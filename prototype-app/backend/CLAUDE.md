# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> The root `../CLAUDE.md` contains full project conventions, architecture, scheduling, and the never-touch list. This file adds backend-specific runtime detail.

## Commands

```bash
# Run the API server (port 8080, default profile)
mvn spring-boot:run

# Run with local profile (enables header-based tenant selection, JWT auth, no prod-secret check)
mvn spring-boot:run -Dspring-boot.run.profiles=local

# Unit tests only (Surefire; excludes *PostgresIntegrationTest.java)
mvn test

# Unit + Postgres integration tests (Failsafe; requires local Postgres)
mvn -Ppostgres-it verify

# Run a single test class
mvn test -Dtest=MyServiceTest

# Run a single Postgres IT class
mvn -Ppostgres-it verify -Dit.test=MyServicePostgresIntegrationTest

# Repair Flyway history after schema drift
# -Dflyway.schemas=tenant_default is required — flyway_schema_history lives there, not public
mvn -q \
  -Dflyway.url=jdbc:postgresql://localhost:5432/vulnwatch \
  -Dflyway.user="$USER" \
  -Dflyway.password= \
  -Dflyway.schemas=tenant_default \
  -Dflyway.locations=filesystem:src/main/resources/db/migration/postgres_reset \
  flyway:repair
```

## Authentication and request auth model

Every `/api/**` request goes through `ApiKeyAuthenticationFilter` (runs before `UsernamePasswordAuthenticationFilter`) before reaching a controller. Two auth paths:

**API key auth** (`X-API-Key` header, enabled when `app.security.allow-api-key-auth=true`):
- Grants `ROLE_OPERATOR`, `ROLE_SECURITY_ANALYST` to all callers.
- `X-Creator-Key` (or an unconfigured creator key) additionally grants `ROLE_CREATOR`, `ROLE_PLATFORM_OWNER`, `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN`.
- `X-User-ID` header sets the user identity; defaults to `APP_DEFAULT_USER_ID` (`local-analyst`).
- Local defaults: api-key `change-me-in-prod`, no creator-key (all callers get creator-level access).

**JWT Bearer auth** (`Authorization: Bearer <token>`):
- `JwtDecoder` bean is only created when `APP_JWT_ISSUER_URI` is set (see `JwtDecoderConfig`).
- Decoded JWT is passed to `JwtTenantAuthenticationService.authenticate()`, which: resolves or creates the `platform.app_users` record, extracts roles from `APP_JWT_ROLES_CLAIM` (default `roles`), also handles namespaced claims ending in `/roles`, sets `TenantContext` from JWT tenant claims.
- The resulting `AuthenticatedTenantActor` is stored as a `TenantAuthenticationDetails` on the `SecurityContext`.

**Authorization rules** (from `SecurityConfig`):
- `/api/platform/**` and `/api/operations/**` → `ROLE_PLATFORM_OWNER` required
- All other `/api/**` → authenticated
- Public: OPTIONS, `/actuator/health`, `/actuator/info`, `POST /api/auth/login`, `POST /api/demo-requests`, `/api/demo-invites/**`

## Multi-tenancy

`TenantAwareDataSource` wraps every connection from the HikariCP pool and runs:
```sql
SELECT set_config('app.current_tenant_id', '<uuid>', FALSE);
SELECT set_config('search_path', '<tenant_schema>,platform', FALSE);
```
On connection close it resets both. This means all JPA queries automatically hit the correct schema without any application-layer schema prefix on queries.

`TenantContext` (thread-local) carries the current tenant UUID and schema name. `ApiKeyAuthenticationFilter` calls `TenantContext.clear()` in a `finally` block. JWT auth sets `TenantContext.setCurrentTenantId(actor.tenantId())` inside the filter.

`APP_ALLOW_HEADER_TENANT_SELECTION=true` (local profile default) lets clients override the tenant via `X-Tenant-ID` header. Must be disabled in production.

### Tenant context must be set BEFORE the transaction begins (critical invariant)

`TenantAwareDataSource` pins a connection's `search_path` (and `app.current_tenant_id`) **at the moment the connection is acquired**, from whatever `TenantContext` holds then — it does not re-read on later queries. A Spring transaction binds its connection at the start of the transaction. Therefore the tenant must be selected *before* the transaction opens.

This is fine for HTTP-invoked code: the auth filter sets `TenantContext` before any `@Transactional` controller/service method runs, so the bound connection already points at the right schema.

It is a trap for **background code** (scheduled jobs, async workers, `@PostConstruct`). A method shaped like this:

```java
@Transactional                                   // transaction (and connection) bound FIRST...
public X doWork(Tenant tenant) {
    return tenantSchemaExecutionService.run(tenant, () -> { ... });  // ...context switched too LATE
}
```

silently runs against `tenant_default` for **every** tenant when called from a thread with no pre-set context — the `search_path` was pinned (to the default schema) before `run()` switched `TenantContext`. No error; it just queries the wrong schema. This caused the async ingestion worker and the finding-delta drain to process only the default tenant.

Correct pattern — context first, transaction inside:

```java
public X doWork(Tenant tenant) {                 // no method-level @Transactional
    return tenantSchemaExecutionService.run(tenant, () ->
        transactionTemplate.execute(status -> { ... }));   // tx opens with context already set
}
```

Equivalently, wrap the call at the background call site in `tenantSchemaExecutionService.run(tenant, () -> service.theTransactionalMethod(...))`. Audit any `@Transactional` method that calls `tenantSchemaExecutionService.run(...)` internally and is reachable from a scheduled/async path.

A scheduled poller/drain over a **per-tenant** table (`ingestion_jobs`, `finding_delta_queue`, etc.) must iterate `tenantService.listTenants()` and run each tenant's claim+process inside `run(tenant, …)` — the scheduler thread carries no context, so a bare drain only ever touches `tenant_default`.

### Scheduled tasks

`SchedulingConfig` provides the `TaskScheduler` (multi-thread pool + log-and-continue error handler). Spring's default would otherwise (a) run all `@Scheduled` methods on one thread and (b) **permanently unschedule** a periodic task that throws. Still, every `@Scheduled fixedDelay` method should guard its entire body in try/catch so a transient failure can never silently kill the task.

## Database migrations

Migration SQL lives in `src/main/resources/db/migration/postgres_reset/`. Flyway is configured to use this location (`spring.flyway.locations: classpath:db/migration/postgres_reset`).

- `V1__platform_and_default_tenant_schemas.sql` is a large consolidated baseline (60+ tables) — a prior drift-repair effort reset and renumbered the whole migration line into it, so it is not a "day one" schema. Current latest is `V41__azure_discovery_targets.sql`.
- `baseline-on-migrate` is `false` in `application.yml` (default) and `true` in `application-local.yml`.
- All statements use `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`, making every migration idempotent to replay.
- If `platform.app_user_global_roles` or other platform tables are missing, run the V1 SQL directly via psql: it will only create what is absent.
- Notable recent migrations: `V29__tenant_rls_rollout_gate.sql` (defers full RLS enforcement to a later rollout phase), `V38__tenant_entitlement_overrides.sql`, `V39__software_identity_metadata.sql`, `V40`/`V41` (Azure Discovery configs/targets).

## Key env vars for local dev

Set in `application-local.yml` or as env vars:

| Env var | Purpose | Local default |
|---|---|---|
| `DB_URL` | JDBC URL | `jdbc:postgresql://localhost:5432/vulnwatch` |
| `APP_JWT_ISSUER_URI` | OIDC issuer; enables JWT auth when set | (empty = disabled) |
| `APP_SECURITY_JWT_AUDIENCE` | Expected JWT audience | (empty) |
| `APP_JWT_ROLES_CLAIM` | Claim name for roles in JWT | `roles` |
| `APP_ALLOW_HEADER_TENANT_SELECTION` | Trust `X-Tenant-ID` header | `false` (local: `true`) |
| `APP_REQUIRE_TENANT_CONTEXT` | Enforce tenant context on every request | `true` (local: `false`) |
| `APP_ALLOW_API_KEY_AUTH` | Enable X-API-Key auth path | `true` |
| `OPENAI_API_KEY` | OpenAI key for AI-assist features | (empty = AI features off) |
| `NVD_API_KEY` | NVD rate-limited API key | (empty = unauthenticated) |
| `GITHUB_API_TOKEN` | GitHub token for SBOM/GHSA | resolved from `backend/secrets/github-api-token` |

## Postgres integration test scaffolding

Tests whose file name ends with `PostgresIntegrationTest.java` are excluded by Surefire and picked up by Failsafe under `-Ppostgres-it`. They require a local Postgres instance.

Use the composed annotations and helpers from `src/test/java/com/prototype/vulnwatch/support/`:

| Class | Purpose |
|---|---|
| `@PostgresIntegrationTest` | Service/repo-layer IT (no MockMvc) |
| `@PostgresControllerIntegrationTest` | Controller IT with MockMvc auto-configured |
| `LocalPostgresTestDatabase.provision("unique_key")` | Creates `vulnwatch_it_<key>` DB; idempotent |
| `PostgresITSupport.registerDatabaseProperties(registry, db)` | Wires dynamic Postgres props |
| `AuthRequest.authedGet/Post/Put/Delete` | Adds `X-API-Key` header automatically |
| `AuthRequest.asPlatformOwner(request)` | Adds creator key (grants PLATFORM_OWNER) |

Minimal controller IT skeleton — see `src/test/java/com/prototype/vulnwatch/support/README.md` for the full template.

Do not add `@Transactional` to controller ITs. Mock outbound HTTP with `MockRestServiceServer`.

## Package layout

```
com.prototype.vulnwatch/
  config/      # Spring beans: SecurityConfig, ApiKeyAuthenticationFilter,
               # JwtDecoderConfig, TenantAwareDataSource, ProductionSafetyValidator,
               # TenantResolutionFilter, WebConfig (16 files)
  controller/  # 41 REST controllers under /api/**
  service/     # 236 business-logic services
  domain/      # 121 JPA entities
  dto/         # 257 API request/response objects
  repo/        # 77 Spring Data JPA repositories
  client/      # 21 external API clients (NVD, EUVD, JVN, GHSA, CSAF, EPSS, GitHub, ServiceNow, AWS, Azure…)
  security/    # SensitiveTenantAction annotation + interceptor (2 files)
  util/        # CPE handling, version comparison, SBOM parsing (6 files)
```

Newer, less-obvious controllers worth knowing about: `CampaignController` (`/api/campaigns` — remediation campaigns), `CbomController` (`/api/bom/cbom` — cloud BOM posture), `BomController` (`/api/bom`), `AzureDiscoveryController` (`/api/connectors/azure-discovery`), `IngestionJobController` (`/api/ingestion-jobs`).

## Docker build

```bash
docker build -t vulnwatch-backend .
docker run -e DB_URL=... -e APP_JWT_ISSUER_URI=... -p 8080:8080 vulnwatch-backend
```

JVM flags in the image: `-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError`.
