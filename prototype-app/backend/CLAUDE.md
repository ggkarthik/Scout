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

## Database migrations

Migration SQL lives in `src/main/resources/db/migration/postgres_reset/`. Flyway is configured to use this location (`spring.flyway.locations: classpath:db/migration/postgres_reset`).

- There is currently a single baseline migration: `V1__platform_and_default_tenant_schemas.sql`.
- `baseline-on-migrate` is `false` in `application.yml` (default) and `true` in `application-local.yml`.
- All statements use `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`, making the V1 SQL idempotent.
- If `platform.app_user_global_roles` or other platform tables are missing, run the V1 SQL directly via psql: it will only create what is absent.

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
               # JwtDecoderConfig, TenantAwareDataSource, TenantResolutionFilter, WebConfig
  controller/  # 37 REST controllers under /api/**
  service/     # 180 business-logic services
  domain/      # 80 JPA entities
  dto/         # 172 API request/response objects
  repo/        # 54 Spring Data JPA repositories
  client/      # 19 external API clients (NVD, GHSA, CSAF, EPSS, GitHub, ServiceNow, AWS…)
  security/    # SensitiveTenantAction annotation + interceptor
  util/        # CPE handling, version comparison, SBOM parsing
```

## Docker build

```bash
docker build -t vulnwatch-backend .
docker run -e DB_URL=... -e APP_JWT_ISSUER_URI=... -p 8080:8080 vulnwatch-backend
```

JVM flags in the image: `-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError`.
