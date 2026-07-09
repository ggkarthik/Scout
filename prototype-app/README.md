# VulnWatch Prototype

Last updated: 2026-07-07

VulnWatch is a Spring Boot + React prototype for SBOM ingestion, vulnerability intelligence ingestion, deterministic CPE-based correlation, and tenant-scoped finding projection and workflow.

## Documentation

| Document | Contents |
|----------|---------|
| [Architecture](docs/architecture.md) | System shape, data flow, security model, tech decisions |
| [Backend](docs/backend.md) | REST API reference, services, external integrations, config |
| [Business Logic Guide](docs/business-logic-guide.md) | Domain concepts, pipeline flows, finding lifecycle, EOL tracking |
| [Database](docs/database.md) | Schema design, table inventory, migration strategy |
| [Frontend](docs/frontend.md) | React app structure, routes, components, state management |
| [Performance Governance Runbook](docs/runbooks/performance-governance.md) | CI/nightly certification flow, runtime roles, rollback gates |

## Quick Start

### Backend

```bash
cd backend
mvn spring-boot:run                                    # default profile (port 8080)
mvn spring-boot:run -Dspring-boot.run.profiles=local   # local profile: JWT auth + header tenant selection
```

For GitHub SBOM / GHCR / GHSA features, place a GitHub token in `backend/secrets/github-api-token` before starting. That path is gitignored. Token resolution order: `GITHUB_API_TOKEN_FILE` → `backend/secrets/github-api-token` → `GITHUB_API_TOKEN`.

### Frontend

```bash
cd frontend
npm install
npm run dev    # dev server on port 5173
```

### Default Local URLs

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8080/api`
- Performance scorecard helper: `./scripts/performance-scorecard.sh`
- Baseline warmup helper: `./scripts/performance-baseline.sh`
- Correlation freshness helper: `./scripts/correlation-certification.sh`
- Full enterprise certification helper: `./scripts/enterprise-performance-certification.sh`

Set `APP_RUNTIME_ROLE=api` on API-serving nodes to suppress scheduled background workers there while keeping default local behavior unchanged. Leave it unset or set it to `all` for the current single-node setup.
Set `MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus` when running the performance and correlation certification scripts in environments where Prometheus exposure is not enabled by default.

Example enterprise certification pass:

```bash
cd prototype-app
BASE_URL=http://127.0.0.1:8080 \
API_KEY=change-me-in-prod \
CREATOR_KEY=local-creator \
SEED_DEMO_DATA=true \
FAIL_ON_NONCOMPLIANT=true \
./scripts/enterprise-performance-certification.sh
```

This orchestrates the baseline capture, correlation/freshness certification, and a final performance scorecard snapshot into one artifact directory.

For a one-command local or CI governance pass that can start the backend, wait for readiness, and emit the certification artifact set:

```bash
cd prototype-app
BASE_URL=http://127.0.0.1:8080 \
API_KEY=change-me-in-prod \
CREATOR_KEY=local-creator \
START_BACKEND=true \
SPRING_PROFILES_ACTIVE=local \
MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus \
sh ./scripts/run-performance-governance.sh
```

## Performance Governance

The repository now includes a dedicated GitHub Actions workflow:

- `.github/workflows/performance-governance.yml`

It runs:

- nightly on a schedule
- on pull requests that touch backend, script, docs, and workflow changes
- on demand through `workflow_dispatch`

The workflow boots the backend against a Postgres service using the `local` profile, runs the full enterprise certification pass, and uploads the resulting artifacts for review. Demo seeding is off by default and only enabled through explicit manual dispatch input.

### Default Local Auth

The frontend injects these headers automatically in local dev:

| Header | Default value |
|--------|--------------|
| `X-API-Key` | `change-me-in-prod` |
| `X-Creator-Key` | `local-creator` |
| `X-Tenant-ID` | `1` |
| `X-User-ID` | `local-analyst` |

Localhost credential login is also available for convenience:

| Account | Email | Password |
|---------|-------|----------|
| Platform owner | `platform.owner@localhost` | `LocalDevPlatform123!` |
| Tenant admin | `tenant.admin@localhost` | `LocalDevTenant123!` |

These credentials are loopback-only and do not activate for non-localhost hosts.

## Core Runtime Shape

| Component | Stack |
|-----------|-------|
| Frontend | React 18 + TypeScript + Vite |
| Backend | Java 17 + Spring Boot 3.3.2 + Spring Data JPA + Spring Security |
| Database | PostgreSQL, schema-per-tenant |
| Migrations | Flyway (`postgres_reset/` line), `ddl-auto=none` |

## Database Setup

The reset-line migration at `backend/src/main/resources/db/migration/postgres_reset/V1__platform_and_default_tenant_schemas.sql` creates the `platform` schema and `tenant_default` schema. Hibernate (in `update` mode, temporary) materializes the full table structure on first start.

If your local `vulnwatch` database has the old shared-schema layout, drop and recreate it before running the reset-line migrations:

```bash
psql postgres -c "DROP DATABASE IF EXISTS vulnwatch;"
psql postgres -c "CREATE DATABASE vulnwatch;"
```

For an offline parity comparison against an archived H2 snapshot:

```bash
cd backend
./tools/run-database-parity.sh
```

## Tests

```bash
# Backend
cd backend
mvn test                          # unit tests + JaCoCo
mvn -Ppostgres-it verify          # unit + Postgres integration tests

# Frontend
cd frontend
npm run lint && npm run typecheck && npm run test:coverage
```

## CI Gates

Backend: `mvn -q verify` — Surefire (units) + Failsafe (Postgres ITs) + JaCoCo coverage floor + SpotBugs.

Frontend: `npm run lint` → `npm run typecheck` → `npm run build` → `npm run test:coverage`.
