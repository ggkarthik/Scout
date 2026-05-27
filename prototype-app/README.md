# VulnWatch Prototype

Last updated: 2026-05-27

VulnWatch is a Spring Boot + React prototype for SBOM ingestion, vulnerability intelligence ingestion, deterministic CPE-based correlation, and tenant-scoped finding projection and workflow.

## Documentation

| Document | Contents |
|----------|---------|
| [Architecture](docs/architecture.md) | System shape, data flow, security model, tech decisions |
| [Backend](docs/backend.md) | REST API reference, services, external integrations, config |
| [Business Logic Guide](docs/business-logic-guide.md) | Domain concepts, pipeline flows, finding lifecycle, EOL tracking |
| [Database](docs/database.md) | Schema design, table inventory, migration strategy |
| [Frontend](docs/frontend.md) | React app structure, routes, components, state management |
| [Production Readiness](docs/production-readiness.md) | Deployment, env vars, health checks, monitoring |
| [Non-Production Test Personas](docs/non-production-test-personas.md) | Dev/preprod persona setup and manual check procedures |
| [Customer Demo Runbook](docs/runbooks/customer-demo.md) | Step-by-step demo provisioning and walkthrough |

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
