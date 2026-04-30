# VulnWatch Prototype

Last updated: 2026-04-29

VulnWatch is a Spring Boot + React prototype for SBOM ingestion, vulnerability intelligence ingestion, deterministic CPE-based correlation, and tenant-scoped finding projection.

## Documentation

The repository documentation is intentionally consolidated into four maintained documents:

- [Architecture](docs/architecture.md)
- [Frontend](docs/frontend.md)
- [Backend](docs/backend.md)
- [Database](docs/database.md)
- [Business logic guide](docs/business-logic-guide.md)
- [Production readiness](docs/production-readiness.md)
- [AWS deployment runbook](docs/runbooks/aws-deployment.md)

Historical implementation summaries, design notes, report cards, and migration checklists were folded into those files so the repo only has one source of truth per area.

## Quick Start

Backend:

```bash
cd backend
mvn spring-boot:run
```

If you want GitHub-backed repo or GHCR SBOM ingestion locally, put a GitHub token in
`backend/secrets/github-api-token` before starting the backend. That path is gitignored.
The same token is reused across GitHub repo SBOM fetches, GHCR ingestion, and GitHub advisory syncs.
It needs package-read access for GHCR discovery.

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Default local URLs:

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8080/api`

Default local auth values used by the frontend:

- `X-API-Key`: `change-me-in-prod`
- `X-Creator-Key`: `local-creator`
- `X-Tenant-ID`: `1`
- `X-User-ID`: `local-analyst`

## Core Runtime Shape

- `frontend/`: React 18 + TypeScript + Vite SPA
- `backend/`: Java 17 + Spring Boot 3.3, Spring Web, Spring Data JPA, Spring Security
- Database: PostgreSQL
- Schema management: Flyway-managed PostgreSQL migrations with `spring.jpa.hibernate.ddl-auto=none`

## PostgreSQL Notes

If an older local PostgreSQL `vulnwatch` database already has Flyway history from before the migration files stabilized, repair it once:

```bash
cd backend
mvn -q \
  -Dflyway.url=jdbc:postgresql://localhost:5432/vulnwatch \
  -Dflyway.user="$USER" \
  -Dflyway.password= \
  -Dflyway.locations=filesystem:src/main/resources/db/migration/postgres \
  flyway:repair
```

The old H2 files are kept only as offline archive artifacts. If you need a one-off parity comparison against an archived H2 snapshot:

```bash
cd backend
./tools/run-database-parity.sh
```

The parity helper is outside the Maven build on purpose, so H2 is no longer part of the normal app or test dependency graph.

For implementation details, API groupings, schema notes, and current limitations, use the docs above instead of older milestone-style markdown.
