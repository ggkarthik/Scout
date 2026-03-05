# VulnWatch Prototype

Last updated: 2026-03-03

This repository contains a Spring Boot + React prototype for SBOM-based vulnerability correlation.

## Current Correlation Model (Implemented)

The backend now uses one deterministic model for applicability/impact projection:

1. CPE 2.3 normalization into `cpe_dim`.
2. Tenant inventory projection into `inventory_component_cpe_map`.
3. CVE/advisory CPE targets in `vulnerability_targets.cpe_id`.
4. Indexed join on `cpe_id` to generate candidate matches.
5. Deterministic version checks (`exact`, `introduced/fixed`, `start/end` inclusive/exclusive).
6. VEX overlay applied after base applicability (status precedence + deterministic tie-break).

Intentionally disabled for runtime candidate generation:

- PURL exact matching
- COORD matching
- advisory-package direct matching
- repo matching
- digest matching
- fuzzy/AI matching

Current `matchedBy` values in correlation evidence:

- `cpe-indexed-direct+version`
- `cpe-indexed-fallback+version`

## Scope and Data Boundaries

- Global vulnerability intel remains immutable in global tables:
  - `vulnerabilities`
  - `vulnerability_intel_summary`
  - `vulnerability_intel_observations`
- Tenant-specific outcomes are projected in tenant-scoped tables:
  - `findings` (created and updated by deterministic CPE correlation)
  - `inventory_components`
  - `inventory_component_cpe_map`

## Incremental Correlation Triggers

- Software delta (`SBOM`): `FindingService.recomputeOnSoftwareDelta(tenantId, componentId)`.
- CVE delta (`NVD/GHSA/KEV/Advisory` target changes): `FindingService.recomputeOnCveDelta(vulnerabilityId)`.
- VEX delta (`CSAF/VEX` statement changes): `FindingService.applyVexDelta*` updates overlay state without full rejoin.

## Architecture

- `backend/` Java 17, Spring Boot, Spring Data JPA
  - Default DB: H2 file
  - Schema style: entity-first (`spring.jpa.hibernate.ddl-auto=update`)
- `frontend/` React + Vite

## Run Locally

Backend:

```bash
cd backend
mvn spring-boot:run
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Default URLs:

- Backend: `http://localhost:8080`
- Frontend: `http://localhost:5173`

## Key Endpoints

Ingestion:

- `POST /api/sbom-upload`
- `POST /api/sbom-fetch`
- `POST /api/sbom-fetch/github`
- `POST /api/ingestion/nvd-sync`
- `POST /api/ingestion/nvd-full-sync`
- `POST /api/ingestion/kev-sync`
- `POST /api/ingestion/ghsa-sync`
- `POST /api/ingestion/csaf/microsoft-sync`
- `POST /api/ingestion/csaf/redhat-sync`
- `POST /api/ingestion/advisories`

Read/workflow:

- `GET /api/dashboard`
- `GET /api/findings`
- `GET /api/findings/filters`
- `GET /api/vulnerability-intelligence`
- `GET /api/vulnerability-intelligence/{externalId}`
- `GET /api/inventory/components`
- `GET /api/sbom-uploads`

## Documentation

- Backend architecture and API behavior: `docs/backend.md`
- Frontend architecture and UI behavior: `docs/frontend.md`
- Database schema and data flows: `docs/database.md`
