# VulnWatch Frontend Documentation

Last updated: 2026-03-03

## What The Frontend Does

The frontend is a React single-page console for security operations. It drives ingestion, inventory visibility, vulnerability intelligence, and operational analytics by calling backend `/api` endpoints.

## Stack And Runtime

- React 18 + TypeScript
- Vite 5
- No external state library; React state/hooks are used throughout
- No React Router; navigation is tab/query-param driven in `App.tsx`

Run locally:

```bash
cd frontend
npm install
npm run dev
```

Default URL: `http://localhost:5173`

## API Integration

Central API client: `src/api/client.ts`.

Environment variables:

- `VITE_API_BASE` (default `http://localhost:8080/api`)
- `VITE_API_KEY` (default `change-me-in-prod`)
- `VITE_CREATOR_KEY` (default `local-creator`)

Behavior:

- Every request sends `X-API-Key`.
- `X-Creator-Key` is sent when configured.
- Standard JSON error envelope is parsed into user-facing messages.
- Multipart upload (`/sbom-upload`) uses dedicated `uploadSbom(...)`.

## App Shell And Navigation

`App.tsx` renders a left navigation + content area:

- Overview (`DashboardPage`)
- Findings (`FindingsPage`)
- Operations (`OperationalDashboardPage`)
- Vulnerability Intelligence (`InventoryPage` with vuln-intel view)
- Software Models (`InventoryPage` with models view)
- Inventory (`InventoryPage` with inventory view variants)
- Connect (`ConnectPage`)
- Configurations (`ConfigurationsPage`)

State is mirrored into URL query params (`tab`, `inventoryView`, `ingestMode`, etc.) for deep-link style behavior.

## Key Screens

### Dashboard

- Calls `GET /dashboard`.
- Shows top KPIs, severity distribution, security score, CPE correlation efficiency, and CSAF/VEX analytics.

### Findings

- Calls `GET /findings` and `GET /findings/filters`.
- Uses filter-builder + active-chip UX and multi-group-by controls.
- Defaults to CPE correlation scope (`cpe-*` match methods) for phased rollout.

### Operations

- Calls `GET /operations/dashboard`.
- Auto-refreshes every 15 seconds.
- Shows ingestion efficiency, normalization quality, read-path metrics, freshness drift, and metric catalog.
- Handles creator-access errors with guided setup messaging.

### Inventory (multi-view)

- Component inventory: `GET /inventory/components`, `GET /inventory/components/filters`
- Software models: `GET /inventory/software-models`
- Vulnerability intelligence list/detail:
  - `GET /vulnerability-intelligence`
  - `GET /vulnerability-intelligence/filters`
  - `GET /vulnerability-intelligence/{externalId}`

Notes:

- Supports filter-builder style query controls.
- Uses async filter loading for vulnerability intelligence while rendering rows quickly.

### Connect

Connector catalog that routes to focused workflows:

- SBOM upload / endpoint / GitHub generated SBOM (`IngestionPage`)
- ServiceNow-style CMDB sync (`AssetsPage`)
- Source sync triggers (NVD, KEV, GHSA, CSAF/VEX, advisories) via `SourcesPage`

### Ingestion

`IngestionPage` supports:

- File upload (`/sbom-upload`)
- Endpoint fetch (`/sbom-fetch`)
- GitHub generated SBOM (`/sbom-fetch/github`)
- Upload history/evidence view (`GET /sbom-uploads`)

### Configurations

- Risk policy editor (`GET/POST /risk-policy`)
- GitHub auto-ingestion pipeline management (`/github-sbom-sources`)
- Embedded integration queue monitor (`SourcesPage`)

### Assets

- CMDB sync payload builders (form/CSV/JSON)
- Calls `POST /assets/cmdb-sync` and refreshes `GET /assets`

## Shared UI Components

- `ResizableTable`: persisted user-adjustable column widths
- `FilterBuilder` and `FilterValueSelectCard`: dynamic filtering UI
- `StatCard` and `SeverityPill`: KPI/status presentation

## Important Implementation Notes

- The app is designed as an operations prototype, not a public-facing site.
- Some legacy page files exist (for example `PolicyPage`) but are not active in current navigation.
- Frontend behavior assumes the backend API key model and single-workspace backend mode.
