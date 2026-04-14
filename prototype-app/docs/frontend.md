# VulnWatch Frontend

Last updated: 2026-04-14

## Purpose

The frontend is a React single-page operations console. It drives SBOM ingestion, vulnerability intelligence review, org-level CVE exposure review, findings workflows, connector setup, and configuration management against the backend `/api` surface.

## Stack

- React 18
- TypeScript
- Vite 5
- Plain React state/hooks; no external state library
- React Router for path-based navigation in `src/App.tsx`
- No query-param-only navigation; deep links use URL paths (`/vuln-repo/org-cves/:cveId`, `/inventory/hosts/:assetId`, etc.)

Run locally:

```bash
cd frontend
npm install
npm run dev
```

Default URL: `http://localhost:5173`

## API Client

Primary client: `src/api/client.ts`.

Environment variables:

- `VITE_API_BASE` defaults to `http://localhost:8080/api`
- `VITE_API_KEY` defaults to `change-me-in-prod`
- `VITE_CREATOR_KEY` defaults to `local-creator`
- `VITE_TENANT_ID` defaults to `1`
- `VITE_USER_ID` defaults to `local-analyst`

Every JSON request includes:

- `X-API-Key`
- `X-Tenant-ID`
- `X-User-ID`
- `X-Creator-Key` when configured

The client also handles:

- JSON error-envelope parsing into readable messages
- multipart SBOM uploads
- org-CVE drill-down calls
- risk policy, GitHub source, sync run, and prototype reset calls
- ServiceNow CMDB connector config, connection test, live sync, and sample sync calls
- host asset detail and host inventory calls
- EOL status summary, component statuses, product catalog, release cycles, mapping confirmation, unresolved mappings, and admin refresh triggers
- SLO status polling (`/slo/status`)
- vulnerability source filter config reads and saves (`/connectors/vulnerability-sources/{sourceSystem}`)
- Vulnerability Repository dashboard, vulnerability list, org-CVE list, and software-asset drilldown calls (`/vuln-repo/**`)

## Navigation Model

`src/App.tsx` renders a sidebar shell using React Router. Navigation uses URL paths, not query params. The `src/app/routes.ts` module owns path builders (`pathForTab`, `pathForVulnRepoView`, `pathForInventoryView`, `pathForConnectView`, etc.) and tab title mappings.

Legacy query-param URLs (`?tab=`, `?inventoryView=`, etc.) are redirected to their path equivalents by `LegacyQueryRedirect`.

Current top-level sections (nav tab key → display label → path):

- `dashboard` → Overview → `/`
- `findings` → Findings → `/findings`
- `operations` → Operational Dashboard → `/operations/:operationsView?`
- `vuln-repo` → Vulnerability Repository → `/vuln-repo`
- `inventory` → Inventory → `/inventory/:inventoryView?`
- `end-of-life` → End-of-Life → `/end-of-life`
- `connect` → Connect → `/connect/:connectView?`
- `configurations` → Configurations → `/configurations`

The active app is organized as a shell with path-routed content areas. Most drill-downs happen inline in tables, drawers, and modals. Certain deep links (host asset detail, CVE detail with selected CVE, CVE assets/software drilldown) have dedicated route paths.

The topbar includes a **⌘K / Ctrl+K** keyboard shortcut that focuses the jump-to-page search input. The theme toggle is an icon-only button (sun/moon SVG) rather than a text label.

## Main Experiences

### Overview

- `DashboardPage`
- Reads `/dashboard`, `/dashboard/applicable-software`, `/dashboard/impacted-cves`, and `/dashboard/cve-inventory-map`
- Focuses on risk posture only: high-level exposure counts, severity/risk summaries, and risk-oriented CVE views
- Does not surface operational, pipeline, quality, freshness, correlation-efficiency, or CSAF/VEX analytics panels

### Findings

- `FindingsPage`
- Reads `/findings` and `/findings/filters`
- Supports severity, status, decision state, VEX, match-method, and package filters

### Operations

- `OperationalDashboardPage`
- Has three sub-views accessible via a flyout menu: **Quality**, **Pipeline**, **Platform Health**
- Quality reads `/operations/quality/summary`, `/operations/quality/issues`, `/operations/quality/filters`, and `/operations/quality/issues/{issueId}`
- Pipeline reads `/operations/dashboard` for ingestion queue and run history
- Pipeline includes correlation efficiency diagnostics such as CPE coverage, direct vs fallback share, recent CPE-created findings, and CSAF/VEX quality analytics
- Platform Health reads operational metrics via `/operations/normalization-quality`, `/operations/api-read-path`, `/operations/freshness-drift`, `/operations/metric-catalog`, and `/api/slo/status`
- the Platform Health summary includes noise-projection readiness, age, refresh failures, and projection refresh p95; it also exposes SLO status (defined/passing/failing counts and per-SLO pass/fail indicators)
- the Pipeline view label `Queued/Running Sync Jobs` refers to sync backlog, not durable delta-queue depth
- Sub-view is tracked in the `:operationsView` route param

### Vulnerability Repository

The `vuln-repo` section replaces what was previously labelled "Vulnerability Intelligence" in the sidebar. It has two sub-views accessible via a section tab bar:

- **Dashboard** (`VulnRepoDashboardPage`, path `/vuln-repo`) — summary metrics, critical/unresolved CVE list, and severity breakdown; links to host-asset and software-asset drilldowns
- **Vulnerabilities** (`VulnRepoVulnerabilitiesPage`, path `/vuln-repo/vulnerabilities`) — filterable vulnerability list

A third view, the **CVE Assessment Workbench**, is reached by clicking into a CVE from other views (path `/vuln-repo/org-cves/:cveId?`). It is rendered by `VulnRepoOrgCvePage`, which opens `VulnRepoCveAssessmentWorkbench` as a drawer. The workbench uses the `/cve-detail/*` workflow APIs for investigations, applicability assessments, manual finding creation, suppression, and export.

Additional drilldown paths under `/vuln-repo`:

- `/vuln-repo/org-cves/:cveId/assets` — `VulnRepoCveAssetsPage`: asset list for a specific CVE
- `/vuln-repo/org-cves/:cveId/software` — `VulnRepoCveSoftwarePage`: software list for a specific CVE
- `/vuln-repo/host-assets/:assetId` — host asset detail reached from the Vuln Repo section
- `/vuln-repo/software-assets` — `VulnRepoSoftwareAssetsPage`: components for a specific software identity (reached via `softwareIdentityId` query param)

Legacy `/vulnerability-intelligence/**` paths are automatically redirected to the corresponding `/vuln-repo/**` paths.

Current workbench behavior:

- analysts no longer use a foreground "Recompute Review Queue" button as the normal workflow
- the page shows queue/projection freshness from `/vuln-repo/org-cves/status`
- it polls every 10 seconds only while queue work is pending and the tab is visible
- when queue work drains or projection freshness advances, it reloads the list and keeps the selected CVE detail in sync
- after manual finding creation, it refreshes both detail and the current list page so row counts stay current while the drawer is still open

### Inventory

The inventory section is organized into two views (flyout groups):

- **Summary** → Software Identities (`SoftwareIdentitiesPage`, view key `software-identities`, path `/inventory/software-identities`)
- **Infrastructure** → Hosts (`InventoryPage`, view key `hosts`, path `/inventory/hosts`)

`SoftwareIdentitiesPage` is the primary inventory summary view. It reads `/inventory/software-identities` (paged, with lifecycle and mapping-state filters) and `/inventory/software-identities/{softwareIdentityId}` for detail. It opens `SoftwareIdentityDetailDrawer` for per-identity EOL status, asset coverage, version breakdown, and EOL slug management. The legacy `imported-assets` query param redirects to `software-identities` for backwards URL compatibility.

The Hosts view sits on top of `/inventory/components` and `/inventory/components/filters` with a host asset-type filter.

`HostAssetDetailPage` is a dedicated drilldown for a single host asset, reached from the Hosts inventory view at `/inventory/hosts/:assetId`. It reads `/api/assets/hosts/{assetId}` for detailed CI metadata, alias list, software instances, and associated findings.

### Connect

`ConnectPage` is a connector catalog with four top-level views accessible from a tab bar:

**Sources** swaps in focused workflow pages per connector:

- `IngestionPage` for SBOM upload, endpoint fetch, and GitHub-generated SBOM ingestion
- `GithubPipelineManager` for reusable GitHub SBOM pipeline configuration and GHCR batch ingestion
- `AssetsPage` for the full ServiceNow CMDB live connector — base URL, auth (Basic/Bearer), table config, field selection, sync scheduling, connection testing, and live sync trigger
- `SourcesPage` for NVD, KEV, GHSA, CSAF/VEX, and advisory ingestion runs

**Inventory Run Queue** is `InventoryRunQueuePage`, a shared table of all host/container/SBOM ingestion run history (ServiceNow CMDB, GitHub SBOM, GitHub GHCR), showing type, status, started time, duration, assets, components, findings, and an expandable details panel per run.

**Vuln Intel Run Queue** surfaces `SourcesPage` in `focusSource="vuln-only"` mode for NVD/KEV/GHSA/CSAF run history.

**Processing Jobs** surfaces `SourcesPage` in `focusSource="processing"` mode for internal maintenance and rebuild jobs such as persisted VEX repair and vendor rollout backfills.

### End-of-Life

`EolPage` is mounted at `/end-of-life`. The `DashboardPage` navigation card links directly to this path.

- Loads summary counts from `/eol/status/summary` once (drives filter-tab badges).
- Loads a paged component list from `/eol/status/components` on filter or page change.
- Filter tabs: All / EOL / Near EOL ≤90d / Supported / Unknown.
- Clicking a row with a resolved slug opens `EolDetailDrawer` with full release-cycle detail from `/eol/products/{slug}/releases`.
- **Unresolved Mappings** panel shows software identities with no EOL slug; analysts can type a slug and confirm it (calls `/eol/mappings/confirm`).
- **Export CSV** button downloads the current filtered page.

Supporting components:

- `EolBadge` — inline status pill (EOL / Near EOL / Supported / Unknown) with optional click handler
- `EolDetailDrawer` — slide-over showing release cycle table for a product slug
- `EolRiskWidget` — summary counts widget used on `DashboardPage`
- `EolSourcePanel` — Connect UI panel wired to the four admin refresh endpoints (`/eol/admin/refresh/*`)
- `src/features/cve-workbench/eol-helpers.ts` — shared `NEAR_EOL_DAYS` constant and EOL helper functions used across workbench and EOL views

### Configurations

`ConfigurationsPage` manages:

- risk score and SLA policy settings via `/risk-policy`
- auto-close and finding generation mode settings
- scheduled GitHub SBOM sources via `/github-sbom-sources`
- prototype data reset via `/configurations/clean-all`
- embedded source/integration queue visibility

## Shared Patterns

- `ResizableTable` is the default dense data-grid primitive
- `FilterBuilder` and `FilterValueSelectCard` drive reusable filter UX
- `StatCard` is used for summary metrics
- `GithubPipelineManager` is a self-contained GitHub source pipeline editor used inside `ConnectPage`
- `VulnRepoCveAssessmentWorkbench` drives the CVE assessment drawer workflow under Vulnerability Repository
- `SoftwareIdentityDetailDrawer` is a slide-over for per-identity detail, EOL status, and slug mapping; used from `SoftwareIdentitiesPage`
- Most long-running actions surface inline status text instead of global toasts

## Current Caveats

- Navigation uses React Router path-based routing. Legacy query-param URLs are redirected by `LegacyQueryRedirect`.
- `CveDetailPage.tsx` exists but is not mounted in `App.tsx`; the live CVE workflow is the Vulnerability Repository CVE Assessment Workbench drawer.
- The frontend assumes the backend's single-default-tenant runtime and supplies tenant/user headers from environment defaults.
- The inventory UI exposes Software Identities and Hosts as the two active views. Container Images and Repositories views exist as `InventoryViewKey` type values but are not currently in the sidebar flyout.
- The frontend package ships `dev`, `build`, `preview`, and `test:unit` scripts. `test:unit` runs Vitest in non-watch mode (`vitest run`). There is no dedicated lint script in `package.json`.
