# VulnWatch Frontend

Last updated: 2026-05-20

## Purpose

The frontend is a React single-page operations console. It drives SBOM ingestion, vulnerability intelligence review, org-level CVE exposure review, findings workflows, connector setup, and configuration management against the backend `/api` surface.

## Stack

- React 18
- TypeScript
- Vite 5
- TanStack Query (`@tanstack/react-query`) for server state — no global client store
- React Router v6 for path-based routing
- Vitest for unit tests (`npm run test:unit`)

Run locally:

```bash
cd frontend
npm install
npm run dev
```

Default URL: `http://localhost:5173`

## API Client

Primary client: `src/api/client.ts` (~600 lines, 70+ exported functions).

Environment variables:

- `VITE_API_BASE` defaults to `http://localhost:8080/api`
- `VITE_API_KEY` defaults to `change-me-in-prod`
- `VITE_CREATOR_KEY` defaults to `local-creator`
- `VITE_TENANT_ID` defaults to `1`
- `VITE_USER_ID` defaults to `local-analyst`
- `VITE_AUTH0_DOMAIN` enables hosted login when set with `VITE_AUTH0_CLIENT_ID`
- `VITE_AUTH0_CLIENT_ID` identifies the Auth0 SPA application
- `VITE_AUTH0_SCOPE` defaults to `openid profile email`
- `VITE_AUTH0_AUDIENCE` should match the Auth0 API identifier so the SPA receives a backend-usable access token

Every JSON request includes:

- `X-API-Key`
- `X-Tenant-ID`
- `X-User-ID`
- `X-Creator-Key` when configured

### Auth0 Hosted Login

Hosted login is already wired in `src/lib/auth0.ts` and `src/pages/DemoPublicPages.tsx`.
The critical frontend requirement is that the SPA must request the backend API audience; otherwise Auth0 can authenticate the browser session but return no usable API access token for Scout.

Recommended local Auth0 frontend env values:

```env
VITE_AUTH0_DOMAIN=dev-ws03t5n4y61lrmi4.us.auth0.com
VITE_AUTH0_CLIENT_ID=tqpCtolsokNVLg5cMr5ObKOoOhLjYxPo
VITE_AUTH0_SCOPE=openid profile email
VITE_AUTH0_AUDIENCE=https://api.hossstore.in
```

For the Auth0 SPA application, keep these local URLs aligned with the app runtime:

- Allowed Callback URLs: `http://localhost:5173/login`
- Allowed Logout URLs: `http://localhost:5173`
- Allowed Web Origins: `http://localhost:5173`

If hosted login succeeds but the UI reports that no API access token is available yet, the usual cause is a missing or mismatched `VITE_AUTH0_AUDIENCE` / Auth0 API identifier pairing.

The frontend also accepts Auth0 namespaced role claims such as `https://hossstore.in/roles` for platform-owner confirmation flows, so Auth0 API tokens and existing locally issued tokens can coexist during rollout.

Functions are grouped by domain in the client (with the matching backend endpoint):

- **Dashboard** — `getDashboard`, `getVulnRepoDashboard`, `listApplicableSoftware`, `listImpactedCves`, `getCveInventoryMap`
- **Findings** — `listFindings`, `listFindingFilters`, `bulkUpdateFindingWorkflow`
- **Operations** — `getOperationalDashboard`, `getOperationalIngestionEfficiency`, `getOperationalNormalizationQuality`, `getOperationalCorrelationEffectiveness`, `getOperationalNoiseLifecycle`, `getOperationalApiReadPath`, `getOperationalFreshnessDrift`, `getOperationalMetricCatalog`, `getOperationalQualitySummary`/`Issues`/`Filters`, `getNormalizationImpact`, `applyNormalizationOverride`/`revokeNormalizationOverride`, `applyCorrelationOverride`/`revokeCorrelationOverride`, `searchSoftwareIdentities`, `getSloStatus`
- **Inventory & Assets** — `listAssets`, `getHostAssetDetail`, `listInventoryComponents`, `listInventoryComponentFilters`, `listSoftwareIdentities`, `getSoftwareIdentityDetail`, `getVulnRepoSoftwareAssets`
- **Vulnerability intelligence** — `listVulnerabilityIntelligence`, `listVulnerabilityIntelligenceSources`, `listVulnerabilityIntelligenceFilters`, `getVulnerabilityIntelligenceDetail`
- **Connectors** — ServiceNow, SCCM, AWS Discovery (config + targets), GitHub SBOM (sources + GHCR/repository runs), vulnerability-source filters
- **Risk policy** — `getRiskPolicy`, `updateRiskPolicy`, `cleanAllPrototypeData`
- **Ingestion / sync** — `syncNvd`, `syncNvdFull`, `syncKev`, `syncGhsa`, `syncMicrosoftCsaf`, `syncRedhatCsaf`, `triggerVexAssertionRepair`, `triggerVexRolloutBackfill`, `getVexAssertionRepairSummary`, `ingestAdvisories`, `getUpgradeRecommendation`, `seedDemo`, `listSyncRuns`, `listIngestions`, `fetchSbomFromEndpoint`
- **EOL** — summary, component statuses, product catalog, release cycles, mapping confirmation, mapping suggestions, package statuses/assets, plus four admin refresh triggers and `triggerEolFullRefresh`

The client also parses JSON error envelopes into readable messages and handles multipart SBOM uploads.

## Navigation Model

`src/App.tsx` mounts React Router v6. All path-builders and route normalization helpers live in `src/app/routes.ts`. Legacy query-param URLs (`?tab=inventory`, `?vulnIntelView=org-cves`, etc.) are redirected to canonical paths via `buildLegacyCompatiblePath()` on first render.

### Top-level routes

| Path | Component | Purpose |
|------|-----------|---------|
| `/` | → `/exposure` redirect | Root redirects to the exposure dashboard |
| `/exposure` | `ExposureDashboardPage` | Risk-focused overview |
| `/findings` | `FindingsPage` | Active findings list with filters |
| `/findings/:displayId` | `FindingDetailPage` | Single finding workflow + comments |
| `/operations/:operationsView?` | `OperationalDashboardPage` | Default `pipeline`; sub-views `quality`, `pipeline`, `platform-health` |
| `/vuln-repo` | `VulnRepoDashboardPage` | Vulnerability repository dashboard |
| `/vuln-repo/org-cves/:cveId?` | `VulnRepoOrgCvePage` | **Unified Records** — org-correlated CVEs (CVE Assessment Workbench) |
| `/vuln-repo/vulnerabilities` | `VulnRepoVulnerabilitiesPage` | **Intelligence** — all ingested CVEs (global feed) |
| `/vuln-repo/org-cves/:cveId/assets` | `VulnRepoCveAssetsPage` | Per-CVE affected asset breakdown |
| `/vuln-repo/org-cves/:cveId/software` | `VulnRepoCveSoftwarePage` | Per-CVE affected software breakdown |
| `/vuln-repo/host-assets/:assetId` | `HostAssetDetailPage` | Asset detail reached from vuln-repo context |
| `/vuln-repo/software-assets` | `VulnRepoSoftwareAssetsPage` | Software-identity-scoped asset list |
| `/inventory/:inventoryView?` | varies (see below) | Default `overview`; many sub-views |
| `/inventory/hosts/:assetId` | `HostAssetDetailPage` | Host detail from inventory context |
| `/end-of-life` | `EolPage` | EOL status, lifecycle filters, slug mappings |
| `/connect/:connectView?` | `ConnectPage` | Default `sources`; also `integration-run-queue`, `processing-jobs` |
| `/admin/:adminView?` | `UserManagementPage` | Tenant + service-account administration |
| `/platform/:platformView?` | `PlatformConsolePage` | Platform-owner console; sub-views `tenants`, `demo-requests`, `support` |
| `/configurations` | `ConfigurationsPage` | Risk policy, SLA, scoring, automation, ownership, suppression |

### Inventory sub-views

Driven by the `inventoryView` path segment. Recognised keys: `overview`, `software-identities`, `manage-software`, `hosts`, `container-images`, `secured-image-catalog`, `container-registries`, `sbom`, `hosted-technologies`, `code-repositories`, `source-mappings`, `developers`, `kubernetes-clusters`, `datastores`, `subscriptions`, `iam`, `api-endpoints`, `application-endpoints`, `vulnerability-intelligence`. Several of these are aliases that map to the same component with different default filters; the canonical four data-bearing views are `software-identities`, `hosts`, `container-images`, and `sbom`.

The topbar includes a **⌘K / Ctrl+K** keyboard shortcut that focuses the jump-to-page search input. The theme toggle is an icon-only button (sun/moon SVG) rather than a text label.

## Main Experiences

### Overview

- `ExposureDashboardPage` (at `/exposure`; `/` redirects here)
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
- Platform Health reads operational metrics and `/operations/normalization-quality`
- the Platform Health summary now includes noise-projection readiness, age, refresh failures, and projection refresh p95
- the Pipeline view label `Queued/Running Sync Jobs` now refers to sync backlog, not durable delta-queue depth
- Sub-view is tracked in the `operationsView` query param

### Vulnerability Intelligence

There are three distinct views under the Vulnerability Intelligence flyout:

- Dashboard: `VulnerabilityIntelDashboardPage`
- Vulnerability list/detail: `InventoryPage` in `vulnerability-intelligence` mode using `/vulnerability-intelligence`, `/vulnerability-intelligence/filters`, and `/vulnerability-intelligence/{externalId}`
- CVE Assessment Workbench: `VulnerabilityIntelOrgCvePage` using `/vulnerability-intelligence/org-cves` and `/vulnerability-intelligence/org-cves/status` (flyout label: "CVE Assessment Workbench", view key: `org-cves`)

CVE Assessment Workbench is the primary place where the current UI exposes CVE drill-down. It opens `CveAssessmentWorkbench`, which uses the `/cve-detail/*` workflow APIs for investigations, applicability assessments, manual finding creation, suppression, and export.

Current workbench behavior:

- analysts no longer use a foreground "Recompute Review Queue" button as the normal workflow
- the page shows queue/projection freshness from `/vulnerability-intelligence/org-cves/status`
- it polls every 10 seconds only while queue work is pending and the tab is visible
- when queue work drains or projection freshness advances, it reloads the list and keeps the selected CVE detail in sync
- after manual finding creation, it refreshes both detail and the current list page so row counts stay current while the drawer is still open

### Inventory

The inventory flyout is organized into groups, each with one view:

- **Summary** → Software Identities (`SoftwareIdentitiesPage`, view key `software-identities`)
- **Infrastructure** → Hosts (`InventoryPage`, view key `hosts`)
- **Cloud** → Container Images (`InventoryPage`, view key `container-images`)
- **Repositories** → Repositories (`InventoryPage`, view key `sbom`)

`SoftwareIdentitiesPage` is the primary inventory summary view. It reads `/inventory/software-identities` (paged, with lifecycle and mapping-state filters) and `/inventory/software-identities/{softwareIdentityId}` for detail. It opens `SoftwareIdentityDetailDrawer` for per-identity EOL status, asset coverage, version breakdown, and EOL slug management. The legacy `imported-assets` query param redirects to `software-identities` for backwards URL compatibility.

The Hosts, Container Images, and Repositories views continue to sit on top of `/inventory/components` and `/inventory/components/filters` with default asset-type filters changing by view.

`HostAssetDetailPage` is a dedicated drilldown for a single host asset, reached from the Hosts inventory view. It reads `/api/assets/hosts/{assetId}` for detailed CI metadata, alias list, software instances, and associated findings.

### Connect

`ConnectPage` is a connector catalog with three top-level views (path: `/connect/:connectView?`): `sources` (default), `integration-run-queue`, and `processing-jobs`.

Connector categories rendered in the catalog:

- **Vulnerability Intelligence** — `nvd-api`, `cisa-kev`, `ghsa-feed`, `microsoft-csaf-vex`, `redhat-csaf-vex`, `advisory-feed`, `endoflife-date`
- **CMDB / Inventory Sources** — `sbom-endpoint`, `sbom-github`, `servicenow-cmdb`, `sccm-cmdb`
- **Cloud Discovery** — `aws-discovery`

Per-connector pages in `src/pages/`:

- `IngestionPage` — SBOM upload, endpoint fetch, and GitHub-generated SBOM ingestion
- `GithubPipelineManager` (component) — GitHub SBOM pipeline configuration and GHCR batch ingestion
- `AssetsPage` — ServiceNow CMDB connector (base URL, auth, table config, field selection, scheduling, test, live sync)
- `SccmConnectorPage` — SCCM/MECM CMDB connector
- `AwsDiscoveryConnectorPage` — AWS EC2 discovery via SSM, multi-account through `aws_discovery_targets`
- `NvdConnectorPage`, `KevConnectorPage`, `GhsaConnectorPage`, `MicrosoftCsafConnectorPage`, `RedhatCsafConnectorPage`, `AdvisoryConnectorPage`, `VulnIntelConnectorPage`, `VulnIntelConfigPage` — per-feed configuration
- `SourcesPage` — embedded vuln-intel run history view

`InventoryRunQueuePage` is the `integration-run-queue` view: a shared table of all host/container/SBOM ingestion run history (ServiceNow CMDB, SCCM, AWS Discovery, GitHub SBOM, GitHub GHCR) with expandable per-run details. `IntegrationRunQueuePage` covers both inventory and vuln-intel queues.

### End-of-Life

`EolPage` is mounted at `activeTab === 'end-of-life'`. The `DashboardPage` navigation card links directly to this tab via the `onViewEol` prop.

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

`ConfigurationsPage` manages risk policy, SLA, ownership, suppression, vulnerability source filters, and scoring settings via a sidebar-nav layout. The 8 sections in order are:

| # | Key | Label |
|---|-----|-------|
| 1 | `sla` | SLA & Remediation |
| 2 | `triage` | S.AI Prioritization |
| 3 | `automation` | Workflow Automation |
| 4 | `ownership` | Ownership (rule-based user/group assignment, `ownership_rules` table) |
| 5 | `vulnerability-sources` | Vulnerability Sources (per-tenant feed filter rules) |
| 6 | `findings-score` | Findings Score |
| 7 | `suppress` | Suppression Rules |
| 8 | `auto-findings` | Auto-Finding Rules |

## Shared Patterns

- `ResizableTable` is the default dense data-grid primitive
- `FilterBuilder` and `FilterValueSelectCard` drive reusable filter UX
- `StatCard` is used for summary metrics
- `GithubPipelineManager` is a self-contained GitHub source pipeline editor used inside `ConnectPage`
- `CveAssessmentWorkbench` drives the CVE assessment drawer workflow under Vuln Intel
- `SoftwareIdentityDetailDrawer` is a slide-over for per-identity detail, EOL status, and slug mapping; used from `SoftwareIdentitiesPage`
- Most long-running actions surface inline status text instead of global toasts

## Feature Directories

Types and queries are colocated per feature under `src/features/`:

| Feature | Notable contents |
|---------|------------------|
| `admin/` | Platform console and tenant administration components |
| `auth/` | `AuthProvider`, identity context, `queries.tsx`, `types.ts` |
| `cve-workbench/` | `CveAssessmentWorkbench` and panels (Investigation, Applicability, Findings, Sidebar), assessment/eol/formatting helpers, hooks |
| `configurations/` | `RiskPolicy` types (includes the 6 triage weight fields), `OwnershipRuleResponse`, `OwnershipRuleRequest`, `SuppressionRule` |
| `connect/` | Per-connector queries (ServiceNow, SCCM, AWS, GitHub, vuln sources), shared types |
| `dashboard/` | Dashboard, ApplicableSoftware, ImpactedCves types + queries |
| `eol/` | EolSummary, EolComponentPage, EolRelease, EolProductCatalog types + queries |
| `findings/` | `Finding`, `FindingPage`, `FindingFilterValues` types + queries |
| `inventory/` | View-key types, filter values, inventory hooks (`useInventoryData`), table panels, modals |
| `operations/` | OperationalDashboard, OperationalQuality, SloStatus types + queries |
| `software-identities/` | SoftwareIdentityPage, SoftwareIdentityDetail types + queries |
| `vulnerability-intel/` | Vulnerability list/detail types |
| `vuln-repo-dashboard/` | VulnRepoDashboard types + queries |
| `widgets/` | Shared UI widget components |

`src/types/index.ts` re-exports for convenience but the source of truth is each feature directory. `src/types/ownership.ts` holds the cross-feature `OwnershipSummary`.

## Current Caveats

- `CveDetailPage.tsx` exists but is not mounted in the router; the live CVE workflow is the CVE Assessment Workbench at `/vuln-repo/org-cves/:cveId?`.
- The frontend assumes the backend's single-default-tenant runtime and supplies tenant/user headers from environment defaults.
- The inventory UI exposes more conceptual categories than the backend currently models explicitly; several filter-based views share the same `/inventory/components` endpoint.
- The frontend package ships `dev`, `build`, `preview`, `lint`, `typecheck`, `test:unit`, and `test:coverage` scripts. `lint` runs `eslint .`. `test:unit` runs Vitest in non-watch mode (`vitest run`).
