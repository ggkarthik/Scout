# Frontend Reference

This document describes the React/TypeScript frontend for VulnWatch (package name `vulnwatch-frontend`). It is derived entirely from reading the source code in `frontend/src/`.

---

## 1. Tech Stack

| Concern | Library / Version |
|---|---|
| UI framework | React 18.3.1 |
| Language | TypeScript 5.5.4 |
| Build tool | Vite 5.4.2 |
| Routing | React Router DOM 7.13.2 |
| Server state | @tanstack/react-query 5.95.2 |
| Table | @tanstack/react-table 8.21.3 |
| Error monitoring | @sentry/react 10.51.0 |
| Report export | docx 9.6.1 |
| HTTP | Native `fetch` (no axios) |
| Test runner | Vitest 4.0.18 |
| Test utilities | @testing-library/react 16.3.2, @testing-library/jest-dom 6.9.1 |
| Coverage | @vitest/coverage-v8 4.1.5 |
| Lint | ESLint 9.39.4 + typescript-eslint 8.57.2 + eslint-plugin-react-hooks 7.0.1 |
| DOM environment | jsdom 29.0.1 |

The app is a pure SPA. There is no SSR. All pages are lazy-loaded via `React.lazy`. The dev server runs strictly on port 5173 (`--strictPort`). Vite proxies `/api/**` to `http://localhost:8080` in dev so the frontend calls the backend without a separate CORS config.

**CI gate order:** `lint` → `typecheck` → `build` → `test:coverage`. All four must pass.

---

## 2. Application Structure

```
frontend/src/
  main.tsx                  Entry point — Sentry init, QueryClientProvider, BrowserRouter, StrictMode
  App.tsx                   Root component — lazy routes, AppShell, AuthSessionBoundary, theme, impersonation
  api/
    client.ts               Single api object; all 60+ backend calls; auth header injection
  app/
    routes.ts               Typed path-builder helpers and legacy query-param redirect logic
  features/                 Feature-colocated modules; types live here, not in src/types/
    auth/                   ActorContext type, context, role helpers, queries
    findings/               Finding type, queries, filters
    cve-workbench/          OrgSpecificCveExposureRecord, CveDetail, assessment helpers, scoring
    configurations/         RiskPolicy, OwnershipRule, SuppressionRule
    inventory/              Asset, HostAssetDetail, InventoryComponentPage, searchState, helpers
    connect/                Connector configs, SyncRun types, queries
    operations/             OperationalDashboard, SLO, quality types and queries
    dashboard/              Dashboard type and queries
    vuln-repo-dashboard/    VulnRepoDashboard type and queries
    software-identities/    SoftwareIdentitySummary, detail, funnel queries
    eol/                    EolSummary, PackageEolStatus, catalog queries
    admin/                  Tenant, PlatformUser, ServiceAccount, AuditEvent, admin queries
    widgets/                DonutChart, HBarChart, WidgetCard SVG components
  lib/
    riskScoring.ts          Pure TS: computeCveRiskScore, computeFindingPriorityScore
    queryClient.ts          createQueryClient factory (retry:1, staleTime:10s, no refetchOnWindowFocus)
    polling.ts              Refresh interval constants
    time.ts                 timeAgo, formatTimestamp helpers
  pages/                    One file per route; lazy-loaded in App.tsx
  components/               Shared presentational components (max ~300 lines each)
  hooks/
    useDebouncedValue.ts    Debounce hook with immediate-clear for empty strings
  types/
    index.ts                Re-exports only — source of truth is always the feature directory
    ownership.ts            OwnershipSummary type
  styles/
    index.css               Imports all CSS files
    base.css                CSS custom properties + font imports
    shared.css              Global layout classes, buttons, pills, badges
    cve-workbench.css       CVE workbench-specific styles
    connect.css             Connector page styles + SBOM wizard
    eol.css                 EOL page styles
    vuln-repo.css           Vuln repo page styles
    user-management.css     User management page styles
    exposure-dashboard.css  Exposure dashboard exec-* classes
  test/
    setup.ts                @testing-library/jest-dom/vitest import
    test-utils.tsx          renderWithProviders — QueryClientProvider + MemoryRouter
    fixtures.ts             buildFinding, defaultRiskPolicy, defaultFindingFilterValues, pageOf
```

### Route Table

All routes are registered in `src/App.tsx` using React Router v7 nested routes. Pages are loaded with `React.lazy`. The `AuthSessionBoundary` component wraps every authenticated route and redirects to `/login` when `useActorQuery()` returns no data.

| Path | Page Component | Purpose |
|---|---|---|
| `/` | Redirect | Redirects to `/exposure` |
| `/exposure` | `ExposureDashboardPage` | Risk-focused exec overview (Overview tab) |
| `/findings` | `FindingsPage` | Active findings list with server+client-side filters |
| `/findings/:displayId` | `FindingDetailPage` | Single finding detail, workflow, and AI remediation |
| `/operations/:operationsView?` | `OperationalDashboardPage` | Pipeline, Platform Health sub-views (default: `pipeline`) |
| `/vuln-repo` | `VulnRepoDashboardPage` | Vulnerability Repository dashboard |
| `/vuln-repo/org-cves/:cveId?` | `VulnRepoOrgCvePage` | Unified Vulnerability Records — CVE Assessment Workbench |
| `/vuln-repo/vulnerabilities` | `VulnRepoVulnerabilitiesPage` | Vulnerability Intelligence — global CVE feed |
| `/vuln-repo/org-cves/:cveId/assets` | `VulnRepoCveAssetsPage` | Per-CVE affected asset breakdown |
| `/vuln-repo/org-cves/:cveId/software` | `VulnRepoCveSoftwarePage` | Per-CVE affected software breakdown |
| `/inventory/:inventoryView?` | `InventoryPage` (dispatches sub-views) | Default `overview`; also `hosts`, `software-identities`, `container-images`, `sbom` |
| `/end-of-life` | `EolPage` | EOL status — At Risk tab and Catalog tab |
| `/connect/:connectView?` | `ConnectPage` | Default `sources`; also `connectors`, `run-history`, `processing-jobs` |
| `/admin/:adminView?` | `UserManagementPage` | Users, Invites, Support Access, Roles, Service Accounts, Audit |
| `/platform/:platformView?` | `PlatformConsolePage` | Platform owner console — Tenants, Users, Demo Requests, Support |
| `/configurations` | `ConfigurationsPage` | SLA, Triage, Automation, Ownership, Vuln Sources, Findings Score, Suppression, Auto-Finding |
| `/demo` | `DemoPublicPages` | Public demo landing |
| `/demo/request` | `DemoPublicPages` | Demo request form |
| `/demo/request/success` | `DemoPublicPages` | Demo request success |
| `/demo/expired` | `DemoPublicPages` | Demo expiry notice |
| `/invite/:token` | (public) | Invite accept flow |
| `/login` | `LoginPage` | Login |

**Legacy redirect:** `LegacyQueryRedirect` in `App.tsx` intercepts old `?tab=inventory&inventoryView=hosts` style URLs and converts them to the equivalent path-based URL via `buildLegacyCompatiblePath()` in `src/app/routes.ts`.

---

## 3. Authentication and Auth Flow

### Token storage

- Primary: `localStorage` key `vulnwatch.authToken` — a JWT Bearer token.
- Fallback (local dev only): `VITE_AUTH_TOKEN` env var.
- Managed by `getStoredAuthToken()`, `setStoredAuthToken()`, `clearStoredAuthToken()` exported from `src/api/client.ts`.

### Request auth header injection

`applyAuthHeaders()` in `src/api/client.ts` runs on every authenticated request:

1. If `getStoredAuthToken()` returns a token, sends `Authorization: Bearer <token>`.
2. Otherwise (local dev), falls back to `X-API-Key: <VITE_API_KEY>` + `X-Creator-Key: <VITE_CREATOR_KEY>`.

### Session lifecycle

1. `useActorQuery()` in `src/features/auth/queries.tsx` calls `GET /api/auth/context`. The React Query key includes the raw token value so the cache auto-invalidates when the token changes (login / logout).
   - `staleTime`: 5 minutes.
   - `AUTH_CONTEXT_QUERY_ROOT = ['auth-context']`.
2. `AuthSessionBoundary` in `App.tsx` wraps all authenticated routes. It renders a redirect to `/login` when the query fails or returns no actor data.
3. The loaded `ActorContext` is published into React context via `ActorContextState = React.createContext<ActorContext | null>(null)`. Read it with `useActor()` from `src/features/auth/context.ts`.

### ActorContext type (source: `src/features/auth/types.ts`)

Key fields:
- `creator`, `principal`, `userId`, `tenantId`, `tenantName`
- `roles: string[]`, `allowedTenants: AllowedTenant[]`
- `platformScope?: boolean` — user is a platform owner who has not yet entered a tenant; in this state, tenant-scoped routes redirect to `/platform/tenants`
- `actingAsPlatformOwner?: boolean` — set after `selectTenantContext` when acting on behalf of a tenant
- `sensitiveActionConfirmationRequired?: boolean`
- `planCode?`, `demoExpiresAt?`, `demoDaysRemaining?`

### Role helpers (source: `src/features/auth/roles.ts`)

All role checks must go through these helpers — never read `actor.roles` directly. They normalize `ROLE_` prefixes and handle `platformScope` edge cases.

| Function | Purpose |
|---|---|
| `hasRole(actor, role)` | Check for a single role |
| `hasAnyRole(actor, ...roles)` | Check for any of the listed roles |
| `canManageTenant(actor)` | ROLE_TENANT_ADMIN or higher |
| `canAccessPlatformConsole(actor)` | ROLE_PLATFORM_OWNER |
| `canManageInventorySources(actor)` | ROLE_INVENTORY_ADMIN or higher |
| `canManageRiskPolicy(actor)` | ROLE_TENANT_ADMIN or higher |
| `canRunSecurityWorkflow(actor)` | ROLE_SECURITY_ANALYST or higher |
| `canViewReadOnly(actor)` | Any authenticated role |
| `canRefreshTenantExposure(actor)` | ROLE_SECURITY_ANALYST or higher |
| `canManageUsers(actor)` | ROLE_TENANT_ADMIN or higher |
| `canManageServiceAccounts(actor)` | ROLE_TENANT_ADMIN or higher |
| `canExportAudit(actor)` | ROLE_SECURITY_ANALYST or higher |
| `isPlatformScopeOnly(actor)` | True when `platformScope=true` and not `actingAsPlatformOwner` |

### Multi-tenant switching

- `api.selectTenantContext(tenantId)` — sets acting tenant; returns a new `ActorContext`.
- `api.clearTenantContext()` — returns platform-scope mode.
- Both are used in `PlatformConsolePage` and the `AppShell` tenant switcher.
- `setStoredAuthToken()` is also called on login to store the returned token.

---

## 4. Feature Modules

Each module under `src/features/<feature>/` owns its TypeScript types, queries, and optionally API calls and helpers.

### auth (`src/features/auth/`)

Files: `types.ts`, `context.ts`, `roles.ts`, `queries.tsx`

`ActorContext` and `AllowedTenant` types; `ActorContextState` React context; `useActor()` hook; `useActorQuery()` React Query hook; all role-check functions.

### findings (`src/features/findings/`)

Files: `types.ts`, `queries.ts`

**Finding type** (50+ fields): `id`, `displayId`, `componentId`, `assetName`, `vulnerabilityId`, `severity` (CRITICAL/HIGH/MEDIUM/LOW), `status` (OPEN/RESOLVED/SUPPRESSED/AUTO_CLOSED), `decisionState`, `inKev`, `epss`, `riskScore`, `vexStatus`, `isEol`, `incidentId`, `findingsScore`, `ownership: OwnershipSummary`, and many more.

Supporting types: `FindingPage`, `FindingFilterValues`, `FindingBulkWorkflowRequest`, `FindingBulkWorkflowResponse`, `FindingTimeline`, `VulnerabilityDetail`.

Queries:
- `useFindingsQuery(params)` — queryKey `['findings', params]`, uses `keepPreviousData`
- `useFindingFiltersQuery()` — queryKey `['finding-filters']`

### cve-workbench (`src/features/cve-workbench/`)

Files: `types.ts`, `api.ts`, `queries.ts`, `assessment-helpers.ts`, `formatting.ts`, `asset-report.ts`, `workflow.ts`, `view-helpers.ts`, `view-models.ts`, `investigation-context.ts`, `eol-helpers.ts`

**Core types:**
- `OrgSpecificCveExposureRecord` — org-correlated CVE with `recordId`, `vulnerabilityId`, `severity`, `cvssScore`, `epssScore`, `inKev`, `matchedAssetCount`, `matchedSoftwareCount`, `eolComponentCount`, `openFindings`, `applicability`, VEX component counts
- `CveDetail` — full CVE detail with `summary`, `signals`, `investigations`, `assessments`, `matchedSoftware`, `vendorIntelligence`, `sourceRecords`, `fixes`
- Payload/response types for all CVE workflow operations

**`cveWorkbenchApi` object** (separate from the main `api`): `listVulnRepoVulnerabilities`, `listOrgSpecificCves`, `getCveDetail`, `createManualFindings`, `createServiceNowIncident`, `getSavedInvestigationSummary`, `getSavedAiSolution`, `generateAiSolution`, `generateAiRequiredActions`, `getFixRecords`, `generateFixRecords`, `saveAnalystFixes`

**Queries:** `useVulnRepoVulnerabilitiesQuery()`, `useOrgSpecificCvesQuery()`, `useOrgSpecificCveAutomationStatusQuery()` (polls at `ORG_CVE_STATUS_REFRESH_INTERVAL_MS = 10s` when `pendingEventCount > 0`), `useCveDetailQuery()`, `useSavedInvestigationSummaryQuery()`, `useSavedAiSolutionQuery()`, `useRiskPolicyQuery()`

**Assessment helpers** (`assessment-helpers.ts`): `parseCvssVector`, `confidenceFromApplicability`, `matchBasisLabel`, `buildSoftwareGroups`, `applicableSoftwareRows`, `buildFindingDisplayRows`, `computedImpactStateOf`, `deriveAssessmentResult`, `exactMatchMeta`, `explainApplicability`, `initialApplicabilityDecision`, `priorityFromSeverityAndImpact`, `vendorStatementFor`

Types: `ApplicabilityDecision` (`APPLICABLE | NOT_APPLICABLE | NEEDS_REVIEW`), `ImpactDecision` (`IMPACTED | NOT_IMPACTED | UNKNOWN`), `SoftwareGroup`, `FindingDisplayRow`

**Formatting helpers** (`formatting.ts`): `formatDateTime`, `formatDate`, `formatLabel`, `severityClassName`, `statusClassName`, `softwareLabel`

### configurations (`src/features/configurations/`)

Files: `types.ts`

**RiskPolicy** (key fields):
- Score thresholds: `criticalThreshold`, `highThreshold`
- SLA deadlines: `criticalSlaDays`, `highSlaDays`, `mediumSlaDays`, `lowSlaDays`
- Asset SLA multipliers (criticality-based)
- Automation: `autoCloseEnabled`, `autoCloseAfterDays`, `findingGenerationMode`
- Custom scoring: `findingsScoreConfig` (JSONB)
- **6 triage weight fields:** `triageExploitabilityWeight`, `triageBlastRadiusWeight`, `triageEolRiskWeight`, `triageSlaBreachWeight`, `triageMissingOwnerBoost`, `triagePatchGapBoost`

Other types: `SuppressionRule`, `SuppressionRuleRequest` (fields: `name`, `state` DRAFT/APPROVED/IN_REVIEW/REJECTED/EXPIRED, `recordType` CVE/FINDING, `validFrom`, `validTo`, `executionOrder`, `reason`), `OwnershipRuleResponse`, `OwnershipRuleRequest`

### inventory (`src/features/inventory/`)

Files: `types.ts`, `api-types.ts`, `queries.ts`, `helpers.ts`, `searchState.ts`, `useInventoryData.ts`, `InventoryShell.tsx`

**InventoryViewKey:** `'overview' | 'software-identities' | 'hosts' | 'container-images' | 'sbom'`

**API types:** `Asset`, `HostAssetSummary`, `HostAliasRecord`, `HostSoftwareInstanceRecord`, `HostFindingRecord`, `HostApplicableCveRecord`, `HostAssetDetail`, `InventoryComponentRecord`, `InventoryComponentPage`, `InventoryComponentFilterValues`

**Queries:** `useInventoryComponentsQuery(params)`, `useInventoryComponentFiltersQuery()`, `useHostAssetDetailQuery(assetId, sourceSystem?)`

**Search state** (`searchState.ts`): URL search parameter helpers for inventory views. Keys: `INVENTORY_QUERY_QUERY_KEY`, `INVENTORY_SOURCE_SYSTEM_QUERY_KEY`, `INVENTORY_GROUP_BY_QUERY_KEY`, `HOST_QUICK_FILTER_QUERY_KEY`, `HOST_ENVIRONMENT_QUERY_KEY`, `HOST_OPERATING_SYSTEM_QUERY_KEY`, `HOST_ASSET_QUERY_KEY`, `HOST_REVIEW_CATEGORY_QUERY_KEY`. Helpers: `readInventoryQueryFromSearch`, `writeInventoryQueryToSearch`, `readInventoryGroupByFromSearch`, `writeInventoryGroupByToSearch`, `readSearchValueFromSearch`, `writeSearchValueToSearch`, `readSearchValuesFromSearch`, `writeSearchValuesToSearch`, `readHostReviewCategoriesFromSearch`, `writeHostReviewCategoriesToSearch`, `clearHostInventorySearchState`

**Helpers** (`helpers.ts`): `defaultAssetTypeForView`, `formatAssetType`, `formatInventorySourceSystem` (maps `upload`->`Legacy Upload`, `api`->`API Endpoint`, `github`->`GitHub Generated`, `servicenow`->`ServiceNow`), `formatInventoryLabel`, `formatHostReviewLabel`, `buildHostReviewLabels`, `normalizeHostReviewCategory`

**`useInventoryData(args)`** (`useInventoryData.ts`): wraps `useInventoryComponentsQuery` and `useInventoryComponentFiltersQuery`, normalizes filter option values, exposes `refreshInventory()`.

**Host group-by options in InventoryPage:** `operatingSystem`, `environment`, `status`, `owner`, `sourceSystem`

**Host quick filters:** `all | online | with-findings | with-cves | with-eol | external-with-cves | linux | windows`

### connect (`src/features/connect/`)

Files: `types.ts`, `queries.ts`

**Types:** `SyncRun`, `IngestionResult`, `SyncTriggerResponse`, `ServiceNowCmdbConfig/Request`, `SccmCmdbConfig/Request`, `AwsDiscoveryConfig/Request`, `AwsDiscoveryTarget/Request`, `GithubSbomSource`, `VulnerabilitySourceFilterConfig/Request`

**Queries:** `useSyncRunsQuery(params)` — auto-polls at `RUN_QUEUE_REFRESH_INTERVAL_MS = 3s` while any run has status RUNNING/STARTED/QUEUED; `useVexAssertionRepairSummaryQuery()`, `useSourceFilterConfigQuery(sourceSystem)`, `useGithubSbomSourcesQuery()`, `useServiceNowCmdbConfigQuery()`, `useSccmCmdbConfigQuery()`, `useAwsDiscoveryConfigQuery()`, `useAwsDiscoveryTargetsQuery()`

### operations (`src/features/operations/`)

Files: `types.ts`, `queries.ts`

**Types:** `OperationalDashboard` with sections `executiveHealth`, `ingestionEfficiency`, `normalizationQuality`, `correlationEffectiveness`, `noiseLifecycle`, `apiReadPath`, `freshnessDrift`, `metricCatalog`; `OperationalQualityIssue`, `OperationalQualityIssueDetail`, `SloStatus`, `SloEntry`

**Queries:**
- `useOperationsViewQuery(selectedView)` — loads Pipeline or Platform Health data in parallel via `Promise.all`; `refetchInterval = OPERATIONS_REFRESH_INTERVAL_MS = 15s`
- `useOperationalQualitySummaryQuery()`, `useOperationalQualityIssuesQuery()`, `useOperationalQualityIssueDetailQuery()`
- Mutations: `useApplyNormalizationOverrideMutation`, `useRevokeNormalizationOverrideMutation`, `useApplyCorrelationOverrideMutation`, `useRevokeCorrelationOverrideMutation`

### dashboard (`src/features/dashboard/`)

Files: `types.ts`, `queries.ts`

**Dashboard type:** `assets`, `components`, `openFindings`, severity counts, `topVulnerabilities`, `latestFindings`, `noiseReduction`, `csafVexAnalytics`, `correlationEfficiency`, `topAssetsAtRisk`, `openCritical/High/Medium/Low`, `averageOpenRiskScore`, `criticalFindings`

**Queries:** `useDashboardSummaryQuery()` — queryKey `['dashboard-summary']`, polls at `DASHBOARD_REFRESH_INTERVAL_MS = 15s`; `useDashboardCveInventoryMapQuery(limit)`

### vuln-repo-dashboard (`src/features/vuln-repo-dashboard/`)

Files: `types.ts`, `queries.ts`

**VulnRepoDashboard type:** `generatedAt`, `summaryCards: VulnRepoDashboardSummaryCards` (trackedCount, exploitCount, impactedKevCount, criticalUninvestigatedCount, kevReinvestigationCount, weekly deltas, etc.), `severityBreakdown`, `resolutionStatus`, `criticalUnresolved`, `topAffectedSoftware`, `recentAdvisories`, `impactedAssets`

**Query:** `useVulnRepoDashboardQuery(platformScope?)` — queryKey `['vuln-repo-dashboard', 'tenant' | 'platform']`

### software-identities (`src/features/software-identities/`)

Files: `types.ts`, `queries.ts`

**Types:** `SoftwareIdentitySummary`, `SoftwareIdentityDetail`, `SoftwareIdentityVersion`, `SoftwareIdentityAsset`, `SoftwareIdentityMetadata`, `SoftwareIdentityFunnel`, `VulnRepoSoftwareAssetsDetail`

**Queries:** `useSoftwareIdentitiesQuery(params)`, `useSoftwareIdentityFunnelQuery()`, `useSoftwareIdentityDetailQuery(softwareIdentityId)`, `useSoftwareIdentityMetadataQuery(softwareIdentityId)`, `useVulnRepoSoftwareAssetsQuery(softwareIdentityId)`

### eol (`src/features/eol/`)

Files: `types.ts`, `queries.ts`

**Types:** `EolSummary` (eolCount, nearEolCount), `ComponentEolStatus`, `EolProductCatalog`, `EolRelease`, `EolComponentPage`, `UnresolvedEolMapping`, `EolSlugSuggestion`, `PackageEolStatus`

**Queries:** `useEolSummaryQuery()`, `useEolComponentStatusesQuery(params)`, `useEolProductsQuery()`, `useEolReleasesQuery(slug)`, `useEolUnresolvedMappingsQuery(params)`, `useEolSlugSuggestionsQuery(normalizedKey)` (staleTime 5 min), `useEolPackageStatusesQuery(params)`, `useEolPackageAssetsQuery(params)`

### admin (`src/features/admin/`)

Files: `types.ts`, `queries.ts`

**Types:** `Tenant`, `TenantMember`, `PlatformUser`, `ServiceAccount`, `AuditEvent`, `AuthContext`, `DemoRequest`, `DemoInvite`, `AuthTokenResponse`, `TenantSupportGrant`, `InventoryConnectorHealth`

**Queries and mutations:** `useAuthContextQuery()`, `useTenantMembersQuery()`, `useAddTenantMemberMutation()`, `useTenantSupportGrantsQuery()`, `useCreateTenantSupportGrantMutation()`, `useRevokeTenantSupportGrantMutation()`, `useServiceAccountsQuery()`, `useCreateServiceAccountMutation()`, `useAuditEventsQuery()`, `usePlatformSupportGrantsQuery()`, `useAcceptPlatformSupportGrantMutation()`, `usePlatformInventoryConnectorHealthQuery()`

### widgets (`src/features/widgets/`)

Files: `FplWidgets.tsx`

`DonutChart` — SVG donut with hover effect and center total label.
`HBarChart` — horizontal bar chart with active row highlight.
`WidgetCard` — wrapper with title and active highlight state.

---

## 5. Shared Components

All files in `src/components/`. Each must stay under ~300 lines. Larger components belong in `src/features/<feature>/`.

### DataTable (`src/components/DataTable.tsx`)

Uses `@tanstack/react-table`. Full column resizing, reordering (drag-and-drop), and show/hide controls.

Props:
- `storageKey: string` — localStorage namespace
- `columns: DataTableColumn[]` — column definitions with `id`, `label`, `header`, `initialSize`
- `rows: DataTableRow[]`
- `minColumnWidth?: number` (default 96)
- `showColumnControls?: boolean` (default true)

LocalStorage persistence:
- `{storageKey}` — column widths
- `{storageKey}:order` — column order
- `{storageKey}:hidden` — hidden column IDs

Internal hook: `useContainerWidth()` — ResizeObserver-based container measurement for proportional width rebalancing when columns are shown/hidden.

### StatCard (`src/components/StatCard.tsx`)

Metric display card. Props: `title`, `value`, `tone` (`neutral | warn | critical`), `caption`, `description`. Renders a `MetricInfoIcon` when `description` is provided.

### CveRiskScorePanel (`src/components/CveRiskScorePanel.tsx`)

SVG-based risk score trend chart. Period selector: 14d / 30d / 90d. Two variants: standard and `mini={true}`. Shows S.AI scoring journey events as dots + cards along the timeline. Plots a CVSS baseline dashed line for comparison. Mini mode shows a tooltip with reasoning trace on hover.

### FilterBuilder (`src/components/FilterBuilder.tsx`)

Dropdown filter selector with category tabs and free-text search. Closes on outside click or Escape.

Props: `categories: FilterBuilderCategory[]`, `fields: FilterBuilderField[]`, `activeKeys: string[]`, `onAddFilter: (key: string) => void`

Each `FilterBuilderField` has: `key`, `label`, `categoryKey`, `description`, `typeLabel`.

### ConfirmDialog (`src/components/ConfirmDialog.tsx`)

Native `<dialog>` element with `showModal()` / `close()`. Closes on backdrop click or Escape via `onCancel` prop.

Props: `isOpen`, `title`, `message`, `confirmLabel?` (default `'Confirm'`), `cancelLabel?` (default `'Cancel'`), `onConfirm`, `onCancel`

### SegmentedControl (`src/components/SegmentedControl.tsx`)

Generic segmented button group. Fully typed with `T extends string`.

Props: `options: Array<{value: T, label: string, activeClass?: string}>`, `value: T`, `onChange: (value: T) => void`, `ariaLabel?`

### MultiGroupBy (`src/components/MultiGroupBy.tsx`)

Two-level group-by selector (primary + multi-select secondary). Closes on outside click or Escape.

Props: `options: MultiGroupByOption[]`, `value: string[]`, `onChange: (next: string[]) => void`, `label?`, `placeholder?`, `maxInlineSelections?`, `allowEmptyPrimary?`, `emptyPrimaryLabel?`, `showSelectorsByDefault?`

### VulnRepoCveAssessmentWorkbench (`src/components/VulnRepoCveAssessmentWorkbench.tsx`)

The main CVE investigation panel rendered inside `VulnRepoOrgCvePage` when a CVE row is selected. 4-step workflow. Integrates `CveRiskScorePanel`, `CVEInvestigationSummary`, `ConfirmDialog`, `SegmentedControl`. Calls multiple `cveWorkbenchApi` methods and `api` methods. Derives `DerivedAssetRow` objects from matched software via `buildAssetRowsFromMatchedSoftware` from `src/features/cve-workbench/asset-report.ts`.

### CVEInvestigationSummary (`src/components/CVEInvestigationSummary.tsx`)

Displays a saved AI investigation summary. Props include `InvestigationSummaryInput`.

### EolBadge (`src/components/EolBadge.tsx`)

Small badge rendered in tables when a component is EOL or near-EOL.

### EolDetailDrawer (`src/components/EolDetailDrawer.tsx`)

Slide-in drawer with full EOL release detail for a selected package.

### EolMappingReviewPanel (`src/components/EolMappingReviewPanel.tsx`)

Panel for reviewing and resolving unresolved EOL slug mappings.

### EolRiskWidget (`src/components/EolRiskWidget.tsx`)

Summary widget card for EOL risk exposure.

### EolSourcePanel (`src/components/EolSourcePanel.tsx`)

Configuration panel for the endoflife.date connector in the Connect page.

### GithubPipelineManager (`src/components/GithubPipelineManager.tsx`)

GitHub SBOM source management UI in the Connect page.

### InfoTooltip (`src/components/InfoTooltip.tsx`)

Simple hover tooltip for inline help text.

### InventoryQualityWorkspace (`src/components/InventoryQualityWorkspace.tsx`)

Panel for reviewing inventory data quality issues (missing versions, unmapped software, alias reviews, discovery review flags).

### MetricInfoIcon (`src/components/MetricInfoIcon.tsx`)

Small info icon with tooltip; used by `StatCard` when `description` is provided.

### SoftwareIdentityDetailDrawer (`src/components/SoftwareIdentityDetailDrawer.tsx`)

Slide-in drawer with full software identity detail.

### ColumnVisibilityToggle (`src/components/ColumnVisibilityToggle.tsx`)

Toggle dropdown for DataTable column show/hide controls.

### FilterValueSelectCard (`src/components/FilterValueSelectCard.tsx`)

Dropdown card used by filter pills to select filter values.

---

## 6. API Layer

All backend calls go through the single `api` export object in `src/api/client.ts`. There is no axios; all requests use native `fetch`.

### Auth header injection

```
applyAuthHeaders(headers):
  if getStoredAuthToken() -> Authorization: Bearer <token>
  else -> X-API-Key: <VITE_API_KEY>  +  X-Creator-Key: <VITE_CREATOR_KEY>
```

### Base URL

`VITE_API_BASE` (default `http://localhost:8080/api`). In dev, Vite proxies `/api/**` to `http://localhost:8080` so the base URL can be relative.

### Token helpers

```typescript
getStoredAuthToken(): string | null        // reads localStorage 'vulnwatch.authToken'
setStoredAuthToken(token: string): void    // writes to localStorage
clearStoredAuthToken(): void               // removes from localStorage
```

### Core request helpers

- `request<T>(path, options?)` — authenticated fetch; throws on non-OK response
- `publicRequest<T>(path, options?)` — unauthenticated fetch

### Platform action confirmation

`shouldConfirmPlatformAction()` checks `ActorContext.sensitiveActionConfirmationRequired`. `currentPlatformTenantContext()` returns the active tenant name when `actingAsPlatformOwner`.

### Key API methods (grouped by domain)

**Findings:**
- `listFindings(params)` -> `FindingPage`
- `getFinding(id)` -> `Finding`
- `updateFindingWorkflow(id, payload)` -> `Finding`
- `bulkUpdateFindings(payload)` -> `FindingBulkWorkflowResponse`
- `deleteFinding(id)`
- `listFindingFilters()` -> filter option lists
- `getFindingTimeline(id)` -> `FindingTimeline`

**CVE / Vulnerability Repo:**
- `getVulnRepoDashboard()` -> `VulnRepoDashboard`
- `getPlatformVulnRepoDashboard()` -> `VulnRepoDashboard` (platform scope)
- `getCveDetail(cveId)` -> `CveDetail`
- `getCveAiSolution(cveId)` -> AI solution text
- `getCveInventoryMap(limit)` -> CVE-inventory map data

**Inventory:**
- `listAssets(params)` -> asset list
- `getHostAssetDetail(assetId, options?)` -> `HostAssetDetail`
- `listInventoryComponents(params)` -> `InventoryComponentPage`
- `listInventoryComponentFilters()` -> `InventoryComponentFilterValues`

**Software Identities:**
- `listSoftwareIdentities(params)` -> paginated list
- `getSoftwareIdentityDetail(id)` -> `SoftwareIdentityDetail`
- `getSoftwareIdentityMetadata(id)` -> `SoftwareIdentityMetadata`
- `getSoftwareIdentityFunnel()` -> `SoftwareIdentityFunnel`
- `getVulnRepoSoftwareAssets(softwareIdentityId)` -> `VulnRepoSoftwareAssetsDetail`

**Dashboard:**
- `getDashboard()` -> `Dashboard`

**Operations:**
- `getOperationalDashboard()` -> `OperationalDashboard`
- `getPlatformHealthData()` -> platform health metrics

**EOL:**
- `getEolSummary()` -> `EolSummary`
- `getEolComponentStatuses(params)` -> paginated component statuses
- `listEolProducts()` -> `EolProductCatalog[]`
- `listEolProductReleases(slug)` -> `EolRelease[]`
- `listEolUnresolvedMappings(params)` -> paginated unresolved mappings
- `listEolMappingSuggestions(normalizedKey)` -> `EolSlugSuggestion[]`
- `getEolPackageStatuses(params)` -> paginated `PackageEolStatus`
- `getEolPackageAssets(params)` -> paginated assets for a package

**Configurations:**
- `getRiskPolicy()` -> `RiskPolicy`
- `updateRiskPolicy(payload)` -> `RiskPolicy`
- `listOwnershipRules()` -> `OwnershipRuleResponse[]`
- `createOwnershipRule(payload)`, `updateOwnershipRule(id, payload)`, `deleteOwnershipRule(id)`
- `listSuppressionRules()` -> `SuppressionRule[]`
- `createSuppressionRule(payload)`, `updateSuppressionRule(id, payload)`, `deleteSuppressionRule(id)`

**Connectors:**
- `listSyncRuns(params)` -> `SyncRun[]`
- `triggerSync(connectorId)` -> `SyncTriggerResponse`
- `getServiceNowCmdbConfig()`, `updateServiceNowCmdbConfig(payload)`
- `getSccmCmdbConfig()`, `updateSccmCmdbConfig(payload)`
- `getAwsDiscoveryConfig()`, `updateAwsDiscoveryConfig(payload)`
- `listAwsDiscoveryTargets()`, `createAwsDiscoveryTarget(payload)`, `deleteAwsDiscoveryTarget(id)`
- `listGithubSbomSources()`, `createGithubSbomSource(payload)`, `deleteGithubSbomSource(id)`
- `getVulnerabilitySourceFilterConfig(sourceSystem)`, `updateVulnerabilitySourceFilterConfig(sourceSystem, payload)`
- `getVexAssertionRepairSummary()`

**Auth / Admin:**
- `getAuthContext()` -> `ActorContext`
- `login(credentials)` -> `AuthTokenResponse`
- `selectTenantContext(tenantId)` -> `ActorContext`
- `clearTenantContext()` -> `ActorContext`
- `listTenants()` -> `Tenant[]`
- `listPlatformUsers()` -> `PlatformUser[]`
- `listServiceAccounts()` -> `ServiceAccount[]`
- `createServiceAccount(payload)` -> `ServiceAccount`
- `listAuditEvents(params)` -> `AuditEvent[]`
- `listTenantMembers()` -> `TenantMember[]`
- `addTenantMember(payload)`, `updateTenantMember(id, payload)`, `removeTenantMember(id)`
- `listTenantSupportGrants()`, `createTenantSupportGrant(payload)`, `revokeTenantSupportGrant(id)`
- `listPlatformSupportGrants()`, `acceptPlatformSupportGrant(id)`
- `getPlatformInventoryConnectorHealth()` -> `InventoryConnectorHealth`

---

## 7. State Management

There is no Redux or Zustand. All remote data is managed by `@tanstack/react-query`. Local/ephemeral state is `React.useState`. Persisted UI state (column prefs, theme, filters) goes to `localStorage`.

### React Query setup

`createQueryClient()` in `src/lib/queryClient.ts`:
- `retry: 1`
- `staleTime: 10_000` (10 seconds, overridable per query)
- `refetchOnWindowFocus: false`

The client is instantiated once in `src/main.tsx` and provided via `QueryClientProvider`.

### Query key conventions

| Domain | Key prefix |
|---|---|
| Auth context | `['auth-context', rawToken]` |
| Findings list | `['findings', params]` |
| Finding filters | `['finding-filters']` |
| Dashboard summary | `['dashboard-summary']` |
| Vuln repo dashboard | `['vuln-repo-dashboard', scope]` |
| CVE detail | `['cve-detail', cveId]` |
| Inventory components | `['inventory-components', params]` |
| Host asset detail | `['host-asset-detail', assetId, sourceSystem]` |
| Software identities | `['software-identities', params]` |
| Software identity detail | `['software-identity-detail', id]` |
| EOL summary | `['eol-summary']` |
| EOL package statuses | `['eol-package-statuses', params]` |
| EOL package assets | `['eol-package-assets', params]` |
| Sync runs | `['sync-runs', params]` |
| GitHub SBOM sources | `['github-sbom-sources']` |

### Polling intervals (`src/lib/polling.ts`)

| Constant | Value | Used by |
|---|---|---|
| `DASHBOARD_REFRESH_INTERVAL_MS` | 15 000 ms | `useDashboardSummaryQuery` |
| `OPERATIONS_REFRESH_INTERVAL_MS` | 15 000 ms | `useOperationsViewQuery` |
| `ORG_CVE_STATUS_REFRESH_INTERVAL_MS` | 10 000 ms | `useOrgSpecificCveAutomationStatusQuery` (conditional) |
| `RUN_QUEUE_REFRESH_INTERVAL_MS` | 3 000 ms | `useSyncRunsQuery` (conditional on active runs) |

### localStorage keys

| Key | Purpose |
|---|---|
| `vulnwatch.authToken` | JWT Bearer token |
| `scoutai-theme` | `'dark'` or `'light'` — applied as `data-theme` on `<html>` |
| `findings-col-vis-v2` | FindingsPage column visibility |
| `{storageKey}` | DataTable column widths (per table) |
| `{storageKey}:order` | DataTable column order |
| `{storageKey}:hidden` | DataTable hidden columns |

### Inventory URL state

Inventory views persist their filter and grouping state as URL search parameters (not localStorage) via the helpers in `src/features/inventory/searchState.ts`. This means inventory filter state survives page refresh and is shareable via URL.

---

## 8. Custom Hooks

### `useDebouncedValue<T>(value, delayMs?)` (`src/hooks/useDebouncedValue.ts`)

Debounces a value with a configurable delay (default 300 ms). Special behavior: empty strings clear immediately without waiting for the delay. Used for search inputs to avoid excess API calls.

### `useActorQuery()` (`src/features/auth/queries.tsx`)

Calls `GET /api/auth/context`. Returns `UseQueryResult<ActorContext>`. Query key includes the raw token so it auto-invalidates on login/logout. `staleTime: 5 minutes`.

### `useActor()` (`src/features/auth/context.ts`)

Reads the `ActorContext` from React context. Throws if called outside `AuthSessionBoundary`.

### `useFindingsQuery(params)` (`src/features/findings/queries.ts`)

Server-side paginated findings. Uses `keepPreviousData` to avoid flash on page change.

### `useOrgSpecificCveAutomationStatusQuery()` (`src/features/cve-workbench/queries.ts`)

Polls at `ORG_CVE_STATUS_REFRESH_INTERVAL_MS` only when `pendingEventCount > 0`. Returns to non-polling when the pending count reaches zero.

### `useOperationsViewQuery(selectedView)` (`src/features/operations/queries.ts`)

Loads both Pipeline and Platform Health sections in parallel using `Promise.all`. Refetches every 15 seconds.

### `useSyncRunsQuery(params)` (`src/features/connect/queries.ts`)

Smart polling: checks `run.status` for RUNNING/STARTED/QUEUED; polls at 3 s when any run is active, stops when all runs complete. Does not poll in background (`refetchIntervalInBackground: false`).

### `useInventoryData(args)` (`src/features/inventory/useInventoryData.ts`)

Composes `useInventoryComponentsQuery` and `useInventoryComponentFiltersQuery`, normalizes filter option values, exposes `refreshInventory()` to force a refetch.

### `useContainerWidth()` (internal to `DataTable.tsx`)

`ResizeObserver`-based hook that measures the table container's width. Used by DataTable to proportionally redistribute column widths when columns are shown or hidden.

---

## 9. Type System

Types are **feature-colocated**, not centralized. `src/types/index.ts` re-exports everything but is only a convenience barrel — the source of truth is always the file in the feature directory. When editing a type, edit the feature file.

### Type file locations

| Type(s) | Source file |
|---|---|
| `ActorContext`, `AllowedTenant` | `src/features/auth/types.ts` |
| `Finding`, `FindingPage`, `FindingFilterValues`, `FindingBulkWorkflowRequest`, `FindingTimeline`, `VulnerabilityDetail` | `src/features/findings/types.ts` |
| `OrgSpecificCveExposureRecord`, `CveDetail`, `CveMatchedSoftware`, `CveInvestigation`, `CveApplicabilityAssessment`, `FixRecord` | `src/features/cve-workbench/types.ts` |
| `ApplicabilityDecision`, `ImpactDecision`, `SoftwareGroup`, `FindingDisplayRow` | `src/features/cve-workbench/assessment-helpers.ts` |
| `RiskPolicy`, `SuppressionRule`, `SuppressionRuleRequest`, `OwnershipRuleResponse`, `OwnershipRuleRequest` | `src/features/configurations/types.ts` |
| `InventoryViewKey`, `InventoryScopedAssetType`, `InventoryComponentFilterKey`, `HostReviewCategory` | `src/features/inventory/types.ts` |
| `Asset`, `HostAssetDetail`, `HostAssetSummary`, `InventoryComponentRecord`, `InventoryComponentPage`, `InventoryComponentFilterValues` | `src/features/inventory/api-types.ts` |
| `SyncRun`, `ServiceNowCmdbConfig`, `SccmCmdbConfig`, `AwsDiscoveryConfig`, `GithubSbomSource`, `VulnerabilitySourceFilterConfig` | `src/features/connect/types.ts` |
| `OperationalDashboard`, `OperationalQualityIssue`, `SloStatus` | `src/features/operations/types.ts` |
| `Dashboard`, `TopFindingMetric` | `src/features/dashboard/types.ts` |
| `VulnRepoDashboard`, `VulnRepoDashboardSummaryCards`, `VulnRepoDashboardResolutionStatus`, `VulnRepoDashboardCriticalUnresolvedItem`, `VulnRepoDashboardTopAffectedSoftwareItem`, `VulnRepoDashboardImpactedAssetItem` | `src/features/vuln-repo-dashboard/types.ts` |
| `SoftwareIdentitySummary`, `SoftwareIdentityDetail`, `SoftwareIdentityFunnel`, `VulnRepoSoftwareAssetsDetail` | `src/features/software-identities/types.ts` |
| `EolSummary`, `ComponentEolStatus`, `EolProductCatalog`, `PackageEolStatus` | `src/features/eol/types.ts` |
| `Tenant`, `TenantMember`, `PlatformUser`, `ServiceAccount`, `AuditEvent`, `TenantSupportGrant` | `src/features/admin/types.ts` |
| `OwnershipSummary` | `src/types/ownership.ts` |
| `PolicyWeights` | `src/lib/riskScoring.ts` |
| `DataTableColumn`, `DataTableRow` | `src/components/DataTable.tsx` |
| `MultiGroupByOption` | `src/components/MultiGroupBy.tsx` |
| `FilterBuilderCategory`, `FilterBuilderField` | `src/components/FilterBuilder.tsx` |
| `AppTab`, `OperationsRouteView`, `VulnerabilityIntelRouteView`, `ConnectRouteView`, `AdminRouteView`, `PlatformRouteView` | `src/app/routes.ts` |

### S.AI scoring types (`src/lib/riskScoring.ts`)

`PolicyWeights` mirrors the 6 `triage*` fields on `RiskPolicy`:
- `triageExploitabilityWeight: number`
- `triageBlastRadiusWeight: number`
- `triageEolRiskWeight: number`
- `triageSlaBreachWeight: number`
- `triageMissingOwnerBoost: number`
- `triagePatchGapBoost: number`

`CveRiskScoreResult` — output of `computeCveRiskScore`: `score` (0–10), `stages` array with per-stage contribution and reasoning.

`FindingPriorityScoreResult` — output of `computeFindingPriorityScore`: `score` (0–10), `signals` array.

---

## 10. Styling

All styles are plain CSS with custom properties. No CSS-in-JS, no Tailwind.

### Theme system

Two themes: `light` (default) and `dark`. Applied as `data-theme="dark"` on `<html>`. Persisted in `localStorage` under `scoutai-theme`. Theme state is managed in `App.tsx`.

### CSS custom properties (defined in `src/styles/base.css`)

| Variable | Purpose |
|---|---|
| `--bg` | Page background |
| `--panel` | Card/panel background |
| `--panel-muted` | Slightly muted panel |
| `--text` | Body text |
| `--title` | Heading text |
| `--muted` | Secondary/caption text |
| `--border` | Default border |
| `--border-strong` | Emphasized border |
| `--accent` | Brand/action color |
| `--critical` | Critical severity color |
| `--high` | High severity color |
| `--medium` | Medium severity color |
| `--low` | Low severity color |
| `--space-1` through `--space-6` | Spacing scale |
| `--control-sm` | Small control height |

### Fonts

- **Space Grotesk** — display/heading text
- **IBM Plex Sans** — body text

### CSS file organization

| File | Contents |
|---|---|
| `base.css` | CSS custom properties for both themes, font imports, reset |
| `shared.css` | Global layout classes (`page-grid`, `panel`, `panel-header`), buttons, pills, badges, filter dropdowns, SBOM wizard, segmented controls |
| `cve-workbench.css` | CVE Assessment Workbench panel and workflow styles |
| `connect.css` | Connector filter bar, connector card grid, wizard step styles |
| `eol.css` | EOL page — at-risk table, catalog styles |
| `vuln-repo.css` | Vuln repo pages — inline bars, status pills |
| `user-management.css` | User management page — role matrix table, member rows |
| `exposure-dashboard.css` | Executive dashboard — `exec-kpi-*`, `exec-pipeline-*`, `exec-cve-*`, `exec-rem-*`, `exec-asset-*`, `exec-software-*`, `exec-insight-*` classes |
| `finding-detail.css` | Finding detail page styles |
| `findings-list.css` | Findings list page styles |

### CSS class naming patterns

| Pattern | Usage |
|---|---|
| `severity-pill severity-{critical,high,medium,low}` | Severity badges |
| `status-pill status-{open,resolved,suppressed,in-progress,unknown,auto_closed}` | Status badges |
| `panel` | Card container |
| `panel-header` | Card header row |
| `panel-caption` | Subdued helper text |
| `btn`, `btn-primary`, `btn-secondary`, `btn-link` | Button variants |
| `segmented-control`, `segmented-control-btn--active` | Segmented button groups |
| `filter-pill`, `filter-pill-chevron` | Filter UI |
| `exec-kpi`, `exec-kpi--critical`, `exec-kpi--warn` | KPI cards on exposure dashboard |
| `impact-impacted`, `impact-fixed`, `impact-no-patch`, `impact-not-impacted`, `impact-unknown` | VEX impact state badges |

---

## 11. Development Notes

### Starting the app

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173 (strictly)
```

Backend must be running on port 8080 (or configure `VITE_API_BASE`).

### Environment variables

Copy `.env.example` to `.env.local`. All variables use the `VITE_` prefix.

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_BASE` | `http://localhost:8080/api` | Backend API base URL |
| `VITE_API_KEY` | `change-me-in-prod` | `X-API-Key` header (local dev fallback) |
| `VITE_CREATOR_KEY` | `local-creator` | `X-Creator-Key` for PLATFORM_OWNER endpoints (local dev) |
| `VITE_AUTH_TOKEN` | (empty) | Static bearer token override |
| `VITE_SENTRY_DSN` | (empty) | Sentry DSN — leave empty to disable |
| `VITE_ENABLE_TEST_PERSONAS` | `false` | Enables impersonation persona switcher in dev |

### S.AI Risk Scoring

`computeCveRiskScore` and `computeFindingPriorityScore` in `src/lib/riskScoring.ts` are **pure TypeScript** — no React imports, no API calls. They compute scores entirely from data already returned by the API. Scores are not stored in the database; they recalculate on every render.

Call sites fetch the risk policy via `useRiskPolicyQuery()` and pass `policyQuery.data` as the optional `policy` argument. `DEFAULT_POLICY` (all weights 1.0) is used when no policy is available.

**`computeCveRiskScore` stages:** CVE Published (CVSS + EPSS) -> In CISA KEV -> Org Exposure (blast radius) -> EOL Risk -> No Patch -> Applicability Decision -> Findings Created.

**`computeFindingPriorityScore` signals:** exploitability (KEV/EPSS weight), SLA breach proximity, missing owner boost, EOL component risk, severity boost, VEX confirmed affected.

### React StrictMode

The app uses `React.StrictMode` (see `src/main.tsx`). Effects run twice in development. All side effects must be idempotent.

### Two distinct CVE list pages

These are different pages backed by different API endpoints — do not confuse them:

- `/vuln-repo/org-cves` (`VulnRepoOrgCvePage`) — **Unified Vulnerability Records.** Queries `org_cve_records` via `useOrgSpecificCvesQuery`. Only shows CVEs correlated to org inventory. Primary analyst triage and investigation workflow. Every CVE here has a CPE match.

- `/vuln-repo/vulnerabilities` (`VulnRepoVulnerabilitiesPage`) — **Vulnerability Intelligence.** Queries `vulnerability_intel_summary` via `useVulnRepoVulnerabilitiesQuery`. Shows ALL ingested CVEs from NVD/GHSA/KEV regardless of inventory match. CVEs with `matchedSoftwareCount = 0` are expected here.

### Adding a new connector

1. Add the connector ID to the `ConnectorId` union in `ConnectPage.tsx`.
2. Add to the `CONNECTORS` array with `id`, `name`, `summary`, `icon`.
3. Add to the appropriate category list (Vulnerability Intelligence, CMDB/Inventory Sources, or Cloud Discovery).
4. Add a `case` in `ConnectorDetailContent` that renders the connector's config component.

### Configurations page sections

8 sections in sidebar order: SLA & Remediation -> S.AI Prioritization (AI badge) -> Workflow Automation -> Ownership -> Vulnerability Sources -> Findings Score -> Suppression Rules -> Auto-Finding Rules. All except Ownership and Vulnerability Sources persist to a single `RiskPolicy` record via `PUT /api/risk-policy`. Call `applyTriageDefaults()` on API responses to fill missing triage fields for backends that predate the V1062 migration.

### Test infrastructure

Page tests live next to their page as `<Page>.test.tsx`. Use `renderWithProviders` from `src/test/test-utils.tsx`:

```typescript
import { renderWithProviders } from '../test/test-utils';

renderWithProviders(<MyPage />, {
  route: '/findings',            // optional initial route
  initialEntries: [{ pathname: '/findings', state: { foo: 'bar' } }],
  queryClient: customClient,     // optional
});
```

Mock API methods with `vi.spyOn(api, 'methodName').mockResolvedValue(...)`. Use `api` from `src/api/client.ts`. The `cveWorkbenchApi` is a separate object and must be mocked separately. Call `localStorage.clear()` in `afterEach` for pages that persist column preferences.

Test `QueryClient` uses `retry: false` so failed queries resolve immediately without retries.

Available test fixtures in `src/test/fixtures.ts`:
- `buildFinding(overrides?)` — builds a complete `Finding` with realistic defaults
- `defaultRiskPolicy(overrides?)` — all 12+ `RiskPolicy` fields with sensible defaults
- `defaultFindingFilterValues(overrides?)` — `FindingFilterValues`
- `pageOf<T>(items, size?)` — wraps items in a paginated envelope
- `findingPageOf(items, size?)` — typed version for `FindingPage`

### Platform owner flow

`ActorContext.platformScope = true` means the user is a platform owner who has not selected a tenant. In this state, all tenant-scoped routes (`/exposure`, `/findings`, `/vuln-repo`, `/inventory`, etc.) redirect to `/platform/tenants`. After calling `api.selectTenantContext(tenantId)`, `actingAsPlatformOwner = true` and tenant-scoped routes become accessible.

### Exposure Dashboard layout

`ExposureDashboardPage` fetches from three queries in parallel: `useDashboardSummaryQuery()`, `useVulnRepoDashboardQuery()`, `useEolSummaryQuery()`. It renders four rows:
1. 6 KPI cards: Critical Findings, Open Findings, Impacted CVEs, CISA KEV Exposure, Needs Attention, EOL Software
2. CVE Exposure Pipeline (funnel with Tracked/Applicable/Impacted/Remediation) + Remediation Progress (status bars + Security Score)
3. Critical CVEs Requiring Action list + Where Attention Is Required (insight chips)
4. Most Exposed Software list + Critical Exposed Assets list

The insight chips are generated client-side from the fetched data and link directly to filtered views on other pages.

### FindingsPage details

`FindingsPage` has 5 widget cards (severity donut, status bars, top assets, SLA/due date, KPI indicators), 19 configurable columns persisted to `findings-col-vis-v2` in localStorage, server-side filters (severity, status, creationSource, vulnerabilityId, packageName) and client-side filters (findingId, asset, owner, supportGroup, assignedTo, incidentId, risk, dueDate band). Bulk actions available: Resolve, Defer, False Positive, Duplicate, Create ServiceNow Incident, Re-open, Delete. `computeFindingPriorityScore()` is called per row for the S.AI Priority column.

### OperationalDashboardPage view keys

Two nav items shown: `pipeline` and `platform-health`. The `quality` view key exists in the type but has legacy aliases mapping to `pipeline`. Views `dashboard`, `overview`, `ingestion-efficiency`, `ingestion`, `normalization-quality`, `normalization`, `correlation`, `noise` all alias to `pipeline`.

### Never-touch list (from project CLAUDE.md)

- Applied Flyway migrations (V*.sql) — add a new one, never edit an applied one
- Security config in backend
- Tenant scoping logic
- Deploy infra (Dockerfile, workflows)
- Golden contract fixture hashes

### Things rejected on sight (from project CLAUDE.md)

- New `any` TypeScript types without a comment explaining why
- `console.log` left in shipped code
- New `src/components/` files larger than ~300 lines
- Lowering coverage thresholds
- `// TODO` without owner or linked issue
