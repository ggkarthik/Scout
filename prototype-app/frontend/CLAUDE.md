# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> The root `../CLAUDE.md` contains full project conventions, route table, feature descriptions, and the never-touch list. This file adds frontend-specific runtime detail.

## Commands

```bash
npm run dev           # dev server on port 5173 (strictly)
npm run build         # tsc -b --force && vite build
npm run lint          # eslint .
npm run typecheck     # tsc -b --noEmit (no output files)
npm run test:unit     # vitest run (all tests, no watch)
npm run test:coverage # vitest run --coverage (enforces line/branch thresholds)

# Run a single test file
npx vitest run src/pages/FindingsPage.test.tsx
```

CI gates in order: `lint` → `typecheck` → `build` → `test:coverage`.

Vite proxies `/api/**` to `http://localhost:8080` in dev, so the frontend talks to the backend directly without a separate CORS config.

## Environment variables

All variables are prefixed `VITE_`. Copy `.env.example` to `.env.local` to start.

| Variable | Purpose | Default / notes |
|---|---|---|
| `VITE_API_BASE` | Backend API base URL | `http://localhost:8080/api` |
| `VITE_API_KEY` | `X-API-Key` header value | `change-me-in-prod` |
| `VITE_CREATOR_KEY` | `X-Creator-Key` for PLATFORM_OWNER endpoints | `local-creator` |
| `VITE_AUTH_TOKEN` | Static bearer token (overrides stored token) | (empty) |
| `VITE_SENTRY_DSN` | Sentry error reporting | (empty = disabled) |
| `VITE_ENABLE_TEST_PERSONAS` | Enable impersonation switcher | `false` |

## Auth model in the browser

Authentication state flows through a single read path:

1. `getStoredAuthToken()` reads `vulnwatch.authToken` from `localStorage` (or falls back to `VITE_AUTH_TOKEN`).
2. `api.client.ts` attaches this as `Authorization: Bearer <token>` on every request. When no token is present it falls back to `X-API-Key` / `X-Creator-Key` headers (local dev only).
3. `useActorQuery()` calls `GET /api/auth/context` and returns an `ActorContext`. The query key includes the raw token so it busts automatically on login/logout.
4. `AuthSessionBoundary` in `App.tsx` wraps all authenticated routes. If the query fails or returns no data it redirects to `/login`.
5. The loaded `ActorContext` is published via `ActorContextState` (React context). Read it with `useActor()` from `src/features/auth/context.ts`.

Role checks **must** go through the helper functions in `src/features/auth/roles.ts` (`hasRole`, `canAccessPlatformConsole`, etc.). Do not check `actor.roles` directly — the helpers normalize `ROLE_` prefixes and handle `platformScope` edge cases.

`ActorContext.platformScope = true` means the user is a platform owner who has not yet entered a tenant. In this state, tenant-scoped routes (`/exposure`, `/findings`, etc.) redirect to `/platform/tenants`. After selecting a tenant, `actingAsPlatformOwner = true`.

## Source layout

```
src/
  api/
    client.ts          # Single api object — all backend calls, auth header injection,
                       # getStoredAuthToken / setStoredAuthToken / clearStoredAuthToken
  app/
    routes.ts          # All typed path helpers (pathForTab, pathForVulnRepoView, …)
                       # and legacy query-param → path-based redirect logic
  features/            # Feature-colocated modules; types live here, not in src/types/
    auth/              # ActorContext type, context, role helpers, queries
    findings/          # Finding type, queries, filters
    cve-workbench/     # OrgSpecificCveExposureRecord, CVE Assessment Workbench types
    configurations/    # RiskPolicy (6 triage weight fields), OwnershipRule, SuppressionRule
    inventory/         # Asset, HostAssetDetail, InventoryComponentPage
    connect/           # Connector configs, sync run types
    operations/        # OperationalDashboard, SLO, quality types
    dashboard/         # Dashboard, ImpactedCve types
    vuln-repo-dashboard/
    software-identities/
    eol/
    admin/             # Tenant, PlatformUser, ServiceAccount, AuditEvent
    widgets/           # Shared chart/widget components
  lib/
    riskScoring.ts     # Pure TS: computeCveRiskScore, computeFindingPriorityScore
    queryClient.ts     # createQueryClient factory (shared between app and tests)
  pages/               # One file per route; lazy-loaded via React.lazy in App.tsx
  components/          # Shared presentational components (≤ 300 lines each)
  test/
    setup.ts           # @testing-library/jest-dom/vitest import
    test-utils.tsx     # renderWithProviders (QueryClientProvider + MemoryRouter)
    fixtures.ts        # buildFinding, defaultRiskPolicy, defaultFindingFilterValues, pageOf
```

`src/types/index.ts` re-exports feature types but the **source of truth** is always the feature directory file. Edit the feature file, not the re-export.

## Page test scaffolding

Tests live next to the page as `<Page>.test.tsx`. Use `renderWithProviders` from `src/test/test-utils.tsx` — it wraps in `QueryClientProvider` and `MemoryRouter`.

```tsx
import { screen } from '@testing-library/react';
import { afterEach, describe, it, vi } from 'vitest';
import { api } from '../api/client';
import { buildFinding, defaultRiskPolicy, findingPageOf } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { FindingsPage } from './FindingsPage';

describe('FindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders rows for findings returned by the API', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([buildFinding()]));
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());
    renderWithProviders(<FindingsPage />);
    expect(await screen.findByText('F-001')).toBeInTheDocument();
  });
});
```

- Mock only the API methods the page actually calls.
- Use `vi.spyOn(api, 'method').mockResolvedValue(...)` / `mockRejectedValue(...)`.
- Pass `{ initialEntries: [{ pathname, state }] }` when the page reads `useLocation().state`.
- Call `localStorage.clear()` in `afterEach` for pages that persist filter/column preferences.

## Key constraints

- Components in `src/components/` must stay under ~300 lines. New substantial components go under `src/features/<feature>/`.
- `src/lib/riskScoring.ts` is pure TypeScript — no React imports, no API calls. `computeCveRiskScore` and `computeFindingPriorityScore` are computed in the browser from already-fetched data; they are not persisted.
- The app uses React StrictMode (see `src/main.tsx`) — effects run twice in development, so side effects should be idempotent.
- Theme (`dark` / `light`) is persisted in `localStorage` under `scoutai-theme` and applied as `data-theme` on `<html>`.
