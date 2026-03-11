# VulnWatch Frontend

Last updated: 2026-03-10

## Purpose

The frontend is a React single-page operations console. It drives SBOM ingestion, vulnerability intelligence review, org-level CVE exposure review, findings workflows, connector setup, and configuration management against the backend `/api` surface.

## Stack

- React 18
- TypeScript
- Vite 5
- Plain React state/hooks; no external state library
- Query-param-driven navigation in `src/App.tsx`
- No React Router

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

## Navigation Model

`src/App.tsx` renders a sidebar shell with query-param state for `tab`, `inventoryView`, `vulnIntelView`, and connector state.

Current top-level sections:

- Overview
- Findings
- Operational Dashboard
- Vulnerability Intelligence
- Inventory
- Connect
- Configurations

The active app is organized as a shell, not route-based pages. Most drill-downs happen inline in tables, drawers, and modals.

## Main Experiences

### Overview

- `DashboardPage`
- Reads `/dashboard`, `/dashboard/applicable-software`, `/dashboard/impacted-cves`, and `/dashboard/cve-inventory-map`
- Focuses on high-level posture, impacted CVEs, and coverage summaries

### Findings

- `FindingsPage`
- Reads `/findings` and `/findings/filters`
- Supports severity, status, decision state, VEX, match-method, and package filters

### Operations

- `OperationalDashboardPage`
- Reads `/operations/dashboard`
- Intended for creator-level operational metrics and queue/ingestion visibility

### Vulnerability Intelligence

There are three distinct views under the Vulnerability Intelligence flyout:

- Dashboard: `VulnerabilityIntelDashboardPage`
- Vulnerability list/detail: `InventoryPage` in `vulnerability-intelligence` mode using `/vulnerability-intelligence`, `/vulnerability-intelligence/filters`, and `/vulnerability-intelligence/{externalId}`
- Org CVEs: `VulnerabilityIntelOrgCvePage` using `/vulnerability-intelligence/org-cves` and `/vulnerability-intelligence/org-cves/recompute`

Org CVEs is the primary place where the current UI exposes CVE drill-down. It opens `OrgCveDetailDrawer`, which uses the `/cve-detail/*` workflow APIs for investigations, applicability assessments, manual finding creation, suppression, and export.

### Inventory

The current sidebar exposes four reachable inventory views:

- Imported Assets
- Hosts
- Container Images
- SBOM

All of them currently sit on top of `/inventory/components` and `/inventory/components/filters`, with default asset-type filters changing by view. `InventoryPage` contains additional future-oriented view keys, but those are not wired into the current navigation or backed by dedicated backend APIs.

### Connect

`ConnectPage` is a connector catalog that swaps in focused workflow pages:

- `IngestionPage` for SBOM upload, endpoint fetch, and GitHub-generated SBOM ingestion
- `AssetsPage` for CMDB sync payloads
- `SourcesPage` for NVD, KEV, GHSA, CSAF/VEX, and advisory ingestion runs

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
- Most long-running actions surface inline status text instead of global toasts

## Current Caveats

- There is no route-level page system; deep links depend on query params and mounted shell state.
- `CveDetailPage.tsx` exists but is not mounted in `App.tsx`; the live CVE workflow is the org-CVE drawer.
- The frontend assumes the backend's single-default-tenant runtime and supplies tenant/user headers from environment defaults.
- The inventory UI exposes more conceptual categories than the backend currently models explicitly.
- The frontend package ships `dev`, `build`, `preview`, and `test:unit` scripts. `test:unit` runs Vitest in non-watch mode (`vitest run`). There is no dedicated lint script in `package.json`.
