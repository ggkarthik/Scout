# Tenant Plan Entitlements Proposal

**Author:** Codex
**Date:** 2026-06-15
**Status:** Proposed
**Scope:** Backend + frontend + platform administration

---

## 1. Goal

Introduce two commercial plans:

- `PRO`
- `ENTERPRISE`

For the first release, the main distinction is AI access:

- `PRO` tenants do **not** get AI features
- `ENTERPRISE` tenants get **all** AI features

The design must also support a future where **any capability** in the app can belong to:

- `PRO` only
- `ENTERPRISE` only
- both plans
- a tenant-specific override regardless of plan

---

## 2. Current State

The app already has useful building blocks:

- `platform.tenants.plan_code` stores the tenant plan label
- `platform.tenants` already stores quota-style fields such as connector and export limits
- `/api/auth/context` already sends tenant plan context to the frontend
- demo-only feature switches already exist via `demoCapabilities`
- AI entry points are already concentrated in a few backend endpoints and services

Current plan handling is not yet scalable because:

- `planCode` is only a label today, not a full entitlement model
- feature access would become fragile if we add `if (planCode === 'ENTERPRISE')` checks throughout the codebase
- demo capabilities and plan capabilities would become two separate systems

---

## 3. Recommendation

Use a **tenant entitlement model** with three layers:

1. `plan_code` stays as the commercial plan identifier
2. plan entitlements define what each plan includes
3. tenant overrides allow exceptions without code changes

This gives us:

- a single source of truth for feature access
- backend-enforced security
- frontend-friendly visibility for hiding, disabling, or upselling features
- room for future limits, modes, and temporary exceptions

The key rule is:

**Never gate behavior directly on `planCode` in feature code. Always ask an entitlement service.**

---

## 4. Architecture Decision

### AD-1: Keep `plan_code`, but make it informational

`platform.tenants.plan_code` should continue to exist because it is useful for:

- billing and CRM alignment
- tenant creation flows
- reporting
- plan-based defaults

But application behavior should come from resolved entitlements, not from `plan_code` string comparisons.

### AD-2: Backend is the source of truth

The backend must decide whether a tenant can use a capability.

Frontend checks are still useful, but only for UX:

- hide buttons
- show upgrade prompts
- disable pages or actions early

Every protected action must still be validated server-side.

### AD-3: Resolve entitlements centrally

Create a single service, for example `TenantEntitlementService`, that resolves the effective access for a tenant.

Resolution order:

1. system default
2. plan entitlement
3. tenant override
4. temporary support or sales override later if needed

### AD-4: Treat AI as the first entitlement category, not a special case

Do not build a one-off “AI plan” solution.

Instead, define entitlement keys such as:

- `ai.investigation_summary`
- `ai.solution_generation`
- `ai.required_actions`
- `ai.fix_generation`
- `ai.investigation_agent`
- `ai.upgrade_recommendation`

This solves today’s requirement and creates the pattern for future non-AI features.

---

## 5. Proposed Data Model

### 5.1 New platform tables

#### `platform.plan_definitions`

Purpose: master list of commercial plans.

Suggested columns:

- `code` varchar PK
- `display_name` varchar
- `status` varchar
- `description` varchar
- `created_at` timestamptz
- `updated_at` timestamptz

Seed values:

- `PRO`
- `ENTERPRISE`
- keep existing `DEMO` and `PILOT` if still needed

#### `platform.entitlement_definitions`

Purpose: registry of every feature or capability that can be gated.

Suggested columns:

- `key` varchar PK
- `category` varchar
- `value_type` varchar
- `description` varchar
- `created_at` timestamptz
- `updated_at` timestamptz

Notes:

- `value_type` can start as `BOOLEAN`
- later it can support `INTEGER`, `STRING`, `JSON`

#### `platform.plan_entitlements`

Purpose: default access by plan.

Suggested columns:

- `plan_code` varchar FK -> `plan_definitions.code`
- `entitlement_key` varchar FK -> `entitlement_definitions.key`
- `enabled` boolean
- `config_json` jsonb
- `created_at` timestamptz
- `updated_at` timestamptz

Primary key:

- `(plan_code, entitlement_key)`

`config_json` is intentionally included now so we can later support things like:

- usage caps
- model selection
- page-level limits
- rollout metadata

without another schema redesign.

#### `platform.tenant_entitlement_overrides`

Purpose: tenant-specific exceptions.

Suggested columns:

- `id` uuid PK
- `tenant_id` uuid FK -> `platform.tenants.id`
- `entitlement_key` varchar FK -> `entitlement_definitions.key`
- `enabled` boolean
- `config_json` jsonb
- `reason` varchar
- `expires_at` timestamptz nullable
- `created_by` uuid nullable
- `created_at` timestamptz
- `updated_at` timestamptz

Unique key:

- `(tenant_id, entitlement_key)`

Use cases:

- sales-granted enterprise AI trial for one Pro tenant
- temporary disablement for a problematic feature
- customer-specific commercial exceptions

---

## 6. Effective Entitlement Shape

The service should resolve each entitlement to a normalized shape like:

```json
{
  "key": "ai.solution_generation",
  "enabled": true,
  "source": "PLAN",
  "planCode": "ENTERPRISE",
  "config": {}
}
```

Suggested sources:

- `DEFAULT`
- `PLAN`
- `TENANT_OVERRIDE`

This helps support:

- debugging
- platform administration
- auditability
- cleaner UI messaging

---

## 7. Initial Entitlement Set

For Phase 1, define only the entitlements we actually need.

### AI entitlements to seed now

- `ai.investigation_summary`
- `ai.solution_generation`
- `ai.required_actions`
- `ai.fix_generation`
- `ai.investigation_agent`
- `ai.upgrade_recommendation`

### Initial plan mapping

#### `PRO`

- all `ai.*` entitlements = `false`

#### `ENTERPRISE`

- all `ai.*` entitlements = `true`

This is enough for the current product requirement while keeping the system expandable.

---

## 8. Backend Design

### 8.1 New service layer

Add a central backend service, for example:

- `TenantEntitlementService`
- `TenantEntitlementSnapshot`
- `EntitlementGuard`

Core methods:

```java
boolean isEnabled(Tenant tenant, String entitlementKey);
Map<String, ResolvedEntitlement> snapshot(Tenant tenant);
void assertEnabled(Tenant tenant, String entitlementKey, String userMessage);
```

### 8.2 New exception

Add a dedicated exception for plan restrictions, for example:

- `EntitlementDeniedException`

Suggested API response:

```json
{
  "code": "PLAN_UPGRADE_REQUIRED",
  "message": "This feature is available on the Enterprise plan.",
  "entitlement": "ai.solution_generation",
  "currentPlan": "PRO"
}
```

This is better than a generic `403` because the frontend can show an upgrade prompt instead of a broken experience.

### 8.3 Protect AI endpoints first

These existing endpoints should be the first ones moved to entitlement checks:

- `POST /api/cve-detail/{cveId}/investigation-ai-summary`
- `POST /api/cve-detail/{cveId}/ai-solution`
- `POST /api/cve-detail/{cveId}/ai-actions`
- `POST /api/cve-detail/{cveId}/generate-fixes`
- `POST /api/cve-detail/{cveId}/investigation/run-agent`
- `POST /api/upgrade-recommendation`

Example:

```java
entitlementGuard.assertEnabled(
    tenant,
    "ai.solution_generation",
    "AI remediation recommendations are available on the Enterprise plan."
);
```

### 8.4 Do not remove demo gating yet

The app already has demo-specific behavior in `DemoLifecycleService`.

Recommended path:

- keep demo checks working in Phase 1
- implement plan entitlements beside them
- in a later cleanup, migrate demo capabilities onto the same entitlement engine

This lowers delivery risk.

---

## 9. Frontend Design

### 9.1 Extend auth context

Extend `/api/auth/context` to include resolved entitlements for the active tenant.

Suggested addition:

```json
{
  "planCode": "PRO",
  "entitlements": {
    "ai.investigation_summary": false,
    "ai.solution_generation": false,
    "ai.required_actions": false,
    "ai.fix_generation": false,
    "ai.investigation_agent": false,
    "ai.upgrade_recommendation": false
  }
}
```

This fits the app’s current pattern because the frontend already consumes `planCode` and `demoCapabilities` from the auth context.

### 9.2 Add frontend helpers

Create a small entitlement helper layer similar to `roles.ts`, for example:

- `features/auth/entitlements.ts`

Example helpers:

```ts
canUseEntitlement(actor, 'ai.solution_generation')
canUseAnyAiFeature(actor)
```

### 9.3 UX behavior

For blocked features, use one of three UI patterns:

- hide the action entirely when the feature would be confusing
- show the action disabled with `Enterprise only`
- allow navigation but show an upsell/upgrade state on the page

Recommended default for AI:

- show the feature entry point
- disable the action
- explain that it requires `Enterprise`

This helps discovery without letting the UI feel broken.

### 9.4 Do not trust the UI alone

Even if the UI hides a button, the backend must still reject direct API calls from Pro tenants.

---

## 10. Platform Administration

### 10.1 Tenant creation

The existing tenant creation flow already accepts `planCode`.

On tenant creation:

1. create tenant with `planCode`
2. resolve plan defaults from `platform.plan_entitlements`
3. do not copy entitlements into the tenant record

This avoids denormalized drift.

### 10.2 Optional admin screen later

Later, the platform console can expose:

- current tenant plan
- resolved entitlements
- manual overrides
- override expiry

This is not required for Phase 1 if migrations and seed data are enough.

---

## 11. Rollout Plan

### Phase 1: Backend foundation

- add entitlement tables and seed data
- add repositories and `TenantEntitlementService`
- add `EntitlementDeniedException`

### Phase 2: Protect AI endpoints

- gate all AI-generating endpoints on backend
- return plan-aware error responses

### Phase 3: Frontend visibility

- extend auth context with `entitlements`
- add entitlement helpers
- disable or upsell blocked AI controls

### Phase 4: Admin and cleanup

- optional platform console for overrides
- migrate `demoCapabilities` into the same entitlement model if desired
- gradually move quota fields into the same framework if the business model expands

---

## 12. Why This Design Fits This Codebase

This proposal aligns with the current app because:

- the app is already tenant-centric
- `plan_code` already exists on `platform.tenants`
- `/api/auth/context` is already the frontend entry point for tenant capability state
- AI functionality is already concentrated in a small number of controllers and services
- the app already uses backend-enforced access control patterns

It also avoids two common mistakes:

- scattering plan checks across controllers and React pages
- overloading roles with commercial access decisions

Roles should continue to answer **who** the user is allowed to act as.

Entitlements should answer **what the tenant has purchased**.

---

## 13. Recommendation Summary

Implement a **central entitlement system** now, even though only AI differs today.

Use:

- `plan_code` for commercial identity
- `plan_entitlements` for default feature access
- `tenant_entitlement_overrides` for exceptions
- backend entitlement guards for enforcement
- auth-context entitlement snapshots for frontend UX

For the first rollout:

- `PRO` => all AI entitlements disabled
- `ENTERPRISE` => all AI entitlements enabled

This is the smallest design that is still strong enough for future packaging changes.

---

## 14. Suggested First Implementation Slice

If we want the lowest-risk implementation path, start with exactly this slice:

1. Add new entitlement tables and seed `PRO` / `ENTERPRISE`
2. Add `TenantEntitlementService`
3. Gate these endpoints:
   - `POST /api/cve-detail/{cveId}/ai-solution`
   - `POST /api/cve-detail/{cveId}/ai-actions`
   - `POST /api/cve-detail/{cveId}/generate-fixes`
   - `POST /api/cve-detail/{cveId}/investigation-ai-summary`
   - `POST /api/cve-detail/{cveId}/investigation/run-agent`
   - `POST /api/upgrade-recommendation`
4. Expose `entitlements` in `/api/auth/context`
5. Disable AI buttons in the UI for Pro tenants with an `Enterprise only` message

That gives the product the requested plan distinction now, without painting us into a corner later.
