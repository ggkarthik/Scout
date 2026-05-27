# Non-Production Test Personas

This feature is a Phase 1 multitenancy validation tool. It is intended for local and preprod environments only, and it must not be used as production support access or customer impersonation.

## Enablement

Backend:

- `APP_TEST_PERSONAS_ENABLED=true`
- `APP_JWT_HMAC_SECRET=<shared non-production HMAC secret>`
- For production-like preprod validation, keep `APP_ALLOW_API_KEY_AUTH=false`, `APP_ALLOW_HEADER_TENANT_SELECTION=false`, and `APP_REQUIRE_TENANT_CONTEXT=true`.

Frontend:

- `VITE_ENABLE_TEST_PERSONAS=true`

Production safety:

- Startup fails when `APP_TEST_PERSONAS_ENABLED=true` and `app.security.require-production-secrets=true`.
- Do not enable this feature in production.

## Personas

The gear menu exposes `Impersonate User` when frontend test personas are enabled.

| Persona Key | Role | Tenant | Purpose |
|---|---|---|---|
| `platform-owner` | `PLATFORM_OWNER` | none (cross-tenant) | Platform console, demo request approval, tenant administration |
| `customer-a-admin` | `TENANT_ADMIN` | `customer-a` | Full tenant admin actions for Tenant A |
| `customer-b-admin` | `TENANT_ADMIN` | `customer-b` | Full tenant admin actions for Tenant B |
| `customer-a-inventory-admin` | `INVENTORY_ADMIN` | `customer-a` | Connector settings; no tenant admin or risk policy controls |
| `customer-a-analyst` | `SECURITY_ANALYST` | `customer-a` | Investigation workflows; no connector/admin/platform operations |
| `customer-a-auditor` | `READ_ONLY_AUDITOR` | `customer-a` | Read-only audit access |

Backend-backed mode requests `POST /api/dev/test-personas/{personaKey}/token`, stores the returned short-lived JWT in the existing frontend auth-token storage, and refetches `GET /api/me`.

UI preview mode only overrides the frontend actor context. It does not change API authorization and always shows a warning banner.

## Token Issuance

`TestPersonaController` (`GET /api/dev/test-personas`, `POST /api/dev/test-personas/{personaKey}/token`) is only registered when `app.test-personas.enabled=true`. The endpoint is permitted without authentication in `SecurityConfig`.

Tokens are HS256 JWTs signed with `APP_JWT_HMAC_SECRET`. They carry the persona's `roles` claim and, where applicable, a `tenant_id` claim. The `TestPersonaService` holds the hardcoded persona definitions; adding a new persona requires editing that service and restarting the backend.

## Manual Phase 1 Checks

1. Select Tenant A Admin and verify Tenant A navigation and actions are available.
2. Search for deterministic Tenant B records such as `b-host-001`; they must not appear in Tenant A views.
3. Select Tenant B Admin and verify Tenant A records such as `a-host-001` do not appear.
4. Select Platform Owner and verify Platform Console is visible.
5. Select Inventory Admin and verify connector settings are accessible, while tenant administration and risk policy controls are blocked.
6. Select Security Analyst and verify investigation workflows are accessible, while connector, admin, and platform operations are blocked.
7. Use `Reset to real user` after testing.

## Local Auth

`LocalAuthController` (`POST /api/auth/login`, `POST /api/auth/setup-password`) provides credential-based login for local and validation-tier environments. It is gated by the presence of `APP_PLATFORM_OWNER_EMAIL` and `APP_PLATFORM_OWNER_PASSWORD_HASH` in config.

- Platform owner login: email + password verified against the bcrypt hash stored in config/Secrets Manager.
- Tenant admin login: email + password verified against `app_users.password_hash` (set during invite acceptance).
- Password setup: accepts a one-time `setupToken` returned from invite acceptance, sets a bcrypt-hashed password on the `AppUser`, and issues a tenant-scoped JWT.

## Support Grant Access

`TenantSupportGrantController` (`POST /api/platform/support-grants`, `DELETE /api/platform/support-grants/{tenantId}`) allows a platform owner to grant temporary read access to a tenant's data for support purposes. Grants are stored in `tenant_support_grants` and are checked by `TenantResolutionFilter` when a `PLATFORM_OWNER` actor accesses a tenant-scoped endpoint.
