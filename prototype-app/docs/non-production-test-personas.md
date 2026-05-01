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

- Platform Owner: `PLATFORM_OWNER`, no tenant.
- Tenant A Admin: `TENANT_ADMIN`, `customer-a`.
- Tenant B Admin: `TENANT_ADMIN`, `customer-b`.
- Tenant A Inventory Admin: `INVENTORY_ADMIN`, `customer-a`.
- Tenant A Security Analyst: `SECURITY_ANALYST`, `customer-a`.
- Tenant A Auditor: `READ_ONLY_AUDITOR`, `customer-a`.

Backend-backed mode requests `/api/dev/test-personas/{personaKey}/token`, stores the returned short-lived JWT in the existing frontend auth-token storage, and refetches `/api/me`.

UI preview mode only overrides the frontend actor context. It does not change API authorization and always shows a warning.

## Manual Phase 1 Checks

1. Select Tenant A Admin and verify Tenant A navigation/actions are available.
2. Search for deterministic Tenant B records such as `b-host-001`; they must not appear in Tenant A views.
3. Select Tenant B Admin and verify Tenant A records such as `a-host-001` do not appear.
4. Select Platform Owner and verify Platform Console is visible.
5. Select Inventory Admin and verify connector settings are available, while tenant administration and risk policy controls are blocked.
6. Select Security Analyst and verify investigation workflows are available, while connector/admin/platform operations are blocked.
7. Use `Reset to real user` after testing.
