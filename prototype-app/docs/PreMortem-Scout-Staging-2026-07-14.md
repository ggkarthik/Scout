# Pre-Mortem Analysis: Scout Staging Deployment

## Decision

Do not apply the staging plan as written. Implement a corrected staging foundation before creating the Render backend service. The Vercel frontend can remain deployed, but the backend/database rollout should stay paused until the launch-blocking items below are closed.

## Tigers (Real Risks)

### Launch-blocking: HMAC staging authentication conflicts with the production safety profile

`application-preprod.yml` imports `application-prod.yml`, which requires an issuer URI or JWK Set URI. `JwtDecoderConfig` gives issuer/JWK configuration precedence over the HMAC key. Consequently, supplying an issuer merely to satisfy startup causes locally issued HS256 login tokens to be validated by the external issuer decoder and rejected.

Mitigation: introduce an explicit staging authentication mode that permits a strong HMAC key only in `preprod`, while keeping OIDC mandatory in `prod`. Test startup, local token issuance, token validation, expiry, and rejection after key rotation.

### Launch-blocking: the first platform-owner login has no supported bootstrap path

Platform-owner bootstrap creates an identity and role but does not create, return, or deliver a password-setup token. Issuing a setup token currently requires an already authenticated administrative workflow, creating a bootstrap deadlock on a fresh database.

Mitigation: add a one-time, auditable bootstrap setup-token flow delivered to the configured owner email, or create a deployment-only CLI that issues the token. Never log the raw token. Disable bootstrap after the first successful setup.

### Launch-blocking: Render's default database owner cannot be the application runtime role

Both `prod` and `preprod` execute the P0 database-role and RLS validator. Render's generated database user owns the migrated objects and has DDL capability, so the service must fail readiness if it uses the plan's direct database credentials.

Mitigation: use the generated database owner only for the one-off migrator. Create a separate non-owner runtime login with DML and sequence usage only, run tenant migration 42, verify RLS, then configure the web service with the runtime credentials.

### Launch-blocking: the proposed Render build and database URL wiring do not match the repository

The repository already provides a multi-stage Java Dockerfile, while Render does not provide a native Java runtime in the Blueprint runtime set used by this project. Additionally, Render connection strings are not a safe direct substitute for the JDBC URL expected by Spring.

Mitigation: retain the Docker-based Render service and use `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`, and `DB_PASSWORD`, as implemented in the validated Blueprint.

### Launch-blocking: internet-facing credential login has no login throttling

The code contains ingestion rate limiting but no protection against repeated `/api/auth/login` attempts. Putting credential login on a public staging hostname creates a straightforward password-guessing surface.

Mitigation: add application-level login throttling keyed by normalized account and trusted client IP, generic failure responses, audit events, and temporary lockouts. Add a Cloudflare rate-limit rule as defense in depth, not as the only control.

### Fast-follow: Cloudflare proxying is enabled too early

The plan enables proxying immediately. Third-party domain and certificate verification commonly requires DNS-only CNAMEs. Render explicitly instructs Cloudflare users to keep records DNS-only until certificate issuance succeeds, then optionally enable proxying.

Mitigation: add and verify custom domains with DNS-only records first. Enable Cloudflare proxying only after Vercel and Render both report valid domain configuration and certificates. Use Cloudflare SSL/TLS mode `Full (strict)` after origin certificates are valid.

### Fast-follow: the plan has no staging data lifecycle

The plan does not define whether staging contains synthetic, anonymized, or copied production data, nor retention, reset, or backup expectations.

Mitigation: prohibit raw production data by default, document approved datasets, define reset cadence, and test restore before staging is used for migration rehearsals.

## Paper Tigers (Overblown Concerns)

### A Cloudflare Worker is required for API routing

It is not required for this topology. Direct browser calls from the Vercel hostname to the Render API are reasonable when CORS and forwarded headers are configured correctly.

### Staging must use external OIDC

External OIDC is preferable for production, but strong HMAC-backed credential login is acceptable for a controlled demo environment if it is explicitly isolated to `preprod`, rate-limited, short-lived, and fully tested.

### Vercel and Render must share one hostname

Separate `app` and `api` hostnames are operationally clear and avoid unnecessary routing complexity.

## Elephants (Unspoken Worries)

### The public domain is still unspecified

Custom-domain, CORS, DNS, and certificate work cannot be completed until the exact Cloudflare zone is selected and ownership is confirmed.

### Free-tier capacity may not support migration rehearsal

Free plans are suitable for an initial demo but may sleep, have limited database capacity, and behave differently from production. Measure cold start, migration duration, connection usage, and representative dataset size before treating staging as a production rehearsal environment.

### Resend has no verified sender domain

The connected Resend account currently has no verified domains. `onboarding@resend.dev` is suitable only for limited testing, not representative staging email delivery.

## Action Plans for Launch-Blocking Tigers

| Risk | Required action | Owner | Completion gate |
|---|---|---|---|
| Auth-mode conflict | Add explicit preprod HMAC mode and automated token tests | Backend/security | Before Render backend creation |
| Bootstrap deadlock | Implement one-time setup-token delivery or deployment CLI | Backend/security | Before first staging login |
| Unsafe DB role | Provision migration/runtime roles and run RLS verification | Platform/DBA | Before backend readiness can pass |
| Render wiring mismatch | Keep validated Docker Blueprint and component DB variables | Platform | Before Blueprint apply |
| Login brute force | Add login throttling, lockout, and audit tests | Backend/security | Before exposing `api` publicly |

## Recommended Sequence

1. Keep the existing Vercel deployment; do not attach the public staging domain yet.
2. Implement and test the five launch-blocking controls.
3. Update the Render Blueprint to use `preprod`, the one-off migration role, and the restricted runtime role.
4. Apply the Blueprint and validate the Render-generated hostname before adding Cloudflare.
5. Add Vercel and Render custom domains using DNS-only records.
6. Wait for both providers to verify domains and issue certificates.
7. Enable Cloudflare proxying and `Full (strict)` TLS, then run the complete smoke test.
