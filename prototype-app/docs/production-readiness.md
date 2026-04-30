# VulnWatch Production Readiness

Last updated: 2026-04-29

## Direction

VulnWatch is moving toward an AWS-hosted managed SaaS delivered first as a production-grade modular monolith. The backend remains one deployable Spring Boot service for v1, with explicit module boundaries and job semantics that can later move to workers or services.

## Tenant And Identity Baseline

The production foundation now includes:

- tenant lifecycle metadata: `slug`, `status`, `plan_code`, billing reference, suspension, deletion, and update timestamps
- first-class `app_users`
- `tenant_memberships` with role and status
- `service_accounts` with tenant scope and role
- immutable `audit_events` for platform and tenant administration actions
- tenant plan quotas for connector count, service account count, daily SBOM uploads, daily exposure refreshes, and export rows

The first supported roles are represented as Spring authorities:

- `PLATFORM_OWNER`
- `TENANT_ADMIN`
- `SECURITY_ANALYST`
- `INVENTORY_ADMIN`
- `OPERATOR`
- `CREATOR` for legacy privileged local flows

Local development still supports API-key authentication. The backend also accepts bearer JWTs when one of these decoder settings is configured:

- `APP_JWT_ISSUER_URI`
- `APP_JWT_JWK_SET_URI`
- `APP_JWT_HMAC_SECRET`

JWT authentication upserts `app_users`, resolves the selected tenant from `tenant_id`, `tenant_slug`, or the first active membership, and maps tenant membership roles into Spring authorities. Platform-only tokens can carry `PLATFORM_OWNER` in the configured roles claim.

Production startup can be hardened by setting:

```bash
APP_REQUIRE_PRODUCTION_SECRETS=true
APP_API_KEY=<strong non-default value>
APP_CREATOR_KEY=<strong non-default value>
APP_ALLOW_HEADER_TENANT_SELECTION=false
APP_REQUIRE_TENANT_CONTEXT=true
APP_CREDENTIAL_ENCRYPTION_KEY=<base64 32-byte key>
APP_CORS_ALLOWED_ORIGINS=https://<customer-app-host>
```

`APP_ALLOW_HEADER_TENANT_SELECTION=true` is a local compatibility setting only. In production, tenant selection must come from authenticated identity claims or service-account resolution, not trusted client headers.

`APP_REQUIRE_TENANT_CONTEXT=true` makes the tenant-aware datasource set a sentinel tenant ID when no tenant is resolved. Tenant-scoped RLS policies then match no tenant rows instead of falling through to cross-tenant visibility. Platform jobs that intentionally need cross-tenant access should use a separate platform datasource or job role.

Useful JWT claim settings:

```bash
APP_JWT_TENANT_ID_CLAIM=tenant_id
APP_JWT_TENANT_SLUG_CLAIM=tenant_slug
APP_JWT_EMAIL_CLAIM=email
APP_JWT_NAME_CLAIM=name
APP_JWT_ROLES_CLAIM=roles
```

## New Administration APIs

- `GET /api/tenants`
- `POST /api/platform/tenants`
- `PATCH /api/platform/tenants/{tenantId}/status`
- `GET /api/tenants/{tenantId}/members`
- `POST /api/tenants/{tenantId}/members`
- `GET /api/service-accounts`
- `POST /api/service-accounts`
- `GET /api/audit-events`
- `GET /api/audit-events/export`
- `GET /api/audit-events/support-bundle`

Platform tenant creation and lifecycle changes require `ROLE_PLATFORM_OWNER`. Tenant member, service-account, and audit reads require `ROLE_PLATFORM_OWNER` or `ROLE_TENANT_ADMIN`.

Suspended or deleted tenants are blocked from normal tenant API requests with `TENANT_SUSPENDED`; platform routes and auth context remain available so platform owners can restore or inspect the tenant.

Audit events are emitted for tenant create/status/member changes, service account creation, finding workflow updates, ServiceNow CMDB connector save/test/sync, support bundle export, audit export, and manual central vulnerability feed sync/advisory triggers.

Tenant quota enforcement has started with service accounts, customer-owned connector records, customer-triggered exposure refreshes, and audit/support export rows. Exposure refresh quotas are counted from tenant audit events over the previous 24 hours. Quota failures return `429` with `code=QUOTA_EXCEEDED` and a stable `quotaCode`.

Connector credential values are encrypted before persistence using AES-256-GCM through `CredentialEncryptionService`. API responses continue to expose only whether a secret exists, never the secret value. Legacy plaintext values are still readable at runtime so existing local data can be migrated by rewriting connector settings.

Backend API responses now emit hardened browser/security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`, and `Permissions-Policy`. Production startup rejects wildcard CORS origins.

## Central Vulnerability Repository Boundary

Canonical vulnerability intelligence remains global: NVD, KEV, GHSA, CSAF/VEX, EPSS, EOL, advisories, and archives are platform-owned. Customer operations should configure inventory, source filters, tenant policy, and tenant-scoped exposure refreshes. Customer-triggered refresh should recompute exposure from current central data; it should not mutate canonical feed data.

The API now reflects that split:

- central feed mutation endpoints under `/api/ingestion/*` require `ROLE_PLATFORM_OWNER`
- tenant exposure refresh is available at `/api/vulnerability-intelligence/org-cves/refresh` and `/api/vuln-repo/org-cves/refresh`
- org-CVE recompute endpoints are retained as platform-owner repair/backfill controls
- tenant exposure refresh audit events include endpoint, central-repository source, refresh status, recompute scope, active component count, exposure rows, changed rows, and open finding counts

## AWS Deployment Baseline

Initial AWS shape:

- backend container on ECS Fargate
- frontend static container or S3/CloudFront distribution
- RDS PostgreSQL with encryption, backups, PITR, and private networking
- S3 for archives and exports
- Secrets Manager/KMS for connector secrets, API keys, and signing secrets
- CloudWatch logs, metrics, and alarms
- SQS/EventBridge later for externalized ingestion/projection workers

Container entrypoints were added in:

- `backend/Dockerfile`
- `frontend/Dockerfile`
- `frontend/nginx.conf`

The first AWS deployment contract now lives in `infra/aws/terraform`. It provisions ECS Fargate services, an ALB, RDS PostgreSQL, an encrypted S3 archive bucket, KMS, Secrets Manager, CloudWatch log groups, and task IAM roles. The backend production profile is `application-prod.yml`; it enables readiness/liveness probes, disables header-based tenant selection, requires production secrets, and uses S3 archive storage.

The vulnerability archive backend now supports S3 through AWS SDK v2. Production startup requires `ARCHIVE_STORAGE_BACKEND=s3` and `ARCHIVE_S3_BUCKET`; credentials should come from the ECS task role. The service stores canonical archive keys such as `descriptions/CVE-2024-1234.txt` and `raw-payloads/CVE-2024-1234.json`, with local path traversal checks retained for filesystem development mode.

Deployment operators should use `docs/runbooks/aws-deployment.md` and `scripts/smoke-test.sh` for the first smoke gate after ECS service stabilization.

The live production backlog and pre-prod checklist are tracked in `docs/production-backlog.md`.

## Operations Observability Baseline

API requests now receive an `X-Request-ID` response header. If a safe `X-Request-ID` is supplied by a caller or load balancer, VulnWatch echoes it; otherwise the backend generates a UUID.

The backend populates MDC fields used by the production log pattern:

- `requestId`
- `tenantId`
- `actorId`
- `actorRoles`
- `httpMethod`
- `httpPath`

Audit events also persist `requestId`, allowing support and incident review to connect tenant-visible administrative actions with backend logs.

## Required Next Hardening

- Complete the pre-prod multi-tenant isolation checklist in `docs/production-backlog.md` before the first customer pilot.
- Replace API-key mode in production with verified OIDC/JWT validation and membership-derived tenant context.
- Replace remaining default-workspace-only connector paths with request-derived tenant context.
- Extend audit coverage to investigations, suppressions, and remaining connector edits.
- Move production credential encryption keys into KMS/Secrets Manager envelope encryption and add rotation workflow.
- Extend quota enforcement to daily SBOM uploads, queued jobs, storage, and API rate limits.
- Add OpenTelemetry trace/span export, CloudWatch dashboards, and alert routing for the request correlation fields.
- Add Terraform remote state, ECR repositories, image scanning, SBOM generation, image signing, and production promotion workflow.
- Add migration validation against an ephemeral PostgreSQL service and smoke tests against deployed preview environments.
