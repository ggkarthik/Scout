# AWS Deployment Runbook

## Preflight

- Build and scan backend and frontend images.
- Complete the pre-prod multi-tenant isolation checklist in `docs/production-backlog.md`; Customer A must not be able to read, write, export, refresh, or infer Customer B data.
- Confirm `SPRING_PROFILES_ACTIVE=prod`.
- Confirm `APP_REQUIRE_PRODUCTION_SECRETS=true`.
- Confirm `APP_ALLOW_HEADER_TENANT_SELECTION=false`.
- Confirm JWT issuer/JWK settings point to the production identity provider.
- Confirm `APP_CORS_ALLOWED_ORIGINS` contains only explicit customer-facing HTTPS origins; do not use `*`.
- Confirm Secrets Manager values are not placeholders.
- Confirm `APP_CREDENTIAL_ENCRYPTION_KEY` is a non-default base64-encoded 32-byte key.
- Confirm `ARCHIVE_STORAGE_BACKEND=s3`, `ARCHIVE_S3_BUCKET` points to the Terraform-managed archive bucket, and the ECS task role can `s3:GetObject`/`s3:PutObject` on it.
- Confirm RDS backup retention, deletion protection, and encryption are enabled.
- Confirm archive S3 bucket has public access blocked and KMS encryption enabled.

## Deploy

1. Push immutable backend and frontend image tags.
2. Run `terraform plan` and review ALB, ECS, RDS, S3, IAM, and secret changes.
3. Apply infrastructure changes.
4. Wait for both ECS services to become stable.
5. Run `BASE_URL=https://<app-host> ./scripts/smoke-test.sh`.
6. Check CloudWatch logs for startup validation, Flyway migration, and readiness status.

## Rollback

- For application-only failures, redeploy the previous image tag.
- For failed migrations, stop rollout and restore from RDS point-in-time recovery only after confirming data-loss impact.
- For bad central vulnerability feed data, quarantine or repair the feed data before rerunning tenant exposure refresh.

## Post-Deploy Checks

- `/actuator/health/readiness` returns `UP`.
- API responses include `X-Request-ID`; the same value appears in backend logs as `requestId`.
- API responses include hardened headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`, and `Permissions-Policy`.
- Vulnerability archive writes and reads use S3; failed archive access should appear as backend log errors with the archive key.
- Login succeeds through OIDC/JWT.
- Tenant selection resolves from authenticated membership.
- Platform owner can view central feed health.
- Tenant admin can trigger exposure refresh without mutating central CVE data.
- Audit events are recorded for administrative actions.
- Suspended tenants are blocked from tenant APIs, while platform tenant status routes remain available.
- Tenant admins can download an audit CSV and support bundle without secrets.
