# AWS Deployment Runbook

## Preflight

- Build and scan the backend image.
- Build the frontend static assets with `npm run build`.
- Confirm `SPRING_PROFILES_ACTIVE=prod`.
- Confirm `APP_REQUIRE_PRODUCTION_SECRETS=true`.
- Confirm `APP_ALLOW_HEADER_TENANT_SELECTION=false`.
- Confirm JWT issuer/JWK settings point to the production identity provider.
- Confirm `APP_CORS_ALLOWED_ORIGINS` contains only explicit customer-facing HTTPS origins; do not use `*`.
- Confirm Secrets Manager values are not placeholders.
- Confirm `APP_CREDENTIAL_ENCRYPTION_KEY` is a non-default base64-encoded 32-byte key.
- Confirm `ARCHIVE_STORAGE_BACKEND=s3`, `ARCHIVE_S3_BUCKET` points to the Terraform-managed archive bucket, and the ECS task role can `s3:GetObject`/`s3:PutObject` on it.
- Confirm customer-validation deployments keep backend `desired_count=1` until scheduled-job locking or worker separation exists.
- Confirm RDS backup retention, deletion protection, and encryption are enabled.
- Confirm archive S3 bucket has public access blocked and KMS encryption enabled.

## Deploy

1. Push an immutable backend image tag.
2. Run `terraform plan` and review ALB, ECS, RDS, S3, CloudFront, IAM, and secret changes.
3. Apply infrastructure changes.
4. Wait for the backend ECS service to become stable.
5. Run `BASE_URL=https://<app-host> ./scripts/smoke-test.sh`.
6. Upload frontend build assets to the Terraform-managed frontend bucket and invalidate CloudFront.
7. If the frontend is hosted on Vercel instead of CloudFront, use `prototype-app/frontend` as the authoritative Vercel project root.
8. In Vercel, set preview or production environment variables:
   - `VITE_API_BASE=https://<api-host>/api`
   - `VITE_SENTRY_DSN=<optional>`
   - `VITE_SHOW_TOKEN_LOGIN=false`
9. Keep the SPA rewrite policy so `/login`, `/demo/*`, and `/invite/*` resolve to `index.html`.
10. Do a preview-first Vercel rollout before promoting to production:
    - deploy preview from the existing Vercel project
    - verify `/`, `/login`, `/demo`, `/demo/request`, and `/demo/expired`
    - submit a public demo request against the hosted backend
    - verify platform-owner login and authenticated tenant navigation
11. If the final Vercel hostname becomes the user-facing frontend URL, update Railway backend `APP_BASE_URL` and `APP_CORS_ALLOWED_ORIGINS` before validating invite and login emails.
12. Treat repo-root `vercel.json` and `prototype-app/vercel.json` as compatibility wrappers only while the existing Vercel project is still bound above `prototype-app/frontend`; the target state is a Vercel project rooted directly at `prototype-app/frontend`.
13. Check CloudWatch logs for startup validation, Flyway migration, and readiness status.

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
- Public demo request submission succeeds with `DEMO_SMOKE=1 BASE_URL=https://<api-host> ./scripts/smoke-test.sh`.
- Platform owner can approve a demo request, resend the invite, and see the demo tenant expiration date.
- Demo tenants can use limited SBOM ingestion but receive stable demo errors for live connector setup.
- Vercel deep links for `/login`, `/demo/request`, `/demo/expired`, and `/invite/<token>` return the SPA instead of a 404.
- Preview frontend requests hit the hosted backend at `VITE_API_BASE` and do not rely on `VITE_API_KEY`, `VITE_CREATOR_KEY`, or `VITE_AUTH_TOKEN`.
- If production moved to a new Vercel hostname or custom domain, invite and login emails resolve to the correct frontend origin after backend `APP_BASE_URL` is updated.
