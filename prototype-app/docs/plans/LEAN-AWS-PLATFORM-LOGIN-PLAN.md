# Lean AWS Cost-Control + Platform Owner Login — Implementation Plan

**Author:** Principal Architect Review
**Date:** 2026-05-03 (v2 — revised auth model, no SES)
**Status:** Ready for Implementation
**Estimated effort:** ~4 engineering days across 5 phases

---

## 1. Problem Statement

Three gaps block a clean customer-validation deployment:

1. **Infrastructure cost and security.** The current Terraform provisions ECS tasks in private subnets (requiring a NAT Gateway for egress — ~$32/mo waste in a single-task validation environment), exposes the frontend S3 bucket as public-read, and defines zero budget or operational alarms.

2. **Platform owner access.** Internal platform owners have no legitimate hosted login path. They must use dev-only token entry (`VITE_SHOW_TOKEN_LOGIN`) or the customer IdP flow and manually navigate. Neither is acceptable for validation.

3. **Tenant admin onboarding.** After a platform owner approves a demo request, the tenant admin needs a clear way to log in. The invite link is already generated and shown in the platform console, but the login page has no credential-based path for returning tenant admins.

---

## 2. Architecture Decisions

### AD-1: Public-subnet ECS with ALB-only ingress (no NAT Gateway)

Move ECS tasks to `public_subnet_ids` with `assign_public_ip = true`. Inbound access remains restricted to the ALB security group on port 8080 — no direct internet-to-task traffic. This eliminates the NAT Gateway while preserving the same security posture at the network layer.

**Trade-off:** Tasks get public IPs, which is cosmetically less clean than private networking. Acceptable for a validation tier. When paying customers or compliance requirements arrive, add NAT Gateway or VPC endpoints in a hardening pass.

**RDS stays in private subnets.** No change — the DB security group already allows only port 5432 from the ECS security group.

### AD-2: CloudFront Origin Access Control replaces public-read S3

Switch the frontend bucket from public-read + website hosting to private bucket + CloudFront OAC. This removes the direct S3 URL attack surface. CloudFront already handles SPA routing via custom error responses (403/404 → /index.html).

**Impact:** The CloudFront origin type changes from `custom` (S3 website endpoint) to `s3` (S3 REST API). The bucket policy changes from `Principal: "*"` to `Principal: cloudfront.amazonaws.com` with a condition on the OAC ID.

### AD-3: Self-contained credential login — no external IdP required for validation

The validation environment uses a single `/login` page with a username/password form that serves both roles:

- **Platform Owner** — logs in with a deployment-time credential stored in AWS Secrets Manager. Set once during `terraform apply`. The backend validates against a bcrypt hash. This replaces any hardcoded credential approach — hardcoded credentials are unacceptable for a security product shown to prospects.

- **Tenant Admin** — logs in with the email from their demo request + a password set during invite acceptance. When the platform owner approves a demo request, the existing invite flow generates a link shown in the platform console. The platform owner copies and shares it manually. The tenant admin clicks the invite link, accepts, and sets their password on a new password-setup step. On subsequent visits, they use the same login form with email + password.

**Why no external IdP for validation:** Eliminates IdP setup as a deployment dependency. The existing `VITE_IDP_LOGIN_URL` flow remains in the codebase for future production use — it's just not the primary path for the validation tier.

**Why no SES:** With single-digit prospects in validation, the platform owner already has a direct relationship with each one. Manual invite link sharing (copy from platform console, send via email/Slack) fits this motion. Add SES when prospect volume justifies it.

### AD-4: Consolidate dev-mode env vars — one gate, not two

Current state has two overlapping dev gates:
- `VITE_SHOW_TOKEN_LOGIN` — shows raw token input on `/login`
- `VITE_ENABLE_TEST_PERSONAS` — shows persona picker in the app header

Consolidate on `VITE_ENABLE_TEST_PERSONAS`. When true, the login page shows a "Use test persona" section. The raw token input field is removed.

### AD-5: Keep current retention and instance defaults

| Setting | This plan | Rationale |
|---------|-----------|-----------|
| RDS instance | `db.t4g.small` (keep) | 1 GiB RAM risks OOM under SBOM ingestion. $3/mo difference. |
| RDS backup retention | 14 days (keep) | Customer might report demo issue 10 days later. Pennies of storage. |
| CloudWatch log retention | 30 days (keep) | Single-task log volume is trivial. |
| RDS storage | 20 GiB | No change needed. |

---

## 3. Auth Flow Details

### 3a. Platform Owner Login

```
Platform Owner → /login → enters email + password
  → POST /api/auth/login { email, password }
  → Backend compares password against bcrypt hash from Secrets Manager
  → Backend issues HS256 JWT with:
       sub: "platform-owner"
       roles: ["PLATFORM_OWNER"]
       tenant_id: null (cross-tenant)
  → Frontend stores JWT in localStorage
  → Navigate to /platform/demo-requests
```

- **Email:** configured via `APP_PLATFORM_OWNER_EMAIL` env var
- **Password hash:** stored in Secrets Manager as `PLATFORM_OWNER_PASSWORD_HASH` (bcrypt, cost factor 10)
- Generate hash: `htpasswd -nbBC 10 "" 'chosen-password' | cut -d: -f2`

### 3b. Tenant Admin Login — First Visit (Invite Acceptance)

```
Platform Owner approves demo request
  → Backend creates invite token (DemoLifecycleService)
  → Platform console shows invite link (already works)
  → Platform Owner copies link, sends to prospect manually

Tenant Admin clicks invite link → /invite/:token
  → Existing invite validation page shows workspace, email, expiry
  → Tenant Admin clicks "Accept invite"
  → POST /api/demo-invites/{token}/accept
  → Response includes a one-time setupToken
  → Frontend redirects to /login?setup=<setupToken>
  → Login page shows "Set your password" form
  → POST /api/auth/setup-password { setupToken, password }
  → Backend validates setup token, hashes password, stores on AppUser
  → Backend issues JWT with TENANT_ADMIN role + tenant context
  → Frontend stores JWT, navigates to /
```

### 3c. Tenant Admin Login — Return Visit

```
Tenant Admin → /login → enters email + password
  → POST /api/auth/login { email, password }
  → Backend looks up AppUser by email, verifies bcrypt password
  → Backend issues JWT with user's roles + tenant context
  → Frontend stores JWT, navigates to /
```

### 3d. Dev / Local Login

```
Developer → /login → clicks "Use Platform Owner test persona"
  → POST /api/dev/test-personas/platform-owner/token
  → Frontend stores JWT, navigates to /platform/demo-requests
```

Only visible when `VITE_ENABLE_TEST_PERSONAS=true`.

---

## 4. Implementation Phases

### Phase 1: Terraform — Networking and S3/CloudFront Hardening

**Goal:** ECS in public subnets, private S3 frontend with OAC, no NAT Gateway dependency.

#### 1a. ECS service moves to public subnets

`infra/aws/terraform/main.tf` — `aws_ecs_service.backend`:

```hcl
network_configuration {
  subnets          = var.public_subnet_ids
  security_groups  = [aws_security_group.ecs.id]
  assign_public_ip = true
}
```

#### 1b. S3 frontend: private bucket + CloudFront OAC

Remove `website` block, set all public access block to `true`, remove `Principal: "*"` bucket policy.

Add:
```hcl
resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "${local.name}-frontend-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}
```

Update CloudFront distribution to use S3 REST API origin with OAC. Replace bucket policy:
```hcl
resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudFrontOAC"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.frontend.arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.frontend.arn
        }
      }
    }]
  })
}
```

### Phase 2: Terraform — Budget, Alarms, and Platform Owner Credential

**Goal:** Cost visibility, operational alerting, and deploy-time platform owner credential.

New variables: `budget_alert_email`, `monthly_budget_limit_usd` (default 100), `platform_owner_email`, `platform_owner_password_hash` (sensitive).

Add to Secrets Manager secret: `PLATFORM_OWNER_EMAIL`, `PLATFORM_OWNER_PASSWORD_HASH`.

Add SNS topic + email subscription, AWS Budget with 50%/80%/100% notifications, and 6 CloudWatch alarms:
- ALB unhealthy targets
- ALB 5xx count > 10 in 5 minutes
- ECS CPU > 80%
- ECS memory > 80%
- RDS CPU > 80%
- RDS free storage < 2 GiB

### Phase 3: Backend — Login Endpoint and Password Setup

**Goal:** Add `POST /api/auth/login` and `POST /api/auth/setup-password` endpoints.

New files:
- `AuthLoginController.java` — `POST /api/auth/login`, `POST /api/auth/setup-password`
- `AuthLoginService.java` — bcrypt verification, JWT issuance via existing HMAC signing pattern

Database migration:
```sql
ALTER TABLE app_users ADD COLUMN password_hash VARCHAR(255);
ALTER TABLE app_users ADD COLUMN password_set_at TIMESTAMPTZ;
ALTER TABLE demo_invites ADD COLUMN setup_token VARCHAR(255);
ALTER TABLE demo_invites ADD COLUMN setup_token_used_at TIMESTAMPTZ;
```

`SecurityConfig` additions to permit list:
```java
.requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
.requestMatchers(HttpMethod.POST, "/api/auth/setup-password").permitAll()
```

`ApiKeyAuthenticationFilter.shouldNotFilter()` must skip `/api/auth/**` POST requests.

`DemoLifecycleService.acceptInvite()` generates a `setupToken` and includes it in `DemoInviteValidationResponse`.

### Phase 4: Frontend — Login Page Redesign

**Goal:** Unified credential login form, invite-based password setup, dev persona support.

Changes:
- Remove `VITE_SHOW_TOKEN_LOGIN` raw token input from `DemoPublicPages.tsx`
- Add `login()` and `setupPassword()` API functions to `src/api/client.ts`
- Replace `LoginPage` with unified email/password form
- Add `PasswordSetupForm` component (rendered when `?setup=` param present)
- Update invite acceptance to redirect to `/login?setup=<setupToken>` on success
- Add `frontend/.env.example`

### Phase 5: Tests

Backend IT (`AuthLoginControllerPostgresIntegrationTest`):
- Platform owner login: correct password → 200 + JWT with PLATFORM_OWNER role
- Platform owner login: wrong password → 401
- Tenant admin login after password setup → 200 + JWT with TENANT_ADMIN + correct tenant
- Tenant admin login before setup → 401
- Setup password with valid token → 200 + JWT
- Setup password with already-used token → 400/409
- Setup password with expired invite → 400
- Login does not leak user existence (same error for missing user and wrong password)

Frontend tests (`LoginPage.test.tsx`): render form, successful login, platform owner navigation, tenant admin navigation, wrong credentials error, test persona button visibility, setup form render, password mismatch error, successful setup.

---

## 5. What This Plan Does NOT Do (Deferred)

| Item | Trigger to revisit |
|------|--------------------|
| SES email delivery for invite links | Prospect volume > 10/month |
| External IdP integration (Cognito, Okta) | Enterprise customer requires SSO |
| NAT Gateway / VPC endpoints for ECS | Compliance audit requires private networking |
| Multi-AZ RDS | First paying customer or SLA commitment |
| Autoscaling ECS | Worker separation + distributed scheduler locks implemented |
| Custom domain + ACM cert for CloudFront | Brand/trust requirements |
| Password reset flow | Tenant admin requests it |

---

## 6. File Change Summary

| File | Change |
|------|--------|
| `infra/aws/terraform/main.tf` | ECS → public subnets; S3 → private + OAC; SNS; budget; 6 alarms; platform owner credential |
| `infra/aws/terraform/variables.tf` | Add `budget_alert_email`, `monthly_budget_limit_usd`, `platform_owner_email`, `platform_owner_password_hash` |
| `infra/aws/terraform/outputs.tf` | Add `sns_alerts_topic_arn` |
| `backend/.../db/migration/postgres_reset/V<next>__app_user_password_hash.sql` | Add password fields to `app_users`, setup token fields to `demo_invites` |
| `backend/.../domain/AppUser.java` | Add `passwordHash`, `passwordSetAt` fields |
| `backend/.../domain/DemoInvite.java` | Add `setupToken`, `setupTokenUsedAt` fields |
| `backend/.../controller/AuthLoginController.java` | New — `POST /api/auth/login`, `POST /api/auth/setup-password` |
| `backend/.../service/AuthLoginService.java` | New — login verification, password setup, JWT issuance |
| `backend/.../service/DemoLifecycleService.java` | Generate `setupToken` on invite acceptance |
| `backend/.../dto/DemoInviteValidationResponse.java` | Add `setupToken` field |
| `backend/.../config/SecurityConfig.java` | Permit `/api/auth/login` and `/api/auth/setup-password` |
| `backend/.../config/ApiKeyAuthenticationFilter.java` | Skip filter for `/api/auth/**` POST |
| `backend/src/main/resources/application.yml` | Add `platform-owner-email`, `platform-owner-password-hash` config |
| `frontend/src/pages/DemoPublicPages.tsx` | Replace LoginPage; add PasswordSetupForm; update invite redirect |
| `frontend/src/api/client.ts` | Add `login()`, `setupPassword()` |
| `frontend/.env.example` | New — document available env vars |

---

## 7. Estimated Monthly Cost (Validation Environment)

| Resource | Estimated cost |
|----------|---------------|
| ECS Fargate (1 task, 0.5 vCPU, 1 GB) | ~$15 |
| ALB (low traffic) | ~$18 |
| RDS db.t4g.small (single-AZ, 20 GiB) | ~$16 |
| S3 (frontend + archives, minimal) | ~$1 |
| CloudFront (low traffic) | ~$1 |
| CloudWatch Logs (30 days, single task) | ~$1 |
| Secrets Manager (1 secret) | ~$0.40 |
| KMS (1 key) | ~$1 |
| NAT Gateway | **$0** (eliminated) |
| **Total** | **~$53/mo** |

---

## 8. Deployment Runbook (Quick Reference)

```bash
# 1. Generate platform owner password hash
PLATFORM_OWNER_PW="<choose-a-strong-password>"
HASH=$(htpasswd -nbBC 10 "" "$PLATFORM_OWNER_PW" | cut -d: -f2)

# 2. Deploy infrastructure
cd infra/aws/terraform
terraform apply \
  -var="budget_alert_email=you@company.com" \
  -var="platform_owner_email=admin@scout.ai" \
  -var="platform_owner_password_hash=$HASH" \
  -var="vpc_id=vpc-xxx" \
  -var="private_subnet_ids=[\"subnet-priv1\",\"subnet-priv2\"]" \
  -var="public_subnet_ids=[\"subnet-pub1\",\"subnet-pub2\"]" \
  -var="backend_image=<ecr-image-uri>" \
  -var="jwt_issuer_uri=unused" \
  -var="jwt_jwk_set_uri=unused" \
  -var="cors_allowed_origins=https://<cloudfront-domain>"

# 3. Confirm SNS email subscription (check inbox)

# 4. Update Secrets Manager with real values
aws secretsmanager put-secret-value \
  --secret-id vulnwatch-validation/backend \
  --secret-string '{
    "APP_API_KEY": "<strong-random>",
    "APP_CREATOR_KEY": "<strong-random>",
    "APP_CREDENTIAL_ENCRYPTION_KEY": "<base64-32-bytes>",
    "DB_PASSWORD": "<from-terraform-output>",
    "PLATFORM_OWNER_EMAIL": "admin@scout.ai",
    "PLATFORM_OWNER_PASSWORD_HASH": "<bcrypt-hash>",
    "APP_JWT_HMAC_SECRET": "<strong-random>"
  }'

# 5. Force new ECS deployment to pick up secret changes
aws ecs update-service --cluster vulnwatch-validation --service backend --force-new-deployment
```
