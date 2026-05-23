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

- **Platform Owner** — logs in with a deployment-time credential stored in AWS Secrets Manager. Set once during `terraform apply`. The backend validates against a bcrypt hash. This replaces the previous `admin/admin` proposal — hardcoded credentials are unacceptable for a security product shown to prospects.

- **Tenant Admin** — logs in with the email from their demo request + a password set during invite acceptance. When the platform owner approves a demo request, the existing invite flow generates a link shown in the platform console. The platform owner copies and shares it manually. The tenant admin clicks the invite link, accepts, and sets their password on a new password-setup step. On subsequent visits, they use the same login form with email + password.

**Why no external IdP for validation:** Eliminates IdP setup as a deployment dependency. The existing `VITE_IDP_LOGIN_URL` flow remains in the codebase for future production use — it's just not the primary path for the validation tier.

**Why no SES:** With single-digit prospects in validation, the platform owner already has a direct relationship with each one. Manual invite link sharing (copy from platform console, send via email/Slack) fits this motion. SES adds infrastructure complexity (verified domains, sender reputation, deliverability) with no proportional benefit at this scale. Add SES when prospect volume justifies it.

### AD-4: Consolidate dev-mode env vars — one gate, not two

Current state has two overlapping dev gates:
- `VITE_SHOW_TOKEN_LOGIN` — shows raw token input on `/login`
- `VITE_ENABLE_TEST_PERSONAS` — shows persona picker in the app header

These serve the same purpose (local dev auth without an IdP) and should be one flag. **Consolidate on `VITE_ENABLE_TEST_PERSONAS`.** When true, the login page shows a "Use test persona" section. The raw token input field is removed — test personas are a strictly better UX and don't require the user to manually obtain a token.

### AD-5: Keep current retention and instance defaults

The original plan proposed reducing several defaults to save money. The savings are negligible ($0–$3/mo) and the operational cost of shorter retention or smaller instances is real:

| Setting | Original plan | This plan | Rationale |
|---------|--------------|-----------|-----------|
| RDS instance | `db.t4g.micro` | **`db.t4g.small`** (keep) | 1 GiB RAM risks OOM under SBOM ingestion. $3/mo difference. |
| RDS backup retention | 7 days | **14 days** (keep) | Customer might report demo issue 10 days later. Pennies of storage. |
| CloudWatch log retention | 14 days | **30 days** (keep) | Same reasoning. Single-task log volume is trivial. |
| RDS storage | 20 GiB | 20 GiB | No change needed. |

---

## 3. Auth Flow Details

### 3a. Platform Owner Login Flow

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

The platform owner credential is a single account set at deploy time:
- **Email:** configured via `APP_PLATFORM_OWNER_EMAIL` env var (e.g., `admin@scout.ai`)
- **Password hash:** stored in Secrets Manager as `PLATFORM_OWNER_PASSWORD_HASH` (bcrypt)
- The deployer generates the hash offline (`htpasswd -nbBC 10 "" 'chosen-password' | cut -d: -f2`) and puts it in Secrets Manager alongside the existing secrets

### 3b. Tenant Admin Login Flow — First Visit (Invite Acceptance)

```
Platform Owner approves demo request
  → Backend creates invite token (existing logic in DemoLifecycleService)
  → Platform console shows invite link in the demo requests table (already works)
  → Platform Owner copies link, sends to prospect manually

Tenant Admin clicks invite link → /invite/:token
  → Existing invite validation page shows workspace, email, expiry
  → Tenant Admin clicks "Accept invite"
  → POST /api/demo-invites/{token}/accept
  → NEW: Response includes a one-time setup token
  → Frontend redirects to /login?setup=<setupToken>
  → Login page shows "Set your password" form
  → POST /api/auth/setup-password { setupToken, password }
  → Backend validates setup token, hashes password, stores on AppUser
  → Backend issues JWT with TENANT_ADMIN role + tenant context
  → Frontend stores JWT, navigates to /
```

### 3c. Tenant Admin Login Flow — Return Visit

```
Tenant Admin → /login → enters email + password
  → POST /api/auth/login { email, password }
  → Backend looks up AppUser by email, verifies bcrypt password
  → Backend issues JWT with user's roles + tenant context
  → Frontend stores JWT, navigates to /
```

### 3d. Dev / Local Login Flow

```
Developer → /login → clicks "Use Platform Owner test persona"
  → POST /api/dev/test-personas/platform-owner/token (existing endpoint)
  → Frontend stores JWT, navigates to /platform/demo-requests
```

Only visible when `VITE_ENABLE_TEST_PERSONAS=true`. Same mechanism as the existing test persona picker in the app header — just surfaced on the login page for convenience.

---

## 4. Implementation Phases

### Phase 1: Terraform — Networking and S3/CloudFront Hardening

**Goal:** ECS in public subnets, private S3 frontend with OAC, no NAT Gateway dependency.

#### 1a. ECS service moves to public subnets

**File:** `infra/aws/terraform/main.tf` — `aws_ecs_service.backend`

```hcl
# BEFORE
network_configuration {
  subnets          = var.private_subnet_ids
  security_groups  = [aws_security_group.ecs.id]
  assign_public_ip = false
}

# AFTER
network_configuration {
  subnets          = var.public_subnet_ids
  security_groups  = [aws_security_group.ecs.id]
  assign_public_ip = true
}
```

No security group changes. ECS ingress is already locked to the ALB SG on port 8080. Egress is already `0.0.0.0/0` (needed for ECR image pull and Secrets Manager).

#### 1b. S3 frontend: private bucket + CloudFront OAC

**File:** `infra/aws/terraform/main.tf`

Remove from `aws_s3_bucket.frontend`:
- `website` block
- `aws_s3_bucket_public_access_block` (set all to `true` instead)
- `aws_s3_bucket_policy` with `Principal: "*"`

Add:
```hcl
resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "${local.name}-frontend-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}
```

Update `aws_cloudfront_distribution.frontend`:
```hcl
origin {
  domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
  origin_id                = "s3-frontend"
  origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
}
```

Remove the `custom_origin_config` block (was needed for S3 website endpoint). The S3 REST API origin works directly with OAC.

Replace the bucket policy:
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

#### 1c. Verify no NAT Gateway references

Grep the Terraform directory for `aws_nat_gateway`, `aws_eip` (NAT-associated), or `nat_gateway_id`. Confirm none exist. Document in the infra README that NAT/VPC endpoints are a deferred hardening step.

**Validation:**
```bash
terraform fmt -check
terraform validate
terraform plan  # Confirm: no NAT, ECS in public subnets, private S3, OAC present
```

---

### Phase 2: Terraform — Budget, Alarms, and Platform Owner Credential

**Goal:** Cost visibility, operational alerting, and deploy-time platform owner credential.

#### 2a. New variables

**File:** `infra/aws/terraform/variables.tf`

```hcl
variable "budget_alert_email" {
  type        = string
  description = "Email address for budget and alarm notifications."
}

variable "monthly_budget_limit_usd" {
  type        = number
  default     = 100
  description = "Monthly AWS spend budget in USD."
}

variable "platform_owner_email" {
  type        = string
  default     = "admin@scout.ai"
  description = "Email for the platform owner login account."
}

variable "platform_owner_password_hash" {
  type        = string
  sensitive   = true
  description = "Bcrypt hash of the platform owner password. Generate with: htpasswd -nbBC 10 '' 'password' | cut -d: -f2"
}
```

#### 2b. Platform owner credential in Secrets Manager

The existing `aws_secretsmanager_secret_version.backend` has `ignore_changes = [secret_string]` — Terraform writes initial placeholders but doesn't overwrite manual edits. Add two new fields to the initial secret JSON:

```hcl
resource "aws_secretsmanager_secret_version" "backend" {
  secret_id = aws_secretsmanager_secret.backend.id
  secret_string = jsonencode({
    APP_API_KEY                     = "replace-with-strong-api-key-before-deploy"
    APP_CREATOR_KEY                 = "replace-with-strong-creator-key-before-deploy"
    APP_CREDENTIAL_ENCRYPTION_KEY   = "replace-with-base64-32-byte-key-before-deploy"
    DB_PASSWORD                     = random_password.db.result
    PLATFORM_OWNER_EMAIL            = var.platform_owner_email
    PLATFORM_OWNER_PASSWORD_HASH    = var.platform_owner_password_hash
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}
```

Add the new env vars to the ECS task definition container environment:
```hcl
{ name = "APP_PLATFORM_OWNER_EMAIL", value = var.platform_owner_email }
```

Add to the ECS task definition secrets (pulled from Secrets Manager):
```hcl
{ name = "APP_PLATFORM_OWNER_PASSWORD_HASH", valueFrom = "${aws_secretsmanager_secret.backend.arn}:PLATFORM_OWNER_PASSWORD_HASH::" }
```

#### 2c. SNS topic for alarms

**File:** `infra/aws/terraform/main.tf`

```hcl
resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-alerts"
  kms_master_key_id = aws_kms_key.app.id
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.budget_alert_email
}
```

#### 2d. AWS Budget

```hcl
resource "aws_budgets_budget" "monthly" {
  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 50
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }
}
```

#### 2e. CloudWatch alarms (6 alarms)

```hcl
resource "aws_cloudwatch_metric_alarm" "alb_unhealthy_targets" {
  alarm_name          = "${local.name}-alb-unhealthy-targets"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions = {
    LoadBalancer = aws_lb.app.arn_suffix
    TargetGroup  = aws_lb_target_group.backend.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${local.name}-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    LoadBalancer = aws_lb.app.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  alarm_name          = "${local.name}-ecs-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.backend.name
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_memory" {
  alarm_name          = "${local.name}-ecs-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.backend.name
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${local.name}-rds-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage_low" {
  alarm_name          = "${local.name}-rds-storage-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Minimum"
  threshold           = 2147483648  # 2 GiB in bytes
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }
}
```

#### 2f. Outputs

Add to `outputs.tf`:
```hcl
output "sns_alerts_topic_arn" {
  value       = aws_sns_topic.alerts.arn
  description = "SNS topic ARN for budget and operational alerts"
}
```

**Validation:**
```bash
terraform fmt -check
terraform validate
terraform plan  # Confirm: budget, 6 alarms, SNS topic, platform owner credential in secrets
```

---

### Phase 3: Backend — Login Endpoint and Password Setup

**Goal:** Add `POST /api/auth/login` and `POST /api/auth/setup-password` endpoints. No other backend changes.

#### 3a. Database migration — add password hash column to `app_users`

**File:** Legacy path at `backend/src/main/resources/db/migration/postgres/V1075__app_user_password_hash.sql` (removed from the active reset line)

```sql
ALTER TABLE app_users ADD COLUMN password_hash VARCHAR(255);
ALTER TABLE app_users ADD COLUMN password_set_at TIMESTAMPTZ;
```

Update CLAUDE.md watermark to V1075.

#### 3b. Add password hash field to AppUser entity

**File:** `backend/src/main/java/com/prototype/vulnwatch/domain/AppUser.java`

Add `passwordHash` and `passwordSetAt` fields with JPA `@Column` annotations.

#### 3c. Add setup token to DemoInvite

When an invite is accepted, the backend generates a one-time setup token (random 32-byte, URL-safe base64 — same pattern as the existing invite token). This token is returned in the accept response and used by the frontend to redirect to the password-setup form.

**File:** Legacy path at `backend/src/main/resources/db/migration/postgres/V1075__app_user_password_hash.sql` (same historical migration)

```sql
ALTER TABLE demo_invites ADD COLUMN setup_token VARCHAR(255);
ALTER TABLE demo_invites ADD COLUMN setup_token_used_at TIMESTAMPTZ;
```

**File:** `backend/src/main/java/com/prototype/vulnwatch/domain/DemoInvite.java`

Add `setupToken` and `setupTokenUsedAt` fields.

#### 3d. Extend invite acceptance to return setup token

**File:** `backend/src/main/java/com/prototype/vulnwatch/service/DemoLifecycleService.java`

In `acceptInvite()`, after marking the invite as accepted:
1. Generate a `setupToken` (same `newToken()` method already in the class)
2. Store it on the `DemoInvite` entity
3. Include the setup token in the `DemoInviteValidationResponse`

**File:** `backend/src/main/java/com/prototype/vulnwatch/dto/DemoInviteValidationResponse.java`

Add `setupToken` field (nullable — only populated on acceptance).

#### 3e. AuthLoginController — new controller

**File:** `backend/src/main/java/com/prototype/vulnwatch/controller/AuthLoginController.java` (new)

```java
@RestController
@RequestMapping("/api/auth")
public class AuthLoginController {

    // POST /api/auth/login — accepts { email, password }, returns { token, expiresAt }
    // POST /api/auth/setup-password — accepts { setupToken, password }, returns { token, expiresAt }
}
```

Both endpoints are public (added to SecurityConfig permit list).

#### 3f. AuthLoginService — new service

**File:** `backend/src/main/java/com/prototype/vulnwatch/service/AuthLoginService.java` (new)

**`login(email, password)` logic:**
1. Check if email matches `APP_PLATFORM_OWNER_EMAIL` (case-insensitive):
   - If yes: verify password against `APP_PLATFORM_OWNER_PASSWORD_HASH` using `BCrypt.checkpw()`
   - On success: issue JWT with `sub: "platform-owner"`, `roles: ["PLATFORM_OWNER"]`, `tenant_id: null`
   - On failure: return 401
2. Otherwise: look up `AppUser` by email
   - If user not found or `passwordHash` is null: return 401
   - Verify password against `user.passwordHash` using `BCrypt.checkpw()`
   - On success: resolve tenant membership (same logic as `JwtTenantAuthenticationService`), issue JWT with user's roles + tenant context
   - On failure: return 401

**`setupPassword(setupToken, password)` logic:**
1. Look up `DemoInvite` by `setupToken`
2. Validate: setup token not already used, invite not expired, tenant active
3. Hash password with `BCrypt.hashpw(password, BCrypt.gensalt(10))`
4. Store hash on the `AppUser` associated with the invite email
5. Mark `setupTokenUsedAt = Instant.now()`
6. Issue JWT with `TENANT_ADMIN` role + tenant context

**JWT issuance:** Reuse the existing `signToken` pattern from `TestPersonaService` — HS256 with `APP_JWT_HMAC_SECRET`. Extract the signing logic into a shared utility or call into `TestPersonaService` directly. Both use the same HMAC key and claim structure.

#### 3g. Configuration additions

**File:** `backend/src/main/resources/application.yml`

```yaml
app:
  security:
    platform-owner-email: ${APP_PLATFORM_OWNER_EMAIL:admin@scout.ai}
    platform-owner-password-hash: ${APP_PLATFORM_OWNER_PASSWORD_HASH:}
```

**File:** `backend/src/main/resources/application-prod.yml`

No change needed — the login endpoint reads from config, and `allow-api-key-auth: false` already prevents API key bypass.

#### 3h. SecurityConfig update

**File:** `backend/src/main/java/com/prototype/vulnwatch/config/SecurityConfig.java`

Add to the permit list:
```java
.requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
.requestMatchers(HttpMethod.POST, "/api/auth/setup-password").permitAll()
```

Place these before the `.requestMatchers("/api/**").authenticated()` rule.

#### 3i. ApiKeyAuthenticationFilter update

**File:** `backend/src/main/java/com/prototype/vulnwatch/config/ApiKeyAuthenticationFilter.java`

Add `/api/auth/login` and `/api/auth/setup-password` to `shouldNotFilter()` — these endpoints don't carry API keys or bearer tokens; they issue them.

```java
@Override
protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return !path.startsWith("/api/")
            || ("/api/demo-requests".equals(path) && "POST".equalsIgnoreCase(request.getMethod()))
            || path.startsWith("/api/demo-invites/")
            || (path.startsWith("/api/auth/") && "POST".equalsIgnoreCase(request.getMethod()));
}
```

---

### Phase 4: Frontend — Login Page Redesign

**Goal:** Unified login form for platform owner and tenant admin, with invite-based password setup and dev persona support.

#### 4a. Remove `VITE_SHOW_TOKEN_LOGIN`

**File:** `frontend/src/pages/DemoPublicPages.tsx`

Delete the raw token input form gated by `VITE_SHOW_TOKEN_LOGIN === 'true'` (lines 214-219). Replaced by the test persona button.

#### 4b. Add login API function

**File:** `frontend/src/api/client.ts`

```typescript
login: (email: string, password: string) =>
  request<{ token: string; expiresAt: string }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
    headers: { 'Content-Type': 'application/json' }
  }),

setupPassword: (setupToken: string, password: string) =>
  request<{ token: string; expiresAt: string }>('/auth/setup-password', {
    method: 'POST',
    body: JSON.stringify({ setupToken, password }),
    headers: { 'Content-Type': 'application/json' }
  }),
```

These bypass the existing auth header injection (the endpoints are public).

#### 4c. Redesign LoginPage component

Replace the current `LoginPage` (lines 186-223 of `DemoPublicPages.tsx`) with a unified login form:

```tsx
export function LoginPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const setupToken = searchParams.get('setup');
  const enableTestPersonas = import.meta.env.VITE_ENABLE_TEST_PERSONAS === 'true';

  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);

  // If setup token present, show password-setup form instead
  if (setupToken) {
    return <PasswordSetupForm setupToken={setupToken} />;
  }

  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const { token } = await api.login(email, password);
      setStoredAuthToken(token);
      // Decode JWT to check roles for navigation target
      const payload = JSON.parse(atob(token.split('.')[1]));
      const roles: string[] = payload.roles ?? [];
      const isPlatformOwner = roles.some(
        (r) => r === 'PLATFORM_OWNER' || r === 'ROLE_PLATFORM_OWNER'
      );
      navigate(isPlatformOwner ? '/platform/demo-requests' : '/');
    } catch {
      setError('Invalid email or password');
    } finally {
      setLoading(false);
    }
  };

  const handleTestPlatformOwner = async () => {
    try {
      const { token } = await api.issueTestPersonaToken('platform-owner');
      setStoredAuthToken(token);
      navigate('/platform/demo-requests');
    } catch { /* test persona endpoint unavailable */ }
  };

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Sign in to Scout.ai</h1>
        <p>Platform owners and demo users sign in below.</p>
        <form onSubmit={handleLogin}>
          <label>Email<input type="email" value={email}
            onChange={(e) => setEmail(e.target.value)} required /></label>
          <label>Password<input type="password" value={password}
            onChange={(e) => setPassword(e.target.value)} required /></label>
          {error && <div className="notice error" role="alert">{error}</div>}
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
        {enableTestPersonas && (
          <div className="dev-persona-section">
            <div className="muted-small">Development only</div>
            <button className="btn btn-secondary" type="button"
              onClick={handleTestPlatformOwner}>
              Use Platform Owner test persona
            </button>
          </div>
        )}
      </section>
    </PublicDemoShell>
  );
}
```

#### 4d. PasswordSetupForm component

New component within `DemoPublicPages.tsx` (not a separate file — under 100 lines):

```tsx
function PasswordSetupForm({ setupToken }: { setupToken: string }) {
  const navigate = useNavigate();
  const [password, setPassword] = React.useState('');
  const [confirm, setConfirm] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);

  const handleSetup = async (event: React.FormEvent) => {
    event.preventDefault();
    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const { token } = await api.setupPassword(setupToken, password);
      setStoredAuthToken(token);
      navigate('/');
    } catch {
      setError('Setup link is invalid or has expired');
    } finally {
      setLoading(false);
    }
  };

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Set your password</h1>
        <p>Choose a password to access your Scout.ai demo workspace.</p>
        <form onSubmit={handleSetup}>
          <label>Password<input type="password" value={password}
            onChange={(e) => setPassword(e.target.value)} required minLength={8} /></label>
          <label>Confirm password<input type="password" value={confirm}
            onChange={(e) => setConfirm(e.target.value)} required minLength={8} /></label>
          {error && <div className="notice error" role="alert">{error}</div>}
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? 'Setting up...' : 'Set password & continue'}
          </button>
        </form>
      </section>
    </PublicDemoShell>
  );
}
```

#### 4e. Update invite acceptance redirect

**File:** `frontend/src/pages/DemoPublicPages.tsx` — `DemoInvitePage`

After successful invite acceptance, if the response includes a `setupToken`, redirect to `/login?setup=<setupToken>` instead of showing the generic "Continue to login" link.

#### 4f. Update `.env.example`

**File:** `frontend/.env.example` (new)

```env
# Enable test persona features (local dev only)
VITE_ENABLE_TEST_PERSONAS=true

# API connection (defaults work for local dev)
# VITE_API_BASE=http://localhost:8080/api
# VITE_API_KEY=change-me-in-prod
# VITE_CREATOR_KEY=local-creator

# Hosted IdP login (not used in validation tier — credential login is primary)
# VITE_IDP_LOGIN_URL=

# Sentry (optional)
# VITE_SENTRY_DSN=
```

---

### Phase 5: Tests

#### 5a. Backend tests

**New controller IT:** `AuthLoginControllerPostgresIntegrationTest.java`

| Test case | Assertion |
|-----------|-----------|
| Platform owner login with correct password | 200 + valid JWT with PLATFORM_OWNER role |
| Platform owner login with wrong password | 401 |
| Platform owner login with wrong email | 401 |
| Tenant admin login after password setup | 200 + valid JWT with TENANT_ADMIN role + correct tenant |
| Tenant admin login before password setup | 401 (no password hash yet) |
| Setup password with valid setup token | 200 + JWT + password stored (bcrypt) |
| Setup password with already-used setup token | 400 or 409 |
| Setup password with expired invite | 400 |
| Login endpoint does not leak user existence | Same error message for "user not found" and "wrong password" |

**Extend existing IT:** `DemoLifecycleService` — verify `acceptInvite()` now returns a `setupToken`.

#### 5b. Frontend tests

**File:** `frontend/src/pages/__tests__/LoginPage.test.tsx` (new)

| Test case | Assertion |
|-----------|-----------|
| Renders email + password form | Both inputs visible, no setup form |
| Successful login stores token and navigates | `setStoredAuthToken` called with JWT |
| Platform owner login navigates to `/platform/demo-requests` | Check `navigate` call |
| Tenant admin login navigates to `/` | Check `navigate` call |
| Wrong credentials show error | "Invalid email or password" visible |
| Test persona button hidden by default | Not in DOM |
| Test persona button visible with `VITE_ENABLE_TEST_PERSONAS=true` | Button present |
| `?setup=` param shows password setup form | Password + confirm inputs visible |
| Password mismatch shows error | "Passwords do not match" visible |
| Successful setup stores token and navigates to `/` | `setStoredAuthToken` called |

#### 5c. Terraform validation

```bash
cd infra/aws/terraform
terraform fmt -check
terraform validate
terraform plan \
  -var="vpc_id=vpc-xxx" \
  -var="private_subnet_ids=[\"subnet-priv1\",\"subnet-priv2\"]" \
  -var="public_subnet_ids=[\"subnet-pub1\",\"subnet-pub2\"]" \
  -var="backend_image=123456789012.dkr.ecr.us-east-1.amazonaws.com/vulnwatch-backend:latest" \
  -var="jwt_issuer_uri=https://unused.example.com" \
  -var="jwt_jwk_set_uri=https://unused.example.com/.well-known/jwks.json" \
  -var="cors_allowed_origins=https://d123456789.cloudfront.net" \
  -var="budget_alert_email=ops@example.com" \
  -var="platform_owner_password_hash=\$2a\$10\$examplehashhere"
```

Plan output must confirm:
- [ ] ECS service subnet = public, `assign_public_ip = true`
- [ ] RDS subnet group = private (unchanged)
- [ ] No `aws_nat_gateway` resource
- [ ] S3 frontend: `block_public_access` all true, no website config
- [ ] CloudFront OAC resource present
- [ ] S3 bucket policy references CloudFront OAC, not `"*"`
- [ ] AWS Budget resource with 3 notifications
- [ ] 6 CloudWatch alarms
- [ ] SNS topic + email subscription
- [ ] Platform owner credential fields in Secrets Manager / ECS task definition

#### 5d. Post-deploy smoke test checklist

| # | Step | Expected result |
|---|------|----------------|
| 1 | Load frontend via CloudFront URL | SPA renders, no S3 direct access |
| 2 | Direct S3 bucket URL | Returns 403 (bucket is private) |
| 3 | Hit ALB health check | `/actuator/health/readiness` returns 200 |
| 4 | Navigate to `/login` | Email + password form renders |
| 5 | Platform owner signs in | JWT issued, navigates to `/platform/demo-requests` |
| 6 | Submit demo request (public form) | 200, request appears in platform console |
| 7 | Platform owner approves request | Tenant created, invite link visible in table |
| 8 | Copy invite link, open in new browser | Invite page shows workspace + email + expiry |
| 9 | Accept invite | Redirects to `/login?setup=<token>`, password form shown |
| 10 | Set password | JWT issued, navigates to `/` with tenant context |
| 11 | Log out, return to `/login` | Tenant admin signs in with email + password set in step 10 |
| 12 | Tenant admin uploads SBOM | Upload succeeds, stored in S3 archive |
| 13 | Tenant admin attempts live connector | Blocked by demo capabilities |
| 14 | Confirm SNS email subscription | Manual — click confirm link in inbox |

---

## 5. What This Plan Does NOT Do (Deferred)

| Item | Trigger to revisit |
|------|--------------------|
| SES email delivery for invite links | Prospect volume > 10 per month or platform owner requests automated sending |
| External IdP integration (Cognito, Okta) | Enterprise customer requires SSO |
| NAT Gateway / VPC endpoints for ECS | Compliance audit requires private networking |
| Multi-AZ RDS | First paying customer or SLA commitment |
| Autoscaling ECS | Worker separation + distributed scheduler locks implemented |
| Read replicas / provisioned IOPS | Query latency > 200ms p95 under real load |
| Custom domain + ACM cert for CloudFront | Brand/trust requirements for customer-facing URL |
| CloudWatch dashboard | Operational team size > 1 |
| Password reset flow | Tenant admin requests it (platform owner can issue new invite as workaround) |
| Password complexity policy beyond minimum length | Security review or compliance requirement |

---

## 6. File Change Summary

| File | Change | Description |
|------|--------|-------------|
| `infra/aws/terraform/main.tf` | Modify | ECS → public subnets; S3 → private + OAC; CloudFront → S3 origin with OAC; SNS topic; budget; 6 alarms; platform owner credential in secrets + ECS env |
| `infra/aws/terraform/variables.tf` | Modify | Add `budget_alert_email`, `monthly_budget_limit_usd`, `platform_owner_email`, `platform_owner_password_hash` |
| `infra/aws/terraform/outputs.tf` | Modify | Add `sns_alerts_topic_arn` |
| Legacy `backend/.../db/migration/postgres/V1075__app_user_password_hash.sql` | Create | Add `password_hash`, `password_set_at` to `app_users`; add `setup_token`, `setup_token_used_at` to `demo_invites` |
| `backend/.../domain/AppUser.java` | Modify | Add `passwordHash`, `passwordSetAt` fields |
| `backend/.../domain/DemoInvite.java` | Modify | Add `setupToken`, `setupTokenUsedAt` fields |
| `backend/.../controller/AuthLoginController.java` | Create | `POST /api/auth/login`, `POST /api/auth/setup-password` |
| `backend/.../service/AuthLoginService.java` | Create | Login verification, password setup, JWT issuance |
| `backend/.../service/DemoLifecycleService.java` | Modify | Generate `setupToken` on invite acceptance |
| `backend/.../dto/DemoInviteValidationResponse.java` | Modify | Add `setupToken` field |
| `backend/.../config/SecurityConfig.java` | Modify | Permit `/api/auth/login` and `/api/auth/setup-password` |
| `backend/.../config/ApiKeyAuthenticationFilter.java` | Modify | Skip filter for `/api/auth/**` POST |
| `backend/src/main/resources/application.yml` | Modify | Add `platform-owner-email`, `platform-owner-password-hash` config |
| `frontend/src/pages/DemoPublicPages.tsx` | Modify | Replace LoginPage with credential form + PasswordSetupForm; remove `VITE_SHOW_TOKEN_LOGIN`; update invite acceptance redirect |
| `frontend/src/api/client.ts` | Modify | Add `login()`, `setupPassword()` API functions |
| `frontend/.env.example` | Create | Document available env vars |
| `backend/.../controller/AuthLoginControllerPostgresIntegrationTest.java` | Create | 9 test cases |
| `frontend/src/pages/__tests__/LoginPage.test.tsx` | Create | 10 test cases |

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

Budget alarm set at $100 provides ~2x headroom.

---

## 8. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| ECS task in public subnet gets probed | Medium | Low | Ingress locked to ALB SG; no open ports to internet. Standard for Fargate public networking. |
| CloudFront OAC migration causes brief frontend 403s | Low | Medium | Test with `terraform plan` before apply. CloudFront invalidation takes ~5 min. |
| Budget alarm email not confirmed | Medium | Low | SNS requires email confirmation. Include in deploy runbook as a manual step. |
| Platform owner password lost | Low | Medium | Re-run `terraform apply` with new hash to update Secrets Manager (requires `ignore_changes` lifecycle to be temporarily removed, or update secret via AWS CLI). |
| Setup token intercepted in transit | Low | Medium | Token is single-use + time-limited (7 days, matching invite expiry). For validation tier, acceptable. HTTPS on CloudFront provides transport encryption. |
| Tenant admin forgets password | Medium | Low | Platform owner issues new invite via "Resend" button. Tenant admin clicks link, sets new password. No self-service reset needed for validation scale. |
| Bcrypt cost too low (brute force) | Low | Low | Cost factor 10 (default `BCrypt.gensalt()`) — ~100ms per attempt. Adequate for validation. Rate limiting on login endpoint is a deferred hardening item. |

---

## 9. Deployment Runbook (Quick Reference)

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
    "PLATFORM_OWNER_PASSWORD_HASH": "<bcrypt-hash>"
  }'

# 5. Set HMAC secret for JWT signing (needed for login + test personas)
# Add APP_JWT_HMAC_SECRET to the secret above

# 6. Force new ECS deployment to pick up secret changes
aws ecs update-service --cluster vulnwatch-validation --service backend --force-new-deployment

# 7. Smoke test (see Phase 5d checklist)
```
