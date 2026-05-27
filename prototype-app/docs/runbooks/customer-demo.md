# Customer Demo Runbook

Last updated: 2026-05-27

## Demo Shape

- Access is invite-only.
- Each approved request provisions a `DEMO` tenant for 7 days.
- Demo tenants can use sample data and limited SBOM ingestion.
- Live ServiceNow, SCCM, AWS Discovery, GitHub SBOM sources, and AI actions are blocked for demo tenants.

## Prerequisites

- Backend running with production-like preprod settings.
- Platform owner credential configured (`APP_PLATFORM_OWNER_EMAIL`, `APP_PLATFORM_OWNER_PASSWORD_HASH`).
- Resend email client configured if using automated invite delivery (`RESEND_API_KEY`).
- Demo tenant expiry job active (runs hourly by default via `DemoTenantExpiryJob`).

## Operator Flow

### 1. Receive and Review Requests

Demo requests are submitted publicly via `POST /api/demo-requests` (no auth required). The request body captures `firstName`, `lastName`, `email`, `company`, and `useCase`.

Review pending requests in **Platform Console → Demo Requests** (`/platform/demo-requests`). Each request shows the submitter details and current status (`PENDING`, `APPROVED`, `DECLINED`).

### 2. Approve a Request

Approve via `POST /api/platform/demo-requests/{id}/decision` with `{"decision": "APPROVED"}` or use the Approve button in the UI.

On approval:
- A `DEMO` tenant is provisioned with a 7-day expiration timestamp.
- A `DemoInvite` record is created with a unique token.
- An invite link is shown in the platform console: `https://<host>/invite/<token>`.

### 3. Share the Invite Link

Copy the invite link from the platform console and send it to the prospect manually (email, Slack, etc.).

### 4. Prospect Accepts the Invite

The prospect opens `/invite/<token>`. The invite page shows workspace name, email address, and expiration date.

On clicking **Accept invite** (`POST /api/demo-invites/{token}/accept`):
- The response includes a one-time `setupToken`.
- The frontend redirects to `/login?setup=<setupToken>`.

### 5. Prospect Sets Their Password

The password setup form at `/login?setup=<setupToken>` prompts for a password (minimum 8 characters). On submit (`POST /api/auth/setup-password`):
- Password is bcrypt-hashed and stored on the `AppUser`.
- A JWT is issued with `TENANT_ADMIN` role and the demo tenant context.
- The prospect is redirected to `/`.

### 6. Verify Demo Environment

Check demo status: `GET /api/demo/status` (requires auth in demo tenant context).

Expected response confirms:
- `plan_code: "DEMO"`
- `daysRemaining: 7` (or fewer)
- Blocked capabilities: `LIVE_CONNECTORS`, `AI_ACTIONS`
- Allowed capabilities: `SBOM_UPLOAD`, `ENDPOINT_INGESTION`

The top bar shows "Demo" and days remaining.

## Demo Walkthrough

Suggested order for a 30-minute demo:

### 1. Exposure Dashboard (`/exposure`)
Show the risk-focused overview: total findings, critical/high CVE counts, SLA breach status. Introduce the S.AI Risk Score concept.

### 2. Vulnerability Repository — Unified Records (`/vuln-repo/org-cves`)
Show CVEs correlated to the org's inventory. Open a critical CVE and walk through the CVE Assessment Workbench. Show the S.AI Risk Score phase timeline (CVE Published → KEV → Org Exposure → EOL Risk → Patch Gap → Findings). Demonstrate the applicability assessment workflow.

### 3. Findings (`/findings`)
Show the findings table with S.AI Priority scores. Open a finding, show the detail panel, demonstrate status transitions (Open → Acknowledged → Resolved). Mention ServiceNow incident creation as a live integration (blocked in demo tier).

### 4. Software Inventory (`/inventory`)
Show the component inventory with EOL status. Highlight end-of-life components and days remaining.

### 5. Connect — SBOM Ingestion (`/connect`)
Show the connector catalog. Demonstrate SBOM file upload or endpoint ingestion (allowed in demo tier). Show that live connectors (ServiceNow CMDB, SCCM, AWS Discovery) are present but blocked.

### 6. Configurations (`/configurations`)
Walk through risk policy settings and SLA thresholds. Show the S.AI Prioritization triage weight sliders and the live Triage Score Simulator. Show suppression rules and ownership assignment.

## Persona Setup for Demos

| Scenario | Persona / Credential |
|---|---|
| Approving demo requests | Platform owner login |
| Full demo as customer admin | Demo tenant admin (credential set during invite acceptance) |
| Showing analyst workflow | Create a second user via tenant admin with `SECURITY_ANALYST` role |

For internal demos using test personas, set `VITE_ENABLE_TEST_PERSONAS=true` and use the persona picker in the gear menu.

## Demo Expiration

The `DemoTenantExpiryJob` runs hourly. Expired active demo tenants are marked `SUSPENDED`. The `TenantStatusFilter` blocks all normal tenant API calls with HTTP 403 for suspended tenants.

The prospect sees an expiration notice on `/demo/expired`.

To extend a demo tenant, update the expiration timestamp via `PUT /api/platform/tenants/{tenantId}` (platform owner only).

## Common Issues

| Symptom | Likely cause | Fix |
|---|---|---|
| Invite link shows "Invalid or expired invite" | Token already used or expired | Issue a new invite via the resend action in the platform console |
| Password setup form says "Setup link is invalid or has expired" | `setupToken` already used or stale | Accept the invite again to generate a fresh setup token |
| Demo tenant shows suspended immediately | Expiry job ran before setup completed | Extend the expiration timestamp via platform console |
| Live connector cards show "Unavailable in demo" | Expected — CMDB, AWS, GitHub SBOM connectors are blocked for `DEMO` plan | Explain during demo |
| AI investigation summary not working | `OPENAI_ENABLED=false` or key not configured | Enable OpenAI or note AI features are disabled in this environment |

## Cleanup

To tear down a demo tenant after the demo:

1. Suspend the tenant: `PUT /api/platform/tenants/{tenantId}` with `{"status": "SUSPENDED"}` (platform owner only).
2. The expiry job handles further cleanup on its next hourly run.
3. For a hard purge, `DemoTenantPurgeService` handles schema drop — invoke via platform tooling or a database reset script.
