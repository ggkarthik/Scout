# VulnWatch Backend

Last updated: 2026-07-13

## Tech Stack

| Component | Version / Detail |
|-----------|-----------------|
| Java | 17 |
| Spring Boot | 3.3.2 |
| Spring Security | JWT Bearer + API key dual-auth |
| Spring Data JPA | PostgreSQL via HikariCP |
| Database | PostgreSQL (Flyway migrations in `postgres_reset/`) |
| Build | Maven, JaCoCo coverage, SpotBugs, Failsafe ITs |
| External HTTP | Custom `OutboundHttpClient` with circuit-breaker + retry |

Package root: `com.prototype.vulnwatch`

---

## Authentication

Two paths, handled by `ApiKeyAuthenticationFilter`:

### API Key (dev/ops)

Enabled when `APP_ALLOW_API_KEY_AUTH=true`.

| Header | Role granted |
|--------|-------------|
| `X-API-Key: <key>` | `ROLE_OPERATOR`, `ROLE_SECURITY_ANALYST` |
| `X-Creator-Key: <key>` | additionally: `ROLE_CREATOR`, `ROLE_PLATFORM_OWNER`, `ROLE_TENANT_ADMIN`, `ROLE_INVENTORY_ADMIN` |
| `X-User-ID: <id>` | sets actor identity (defaults to `APP_DEFAULT_USER_ID`) |

Default local api-key: `change-me-in-prod`. No creator-key configured locally means all callers get creator-level access.

### JWT Bearer (production)

Active when `APP_JWT_ISSUER_URI` is set. Token decoded by `JwtTenantAuthenticationService`. Roles resolved from the `roles` JWT claim (or any namespaced claim ending in `/roles`). Tenant ID resolved from `tenant_id` claim.

### Tenant Resolution

`TenantResolutionFilter` populates thread-local `TenantContext` from:
1. JWT `tenant_id` claim (production)
2. `X-Tenant-ID` header (only when `APP_ALLOW_HEADER_TENANT_SELECTION=true` — local dev only)
3. Default tenant fallback

`TenantStatusFilter` follows and rejects requests with HTTP 403 if tenant is `SUSPENDED` or `EXPIRED`.

### Local Credential Auth

`LocalAuthController` / `AuthLoginController` (`POST /api/auth/login`, `POST /api/auth/setup-password`) provides bcrypt-based login for platform owner and tenant admins in validation/preprod environments.

---

## Authorization Rules

| Path prefix | Required |
|-------------|---------|
| `OPTIONS /*` | Public |
| `GET /actuator/health`, `GET /actuator/health/readiness`, `GET /actuator/health/liveness`, `GET /actuator/info` | Public |
| `POST /api/auth/login`, `POST /api/auth/setup-password` | Public |
| `POST /api/demo-requests` | Public |
| `/api/demo-invites/**` | Public |
| `/api/platform/**` | `ROLE_PLATFORM_OWNER` |
| `/api/operations/**` | `ROLE_PLATFORM_OWNER` |
| All other `/api/**` | Authenticated |

---

## REST Controllers

41 controllers total, verified against `@RequestMapping`/`@GetMapping`/etc. annotations directly (several base paths below differ from older drafts of this doc — connector controllers moved under a shared `/api/connectors/` prefix at some point, and quite a few controllers have grown far beyond simple CRUD).

### Assets / Ingestion

**AssetController — `/api/assets`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List tenant assets |
| POST | `/cmdb-sync` | Sync CMDB asset data |
| GET | `/assignment-groups` | List assignment groups |
| GET | `/assigned-to` | List assigned-to users |
| GET | `/hosts/{assetId}` | Get host detail by asset UUID |

Asset domain: `Asset` entity. Types: `AssetType` enum. Criticality: `BusinessCriticality` enum.

**IngestionController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sbom-fetch` | Queue endpoint SBOM fetch job |
| GET | `/ingestions` | Paginated upload list, filterable by source system/date |
| POST | `/ingestion/nvd-sync` | Trigger NVD incremental sync (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/ingestion/nvd-full-sync` | Trigger NVD full sync (`PLATFORM_OWNER`) |
| POST | `/ingestion/nvd-cve/{cveId}` | Refresh single CVE from NVD (`PLATFORM_OWNER`) |
| POST | `/ingestion/kev-sync` | Trigger CISA KEV sync |
| POST | `/ingestion/ghsa-sync` | Trigger GHSA sync |
| POST | `/ingestion/euvd-sync` | Trigger EUVD sync |
| POST | `/ingestion/jvn-sync` | Trigger JVN sync |
| POST | `/ingestion/csaf/microsoft-sync` | Trigger Microsoft CSAF sync |
| POST | `/ingestion/csaf/redhat-sync` | Trigger Red Hat CSAF sync |
| POST | `/ingestion/vex-assertion-repair` | Repair VEX assertions (`PLATFORM_OWNER`) |
| POST | `/ingestion/vex-rollout-backfill` | VEX rollout backfill (`PLATFORM_OWNER`) |
| GET | `/ingestion/vex-assertion-repair/summary` | Get VEX repair summary |
| POST | `/ingestion/advisories` | Ingest advisory batch (`PLATFORM_OWNER`) |

Supported SBOM formats (`SbomFormat` enum): CycloneDX, SPDX.

**IngestionJobController — `/api/ingestion-jobs`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{jobId}` | Get job status by UUID |
| GET | `/` | Paginated list of ingestion jobs |

**GithubSbomSourceController — `/api/github-sbom-sources`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List configured GitHub SBOM sources |
| POST | `/` | Create source (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| PUT | `/{id}` | Update source config |
| DELETE | `/{id}` | Delete source |
| POST | `/ghcr/run` | Trigger GHCR ingestion once |
| POST | `/repository/run` | Trigger repository SBOM ingestion |
| POST | `/{id}/run` | Trigger a specific source's sync |

`GithubSbomSource` entity. Frequency: `GithubIngestionFrequency` enum (EVERY_5_MIN, HOURLY, DAILY).

**BomController — `/api/bom`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| POST | `/fetch` | Fetch BOM from URL |
| POST | `/upload` | Upload BOM file (multipart) |
| GET | `/inventory` | Paginated BOM inventory list |
| GET | `/components` | Paginated BOM components list |
| GET | `/components/{componentId}` | Get component detail |
| GET | `/assets/{assetId}/cves` | Get application CVEs for an asset |
| GET | `/application-risk` | Application risk summary |
| GET | `/dashboard` | BOM dashboard metrics |
| GET | `/support` | BOM support matrix |
| GET | `/inventory/{bomId}` | Get single BOM detail |
| GET | `/inventory/{bomId}/lineage` | Get BOM lineage |
| DELETE | `/inventory/{bomId}` | Soft-delete a BOM |

**CbomController — `/api/bom/cbom`** *(undocumented until now — cloud/container BOM posture tracking)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/posture` | List CBOM posture summary |
| GET | `/posture/{assetId}` | Get asset CBOM posture |
| GET | `/components` | List components for an asset |
| GET | `/findings` | List risk findings for an asset |
| POST | `/findings/{findingId}/accept` | Accept a finding (`SECURITY_ANALYST`/`TENANT_ADMIN`/`CREATOR`) |

### Inventory

**InventoryController — `/api/inventory`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/components` | Paginated components (filters: assetType, status, sourceSystem, ecosystem, …) |
| GET | `/components/filters` | Available filter values |
| GET | `/software-identities` | Paginated software identities |
| GET | `/software-identities/funnel` | Software identity funnel analytics |
| GET | `/software-identities/{id}` | Get software identity detail |
| GET | `/software-identities/{id}/metadata` | Get software identity metadata |
| PUT | `/software-identities/{id}/metadata` | Save metadata (`@SensitiveTenantAction`) |

`InventoryComponent` entity. CPE mappings via `InventoryComponentCpeMap`.

### Vulnerabilities / Intelligence

**VulnerabilityController — `/api/vulnerabilities`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{externalId}` | Get vulnerability detail by CVE ID |

**VulnerabilityIntelligenceController — `/api/vulnerability-intelligence`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Paginated intel list (filters: query, severity, source, inKev, …) |
| GET | `/sources` | List available vulnerability sources |
| GET | `/filters` | Available filter values |
| GET | `/{externalId}` | Get vulnerability intel detail |
| GET | `/org-cves` | Paginated org-specific CVE exposure |
| GET | `/org-cves/status` | Get org CVE automation status |
| POST | `/org-cves/recompute` | Recompute org-specific CVEs (`TENANT_ADMIN`/`SECURITY_ANALYST`) |
| POST | `/org-cves/refresh` | Refresh tenant exposure (`TENANT_ADMIN`/`SECURITY_ANALYST`) |

Backed by `vulnerability_intel_summary` + `vulnerability_intel_observations` projections.

### Findings

**FindingController — `/api/findings`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Paginated findings (cursor/limit or page/size) |
| GET | `/summary` | Finding summary metrics |
| GET | `/distributions` | Finding distribution analytics |
| GET | `/backlog-health` | Backlog health metrics |
| GET | `/projection-status` | Finding projection status (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| POST | `/projection-rebuild` | Rebuild finding projection (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| GET | `/queues` | List saved finding queues |
| GET | `/queues/{queueKey}` | Get queue definition |
| POST | `/queues` | Create queue (`TENANT_ADMIN`/`SECURITY_ANALYST`) |
| PUT | `/queues/{queueRef}` | Update queue |
| POST | `/queues/{queueRef}/duplicate` | Duplicate queue |
| POST | `/queues/{queueRef}/default` | Set default queue |
| DELETE | `/queues/{queueRef}` | Delete queue |
| GET | `/filters` | Available filters |
| GET | `/{findingId}` | Get finding by UUID |
| PUT | `/{findingId}/workflow` | Update finding workflow (status, assignee, etc.) |
| POST | `/bulk-workflow` | Bulk update workflow |
| DELETE | `/bulk` | Bulk delete findings |

`Finding` entity. Status: `FindingStatus` enum (OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, SUPPRESSED, FALSE_POSITIVE, RISK_ACCEPTED). Decision state: `FindingDecisionState`. Creation source: `FindingCreationSource` enum.

**CveDetailController — `/api/cve-detail`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{cveId}` | Full CVE detail (summary, signals, investigations, assessments) |
| GET | `/{cveId}/vex-evidence` | Get VEX evidence for a component |
| POST | `/{cveId}/investigation` | Create investigation |
| PUT | `/investigation/{investigationId}` | Update investigation |
| POST | `/{cveId}/investigation/submit` | Upsert investigation |
| POST | `/{cveId}/assessment/submit` | Upsert applicability assessment |
| POST | `/{cveId}/applicability-assessment` | Create assessment |
| PUT | `/applicability-assessment/{assessmentId}` | Update assessment |
| POST | `/applicability-assessment/{assessmentId}/complete` | Complete assessment |
| POST | `/{cveId}/manual-finding` | Create manual finding |
| POST | `/{cveId}/suppress` | Suppress CVE org-wide |
| POST | `/{cveId}/export` | Export CVE report (`…`/`READ_ONLY_AUDITOR`) |
| POST | `/{cveId}/investigation-summary` | Generate deterministic investigation summary |
| POST | `/{cveId}/investigation-ai-summary` | Generate AI investigation summary (OpenAI) |
| GET | `/{cveId}/saved-investigation-summary` | Get saved investigation summary |
| GET | `/{cveId}/fixes` | Get previously generated fix records |
| GET | `/software-fixes` | Get fix records by software name |
| POST | `/{cveId}/generate-fixes` | Generate AI fix records |
| POST | `/{cveId}/analyst-fixes` | Save analyst-entered fixes |
| GET | `/{cveId}/ai-solution` | Get saved AI remediation recommendation |
| POST | `/{cveId}/ai-solution` | Generate AI solution |
| GET | `/{cveId}/ai-actions` | Get saved AI required actions |
| POST | `/{cveId}/ai-actions` | Generate AI actions |
| GET | `/{cveId}/investigation/runbook` | Get investigation runbook |
| PUT | `/{cveId}/investigation/runbook` | Save runbook |
| POST | `/{cveId}/investigation/log` | Append runbook log entry |
| POST | `/{cveId}/investigation/resolve-inventory` | Resolve inventory criteria |
| POST | `/{cveId}/investigation/confirm-applicability` | Confirm applicability |
| POST | `/{cveId}/investigation/false-positive-analysis` | Analyze false positives |
| POST | `/{cveId}/investigation/eol-analysis` | Analyze EOL status |
| POST | `/{cveId}/investigation/run-agent` | Run investigation agent |

`OrgCveRecord` entity stores per-tenant CVE state. `OrgCveAiArtifact` stores persisted AI outputs. Most write endpoints require `TENANT_ADMIN`/`SECURITY_ANALYST`.

**ServiceNowIncidentController — `/api/cve-detail`** (separate controller, same base path)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/servicenow/assignment-groups` | List assignment groups from ServiceNow |
| POST | `/{cveId}/servicenow-incident` | Create ServiceNow incident(s) for a CVE |

### Dashboards

**DashboardController — `/api/dashboard`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Main dashboard summary |
| GET | `/applicable-software` | Paginated applicable software |
| GET | `/impacted-cves` | Paginated impacted CVEs |
| GET | `/cve-inventory-map` | CVE-to-inventory mapping |
| GET | `/grid-exposure` | Grid exposure matrix |

Results are cached in memory (Caffeine).

**VulnRepoDashboardController — `/api/vuln-repo`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Vulnerability repo dashboard |
| GET | `/vulnerabilities` | List vulnerabilities (filterable) |
| GET | `/org-cves` | List org-specific CVEs |
| GET | `/org-cves/status` | CVE automation status |
| POST | `/org-cves/recompute` | Recompute org CVEs |
| POST | `/org-cves/refresh` | Refresh tenant exposure |
| GET | `/software-assets/{softwareIdentityId}` | Get software assets |

**OperationalDashboardController — `/api/operations`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Operational dashboard |
| GET | `/overview` | Operational overview |
| GET | `/ingestion-efficiency` | Ingestion efficiency metrics |
| GET | `/normalization-quality` | Normalization quality metrics |
| GET | `/correlation-effectiveness` | Correlation effectiveness metrics |
| GET | `/noise-lifecycle` | Noise lifecycle metrics |
| GET | `/api-read-path` | API read path metrics |
| GET | `/freshness-drift` | Freshness drift metrics |
| GET | `/metric-catalog` | Metric catalog |
| GET | `/performance-scorecard` | Performance scorecard |
| GET | `/tenant-attention` | Tenants needing attention |
| GET | `/connector-issues` | Connector issues |
| GET | `/quality/summary` | Quality summary |
| GET | `/quality/issues` | Paginated quality issues |
| GET | `/quality/issues/{issueId}` | Quality issue detail |
| GET | `/quality/filters` | Quality filter values |

Requires `ROLE_PLATFORM_OWNER` (plus `TENANT_ADMIN`/`INVENTORY_ADMIN`/`SECURITY_ANALYST`/`READ_ONLY_AUDITOR` for `/quality/**`).

### End of Life

**EolController — `/api/eol`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status/summary` | EOL summary counts |
| GET | `/status/components` | Paginated component EOL statuses |
| GET | `/status/packages` | Paginated package EOL statuses |
| GET | `/status/packages/assets` | Assets with a given package installed |
| GET | `/products` | List all EOL products |
| GET | `/products/{slug}/releases` | List releases for a product |
| GET | `/mappings/suggestions` | AI-suggested EOL slugs for unmatched components |
| GET | `/mappings/unresolved` | Paginated unresolved mappings |
| POST | `/mappings/confirm` | Confirm/reject a suggested EOL mapping (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/catalog` | Trigger catalog refresh (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/releases` | Trigger release refresh (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/mappings` | Trigger mapping resolve (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/denormalize` | Trigger denormalize (`PLATFORM_OWNER`) |
| POST | `/admin/refresh/full` | Trigger full refresh (`PLATFORM_OWNER`) |

`EolProductCatalog`, `EolRelease`, `SoftwareEolMapping` entities. Data sourced from endoflife.date API.

### Policy / Rules

**RiskPolicyController — `/api/risk-policy`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get tenant risk policy |
| POST | `/` | Update risk policy (`TENANT_ADMIN`) |
| POST | `/recompute-findings-scores` | Recompute all finding scores |
| POST | `/auto-close/execute-now` | Run the auto-close job immediately |

`RiskPolicy` entity. Fields include: `sla*`, `triage*` (6 weight fields), `autoClose*`, `findingGenerationMode`, `findingsScoreConfig` (JSONB).

**SuppressionRuleController — `/api/suppression-rules`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List suppression rules |
| POST | `/` | Create rule (`TENANT_ADMIN`) |
| PUT | `/{id}` | Update rule |
| DELETE | `/{id}` | Delete rule |
| POST | `/{id}/execute` | Execute a rule immediately |
| POST | `/{id}/reopen-all` | Reopen findings suppressed by a rule |
| POST | `/cve-reopen/{recordId}` | Reopen a specific suppressed CVE record |

`SuppressionRule` entity. States: DRAFT, APPROVED, IN_REVIEW, REJECTED, EXPIRED. Types: CVE, FINDING.

**OwnershipRuleController — `/api/ownership-rules`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List ownership rules |
| POST | `/` | Create rule (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| PUT | `/{id}` | Update rule |
| DELETE | `/{id}` | Delete rule |
| POST | `/apply` | Apply all rules |
| POST | `/{id}/apply` | Apply a specific rule |

`OwnershipRule` entity. Conditions stored as JSONB. Evaluated by priority to auto-assign findings.

**VulnerabilitySourceFilterConfigController — `/api/connectors/vulnerability-sources`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List all source filter configs |
| GET | `/{sourceSystem}` | Get config for a source (nvd, ghsa, etc.) |
| PUT | `/{sourceSystem}` | Save config (`PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`) |

Per-tenant configuration of which vulnerability intelligence sources participate in correlation.

### Remediation Campaigns

**CampaignController — `/api/campaigns`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List campaigns (optional status filter) |
| GET | `/{campaignId}` | Get campaign detail |
| POST | `/` | Create campaign |
| POST | `/{campaignId}/status` | Update campaign status |
| POST | `/{campaignId}/notes` | Add note |
| POST | `/{campaignId}/exceptions` | Add exception |
| POST | `/{campaignId}/exceptions/{exceptionId}/status` | Update exception status |
| POST | `/{campaignId}/notify-groups/{notifyGroupId}` | Update notify group |
| POST | `/{campaignId}/watchlist/{watchlistEntryId}` | Update watchlist entry |

All write endpoints: `PLATFORM_OWNER`/`TENANT_ADMIN`/`SECURITY_ANALYST`.

### Connectors

**ServiceNowCmdbConfigController — `/api/connectors/servicenow-cmdb`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get CMDB config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test connection |
| POST | `/sync` | Trigger sync |

**SccmCmdbController — `/api/connectors/sccm-cmdb`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get SCCM config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test connection |
| POST | `/sync` | Trigger sync |
| GET | `/sync/status` | Get sync status |

**AwsDiscoveryController — `/api/connectors/aws-discovery`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get discovery config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test AWS credentials |
| POST | `/sync` | Trigger global sync |
| GET | `/sync/status` | Get sync status |
| GET | `/targets` | List discovery targets |
| POST | `/targets` | Create target (account + region) |
| PUT | `/targets/{targetId}` | Update target |
| DELETE | `/targets/{targetId}` | Delete target |
| POST | `/targets/{targetId}/test` | Test target connection |
| POST | `/targets/{targetId}/sync` | Trigger target sync |

`AwsDiscoveryConfig`, `AwsDiscoveryTarget` entities. Discovery scoped to EC2 instances via SSM; multi-account via cross-account role ARN + external ID.

**AzureDiscoveryController — `/api/connectors/azure-discovery`** *(undocumented until now)*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get discovery config |
| PUT | `/` | Save config (`TENANT_ADMIN`/`INVENTORY_ADMIN`) |
| POST | `/test` | Test connection |
| POST | `/sync` | Trigger global sync |
| GET | `/sync/status` | Get sync status |
| GET | `/targets` | List discovery targets |
| POST | `/targets` | Create target (per-subscription scope) |
| PUT | `/targets/{targetId}` | Update target |
| DELETE | `/targets/{targetId}` | Delete target |
| POST | `/targets/{targetId}/test` | Test target connection |
| POST | `/targets/{targetId}/sync` | Trigger target sync |

Mirrors the AWS Discovery architecture. Auth: `CLIENT_SECRET` or `MANAGED_IDENTITY` (`azure_discovery_configs`/`azure_discovery_targets`, V40/V41).

**SyncController — `/api/sync-runs`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List sync runs |
| GET | `/sources-summary` | Vulnerability source summary |

`SyncRun` entity tracks each connector sync job.

### Auth / Admin

**AuthContextController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/context` or `/me` | Get current auth context (roles, tenant, demo status, etc.) |

**LocalAuthController — `/api/auth`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/login` | Credential login (email + password) |
| POST | `/setup-password` | Set password via one-time setup token |
| POST | `/tenant-context` | Switch acting tenant context (`PLATFORM_OWNER`) |
| DELETE | `/tenant-context` | Clear acting tenant context (`PLATFORM_OWNER`) |

**TestPersonaController — `/api/dev/test-personas`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List available personas |
| POST | `/{personaKey}/token` | Issue JWT for persona |

Only registered when `app.test-personas.enabled=true`.

**TenantAdministrationController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants` | List tenants accessible to the caller |
| POST | `/platform/tenants` | Create tenant (`PLATFORM_OWNER`) |
| GET | `/platform/tenants/{tenantId}` | Get tenant (`PLATFORM_OWNER`) |
| PATCH | `/platform/tenants/{tenantId}/status` | Update tenant status |
| PATCH | `/platform/tenants/{tenantId}/quotas` | Update entitlement quotas |
| DELETE | `/platform/tenants/{tenantId}` | Delete tenant |
| GET | `/platform/users` | List platform users |
| GET | `/platform/inventory-connectors/health` | Connector health across tenants |
| POST | `/platform/users` | Upsert platform user |
| DELETE | `/platform/users/{userId}/roles/{role}` | Revoke a role |
| POST | `/platform/users/{userId}/setup-link` | Issue password setup link |
| GET | `/tenants/{tenantId}/members` | List members (`TENANT_ADMIN`) |
| POST | `/tenants/{tenantId}/members` | Add member |
| PATCH | `/tenants/{tenantId}/members/{memberId}` | Update member |
| DELETE | `/tenants/{tenantId}/members/{memberId}` | Remove member |
| GET | `/tenants/{tenantId}/invites` | List invites |
| POST | `/tenants/{tenantId}/invites` | Create invite |
| POST | `/tenants/{tenantId}/invites/bulk` | Bulk invite |
| POST | `/tenants/{tenantId}/invites/{inviteId}/resend` | Resend invite |
| DELETE | `/tenants/{tenantId}/invites/{inviteId}` | Cancel invite |

**TenantInviteController — `/api/tenant-invites`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{token}` | Validate invite token |
| POST | `/{token}/accept` | Accept invite |

**ServiceAccountController — `/api/service-accounts`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List service accounts |
| POST | `/` | Create service account (`TENANT_ADMIN`) |
| DELETE | `/{accountId}` | Delete account |
| POST | `/{accountId}/deactivate` | Deactivate account |

### Demo

**DemoController — `/api/demo`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/seed` | Seed demo data advisories (`PLATFORM_OWNER`) |

**DemoLifecycleController — `/api`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/demo-requests` | Submit a demo request (public) |
| GET | `/platform/demo-requests` | List demo requests (`PLATFORM_OWNER`) |
| POST | `/platform/demo-requests/{requestId}/approve` | Approve |
| POST | `/platform/demo-requests/{requestId}/reject` | Reject |
| POST | `/platform/demo-requests/{requestId}/resend-invite` | Resend invite |
| POST | `/platform/demo-requests/{requestId}/issue-setup-link` | Issue setup link |
| DELETE | `/platform/demo-requests/{requestId}` | Delete request |
| GET | `/demo-invites/{token}` | Validate invite token |
| POST | `/demo-invites/{token}/accept` | Accept invite (returns setup token) |
| GET | `/demo/status` | Get demo status for the current tenant |

### Platform

**PlatformVulnRepoController — `/api/platform/vuln-repo`** (all endpoints `PLATFORM_OWNER`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Platform-wide vulnerability repo dashboard |
| GET | `/vulnerabilities` | List all vulnerabilities, platform-wide |
| GET | `/source-stats` | Source statistics |
| GET | `/intel/{externalId}` | Vulnerability intel detail |

**OperationsOverrideController — `/api/operations`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/quality/issues/{issueId}/normalize/impact` | Normalization override impact preview |
| POST | `/quality/issues/{issueId}/normalize` | Apply normalization override (`@SensitiveTenantAction`) |
| DELETE | `/quality/issues/{issueId}/normalize` | Revoke normalization override |
| POST | `/quality/issues/{issueId}/correlate` | Apply correlation override |
| DELETE | `/quality/issues/{issueId}/correlate` | Revoke correlation override |
| GET | `/software-identities/search` | Software identity autocomplete search |

**VulnerabilityArchiveController — `/api/operations/vulnerability-archive`** (all endpoints `PLATFORM_OWNER`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/migrate` | Migrate existing vulnerability data to archive |
| GET | `/{externalId}/description` | Get archived description |
| GET | `/{externalId}/raw-payload` | Get archived raw payload |
| GET | `/status` | Get archive migration status |

**UpgradeRecommendationController — `/api/upgrade-recommendation`**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/` | Get upgrade recommendation (`TENANT_ADMIN`/`SECURITY_ANALYST`) |

**AuditEventController — `/api/audit-events`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List audit events (`PLATFORM_OWNER`/`TENANT_ADMIN`) |
| GET | `/export` | Export as CSV |
| GET | `/support-bundle` | Get support bundle |
| GET | `/platform-users` | Platform user audit events (`PLATFORM_OWNER`) |

**SloController — `/api/slo`**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | SLO compliance status (`PLATFORM_OWNER`) |

### ApiExceptionHandler

`@RestControllerAdvice` providing consistent error responses for all controllers: 404 (entity not found), 400 (validation), 403 (authorization), 429 (quota exceeded), demo access violations, 409 (lock contention/data integrity), 500 (generic).

---

## External Integrations (Clients)

### NVD API (`NvdApiClient`)

Fetches CVE data from NIST National Vulnerability Database. Used in daily incremental sync (`01:00` UTC) and on-demand CVE lookups. API key via `NVD_API_KEY`.

### EUVD API (`EuvdApiClient`)

European Union Vulnerability Database — alternative CVE source.

### JVN API (`JvnApiClient`)

Japan Vulnerability Notes — Japanese CVE database.

### GitHub API (`GithubApiClient`)

SBOM ingestion from GitHub repos (dependency graph export) and GHCR (container image attestations). Also GHSA (GitHub Security Advisory) feed sync. Token via file `backend/secrets/github-api-token` or `GITHUB_API_TOKEN`.

### EOL API (`EolApiClient`)

Fetches product lifecycle data from endoflife.date. Drives the 4-stage EOL pipeline (Sunday, stages 1–4).

### AWS (`AwsDiscoveryClient`, `AwsCredentialProvider`)

Discovers EC2 instances via AWS SSM. Supports IAM role assumption, access keys, and instance profile auth. Multi-account via cross-account role ARN + external ID in `AwsDiscoveryTarget`.

### Azure (`AzureDiscoveryClient` and related)

Discovers compute/platform resources per subscription. Supports `CLIENT_SECRET` and `MANAGED_IDENTITY` auth. Multi-subscription via `AzureDiscoveryTarget` (`azure_discovery_configs`/`azure_discovery_targets`, added in V40/V41). Mirrors the AWS Discovery client architecture; newer and less exercised in production.

### OpenAI (`OpenAiClient`)

AI investigation summaries, CVE triage, and AI-assisted actions. Gated by `OPENAI_ENABLED`. Results persisted in `org_cve_ai_artifacts` to avoid redundant API calls.

### Resend (`ResendEmailClient`)

Transactional email (invite delivery, notifications). API key via `RESEND_API_KEY`.

### Outbound HTTP Infrastructure

All outbound HTTP calls go through `OutboundHttpClient` which wraps Spring's `RestClient`. Configured via `OutboundPolicy` / `OutboundPolicyFactory`. `OutboundFailureClassifier` categorizes failures. `OutboundFailureDecision` controls retry vs. circuit-break behavior. `OutboundPolicyDefaults` provides sensible per-service defaults. `AdvisoryFetchService` handles bulk advisory fetching for CSAF/VEX sources.

---

## Service Layer

### SBOM Ingestion (`service/sbomingestion/`)

Parses CycloneDX and SPDX SBOMs, normalizes component names and versions, resolves CPEs against `cpe_dim`, writes `inventory_components` and `inventory_component_cpe_map`. Deduplicates components within a tenant by normalized identity.

### CMDB Ingestion (`service/cmdbingestion/`)

ServiceNow CMDB sync: pulls CI records, resolves identity via `IdentityMatchRule`, writes `assets` and `cis`. SCCM sync performs full sweep of device records. Both write to `software_instances` and `discovery_models`.

### Vulnerability Ingestion (`service/vulningestion/`)

Processes NVD CVE JSON, GHSA advisories, CISA KEV list, and Microsoft/Red Hat CSAF/VEX documents. Writes `vulnerabilities`, `vulnerability_targets`, and `vex_assertions`. `ApplicabilityDecisionService` re-evaluates component states after new intel arrives.

### Finding Service

`FindingService` drives finding lifecycle: create when `component_vulnerability_state` flips to applicable, reopen when suppression expires or VEX assertion is withdrawn, resolve when component is patched or suppressed. Delta queue (`finding_delta_queue`) batches state changes, drained every 2 seconds in batches of 100.

### EOL Pipeline

Four-stage weekly pipeline (Sunday):
1. Catalog refresh — fetch product list from endoflife.date
2. Release data — fetch release cycles per product
3. Slug resolution — match `inventory_components` to EOL catalog slugs (AI-assisted via OpenAI)
4. Denormalization — write `is_eol`, `eol_days_remaining`, `eol_date` onto `inventory_components`

### Ownership Rule Evaluation

`OwnershipRuleEvaluationService` evaluates `ownership_rules` by priority when findings are created or updated. First matching rule assigns ownership. Evaluated server-side, not stored as a trigger.

### Findings Score

`FindingsScoreService` evaluates the `findings_score_config` JSONB from `risk_policies` against each finding's attributes. Score (0–10) returned as `findingsScore` on every `FindingResponse`. `FindingsScoreRecomputeService.recomputeAll()` is triggered by `POST /api/risk-policy/recompute-findings-scores`.

### Suppression

Suppression rules evaluated at finding creation and on the 15-minute reopen sweep. `SuppressionRuleService` handles expiry, transitions, and finding state changes triggered by rule changes. All approved rules are also re-run nightly (midnight).

### Remediation Campaigns

`CampaignController`/`CampaignService` group findings/CVEs under a tracked remediation effort with lifecycle states (DRAFT, ACTIVE, PAUSED, BLOCKED, IN_REVIEW, CLOSED, CANCELLED), per-item exceptions, notify groups, and a watchlist. Frontend at `/vuln-repo/campaigns`.

### BOM / CBOM

`BomController` (`/api/bom`) handles general Bill-of-Materials ingestion (fetch by URL or upload) with dashboard/support/lineage views. `CbomController` (`/api/bom/cbom`) tracks cloud/container BOM posture and risk findings per asset, with an accept-finding workflow.

---

## Configuration Properties

| Property | Env var | Default | Description |
|----------|---------|---------|-------------|
| `app.api-key` | `APP_API_KEY` | `change-me-in-prod` | API key for `X-API-Key` auth |
| `app.creator-key` | `APP_CREATOR_KEY` | (none) | Creator key for elevated access |
| `app.allow-api-key-auth` | `APP_ALLOW_API_KEY_AUTH` | `false` | Enable API key auth path |
| `app.allow-header-tenant-selection` | `APP_ALLOW_HEADER_TENANT_SELECTION` | `false` | Allow `X-Tenant-ID` header |
| `app.require-tenant-context` | `APP_REQUIRE_TENANT_CONTEXT` | `true` | Reject requests without tenant |
| `app.test-personas.enabled` | `APP_TEST_PERSONAS_ENABLED` | `false` | Enable test persona endpoints |
| `app.jwt.hmac-secret` | `APP_JWT_HMAC_SECRET` | — | HMAC secret for HS256 JWT signing |
| `app.jwt.issuer-uri` | `APP_JWT_ISSUER_URI` | — | OIDC issuer for RS256 JWT validation |
| `app.security.bootstrap.platform-owners.enabled` | `APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED` | `false` | Seed platform-owner identities from config at startup |
| `app.security.bootstrap.platform-owners.users[n].email` | `APP_PLATFORM_OWNER_BOOTSTRAP_USERS_<N>_EMAIL` | — | Login email for a seeded platform owner |
| `app.cors.allowed-origins` | `APP_CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | Comma-separated CORS origins |
| `app.credential-encryption-key` | `APP_CREDENTIAL_ENCRYPTION_KEY` | — | AES-256 key (base64) for credential storage |
| `spring.datasource.url` | `DB_URL` | `jdbc:postgresql://localhost:5432/vulnwatch` | Database URL |
| `openai.enabled` | `OPENAI_ENABLED` | `false` | Enable OpenAI integration |
| `openai.api-key` | `OPENAI_API_KEY` | — | OpenAI API key |
| `nvd.api-key` | `NVD_API_KEY` | — | NVD API key (higher rate limit) |
| `resend.api-key` | `RESEND_API_KEY` | — | Resend email API key |
| `github.api-token` | `GITHUB_API_TOKEN` | — | GitHub personal access token |

---

## Scheduled Jobs

| Time | Job |
|------|-----|
| `00:15` daily | Lifecycle date sweep (EOL/EOS transitions) |
| `01:00` daily | NVD incremental + KEV sync |
| `01:15` daily | GHSA sync |
| `01:45` daily | Microsoft + Red Hat CSAF/VEX sync |
| `02:05` daily | Mark stale assets inactive |
| `02:30` daily | VEX staleness recompute |
| `03:15` daily | EPSS score refresh |
| `07:00` daily | ServiceNow incident status sync |
| `02:00` Sunday | EOL catalog refresh (stage 1) |
| `03:00` Sunday | EOL release data (stage 2) |
| `03:30` Sunday | EOL slug resolution (stage 3) |
| `04:00` Sunday | EOL denormalization (stage 4) |
| Every 5 min | GitHub SBOM sources |
| Every 5 min | ServiceNow / SCCM / AWS Discovery / Azure Discovery scheduled syncs |
| Every 15 min | Reopen expired suppressions |
| Every 2 sec | Drain `finding_delta_queue` (batches of 100) |
| Every 2 sec | Poll `ingestion_jobs` queue (`IngestionJobWorkerService`) |
| Every 5 sec | Poll queued vulnerability ingestion runs (`VulnerabilityQueuedRunWorkerService`) |
| Every 5 min | Refresh stale finding projections (`FindingProjectionMaintenanceService`) |
| Every 5 min | Reconcile BOM projection drift (`BomProjectionReconciliationService`) |
| Every 30 sec | Performance telemetry snapshot refresh |
| Hourly | Policy-based auto-close findings |
| Hourly (at :10) | Demo tenant expiry check |
| Midnight | Re-run all approved suppression rules |

---

## Actuator Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /actuator/health` | Overall health |
| `GET /actuator/health/readiness` | Readiness probe |
| `GET /actuator/health/liveness` | Liveness probe (prod only) |
| `GET /actuator/info` | Build info |
| `GET /actuator/prometheus` | Micrometer/Prometheus scrape endpoint for explicitly enabled local or certification environments |

---

## Operational Metrics

`OperationalMetricsInterceptor` tracks response time (ms) for 23 monitored endpoints. Metrics are exposed for query via `OperationalDashboardController`.
