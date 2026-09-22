# VulnWatch — End-to-End Business Logic Guide

Last updated: 2026-09-08

**Audience:** Engineers and product stakeholders who need to understand how the platform works end-to-end.

---

## Core Concept: What VulnWatch Does

VulnWatch is a vulnerability operations platform. It answers: *"Which of our software components have known vulnerabilities, how bad are they, and what should we do about them?"*

The pipeline is:

```
Inventory IN          →   Vulnerability Intel IN    →   Correlation
(SBOMs, CMDB sync,        (NVD, GHSA, KEV, CSAF,       (CPE join +
 AWS discovery)            EPSS, EUVD, JVN)             version check)
                                                             ↓
                                                      Findings + Workflow
                                                      (triage, assign,
                                                       suppress, resolve)
```

---

## Multi-Tenant Architecture

### Schema-Per-Tenant Isolation

Every tenant gets its own PostgreSQL schema. The `TenantAwareDataSource` wraps HikariCP and sets `search_path = <tenant_schema>, public` on every connection checkout. This means:

- Tenant A cannot query Tenant B's data even with a crafted query — the schema isn't in the search path.
- Platform-level tables (`tenants`, `app_users`, `tenant_memberships`, etc.) live in the `platform` schema.
- Per-tenant operational tables (`findings`, `assets`, `inventory_components`, `org_cve_records`, etc.) live in each tenant's schema.

### Tenant Context Flow

1. `TenantResolutionFilter` runs on every request, extracts tenant ID from JWT claim or header, stores in thread-local `TenantContext`.
2. `TenantStatusFilter` follows — blocks suspended/expired tenants with HTTP 403.
3. All repository calls execute within the correct schema automatically via connection-level search path.
4. `TenantSchemaService` creates new tenant schemas by cloning `tenant_default`.

### Tenant Lifecycle

States: `ACTIVE`, `TRIAL`, `SUSPENDED`, `EXPIRED`, `DEMO`.

Demo tenants auto-expire after 7 days. `DemoTenantExpiryJob` runs hourly, marks expired demos as `SUSPENDED`. `DemoTenantPurgeService` handles schema cleanup. `DemoDatasetProvisioningService` (polls every 30s by default) seeds or repairs a requested tenant's demo dataset once it reaches `ACTIVE`; `DemoDatasetController` (`POST /api/platform/tenants/{tenantId}/demo-data`, `PLATFORM_OWNER`) can trigger this manually.

### Tenant-Authorized Support Access

`TenantSupportAccessController` (its supporting schema predates the migration-history reset and now lives in the `tenant/V1__tenant_schema.sql` baseline) lets a tenant admin grant a time-boxed, break-glass platform-owner access grant (`POST /api/tenants/{tenantId}/support-grants`, `TENANT_ADMIN`), which the invited platform owner then accepts (`POST /api/auth/support-grants/{grantId}/accept`). This is distinct from — and layers on top of — the existing `tenant_support_grants` table and `TenantSupportGrant` lifecycle described elsewhere in this doc; the new piece is that the *tenant* can initiate the grant rather than only the platform owner requesting access.

---

## Inventory Pipeline

### SBOM Ingestion

SBOMs arrive via three paths:
1. **File upload** — `POST /api/ingestion/sbom` with multipart file
2. **Endpoint fetch** — backend pulls SBOM from a configured URL on a schedule
3. **GitHub** — periodic fetch from GitHub dependency graph or GHCR attestation for configured repos

**Processing flow:**
1. Parse SBOM (CycloneDX JSON/XML or SPDX JSON/tag-value)
2. Normalize each component: name, version, PURL, CPE
3. Resolve or create `SoftwareIdentity` (deduplication by normalized name + ecosystem)
4. Create/update `InventoryComponent` records linking identity to asset
5. Resolve CPEs: match against `cpe_dim` and write `inventory_component_cpe_map`
6. Update `SbomUpload` status to COMPLETE or FAILED

**Deduplication:** Components are deduplicated by `(softwareIdentityId, assetId)`. Re-ingesting the same SBOM updates version and metadata; it does not create duplicate rows.

### CMDB Sync (ServiceNow)

`ServiceNowCmdbSyncService` pulls CI records from ServiceNow CMDB using the configured instance URL and credentials.

**Flow:**
1. Fetch CI records (Hardware CIs, Software CIs) from ServiceNow table API
2. Resolve each CI to an `Asset` using `IdentityMatchRule` (match on hostname, IP, serial number, or ServiceNow sys_id)
3. Create `CiAlias` records for alternative identifiers
4. Write `Ci` records linking ServiceNow CI metadata to Scout assets
5. Write `SyncRun` with outcome metrics

### CMDB Sync (SCCM/MECM)

`SccmCmdbSyncService` performs a full sweep against the SCCM/MECM database via JDBC (MSSQL). Each run is a full sweep — no delta sync.

**Flow:**
1. Connect to SCCM DB using configured credentials (`SccmCmdbConfig`)
2. Query device inventory tables
3. Map device records to `Asset` + `SoftwareInstance` records
4. Write `DiscoveryModel` with field mapping and raw payload

### AWS Discovery

`AwsDiscoveryClient` discovers EC2 instances via AWS Systems Manager (SSM).

**Flow:**
1. Resolve credentials via `AwsCredentialProvider` (IAM role assumption, access keys, or instance profile)
2. For each configured `AwsDiscoveryTarget` (account + region + optional role ARN):
   - Call `DescribeInstanceInformation` via SSM to get managed instance inventory
   - Map instance metadata (instance ID, OS, platform) to Scout `Asset` records
   - Write `DiscoveryModel` with raw AWS payload
3. Multi-account supported via cross-account role ARN + external ID

**Auth types** (`AwsAuthType` enum): `IAM_ROLE`, `ACCESS_KEY`, `INSTANCE_PROFILE`.

### Azure Discovery

`AzureDiscoveryController` (`/api/connectors/azure-discovery`) mirrors the AWS Discovery architecture for Azure subscriptions (newer and less battle-tested than AWS Discovery).

**Flow:**
1. Resolve credentials via `CLIENT_SECRET` or `MANAGED_IDENTITY` auth
2. For each configured `AzureDiscoveryTarget` (per-subscription scope):
   - Discover compute/platform resources within the subscription
   - Map resource metadata to Scout `Asset` records

---

## Vulnerability Intelligence Pipeline

### Sources

| Source | Schedule | Data |
|--------|----------|------|
| NVD | Daily 01:00 + incremental | CVE records, CVSS scores, CPE applicability |
| CISA KEV | Daily 01:00 | Known-exploited CVE list |
| GHSA | Daily 01:15 | GitHub Security Advisories |
| Microsoft CSAF/VEX | Daily 01:45 | Microsoft product VEX assertions |
| Red Hat CSAF/VEX | Daily 01:45 | Red Hat product VEX assertions |
| EPSS | Daily 03:15 | Exploit Prediction Scoring System scores |
| EUVD | On-demand | EU Vulnerability Database |
| JVN | On-demand | Japan Vulnerability Notes |

### What Gets Written

- `vulnerabilities` — one row per CVE with CVSS base score, description, published date
- `vulnerability_targets` — CPE match patterns for each CVE (drives correlation)
- `vulnerability_intel_summary` — read-model projection aggregating all intel for a CVE
- `vulnerability_intel_observations` — per-CVE signals (KEV membership, EPSS score, CSAF assertions)
- `vex_assertions` — VEX statements from CSAF documents

### VEX Processing

CSAF documents contain VEX statements asserting whether specific product versions are affected, not affected, fixed, or under investigation. `VexAssertion` entities store these statements. The `VexStalenessRecomputeJob` (daily 02:30) re-evaluates VEX assertions against current inventory to handle document updates.

---

## Correlation Engine

The correlation engine answers: *"Which of our software components match CVE applicability criteria?"*

### CPE-Based Matching

1. `InventoryComponentCpeMap` links each inventory component to normalized CPE 2.3 strings
2. `vulnerability_targets` stores the CPE patterns from NVD (with version range constraints)
3. A join on CPE product + vendor produces candidate matches
4. `ApplicabilityDecisionService` evaluates version constraints (using `VersionScheme`-aware comparison) to confirm or reject each candidate

**Result:** `ComponentVulnerabilityState` records — one row per `(inventoryComponent, vulnerability)` pair with `applicabilityState` (APPLICABLE, NOT_APPLICABLE, UNKNOWN).

### Org CVE Records

`org_cve_records` is a rollup projection: one row per `(tenantId, cveId)`. It aggregates:
- `matchedAssetCount` — distinct assets with applicable software
- `matchedSoftwareCount` — distinct software components matched
- `maxSeverity` — highest severity across all matches
- `hasKev` — whether the CVE is in CISA KEV
- `epssScore` — current EPSS score
- `orgImpact` — assessed organizational impact
- `applicabilityState` — overall state for the org (APPLICABLE, PARTIALLY_APPLICABLE, NOT_APPLICABLE)

This table drives the **CVE Assessment Workbench** UI.

---

## Finding Lifecycle

### What is a Finding?

A `Finding` represents a specific, actionable security issue: a vulnerability (CVE) that is applicable to an asset in the tenant's inventory and requires a decision.

Findings are created automatically when `ComponentVulnerabilityState` transitions to APPLICABLE, or manually via `FindingCreationSource.MANUAL`.

### States

```
OPEN → ACKNOWLEDGED → IN_PROGRESS → RESOLVED
  ↓                              ↑
SUPPRESSED ──────────────────────┘ (if suppression expires)
  ↓
FALSE_POSITIVE
  ↓
RISK_ACCEPTED
```

`FindingStatus` enum: `OPEN`, `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `SUPPRESSED`, `FALSE_POSITIVE`, `RISK_ACCEPTED`.

### Finding Events

Every status transition is recorded as a `FindingEvent` with actor, timestamp, and reason. This provides a complete audit trail for each finding.

### Delta Queue

`FindingDeltaQueueEntry` records pending state changes. The drain job processes batches of 100 every 2 seconds, applying changes atomically. This decouples the correlation engine (which produces many changes) from the finding service (which must handle them correctly).

### Finding Generation Modes

`RiskPolicy.findingGenerationMode`:
- `AUTO` — findings created automatically when correlation determines applicability
- `MANUAL` — analysts must explicitly promote an org-CVE record to a finding

### Auto-Close

The hourly auto-close job closes OPEN findings that meet the policy criteria (configurable in `RiskPolicy.autoClose*` fields). Typically used to close low-severity findings after a configurable number of days without action.

---

## Suppression System

`SuppressionRule` entities define conditions under which findings or CVE records are suppressed.

**Lifecycle:** DRAFT → IN_REVIEW → APPROVED (active) → EXPIRED.

**Evaluation:**
1. When a finding is created, all APPROVED suppression rules are evaluated
2. If a rule matches, the finding is created in `SUPPRESSED` state
3. The 15-minute reopen job re-evaluates expired suppressions and reopens affected findings
4. Rules have an `executionOrder` — lower order evaluated first

**Suppress CVE (org-wide):** `POST /api/cve-detail/{cveId}/suppress` is a shortcut that creates a CVE-scoped suppression rule and suppresses all existing findings for that CVE.

---

## Risk Policy

The `RiskPolicy` is a single record per tenant (created on tenant provisioning) that drives multiple behaviors:

| Field group | Effect |
|-------------|--------|
| `sla*` (critical/high/medium/low deadlines, asset criticality multipliers) | SLA breach calculation on findings |
| `triage*` (6 weight fields: exploitability, blast radius, EOL risk, SLA breach, missing owner, patch gap) | S.AI Priority score weighting |
| `autoClose*` (enabled, days) | Hourly auto-close job behavior |
| `findingGenerationMode` | AUTO vs. MANUAL finding creation |
| `findingsScoreConfig` (JSONB) | Custom attribute-based finding score rules |

---

## End-of-Life (EOL) Tracking

### Four-Stage Pipeline (Weekly, Sunday)

1. **Catalog refresh** — fetch all products from endoflife.date API → write `EolProductCatalog`
2. **Release data** — fetch release cycles for each product → write `EolRelease`
3. **Slug resolution** — for each unique `SoftwareIdentity`, match to an EOL product slug. Uses OpenAI to suggest slugs for unmatched identities. Confirmed mappings stored in `SoftwareEolMapping`
4. **Denormalization** — compute `is_eol`, `eol_days_remaining`, `eol_date` for each `InventoryComponent` based on its version and the matched EOL release data

### Daily Lifecycle Sweep (00:15)

Checks for components that have crossed their EOL date since the last run and updates `is_eol` flags and triggers any configured alerts.

---

## AI Integration (OpenAI)

Gated by `OPENAI_ENABLED=true`. Results are persisted in `OrgCveAiArtifact` after first generation — subsequent reads return the cached result without calling OpenAI again.

**AI features:**

| Feature | Endpoint | What it does |
|---------|----------|-------------|
| Investigation summary | `POST /api/cve-detail/{cveId}/ai-summary` | Generates a natural-language summary of a CVE's impact on the org, citing matched assets |
| EOL slug suggestion | Internal (EOL stage 3) | Suggests endoflife.date slugs for unmatched software identities |

The `VulnerabilityIntelSummary` entity stores `aiSummary` and `aiSummaryGeneratedAt` fields.

---

## Ownership Rules

`OwnershipRule` entities define conditions for auto-assigning findings to users or groups.

**Evaluation:**
1. Rules are ordered by `priority`
2. Each rule's `conditions` (JSONB array: field + operator + value) are evaluated against the finding
3. First matching rule sets `finding.assignee`
4. Re-evaluated when findings are created or when ownership rules are updated

**Operators** (common): `equals`, `contains`, `starts_with`, `in`, `not_in`.

**Fields** (common): asset name, asset criticality, CVE severity, affected component name, business unit tag.

---

## ServiceNow Incident Integration

`POST /api/cve-detail/{cveId}/servicenow-incident` creates a ServiceNow incident linked to a finding.

- `incident_id` and `incident_status` are stored on the `Finding` entity
- `FindingIncidentSyncService` runs daily at 07:00 and pulls updated incident states from ServiceNow back into Scout findings
- Integration is not fully bi-directional — Scout reads incident state but does not push finding state changes back to ServiceNow

---

## Remediation Campaigns

`CampaignController` (`/api/campaigns`) — undocumented in earlier drafts of this guide, but a fully shipped feature (frontend at `/vuln-repo/campaigns`, `CampaignsPage`/`CampaignDetailPage`).

A **Campaign** groups findings/CVEs into a tracked remediation effort:

- **Lifecycle:** `DRAFT` → `ACTIVE` → `PAUSED` / `BLOCKED` / `IN_REVIEW` → `CLOSED` / `CANCELLED`.
- **Exceptions:** individual findings/CVEs within a campaign can be marked exempt from the campaign's remediation requirement, with their own status workflow.
- **Notify groups:** teams/individuals subscribed to campaign status changes.
- **Watchlist:** entries tracked for visibility without being formally part of the remediation scope.
- **Notes:** free-form campaign annotations.
- The frontend detail page includes AI-assisted insights (OpenAI-backed, same `OPENAI_ENABLED` gate as CVE investigation summaries) and can bulk-add assets, CVEs, or software to a campaign.

## Cloud/Container BOM (CBOM)

`BomController` (`/api/bom`) handles general Bill-of-Materials ingestion (fetch by URL or file upload), with dashboard, support-matrix, and lineage views per BOM. `CbomController` (`/api/bom/cbom`) is a specialized branch tracking cloud/container posture: per-asset CBOM posture summaries, components, and risk findings with an analyst accept-finding workflow. The Connect page's `bom-management` connector exposes SBOM, AI-BOM, CBOM, and Vendor-BOM ingestion in one place.

## AI Security / AI Grid Pipeline

Not to be confused with [AI Integration (OpenAI)](#ai-integration-openai) above — that section covers VulnWatch *using* an LLM internally (EOL slug suggestion, CVE investigation summaries). This section covers VulnWatch *discovering and governing other systems'* AI/ML resources (Bedrock agents, Azure AI Foundry projects, MCP servers, etc.) as a security posture management capability, entitlement-gated per tenant behind the `ai.security` key (`TenantEntitlementService.AI_SECURITY`). It backs the `/findings/ai`, `/policies`, and `/inventory/ai` frontend routes and lives in its own top-level backend package, `com.prototype.vulnwatch.aisecurity` (14 controllers, 48 services — separate from the main `controller`/`service` packages).

AI Grid is the sole policy and findings generation. It evaluates governed, versioned policies against discovered artifacts; canonical findings retain the host workflow. `AiSecurityController` remains only for shared artifact inventory, graph, discovery-run, and compatibility finding reads.

### Discovery

`AiSecurityJobWorkerService` polls `ingestion_jobs` for `AI_SECURITY_AWS_BEDROCK` / `AI_SECURITY_AZURE_DISCOVERY` job types (every 3s by default) and dispatches to a provider:

- **AWS** (`AwsBedrockDiscoveryService`) — via AWS SDK v2, discovers Bedrock agents/action-groups/knowledge bases/guardrails/models/inference profiles/prompts/flows, AgentCore gateways/targets, and SageMaker domains/endpoints/pipelines; checks IAM policies for wildcard actions, Lambda function-URL auth, and S3 bucket public-access status. Optionally reads *existing* AWS Macie PII classification findings for referenced S3 buckets (`AwsMaciePiiLookupService` — never triggers a new Macie scan). Gated by `AiSecurityAwsAdmissionService` (per account/region semaphores) and the budget service below. A set of default-off flags additionally builds a version-rooted definition graph, an IAM identity graph and AgentCore execution-surface inventory — see [AWS deployed-agent graph](#aws-deployed-agent-graph) below.
- **Azure** (`AzureAiDiscoveryService` / `AzureAiManagementClient`) — raw ARM API calls discovering Cognitive Services/AI accounts, Foundry projects/deployments/RAI policies/agents, ML workspaces/endpoints, AI Search services/indexers/knowledge sources, Bot Service, diagnostic settings, RBAC assignments, Storage accounts. `AzureRaiPolicyAnalyzer` conservatively parses RAI content-filter configs. Optionally reads *existing* Microsoft Purview Data Map classification results for Storage accounts (`AzurePurviewClassificationClient` — read-only). Gated by `AiSecurityAzureAdmissionService` and a config-driven kill switch (`AiSecurityAzureKillSwitchService`).

A third provider, **Microsoft Copilot Studio** (`CopilotStudioDiscoveryService` / `CopilotStudioDataverseClient`), is wired differently: `CopilotStudioConnectorController`'s `POST /{connectorId}/run` calls `discovery.run()` synchronously in the request thread rather than enqueueing an `ingestion_jobs` row for the poller above. It calls the Dataverse API for the configured organization to enumerate bots/topics/prompt components (metadata only), starts and completes its own `SyncRun` (`AI_SECURITY_COPILOT_STUDIO`) inline, and still emits an `ObservationEnvelopeV1` (`provider = MICROSOFT_COPILOT`) into `AiSecurityObservationService` so it feeds the same AI Grid pipeline below — it just never appears as a QUEUED/RUNNING `ingestion_jobs` row the way AWS/Azure discovery does.

Both async connectors emit `ObservationEnvelopeV1` chunks (validated, allow-listed-field-only via `AiSecurityMetadataSanitizer` — no prompt bodies, secrets, or free-text PII) which `AiSecurityObservationService` persists idempotently by receipt and, once a scan scope completes, hands to the AI Grid pipeline.

#### AWS deployed-agent graph

AWS posture is derived from the canonical deployed definition graph. Discovery is bounded by the shared provider-call ceiling; connector enablement, kill switches, budgets, concurrency, retries, and separately costed integrations remain operational controls.

```text
AI_AGENT
  ├── HAS_COMPONENT ──> AWS_BEDROCK_AGENT_ALIAS (AI_COMPONENT)
  │                        └── SERVES_VERSION ──> AI_AGENT_VERSION

AI_AGENT_VERSION (AWS_BEDROCK_AGENT_VERSION)
  ├── VERSION_OF ──> AI_AGENT
  ├── USES_MODEL ──> AI_MODEL
  ├── USES_PROMPT ──> AI_PROMPT            (digest only, never the body)
  ├── USES_TOOL ──> AI_TOOL                (AWS_BEDROCK_ACTION_GROUP)
  ├── USES_KNOWLEDGE_BASE ──> KNOWLEDGE_BASE
  ├── USES_GUARDRAIL ──> AI_GUARDRAIL      (exact guardrail version)
  └── ASSUMES_ROLE ──> AWS_IAM_ROLE

AI_TOOL ── IMPLEMENTED_BY ──> AWS_LAMBDA_FUNCTION
```

Semantics worth knowing before extending this:

- **Alias routing is the authority on what is served.** `DRAFT` is collected as a version like any other, but a version counts as deployed only because some alias's `routingConfiguration` points at it. Multiple aliases and multiple served versions per agent are supported — there is no single "active version".
- **Four distinct evidence states** are modelled and must not be conflated in UI or policy copy: *configured* (attached to the definition), *reachable* (an evidence-backed graph path exists), *activity observed* (a governed external source reported activity), *confirmed* (an exposure template's evidence contract is satisfied).
- **Retyping, not re-keying.** AWS prompts, guardrails, action groups, AgentCore runtimes/browsers/code-interpreters/memories and IAM roles moved off `OTHER_AI_ARTIFACT` onto canonical types (`AI_PROMPT`, `AI_GUARDRAIL`, `AI_TOOL`, `AI_COMPONENT`, `SUPPORTING_RESOURCE`) while keeping their provider ARN as `provider_resource_id`, so artifact identity and history survive the change. Provider-native-kind scoping remains authoritative for policy applicability — canonical types were *not* bulk-added to AWS policy packages.
- **No compatibility edges or copied posture facts.** Knowledge bases and roles attach to the served version, and tool implementations attach through `IMPLEMENTED_BY`; agent-level copies and `INVOKES_LAMBDA` are not emitted.
- **No inferred AgentCore edges.** AgentCore runtimes, browsers, code interpreters and memories are inventoried, but no `CONNECTS_TO_MCP` or agent→runtime edge is emitted, because no authoritative control-plane field links a classic Bedrock agent to an AgentCore runtime. Unattached AgentCore resources are meant to surface as coverage/ownership work, not as a guessed relationship.
- **Per-role IAM isolation.** One malformed or unreadable role degrades that role only (`IAM_GLOBAL` → `PARTIAL`, diagnostic `IAM_ROLE_EVIDENCE_PARTIAL`, role ARN hashed); it does not void global IAM evidence.
- **Disabled ≠ empty.** A disabled connector or separately controlled integration emits `DISABLED`; an authoritatively empty list probe emits verified-empty evidence instead of permission remediation.

#### Curated AWS activity evidence

The first release intentionally excludes continuous CloudWatch log ingestion, log normalization, per-run AWS execution timelines, and any external write to `ai_agent_executions`. Activity is instead expressed as governed, **metadata-only** host-context facts from a trusted producer `SCOUT_AWS_ACTIVITY`, posted to the existing `POST /api/internal/ai-grid/evidence/{producerId}` port (`ROLE_SERVICE_ACCOUNT`, principal must equal the producer id) and gated by `AWS_ACTIVITY_EVIDENCE`. Intended sources are customer SIEM/SOAR detections, CloudWatch alarms or customer-managed summaries, and agent gateway/runtime-control decisions — never raw prompts, responses, conversations, tool arguments, results, secrets, or personal identifiers.

Seven fact keys are authorized (`activity.agent_invocation_observed`, `.tool_use_observed`, `.identity_use_observed`, `.external_action_observed`, `.sensitive_data_access_observed`, `.invocation_count_observed`, `.agent_last_observed_at`). The `_observed` suffix is load-bearing: these keys are **non-validating** and cannot promote an exposure to `VALIDATED_EXPOSURE`. They do two things only — drive the "activity observed" state on agent/version detail, and add a bounded `activityPoints` component to `AiExposureIntelligenceService`'s exposure priority. Facts require `validUntil`, bucket `observedAt` to the UTC day so a repeated push for the same window updates in place, and stop contributing once expired (the row stays for audit). **Absence of activity evidence is not evidence of non-use** and the UI says "No activity evidence available", never "Not used".

### AI Grid Pipeline (per completed scope)

`AiGridPipelineService.processCompleteScope()` runs, in order:

1. **Snapshot** (`AiGridSnapshotService`) — commits an immutable, redacted, hash-deduped snapshot of discovered artifacts; derives versioned **facts** from it (the sole input to policy evaluation).
2. **Ownership** (`AiGridOwnershipService`) — resolves CONFIRMED / INFERRED (via `ownership_rules` — the same table used by Configurations → Ownership) / CANDIDATE (tag heuristic) / UNOWNED. Tags never get promoted to authoritative on their own.
3. **System grouping** (`AiGridSystemService`) — derives agent-rooted "AI systems" via bounded breadth-first search (depth 6, fan-out 100) over provider relationships; tracks revisions and split/merge/successor/retirement lineage across scans.
4. **Policy assessment** (`AiGridAssessmentService`) — evaluates each artifact against every policy the tenant has selected REQUIRED/ENABLED/PREVIEW for (via `AiGridPredicateEngine`, a JSON predicate evaluator over facts, with per-tenant scope conditions/exceptions/parameters), producing PASS/FAIL/NO_DECISION/ERROR/NOT_APPLICABLE decisions.
5. **Exposure correlation** (`AiGridExposureService`) — an R2-generation bounded graph-traversal engine running three hardcoded correlation templates (external sensitive-data access, excessive tool privilege, untrusted autonomous execution). Hypotheses are promoted to a **validated exposure** only when every supporting fact is exact, evidence-graded, and still fresh; `AiGridExposureFreshnessService` (60s cadence) demotes validated exposures whose supporting evidence has expired.
6. **Coverage & setup** (`AiGridReconciliationService`, `AiGridCoverageService`, `AiGridReadinessService`) — surfaces coverage gaps (unknown technology, no policy coverage, missing assessment, unresolved owner), materializes a deletion-safe "current epoch" view of the latest complete scan per scope, and generates a prioritized tenant setup-action queue.
7. **Finding bridge** (`AiGridFindingService` / `AiGridExposureFindingService`) — promotes qualifying policy failures and validated exposures into the canonical `findings` table (`finding_kind = AI_POSTURE` / `AI_EXPOSURE`, `creation_source = AI_SECURITY`), reusing the same `FindingWorkflowService`, SLA logic, and ServiceNow incident creation as CVE findings — there is no separate AI finding table.

Host-context evidence (from external CIEM/DSPM/ASM/runtime tools, or analyst attestation) can be ingested via `AiGridEvidenceIngestionController` (`ROLE_SERVICE_ACCOUNT` only) and is tracked with confidence/evidence-class rules in `AiGridHostContextService` — it can promote a fact to "validating" status only under those rules, never unconditionally.

### Governance & Release Certification (platform-scoped)

A separate platform-owner-only track gates what AI Grid content ever reaches tenants, mirroring how NVD/GHSA feeds are trusted inputs but with an explicit sign-off step because policy false positives here can misdirect security teams:

- **Policy catalog & distribution** (`AiGridPolicyCatalogService`) — platform imports immutable policy/correlation *versions* into a catalog, then controls rollout via `platform.ai_grid_policy_distribution` (GA / canary / paused / retired, canary tenant list, pinned version). V67 backfilled the earlier toggle table once; AI Grid is the only runtime authority.
- **Answer-key & precision review** (`AiGridValidationGovernanceService`) — a labeled test-case framework (`ai_grid_answer_key_*`) plus statistical (Wilson-interval) precision/bias review (`ai_grid_precision_reviews`) that a policy version must pass before it can be published.
- **Release certification** (`AiGridR1CertificationService`, `AiGridR2CertificationService`) — combines platform-computed evidence with externally attested operational gates into an immutable release manifest (`ai_grid_release_manifest_items`, update/delete blocked by a database trigger).
- **Portfolio** (`AiGridPolicyPortfolioService`) — tracks OWASP LLM Top-10 coverage and a RICE-scored intake backlog of candidate policies not yet authored.
- **Tenant policy configuration** — AI Grid owns selections, scopes, artifact overrides, and parameters; assessment reads only these governed records.

### Operations: Budget, Cadence, and Retention

`AiGridBudgetService` enforces per-tenant daily scan/API-call/byte/processing-time budgets and scan-cadence throttling (new tenants start in an `OBSERVE`-only mode), raising `ai_grid_budget_alerts` on breach. `AiGridRetentionService` classifies evidence into HOT / ARCHIVE / RESTRICTED_EVIDENCE retention tiers, supports legal holds, and runs a purge sweep that leaves a durable audit trail (`ai_grid_retention_purge_audit`) even after the underlying snapshot bodies are deleted. Both are exposed to tenant admins via `AiGridOperationsGovernanceController` (`/api/ai-governance`).

### Scheduled Jobs (AI Security / AI Grid)

| Cadence | Job |
|---|---|
| Every 3s (default) | `AiSecurityJobWorkerService` — poll `ingestion_jobs` for AWS/Azure AI discovery jobs |
| Every 60s (default) | `AiGridExposureFreshnessService` — demote validated exposures with expired evidence |
| Daily 02:20 (default) | `AiSecurityAzureCredentialExpiryService` — sweep Azure AI credential profiles for expiry |

### Known Limitations (AI Security / AI Grid)

- All AI Grid/AI Security tables are accessed via `JdbcTemplate` directly — there are no JPA entities or Spring Data repositories for this module, unlike the rest of the backend.
- Azure discovery is newer and less battle-tested than AWS; a config-driven kill switch (`AiSecurityAzureKillSwitchService`) exists specifically to disable it per tenant/connector/resource-family/policy if needed.
- Macie and Purview integrations are strictly read-only against *existing* classification results — neither path ever triggers a new PII scan.
- `com.prototype.vulnwatch.web.PlatformAdminRequestPaths` (a request-path classifier added alongside recent platform-admin hardening work) has no call site anywhere outside its own unit test as of this writing — likely wired up incompletely; verify before relying on it.

## Audit Trail

`AuditEvent` records capture state-changing operations:

- Fields: `tenantId`, `actorId`, `action`, `resourceType`, `resourceId`, `timestamp`, `detail` (JSONB)
- Stored in the `platform` schema (accessible for cross-tenant admin/support queries)
- `RequestCorrelationFilter` injects `traceId` and `requestId` into MDC; every structured log line carries both

---

## Known Limitations

- GHCR attestation ingestion does not perform cryptographic signature verification.
- SCCM sync is a full sweep on every run — no incremental delta sync.
- AWS Discovery is scoped to EC2 instances via SSM only.
- Azure Discovery mirrors the AWS Discovery architecture but is newer (V40/V41) and less exercised in production.
- S.AI Risk Score and S.AI Priority are computed entirely in the browser — not stored in the database.
- ServiceNow integration is read-heavy (finding → incident creation, then status polling) but not event-driven.
- Multi-tenant schema-per-tenant isolation is implemented (`TenantAwareDataSource`, `TenantSchemaService`, `ProductionSafetyValidator`) and `TenantService.getDefaultTenant()` is no longer used by controllers or services. Row-level security policies are created on every provisioned tenant schema, but full RLS *enforcement* across existing production tenants remains gated behind `ProductionSafetyValidator.validateRuntimeRoleCannotBypassRls()` pending verification that the production/preprod database runtime role is non-superuser and lacks `BYPASSRLS`.
- AI Security / AI Grid (see above) — see its own "Known Limitations" subsection for module-specific caveats (JdbcTemplate-only data access, Azure kill switch, read-only Macie/Purview integration).
- `EntitlementShadowSweepService` (every 30 min by default) computes corrected-vs-legacy entitlement decisions for every active tenant/key so shadow-mode coverage doesn't depend on the feature being exercised live — a sign that at least one entitlement migration is still running in shadow/compare mode rather than fully cut over.
- `FindingDeltaQueueService` has a second scheduled method (`recoverStaleProcessingEntriesOnSchedule`, 1 min by default) beyond the documented 2-second drain — it recovers queue entries stuck in `PROCESSING` after a worker dies mid-batch.
