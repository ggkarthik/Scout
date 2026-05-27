# VulnWatch — End-to-End Business Logic Guide

Last updated: 2026-05-27

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

Demo tenants auto-expire after 7 days. `DemoTenantExpiryJob` runs hourly, marks expired demos as `SUSPENDED`. `DemoTenantPurgeService` handles schema cleanup.

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

## Audit Trail

`AuditEvent` records capture state-changing operations:

- Fields: `tenantId`, `actorId`, `action`, `resourceType`, `resourceId`, `timestamp`, `detail` (JSONB)
- Stored in the `platform` schema (accessible for cross-tenant admin/support queries)
- `RequestCorrelationFilter` injects `traceId` and `requestId` into MDC; every structured log line carries both

---

## Known Limitations

- GHCR attestation ingestion does not perform cryptographic signature verification.
- SCCM sync is a full sweep on every run — no incremental delta sync.
- AWS Discovery is scoped to EC2 instances via SSM only (RDS, Lambda, S3, ECS, EKS were removed in V1069).
- S.AI Risk Score and S.AI Priority are computed entirely in the browser — not stored in the database.
- ServiceNow integration is read-heavy (finding → incident creation, then status polling) but not event-driven.
- Multi-tenant hardening is in progress; most controllers currently resolve to a single default tenant. Full multi-tenant operation requires complete resolution of the `tenant_id` compatibility tail.
