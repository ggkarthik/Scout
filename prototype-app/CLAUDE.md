# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Commands

### Backend

```bash
cd backend
mvn spring-boot:run          # start the API server (port 8080)
mvn test                     # unit tests
mvn -Ppostgres-it test       # unit + PostgreSQL integration tests
```

To repair Flyway history after schema drift:
```bash
cd backend
mvn -q \
  -Dflyway.url=jdbc:postgresql://localhost:5432/vulnwatch \
  -Dflyway.user="$USER" \
  -Dflyway.password= \
  -Dflyway.locations=filesystem:src/main/resources/db/migration/postgres \
  flyway:repair
```

### Frontend

```bash
cd frontend
npm install
npm run dev      # dev server on port 5173
npm run build    # tsc -b --force && vite build
npm run test:unit  # vitest run (non-watch)
```

There is no lint script in `package.json`.

---

## Architecture

### System Shape

VulnWatch is a security operations prototype: SBOM ingestion → vulnerability intelligence ingestion → deterministic CPE-based correlation → finding projection and workflow.

- `frontend/` — React 18 + TypeScript + Vite SPA
- `backend/` — Java 17 + Spring Boot 3.3.2, Spring Data JPA, Spring Security
- Database — PostgreSQL at `jdbc:postgresql://localhost:5432/vulnwatch`
- Schema — Flyway-owned migrations in `backend/src/main/resources/db/migration/postgres/` (`ddl-auto=none`)

### Backend Package Layout (`com.prototype.vulnwatch`)

| Package | Contents |
|---|---|
| `controller/` | ~20 REST controllers under `/api/**` |
| `service/` | ~54 business-logic services |
| `domain/` | JPA entities (assets, inventory, vulns, findings, policies, CMDB, EOL) |
| `dto/` | API request/response objects |
| `repo/` | Spring Data JPA repositories |
| `client/` | External API clients (NVD, GHSA, CSAF, EPSS, GitHub, ServiceNow, endoflife.date) |
| `config/` | Spring beans and security configuration |
| `util/` | CPE handling, version comparison, SBOM parsing |

### Core Data Flow

1. **Inventory in** — SBOMs (upload, endpoint fetch, GitHub repo/GHCR) or ServiceNow CMDB live sync write `assets`, `inventory_components`, `software_identities`, `software_instances`, and normalize CPEs into `cpe_dim` + `inventory_component_cpe_map`.
2. **Vulnerability intel in** — NVD, KEV, GHSA, Microsoft/Red Hat CSAF/VEX, advisory imports populate `vulnerabilities`, `vulnerability_targets`, and read-model projections.
3. **Correlation** — CPE joins between `inventory_component_cpe_map` and `vulnerability_targets`, version-checked by `ApplicabilityDecisionService`, write `component_vulnerability_states`.
4. **Projection** — States roll up to `org_cve_records` (one row per CVE per tenant). `FindingService` drives finding create/reopen/resolve.
5. **EOL pipeline** — 4-stage async job: catalog refresh → release cycles → slug resolution → denormalization into `inventory_components.is_eol / eol_days_remaining`.

### Projection Tables (Central to Read Performance)

- `component_vulnerability_states` — component-level CPE applicability truth
- `org_cve_records` — tenant/CVE rollup used by CVE Assessment Workbench UI
- `vulnerability_intel_summary` — vuln list read model
- `software_inventory_items` — flattened software inventory for reporting
- `software_identity_summary` — per-identity aggregation (asset/component/version counts, EOL breakdown) for Software Identities view
- `quality_issue_projection` — data quality issues by domain/severity for Operations Quality view

### Security Model

- Every `/api/**` request requires `X-API-Key`.
- `X-Creator-Key` grants `ROLE_CREATOR`; required for `/api/operations/**`.
- `X-Tenant-ID` and `X-User-ID` are used directly by CVE workflow endpoints.
- Local defaults: API key `change-me-in-prod`, creator key `local-creator`, tenant `1`, user `local-analyst`.

### Frontend Navigation

`src/App.tsx` is a sidebar shell with query-param state (`tab`, `inventoryView`, `vulnIntelView`). There is no React Router — all navigation is URL query params. Drill-downs happen in drawers and modals, not separate pages.

Top-level sections: Overview → Findings → Operational Dashboard (Quality / Pipeline / Platform Health) → Vulnerability Intelligence → Inventory → End-of-Life → Connect → Configurations.

Overview is reserved for risk metrics and risk-focused summaries only. Do not place operational, pipeline, quality, freshness, correlation-efficiency, or CSAF/VEX analytics panels on Overview; those belong under Operational Dashboard.
Correlation Efficiency and CSAF/VEX Quality Analytics live under Operations → Pipeline.

All API calls go through `src/api/client.ts`. Base URL defaults to `http://localhost:8080/api` (via `VITE_API_BASE`). Auth headers are injected on every request.

TypeScript types are co-located with their feature: `src/features/{feature}/types.ts` (e.g. `src/features/eol/types.ts`, `src/features/operations/types.ts`). Shared primitives live in `src/types/index.ts`.

### Connect Page Architecture

`ConnectPage` is a connector catalog. Clicking a source card opens a modal rendering `ConnectorDetailContent`, which delegates to a focused component per connector (e.g., `IngestionPage`, `GithubPipelineManager`, `AssetsPage`, `SourcesPage`, `EolSourcePanel`). Adding a new connector means: add to `ConnectorId` union, `CONNECTORS` array, the appropriate category list, and a `ConnectorDetailContent` case.

### Adding a Database Migration

Create `backend/src/main/resources/db/migration/postgres/V{next}__description.sql`. Flyway applies migrations in version order on startup. Never edit an already-applied migration file.

### Scheduled Jobs

| Time | Job |
|---|---|
| `01:00` daily | NVD incremental + KEV sync |
| `01:15` daily | GHSA sync |
| `01:45` daily | Microsoft + Red Hat CSAF/VEX sync |
| `02:05` daily | Mark stale assets inactive |
| `02:30` daily | VEX staleness recompute |
| Every 5 min | Run enabled GitHub SBOM sources |
| Every 15 min | Reopen expired suppressions |
| Hourly | Policy-based auto-close findings |

### Known Limitations

- `POST /api/cve-detail/{cveId}/suppress` persists suppression state via `OrgCveRecordService.suppress()` and returns a `SuppressionResponse`. Suppression expiry is handled by the 15-minute reopen job.
- Schema is tenant-aware but runtime is effectively single-tenant; most controllers call `TenantService.getDefaultTenant()`.
- `CveDetailPage.tsx` exists but is not mounted in `App.tsx`; the live CVE workflow is the CVE Assessment Workbench drawer.
- GHCR attestation ingestion does not yet perform cryptographic signature verification.

### CSS Design Tokens

All colours and surface variables are defined in `frontend/src/index.css`. Never use raw hex values in component CSS; always use tokens:

| Token | Usage |
|---|---|
| `var(--bg)` | Page background |
| `var(--panel)` | Card / panel background |
| `var(--panel-solid)` | Opaque panel (overlays, drawers) |
| `var(--text)` | Primary text |
| `var(--text-muted)` | Secondary / caption text |
| `var(--border)` | Default border |
| `var(--accent)` | Interactive / brand accent |
| `var(--accent-muted)` | Subtle accent tint (hover, selected row) |
| `var(--danger)` | Error / critical |
| `var(--warning)` | Warning / near-EOL |
| `var(--success)` | Success / healthy |

---

### Database — Useful Commands

```bash
# psql (Homebrew PostgreSQL 16)
/opt/homebrew/Cellar/postgresql@16/16.13/bin/psql -U "$USER" -d vulnwatch

# Check next migration version
ls backend/src/main/resources/db/migration/postgres/ | sort | tail -5
```

Never edit an already-applied migration. If Flyway fails with "applied migration not resolved locally", run `flyway:repair` (see Commands section).

---

### Common Pitfalls

1. **Wrong constructor arg count in tests** — When a new dependency is added to a `@Service` constructor, update every `new ServiceName(...)` call in the corresponding `*Test.java` and add a `@Mock` + `when(...)` stub.
2. **`RequestActor` is a record, not an interface** — Use `new RequestActor("user-id", false, null, null)`, not a lambda.
3. **Flyway validation on startup** — If local schema diverges from another branch, run `flyway:repair` before `spring-boot:run`.
4. **Frontend build type errors only surface in `npm run build`** — `npm run dev` may succeed while `tsc -b --force` fails. Run build before committing frontend changes.
5. **`keepPreviousData` is required for paginated queries** — Without it, the table flickers to empty between page transitions.
6. **SQL filter clauses must match across backend methods** — Changing the ecosystem exclusion list in `getSummary()` must be mirrored in `buildComponentFilterClause()` and `UNRESOLVED_WHERE`. They all reference `LIBRARY_ECOSYSTEMS_SQL`.
7. **`Page<T>` responses from backend** — Paginated endpoints return `{ content, number, size, totalElements, totalPages }`. The frontend type must match exactly.
8. **No React Router** — All navigation uses URL query params. Use `pathForTab()` to generate tab links; do not hardcode `?tab=` strings.

---

### Adding a New Connector

1. Add the connector ID to the `ConnectorId` union in `frontend/src/features/connect/types.ts`.
2. Add a card entry to the `CONNECTORS` array in `frontend/src/features/connect/connectors.ts` (category, label, description, icon).
3. Add a `case 'your-connector-id':` branch in `ConnectorDetailContent` that renders the detail component.
4. Implement the backend: new `client/` HTTP client, `service/` ingestion service, `controller/` endpoint, and Flyway migration for any new tables.

---

### EOL Pipeline Quick Reference

| Stage | Scheduler | What it does |
|---|---|---|
| Catalog refresh | Sunday 02:00 | Fetches full product list from endoflife.date `/api/v1/all.json`, upserts `eol_product_catalog` |
| Release refresh | Sunday 03:00 | For each slug in `software_eol_mapping`, fetches cycles, upserts `eol_release` |
| Mapping resolve | Sunday 03:30 | Runs 4-tier resolver (CPE → PURL → Alias → Name hints) for every unresolved `software_identity`; writes `software_eol_mapping` |
| Denormalize | Sunday 04:00 | Joins `eol_release` → `inventory_components` on version prefix; writes `is_eol`, `eol_date`, `eol_days_remaining` |

Slug suggestion tiers (in `EolSlugResolverService.resolveCandidates()`):
- **Tier 1 — CPE match**: `cpe_vendor` / `cpe_product` exact match in catalog
- **Tier 2 — PURL match**: `purl_type` + `purl_namespace` match
- **Tier 3 — Alias match**: catalog aliases contain vendor or product name
- **Tier 4 — Name hints**: hardcoded `NAME_HINTS` / `PURL_HINTS` maps
- **Tier 5 — Text search**: ILIKE on `slug` or `display_name` (fallback, LOW confidence)

---

### VEX Pipeline Quick Reference

| Stage | Source | What it produces |
|---|---|---|
| CSAF sync | Microsoft / Red Hat advisory feeds | `vulnerability_targets` rows with `VEX` source type |
| VEX assertion | `VexAssertionService` | Reads `known_not_affected`, `fixed`, `known_affected` from CSAF `product_status`; writes `component_vulnerability_states` |
| Finding update | `FindingService` | Resolves or reopens findings based on VEX assertion outcome |
| Staleness recompute | Daily 02:30 | Marks VEX assertions stale if CSAF document is older than 90 days |

VEX assertions take precedence over CPE-based correlation when the same component/CVE pair has both. See `ApplicabilityDecisionService.decide()` for precedence logic.

---

### GitHub Token

For GitHub SBOM / GHCR / GHSA features, place a token in `backend/secrets/github-api-token` (gitignored). Resolution order: `GITHUB_API_TOKEN_FILE` → `backend/secrets/github-api-token` → `GITHUB_API_TOKEN`.

---

---

## Product & Engineering Principles

The sections below capture the product intent, engineering philosophy, and design guardrails for this project. They are meant to inform every decision made inside the codebase — from data modeling to UI design to how findings are scored.

---

### Purpose

This repository is for **Project No Scan / Scout**, a vulnerability intelligence and exposure correlation product.

The product is aimed at a **Vulnerability Analyst** who needs to understand **asset exposure to critical and 0-day vulnerabilities**, reduce noise, distinguish false positives, and surface **what matters most** for remediation. Core MVP scope includes ingesting vulnerability intelligence from **NVD, KEV, CSAF, VEX, and top-vendor EoL data**, ingesting asset and software inventory from **ServiceNow CMDB** (live), with **SCCM and Intune** planned but not yet implemented, correlating **CPE/CVE/software/CI** data into findings, and supporting **multi-tenancy**. Source project notes also call out host, container, and app/SBOM layers, plus automated and manual CVE assessment flows.

---

### Operating Stance

Act like a senior staff engineer and security product architect working inside an enterprise-grade vulnerability correlation platform.

Optimize for:

1. **Correctness over speed**
2. **Explainability over cleverness**
3. **Deterministic correlation over fuzzy magic**
4. **Tenant isolation over convenience**
5. **Incremental, reviewable changes over broad rewrites**

When making changes:

- Preserve existing architecture unless there is a strong reason to change it.
- Prefer small patches that keep behavior obvious and testable.
- Do not introduce hidden heuristics for vulnerability matching without documenting them.
- Do not fabricate package names, CPEs, PURLs, versions, or vendor mappings.
- Do not silently weaken security, tenancy boundaries, or auditability.
- Do not assume scan-based discovery is available; this product is built around **correlation**, not active scanning.

---

### Product Intent

The product exists to answer:

- **Which assets are actually exposed to this CVE?**
- **Which findings are false positives or not actionable?**
- **Where is patch not available, end-of-life, or vendor-exempt status affecting remediation?**
- **What should the analyst do first?**

The MVP is not a generic VM dashboard. It is a **context-enriched exposure correlation engine** with workflow support.

#### Primary persona

- Vulnerability Analyst

#### Core jobs to be done

- Ingest and normalize vulnerability intelligence
- Ingest software and asset context from enterprise inventory systems
- Correlate CVE → software → asset/CI with clear evidence
- Use VEX/CSAF/vendor signals to suppress noise
- Highlight what matters most
- Create tickets and track remediation workflow
- Support both **automatic** and **manual** CVE assessment flows

---

### Source-of-Truth Product Assumptions

Use these assumptions unless the codebase clearly implements a different, deliberate design.

#### 1) Correlation model

Findings should be modeled around a deterministic key such as:

- `{tenant + CI/asset + vulnerability + software identity}`

Avoid collapsing findings too early. Preserve enough structure to answer:

- which software on which asset caused the match,
- which source asserted the vulnerability,
- which advisory or vendor status changed the final state.

#### 2) Canonical identity approach

Treat software identity as a first-class abstraction that links:

- inventory product names / publisher / version strings,
- SBOM package identifiers such as PURLs,
- vulnerability targets such as CPEs,
- vendor/product-tree identifiers from CSAF,
- optional SWID or ecosystem-specific identifiers.

Previous project work favored a canonical identity model with normalized identifiers, provenance, and link tables instead of one-shot string matching.

#### 3) Tiered matching

Prefer a tiered matching pipeline:

- Tier 0: exact cryptographic or immutable anchors
- Tier 1: exact package identity matches
- Tier 2: vendor advisory / CSAF product tree applicability
- Tier 3: NVD CPE applicability with version logic
- Tier 4: tightly controlled fuzzy candidate generation only

Fuzzy logic may propose candidates but should not become authoritative exposure evidence without deterministic confirmation.

#### 4) Explainability

Every finding should have a machine-readable and human-readable explanation trail, for example:

- inventory evidence,
- matched software identity,
- matched advisory target,
- version applicability result,
- VEX override or vendor status,
- final risk state and confidence.

#### 5) State precedence

Where multiple sources disagree, prefer a documented precedence order. A reasonable default is:

1. Vendor-specific advisory / CSAF / VEX
2. Vendor lifecycle / EoL information
3. KEV enrichment for urgency
4. NVD / generic intel

Never discard raw source facts; preserve both raw and resolved state.

---

### Domain Rules That Should Shape Code

#### Supported product layers

The product vision includes:

- Vulnerability intelligence
- Inventory
- Host
- Container
- Apps / SBOM
- Findings
- Insights / What matters most
- Escalation
- Overview dashboard
- Remediation plan
- Configuration and integrations

#### Vulnerability intelligence inputs

MVP sources:

- NVD
- KEV
- CSAF
- VEX
- top-vendor EoL / lifecycle data
- OSV is acceptable if the codebase already supports it or the design calls for app ecosystem coverage

#### Inventory inputs

Currently implemented:

- ServiceNow CMDB (live connector)

Planned but not yet implemented:

- SCCM
- Intune

Prefer adapters that normalize into a stable internal inventory contract rather than leaking source-specific shape through the codebase.

#### Ticketing outputs

Planned but not yet implemented:

- Jira
- ServiceNow (ticket creation, separate from the CMDB inventory connector)

---

### CPE and Naming Guidance

This project uses CPE heavily. Treat CPE handling as a standards-sensitive area.

Relevant CPE 2.3 facts:

- CPE 2.3 is built around the **Well-Formed Name (WFN)** logical model.
- WFN is an abstract canonical form rather than just a transport string.
- The spec defines both **URI binding** and **formatted string binding**.
- CPE can describe applications, operating systems, and hardware devices.
- The extended WFN attributes include `sw_edition`, `target_sw`, `target_hw`, and `other`.

#### Implications for implementation

- Prefer a **normalized internal representation** for CPE rather than raw string-only handling.
- Support parsing and emitting CPE 2.3 formatted strings correctly where the codebase requires it.
- Keep round-trip behavior and escaping rules explicit in tests.
- Distinguish between **identifier parsing**, **version applicability**, and **matching policy**. They are separate concerns.
- Do not overfit logic to only one CPE serialized form.

If you touch CPE parsing, binding, unbinding, or normalization, add or update tests for:

- escaped characters,
- wildcard handling,
- target software / hardware qualifiers,
- invalid percent-encoding or malformed formatted strings,
- round-trip parse/serialize behavior.

---

### Architectural Preferences

#### Preferred high-level modules

If the repository structure is still evolving, favor separation like this:

- `ingestion/` — source collectors, fetchers, parsers
- `normalization/` — canonical models and source-to-canonical mapping
- `identity/` — software identity graph, identifier linkage, version normalization
- `correlation/` — matching engine and applicability rules
- `findings/` — finding lifecycle, dedupe, state, suppression, audit trail
- `prioritization/` — KEV, asset criticality, exploitability, risk ranking
- `integrations/` — ServiceNow, Jira, future connectors
- `api/` — typed service/API layer
- `ui/` — analyst workflows, dashboards, triage and remediation views
- `config/` — tenant config, mapping rules, thresholds, feature flags

#### Boundaries to protect

- Ingestion code should not contain business-level risk scoring.
- UI code should not implement vulnerability-correlation logic.
- Source adapters should not become canonical data models.
- Suppression logic should not be buried in rendering code.
- Tenant-specific mapping rules should not be hard-coded in shared business logic.

---

### Multi-Tenancy and Security Requirements

This project explicitly requires a **secured multi-tenant architecture**, customer-specific metadata mapping, ACLs, roles, and tenant-aware configuration.

Treat the following as non-negotiable:

- Every persisted business object must be clearly tenant-scoped unless it is part of the shared global intelligence layer.
- Shared vulnerability intelligence may be global; findings, tickets, mappings, user actions, and suppression decisions are tenant-specific.
- Never leak one tenant's asset metadata, suppression rules, notes, tickets, or scoring inputs into another tenant's context.
- All mutating operations should be auditable.
- Avoid implicit tenant resolution. Tenant context should be explicit in service boundaries, APIs, and storage queries.

#### Shared vs tenant-scoped default

**Usually shared:**

- normalized CVEs
- KEV catalog
- CSAF/VEX raw advisories
- common CPE / product intelligence
- vendor lifecycle reference data

**Usually tenant-scoped:**

- assets / CIs
- installed software observations
- SBOM instances
- findings
- suppression decisions
- remediation plans
- ticket links
- user notes
- dashboards / saved views
- mapping rules and thresholds

---

### UX Principles

Optimize the user experience for analyst triage, not vanity metrics.

#### The UI should make it easy to answer

- what is affected,
- why it is affected,
- what is suppressed and why,
- whether a patch exists,
- whether the software is EoL,
- which assets are highest priority,
- what action should happen next.

#### UI requirements

- Evidence should be visible, not hidden behind unexplained badges.
- Risk labels must be backed by transparent factors.
- "What matters most" should reflect urgency and actionability, not just CVSS.
- Manual assessment flows should allow choosing a CVE against assets or software.
- Auto-assessment flows should be configuration-driven, such as rules like `CVSS > 8` or `KEV = true`.

Avoid building a dashboard-first product where analysts cannot drill into the reasoning.

---

### Data Modeling Guidance

Prefer explicit entities over overloaded JSON blobs when the domain is core to the product.

> Note: the entity names below are conceptual domain names, not necessarily the actual table names in the current schema. For actual table names see `docs/database.md` and the Flyway migrations.

#### Likely core entities

- `tenants`
- `assets` / `configuration_items`
- `software_observations`
- `sbom_components`
- `software_identities`
- `software_identifiers`
- `vulnerabilities`
- `vulnerability_targets`
- `advisories`
- `vex_statements`
- `findings`
- `finding_evidence`
- `suppression_rules`
- `risk_scores`
- `tickets`
- `tenant_mappings`
- `ingestion_runs`
- `audit_events`

#### Modeling preferences

- Raw source payloads may be stored for traceability, but must not replace canonical models.
- Preserve provenance for each normalized field where practical.
- Version fields should be modeled in a way that supports source-native comparison rules.
- Use append-only or audited state transitions for findings where feasible.

---

### Performance Expectations

The source requirements explicitly care about performance at scale, including correlating a single CVE against **100k assets** and large-scale correlation of **50k CVEs against 200k assets**.

This means:

- avoid N×M naïve matching loops,
- design for incremental recomputation,
- pre-index by normalized identifiers,
- separate ingestion from correlation execution,
- cache reusable applicability artifacts when safe,
- batch external API operations,
- test with realistic cardinality assumptions.

When changing performance-sensitive code:

- document complexity assumptions,
- preserve or improve index usage,
- add benchmark notes if the change affects correlation paths,
- avoid adding per-row network calls.

---

### Coding Standards for Claude

#### General

- Match existing conventions in the repo before introducing new patterns.
- Prefer clear names from the vulnerability-management domain.
- Write code so that a security engineer can review it without reverse-engineering intent.
- Favor typed interfaces and structured contracts over loose dictionaries when the language supports it.
- Keep pure functions pure when modeling normalization and matching logic.

#### Comments

Use comments to explain:

- why a precedence rule exists,
- why a vendor-specific exception exists,
- why a matcher is conservative,
- what evidence is required to transition finding state.

Do not add noisy comments that simply restate code.

#### Error handling

- Fail loudly on malformed standards payloads when correctness matters.
- Be tolerant at ingestion boundaries, but explicit about partial failures.
- Preserve source identifiers in errors and logs for troubleshooting.
- Avoid swallowing parse failures in security-critical code.

#### Logging

- Log ingestion and correlation progress with stable identifiers.
- Do not log secrets, access tokens, tenant-sensitive notes, or raw PII.
- Include enough context to debug a bad match without exposing unrelated tenant data.

---

### Testing Expectations

Any change in correlation, parsing, or finding state should come with tests.

#### Minimum testing bar

Add or update tests for:

- source normalization,
- identifier parsing,
- version applicability,
- deduplication,
- VEX/vendor override behavior,
- tenant isolation,
- risk ranking or prioritization,
- regression cases from previously observed false positives.

#### High-value test fixtures

Prefer fixtures that reflect real product use cases:

- inventory name + version → normalized identity → NVD CPE match
- SBOM package → CSAF product tree match
- VEX `not_affected` suppression
- patch unavailable / EoL edge cases
- multiple advisories for same CVE with vendor precedence
- same vulnerability across multiple assets with different evidence strength

#### For CPE-heavy code

Add round-trip and malformed-input tests based on the CPE 2.3 concepts of WFN, URI binding, and formatted string binding.

---

### Workflow Instructions for Claude Code

When asked to work in this repo:

1. **Inspect before editing**
   - Read project manifests, config files, schema definitions, and existing architecture docs first.
   - Infer the actual stack from the repo rather than assuming it.

2. **Plan from domain boundaries**
   - Identify whether the task touches ingestion, normalization, correlation, findings, integrations, or UI.
   - Keep business logic in the correct layer.

3. **Prefer surgical edits**
   - Change the smallest viable surface area.
   - Reuse existing utilities and types where sensible.

4. **Validate locally using repo-native commands**
   - Use the package manager and scripts already present in the repo.
   - Do not invent npm/pnpm/yarn commands if the repo uses something else.

5. **Explain security and data implications in reviews**
   - Call out tenancy, evidence, and precedence implications.

6. **When requirements are ambiguous**
   - Default to deterministic, auditable behavior.
   - Capture unresolved product questions as TODOs or follow-up notes instead of burying assumptions in code.

---

### Preferred Implementation Style by Area

#### Ingestion

- Make adapters idempotent where possible.
- Separate fetch, parse, normalize, and persist steps.
- Track source timestamps and ingestion run IDs.

#### Normalization

- Keep normalization deterministic.
- Preserve original raw values alongside canonical values where useful.
- Make source-specific rules explicit and tested.

#### Correlation

- Make matching tiers explicit.
- Emit evidence objects, not just booleans.
- Keep confidence, severity, and final disposition separate.

#### Findings lifecycle

- Distinguish `detected`, `suppressed`, `not_affected`, `resolved`, `risk_accepted`, and `needs_review` states if the domain model supports them.
- Prefer state transitions with reasons and evidence.

#### Integrations

- Use boundary interfaces for Jira/ServiceNow.
- Keep external payload mapping out of core domain entities.
- Support retries and idempotency for ticket creation/update paths.

#### UI

- Prioritize triage tables, drill-down evidence panels, remediation workflow, and saved analyst views.
- Avoid purely decorative analytics.

---

### Anti-Patterns to Avoid

- treating raw product strings as canonical truth,
- making CPE string comparison the entire correlation strategy,
- hidden fuzzy matching that creates unexplained exposure,
- global mutable tenant context,
- embedding business rules in controllers or components,
- mixing suppression logic with severity scoring,
- deleting source provenance after normalization,
- using one opaque "status" field for all finding states,
- optimizing dashboard cosmetics ahead of evidence quality.

---

### Definition of Done for Meaningful Changes

A change is closer to done when:

- the implementation is consistent with the product's correlation-first architecture,
- the reasoning is auditable,
- tenant boundaries are preserved,
- tests cover the changed behavior,
- naming reflects security-domain meaning,
- reviewer notes explain any precedence, suppression, or matching behavior,
- no fake data mappings or silent assumptions were introduced.

---

### If You Need to Generate Docs or Design Artifacts

When writing docs for this repo, align language with the project's core narrative:

- **No Scan** means **asset-aware correlation without active scanning**.
- Value comes from combining **intelligence + inventory + applicability + explainability**.
- "What matters most" means **actionable, risk-informed, evidence-backed prioritization**.

Prefer crisp enterprise language over marketing fluff.

---

### Open Implementation Questions to Keep Visible

Unless the codebase already answers these, keep them explicit rather than assuming:

- exact canonical software identity schema,
- supported package ecosystems for SBOM correlation,
- exact precedence rules across NVD / CSAF / VEX / KEV / vendor lifecycle,
- risk scoring formula and tenant-level overrides,
- whether remediation planning is rule-builder first or AI-assisted first,
- trial-mode technical enforcement model,
- container coverage beyond initial registry assumptions,
- exact ACL and role matrix.

Do not guess these silently in production code.
