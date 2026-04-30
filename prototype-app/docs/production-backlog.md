# VulnWatch Production Backlog

Last updated: 2026-05-01

## North Star

A pipeline where founder taste is the only scarce resource, and everything
else is queue + agent + CI. Three loops share the same agent harness, repo,
test suite, and review queue:

1. **Bug → Fix → Ship.** User taps "Report bug" → triage agent ranks →
   fix agent writes failing test + fix + PR → founder reviews → auto-deploy.
2. **Support → Fix.** Inbound from email + in-app chat → support agent
   answers from docs, files bugs into the bug queue, or escalates to
   founder. Same agent can write code to fix the underlying cause.
3. **Demand → Feature.** Public voting board → founder writes a one-paragraph
   spec on the weekly survivor → agent breaks it into 3–6 PRs behind a
   feature flag → founder reviews → ship dark, then enable.

The constraint this design respects: founder reviews ~60 min/day. Anything
that grows that budget linearly with shipping volume kills the model.

## Plan Overview

| Phase | Goal | Status |
|---|---|---|
| 0 — Foundations | Tests, telemetry, conventions, rollback | In progress |
| 1 — Bug → Fix Loop | Report → triage → fix → ship | Not started |
| 2 — Support Agent | Inbound → docs / bug / escalate | Not started |
| 3 — Feature Voting | Vote → spec → build → ship | Not started |
| 4 — Self-Monitoring | Adversarial test, health, refactor | Ongoing after Phase 1 |

Phases must land in order. Phase 1 cannot start until the test suite is
green, fast, and meaningful — without that, the fix agent can't tell its
fix from a regression. Phase 3 cannot start until Phase 1 has been humming
for at least a month — that's where the trust gets built that agents won't
break things.

## Phase 0 — Foundations

**Goal:** without these, agents either don't work or quietly destroy the
codebase.

### Done

- **Postgres IT suite green** (30/30) via `mvn -Ppostgres-it verify`.
- **Postgres IT scaffolding** — `backend/src/test/java/com/prototype/vulnwatch/support/`
  (`PostgresIntegrationTest`, `PostgresControllerIntegrationTest`, `AuthRequest`,
  `PostgresITSupport`, README). New IT class is ~50 lines, not ~250.
- **Frontend page-test scaffolding** — `frontend/src/test/` (`renderWithProviders`
  with `initialEntries` support, `fixtures.ts` with `buildFinding` /
  `defaultRiskPolicy` / `pageOf`, README).
- **PR template** — `.github/pull_request_template.md`. Forces scope, why,
  repro, test, blast radius, rollback. Same template the fix agent fills in.
- **Frontend type-check CI gate** — `npm run typecheck` (`tsc -b --noEmit`)
  runs as a discrete CI step before build, fails fast.
- **Coverage gates wired in CI**
  - Backend: JaCoCo `check` execution, line floor 0.40 (current ~43%).
  - Frontend: vitest `thresholds`, lines/statements 14, functions 11, branches 10
    (current 14.7 / 14.1 / 11.5 / 10.3).
- **CLAUDE.md prescriptive Conventions section** — what counts as "done",
  when to add tests, refactor policy, naming/commit conventions, never-touch
  list, sight-rejection list.

### Pending — Test Floor

Coverage on `controller/` is 21% lines; 30 of 35 frontend pages are at 0%.
Fix-agent fixes will land blind without these.

#### P0 controller integration tests

- [ ] **CveDetailController** — happy path + suppression + ServiceNow incident creation flow.
- [ ] **FindingController** — list + detail + bulk workflow + comments + timeline.
- [ ] **IngestionController** — `/api/sbom-upload` (multipart), `/api/sbom-fetch` (URL), error paths.
- [ ] **VulnerabilityIntelligenceController** — vuln-repo intelligence list + filters.
- [ ] **AssetController + InventoryController** — asset list, inventory components, software identities.
- [ ] **RiskPolicyController + DashboardController** — policy GET/PUT, dashboard read endpoints.
- [ ] **ServiceNowIncidentController** — incident creation, status sync, error paths.
- [ ] **ApiExceptionHandler** — 401/403/404/422/500 mappings.

#### P0 page tests

- [ ] **InventoryOverviewPage** — render with mocked overview API, assert key widget headers.
- [ ] **InventoryComponentViewsPage + InventoryPage** — table render, view switch, filter chip.
- [ ] **ConfigurationsPage** — tab nav, RiskPolicy load, save policy.
- [ ] **ConnectPage + DashboardPage** — connector catalog render, connector card click.
- [ ] **Extend FindingsPage + FindingDetailPage** — beyond current smoke; cover bulk ops + timeline.
- [ ] **Extend VulnRepoOrgCvePage + VulnRepoVulnerabilitiesPage** — beyond current smoke; cover the two-view distinction.

#### P1 controller IT batches

- [ ] **Ingestion + admin** — operations endpoints, demo seed, prototype data reset, admin user management.
- [ ] **Connectors** — NVD, GHSA, KEV, CSAF, GitHub SBOM, ServiceNow CMDB, SCCM, AWS Discovery config endpoints.
- [ ] **Read-models** — software inventory items, software identity summary, quality issue projection, vulnerability intel summary.

#### P1 page test batches

- [ ] **Inventory surfaces** — software identities, software instances, asset detail, components-by-cpe.
- [ ] **Operations + EOL** — ops dashboard sub-pages, run queues, EOL page.
- [ ] **Connector pages** — Sccm, AwsDiscovery, NvdConnector, KevConnector, GhsaConnector, MicrosoftCsafConnector, RedhatCsafConnector, AdvisoryConnector, VulnIntelConfig.

#### Deferred

- [ ] **P2 thin connector wrapper pages** — pages that are <100 lines and just delegate to a feature component. Test the feature component directly rather than the wrapper.

### Pending — Telemetry, Boundaries, Rollback

- [ ] **Wire Sentry** into backend + frontend. `@sentry/react` is already a
      dependency but unused. Errors group by stack + user count + tenant +
      revenue tier. Without this, agents can't see what to fix.
- [ ] **Add ArchUnit module-boundary rules** — enforce that `controller/`
      only depends on `service/` and `dto/`, that `domain/` doesn't import
      `dto/` or controllers, that `client/` doesn't reach into `service/`.
      ArchUnit is already on the classpath. Modular monolith for v1, with
      enforced seams so we can extract workers (per Architecture Backlog
      below) without rewrites.
- [ ] **One-click rollback on every deploy.** Agents will ship bad code.
      Recovery time matters more than prevention. Define what "rollback"
      means here: image rollback for backend, last-good-commit static
      redeploy for frontend, migration rollback policy (forward-only with
      compensating migration, not down-migrate).
- [ ] **Per-file PR-diff coverage gate** — global thresholds catch
      regressions in aggregate, but a 0%-covered file can still slip in.
      Needs a custom GitHub Action (e.g. `diff_cover`). Backend ≥60% on
      touched files, frontend ≥50%.

**Phase 0 exit criteria:** all P0 ITs and P0 page tests landed; Sentry
emitting from at least one prod-like environment; rollback runbook tested
end-to-end at least once; ArchUnit rules green.

## Phase 1 — Bug → Fix Loop

**Goal:** a user-reported bug becomes a green-CI'd PR in the founder's
review queue, automatically, within 24 hours.

### Tasks

- [ ] **In-app "Report bug" button.** Captures: last 50 user actions,
      console errors, viewport state, account/tenant ID, screenshot.
      Posts a single structured payload to GitHub Issues with a `from-app`
      label. Action log lives in browser memory (capped); no PII written
      to the payload without explicit user consent.
- [ ] **Daily triage agent — 09:00 cron.** Reads new `from-app` issues,
      dedupes by error fingerprint (stack + path + status code), ranks by
      `unique_users × revenue_tier`, labels P0/P1/P2, drops noise (single
      user + no repro). Posts a daily triage summary to the founder's
      inbox.
- [ ] **Fix agent.** Picks top of queue. Writes a failing test that
      reproduces the bug, then writes the fix, opens a PR linking the
      original report, runs full CI. PR description follows
      `.github/pull_request_template.md`.
- [ ] **Founder review queue.** Single Linear list, ranked by impact.
      Anything you reject goes back with a one-line comment the agent
      reads. Goal: ≤60 min/day at the queue.
- [ ] **Auto-deploy on merge.** Backend image build + push + deploy.
      Frontend build + push to CDN. Both gated on green CI (already in
      place from Phase 0).
- [ ] **Auto-rollback on error spike.** Sentry release + error-rate
      threshold (e.g. >2× baseline within 10 min of deploy) triggers
      rollback. Agent posts the rollback into the queue with a
      `regressed` label so the next cycle re-fixes properly.

### Phase 1 exit criteria

- ≥10 user-reported bugs flowed through the loop end-to-end.
- ≥80% of fix-agent PRs merge without the founder rewriting code (small
  comment-driven revisions are fine; rewrites mean the agent isn't
  trustworthy yet).
- Median report-to-merged time ≤24h for P1, ≤4h for P0.
- No silent regressions: every fix has a regression test that fails
  before the fix.

Do not start Phase 2 until these criteria hold for ≥4 consecutive weeks.

## Phase 2 — Support Agent

**Goal:** customer email + in-app chat get answered, bugs get filed into
Phase 1's queue, and only the conservative-escalation cases reach the
founder.

### Tasks

- [ ] **Unified inbox.** Email + in-app chat → single thread store with
      stable IDs. Agent reads, replies, marks resolved.
- [ ] **Support agent capabilities.** Reads docs (markdown in repo + any
      help center). Greps the repo. Files structured bug reports into the
      Phase 1 queue with full repro context.
- [ ] **Three-tier handling.**
  1. Agent answers from docs (e.g. "how do I…").
  2. Agent files a bug, replies "we're on it, tracking #X."
  3. Escalate to founder — refunds, security, data loss, anything
     PII-adjacent, anything legal- or contract-shaped.
- [ ] **Tone guide.** System prompt with 10 real reply examples in your
      voice. Without this, the brand decays into generic SaaS.
- [ ] **Conservative escalation defaults.** When in doubt, escalate.
      An agent telling a customer something legally or factually wrong
      is much costlier than a slower founder reply.

### Phase 2 exit criteria

- ≥70% of inbound resolved without founder touch.
- Zero escalations missed (every legal/security/PII case routed to founder).
- Customer-facing tone audited monthly; brand voice still recognisable.

## Phase 3 — Feature Voting → Build

**Goal:** demand becomes a shipped feature on a weekly cadence, with
founder taste deciding what gets built (not vote count alone).

### Tasks

- [ ] **Public voting board.** Canny, or roll your own (≈200 lines).
      Vote weight = `account_age × monthly_usage` to kill sybils and
      reward real users.
- [ ] **Weekly 30-min spec ritual.** Founder reviews top 5 candidates,
      kills 4, writes a one-paragraph spec for the survivor. The spec
      is the contract — agent will not negotiate it.
- [ ] **Build agent.** Breaks the spec into 3–6 PRs behind a feature
      flag. Founder reviews each. Ship dark, then enable.
- [ ] **Auto-generated changelog.** Merged PRs with the feature flag
      name get aggregated into public release notes.
- [ ] **Reserve 30% of build capacity for non-voted bets.** Voting
      captures power users, not future users. Top of the board will
      always be incremental. Founder picks the bets that don't show
      up in votes.

### Phase 3 exit criteria

- ≥3 voted features shipped under the loop without founder rewriting code.
- ≥1 non-voted bet shipped per quarter.
- Spec rejection rate ≥80% (kill aggressively — saying yes to everything
  is what kills the velocity).

## Phase 4 — Self-Monitoring

**Goal:** the system catches its own failure modes before the founder
notices them. Ongoing after Phase 1 lands.

### Tasks

- [ ] **Adversarial test agent.** Every shipped fix gets a regression
      test written by a *different* agent invocation reading the diff +
      original report. Catches "agent fixed the symptom, not the cause."
      Failures here are higher-priority than normal bugs.
- [ ] **Weekly health agent.** Scans churn, error rates, complexity
      creep (cyclomatic complexity per file, file-size growth, test
      coverage drift). Reports 3 things to refactor; founder picks one
      for the next cycle.
- [ ] **Quarterly founder-only architecture review.** You, alone, with
      the codebase. Agents can't do this — they keep adding rather than
      consolidating. Output: kill list (modules to delete), consolidation
      list (modules to merge), simplification list (abstractions to
      collapse).

## Failure Modes to Watch

These are the ranked ways the model breaks. Mitigations are listed.

1. **Founder review becomes the bottleneck.** 20 PRs/day × 5 min review =
   your whole day, then the queue grows past your throughput.
   *Mitigation:* kill aggressively; batch-merge trusted patterns
   (e.g. dependency bumps, doc tweaks); don't review tests line-by-line.
2. **Codebase decay.** Agents take the easy local fix every time.
   In 6 months you have a codebase no agent (or human) can navigate.
   *Mitigation:* Phase 4's quarterly review is non-negotiable.
3. **"No pushback" cuts both ways.** Sometimes the engineer pushing back
   is right.
   *Mitigation:* red-team agent that argues against your plan before
   you build it. 5 min cost, saves rebuilds.
4. **Customer support edge cases.** An agent will eventually tell a
   customer something legally or factually wrong.
   *Mitigation:* Phase 2 tier-3 rules conservative; escalate-on-doubt;
   monthly audit of agent-resolved threads.
5. **Voting captures power users, not future users.**
   *Mitigation:* Phase 3's 30% reserved capacity for non-voted bets.
6. **Telemetry blind spots.** If Sentry doesn't see it, the loop can't
   fix it.
   *Mitigation:* periodic "no-error week" audit — if a week has zero
   reported errors, that's not success, that's likely a telemetry hole.

## What to Do This Week

1. Finish Phase 0's pending P0 controller ITs and P0 page tests. Without
   them, the fix agent's PR cannot be trusted to not regress.
2. Wire Sentry. Without it, Phase 1 has no signal to act on.
3. Test the rollback path end-to-end at least once.

Then Phase 1 in week 2 and beyond. Don't build feature voting until
bug → fix is humming for a month.

---

## Production Readiness Backlog

Parallel track: what VulnWatch needs to become a multi-customer managed
SaaS. Distinct from the agent-loop plan above — these are not gated on
the agent loop and the agent loop is not gated on these (you can run
the agent loop on a single-tenant prototype).

### Pre-Prod Checklist

- [ ] Run a dedicated multi-tenant isolation test pass before the first customer pilot.
  - Create at least two tenant accounts, for example Customer A and Customer B.
  - Create users, memberships, service accounts, connector configs, inventory, findings, investigations, audit events, refresh requests, and exports for each tenant.
  - Prove Customer A cannot read, write, export, refresh, or infer Customer B data through any API or UI path.
  - Verify tenant-scoped PostgreSQL RLS behavior with `APP_REQUIRE_TENANT_CONTEXT=true`.
  - Verify requests without tenant context return no tenant rows.
  - Verify suspended/deleted tenants are blocked from normal tenant APIs.
  - Verify platform-owner routes are the only cross-tenant operational path.
  - Record test evidence and defects before pilot approval.
- [ ] Validate real OIDC/JWT integration with tenant membership claims.
- [ ] Disable header-based tenant selection in the pre-prod and prod environments.
- [ ] Confirm central vulnerability feed sync endpoints require platform-owner access.
- [ ] Confirm tenant users can only run tenant exposure refresh from the current central repository.
- [ ] Confirm connector credentials are encrypted at rest and never returned by APIs.
- [ ] Confirm S3 vulnerability archive write/read works through the ECS task role.
- [ ] Confirm audit CSV export and support bundle exports contain no secrets.
- [ ] Run backup restore drill against RDS and archive restore drill against S3.
- [ ] Run migration validation against an ephemeral PostgreSQL database.
- [ ] Run smoke tests against the deployed pre-prod environment.

### Product Backlog

- [ ] Build customer-facing user management UI for users, roles, memberships, and service accounts.
- [ ] Build tenant admin settings UI for plan, quotas, audit export, support bundle, and tenant status.
- [ ] Build onboarding flow: create tenant, invite users, configure first inventory source, run first sync, review exposure dashboard.
- [ ] Add customer-facing billing/plan hooks beyond stored plan metadata.
- [ ] Add support access workflow or audited support impersonation with approval.

### Security Backlog

- [ ] Add broader RLS integration tests for inventory, findings, connectors, queues, exports, investigations, and projections.
- [ ] Add SSRF allowlists and outbound egress controls for customer-configured connectors.
- [ ] Add secret rotation workflow for connector secrets and application encryption keys.
- [ ] Add immutable audit retention controls and retention policy enforcement.
- [ ] Add dependency/container scanning, SAST, secret scanning, SBOM generation, and image signing in CI.

### Operations Backlog

- [ ] Add OpenTelemetry trace/span export.
- [ ] Add CloudWatch dashboards and alert routing for API latency, DB saturation, queue age, source staleness, connector failures, login failures, quota failures, and RLS failures.
- [ ] Add Terraform remote state and environment promotion workflow.
- [ ] Add ECR repositories and image promotion gates.
- [ ] Add runbooks for incident response, customer data deletion, backup restore, feed quarantine, and failed deployment rollback.

### Architecture Backlog

- [ ] Keep the backend as a modular monolith for v1 unless scale or isolation pressure proves otherwise.
- [ ] Prepare SQS/EventBridge job contracts for feed ingestion, inventory ingestion, projection refresh, report generation, and notification delivery.
- [ ] Extract vulnerability ingestion workers only when feed refresh load or failure isolation requires it.
- [ ] Extract inventory ingestion workers only when customer connector load grows unevenly.
