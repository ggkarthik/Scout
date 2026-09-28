# AI-BOM Integration — Remaining Plan

Handover for continuing this work on another machine. Written against the state of
`feat/ai-bom-m2-declared-inventory` at the time of writing.

---

## 1. Branch state

| Branch | Contents |
|---|---|
| `main` | Untouched by this work |
| `feat/ai-bom-m1-lifecycle` | Milestone 1 complete. 17 commits. Tenant V4–V6, platform V5 |
| `feat/ai-bom-m2-declared-inventory` | Branched off M1. 1 commit: tenant V7 declared-inventory **schema only** |

Start from `feat/ai-bom-m2-declared-inventory` — it contains everything.

```bash
git clone git@github.com:ggkarthik/Scout.git
cd Scout
git switch feat/ai-bom-m2-declared-inventory
```

---

## 2. Local environment setup — do this first

This is where the previous machine lost hours. The repo has **no** working local
config committed (correctly — it holds secrets), and every setting defaults to its
production-safe value. Without the steps below the backend either fails to start or
rejects every request.

### 2.1 `prototype-app/backend/.env.local`

`application.yml` imports this automatically via
`spring.config.import: optional:file:.env.local[.properties]`. The filename matters —
`.env` is **not** read.

```properties
# Generate once and never change it: any connector credential encrypted under a
# previous key becomes permanently unreadable.
#   openssl rand -base64 32
APP_CREDENTIAL_ENCRYPTION_KEY=<generate>

# Must equal frontend/.env.local's VITE_API_KEY.
APP_API_KEY=local-dev-key

# Local only. Header tenant selection would let any caller choose any tenant,
# so both must stay off in production.
APP_ALLOW_HEADER_TENANT_SELECTION=true
APP_REQUIRE_TENANT_CONTEXT=false
```

`chmod 600` it. It is gitignored via `.gitignore:8`.

### 2.2 `prototype-app/frontend/.env.local`

```properties
VITE_API_BASE=http://localhost:8080/api
VITE_API_KEY=local-dev-key
VITE_CREATOR_KEY=local-creator
VITE_AUTH_TOKEN=
VITE_ENABLE_TEST_PERSONAS=true
VITE_LOCAL_DEV=true
```

**`VITE_AUTH_TOKEN` must be empty.** A non-empty value makes the client send
`Authorization: Bearer` *instead of* the API-key headers, and the backend rejects
that with `JWT authentication is not configured` unless `APP_JWT_ISSUER_URI` is set.
Because Spring Security rejects before CORS headers are added, the browser reports
this as a generic `Failed to fetch` — the real 401 is invisible. This cost three
rounds of misdiagnosis.

### 2.3 Apply the tenant migrations manually

**The application never applies the tenant migration line.**
`APP_SCHEMA_MIGRATION_ENABLED` defaults to `false` (`application.yml:55`), and startup
Flyway only handles the platform line. Tenant V4–V7 must be applied by hand:

```bash
cd prototype-app/backend
mvn -q \
  -Dflyway.url=jdbc:postgresql://localhost:5432/vulnwatch \
  -Dflyway.user="$USER" \
  -Dflyway.password= \
  -Dflyway.schemas=tenant_default \
  -Dflyway.defaultSchema=tenant_default \
  -Dflyway.table=tenant_schema_history \
  -Dflyway.locations=filesystem:src/main/resources/db/migration/tenant \
  -Dflyway.placeholders.tenantSchema=tenant_default \
  -Dflyway.placeholders.tenantId=e5fe0d29-1d64-4175-8ce6-c34f42b214cc \
  flyway:migrate
```

Verify:

```sql
select version, description, success from tenant_default.tenant_schema_history
order by installed_rank;   -- expect V1..V7 all true
```

If the history has a V2 recorded as *"ai grid policy coverage thresholds"* rather
than *"ai grid approved manifests"*, the local schema predates the repo and Flyway
will refuse to migrate. If the tenant schema holds no data worth keeping, rename it
aside and rebuild rather than running `flyway repair`, which rewrites checksums and
hides the divergence:

```sql
ALTER SCHEMA tenant_default RENAME TO tenant_default_backup;
CREATE SCHEMA tenant_default;
```

Then re-run the migrate command above.

### 2.4 Start and smoke-test

```bash
# backend (needs Postgres 16 on 5432, database "vulnwatch")
cd prototype-app/backend && mvn spring-boot:run -Dspring-boot.run.profiles=local

# frontend
cd prototype-app/frontend && npm install && npm run dev
```

Smoke test — this exercises the M1 classification fix end to end:

```bash
cat > /tmp/aibom.json <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:11111111-2222-3333-4444-555555555555","version":1,
 "components":[
  {"type":"machine-learning-model","name":"llama-3","version":"3.1","purl":"pkg:huggingface/llama-3@3.1"},
  {"type":"data","name":"corpus","version":"2024.1","purl":"pkg:generic/corpus@2024.1"},
  {"type":"library","name":"transformers","version":"4.38.0","purl":"pkg:pypi/transformers@4.38.0"}]}
JSON

curl -s -X POST "http://localhost:8080/api/bom/upload?bomType=AI_BOM&assetType=APPLICATION&assetName=test-app&assetIdentifier=pkg:generic/test-app@1.0.0" \
  -H "X-API-Key: local-dev-key" -H "X-Creator-Key: local-creator" \
  -H "X-Tenant-ID: e5fe0d29-1d64-4175-8ce6-c34f42b214cc" -H "X-User-ID: local-analyst" \
  -F "file=@/tmp/aibom.json;type=application/json"
```

Expect HTTP 200. Then confirm **only the library** entered software inventory:

```sql
select purl, bom_evidence_state from tenant_default.inventory_components;
-- expect exactly pkg:pypi/transformers@4.38.0, SUPPORTED
```

### 2.5 Running tests

```bash
cd prototype-app/backend
mvn test                                      # unit; 4 pre-existing security failures are expected
mvn -Ppostgres-it verify                      # + Postgres ITs (needs local Postgres)

cd prototype-app/frontend
npm run typecheck && npm run lint && npm run test:unit
```

**Four unit-test failures are pre-existing and unrelated** — `ActuatorSecurityIntegrationTest`
and three `ApiSecurity*` tests. Verified by running them at the commit before any of
this work. Root cause is `ApiKeyAuthenticationFilter` yielding `anonymousUser`; it is
not CSRF, despite what an earlier commit message claimed.

Do not use `mvn ... | tail -N && echo OK` to check results — `tail`'s exit code masks
Maven's and the OK prints unconditionally. Redirect to a file and check `$?`.

---

## 3. What is already done (Milestone 1)

Complete and tested. Do not redo.

- **Logical sources.** `bom_sources` gives each source a stable identity holding immutable
  document versions with a current pointer. The implicit
  `(tenant, bom_type, asset, lower(supplier))` replacement key is **deleted** —
  replacement is now explicit via `sourceId`, and the four automated callers
  (remote endpoint, GitHub repo, GHCR, GitHub BOM file) carry stable derived keys so
  scheduled syncs replace their own source instead of accumulating one per run.
- **Completeness.** `PARTIAL` by default; `COMPLETE_ASSET_SOFTWARE` requires an
  inventory-admin role, writes an append-only audited assertion, must be repeated on
  every replacement, and is forbidden for CBOM by both a service check and a DB
  constraint. Retirement authority follows the asserted completeness, not the BOM type.
- **Evidence contributions.** `bom_component_contributions` records one standing claim
  per (source, inventory component). `bom_evidence_state` on `inventory_components`
  carries `SUPPORTED` / `CONFLICTING` / `WITHDRAWN` / `LEGACY_UNKNOWN`, separate from
  `component_status`. All six reconciliation rules implemented.
- **Withdrawal guards.** Withdrawal never sets `component_status`, never refreshes
  `last_observed_at`, never touches findings.
- **CBOM evidence lifecycle** with `status`/`resolved_at` preserved; deleting a CBOM
  now also deactivates its cryptographic components (previously it did not).
- **Per-asset serialization** moved from an in-JVM `ReentrantLock` to a
  transaction-scoped Postgres advisory lock, sharing its key with the ingestion-job
  worker so the two paths actually exclude each other.
- **Component classification.** Component type now survives parsing; models, datasets
  and cryptographic assets stay out of software inventory and CVE correlation, while an
  AI-BOM's libraries still enter both.
- **Backfill** reconstructs sources from `previous_bom_id` chains and contributions from
  `sbom_upload_id`, with a per-asset gate. Misclassified historical components are
  detected and counted; the correction itself is behind
  `app.bom.reclassification.retire-non-software`, **default false**.
- **Relationship parsing.** `bom_component_relationships` stores `DEPENDS_ON` and
  `COMPOSED_OF` verbatim.
- **`finding_kind` filtering** on both query paths plus the projection column.
- **UI:** source-replacement dropdown and completeness checkbox on the upload form;
  BOM Evidence column on the components table.

### Known gaps left in M1

1. **Evidence state is not in inventory *counts*** — only labels and the API.
2. **Reclassification correction ships disabled.** Enabling it retires inventory rows and
   closes findings as `AUTO_RECLASSIFIED_NOT_SOFTWARE`. Decide per environment after
   reading the counts the backfill logs.
3. **Concurrent-upload fail-fast is not tested end to end.** The mechanism is covered by
   `AssetAdvisoryLockPostgresIntegrationTest`. A threaded upload test needs a transaction
   held open across threads and fails for timing reasons.

---

## 4. Milestone 2 — remaining work

Tenant V7 (`ai_bom_declared_resources`), its entity, four enums and repository are
committed. **Nothing writes the table.** Everything below is outstanding.

### 4.1 Declared-inventory writer — start here

Write declared resources during ingestion for `MODEL` and `DATASET` typed components.

- Hook alongside `BomContributionService.syncContributions` in
  `BomIngestionOrchestrator.persistEvidenceAndCorrelations`, which already has the
  record, the source and the parsed `BomComponent` list.
- Identity, in order: content digest from `BomComponent.hashes` → `DIGEST`; a versioned
  purl → `VERSIONED_IDENTIFIER`; otherwise `bomRef` or name|version → `SOURCE_SCOPED_REF`.
  **Never derive identity from the display name.**
- `deployment_state` starts `UNVERIFIED` and nothing may present a declaration as a
  deployment.
- Upsert on `(tenant_id, source_id, identity_value)`; refresh `last_declared_at`.
- Sanitize any attributes through `AiSecurityMetadataSanitizer` before storing.

### 4.2 Deployment verification and linking

- Match a declared resource to a connector-discovered `ai_security_artifacts` row by
  tenant-scoped provider/version/digest identity.
- Exactly one unambiguous candidate → `LINKED` with `DIGEST_MATCH` or
  `VERSIONED_IDENTIFIER_MATCH`. More than one → `AMBIGUOUS`; do not guess.
- A reviewed mapping sets `REVIEWED` and records the reviewer. DB constraints already
  enforce that `LINKED` carries both an artifact and a method, and that only `REVIEWED`
  may name a reviewer.
- Fix provider-unqualified relationship lookup before enabling projection (plan §3).

### 4.3 Projection pipeline

- Reuse `ingestion_jobs` with job type `AI_GRID_BOM_PROJECTION`.
- **Add it to `IngestionJobService.AI_SECURITY_JOB_TYPES` or the job is never claimed** —
  it fails silently.
- Persist projection intent in the ingestion transaction, process after commit.
- Identify work by source revision + document checksum + projection version + operation.
- Durable receipts for completed-work idempotency; queued/running dedup is not enough.
- Serialize per tenant; coalesce over a configurable 10s window; process only the latest
  source revision and discard obsolete work.
- Key replacement scopes by logical source, not document id.

### 4.4 `provenance.ai_bom_present`

The fact definition is registered (platform V5) with evidence class `BOM_DOCUMENT` and
workflow use `COVERAGE_CONTEXT`. Still to do: emit it per asset on ingestion, keeping
document ingestion time separate from projection time, and **do not overwrite connector
coverage facts**. Allowlist only bounded fields such as `bomFormat` and `specVersion`.

### 4.5 Budget, retry, entitlement

- Configurable allowance, default 100 admitted projections per tenant per UTC day.
- **Exclude BOM projections from connector scan counts** — a different provider label
  alone does not isolate the budget in `AiGridBudgetService`.
- Requeue throttled jobs via `visible_at` without consuming ordinary failure retries.
- Cap queued/running at 100 per tenant; overflow becomes durable dirty-source state
  displayed as deferred.
- Non-entitled tenants: keep ordinary BOM ingestion working, record
  `HELD_ENTITLEMENT` on the source rather than creating a job per upload, and schedule
  each source's latest revision on enablement.

### 4.6 M2 landmines already handled — do not redo

- `AiSecurityMetadataSanitizer` has the `AI_BOM` provider branch plus
  `AI_BOM_DECLARED_MODEL` / `AI_BOM_DECLARED_DATASET`. Without it every attribute is
  dropped and the artifact **skipped with no error**.
- `AiSecurityTaxonomy` has `AI_DATASET`.
- `provenance.ai_bom_present` is registered in platform V5.

---

## 5. Milestone 3 — remaining work

`finding_kind` filtering is done on both query paths. Everything else is outstanding.

### 5.1 Canonical applicability

- The component assessment path stays the **sole** writer of software vulnerability
  applicability and remediation state. BOM-native correlation records describe document
  matches and reference canonical findings; they must not modify applicability or resolve
  findings.
- Component is the primary vulnerability subject; add `AFFECTED_AI_RESOURCE` as a
  secondary subject role. `finding_subjects` already supports arbitrary roles, so **no
  migration is needed**.
- One finding per resolved component/vulnerability pair — already enforced by the partial
  unique index `uk_findings_component_vulnerability`.
- Refresh BOM workflow summaries after asynchronous correlation completes.

### 5.2 API and query contracts

- Extend vulnerability queries with AI-related and affected-resource filters.
- Use existence predicates for resource filtering; paginate findings **before** loading
  affected-resource summaries.
- Keep policy endpoints and DTOs separate from vulnerability ones.
- **Never infer kind from `finding_list_projection.vulnerability_id`** — it holds a CVE id
  for `VULNERABILITY` rows and an AI policy id for AI rows. `package_name` and `ecosystem`
  are overloaded the same way.
- Apply the same predicates to lists, totals, summaries and exports or they will disagree.

### 5.3 UI

- Split AI Findings into **Software Vulnerabilities** (`finding_kind=VULNERABILITY`) and
  **Policy Violations**. `AiFindingsPage.tsx` has no sub-tab pattern; there is a reusable
  one in `AiFindingDetailPage.tsx` (`fd3-tab` / `fd3-tab--active`).
- New route must be declared **above** `/findings/ai/:findingId` in `App.tsx`, or the
  param route swallows it. There is no `pathForAiFindings()` helper; `/findings/ai` is a
  bare literal in two places.
- Keep All Findings inclusive by default — no existing user's view changes.
- Add `findingKind` to `FindingsFilterModel` and `buildFindingsSearchParams`
  (`client.ts`), the single query-string serializer.
- Show BOM versions, completeness assertions, declared deployment status, component
  breakdown, evidence state and projection status.
- Surface unlinked / failed / held / deferred work as **coverage setup actions, not
  policy violations**.
- Tenant-scoped mapping propose / approve / remove with method-level authorization,
  sensitive-action controls and explicit audit events.

---

## 6. Open decisions

1. **Enable the reclassification correction?** Retires inventory rows and closes findings.
2. **Deploy the migrations.** Platform V5 and tenant V4–V7 exist only on local machines.
3. **Review two `SecurityConfig` edits** — a never-touch file.
   `a47af37` on `main` removed a `permitAll` for `GET /api/auth/context` and `/api/me`
   (tightening, no benefit demonstrated). The M1 branch adds `.cors(withDefaults())` so
   security rejections carry CORS headers. Both were made without prior approval.
4. **Fix the four pre-existing security tests** — investigate `ApiKeyAuthenticationFilter`
   producing `anonymousUser`.
5. **Browser-verify the UI.** Only the upload form has been seen rendering; the BOM
   Evidence column has not.

---

## 7. Conventions that will bite

- **Never edit an applied migration.** Add a new one. Bump both assertions in
  `MigrationCatalogTest` when adding to either line.
- **Repositories must not take a `tenantId` parameter.** `TenantAwareDataSource` pins
  `search_path` and RLS enforces the boundary; `ServiceLayerSchemaIsolationTest` fails
  tenant-qualified queries.
- **Tenant context before the transaction, always.** `TenantAwareDataSource` pins
  `search_path` when the connection is acquired. A `@Transactional` method that switches
  tenant internally silently runs against `tenant_default`. Background code must wrap at
  the call site: `tenantSchemaExecutionService.run(tenant, () -> ...)`.
- Every new tenant table needs `tenant_id NOT NULL REFERENCES platform.tenants(id)`,
  `ENABLE` **and** `FORCE ROW LEVEL SECURITY`, and a `tenant_isolation` policy.
- `@RequiredArgsConstructor` generates parameters in **field declaration order** — adding
  a field mid-class shifts every positional argument in tests.
