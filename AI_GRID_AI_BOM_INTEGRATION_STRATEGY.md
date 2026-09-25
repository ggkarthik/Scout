# Wire AI-BOM ingestion into AI Grid

## Decision

Treat an uploaded AI-BOM as a versioned, tenant-owned evidence source. Project its safe model and component metadata into AI Grid, link it to a deployed model only through an explicit or verified identifier, and evaluate it in a new Grid run. Keep the original BOM record and components as the source of truth. An upload alone is evidence of a document, not proof that a deployed model has complete or current BOM coverage.

## Current path and gap

1. `BomController` accepts `AI_BOM` through upload and fetch. `BomIngestionOrchestrator` creates a `bom_ingestion_records` row and `bom_components` rows, superseding the prior active record for the same asset/type/supplier. It also sends every non-CBOM, including AI-BOM, through generic software inventory and CVE correlation.
2. `BomComponentCategorizationService` labels **every** component of an AI-BOM `AI_MODEL`. That loses the distinction between model, dataset, software, service, and other CycloneDX component types. The parser retains common component fields and raw properties, but has no normalized AI-BOM model identity, composition, or relationship projection.
3. AI Grid is driven by completed `ObservationEnvelopeV1` scopes. `AiSecurityObservationService` stores artifacts and relationships; `AiGridPipelineService` then commits snapshots, facts, assessments, current coverage, systems, and findings. The Grid never reads BOM records or components.
4. The observation metadata sanitizer only accepts registered AWS, Azure, and Copilot native kinds. Persisted relationship targets are looked up by tenant plus `provider_resource_id` without a provider qualifier, so an AI-BOM link needs a stronger unambiguous identity contract. Existing `provenance.model_sbom_coverage_present` facts come from connector attributes, not uploaded BOMs. The related AWS and Azure policies (`AGCF-AWS-058`, `AGCF-AZR-060`) are Phase 2 and paused/disabled; wiring evidence must not silently turn them on.

## Proposed contract

### 1. Define what can be claimed

Add a bounded `AiBomProjection` with `bomId`, tenant, asset ID, checksum, format/version, observed time, status, source, subject identifiers, component counts by actual type, and normalized relationship summaries. Store document and component IDs as evidence references; do not copy the full uploaded document, arbitrary `properties`, model weights, dataset contents, prompts, credentials, or unrestricted external URLs into Grid snapshots.

Keep three distinct states per model: `UNLINKED` (no verified target), `LINKED_UNVERIFIED` (a candidate or manually proposed link), and `VERIFIED` (tenant-scoped provider model/version/deployment identity matches). A verified link can support **BOM present for this model version**. A stronger **coverage complete** claim needs an explicit completeness rule, supported format, and required model/component relationships; absence of a BOM is `UNKNOWN` unless a complete, authoritative source inventory establishes absence.

### 2. Add a durable, auditable bridge

After a successful AI-BOM transaction, enqueue a tenant-scoped projection event keyed by `(tenant_id, bom_id, checksum, projection_version)`. A worker reads only active AI-BOM records and active components, creates or updates a first-class Grid BOM evidence projection, and records processing state, error, and retry count. The bridge must also handle supersede, deletion, retry, and a one-time backfill of existing active AI-BOMs. Do not call Grid evaluation inside the upload transaction; a Grid failure should be retryable without changing a successful BOM ingestion result.

Give the projection its own `AI_BOM` source family and stable identity derived from tenant plus BOM source/subject identity. Extend the Grid admission contract and metadata allowlist deliberately for that source, or use an equivalent dedicated internal projection API with the same tenant, idempotency, sanitization, and complete-scope guarantees. Reuse the snapshot/fact pipeline rather than writing directly to `ai_grid_facts` or mutating an earlier run. One projection run must produce a complete scope so replacement/removal can retire old evidence correctly.

### 3. Resolve deployed-model identity before correlation

Add a link table from BOM subject (and optional version) to an `ai_security_artifacts` model ID. Require same tenant and an exact provider-native model/deployment/version ID, immutable digest, or explicit reviewed mapping. Record match method, confidence, reviewer, timestamps, and the BOM ID. Do not auto-link by display name, supplier, asset name, or loose PURL alone. Support AWS and Azure model kinds already inventoried by Grid; leave unmatched BOMs visible in an `Unlinked AI-BOM` queue. A later connector discovery can retry matching without reuploading the BOM.

Represent `AI_BOM_DOCUMENT -> DESCRIBES_MODEL` and `AI_BOM_DOCUMENT -> CONTAINS_COMPONENT` as governed relationship semantics, or use an equivalent explicit evidence-link table consumed by assessment and API reads. If using `ObservationEnvelopeV1`, replace its provider-unqualified fallback lookup with an explicitly qualified target identity or resolved artifact ID; `limit 1` is unsafe when resource IDs collide across providers. No link should be fabricated from an ambiguous identifier.

### 4. Emit governed facts and reassess

Add BOM-backed fact definitions with precise meanings, for example `provenance.ai_bom_present`, `provenance.ai_bom_version_matched`, `provenance.ai_bom_component_count`, and `provenance.ai_bom_completeness_state`. Each fact carries BOM ID/checksum, matching method, projection version, observed time, validity, and evidence class. Only derive `provenance.model_sbom_coverage_present=true` for the **matched model artifact** after a documented coverage rule passes. Keep provider-supplied coverage evidence separate so conflicting claims are visible and source precedence is explicit.

On upload, replacement, deletion, or newly verified link, start an immutable Grid evaluation run for affected model artifacts and refresh current coverage/findings through the normal pipeline. A replay of an old run must reproduce its old evidence, not read whatever BOM is active today. On expiration or supersede, the current fact becomes stale/unknown and affected findings are reconciled. Never turn missing, unsupported, or unlinked BOM evidence into a negative `false` fact.

### 5. Surface the result

In AI Grid model details show linked BOM status, version/checksum, ingestion and freshness times, source, component breakdown, link method, and a route to the BOM inventory record. Show unlinked and failed projections as setup/coverage actions. Keep policy decisions separate from inventory: a BOM can appear in Grid before any BOM-dependent policy is enabled.

## Implementation order

| Step | Change | Acceptance gate |
| --- | --- | --- |
| 1 | Correct AI-BOM parsing/categorization and define the bounded projection contract. Decide whether AI-BOM should enter generic SBOM/CVE ingestion for each supported component type. | Mixed model/dataset/library fixture retains distinct types; unsupported fields are rejected or omitted. |
| 2 | Add bridge schema, worker, idempotent event, and historical backfill. | Upload, retry, replacement, and delete converge to one current projection per source; tenant isolation holds. |
| 3 | Add verified model identity links and Grid source/relationship admission. | Exact model version links; same-name or cross-tenant models do not; unmatched BOM stays visible. |
| 4 | Produce immutable snapshots/facts and trigger targeted reassessment. | Current model page changes after upload; historical assessment does not; supersede/removal removes current support. |
| 5 | Add UI/API status and coverage actions. | A user can trace every BOM-derived claim to its BOM and matching decision. |
| 6 | Validate the existing BOM coverage policies in preview, then use normal Phase 2 certification and rollout gates. | Unknown stays `NO_DECISION`; true/false decisions require authoritative evidence; no automatic policy enablement. |

## Tests that matter

- End-to-end tenant test: upload an AI-BOM with an exact model version ID, project it, verify its Grid link/facts and current API result, then replace and delete it.
- Negative matching tests: duplicate names across providers/tenants, version mismatch, missing native ID, malformed/unsupported BOM, and a document with only software components.
- Lifecycle tests: duplicate upload/event, worker retry, upload before connector discovery, connector discovery before upload, backfill, out-of-order replacement, and stale evidence.
- Policy tests: unlinked/unsupported/incomplete evidence yields `NO_DECISION`; a verified sufficient BOM yields the intended assessment; a current run cannot rewrite historical assessments.
- Privacy and scale tests: prohibited fields never reach snapshot bodies or API responses; large BOMs stay within bridge and Grid budget limits.

## First deliverable

Ship the bridge, verified model link, inventory visibility, and a narrow `ai_bom_present` fact first. Hold the stronger coverage claim and the paused BOM policies until completeness semantics and golden fixtures are certified. This gives users traceable AI-BOM inventory in Grid without overstating deployed-model security coverage.
