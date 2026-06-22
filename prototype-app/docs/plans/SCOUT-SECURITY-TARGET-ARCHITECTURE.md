# Scout Security Target Architecture

Last updated: 2026-06-21

---

## Purpose

This document converts the current security analysis into a Scout-specific target architecture and execution plan.

The goal is to make Scout credible for:
- enterprise buyer diligence
- regional data-residency expectations
- regulated customer discussions
- future SOC 2 / ISO 27001 readiness

This document intentionally prioritizes architecture and operating controls over certifications.

---

## Executive Position

Scout should adopt a `single global security baseline` with `regional compliance overlays`.

The recommended target state is:
- one product architecture
- one canonical control library
- three initial regional deployment boundaries: `EU`, `Japan`, `Global`
- a default `shared bridge tenancy model`
- a promotion path to `dedicated regional stamps` for sensitive customers

For the current codebase, this means preserving the schema-per-tenant direction already in place while finishing the remaining multi-tenant hardening tail, eliminating production-unsafe defaults, and separating the platform control plane from customer security data more explicitly.

---

## Target Principles

1. `Tenant isolation is a top-tier architecture concern`
Each request, background job, cache, export, search index, AI prompt, and log record must preserve tenant boundaries.

2. `Regionality is first-class metadata`
Every tenant-owned dataset must carry a region classification and be processed according to that region's rules.

3. `Control plane and customer data plane must be separate`
Platform administration data can be shared; customer security payloads cannot.

4. `Evidence is part of the control`
A control is incomplete unless Scout can prove it through logs, tests, reports, or runbooks.

5. `Default to the smallest reasonable data footprint`
Retention, deletion, masking, and AI data minimization should be default behaviors.

---

## Current-State Read

Based on the existing repository and docs:
- the platform already uses `schema-per-tenant` PostgreSQL isolation
- the platform schema already holds shared-plane entities such as tenants, users, support grants, and audit events
- tenant-local schemas already hold findings, inventory, correlation state, and connector state
- multi-tenant hardening is still incomplete in some runtime paths
- local and pre-production auth defaults are still more permissive than a production-grade design should allow
- production evidence for restore drills, supply-chain controls, and incident runbooks is not yet mature enough for enterprise diligence

That makes the current architecture directionally right, but not yet trust-complete.

---

## Target Architecture

### 1. Regional Deployment Model

Scout should support three initial regional boundaries:
- `EU`
- `Japan`
- `Global`

Each region should have:
- its own application deployment stamp
- its own primary database
- its own object storage / backup boundary
- its own KMS or equivalent encryption boundary
- its own log storage and retention policy

#### Decision

The default design should be `regional stamp + schema-per-tenant inside the stamp`.

That gives Scout:
- stronger regional guarantees than a globally shared deployment
- lower cost than per-customer deployments
- a clean upgrade path for sensitive customers

#### Promotion Path

Customers should be tiered into:
- `Standard`: shared regional stamp, schema-per-tenant
- `Regulated`: shared regional stamp, schema-per-tenant, dedicated encryption context, stricter support and export rules
- `Strategic`: dedicated regional stamp

---

### 2. Control Plane vs Data Plane Separation

Scout should explicitly split platform services into:

#### Control plane

Stores and serves:
- tenant registry
- plan and billing metadata
- platform user identities
- membership links
- support grants
- configuration metadata that does not contain customer security payloads
- audit index metadata

#### Customer security data plane

Stores and serves:
- SBOMs
- repository-derived metadata tied to a customer tenant
- findings
- correlation records
- inventory records
- exports
- AI summaries and AI-generated workflow artifacts
- tenant-scoped logs and evidence

#### Rules

- customer security data must never be copied into shared-plane tables except by explicit derived, minimized, approved projections
- shared logs must not contain raw tenant payloads
- caches must be tenant-scoped
- search indexes must be tenant-scoped
- AI context windows must be tenant-scoped

---

### 3. Tenant Isolation Model

#### Standard isolation baseline

Scout should keep the current `schema-per-tenant` model as the default isolation pattern.

Required controls:
- no production fallback to default tenant
- tenant context required on every authenticated request
- background jobs execute inside an explicit tenant execution boundary
- pooled connections must always reset `search_path` and tenant session variables
- all exports must be tenant-scoped
- audit events must include actor, tenant, request ID, and target resource

#### Higher-assurance isolation

For regulated or sensitive customers, add:
- per-tenant encryption context
- isolated export buckets / prefixes
- stricter JIT support access
- dedicated log partitioning
- optional dedicated regional stamp

#### Explicit anti-patterns

Scout should not allow:
- mixed-tenant report queries in app code
- shared caches without tenant keys
- AI prompts containing data from multiple tenants
- support tooling with standing broad production access

---

### 4. Data Sovereignty and Data Lifecycle

#### Data classes

Scout should formally classify at least these data classes:
- `Identity`: user profile, role, membership, support grant
- `Repo metadata`: repository references, connector configuration, source metadata
- `SBOM`: package/component manifests and ingestion evidence
- `Security findings`: findings, comments, workflow state, org CVE records
- `Audit logs`: auth, admin, export, support, security events
- `AI input/output`: prompts, summaries, generated actions, model metadata
- `Secrets`: tokens, passwords, API keys, certificates

#### Required metadata per class

Each data class should have:
- tenant ownership
- region scope
- legal sensitivity
- storage system
- retention window
- deletion behavior
- backup behavior
- AI usage permission
- cross-border transfer rule

#### Lifecycle rules

- default to retention minima rather than indefinite storage
- support reversible deletion windows where product behavior requires recovery
- define purge semantics for tenant deletion and export retention
- separate operational recovery retention from customer-visible data retention

---

### 5. Encryption and Key Management

Scout should encrypt:
- database storage
- object storage
- backups
- secrets at rest
- all service-to-service and user-to-service traffic in transit

#### Key management target

- region-scoped KMS roots
- service-scoped runtime decryption permissions
- connector secrets in managed secrets storage, not static config
- rotation policies for high-risk secrets

#### Higher-tier option

For enterprise-regulated customers, Scout should prepare a roadmap for:
- customer-specific encryption contexts
- eventually customer-managed key integration where commercially justified

---

### 6. Secure SDLC and Supply Chain

Every release should pass:
- threat-model review for major changes
- SAST
- dependency scanning
- secret scanning
- container / image scanning
- IaC scanning
- SBOM generation
- signed artifact generation

#### Minimum release gate

No release should proceed when:
- critical vulnerabilities are unresolved without formal risk acceptance
- new secrets are detected in source control
- tenant isolation tests fail
- artifact provenance is missing

#### Product-security operating model

Scout should establish:
- vulnerability intake process
- triage SLAs
- patch SLAs
- coordinated disclosure policy
- lightweight PSIRT ownership

This is the right foundation for future CRA-aligned product security maturity.

---

### 7. Detection, Response, and Resilience

#### Logging target

Centralize:
- authentication events
- role and policy changes
- support access
- data export activity
- connector secret changes
- restore operations
- tenant isolation anomalies
- CI/CD security gate failures

Critical log streams should have immutable or write-restricted retention.

#### Detection target

Add alerts for:
- repeated auth failures
- privilege escalation
- expired-grant access attempts
- cross-tenant access attempts
- abnormal bulk exports
- secret access anomalies
- suspicious AI usage patterns involving sensitive data

#### Incident classes

Scout should maintain playbooks for:
- privacy breach
- tenant isolation failure
- credential compromise
- supply-chain compromise
- AI misuse / data leakage

#### Recovery target

Each platform service should have explicit:
- `RTO`
- `RPO`
- backup ownership
- restore steps
- validation evidence

Monthly restore drills should become a standing control.

---

## Architecture Decisions To Lock Now

### ADR-1: Regional Stamp Model

Decision:
Use `EU`, `Japan`, and `Global` regional stamps as the default deployment boundary.

Why:
This is the simplest architecture that satisfies early residency expectations without forcing per-customer silos.

### ADR-2: Default Tenancy Model

Decision:
Use `schema-per-tenant inside a regional stamp` as the standard model.

Why:
It is already close to the current architecture and offers a practical balance of isolation and cost.

### ADR-3: Sensitive Customer Promotion Path

Decision:
Introduce `Standard`, `Regulated`, and `Strategic` tenancy tiers.

Why:
This prevents one tenancy model from being overloaded with contradictory promises.

### ADR-4: No Default-Tenant Fallback In Production

Decision:
Production requests and background flows must never resolve to a default tenant implicitly.

Why:
This is required to make the isolation model credible.

### ADR-5: Control Plane / Data Plane Split

Decision:
Platform-plane services may store shared metadata, but tenant security payloads remain region-local and tenant-local.

Why:
This reduces accidental cross-tenant leakage and makes residency rules enforceable.

### ADR-6: Security Release Gates

Decision:
A release is not valid unless it passes security checks, isolation tests, and artifact provenance requirements.

Why:
This turns secure SDLC from policy text into an actual control.

---

## 6-Week Delivery Plan

### Week 1: Architecture and Inventory

Deliverables:
- `data-classification-matrix`
- `regional-data-residency-matrix`
- `tenant-isolation-architecture`
- `control-plane-vs-data-plane-diagram`

Success criteria:
- every major data class is identified
- every data class has a region and retention owner
- target tenancy model is approved

### Week 2: Tenancy Hardening Decisions

Deliverables:
- remove or plan removal of production default-tenant fallback
- tenant execution boundary review for background jobs
- tenant escape test suite design
- support access target design

Success criteria:
- all known production paths have an explicit tenant-context strategy
- tenant-escape acceptance tests are defined

### Week 3: Logging and Detection

Deliverables:
- audit event taxonomy
- security logging schema
- alert catalog
- incident class matrix

Success criteria:
- key auth/admin/export/support events are logged consistently
- at least the top anomaly alerts are defined

### Week 4: Recovery and Resilience

Deliverables:
- backup and PITR design
- RTO/RPO matrix
- restore drill runbook
- regional failover assumptions

Success criteria:
- service owners are assigned
- restore evidence format is defined

### Week 5: Secure SDLC and Supply Chain

Deliverables:
- release security gates spec
- CI security toolchain plan
- SBOM policy
- PSIRT / vulnerability workflow

Success criteria:
- required release checks are documented and owned
- vulnerability SLA policy is approved

### Week 6: Diligence Pack v1

Deliverables:
- security target architecture packet
- privacy/residency summary
- support access summary
- restore/runbook evidence placeholders
- customer and investor security FAQ draft

Success criteria:
- Scout can explain its trust architecture in one review packet
- the packet clearly distinguishes current controls, in-flight controls, and roadmap items

---

## Implementation Backlog

### P0

- complete multi-tenant hardening tail
- eliminate production-unsafe auth and default-tenant behaviors
- define regional stamp model
- separate control-plane metadata from tenant security payload handling
- implement backup + PITR + restore drill process

### P1

- add tenant-escape tests in CI
- formalize audit logging taxonomy
- introduce JIT support access workflow
- add release security gates: SAST, SCA, secrets, container, IaC, SBOM, signing
- create vulnerability intake and triage workflow

### P2

- regulated-tier encryption context design
- enterprise SSO / SCIM roadmap
- customer-managed key feasibility study
- regional failover design
- diligence packet automation

---

## Evidence Expectations

Scout should collect evidence for each control family:

### Data sovereignty and tenancy
- architecture diagrams
- residency matrix
- tenant isolation tests
- support grant logs

### Secure SDLC
- CI run history
- scan results
- SBOM artifacts
- artifact signing proof

### Detection and resilience
- logging screenshots or queries
- alert definitions
- restore drill reports
- incident tabletop notes

### Governance
- vulnerability register
- policy approvals
- vendor/subprocessor list
- risk register

---

## Recommended Immediate Next Steps

1. Approve the `regional stamp + schema-per-tenant` target model.
2. Create the data classification and residency matrices.
3. Write ADRs for tenancy, control-plane separation, and release gates.
4. Remove production default-tenant behaviors from the target design.
5. Start tenant-escape testing and restore-drill planning in parallel.

---

## Bottom Line

Scout does not need to start with certifications.

Scout needs to become able to prove:
- where tenant data lives
- how tenant boundaries are enforced
- how releases are secured
- how incidents are detected
- how recovery works

Once that trust core exists, regulatory overlays and attestations become much faster, cheaper, and more credible.
