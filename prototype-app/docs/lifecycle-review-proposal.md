# Software Lifecycle Governance Proposal

**Audience:** Product management, design, backend, frontend, and operations stakeholders
**Purpose:** Expand the current EOL mapping workflow into a broader lifecycle governance model for product, platform, service, internal-software, and appliance identities while explicitly excluding package libraries
**Status:** Proposal
**Date:** 2026-04-11

---

## 1. Executive Summary

The current EOL workflow is centered on one narrow question:

- "Can this software identity be mapped to a public lifecycle source such as `endoflife.date`?"

That is useful, but it is not broad enough to represent how organizations actually govern software lifecycle risk.

In practice, a software estate includes many different classes of software:

- operating systems
- runtimes
- databases
- commercial off-the-shelf products
- evergreen SaaS products
- managed cloud services
- internally built software
- appliances, embedded software, and firmware-backed products

These categories do not all share the same lifecycle model.

Some have:

- publicly documented EOL dates

Some are governed by:

- vendor support contracts
- release channels
- vendor release and support practices
- internal product ownership
- service operating models

The current unmatched EOL queue is therefore solving only one slice of a larger governance problem.

### Proposal

Reframe the current EOL review area into a broader **Software Lifecycle Governance** workflow inside `Operations -> Quality -> EOL`.

The system should determine:

1. what class of software an identity belongs to
2. which lifecycle control model applies
3. what evidence supports that lifecycle posture
4. when it should be reviewed again
5. whether it requires analyst action

Instead of treating everything as a missing public EOL mapping problem, the product should support multiple lifecycle control types such as:

1. `Public Lifecycle Mapped`
2. `Vendor Support Governed`
3. `Evergreen Vendor Managed`
4. `Internal Owner Governed`
5. `Accepted Exception`
6. `Needs Research`

This approach gives the platform a more accurate lifecycle model, reduces queue noise, improves auditability, and creates a foundation for better lifecycle reporting across the entire estate.

---

## 2. Why The Scope Should Be Broader Than COTS

The COTS problem is real, but it is only one symptom of a larger issue.

### What We Learned From The Current EOL Queue

The current workflow exposed a basic modeling gap:

- an identity without a public EOL mapping is not necessarily a bad record
- it may simply belong to a category where public EOL is not the right control

That applies not only to COTS software, but also to:

- evergreen SaaS products with no version-specific retirement date
- internal services whose lifecycle is governed by product teams
- managed services where lifecycle is governed by a cloud provider
- appliances where support is governed by entitlement or hardware generation

### Broader Product Insight

The real product need is not:

- "track end-of-life"

The real need is:

- "govern software lifecycle posture using the right control for each software type"

This is a broader and more durable framing.

---

## 3. Problem Statement

### Current Limitation

Today, lifecycle ambiguity is handled mostly through a public EOL lens.

That creates several failure modes:

1. valid software appears unresolved because it lacks a public lifecycle slug
2. analysts are pushed to create artificial mappings just to clear the queue
3. different lifecycle concepts get collapsed into one status
4. the system cannot clearly distinguish between:
   - missing evidence
   - not applicable to public EOL
   - governed by another control
   - accepted risk

### Why This Matters

Without a broader lifecycle model, we risk:

1. lower analyst trust in the queue
2. inaccurate lifecycle reporting
3. unnecessary manual work
4. bad incentives to encode fake precision
5. poor long-term governance maturity

### Explicit Scope Boundary

This proposal intentionally excludes package libraries such as:

- npm packages
- PyPI packages
- Maven artifacts
- Go modules
- NuGet packages

Those identities should remain out of the EOL-quality review scope unless and until we define a separate package-maintenance governance model.

---

## 4. Product Goal

Build a lifecycle governance model that lets the system answer, for any software identity:

1. **What kind of software is this?**
2. **What lifecycle control model should apply?**
3. **What evidence do we have?**
4. **Who owns the lifecycle decision?**
5. **When should it be reviewed again?**
6. **Is there actionable lifecycle risk, or is lifecycle governed appropriately?**

---

## 5. Scope Taxonomy

To handle lifecycle correctly, we should explicitly recognize that different software classes use different governance models.

### 5.1 Public Lifecycle Products

These are products where lifecycle is publicly documented and versioned.

Examples:

- Windows Server
- SQL Server
- Ubuntu
- Node.js
- Python
- Tomcat
- Spring Boot

**Primary control**

- map to public lifecycle source
- compute EOL or near-EOL automatically

### 5.2 Commercial Products With Contractual Support

These are products where support exists, but not necessarily through a public lifecycle calendar.

Examples:

- commercial desktop software
- licensed enterprise middleware
- proprietary vendor tools
- commercial security products

**Primary control**

- vendor support evidence
- entitlement or contract status
- version support statement

### 5.3 Evergreen SaaS And Vendor-Managed Services

These are products where version-specific EOL is not the right model.

Examples:

- SaaS platforms
- managed cloud services
- vendor-operated hosted software

**Primary control**

- vendor-managed evergreen posture
- service-level or product-level support evidence

### 5.4 Internal Software And Internal Services

These are software identities that the organization owns directly.

Examples:

- internal applications
- internal services
- internal shared libraries
- custom frameworks

**Primary control**

- internal owner assignment
- release policy
- support commitment
- retirement plan or roadmap

### 5.5 Appliances, Embedded Software, And Firmware-Backed Products

These are products where lifecycle may be tied to hardware models, appliance generations, firmware baselines, or entitlement.

Examples:

- network appliances
- security appliances
- storage systems
- hardware controllers

**Primary control**

- vendor support matrix
- firmware train support
- hardware generation support window

---

## 6. Lifecycle Governance Model

### Core Design Principle

The system should not have one generic "EOL status" for everything.

Instead, each software identity should have:

1. a `software class`
2. a `lifecycle control type`
3. a `lifecycle disposition`
4. a `supporting evidence record`
5. a `review cadence`

### Proposed `software class`

- `PUBLIC_PRODUCT`
- `COMMERCIAL_PRODUCT`
- `EVERGREEN_SERVICE`
- `INTERNAL_SOFTWARE`
- `APPLIANCE_OR_FIRMWARE`
- `UNKNOWN`

### Proposed `lifecycle control type`

- `PUBLIC_EOL_SOURCE`
- `VENDOR_SUPPORT_EVIDENCE`
- `EVERGREEN_SERVICE_MODEL`
- `INTERNAL_OWNER_MODEL`
- `APPLIANCE_SUPPORT_MODEL`
- `EXCEPTION_MODEL`

### Proposed `lifecycle disposition`

- `PUBLIC_LIFECYCLE_MAPPED`
- `VENDOR_SUPPORTED`
- `EVERGREEN_VENDOR_MANAGED`
- `INTERNAL_OWNER_GOVERNED`
- `APPLIANCE_SUPPORT_GOVERNED`
- `ACCEPTED_EXCEPTION`
- `NEEDS_RESEARCH`

This lets us distinguish:

- how lifecycle is governed
- what the current outcome is

without forcing everything into an EOL-mapping bucket.

---

## 7. What "Safe To Use" Should Mean

This is an important business clarification.

We should avoid using "no EOL" as shorthand for "safe."

### Better Interpretation

If a product has no public EOL, that should mean:

- "public EOL tracking is not the governing lifecycle control"

It should not automatically mean:

- "low risk"
- "fully supported"
- "safe indefinitely"

### Recommended Language

Instead of saying:

- `No EOL`

We should say one of:

- `Public EOL not applicable`
- `Vendor support governs lifecycle`
- `Internal owner governs lifecycle`
- `Evergreen service lifecycle model`

That language is much more precise and much more useful operationally.

---

## 8. Proposed Analyst Workflow

### Queue Name

Retain the existing location:

- `Operations -> Quality -> EOL`

But reinterpret it as:

- `Lifecycle Review`

### Analyst Questions

When a record enters the queue, the analyst should answer:

1. What kind of software is this?
2. Is public lifecycle mapping appropriate?
3. If not, which lifecycle control model governs it?
4. What evidence supports that conclusion?
5. When do we want to review this again?

### Proposed Analyst Actions

1. `Map to Public Lifecycle`
2. `Mark Vendor Supported`
3. `Mark Evergreen Service`
4. `Mark Internal Owner Governed`
5. `Mark Appliance Support Governed`
6. `Create Exception`
7. `Needs Research`

### Why This Is Better

This workflow acknowledges that:

- not every software identity needs a slug
- not every software identity needs an EOL date
- every software identity still needs a lifecycle governance model

---

## 9. Evidence Model

Every lifecycle decision should be auditable.

### Suggested Common Evidence Fields

- `evidence_source_type`
- `evidence_url`
- `evidence_note`
- `review_owner`
- `reviewed_by`
- `reviewed_at`
- `next_review_at`
- `expires_at`

### Suggested Evidence Source Types

- `PUBLIC_EOL_CATALOG`
- `VENDOR_DOC`
- `SUPPORT_CONTRACT`
- `VENDOR_PORTAL`
- `PACKAGE_REGISTRY`
- `PACKAGE_REPOSITORY`
- `INTERNAL_OWNER_ATTESTATION`
- `PROCUREMENT_RECORD`
- `ANALYST_EXCEPTION`

### Evidence By Control Type

#### Public Lifecycle Mapped

- EOL slug
- source URL
- optional cycle mapping evidence

#### Vendor Supported

- vendor support page
- support contract or entitlement reference
- edition/version review note

#### Evergreen Vendor Managed

- vendor statement that service is evergreen
- internal classification note

#### Internal Owner Governed

- owner team
- service/application owner
- support commitment
- retirement policy or roadmap reference

#### Accepted Exception

- approver
- rationale
- expiry date

---

## 10. Queue And Issue Design

### Current State

The current queue is mostly built around "missing public EOL mapping."

### Proposed Future State

The queue should represent "missing or stale lifecycle governance decisions."

### Recommended Issue Types

1. `No lifecycle control assigned`
2. `Public lifecycle mapping missing`
3. `Vendor support evidence missing`
4. `Internal lifecycle owner missing`
5. `Lifecycle review expired`
6. `Lifecycle exception expiring`
7. `Lifecycle source stale or invalid`

### Queue Columns

Retain:

- software identity
- source system
- ecosystem
- open findings
- open vulnerabilities
- components
- assets
- last seen

Add:

- software class
- lifecycle control type
- lifecycle disposition
- evidence freshness
- next review

---

## 11. Decision Framework By Software Type

### 11.1 Public Product / Runtime / Platform

**Default control**

- `PUBLIC_EOL_SOURCE`

**Fallback**

- if no public source exists, analyst may choose vendor support or needs research

### 11.2 Commercial Product

**Default control**

- `VENDOR_SUPPORT_EVIDENCE`

**Fallback**

- if public lifecycle exists, public mapping may still be used

### 11.3 Evergreen SaaS

**Default control**

- `EVERGREEN_SERVICE_MODEL`

### 11.4 Internal Software

**Default control**

- `INTERNAL_OWNER_MODEL`

The lifecycle question becomes:

- who owns this software
- what is its support policy
- is it actively maintained
- is there a decommissioning plan

### 11.5 Appliance / Firmware

**Default control**

- `APPLIANCE_SUPPORT_MODEL`

The lifecycle question becomes:

- is this hardware generation supported
- is this firmware train supported
- is entitlement active

---

## 12. Data Model Proposal

### New Lifecycle Decision Record

Introduce a dedicated lifecycle decision record separate from the existing slug mapping table.

Suggested fields:

- `id`
- `tenant_id`
- `software_identity_id`
- `software_class`
- `lifecycle_control_type`
- `lifecycle_disposition`
- `decision_status`
- `eol_slug`
- `evidence_source_type`
- `evidence_url`
- `evidence_note`
- `owner`
- `reviewed_by`
- `reviewed_at`
- `next_review_at`
- `expires_at`
- `created_at`
- `updated_at`

### Decision Status

- `ACTIVE`
- `SUPERSEDED`
- `EXPIRED`
- `REOPENED`

### Relationship To Existing EOL Mapping

Keep the current EOL mapping table for public lifecycle mappings.

Use the new lifecycle decision record to represent broader governance outcomes.

This avoids overloading slug mappings with meanings such as:

- vendor supported
- evergreen
- internal ownership
- exception

---

## 13. How Reporting Should Evolve

With a broader lifecycle model, the system can report on lifecycle governance in a much more useful way.

### Recommended Rollups

1. `Public lifecycle tracked`
2. `Vendor support governed`
3. `Evergreen managed`
4. `Internal owner governed`
5. `Accepted exceptions`
6. `Needs research`
7. `Review expired`

### Recommended Business Questions

Leadership should be able to answer:

1. How much of our estate has an explicit lifecycle governance model?
2. How much depends on public lifecycle sources versus other controls?
3. Which unresolved lifecycle records affect the most assets and findings?
4. Which lifecycle decisions are stale and need revalidation?
5. How much of our software estate still lacks any lifecycle decision?

---

## 14. MVP Recommendation

Even though the full model is broad, we should still stage this carefully.

### MVP Scope

Ship:

1. software class
2. lifecycle disposition
3. evidence note or URL
4. review owner
5. next review date
6. queue suppression for resolved lifecycle decisions

### Recommended MVP Dispositions

1. `PUBLIC_LIFECYCLE_MAPPED`
2. `VENDOR_SUPPORTED`
3. `EVERGREEN_VENDOR_MANAGED`
4. `PACKAGE_MAINTENANCE_GOVERNED`
5. `INTERNAL_OWNER_GOVERNED`
6. `NEEDS_RESEARCH`
7. `ACCEPTED_EXCEPTION`

### Why This MVP Is Worth It

This gives us a single lifecycle decision framework that works for:

- products
- services
- internal software
- appliances and firmware-backed products

without requiring all the advanced automation on day one.

---

## 15. Phased Roadmap

### Phase 1: Lifecycle Decision Layer

Add:

- lifecycle decision data model
- lifecycle review queue actions
- rationale and evidence capture
- next review date

### Phase 2: Broader Lifecycle Signals

Add:

- vendor support evidence workflows
- internal software ownership capture
- evergreen classification support

### Phase 3: Automation And Revalidation

Add:

- automatic reopening of stale decisions
- stale evidence alerts
- exception expiry alerts
- governance dashboards

### Phase 4: Stronger Domain-Specific Controls

Potential later additions:

- contract-system integration
- appliance support-matrix integration

---

## 16. Risks And Mitigations

### Risk 1: The model becomes too abstract

**Mitigation**

- keep the analyst workflow concrete
- anchor actions to software class
- ship clear defaults by class

### Risk 2: Analysts overuse broad classifications

Examples:

- everything gets marked vendor supported
- everything gets marked evergreen

**Mitigation**

- require rationale
- require evidence for non-research states
- require review date

### Risk 3: Scope creep pulls package-governance work into this track

**Mitigation**

- keep package libraries out of this scope entirely
- continue excluding them from the lifecycle review queue
- address them later in a separate package-governance proposal if needed

### Risk 4: Internal software ownership data is incomplete

**Mitigation**

- start with manual owner capture
- treat missing owner as a lifecycle issue type

### Risk 5: The queue becomes a dumping ground

**Mitigation**

- report by disposition
- track unresolved volume and aging
- reopen stale decisions automatically

---

## 17. Open Questions

1. Should internal software and COTS use the same analyst form with conditional fields, or separate review panels by software class?
2. Should evergreen vendor-managed services count as "resolved" or as a separate monitored state?
3. How do we infer software class initially:
   - ecosystem
   - source system
   - vendor heuristics
   - analyst override
4. Should lifecycle governance be shown directly in the Software Identities page as a first-class facet?

---

## 18. Final Recommendation

The right long-term framing is not:

- `EOL mapping`

The right framing is:

- `Software lifecycle governance`

Public EOL is one important lifecycle control, but it is only one control among several.

The product should evolve toward a lifecycle model that supports:

1. public lifecycle tracking
2. vendor support governance
3. evergreen service governance
4. internal ownership governance
5. exceptions and revalidation

That broader model gives us:

- better analyst experience
- cleaner queues
- better reporting
- stronger governance semantics
- a more accurate representation of real-world software estates

### Recommended Immediate Product Direction

Use the current Operations Quality EOL area as the launch point for a broader lifecycle decision framework, while keeping the existing public EOL mapping capability as one workflow inside that broader system.

### Scope Note

Package libraries are intentionally excluded from this proposal and should remain excluded from the lifecycle review queue until we define a separate package-maintenance strategy.
