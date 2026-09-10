# ARISE Compliance and Coverage Plan for Scout

## 1. Executive summary

ARISE (Agentic Runtime Identity Security Enforcement) focuses on governing AI-agent actions while they are executing. It combines agent identity, delegated authority, tool and MCP governance, behavioral analysis, data context, policy decisions, runtime enforcement, and audit evidence.

Scout currently provides a strong foundation for ARISE Layer 1 controls: AI inventory, ownership, identity posture, permissions, MCP/tool configuration, sensitive-data relationships, policy evaluation, and evidence tracking. The immediate opportunity is to make this Layer 1 capability complete, reliable, and operationally valuable before adding runtime enforcement.

## 2. Policy mapping estimate

Scout currently contains 159 AGCF policies:

- 72 AWS policies
- 75 Azure policies
- 12 multi-cloud policies

The initial ARISE mapping is:

| Mapping level | Policy count | Interpretation |
|---|---:|---|
| Direct or strong ARISE alignment | 61 | Identity, permissions, credentials, MCP/tools, authorization, delegation, sensitive-data paths, and logging |
| Partial ARISE alignment | 12 | Guardrails, public exposure, encryption, classification, lifecycle, and posture controls supporting runtime decisions |
| Not meaningfully mapped | 86 | Controls not directly related to agent runtime identity or action governance |
| Total catalog | 159 | Current Scout policy estate |

This is a capability mapping, not a certification claim. The mapping should be validated through implementation evidence and runtime demonstrations.

Examples of strongly aligned policy families include:

- AgentCore and MCP authentication
- Approved tools and MCP servers
- Agent execution roles and wildcard permissions
- Privileged role assumption and access elevation
- Cross-account and sensitive-resource access
- Azure RBAC, PIM, access reviews, and conditional assignments
- High-impact tools such as Code Interpreter
- Multi-cloud identity-to-sensitive-data paths
- Authentication and audit logging

Representative policy IDs include `AGCF-AWS-031`, `AGCF-AWS-034`, `AGCF-AWS-039` through `AGCF-AWS-042`, `AGCF-AZR-019` through `AGCF-AZR-021`, `AGCF-AZR-030` through `AGCF-AZR-039`, and `AGCF-XSP-003` through `AGCF-XSP-012`.

## 3. Current maturity assessment

### Layer 1: Deterministic governance — strong foundation

Scout currently supports or is positioned to support:

- Agent and AI artifact inventory
- Owner and resource context
- IAM and RBAC posture
- MCP and tool allowlists
- Credential and authentication posture
- Sensitive-data relationship analysis
- Policy evaluation and evidence tracking

### Layer 2: Behavioral and intent analysis — future extension

These capabilities are useful future extensions, but they are not required for the initial Layer 1 implementation.

### Layer 3: Dynamic runtime governance — future boundary

In-path enforcement should remain a future integration boundary. Layer 1 should produce the trusted inventory, policy decisions, ownership context, and evidence that a future enforcement point can consume.

## 4. Layer 1 implementation plan

The Layer 1 objective is to answer, with authoritative evidence: what AI artifacts exist, who owns them, what identities and resources they use, which controls apply, whether the controls are enabled, and whether the evidence is complete and current. Scout already has the core AI Inventory categories for agents, models, guardrails, identities, MCP servers, data stores, and other artifacts. The implementation should therefore extend the existing inventory and identity views rather than create a parallel asset registry.

### 4.1 Make the existing inventory ARISE-ready

Use the existing AI Inventory as the system of record and strengthen its normalized fields for:

- AI agents and agent versions
- Models, deployments, endpoints, and inference profiles
- MCP servers, gateways, tools, plugins, and action groups
- Knowledge bases, vector stores, search indexes, and data sources
- Bots, workflows, notebooks, pipelines, and AI-enabled applications
- Service accounts, workload identities, managed identities, roles, OAuth grants, and API integrations

Each existing artifact should expose a stable Scout ID, provider resource ID, provider, account or subscription, region, environment, native type, lifecycle state, first-seen time, last-seen time, and source connector. Preserve the current category navigation and add completeness, freshness, ownership, and relationship indicators to each category.

### 4.2 Complete provider discovery coverage

Implement and standardize discovery for AWS, Azure, and multi-cloud sources:

- AWS Bedrock agents, guardrails, models, knowledge bases, data sources, AgentCore, MCP targets, SageMaker, and AI-linked storage
- Azure AI, Foundry, Azure ML, AI Search, Bot Services, managed identities, role assignments, PIM, RAI policies, MCP servers, and endpoints
- Shared cloud identity, network, data classification, and relationship sources

Extend the current provider adapters where fields or artifact relationships are missing. Every adapter should provide:

1. Full inventory discovery
2. Incremental refresh
3. Stable identity reconciliation
4. Deletion and disappearance detection
5. Source freshness and collection status
6. Evidence provenance for each discovered field

### 4.3 Enrich the existing identity artifacts

The existing Identities inventory should become the canonical identity context for agents. Enrich and link those records to:

- Artifact to owner
- Agent to human or team owner
- Agent to service account or workload identity
- Agent to delegating business owner
- Artifact to application or business service
- Artifact to account, subscription, environment, and region
- Artifact to connected tools, APIs, data stores, and other agents

Do not create a duplicate agent-identity registry. Ownership should have an explicit state such as `CONFIRMED`, `INFERRED`, `MISSING`, or `STALE`, together with the evidence source, confidence, reviewer, and review timestamp. The screenshot’s Azure `RBAC GLOBAL` and `IDENTITY` artifacts should be linked to the relevant AI agents, tools, data stores, subscriptions, and role assignments instead of remaining standalone rows.

### 4.4 Add relationship and dependency views to the existing inventory

Represent relationships between the existing inventory artifacts as a graph with relationships such as:

- Agent uses model
- Agent invokes tool
- Agent connects to MCP server
- Agent assumes role
- Agent reads data source
- Agent reaches vector store
- Agent invokes API or workflow
- Public endpoint exposes agent
- Agent reaches sensitive data
- Agent delegates to another agent

This graph is the foundation for multi-cloud exposure policies and future ARISE delegation analysis.

### 4.5 Define authoritative evidence contracts

For every discovered fact, store:

- Fact key and normalized value
- Source provider and connector
- Native resource ID
- Collection timestamp
- Evidence observation timestamp
- Evidence class, such as configuration, identity, relationship, or classification
- Source payload reference or hash
- Freshness limit
- Collection status: complete, partial, failed, or stale

Policies must distinguish `PASS`, `FAIL`, `NO_DECISION`, `NOT_APPLICABLE`, `STALE`, and `INCOMPLETE_SCOPE`. Missing or stale evidence must not be treated as a secure result.

### 4.6 Implement deterministic policy governance

The Layer 1 policy model should govern the catalog and tenant rollout lifecycle:

- Draft
- Validated
- Approved
- Published
- Distributed
- Tenant enabled, preview, or disabled
- Deprecated or retired

Keep platform governance separate from tenant selection. Platform owners should approve and version policies centrally, while tenant administrators control whether distributed policies are enabled for their tenant.

Each policy should declare:

- Provider and native artifact types
- Required resource families
- Required facts and evidence classes
- Required relationships
- Required capabilities and connector dependencies
- Scope and exception behavior
- Severity and workflow class
- Framework mappings
- Default tenant selection
- Evidence freshness requirements

### 4.7 Strengthen policy-to-artifact applicability

For every policy, compute and display:

- Applicable artifact count
- Evaluated artifact count
- Failed artifact count
- Passed artifact count
- No-decision count
- Stale or incomplete evidence count
- Unsupported or unavailable capability count
- Policy coverage percentage

The policy page should explain why a policy applies, why it does not apply, and what evidence is missing. This prevents a zero-failure result from being confused with a zero-resource or unevaluated result.

### 4.8 Add policy simulation and approval workflows

Before enabling a policy for tenants, support:

- Impact preview against the current artifact inventory
- Expected failure count
- Affected provider and artifact types
- Evidence readiness check
- Duplicate or overlapping-policy detection
- Framework mapping review
- Platform approval with version and decision record
- Tenant rollout and rollback

This lets Scout demonstrate governed control deployment without requiring live action blocking.

### 4.9 Make discovery and governance operational

Add Layer 1 dashboards and reports for:

- Total AI artifacts by provider and type
- Unowned and stale artifacts
- Artifacts with unknown identities or credentials
- MCP servers and tools without approved ownership
- Policies with no applicable resources
- Policies blocked by missing connector capabilities
- Failed, partial, stale, and unevaluated evidence
- Tenant policy adoption and rollout status
- Framework coverage by provider, artifact type, and business owner

### 4.10 Establish Layer 1 acceptance criteria

Layer 1 should be considered complete only when Scout can demonstrate:

- Every existing supported AI Inventory artifact has a stable identity and provenance.
- Every existing agent artifact has an owner state and connected identity context.
- Every MCP server and tool is inventoried and linked to consumers.
- Every policy has deterministic applicability and evidence requirements.
- Every result distinguishes failure from missing or stale evidence.
- Every policy change is approved, versioned, auditable, and reversible.
- Tenant policy state is separate from platform policy governance.
- Discovery freshness and connector health are visible.
- Framework mappings can be traced from framework control to policy to artifact evidence.

### 5. Future extensions beyond Layer 1

The following capabilities should be treated as later ARISE phases, not prerequisites for the Layer 1 release:

### 5.1 Runtime identity and delegation extensions

Track the following as first-class entities:

- Agent ID and version
- Human owner
- Delegating user
- Service account or workload identity
- OAuth grant, cloud role, or credential
- Session and task ID
- Connected tools, MCP servers, APIs, models, and data stores

### 5.2 In-path runtime enforcement

Expose a runtime authorization service that evaluates every:

- Tool call
- MCP request
- API request
- Credential request
- Data retrieval
- File export
- Write, delete, or update action
- Agent-to-agent handoff

The decision model should support:

```text
ALLOW, BLOCK, REDACT, PAUSE, STEP_UP,
RESTRICT_SCOPE, REVOKE, ESCALATE
```

### 5.3 Action-level policy fields

Extend policy definitions with:

- Action verb: read, write, delete, export, execute
- Target resource
- Data sensitivity
- Business purpose
- Maximum transaction value
- Approved user or delegator
- Approved tool and model
- Time and location constraints
- Human approval requirement
- Maximum chain depth

### 5.4 Delegated-authority and JIT controls

Implement:

- Short-lived credentials
- Secretless agent execution where possible
- Just-in-time access issuance
- Automatic credential expiry
- Token scope restrictions
- Delegation-chain validation
- Credential revocation during a session
- Prevention of direct secret exposure to model context

### 5.5 Runtime telemetry and action-chain reconstruction

Create an immutable event model linking:

```text
prompt → plan → tool call → credential → resource → data
       → policy decision → outcome
```

The evidence should answer:

- Who or what acted?
- Whose authority was used?
- What action was attempted?
- Which tool, credential, and resource were involved?
- Why was the action allowed or denied?
- What data was touched?
- What was the final outcome?

### 5.6 Behavioral and intent analysis

Introduce detections for:

- Intent drift
- Unexpected tool sequences
- Excessive retries
- Privilege escalation attempts
- Sensitive-data access outside the declared task
- Unusual agent-to-agent handoffs
- Model or tool changes during execution
- High-risk action chains

### 5.7 Runtime-specific policy families

Add approximately 25–35 new ARISE controls covering:

- Agent identity and ownership
- Delegation and authority lineage
- Credential and token use
- MCP action authorization
- Tool risk scoring
- Read/write/delete/export separation
- Human approval
- Runtime blocking and pause controls
- Session termination
- Intent drift
- Chain-level anomaly detection
- Evidence retention and replay
- SIEM, SOAR, and ITSM integration

### 5.8 Extend the policy data model for runtime decisions

Add runtime governance metadata similar to:

```json
{
  "runtimeEnforcement": {
    "required": true,
    "actions": ["READ", "WRITE", "DELETE"],
    "decisionModes": ["ALLOW", "BLOCK", "PAUSE", "ESCALATE"]
  },
  "identityContext": {
    "requiresOwner": true,
    "requiresDelegator": true,
    "requiresCredentialLineage": true
  },
  "intentAnalysis": {
    "enabled": true,
    "detectDrift": true,
    "maxToolChainLength": 8
  },
  "humanApproval": {
    "requiredFor": ["DELETE", "EXPORT", "PRIVILEGE_ESCALATION"]
  }
}
```

## 6. Phased implementation plan with Platform and Tenant scopes

Platform scope governs the shared catalog, schemas, policy lifecycle, provider integrations, evidence standards, and product-wide controls. Tenant scope governs tenant-specific connections, ownership, exceptions, policy selection, operational review, and tenant evidence. Platform governance must remain separate from tenant policy enablement.

### Phase 0: Establish scope and ownership boundaries

**Platform scope**

- Define the canonical AI artifact, identity, ownership, relationship, evidence, and policy data model.
- Define platform roles: Platform Owner, Policy Author, Security Analyst, and Auditor.
- Define tenant roles: Tenant Admin, Tenant Security Analyst, and Tenant Auditor.
- Establish which fields are platform-owned, tenant-owned, connector-owned, or derived.
- Define the ARISE Layer 1 control taxonomy and framework mapping standards.

**Tenant scope**

- Confirm tenant administrator and security contacts.
- Register tenant accounts, subscriptions, regions, environments, and business units.
- Define tenant ownership groups, criticality levels, data classifications, and review periods.
- Identify the tenant’s required providers, artifact types, and evidence retention needs.

**Exit criteria**

- Ownership of every data field and policy decision is documented.
- Tenant data is isolated and platform policy governance cannot be changed from a tenant scope.

### Phase 1: Complete existing discovery and evidence

**Platform scope**

- Reuse the existing AI Inventory and Identities artifacts as the source of truth.
- Standardize artifact IDs, provider resource IDs, native types, lifecycle states, timestamps, and provenance.
- Define the common connector contract for discovery, incremental refresh, deletion detection, freshness, and evidence status.
- Define evidence classes, freshness limits, hashes, source references, and collection states.
- Maintain shared AWS, Azure, and multi-cloud discovery adapters.

**Tenant scope**

- Configure tenant provider connections and discovery targets.
- Discover and reconcile tenant agents, models, guardrails, identities, RBAC artifacts, MCP servers, tools, data stores, and other AI artifacts.
- Confirm or correct ownership, environment, criticality, and business-service metadata.
- Review unowned, stale, failed, and incomplete artifacts.
- Accept or remediate connector and evidence collection gaps.

**Exit criteria**

- Every supported tenant artifact has a stable identity and provenance.
- Existing `RBAC GLOBAL` and `IDENTITY` records are linked to the relevant agents, resources, roles, and data paths.
- Inventory freshness and connector health are visible to both platform and tenant operators.

### Phase 2: Build the AI relationship and identity context

**Platform scope**

- Provide the shared relationship graph and normalized identity model.
- Support relationships for agent-to-owner, agent-to-identity, agent-to-tool, agent-to-MCP, agent-to-data, and agent-to-agent paths.
- Define confidence, confirmation, stale, and missing states.
- Provide reusable graph queries for policy evaluation and framework reporting.

**Tenant scope**

- Confirm agent owners, delegating business owners, service accounts, managed identities, roles, and OAuth grants.
- Review agent access to tools, APIs, data stores, and sensitive resources.
- Resolve identity and ownership gaps or record justified exceptions.
- Approve tenant-specific scope boundaries and critical-resource classifications.

**Exit criteria**

- Each agent has usable owner and identity context.
- Each MCP server and tool is linked to its consumers and access paths.
- Sensitive-data and high-impact access paths are explainable.

### Phase 3: Govern the platform policy catalog

**Platform scope**

- Author, validate, version, approve, publish, deprecate, and retire policies.
- Maintain framework mappings, policy objectives, severity, evidence requirements, capabilities, scope rules, and remediation guidance.
- Detect duplicate and overlapping policies.
- Provide impact simulation against representative inventory data.
- Define rollout stages and approved policy package digests.

**Tenant scope**

- View published policy definitions and impact previews.
- Enable, disable, or place distributed policies in preview according to tenant authority.
- Configure tenant scopes, parameters, exceptions, and evidence thresholds where permitted.
- Review policy applicability, failed artifacts, no-decision results, and remediation ownership.

**Exit criteria**

- Platform approval and tenant enablement are separate auditable actions.
- Every tenant policy result can be traced to a specific platform policy version.

### Phase 4: Operationalize assessment and compliance reporting

**Platform scope**

- Provide deterministic policy evaluation, evidence reconciliation, readiness calculation, and framework traceability.
- Maintain common dashboards for policy estate, coverage, evidence readiness, blind spots, and rollout health.
- Provide cross-tenant aggregate reporting without exposing tenant data across boundaries.
- Retain policy decisions, evidence provenance, approvals, and change history.

**Tenant scope**

- Execute assessments against the tenant’s discovered artifacts.
- Review failed, stale, incomplete, unsupported, and unevaluated results.
- Assign remediation owners and due dates.
- Produce tenant-level framework, risk, evidence, and audit reports.
- Submit exceptions and compensating controls for approval.

**Exit criteria**

- A zero-failure result is distinguishable from zero resources or no evaluation.
- Tenants can produce evidence-backed reports for their own scope.
- Platform owners can measure adoption, coverage, and policy health across tenants.

### Phase 5: ARISE readiness extension

This phase is optional for the initial Layer 1 release and prepares Scout for later ARISE Layers 2 and 3.

**Platform scope**

- Define shared event schemas for prompt, plan, tool call, credential, resource, data, policy decision, and outcome.
- Define runtime identity, delegated authority, action, and session contracts.
- Provide integration boundaries for future policy decision and enforcement points.
- Add organization-wide behavioral and intent signal definitions.

**Tenant scope**

- Select runtime surfaces for pilot coverage, such as MCP, cloud APIs, SaaS, coding agents, or browser agents.
- Configure high-risk action categories and human approval requirements.
- Validate runtime telemetry, action-chain reconstruction, and evidence retention.
- Pilot future allow, block, pause, restrict, revoke, and escalate integrations.

**Positioning outcome**

- Scout is positioned as the ARISE Layer 1 control plane because it already inventories the agents and identities, establishes ownership and relationships, governs policy distribution, and produces trusted evidence.
- Future runtime enforcement components can consume the same tenant-scoped identities, relationships, policy versions, and evidence contracts.
- Customers can adopt ARISE progressively without replacing the existing inventory or policy governance model.

## 7. Bottom line

Scout has a credible ARISE foundation, especially for discovery, identity posture, MCP and tool governance, permissions, and sensitive-data exposure. The highest-value immediate investment is to make Layer 1 authoritative: complete the artifact graph, improve ownership and identity context, formalize evidence freshness, and operationalize versioned policy governance.

This positions Scout for ARISE by providing the trusted control-plane foundation that runtime enforcement depends on. Scout can establish what exists, who owns it, what authority and data paths are connected, which policies apply, what evidence supports the decision, and where gaps remain. Later ARISE runtime components can consume these identities, relationships, policy decisions, and evidence contracts without redesigning the governance model.

## 8. Reference

- Software Analyst Cyber Research, [ARISE: Agentic Runtime Identity Security Enforcement for Agents](https://softwareanalyst.substack.com/p/arise-agentic-runtime-identity-security)
