# AI Grid customer security roadmap

**Decision date:** 2026-09-23
**Purpose:** Help customers understand and reduce AI and agent security weaknesses using evidence AI Grid already collects, while expanding coverage in controlled steps.

## Customer promise

AI Grid should tell customers:

> Which AI systems are exposed, weakly controlled, overprivileged, connected to sensitive data, or able to use risky tools—and what evidence and remediation support that conclusion.

For the near term, position AI Grid as **AI security posture and exposure management**, not as complete OWASP compliance, AI red teaming, or runtime threat prevention.

## Current OWASP coverage

The governed catalog has 159 policies: 76 generally available and 83 Phase 2 policies paused.

| OWASP control | Total mappings | GA policies | Paused policies | Direct mappings | Customer assessment |
|---|---:|---:|---:|---:|---|
| LLM01 | 16 | 16 | 0 | 0 | Useful guardrail and prompt-control posture; framework coverage remains partial |
| LLM02 | 59 | 18 | 41 | 8 | Strongest coverage for sensitive data, exposure, encryption and isolation |
| LLM03 | 43 | 24 | 19 | 19 | Strong coverage for effective permissions, identities, tools and MCP paths |
| LLM04 | 35 | 21 | 14 | 8 | Good model, tool, allowlist and provenance coverage |
| LLM05 | 10 | 5 | 5 | 0 | Dataset/pipeline evidence exists; coverage is partial |
| LLM06 | 13 | 3 | 10 | 0 | Consumption and availability evidence exists; most depth is paused |
| LLM07 | 3 | 3 | 0 | 0 | Thin coverage |
| LLM08 | 0 | 0 | 0 | 0 | Mapping gap despite relevant vector/retrieval controls |
| LLM09 | 8 | 8 | 0 | 1 | Limited but operational coverage |
| LLM10 | 7 | 7 | 0 | 0 | Thin supporting coverage |

AI Grid therefore has **mapping breadth across 9 of 10 controls**, but this should not be represented as 90% effective coverage. Only 36 of 194 OWASP mappings are direct, and paused policies must not count as active customer protection.

Before publishing category names in the UI, independently validate the catalog's `frameworkVersion: 2026` mappings against the final OWASP 2026 control definitions. OWASP describes its 2026 release as an updated, incident-informed taxonomy with cross-framework mappings; control IDs should not be assumed to retain earlier-edition meanings without review.

## Metadata available now

### AWS Bedrock and AgentCore

- Agent status, execution role and wildcard permissions.
- Guardrail attachment, status, strength and filter counts.
- Models, action groups, Lambda targets and unauthenticated function URLs.
- Knowledge bases, data sources, S3 exposure and Macie classifications.
- Invocation logging, KMS and private-network posture.
- AgentCore gateway/target auth, endpoint hostname, status and synchronization.
- AgentCore runtimes, versions, endpoints, served versions, execution roles and workload identities.
- Browser, Code Interpreter and memory inventory and status.
- SageMaker models, endpoints, pipelines and network posture.

### Azure AI and Foundry

- AI account exposure, local authentication, managed identities, logging, CMK and private endpoints.
- Foundry agents and versions, active version, model, prompt digest, tools and MCP relationships.
- RAI policy and filter configuration.
- Effective RBAC, PIM, access review and role-condition metadata.
- Azure ML jobs/endpoints and network isolation.
- Search ACL, document authorization, tenant partitioning and retrieval mode.
- Storage exposure and Purview sensitivity evidence.
- Bot identity, authentication and channel posture.

### Copilot Studio

- Bots and versions.
- Prompt, tool and component inventory.
- Component type and version.
- HMAC-safe prompt and tool-definition digests.
- Version-to-prompt/tool/component relationships.
- Execution ID, agent correlation, status and timestamp.

### Phase boundary for runtime evidence

Phase 1 uses control-plane configuration, inventory and authoritative graph relationships only. It does not create findings from execution events, observed actions, approval decisions, action outcomes, retries, spend, memory operations or agent-to-agent handoffs.

The storage model can hold some of that runtime context, but connectors currently populate only a subset. All execution-dependent detections—and connector enrichment needed to support them—are explicitly deferred to Phase 2. Until the Phase 2 evidence and certification gates are met, runtime signals may be shown only as diagnostics or observations, never as policy violations.

## Customer risk stories to lead with

### 1. AI system exposed to sensitive data

Show public network exposure, weak authentication, sensitive data classification and the relationship path between them.

Relevant policies include `AGCF-XSP-001`, `AGCF-XSP-004`, `AGCF-XSP-006`, AWS S3/knowledge-base policies and Azure Search/Storage policies.

### 2. Agent has excessive effective privilege

Show execution identity, wildcard or admin access, resources reachable and high-impact tools.

Relevant policies include AWS 005 and 039–042, Azure 030–039, and `AGCF-XSP-003/009`.

### 3. Agent lacks an effective safety boundary

Show missing or weak guardrails, missing PII filtering, Code Interpreter use, sensitive retrieval and unapproved tools.

Relevant policies include AWS 001–016, Azure 010–017 and `AGCF-XSP-002/006`.

### 4. MCP or external tool path is untrusted

Show external hostname, authentication posture, route from the agent and sensitive-data reach.

Relevant policies include AWS 031–034 and 063–064, Azure 019–021 and 069/072, and `AGCF-XSP-004/005/010/011`.

### 5. Agent or model definition has drifted

Show active version, model/tool/prompt definition, approved baseline and digest change without storing content.

Current metadata supports this for Azure Foundry and Copilot Studio once an approved-baseline workflow is added.

## Policies to add now

Keep the first agent-risk pack small and deterministic.

These are proposed policy additions unless the table below explicitly references an existing policy. Connector metadata alone does not create a violation. Each risk must be implemented as a governed policy package, evaluated with its declared evidence contract, and certified before it is presented as an active policy violation.

| Priority | New policy | Available evidence | Customer message |
|---|---|---|---|
| P0 | Privileged agent lacks an approved guardrail | Agent→identity, effective privilege, guardrail attachment/filter facts | “This agent can perform high-impact actions without the required safety boundary.” |
| P0 | Active agent version uses an unapproved tool | Active version and provider-backed `USES_TOOL`; tool type/allowlist | “The production agent can invoke a tool that has not been approved.” |
| P0 | Sensitive agent path includes Code Interpreter or another high-impact tool | Provider-backed agent→tool and agent→data relationships; data classification | “A code-capable tool can operate in a system that reaches sensitive data.” |
| P0 | Agent definition changed after approval | Active version plus prompt/tool digest and approved baseline | “The deployed prompt or tool definition changed after security approval.” |
| P1 | Copilot external trigger or skill is outside the allowlist | Component type, version and `USES_TOOL` | “The Copilot can be activated by or invoke an unapproved external component.” |
| P1 | Production agent has no confirmed owner | Agent inventory; normalized cross-provider owner state is a prerequisite | “No accountable owner is confirmed for this production agent.” |
| P1 | Active agent version uses a failed/inactive declared component | Component status plus an authoritative active-version membership edge | “The production agent depends on an unhealthy declared component.” |

Do not create duplicates for risks already covered by `AGCF-XSP-001` through `006`. Improve or certify those correlations and add provider-specific evidence where needed. Phase 1 must not infer AgentCore runtime-to-browser, runtime-to-Code-Interpreter or runtime-to-memory usage: the current control-plane connector inventories those resources but does not provide authoritative attachment edges.

## Finding classification

Use four distinct customer-visible states:

| State | Meaning | Policy violation? |
|---|---|---|
| Posture finding | A published artifact-fact policy failed with complete, fresh evidence | Yes |
| Validated exposure | A published correlation policy matched an authoritative multi-resource path and passed its evidence gate | Yes; present it as a policy-backed exposure |
| Exposure hypothesis or security observation | A risky signal/path exists, but required evidence, freshness or confidence is incomplete | No; show it separately and state what evidence is missing |
| Coverage gap / not assessed | Connector, relationship, capability or metadata is unavailable | No |

Framework mappings belong to the policy definition. A raw observation, graph path or connector field must not independently claim an OWASP violation.

### Current versus proposed agent risks

| Agent risk | Current status |
|---|---|
| High-impact tool reaches confirmed sensitive data | Existing validated-exposure policy: `AGCF-XSP-002` |
| Broad identity permissions reach a high-impact tool | Existing validated-exposure policy: `AGCF-XSP-003` |
| External/unapproved MCP reaches sensitive data | Existing validated-exposure policy: `AGCF-XSP-004` |
| Autonomous/high-impact execution uses weak MCP authentication | Existing validated-exposure policy: `AGCF-XSP-005` |
| Sensitive retrieval lacks required guardrail/PII baseline | Existing validated-exposure policy: `AGCF-XSP-006` |
| Bedrock agent has no attached guardrail | Existing posture policy: `AGCF-AWS-001` |
| Foundry tool type is outside the approved allowlist | Existing posture policy: `AGCF-AZR-021`; it does not yet provide every active-version correlation proposed above |
| Privileged agent lacks an approved guardrail | Proposed combined correlation policy |
| Prompt or tool definition changed after approval | Proposed policy; digest evidence exists, approval baseline is required |
| Copilot external trigger/skill is unapproved | Proposed policy |
| Production agent lacks confirmed ownership | Proposed policy; owner normalization is required |
| AgentCore runtime lacks authoritative execution identity | Phase 2 runtime-foundation policy |
| AgentCore endpoint serves an unhealthy/unapproved version | Phase 2 runtime-foundation policy |
| Runtime execution cannot resolve to one agent/version | Phase 2 policy; currently retained only as correlation diagnostic metadata |
| Approval bypass, denied action succeeded, or sensitive-read-to-external-action | Phase 2 behavior policies; current connector evidence is insufficient |

## Phase 2 runtime detections

The following are not part of Phase 1 and must remain roadmap items rather than current customer claims:

- Consequential action succeeded without approval.
- Policy-denied action nevertheless succeeded.
- Sensitive-data read followed by external send/write.
- Runtime used an undeclared tool or tool version.
- Repeated tool-call/retry loop exceeded the safety threshold.
- Agent-to-agent handoff lacked authenticated, constrained delegation.
- Durable memory lacked tenant/user isolation or retention controls.

The connector enrichment, runtime evidence contract, policy waves and release gates for these detections are specified in [AI Grid Phase 2 runtime security plan](./AI_GRID_PHASE_2_RUNTIME_SECURITY_PLAN.md).

## Outcome roadmap

### Phase 1 — trustworthy posture and static agent exposure (0–60 days)

**Outcome:** Enable customers to find and remediate what an AI system or agent *could* access or invoke, using authoritative control-plane evidence without requiring runtime telemetry.

- Present the five customer risk stories above.
- Show the affected AI system, evidence path, root cause, remediation and reviewed framework mapping for every finding.
- Separate GA, preview/paused, unsupported and missing-evidence coverage.
- Certify the highest-value identity, MCP, retrieval and exposure policies already backed by connector evidence.
- Add approved baselines for active agent versions, prompt/tool digests, models and declared components.
- Normalize ownership across AWS, Azure and Copilot Studio.
- Release the Phase 1 agent-risk policies listed in “Policies to add now.”
- Add an Agent Risk view organized around identity, tools, data, guardrails, definitions, versions and MCP.
- Map relevant policies to OWASP Top 10 for Agentic Applications 2026 while retaining reviewed OWASP LLM and CSA AICM mappings.

#### Phase 1 definition of done

Phase 1 is complete only when all of the following are true:

- **Scope integrity:** every enabled policy uses only configuration, inventory, classification, approved-baseline or authoritative graph evidence; no policy requires execution-event metadata.
- **Applicability integrity:** missing, stale, ambiguous or unsupported evidence produces `UNKNOWN` or `NOT_ASSESSED`, never `PASS`.
- **Coverage transparency:** the published matrix distinguishes direct, partial and not-assessed coverage and excludes paused policies from effective coverage.
- **Evidence quality:** at least 85% of supported in-scope AI assets are evaluable for their applicable GA policy families.
- **Finding quality:** High/Critical policies achieve at least 95% precision in an answer-key corpus and pass positive, negative and missing-evidence certification cases.
- **Agent graph completeness:** at least 80% of supported production agents have a resolved owner, acting identity, active version and declared tool relationships, or an explicit coverage-gap reason.
- **Actionability:** at least 90% of findings include resource-specific evidence, the failed condition, a remediation path and reviewed framework mapping rationale.
- **Product semantics:** posture findings, validated exposures, hypotheses and coverage gaps are visibly distinct; no runtime observation is labelled a policy violation.
- **Release governance:** policy versions, manifests and mappings are immutable, independently reviewed and released through the existing certification gate.

### Phase 2 — evidence-backed runtime risk (separate plan; target 61–180 days)

**Outcome:** Enable customers to distinguish what an agent *could* do from what it *actually did*, using privacy-minimised, capability-aware execution evidence.

Phase 2 engineering can proceed in parallel, but no runtime policy is released until the Phase 1 scope and finding-quality gates are met. Phase 2 covers runtime-resource foundations, connector enrichment, execution correlation, runtime sequence/aggregate evaluation and behavior policies. The implementation roadmap is maintained separately in [AI Grid Phase 2 runtime security plan](./AI_GRID_PHASE_2_RUNTIME_SECURITY_PLAN.md).

#### Phase 2 definition of done

Phase 2 is complete only when all of the following are true:

- **Connector capability:** at least two supported connectors emit normalized action, target, acting identity, agent/version, policy decision, approval decision and outcome metadata for consequential actions.
- **Correlation:** at least 90% of collected executions resolve to exactly one agent and at least 80% resolve to the executing version where the provider exposes that identifier.
- **Decision completeness:** at least 90% of consequential actions contain authoritative or explicitly qualified policy, approval and outcome evidence.
- **Runtime evaluator:** bounded `RUNTIME_SEQUENCE` and `RUNTIME_AGGREGATE` modes enforce tenant, time-window and event-count limits and are protected by feature flags and kill switches.
- **Policy semantics:** absent required telemetry results in `UNKNOWN` or `NOT_ASSESSED`; an observation or hypothesis cannot become a violation without its policy evidence gate.
- **Detection quality:** the initial runtime pack has at least five precision-certified policies, with at least 95% precision for High/Critical findings and tested late, duplicate and out-of-order events.
- **Investigation quality:** a finding reconstructs agent, version, acting/delegated identity, tool, target class, decision, approval and outcome without exposing raw prompt or business payload content.
- **Privacy and operations:** raw prompts, responses, tool arguments, credentials and document bodies are excluded by default; retention, access, deletion, health, lag and cost controls are operational.
- **Framework integrity:** each runtime policy has independently reviewed mappings to OWASP Agentic Top 10 and, where applicable, OWASP LLM or CSA AICM.

## Customer-facing coverage language

Use:

- “Mapped to OWASP” for a reviewed relationship.
- “Directly assessed” when the policy evaluates the core risk with authoritative evidence.
- “Partially assessed” when AI Grid evaluates only supporting conditions.
- “Not assessed” when a connector or required capability is absent.

Avoid:

- “OWASP compliant.”
- A single coverage percentage that counts partial, paused and unsupported policies equally.
- Treating absence of metadata as a pass.
- Calling static permission or reachability evidence a runtime attack detection.

## Immediate backlog

1. Certify the currently paused effective-permission policies: AWS 039–042 and Azure 033–039; release them under the Phase 1 static-evidence boundary.
2. Certify MCP authoritative-auth policies: AWS 071–072 and Azure 072.
3. Certify retrieval/isolation policies: AWS 048–050, Azure 042–045 and XSP-012.
4. Add reviewed LLM08 mappings to those retrieval/vector policies.
5. Implement “privileged agent without approved guardrail.”
6. Implement “active version uses unapproved tool.”
7. Add approved prompt/tool digest baselines for Foundry and Copilot.
8. Add normalized owner state and unowned-production-agent policy.
9. Publish the customer-facing OWASP coverage matrix with effective, partial and not-assessed states.
10. Keep runtime-resource and execution-event policies disabled and route their prerequisites to the separate Phase 2 backlog.

## Source

- [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
