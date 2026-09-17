# AI Grid: Current Capabilities and Research Brief for an AI-Agent-Security Roadmap

## Purpose

AI Grid is an enterprise AI security posture-management capability within ScoutGrid/VulnWatch. It discovers and governs customer-operated AI and ML systems; it is not the product's internal LLM-assist feature. This brief documents the implemented baseline so that a Deep Research exercise can recommend a credible roadmap from today's AI posture security to AI agent security.

The desired outcome is a sequenced, evidence-based product roadmap. It should identify the smallest high-value expansion that gives security teams visibility and control over autonomous agents, their identities, tools, data, memory, execution, and runtime behavior—while building on AI Grid rather than creating a disconnected product.

## Executive Summary

AI Grid already implements much of the durable control plane required for agent security:

- Multi-cloud discovery of AI resources and their relationships.
- An immutable, redacted evidence pipeline that derives versioned facts.
- Agent-rooted grouping into AI systems, including lineage across scans.
- Governed policy distribution, tenant-level policy configuration, policy evaluation, coverage measurement, and release quality gates.
- Evidence-based exposure correlation, remediation workflow integration, ownership, auditability, scan budgets, cadence control, and retention/legal-hold controls.

The primary gap is not a generic policy engine. It is **agent-runtime observability and enforcement**. Today, the product primarily sees control-plane configuration and selected cloud relationships. It does not yet model an agent execution as a first-class object, continuously ingest agent traces, govern delegated identities and tool permissions at call time, analyze or control memory/RAG provenance, or apply preventive decisions to risky actions. The roadmap should therefore treat AI agent security as a transition from periodic configuration posture to continuous, identity- and action-aware exposure management.

## Product and Operating Model Today

AI Grid is tenant-entitlement-gated (`ai.security`) and isolated from the product's internal AI-assist functionality. A tenant must have the entitlement and a user must have the relevant role. Platform owners control cross-tenant policy publication; tenant administrators and security analysts configure and operate their tenant's adopted policies.

The capability spans these user surfaces:

- AI inventory, artifact detail, relationships, graph, risk rollups, discovery-run history, and policy-failure findings.
- AI systems, their facts, system graph, lineage, and linked findings.
- Validated AI exposure paths, exposure triage/disposition, prioritized overview, action queue, asset posture, and activity history.
- Tenant policy catalog, policy selection, scopes, conditions, parameters, exceptions, and explanations.
- Coverage/readiness views, setup-action queue, assessment-run metrics, budgets, cadence, evidence retention, and legal holds.
- A platform-owner policy studio for policy/correlation catalog governance, quality validation, canary/GA rollout, deprecation, and release certification.

AI Grid uses tenant-isolated data and integrates qualifying AI outcomes into the product's existing canonical finding workflow. AI posture and exposure findings reuse existing SLA, workflow, review, and ServiceNow incident capabilities rather than creating a separate analyst workflow.

## End-to-End Current-State Flow

### 1. Connector setup and discovery scheduling

Administrators configure AWS Bedrock or Azure AI connectors. The system schedules discovery jobs and applies provider admission controls plus daily tenant budgets for scans, API calls, bytes, and processing time. New tenants begin in an observe-only budget mode. Scan cadence rules and budget alerts prevent uncontrolled discovery costs.

AWS discovery uses AWS SDK v2. Azure discovery uses ARM APIs and has a configuration-driven kill switch so that a tenant, connector, resource family, or policy can be disabled when required operationally. This is meaningful operational risk management, especially while Azure support is newer.

### 2. AWS and Azure resource discovery

AWS discovery currently inventories Bedrock agents, action groups, knowledge bases, guardrails, models, inference profiles, prompts, and flows; AgentCore gateways and targets; and SageMaker domains, endpoints, and pipelines. It also evaluates selected surrounding cloud controls: IAM wildcard actions, Lambda function-URL authentication, and S3 public-access configuration. Where a customer already has Macie findings, it can read those classification results for referenced S3 data; it never launches a Macie scan.

Azure discovery inventories Cognitive Services/AI accounts, AI Foundry projects, deployments, Responsible AI policies, agents, ML workspaces and endpoints, AI Search services/indexers/knowledge sources, Bot Service, diagnostic settings, RBAC assignments, and Storage accounts. It can conservatively parse Azure Responsible AI content-filter configuration and can read existing Purview Data Map classification results for storage; it never triggers Purview scanning.

The discovered inventory already covers key ingredients of many agentic systems: agents, model endpoints, guardrails, knowledge/data sources, MCP-related infrastructure, tool-adjacent cloud permissions, and relationship metadata. It is primarily cloud-control-plane evidence, however, not a record of live agent actions.

### 3. Sanitized observation ingestion

Providers publish validated `ObservationEnvelopeV1` chunks. A metadata sanitizer admits only allow-listed fields; it intentionally excludes prompt bodies, secrets, and free-text PII. Observation receipts make chunk ingestion idempotent. When all observations for a scope are complete, the pipeline begins processing.

This privacy-preserving evidence boundary is a valuable design principle for agent security. The agent roadmap should preserve it, adding configurable, minimised runtime telemetry rather than indiscriminate prompt or payload capture.

### 4. Immutable evidence and fact creation

For each completed scope, AI Grid commits immutable, redacted, hash-deduplicated artifact snapshots. It derives versioned facts from those snapshots. Facts are the sole input to policy evaluation, which provides reproducibility: a policy result can be tied to the evidence available at the time.

The platform stores snapshot manifests and bodies, facts, artifact classifications, relationship snapshots, scope/run metrics, and an outbox. It also maintains a deletion-safe current-epoch view that represents the latest complete scan per scope rather than mixing incomplete and stale discovery data.

### 5. Ownership and AI-system modeling

AI Grid resolves ownership as `CONFIRMED`, `INFERRED`, `CANDIDATE`, or `UNOWNED`. Inference reuses the broader product's ownership rules. Tags can suggest a candidate but are not treated as authoritative ownership without confirmation. Ownership history supplies a defensible audit trail.

It then groups provider artifacts into agent-rooted AI systems by traversing discovered relationships with bounded breadth-first search (depth 6, fan-out 100). The system captures revisions and handles split, merge, successor, and retirement lineage across scans. A user can review or adjust memberships. This is an unusually strong foundation for agent-security asset modeling: the roadmap can extend a system graph rather than inventing a separate agent inventory.

### 6. Governed policy assessment

The assessment service evaluates each artifact against every tenant-selected governed policy. Policies are evaluated by a JSON predicate engine over derived facts and can return `PASS`, `FAIL`, `NO_DECISION`, `ERROR`, or `NOT_APPLICABLE`.

Tenant selection states are `REQUIRED`, `ENABLED`, `PREVIEW`, and `DISABLED`. A tenant can configure scope and logical conditions, parameters, artifact-specific exceptions, and rule-based exceptions. It can replay an assessment after a policy change. The design separates centrally governed immutable policy versions from tenant adoption and configuration.

### 7. Exposure correlation and validation

AI Grid performs bounded graph correlation using three current R2 templates:

1. External sensitive-data access.
2. Excessive tool privilege.
3. Untrusted autonomous execution.

The system does not label a graph hypothesis as validated merely because a pattern matches. It requires every supporting fact to be exact, evidence-graded, and fresh. An exposure-freshness worker demotes validated exposures when supporting evidence expires. Analysts can accept or mark an exposure false positive.

External CIEM, DSPM, ASM, runtime tools, and analysts can supply host-context evidence. Trusted producers authenticate as service accounts and may only write under their own producer identity. Confidence and evidence-class rules determine whether external evidence can elevate a fact; it cannot do so unconditionally.

### 8. Coverage, readiness, remediation, and operations

AI Grid identifies unknown technology, missing policy coverage, missing assessments, and unresolved ownership. It materializes coverage dimensions and produces prioritized onboarding/setup actions. Assessment-run metrics provide economics and utility signals.

Qualifying policy failures become canonical `AI_POSTURE` findings. Validated correlation outcomes become `AI_EXPOSURE` findings. Both reuse common finding workflow, SLA, finding subject/review records, and ServiceNow incident creation. Evidence is governed by retention classes (`HOT`, `ARCHIVE`, `RESTRICTED_EVIDENCE`), legal holds, and purge audit records that remain after snapshot-body deletion.

### 9. Policy governance and quality controls

Platform owners import immutable policy and correlation versions, but imports are not directly published. Distribution is explicitly managed as GA, canary, paused, or retired, with pinned versions and target cohorts.

Before a policy version reaches tenants, an answer-key corpus, Wilson-interval precision/bias review, approval workflow, and release certification gate are available. Release manifests are immutable. A portfolio process maps current policy coverage to OWASP LLM Top 10 and uses a RICE-scored candidate backlog for policy proposals. Rollout and deprecation workers process pending tasks on a short cadence.

## What AI Grid Can Reliably Claim Today

| Capability | Current evidence | Boundary |
|---|---|---|
| AI asset inventory | AWS and Azure discovery, artifacts, relationships, graph, run history | Not a universal inventory of self-hosted, SaaS, or non-cloud agents |
| Agent/system topology | Agent-rooted grouping with membership, lineage, and relationship graph | Primarily derived from discovered provider/control-plane relationships |
| Configuration posture | Governed fact-based policy checks, tenant configuration, reproducible snapshots | No general real-time decision at a tool invocation |
| Data-risk context | Existing Macie/Purview classifications and trusted external DSPM evidence | Read-only classification lookup; no native content scanning |
| Identity/privilege posture | Cloud IAM/RBAC and selected surrounding privilege signals | No complete delegated-identity, token, or agent-to-tool authorization model |
| Exposure intelligence | Freshness-gated, evidence-validated correlation across three templates | Templates are currently hardcoded and are not a general attack-path engine |
| Remediation workflow | Canonical findings, SLA, reviews, ServiceNow integration | No in-product enforcement, kill switch, or automated privilege reduction for an agent action |
| Policy quality and shipping | Catalog, answer keys, precision/bias review, canary/GA, certification | Current policy content focuses on AI posture; agent-specific corpus coverage must be expanded |

## The Agent-Security Delta

An AI agent is not only an AI asset. It is an actor that receives untrusted inputs, forms plans, retrieves or writes memory, invokes tools, assumes or delegates identities, exchanges messages with other agents, and can cause external effects. This creates a move from **"is this configuration safe?"** to **"was this action authorized, safe in context, and explainable?"**

The roadmap must research and prioritize these missing domains:

1. **Agent identity and inventory:** unique agent/workload identities; framework, version, owner, deployment, model, prompt/skill/package, runtime, and environment inventory; relationships to tools, MCP servers, A2A peers, data stores, and human owners.
2. **Runtime telemetry:** privacy-minimised event schema for runs, plans, tool calls, tool results, approval decisions, identity/token use, data classifications, policy decisions, failures, and termination. Correlation IDs must tie every action to an agent, session, policy version, and source evidence.
3. **Tool and delegated-access governance:** discovery of MCP tools/servers and agent tool bindings; least-privilege authorization; scoped/short-lived credentials; capability grants; allow/deny rules; rate, spend, and blast-radius limits; approval gates for consequential actions.
4. **Prompt, memory, and RAG security:** provenance/trust labels for retrieved data, skills, tool descriptions, and memory; prompt-injection and indirect-injection indicators; tenant/data-boundary enforcement; memory read/write controls; poisoning detection and rollback.
5. **Runtime prevention and response:** a policy decision point/enforcement point architecture that can warn, require approval, block, revoke credentials, quarantine a tool or agent, or stop a run; a clear distinction between observe, detect, enforce, and autonomous-remediate modes.
6. **Behavioral detection and attack paths:** baselines for normal tool/data/identity behavior; detection for goal hijack, tool misuse, privilege abuse, supply-chain compromise, unexpected code execution, unsafe inter-agent delegation, data exfiltration, and runaway autonomy. Extend the three existing templates into a governed, testable correlation/detection library.
7. **Agent assurance:** pre-deployment threat modeling, policy simulation, adversarial testing/red teaming, evaluation datasets, CI/CD checks, release gates, and continuous regression testing.
8. **Governance and evidence:** human-approval provenance, non-repudiation, audit/replay, data minimization, retention, legal holds, and mappings to NIST AI RMF, OWASP Agentic Top 10, MITRE ATLAS, and applicable regulations.

## Roadmap Design Principles

- **Extend the existing graph and fact model.** Model agents, runs, tools, tool invocations, identities, authorizations, approvals, memory objects, and artifacts as additions to the AI-system graph and evidence lineage.
- **Keep prevention policy-driven and staged.** Introduce every control in observe/simulate mode first; establish precision and operational impact before warning, approval, block, or automatic remediation.
- **Use the existing governance runway.** New policies, correlations, and behavioral detections should inherit answer keys, replay, precision review, canary rollout, and release certification.
- **Separate evidence from content.** Avoid default storage of prompts, model responses, secrets, or raw sensitive records. Capture metadata, structured security signals, hashes, provenance, classifier outputs, and narrowly scoped forensic evidence under retention/hold controls.
- **Treat identity as the control plane.** An agent must never be represented only as a service principal with broad standing access. The roadmap should favor attributable, scoped, time-bound delegated access and explicit tool/action authorization.
- **Do not overclaim native enforcement.** Discovery and detection are valuable phases. A prevent/allow decision must be tied to an actual integration point such as an agent SDK, gateway, sidecar, MCP proxy, API gateway, cloud policy control, or identity provider.
- **Build for heterogeneous agent stacks.** Research which integration layers provide the best coverage across Bedrock, Azure AI Foundry, custom applications, MCP, agent frameworks, and emerging A2A patterns.


## Research Questions That Need Evidence-Based Answers

1. Which agent-security control points are sufficiently standardized and deployable today across Bedrock, Azure Foundry, custom agents, MCP, and common frameworks?
2. What telemetry produces high-signal detections without retaining sensitive prompt or business data? What is the smallest viable agent-security event schema?
3. Which early controls deliver value in observe-only mode, and which require enforcement to matter?
4. Which first-party cloud controls can AI Grid discover or integrate rather than replicate?
5. What is the strongest beachhead buyer and use case: cloud security/posture, identity security, data security, application security, SOC investigation, or AI governance?
6. What evidence, precision, and safety thresholds should allow a policy to progress from preview to block?
7. Which runtime enforcement architecture can be adopted incrementally and remains useful in mixed-vendor, mixed-framework enterprise environments?
8. How should the product quantify agent risk and business impact without relying on opaque model judgments?

## Initial Capability Map for Evaluation

| Area | Current | Extension likely required | Net-new product surface |
|---|---|---|---|
| Asset inventory | Cloud AI artifacts, selected MCP/data/tool-adjacent resources | Agent framework/SaaS/custom runtime discovery | Universal agent registration and attestation |
| System graph | Agent-rooted systems, relationships, lineage | Tool, identity, memory, and execution edges | Run/session and cross-agent interaction graph |
| Evidence | Sanitized snapshots, facts, host context, freshness | Structured runtime security events | High-volume telemetry pipeline and forensic query UX |
| Policy | Versioned JSON predicates, tenant configuration, quality gates | Agent action/context policies and simulation | Runtime PDP/PEP and enforcement adapters |
| Exposure | Three evidence-gated templates | Governed detection/correlation library | Behavioral/sequence analytics and attack-path simulation |
| Workflow | Findings, SLA, ServiceNow, ownership, triage | Agent-response playbooks | Kill/revoke/quarantine orchestration |
| Governance | Answer keys, precision/bias review, canary/GA certification | Agent threat-model and red-team corpus | Agent assurance scorecard and compliance packs |

## Current Constraints to Respect

- Azure discovery is newer than AWS and has a kill switch; roadmap assumptions about Azure should be validated in production.
- Macie and Purview integrations are read-only against existing results. The roadmap should not assume native data scanning without a new connector/product decision.
- AI Grid uses JDBC-based access rather than JPA entities. High-throughput runtime data may warrant a deliberately chosen storage/query architecture rather than simply expanding the current transactional tables.
- The existing validated-exposure model is intentionally conservative: exact, evidence-graded, fresh facts are required. Agent runtime detections will need an explicit model for confidence, confidence decay, policy state, and analyst feedback rather than weakening this standard.
- Current R2 templates are hardcoded. Generalizing them should preserve deterministic replay, test datasets, answer keys, and release controls.

## Sources

1. OWASP GenAI Security Project. [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/). December 2025.
2. OWASP Foundation. [OWASP Agentic Skills Top 10](https://owasp.github.io/www-project-agentic-skills-top-10/). Accessed September 2026.
3. National Institute of Standards and Technology. [AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) and [Generative AI Profile, NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf). July 2024.
4. MITRE. [ATLAS: Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/). Accessed September 2026.
5. Google. [Secure AI Framework](https://www.saif.google/) and [Focus on Agents](https://saif.google/focus-on-agents). Accessed September 2026.
6. ScoutGrid/VulnWatch repository: `prototype-app/docs/business-logic-guide.md`, `prototype-app/docs/backend.md`, `prototype-app/docs/database.md`, and implementation under `prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/`. Current local `main` at commit `627a2df`.
