# AI Grid policy and framework coverage expansion plan

**Decision date:** 2026-09-22
**Scope:** The versioned AGCF policy catalog, AWS Bedrock and AgentCore discovery, Azure AI/Foundry discovery, Copilot Studio discovery, and the metadata-only runtime execution model.

> **Roadmap alignment (2026-09-23):** Phase 1 is limited to control-plane posture and authoritative static exposure. Every runtime-resource or execution-dependent policy in this document is assigned to Phase 2 and governed by [AI Grid Phase 2 runtime security plan](./AI_GRID_PHASE_2_RUNTIME_SECURITY_PLAN.md). “Wave A/B/C” labels below describe backlog sequencing, not the Phase 1/Phase 2 product boundary.

## Executive recommendation

AI Grid should make **OWASP Top 10 for Agentic Applications 2026** its next framework, while retaining OWASP GenAI LLM Top 10 2026 and CSA AI Controls Matrix (AICM) 1.1. This is the best fit because AI Grid now inventories agents, versions, tools, MCP endpoints, workload identities, prompts, memory resources, and execution metadata—the exact change in risk from what a model can produce to what an agent can access and do.

The next release should not be measured by the number of mappings added. It should be measured by the percentage of applicable assets for which AI Grid can produce a fresh, authoritative, deterministic result. The recommended sequence is:

1. Certify and selectively enable the 83 paused Phase 2 policies.
2. Correct gaps in the existing OWASP LLM mapping, especially the absence of LLM08 mappings for vector, retrieval, ACL, and tenant-isolation policies.
3. Backfill Agentic Top 10 mappings onto existing policies before creating duplicates.
4. Add a small set of posture and drift policies that can use metadata already collected.
5. Extend connector telemetry and the evaluator for runtime sequence and aggregate policies.

## 1. Current baseline

The governed AGCF package catalog contains **159 policies**:

| Dimension | Current state | Implication |
|---|---:|---|
| AWS | 72 | Strong Bedrock, IAM, S3, AgentCore/MCP, SageMaker, provenance, and consumption coverage |
| Azure | 75 | Strong AI/Foundry, RBAC, Search, Storage, ML, Bot, provenance, and consumption coverage |
| Multi-cloud correlations | 12 | Useful path-based policies for identity, tools, MCP, and sensitive data |
| General availability / Phase 1 | 76 | Runnable baseline |
| Paused / Phase 2 | 83 | Catalog breadth is ahead of proven evidence readiness |
| Artifact-fact policies | 147 | The evaluator is primarily configuration/posture oriented |
| Correlation-path policies | 12 | Limited graph-risk coverage |

Every governed policy has at least one framework mapping. The catalog has 194 OWASP LLM mapping records across 9 controls and 325 CSA AICM mapping records across 52 controls. However:

- Only **36 of 194 OWASP mappings (19%)** are `DIRECT`; 158 are `PARTIAL`.
- Only **102 of 325 CSA mappings (31%)** are `DIRECT`; 223 are `PARTIAL`.
- OWASP LLM policy counts are concentrated in LLM02 (59), LLM03 (43), and LLM04 (35).
- LLM08 currently has **zero mappings**, even though the catalog contains vector-store, Search ACL, document authorization, tenant partitioning, retrieval-mode, and retrieval-path controls.
- Phase 2 adds depth for effective permissions, storage, retrieval, provenance, network controls, and consumption, but all 83 policies are paused. Enabling trustworthy coverage is more valuable than immediately adding another large batch of static checks.

### Existing OWASP LLM coverage

| Control | Policies mapped | Direct mappings | Assessment |
|---|---:|---:|---|
| LLM01 | 16 | 0 | Breadth exists; mapping rationales need stronger evidence boundaries |
| LLM02 | 59 | 8 | Deepest area; risks over-counting many similar cloud posture checks |
| LLM03 | 43 | 19 | Strong identity/agency coverage |
| LLM04 | 35 | 8 | Strong model, tool, and provenance posture coverage |
| LLM05 | 10 | 0 | Dataset and pipeline checks exist but are all partial |
| LLM06 | 13 | 0 | Consumption and availability checks exist but are all partial |
| LLM07 | 3 | 0 | Thin coverage |
| LLM08 | 0 | 0 | Clear mapping gap |
| LLM09 | 8 | 1 | Limited evidence depth |
| LLM10 | 7 | 0 | Limited evidence depth |

These counts are policy-to-control mappings, not certification claims. One policy can map to more than one control.

### Evidence-certification wave 1

Before authoring another policy, certify the 16 controls for which the normalized evidence contract already exists: `AGCF-AWS-039`–`042`, `AGCF-AZR-033`–`039`, `AGCF-AWS-048`–`050`, and `AGCF-AWS-071`–`072`. The certification release carries a new immutable `1.0.1` package for each, with its OWASP mapping promoted to `DIRECT`, raising the catalog’s direct mapping count to **52 of 194 (27%)** without inflating effective tenant coverage.

The packages remain paused and disabled by default. Every policy must still pass answer-key validation, precision review, independent mapping review, approval, and a provider-specific canary before it is published. A direct mapping records semantic fit; it is not a claim that a tenant is protected.

## 2. What the connectors can actually assess

### AWS Bedrock and AgentCore

Current discovery can support policies over:

- Bedrock agents, models, guardrails, knowledge bases, data sources, flows, IAM roles, Lambda targets, invocation logging, S3 exposure, and Macie classification evidence.
- AgentCore gateways and targets: inbound and outbound auth type, status, target subtype, last synchronization time, MCP endpoint hostname, and direct gateway-to-target-to-server relationships.
- AgentCore runtimes: stable runtime ARN/ID, runtime versions, deployment endpoints, served version, runtime status, execution role, workload identity, and authoritative membership relationships.
- AgentCore browser, code-interpreter, and memory inventory with stable provider identifiers and status.

Important constraint: the control plane does **not** provide authoritative runtime-to-browser, runtime-to-code-interpreter, runtime-to-memory, runtime-to-gateway, or runtime-to-tool bindings. AI Grid correctly avoids inventing those edges. Policies requiring those paths must remain `NOT_ASSESSED` until runtime or harness evidence supplies them.

### Azure AI and Foundry

Current discovery can support policies over:

- Agents and agent versions, active-version relationships, model deployments, prompt digests, tool inventory, and direct `USES_MODEL`, `USES_PROMPT`, and `USES_TOOL` relationships.
- Foundry MCP inventory without fetching or executing the endpoint.
- AI accounts, RAI filters and policies, private endpoints, managed identities, RBAC, ML endpoints/jobs, Search data sources and indexes, Storage/OneLake references, Purview classification, diagnostic settings, Bot services, and channels.
- Effective-access, retrieval, isolation, provenance, consumption, and authoritative-exposure facts defined for Phase 2.

### Copilot Studio

Current discovery can support policies over:

- Bots and versions.
- Prompt, tool, and component inventory.
- Component type, version, and HMAC-safe prompt/tool-definition digests.
- Direct version-to-prompt/tool/component relationships.
- Runtime execution ID, bot correlation, status, and event time from Dataverse.

The digest design is particularly useful: AI Grid can detect definition drift without storing prompt text, tool schemas, or arguments.

### Runtime execution model

The common schema can store agent/version correlation, start/completion time, status, outcome category, approval state, policy state, classification, API version, token count, latency, retry count, spend, timestamped event types, and declared participants.

Actual connector population is narrower:

- Azure Foundry currently provides execution identity, agent/version reference, timestamps, status, and token count.
- Copilot Studio currently provides execution identity, bot reference, timestamp, and status.
- Azure ML jobs provide correlated execution identity and status when an agent reference is present.
- Tool-call events, action category, target classification, delegated identity, approval decision, policy decision, retry count, spend, and memory or handoff events are not yet consistently collected.

This difference between **schema capacity** and **collected evidence** must be visible in policy applicability. Null runtime fields are `UNKNOWN` or `NOT_ASSESSED`, never a pass.

## 3. Additional framework: OWASP Top 10 for Agentic Applications 2026

Use the catalog key `OWASP_AGENTIC_TOP_10`, framework version `2026`, and control identifiers `ASI01` through `ASI10`.

| Control | Risk | AI Grid relevance | Existing policy families to backfill first |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Guardrails, prompt integrity, MCP paths, sensitive retrieval | AWS 001–016; Azure 010–014; XSP 004–006 |
| ASI02 | Tool Misuse and Exploitation | Tool allowlists, Code Interpreter, Lambda/action targets, consequential permissions | AWS 005–008; Azure 017, 021; XSP 002–003, 008–009 |
| ASI03 | Identity and Privilege Abuse | Workload identity, IAM/RBAC, auth, effective privilege | AWS 004–006, 031–032, 039–042, 071–072; Azure 003, 022, 026–028, 030–039, 072–074; XSP 003, 005, 009, 011 |
| ASI04 | Agentic Supply Chain Vulnerabilities | Model/tool provenance, versions, attestations, SBOMs, MCP trust | AWS 007–008, 028, 034, 056–062, 068; Azure 015–016, 020–021, 058–063; XSP 004, 010 |
| ASI05 | Unexpected Code Execution | Code Interpreter, Lambda/action groups, browser/code execution | AWS 006, 008; Azure 017; XSP 002, 008 |
| ASI06 | Memory and Context Poisoning | Knowledge sources, datasets, retrieval controls, memory integrity | AWS 017–024, 048–050, 060–062; Azure 032, 040–47, 062–063, 075; XSP 006, 012 |
| ASI07 | Insecure Inter-Agent Communication | Agent-to-agent identity, message provenance, delegated authority | No adequate current policy; requires new A2A metadata |
| ASI08 | Cascading Failures | Retry loops, failure propagation, dependency health, termination controls | Status/consumption policies are partial precursors; runtime policies required |
| ASI09 | Human-Agent Trust Exploitation | Approval gates, ownership, provenance, consequential-action confirmation | Ownership, provenance, and logging policies are partial precursors; runtime approval evidence required |
| ASI10 | Rogue Agents | Version drift, out-of-scope actions, kill switch, containment, undeclared tools | Effective permissions and allowlists are partial precursors; runtime behavior policies required |

Why this framework now:

- It is specific to autonomous, tool-using systems and complements rather than duplicates the LLM Top 10.
- It gives the new AgentCore, Foundry, Copilot, MCP, tool, identity, memory, and runtime metadata a coherent security narrative.
- The official framework is incident-informed and uses the same operational concepts already present in AI Grid.

OWASP's newly published Agent Control Standard should be treated as a future runtime-enforcement design reference, not as the reporting framework for this release. AI Grid should first map posture and evidence to the Agentic Top 10, then use the control standard when portable enforcement hooks are introduced.

## 4. Immediate mapping corrections

### 4.1 Close the LLM08 gap

Independently review and add LLM08 mappings to the policies whose security intent directly concerns vector/retrieval isolation:

- `AGCF-AWS-048` through `AGCF-AWS-050` — vector-store public access, encryption, and principal boundaries.
- `AGCF-AZR-042` through `AGCF-AZR-045` — permission filtering, document authorization, tenant partitioning, and approved retrieval mode.
- `AGCF-XSP-012` — effective retrieval path with ACL, tenant isolation, and sensitive-data evidence.

Do not mechanically map every storage or data policy to LLM08. A mapping should require a vector, embedding, retrieval, index, or tenant-isolation security intent.

### 4.2 Backfill Agentic mappings before creating policies

Apply the ASI crosswalk above to the 159 existing packages with:

- an independent reviewer;
- `DIRECT`, `PARTIAL`, or `SUPPORTING` mapping type;
- a short policy-specific rationale;
- no claim that a cloud configuration policy alone satisfies a whole ASI risk category.

### 4.3 Reduce inflated coverage

Report both:

- **breadth:** controls with at least one mapped policy; and
- **effective coverage:** controls with at least one enabled, evaluable policy and fresh evidence on an applicable asset.

A paused policy, missing capability, stale fact, or `UNKNOWN` result must not increase effective coverage.

## 5. Proposed new policies

Policy identifiers below are planning identifiers. Final IDs should be allocated through the governed catalog process.

### Wave A — use evidence already collected

| Priority | Proposed policy | Deterministic condition | Evidence readiness | Framework mapping |
|---|---|---|---|---|
| P0 | AgentCore runtime lacks authoritative execution identity | Root-qualified runtime has neither a direct execution-role nor workload-identity relationship | Ready | ASI03 direct; LLM03 direct; CSA IAM-13/IAM-18 |
| P0 | AgentCore endpoint serves an unhealthy or unapproved runtime version | Active endpoint is unhealthy, targets a non-approved version, or has no resolvable `SERVES_VERSION` edge | Ready; allowlist parameter needed | ASI04/ASI10; LLM04; CSA AIS-11 |
| P0 | Agent definition changed after approval | Active version's prompt or tool digest differs from the approved digest/version | Azure Foundry and Copilot digests ready; approval baseline needed | ASI01/ASI04/ASI10; LLM01/LLM04 |
| P0 | Copilot external trigger or skill is outside the approved component allowlist | Active bot version uses `EXTERNAL_TRIGGER`, `SKILL`, or `SKILL_V2` not in tenant allowlist | Ready | ASI02/ASI04; LLM03/LLM04 |
| P0 | Production agent is unowned or ownership is stale | Production/root-eligible agent owner state is missing, inferred below threshold, or review age exceeds baseline | Partially ready; normalize owner state across providers | ASI09/ASI10; CSA GRC-09 |
| P1 | Active agent version uses an unapproved definition component | Active version has a prompt, tool, model, or component not present in its approved manifest | Graph ready; approved manifest needed | ASI02/ASI04/ASI10; LLM03/LLM04 |
| P1 | Runtime inventory or execution cannot be correlated to one agent/version | Runtime or execution resolution is unresolved, ambiguous, or multi-target without an explicit version | Ready; requires aggregate/query evaluator | ASI04/ASI10; CSA AIS-11/LOG-14 |
| P1 | Deployed AgentCore utility is failed or inactive | Browser, Code Interpreter, memory, runtime, version, or endpoint has a terminal/unhealthy status while deployed | Ready | ASI05/ASI08; CSA BCR-03/TVM-13 |

These policies deliberately avoid inventing AgentCore tool-attachment relationships. A standalone browser, interpreter, or memory resource is not evidence that a runtime can use it.

### Wave B — populate existing runtime fields and add bounded runtime evaluation

| Priority | Proposed policy | Deterministic condition | Required connector/evaluator work | Framework mapping |
|---|---|---|---|---|
| P1 | Consequential action executed without approval | High-impact action succeeded and approval state is absent, bypassed, or denied | Collect action category, outcome, and approval decision; add runtime policy mode | ASI02/ASI09/ASI10; LLM03 |
| P1 | Policy-denied action nevertheless succeeded | Policy decision is deny/block and the corresponding action outcome is success | Populate policy state and action outcome with common enums | ASI02/ASI10 |
| P1 | Sensitive-data read followed by external write/send | Same run reads classified data and later performs an external or mutating action without approved declassification | Emit ordered metadata-only events and target/data classifications | ASI01/ASI02/ASI03; LLM02/LLM03; CSA DSP-17 |
| P1 | Runtime used an undeclared tool or version | Observed tool participant/digest is absent from the approved active-version graph | Emit actual tool ID/version/digest; compare to declared graph | ASI02/ASI04/ASI10 |
| P1 | Agent executed a retired or non-approved version | Correlated runtime version is retired, non-active, or outside the deployment allowlist | Ensure version reference population across runtime connectors | ASI04/ASI10 |
| P1 | Repeated tool-call or retry loop exceeds safety threshold | Repeated action signature, retries, latency, spend, or tokens exceed bounded tenant threshold | Populate retry/spend/event type; add windowed aggregate evaluation | ASI08/ASI10; LLM06 |
| P1 | Consequential runtime telemetry is incomplete | High-impact agent has executions but lacks approval, policy, identity, or outcome evidence above a threshold | Capability-aware completeness policy | ASI09/ASI10; CSA LOG-07/LOG-14 |

### Wave C — collect new agentic metadata

| Priority | Proposed policy | Deterministic condition | New metadata required | Framework mapping |
|---|---|---|---|---|
| P2 | Agent-to-agent handoff lacks authenticated identity and constrained delegation | Handoff has no verified source/destination agent, delegation scope, expiry, or audience | Parent run, source/destination agent, delegated identity/scope, auth result | ASI03/ASI07 |
| P2 | Persistent memory lacks tenant/user isolation or retention controls | Memory is persistent and lacks tenant/user namespace, TTL, encryption, or deletion policy | Memory type, scope, isolation, TTL, encryption, retention | ASI06; LLM02 |
| P2 | Untrusted input can write durable memory without validation | External/untrusted event precedes a durable memory write without policy approval or validation | Input trust class, memory operation, validation/policy decision | ASI01/ASI06 |
| P2 | Tool, plugin, or MCP definition lacks integrity provenance | Executable component has no pinned version, digest/signature, publisher trust, or approved registry lineage | Tool/MCP version, digest/signature, publisher, registry lineage | ASI04/ASI05 |
| P2 | High-impact autonomous agent lacks an effective stop or containment control | Agent can mutate external systems but has no kill switch, maximum-step/time limit, or revocable credential boundary | Autonomy level, max steps/time, stop control, credential revocability | ASI08/ASI10 |

## 6. Metadata contract changes

Extend the privacy-preserving runtime contract with enumerated, metadata-only fields. Do not collect raw prompts, responses, tool arguments, documents, credentials, or message bodies by default.

Minimum additions:

- `actionCategory`: `READ`, `WRITE`, `DELETE`, `SEND`, `EXECUTE`, `ADMIN`, `PAYMENT`, `PUBLISH`, `OTHER`.
- `targetClass`: internal, external, public, sensitive store, code runtime, identity system, financial system, or unknown.
- HMACed `toolId`, `toolVersion`, `toolDefinitionDigest`, and `targetId`.
- HMACed acting identity and delegated identity, plus delegation scope and expiry class.
- `approvalState`, `policyState`, `decisionReasonCode`, and `enforcementPoint` using closed enums.
- `dataSensitivityClass` and `dataOperation`, sourced from existing classification systems rather than content inspection.
- `parentExecutionId`, HMACed source/destination agent identifiers, and handoff authorization result.
- `memoryOperation`, memory persistence class, tenant/user scope state, and retention class.
- `terminationReason`, retry count, step count, token count, spend, and latency.

Add capability flags for each field family. A policy is applicable only when all required capabilities are complete and fresh.

## 7. Evaluator and catalog changes

1. Add a bounded `RUNTIME_SEQUENCE` evaluation mode for ordered events inside one execution.
2. Add a bounded `RUNTIME_AGGREGATE` mode for count/rate/threshold checks over a fixed window.
3. Keep raw provider payloads outside the policy engine; evaluate normalized facts and enums only.
4. Add `requiredRuntimeFields`, `window`, `groupBy`, and `minimumSampleSize` to the evidence contract.
5. Preserve four-state outcomes: `PASS`, `FAIL`, `UNKNOWN`, and `NOT_ASSESSED`.
6. Require answer-key fixtures, minimum positive/negative cases, missing-evidence cases, precision review, and independent framework-mapping approval for every High/Critical package.
7. Version mappings independently enough to support framework revisions without changing the policy predicate.

## 8. Delivery plan

### 0–30 days — make existing coverage trustworthy

- Produce a machine-readable coverage matrix: policy × provider × capability × evidence tier × lifecycle × framework mapping.
- Certify the highest-value Phase 2 identity, retrieval, MCP, and authoritative-exposure policies; enable them in small provider-specific cohorts.
- Add the independently reviewed LLM08 mappings.
- Register `OWASP_AGENTIC_TOP_10` 2026 and backfill ASI mappings onto existing policies.
- Implement Wave A policies that use current evidence.

**Exit criteria:** no paused policy is counted as effective coverage; all ten ASI categories show honest `effective`, `partial`, or `not assessed` status; Phase 2 enablement has precision evidence.

### 31–60 days — definition integrity and runtime foundations

- Introduce approved manifests for active agent versions, prompt digests, tool digests, models, and components.
- Add runtime field capability reporting per connector.
- Implement `RUNTIME_SEQUENCE` and `RUNTIME_AGGREGATE` behind feature flags.
- Populate approval, policy, outcome, token, retry, latency, spend, and action metadata where provider APIs expose it.
- Release the first three Wave B policies in preview.

**Exit criteria:** runtime policies never pass on absent telemetry; at least two connectors produce normalized action/decision metadata; definition drift is explainable without storing content.

### 61–90 days — actionable agent risk paths

- Add actual tool-use participants and version/digest evidence.
- Correlate classified-data access to external or mutating actions.
- Add consequential-action approval and denied-but-succeeded policies.
- Add retry-loop/cascading-failure detection with tenant-tunable thresholds.
- Expose investigation timelines with the exact evidence and mapping rationale behind each finding.

**Exit criteria:** at least five Wave B policies are precision-certified; high-impact findings link agent, version, identity, tool, target, decision, and outcome without exposing payload content.

### 90–180 days — memory, A2A, and control readiness

- Add memory isolation/retention metadata and policies.
- Add authenticated A2A handoff and constrained-delegation metadata and policies.
- Add tool/MCP integrity provenance and containment/stop-control policies.
- Use the OWASP Agent Control Standard as an implementation reference for future enforcement hooks, while keeping assessment and enforcement claims separate.

## 9. Success measures

Use these metrics instead of raw policy count:

| Metric | 90-day target |
|---|---:|
| Applicable-asset evaluability | ≥85% of applicable assets return pass/fail rather than unknown/not assessed |
| Fresh-evidence coverage | ≥90% of evaluated facts meet their max-age contract |
| Phase 2 activation | ≥25 highest-value policies certified and enabled; remaining policies explicitly blocked with a capability reason |
| Agentic framework breadth | 10/10 ASI categories mapped honestly; at least 7/10 have an enabled policy |
| Agentic effective depth | At least 2 independently validated policies in each of ASI02, ASI03, ASI04, ASI06, ASI08, and ASI10 |
| Mapping quality | 100% of new ASI mappings independently reviewed; no generic copy-paste rationales |
| Precision | ≥95% precision on High/Critical answer-key and pilot samples |
| Runtime correlation | ≥90% of collected executions resolve to one agent; ≥80% resolve to an agent version where the provider exposes it |
| Definition integrity | ≥90% of production agent versions have an approved manifest or an explicit exception |

## 10. Product trade-offs

- Do not claim full framework compliance from Top 10 threat mappings; report risk coverage and evidence, not certification.
- Do not add policies whose necessary relationship is unavailable and inferred.
- Do not store raw prompts, completions, tool arguments, or business records to gain coverage.
- Do not enable all 83 Phase 2 policies at once; certify in risk-value waves.
- Do not use a single opaque AI risk score. Preserve the evidence path, missing capabilities, framework rationale, and confidence.
- Do not prioritize broad new provider coverage until AWS, Azure, and Copilot evidence is consistently evaluable.

## 11. First backlog slice

1. `POLICY-MAP-001`: Add reviewed LLM08 mappings to retrieval/vector policies.
2. `FRAMEWORK-001`: Register OWASP Agentic Top 10 2026 and its ten controls.
3. `POLICY-MAP-002`: Backfill ASI mappings to Phase 1 identity, tool, MCP, dataset, and provenance policies.
4. `PHASE2-CERT-001`: Certify effective-permission policies AWS 039–042 and Azure 033–039.
5. `PHASE2-CERT-002`: Certify retrieval/isolation policies AWS 048–050, Azure 040–047, and XSP-012.
6. `AGENT-POL-001`: AgentCore runtime missing authoritative execution identity.
7. `AGENT-POL-002`: AgentCore endpoint serves unhealthy or unapproved version.
8. `AGENT-POL-003`: Agent definition changed after approval.
9. `AGENT-POL-004`: Copilot external trigger or skill outside allowlist.
10. `RUNTIME-ENG-001`: Add capability-aware runtime sequence/aggregate evaluation.
11. `RUNTIME-POL-001`: Consequential action without approval.
12. `RUNTIME-POL-002`: Policy-denied action succeeded.
13. `RUNTIME-POL-003`: Sensitive read followed by external write/send.

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [OWASP Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/)
- [CSA AI Controls Matrix v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1)
