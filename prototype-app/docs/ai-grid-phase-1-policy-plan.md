# AI Grid Phase 1 — production policy catalog and connector evidence plan

**Audience:** Product, AI Security, Cloud Connector, Policy Platform, and QA teams  
**Decision date:** 24 August 2026  
**External baselines:** CSA AI Controls Matrix (AICM) v1.1 and OWASP GenAI LLM Top 10 2026

## Executive decision

Phase 1 should ship a production catalog of **76 independently authored AI Grid policies**: 38 AWS posture policies, 32 Azure posture policies, and 6 multi-resource exposure policies. This is not a 15–20-policy proof of concept. It is the complete set of high-confidence, security-relevant policies that can be decided from metadata already collected and persisted by the current AWS and Azure connectors, including policies that need normalization or graph predicates before release.

No SAIL catalog content, identifiers, wording, structure, or mappings are included. SAIL may remain an internal source of general design ideas only; it is not a Phase 1 dependency or product compatibility claim.

The catalog is exhaustive within this explicit boundary:

- A policy must have a deterministic undesirable state, a defensible remediation, and direct provider evidence or a direct provider relationship.
- A missing field is `NO_DECISION`, never PASS.
- Availability-only alarms, arbitrary tag hygiene, and policies that merely restate inventory are excluded unless they materially test an AICM control or OWASP risk.
- Parameter variants are one policy, not separate catalog entries. For example, one model-allowlist policy supports different tenant allowlists.
- AICM mappings reference identifiers only and include a mapping type. AI Grid does not reproduce AICM control text or claim AICM certification.

The current codebase seeds **21 posture-policy IDs** across platform migrations V50, V51, V58, and V72, plus **three separately stored published correlation templates** in V63. It therefore has 24 governed detectors in two catalogs, not 24 posture-policy entries. Several seeded preview policies cannot receive decisive facts from the present collectors. Phase 1 replaces detector-count messaging with **decision-capable coverage** and wraps all six target correlations in the unified policy governance envelope.

## Version correction required before release

The prior discussion and current packages use OWASP 2025 identifiers. The current release is **OWASP GenAI LLM Top 10 2026**, published in August 2026. Several numbers changed: Excessive Agency is now LLM03, Supply Chain LLM04, Unbounded Consumption LLM06, Vector and Embedding Weaknesses LLM09, and Improper Output Handling LLM10. System Prompt Leakage was broadened and renamed Hidden Context Exposure at LLM08. Existing mappings must therefore be versioned and migrated; silently retaining unqualified `LLM06`-style labels would be wrong.

The current AICM release is **v1.1**, released 22 June 2026, with 247 objectives across 18 domains. AICM IDs must also carry the version because control content changed between releases.

Required mapping schema:

```text
framework: CSA_AICM | OWASP_GENAI_LLM_TOP_10
frameworkVersion: 1.1 | 2026
controlId: IAM-18 | LLM03
mappingType: DIRECT | PARTIAL | INFORMATIVE
rationale: independently authored explanation
```

Sources: [CSA AICM v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1), [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), and the [OWASP canonical 2026 source](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final).

## Phase 1 outcomes

Phase 1 is complete only when all of the following outcomes are true:

1. **76 packages are shipped out of the box.** Every package is immutable, versioned, independently worded, parameterized where appropriate, and visible in the catalog. Recommended baseline policies default to `REQUIRED` or `ENABLED`; environment-specific baselines default to `DISABLED`, not hidden or absent.
2. **Every verdict is evidence-backed.** Each policy has a fact contract, provider source, freshness limit, evidence class, supported native kinds, and explicit behavior for absent/partial/unsupported scopes.
3. **AICM v1.1 and OWASP 2026 mappings are honest.** Each mapping is DIRECT, PARTIAL, or INFORMATIVE with a rationale. Product UI never turns a mapped policy into a compliance claim.
4. **Connector sufficiency is proven.** AWS and Azure connector tests demonstrate representative PASS, FAIL, NO_DECISION, stale evidence, access denied, and partial-scope results for every shipped provider adapter.
5. **Decision coverage is measurable.** For each provider, native kind, and policy, the release dashboard reports eligible assets, decisive assessments, NO_DECISION by reason, collection failures, and evidence freshness.
6. **No preview policy is marketed as coverage.** A policy counts toward OWASP/AICM coverage only after its connector facts and answer-key gate are certified.
7. **The next connector backlog is funded and bounded.** Missing metadata targets are tracked separately and do not delay the metadata-feasible Phase 1 catalog.

## Evidence validation of the current connectors

### What exists now

The AWS collector already discovers Bedrock agents, IAM role policy documents, action-group Lambda targets and URL auth, knowledge bases and data sources, S3 public-policy status, optional Macie PII results, detailed guardrails, invocation logging, Bedrock models/prompts/flows, AgentCore gateways/targets, and SageMaker domains/models/endpoints/jobs. The Azure collector already discovers AI accounts, Foundry projects/deployments/RAI policies/agents/tools, ML workspaces/models/endpoints/deployments/jobs, Search services and definitions, Bots, diagnostic settings, RBAC assignments, Storage/Fabric relationships, and optional Purview classifications.

The observation contract persists sanitized artifact attributes and direct relationships. `AiGridSnapshotService` currently normalizes only a subset into policy facts. This creates three implementation classes:

- **E0 — ready fact:** the fact is already normalized and usable by the predicate engine.
- **E1 — normalization-only:** the connector already persists the needed attribute; Phase 1 adds a fact definition and normalization/predicate support.
- **E2 — graph adapter:** direct relationships and endpoint attributes already exist; Phase 1 adds a graph predicate/correlation package.
- **C — conditional source:** decisive results require an optional read-only source such as Macie, Purview, Foundry Agents, or Azure Search data plane. Without it the policy returns NO_DECISION.

### Important release findings

- AWS metadata is broadly sufficient for the 38-policy AWS set. The maintained read-only role at `src/main/resources/ai-security/permissions/scout-ai-inventory-readonly-v2.json` covers the collector calls. The older `backend/ai-security-discovery-policy.json` is incomplete and must be retired or redirected so customers do not install the wrong role.
- Azure metadata is sufficient for the 32-policy Azure set, but Azure discovery, Foundry Agents, Search data plane, and Purview are disabled by default in `application.yml`. Production onboarding must expose these as named capabilities and show which policies become decision-capable when each is enabled.
- Existing `MCP_PUBLIC_ENDPOINT_WITHOUT_CONFIGURED_AUTH` cannot currently fail: collectors persist `EXTERNAL_ENDPOINT`, while the policy requires provider-confirmed `PUBLIC_NETWORK_REACHABLE`. It must remain NO_DECISION and move to the next-target list until reachability evidence is added.
- Existing `AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH` has a normalized fact contract, but the collector intentionally does not emit authoritative non-identity authentication evidence. It also moves to the next-target list until a secret-safe auth classifier is implemented.
- `data.source_acl_enforced`, `data.retrieval_mode`, and `mcp.private_endpoint` exist as fact definitions but are not currently produced by either collector. They are coverage gaps, not shipped coverage.
- Macie and Purview evidence is deliberately read-only and optional. PII policies ship out of the box, but count as **conditional automated coverage**, not universal automated coverage.

Repository evidence: `AwsBedrockDiscoveryService`, `AzureAiDiscoveryService`, `AzureAiManagementClient`, `AiGridSnapshotService`, migrations V50–V73, and the AWS/Azure permission manifests.

## Out-of-the-box policy catalog

Mapping notation: `D` = DIRECT, `P` = PARTIAL, `I` = INFORMATIVE. OWASP IDs are the 2026 release; AICM IDs are v1.1. `DISABLED` policies still ship in the package set but require a tenant baseline or allowlist.

### AWS — 38 policies

| ID | Policy shipped out of the box | Evidence | Default | OWASP 2026 | AICM v1.1 |
|---|---|---:|---|---|---|
| AGCF-AWS-001 | Bedrock agent has no guardrail attached | E0 | ENABLED | LLM01 P | TVM-13 D; AIS-09 P |
| AGCF-AWS-002 | Attached Bedrock guardrail is below the configured minimum strength | E0 | REQUIRED | LLM01 P | TVM-13 D |
| AGCF-AWS-003 | Bedrock agent is not in an approved operational state | E0 | ENABLED | LLM03 I | AIS-11 P; MDS-11 P |
| AGCF-AWS-004 | Bedrock agent execution role is missing | E0 | REQUIRED | LLM03 P | IAM-03 D; IAM-18 D |
| AGCF-AWS-005 | Bedrock execution role contains wildcard actions | E0 | REQUIRED | LLM03 D | IAM-05 D; IAM-18 D |
| AGCF-AWS-006 | Action-group Lambda URL permits unauthenticated invocation | E0 | REQUIRED | LLM03 D | IAM-13 D; IAM-15 D; AIS-08 P |
| AGCF-AWS-007 | Agent foundation model is outside the tenant-approved allowlist | E1 | DISABLED | LLM04 D | STA-08 D; STA-10 P; MDS-12 P |
| AGCF-AWS-008 | Agent action-group Lambda target is outside the approved target allowlist | E2 | DISABLED | LLM03 D | IAM-18 D; AIS-11 D |
| AGCF-AWS-009 | Bedrock model invocation logging is disabled | E0 | REQUIRED | LLM02 P | LOG-07 D; LOG-15 P; LOG-16 P |
| AGCF-AWS-010 | Bedrock guardrail is failed, deleting, or otherwise non-active | E1 | ENABLED | LLM01 P | TVM-13 D; MDS-11 P |
| AGCF-AWS-011 | Bedrock guardrail lacks a customer-managed KMS key where CMK is required | E1 | DISABLED | LLM02 P | CEK-03 P; CEK-08 D |
| AGCF-AWS-012 | Bedrock guardrail has no configured content filters | E1 | ENABLED | LLM01 P; LLM10 P | TVM-13 D; AIS-09 P; AIS-10 P |
| AGCF-AWS-013 | Sensitive-data agent lacks configured PII guardrail entities | E1+C | ENABLED | LLM02 D | DSP-17 D; TVM-13 D |
| AGCF-AWS-014 | Grounded-generation baseline requires contextual grounding filters, but none are configured | E1 | DISABLED | LLM07 P | TVM-13 D; GRC-13 P |
| AGCF-AWS-015 | Denied-topic baseline is required, but no denied topics are configured | E1 | DISABLED | LLM01 P; LLM07 P | TVM-13 D; GRC-09 P |
| AGCF-AWS-016 | Guardrail configuration has not been reviewed within the configured maximum age | E1 | DISABLED | LLM01 I | CCC-06 D; TVM-13 D |
| AGCF-AWS-017 | Bedrock knowledge base uses an S3 source with public policy exposure | E0 | REQUIRED | LLM02 D; LLM09 D | DSP-17 D; I&S-03 D; IAM-16 P |
| AGCF-AWS-018 | Bedrock knowledge base is failed or unavailable | E1 | ENABLED | LLM09 I | MDS-11 P; BCR-03 P |
| AGCF-AWS-019 | Bedrock data source is failed or unavailable | E1 | ENABLED | LLM05 P; LLM09 P | DSP-20 P; DSP-23 P |
| AGCF-AWS-020 | Bedrock data-source configuration is absent | E1 | ENABLED | LLM09 P | DSP-03 D; DSP-05 P |
| AGCF-AWS-021 | Bedrock data-source type is outside the approved source allowlist | E1 | DISABLED | LLM04 P; LLM05 P | STA-08 D; DSP-20 P |
| AGCF-AWS-022 | Bedrock data deletion policy violates the tenant retention baseline | E1 | DISABLED | LLM02 P | DSP-02 P; DSP-16 D |
| AGCF-AWS-023 | AI data store has unknown, failed, or stale sensitivity classification | E0+C | ENABLED | LLM02 P; LLM09 P | DSP-03 D; DSP-04 D |
| AGCF-AWS-024 | Macie-confirmed sensitive AI data store permits public content access | E0+C | REQUIRED | LLM02 D | DSP-17 D; I&S-03 D |
| AGCF-AWS-025 | Bedrock custom model lacks a customer-managed KMS key where required | E1 | DISABLED | LLM04 P; LLM05 P | CEK-03 P; CEK-08 D; MDS-08 P |
| AGCF-AWS-026 | Bedrock imported model lacks a customer-managed KMS key where required | E1 | DISABLED | LLM04 D | CEK-03 P; MDS-09 P |
| AGCF-AWS-027 | Referenced foundation model lifecycle is not ACTIVE | E1 | ENABLED | LLM04 D | STA-10 D; MDS-12 D |
| AGCF-AWS-028 | Model provider or model identifier is outside the approved allowlist | E1 | DISABLED | LLM04 D | STA-08 D; STA-10 D |
| AGCF-AWS-029 | Bedrock custom/imported model or customization job is in a failed terminal state | E1 | ENABLED | LLM04 P; LLM05 P | MDS-01 P; MDS-11 D |
| AGCF-AWS-030 | Provisioned model or inference profile is in an unhealthy state | E1 | ENABLED | LLM06 P | I&S-02 P; MDS-11 D |
| AGCF-AWS-031 | AgentCore gateway inbound authorization is missing or outside the approved auth types | E1 | REQUIRED | LLM03 D | IAM-13 D; IAM-15 D; AIS-08 P |
| AGCF-AWS-032 | AgentCore target outbound authorization is NONE, UNKNOWN, or outside the approved types | E1 | REQUIRED | LLM03 D; LLM04 P | IAM-13 D; IAM-18 D |
| AGCF-AWS-033 | AgentCore target is failed, unsynchronized, or stale beyond the configured age | E0/E1 | ENABLED | LLM03 P | AIS-11 P; LOG-14 P |
| AGCF-AWS-034 | MCP target subtype or server hostname is outside the tenant allowlist | E1/E2 | DISABLED | LLM01 P; LLM04 D | STA-08 D; AIS-11 P |
| AGCF-AWS-035 | SageMaker domain lacks VPC attachment | E1 | ENABLED | LLM02 P; LLM04 P | I&S-03 D; I&S-06 P |
| AGCF-AWS-036 | SageMaker endpoint, model package, or execution space is in a failed terminal state | E1 | ENABLED | LLM04 P | MDS-11 D; BCR-03 P |
| AGCF-AWS-037 | SageMaker notebook instance type is outside the approved compute baseline | E1 | DISABLED | LLM06 P | I&S-02 D; GRC-09 P |
| AGCF-AWS-038 | Bedrock flow is failed or outside the approved lifecycle state | E1 | ENABLED | LLM03 P | AIS-11 P; MDS-11 P |

### Azure — 32 policies

| ID | Policy shipped out of the box | Evidence | Default | OWASP 2026 | AICM v1.1 |
|---|---|---:|---|---|---|
| AGCF-AZR-001 | Azure AI, ML workspace, or Search service permits unrestricted public network access | E0 | REQUIRED | LLM02 D; LLM03 P | I&S-03 D; DSP-17 P |
| AGCF-AZR-002 | Private endpoint is absent where the tenant baseline requires one | E0 | DISABLED | LLM02 P | I&S-03 D; I&S-06 P |
| AGCF-AZR-003 | Azure AI account permits local/key authentication | E0 | REQUIRED | LLM03 D | IAM-13 D; IAM-15 D |
| AGCF-AZR-004 | Azure AI account lacks customer-managed-key encryption where required | E0 | DISABLED | LLM02 P; LLM04 P | CEK-03 P; CEK-08 D |
| AGCF-AZR-005 | Azure AI diagnostic logging is disabled | E0 | REQUIRED | LLM02 P | LOG-03 P; LOG-07 D; LOG-09 P |
| AGCF-AZR-006 | Diagnostic settings have no enabled destination | E1 | REQUIRED | LLM02 P | LOG-02 P; LOG-07 D |
| AGCF-AZR-007 | Managed AI resource provisioning state is failed or non-succeeded | E1 | ENABLED | LLM04 I | MDS-11 P; LOG-14 P |
| AGCF-AZR-008 | Managed AI resource lacks a confirmed owner tag | E1 | ENABLED | — | DCS-07 P; DSP-06 P; GRC-06 P |
| AGCF-AZR-009 | Managed AI resource lacks required environment or criticality tags | E1 | DISABLED | — | DCS-06 P; DCS-07 P; GRC-02 P |
| AGCF-AZR-010 | Azure RAI policy explicitly disables or does not block a returned filter | E0 | REQUIRED | LLM01 P; LLM10 P | TVM-13 D; AIS-09 P; AIS-10 P |
| AGCF-AZR-011 | Azure RAI policy has no content-filter definitions | E1 | ENABLED | LLM01 P; LLM10 P | TVM-13 D |
| AGCF-AZR-012 | Foundry deployment has no RAI policy reference | E0 | REQUIRED | LLM01 P; LLM10 P | TVM-13 D; CCC-06 P |
| AGCF-AZR-013 | RAI mode or base policy is outside the approved baseline | E1 | DISABLED | LLM01 P | TVM-13 D; CCC-06 P |
| AGCF-AZR-014 | Required custom blocklist baseline is absent | E1 | DISABLED | LLM01 P; LLM07 P | TVM-13 D; GRC-09 P |
| AGCF-AZR-015 | Foundry model name or publisher is outside the approved allowlist | E1 | DISABLED | LLM04 D | STA-08 D; STA-10 D; MDS-12 P |
| AGCF-AZR-016 | Foundry model version or upgrade option violates the patch/lifecycle baseline | E1 | DISABLED | LLM04 D | TVM-06 P; CCC-06 D; MDS-11 P |
| AGCF-AZR-017 | Foundry agent has Code Interpreter enabled outside an approved scope | E0+C | DISABLED | LLM03 D; LLM10 P | AIS-13 D; IAM-18 D |
| AGCF-AZR-018 | Foundry agent model deployment is absent or outside the approved allowlist | E1+C | ENABLED | LLM04 P | STA-08 D; AIS-11 P |
| AGCF-AZR-019 | Foundry MCP server uses NONE or UNKNOWN configured authentication | E0+C | REQUIRED | LLM03 D; LLM04 P | IAM-13 D; IAM-18 D |
| AGCF-AZR-020 | Foundry MCP server hostname is outside the approved allowlist | E1+C | DISABLED | LLM01 P; LLM04 D | STA-08 D; STA-10 P |
| AGCF-AZR-021 | Foundry agent uses a tool type outside the approved tool allowlist | E1+C | DISABLED | LLM03 D | AIS-11 D; IAM-18 D |
| AGCF-AZR-022 | Azure ML online endpoint permits local/key authentication | E0 | REQUIRED | LLM03 D | IAM-13 D; IAM-15 D |
| AGCF-AZR-023 | Azure ML endpoint traffic references a missing or non-ready deployment | E1/E2 | ENABLED | LLM04 P | MDS-11 D; CCC-06 P |
| AGCF-AZR-024 | Azure ML deployment instance type or model reference is outside the approved baseline | E1 | DISABLED | LLM04 P; LLM06 P | STA-08 P; I&S-02 D |
| AGCF-AZR-025 | Azure ML job or pipeline is in a failed terminal state | E1 | ENABLED | LLM05 P | MDS-01 D; MDS-11 P |
| AGCF-AZR-026 | Azure AI Search permits local admin-key authentication | E0 | REQUIRED | LLM03 D; LLM09 P | IAM-13 D; IAM-16 D |
| AGCF-AZR-027 | Azure Bot uses password authentication without managed identity | E0 | REQUIRED | LLM03 D | IAM-13 D; IAM-18 D |
| AGCF-AZR-028 | Azure Bot has no managed identity where the baseline requires one | E1 | ENABLED | LLM03 D | IAM-03 D; IAM-18 D |
| AGCF-AZR-029 | Azure Bot channel is outside the approved channel allowlist | E1 | DISABLED | LLM04 P | STA-08 D; AIS-11 P |
| AGCF-AZR-030 | High-privilege Azure role assignment is broader than the approved AI resource scope | E1/E2 | REQUIRED | LLM03 D | IAM-05 D; IAM-09 P; IAM-18 D |
| AGCF-AZR-031 | High-privilege Azure role assignment lacks the required condition or approved principal type | E1 | DISABLED | LLM03 D | IAM-05 D; IAM-10 P; IAM-15 D |
| AGCF-AZR-032 | AI-linked Azure Storage or OneLake store has unknown, failed, or stale sensitivity classification | E0+C | ENABLED | LLM02 P; LLM09 P | DSP-03 D; DSP-04 D |

### Multi-resource exposure policies — 6 policies

These are not duplicates of posture findings. They raise severity only when direct relationships connect individually meaningful facts.

| ID | Exposure policy | Evidence | Default | OWASP 2026 | AICM v1.1 |
|---|---|---:|---|---|---|
| AGCF-XSP-001 | Publicly reachable AI service has a direct path to confirmed sensitive data | E2+C | REQUIRED | LLM02 D | DSP-17 D; I&S-03 D |
| AGCF-XSP-002 | Code Interpreter or another high-impact tool has a direct path to confirmed sensitive data | E2+C | REQUIRED | LLM02 D; LLM03 D | AIS-13 D; IAM-18 D; DSP-17 D |
| AGCF-XSP-003 | Wildcard or broad identity permissions reach a high-impact agent tool | E2 | REQUIRED | LLM03 D | IAM-05 D; IAM-18 D |
| AGCF-XSP-004 | External or unapproved MCP server is reachable from an agent that can access sensitive data | E2+C | REQUIRED | LLM01 P; LLM02 D; LLM03 D | AIS-11 D; IAM-18 D; DSP-17 D |
| AGCF-XSP-005 | Agent with autonomous/high-impact execution routes through an MCP target with missing or unknown auth | E2 | REQUIRED | LLM01 P; LLM03 D | IAM-13 D; IAM-18 D; AIS-11 D |
| AGCF-XSP-006 | Agent can retrieve sensitive data but lacks the required guardrail/PII-filter baseline | E2+C | REQUIRED | LLM01 P; LLM02 D; LLM09 P | TVM-13 D; DSP-17 D; IAM-16 D |

## OWASP 2026 coverage outcome

Policy mappings show risk reduction, not proof that an OWASP vulnerability cannot be exploited.

| OWASP risk | Phase 1 result | What Phase 1 can honestly claim |
|---|---|---|
| LLM01 Prompt Injection | Partial automated posture + exposure coverage | Guardrail presence/strength, input-related RAI controls, untrusted MCP/RAG paths. Runtime attack resistance still requires testing and telemetry. |
| LLM02 Sensitive Information Disclosure | Strong automated/conditional posture coverage | Network exposure, logging, classification, public stores, encryption baselines, and sensitive-data paths. Output DLP remains a next target. |
| LLM03 Excessive Agency | Strong automated posture + exposure coverage | IAM/RBAC breadth, local auth, tool/MCP auth, Code Interpreter, action targets, and sensitive-data paths. Effective permission simulation and approval gates remain next targets. |
| LLM04 Supply Chain | Moderate automated posture coverage | Model/tool/source inventory, allowlists, lifecycle, provider, and deployment integrity signals. Signing, hashes, SBOM, and vulnerability evidence remain next targets. |
| LLM05 Data and Model Poisoning | Limited posture coverage | Data-source health/type and training/customization pipeline states. Provenance, hashes, ingestion history, and anomaly signals remain next targets. |
| LLM06 Unbounded Consumption | Limited posture coverage | Provisioned capacity and approved compute baselines only. Quotas, budgets, token/cost metrics, loop limits, and alerts require new telemetry. |
| LLM07 Misinformation | Preventive configuration only | Contextual-grounding and RAI baseline presence. Groundedness evaluations, source quality, human review, and output monitoring require new evidence. |
| LLM08 Hidden Context Exposure | Not materially covered | Existing discovery intentionally does not read prompt bodies, secrets, memory, or conversation context. Phase 1 must show this as a gap. |
| LLM09 Vector and Embedding Weaknesses | Moderate posture coverage | Knowledge/data-source inventory, public exposure, classification, auth, and path analysis. Index-level ACLs, tenant isolation, vector encryption, and embedding provenance require new facts. |
| LLM10 Improper Output Handling | Preventive configuration only | Output-side guardrail/RAI configuration. Sink validation, escaping, code execution controls, and application telemetry are not visible to current cloud connectors. |

## Policies explicitly not counted in Phase 1 decision coverage

The following existing preview concepts stay visible in the backlog but must not be counted as shipped coverage until connector evidence exists:

- Public MCP endpoint without configured auth — an external hostname is not proof of Internet reachability.
- Azure Search non-identity data-source authentication — connection strings are intentionally not persisted; a safe classifier is still required.
- MCP private endpoint absent — neither collector currently emits authoritative private-endpoint state.
- Data-source ACL enforcement absent — current collectors do not produce the fact.
- Retrieval mode outside baseline — current collectors do not produce the fact.
- The three R2 validated-exposure templates when only hypothesis facts exist — they remain hypotheses until approved runtime, graph, or active-test evidence verifies the decisive facts.

## Next-target policy backlog and connector enhancements

These controls are valuable but cannot be validated from current connector evidence. They form Phase 2 candidates; the connector work can begin during Phase 1 after the 76-policy fact contracts freeze.

### AWS metadata gaps

| Potential next policies | Metadata missing today | Connector enhancement |
|---|---|---|
| Effective excessive agent permission; permission-boundary/SCP escape; cross-account resource access | Effective IAM decisions, boundaries, SCP/resource-policy interaction | Add an optional IAM evidence module using `SimulatePrincipalPolicy` for a bounded action/resource matrix and Access Analyzer findings. Store decisions, not raw sensitive policies beyond current sanitized evidence. |
| S3 Block Public Access incomplete; bucket encryption absent; cross-account bucket policy; TLS-only bucket | Public-access-block bits, encryption configuration, policy findings | Add `GetPublicAccessBlock`, `GetBucketEncryption`, and a safe bucket-policy analyzer. Preserve account-level ambiguity as NO_DECISION. AWS notes that bucket-level Public Access Block alone is not the full effective result. |
| Knowledge-base/vector encryption missing; vector index network exposure; tenant isolation absent | Storage configuration, vector-store endpoint/security policy, collection encryption and access policies | Enrich `GetKnowledgeBase`; add read-only OpenSearch Serverless/Pinecone/Redis/Aurora adapters only for directly referenced stores. |
| Training/validation data provenance and poisoning controls | Object version IDs, checksums, dataset manifests, ingestion job history, source change evidence | Resolve only referenced S3 prefixes; collect versioning, inventory manifests/checksums, Bedrock ingestion job status, and approved provenance attestations. Do not read object content. |
| Model artifact integrity/signature, AI-BOM, external model vulnerabilities | Hash/signature, artifact manifest, package/dependency inventory, vulnerability evidence | Add model registry/ECR/S3 attestation adapters and SBOM/AI-BOM ingestion. Map to MDS-02, MDS-08, MDS-09, STA-09. |
| Runtime prompt-injection/guardrail failures; sensitive output leakage | Guardrail invocation metrics, blocked/intervened events, invocation-log analysis, DLP results | Add CloudWatch metrics/log evidence behind explicit opt-in. Prefer counters/classifications over prompt/output bodies. |
| Unbounded consumption, token/cost anomaly, missing alarms | Invocations, token counts, throttles, latency, EstimatedTPMQuotaUsage, budgets/alarms | Add CloudWatch `AWS/Bedrock` metrics, Service Quotas, Budgets, and alarm configuration. AWS publishes invocation, token, throttle, and quota-usage metrics. |
| AgentCore endpoint publicly reachable; MCP TLS/certificate/auth handshake weak | Verified reachability, resource/network policy, TLS/auth negotiation | Add provider network-policy metadata first; optionally add a separately consented non-invasive reachability verifier. Never infer public reachability from a URL. |
| SageMaker network isolation, KMS, root access, image/vulnerability controls | Domain/user profile security settings, endpoint network isolation, volumes/KMS, container image provenance | Add detailed `Describe*` fields and referenced ECR/Inspector evidence. |

AWS references: [IAM policy simulation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html), [IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html), [S3 GetPublicAccessBlock](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html), and [Bedrock runtime CloudWatch metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html).

### Azure metadata gaps

| Potential next policies | Metadata missing today | Connector enhancement |
|---|---|---|
| Search data source uses keys/SAS; Search source auth unknown; connection secret not CMK protected | Secret-safe auth type, identity reference, data-source encryption-key presence | In the Search data-plane client, classify the credential form in memory (`MANAGED_IDENTITY`, `KEY_OR_SAS`, `UNKNOWN`) and persist only the classification. Collect object-level/service-level CMK references, never connection strings. |
| Search knowledge ACL enforcement absent; document-level authorization missing; cross-tenant vector access | Permission filter/ACL configuration, index authorization schema, tenant partition signal | Extract stable ACL/permission metadata from knowledge source/index definitions and managed knowledge-base settings. Add explicit `UNKNOWN` for unsupported API versions. |
| Search/vector encryption and network controls incomplete | Search service CMK, object CMK, outbound private-link/shared-private-link state | Extend ARM and Search definition projection for service/object encryption and private link. Azure documents managed encryption by default and optional CMK, so policies must distinguish mandatory encryption from tenant-required CMK. |
| Azure Storage/OneLake backing store is public, permits shared keys, lacks secure transfer, or lacks CMK | Storage network ACL, blob public access, shared-key access, TLS version, encryption, private endpoints | Enrich only directly linked Storage/Fabric resources with read-only ARM properties. This unlocks Azure parity for sensitive-public-data exposure. |
| Effective excessive RBAC, custom role wildcard actions, stale assignments, PIM/MFA gaps | Role definition actions/dataActions, deny assignments, effective scope, PIM eligibility/activation, access reviews | Collect role definitions for referenced assignments and optional Microsoft Graph/PIM evidence through a separate consent scope. Keep control-plane RBAC distinct from identity-governance evidence. |
| Foundry MCP endpoint reachability/private endpoint; connection credential hygiene | Network policy, project connection auth type, private endpoint, credential age/rotation | Persist safe classifications from Foundry connection resources and authoritative network configuration; do not store headers or secrets. |
| Foundry/ML prompt injection, hidden context, output handling | Prompt/version metadata, evaluation results, tracing/guardrail events, content-safety results | Add opt-in evaluation and monitoring adapters. Store test IDs, scores, verdicts, and hashes rather than prompt/output bodies by default. |
| Foundry/ML unbounded consumption and cost controls | Tokens/requests, quota assignment, capacity saturation, budgets, alerts | Add Azure Monitor metrics, deployment quota/capacity, Cost Management budgets, and alert-rule inventory. |
| ML endpoint outbound Internet access; workspace managed network absent; deployment egress unrestricted | Endpoint public network flag, workspace managed-network isolation, deployment egress policy, private outbound rules | Extend ML endpoint/workspace projections. Microsoft documents separate inbound private endpoints and outbound managed-network isolation. |
| Model/data provenance, registry signature, training data integrity, AI-BOM | Model registry lineage, hashes/signatures, environment image, datastore versions, MLflow lineage | Add Azure ML registry/MLflow lineage and referenced ACR/Defender/SBOM evidence. |
| Bot channel auth, secrets, TLS, and endpoint exposure | Channel-specific settings and endpoint network/auth metadata | Add per-channel safe projections and linked App Service/Function/Key Vault configuration, without retrieving secret values. |

Azure references: [Azure AI Search security responsibilities](https://learn.microsoft.com/en-us/azure/search/search-security-built-in), [Azure AI Search security best practices](https://learn.microsoft.com/en-us/azure/search/search-security-best-practices), [Azure Search CMK](https://learn.microsoft.com/en-us/azure/search/search-security-manage-encryption-keys), [Azure ML online endpoint isolation](https://learn.microsoft.com/en-us/azure/machine-learning/concept-secure-online-endpoint), and [Azure ML endpoint monitoring](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-monitor-online-endpoints).

## Delivery plan

The plan assumes two parallel delivery squads (policy platform + cloud connectors), dedicated QA automation, two available security reviewers, and one cloud-security/product owner. The release target is **22 weeks**; certification is a continuous critical-path workstream rather than an end-stage QA activity. With one engineering squad or shared part-time QA, preserve the outcomes and sequence but expect roughly 32–36 weeks.

### Workstream 0 — baseline and legal/provenance gate (weeks 1–2)

**Outcome:** the catalog has a stable intellectual-property and versioning boundary.

- Freeze AGCF naming, domains, policy-ID rules, mapping schema, and independent-authoring provenance record.
- Import only AICM/OWASP identifiers and independently authored mapping rationales; legal/product review CSA commercial-use and attribution requirements before distribution.
- Add explicit framework versions and mapping types; migrate all 2025 OWASP mappings to 2026.
- Mark current preview/non-decision policies accurately in product APIs and UI.

**Exit gate:** no unversioned OWASP/AICM label remains; every proposed policy has an owner and independent wording review.

### Workstream 1 — capability, connector, and fact-contract hardening (weeks 1–7)

**Outcome:** every one of the 76 policies has a producible, testable fact path.

- Define the E1 facts for all already-persisted AWS/Azure attributes.
- Add timestamp-age, parameter-backed negated allowlists, empty/non-empty, and collection-count operators; retain the existing `in`, ordered, logical, and strength operators.
- Add E2 relationship predicates for direct paths and allowlisted targets.
- Implement the net-new run-scoped capability-observation model, resource-family producers, assessment gating, NO_DECISION reasons, and setup actions. Aggregate AWS/Azure base health is informational only; policies depend on granular resource-family capabilities so one missing permission cannot block unrelated families.
- Split optional capabilities (Macie, Purview, Foundry Agents, Search data plane) into explicit conditional-source states.
- Retire the obsolete AWS permission sample; generate permission manifests from a single tested matrix.
- Add connector contract fixtures for complete, partial, unsupported, access denied, stale, and no-data scopes.

**Exit gate:** a generated policy-to-fact-to-source matrix has no unresolved source for any of the 76 packages.

### Workstream 2 — AWS policy release (weeks 4–13)

**Outcome:** all 38 AWS policies are certified and decision-capable for eligible assets.

- Migrate surviving legacy behavior into packages, then add new E1/E2 packages.
- Certify agent/IAM/Lambda and guardrail policies first, then data/RAG, model lifecycle, AgentCore MCP, and SageMaker.
- Keep Macie-dependent policies conditional; verify NO_DECISION when Macie is disabled, unavailable, or stale.

**Exit gate:** each policy passes schema validation, unit tests, answer-key fixtures, precision review, canary, rollback, and permission-denied tests.

### Workstream 3 — Azure policy release (weeks 4–15)

**Outcome:** all 32 Azure policies are certified and decision-capable for enabled connector capabilities.

- Add E1 projections for RAI, model/deployment, tags, tools, RBAC, Bot, diagnostic, and ML status metadata.
- Enable Azure capability onboarding and surface permissions/API-version failures by resource family.
- Keep Purview-dependent policies conditional and retain NO_DECISION on unsupported Search/Foundry APIs.

**Exit gate:** AWS-equivalent network/auth/logging behavior has parity tests; Azure-only RAI, Foundry, Search, ML, Bot, and RBAC policies have provider-specific answer keys.

### Workstream 4 — exposure policies and portfolio UX (weeks 12–18)

**Outcome:** six multi-resource policies produce explainable paths, and framework coverage is presented without overclaiming.

- Author three new correlation definitions and wrap all six correlations, including the three currently published templates, in the unified governance envelope.
- Implement direct-relationship graph predicates and evidence path rendering on a shared graph-evidence resolver. One-hop E2 posture evaluation remains artifact-scoped; multi-hop correlation remains system/path-scoped and is the only mechanism that can create exposure hypotheses or validated exposures.
- De-duplicate exposure findings against underlying posture findings while preserving all evidence.
- Show OWASP risk status as Automated, Conditional Automated, Preventive Only, Requires Runtime/Test, or Not Covered.
- Show AICM objective mappings with mapping type, version, rationale, and evidence coverage.

**Exit gate:** every exposure finding renders the exact artifact/fact/relationship path and cannot be produced from inferred proximity alone.

### Workstream 5 — continuous certification and production release (weeks 3–22)

**Outcome:** Phase 1 is a production release, not a catalog preview.

- Build and review at least five mandatory answer-key outcomes per adapter, producing a minimum of 380 certified cases before parameter and correlation variants. Run representative AWS/Azure account fixtures, negative controls, access-denied tests, stale-data tests, and scale/performance certification continuously as each adapter becomes available.
- Certify every parameterized `DISABLED` policy against a fixed, versioned certification parameter profile containing both an allowed and disallowed value; tenant runtime defaults remain disabled and are not used as certification shortcuts.
- Canary by provider and policy family; measure decisive rate and false-positive disposition.
- Publish release manifest, policy changelog, permission delta, framework coverage statement, and connector-capability guide.
- Start the next-target connector work only after Phase 1 facts freeze, so new permissions cannot destabilize certification.

**Exit gate:** release board signs off the quantitative gates below and all 76 packages are PUBLISHED, not merely present in source.

## Quantitative release gates

| Gate | Required result |
|---|---|
| Catalog completeness | 76/76 packages published; 76/76 have versioned AICM and/or OWASP mapping rationale where applicable |
| Fact provenance | 100% of required facts resolve to a collector field, approved evidence producer, or direct relationship |
| Decision semantics | 100% of missing/unsupported/stale required evidence returns NO_DECISION, never PASS |
| Answer keys | At least one true positive, true negative, missing evidence, stale evidence, and permission-failure case per provider adapter |
| Precision | Wilson-interval/precision governance passes for all 76 policies. Parameterized `DISABLED` policies use their immutable certification parameter profile; no policy reaches PUBLISHED through a reduced gate. |
| Connector permission contract | Generated AWS role and Azure custom-role requirements match actual API calls; prohibited write/data-plane-content actions remain absent |
| Decision coverage | At least 95% decisive assessments on fully enabled, fully permitted golden connectors; every remaining NO_DECISION has an enumerated reason |
| Exposure integrity | 100% of exposure findings contain a direct evidence path; zero proximity-only paths |
| Performance | Full catalog assessment stays within the existing certified scan and evaluation budgets and does not regress assessment time or database writes by more than 20% versus the frozen pre-Phase-1 baseline |
| Rollback | Policy-family rollback and version pinning demonstrated for AWS, Azure, and exposure packages |

## Product positioning at Phase 1 exit

Use this statement:

> AI Grid continuously assesses AWS and Azure AI security posture using independently authored controls mapped to CSA AICM v1.1 and the OWASP GenAI LLM Top 10 2026. Coverage is reported by evidence type and decision capability; mappings do not imply framework certification or complete runtime protection.

Do not use “OWASP compliant,” “AICM certified,” “all OWASP risks covered,” or policy-count-only claims.

## Evidence ledger and limitations

| Claim family | Primary evidence | Confidence / limitation |
|---|---|---|
| AICM v1.1 release, size, and control IDs | [CSA AICM v1.1 release page](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) and CSA's machine-readable AICM 1.1.0 catalog | High. Mapping rationales are AI Grid's interpretation; CSA has not endorsed them. |
| OWASP 2026 names, numbers, and posture/runtime boundary | [OWASP 2026 release](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) and [canonical final source](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final) | High. A mapped posture control reduces risk but does not prove exploit resistance. |
| Current AWS metadata and relationships | [`AwsBedrockDiscoveryService.java`](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/aws/AwsBedrockDiscoveryService.java) and [`scout-ai-inventory-readonly-v2.json`](../backend/src/main/resources/ai-security/permissions/scout-ai-inventory-readonly-v2.json) | High for fields in code. Provider/API behavior still requires golden-account certification. |
| Current Azure metadata and relationships | [`AzureAiDiscoveryService.java`](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/azure/AzureAiDiscoveryService.java), [`AzureAiManagementClient.java`](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/azure/AzureAiManagementClient.java), and [`azure-policy-permission-matrix.yaml`](../backend/src/main/resources/ai-security/azure-policy-permission-matrix.yaml) | High for fields in code. Preview/data-plane API availability can vary and must yield NO_DECISION when unsupported. |
| Current normalized facts and catalog state | [`AiGridSnapshotService.java`](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridSnapshotService.java) and platform migrations V50–V73 | High. Count is based on distinct policy IDs present in the migration line, not tenant rollout state. |
| Feasibility of next AWS evidence | AWS documentation for [IAM simulation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html), [S3 Public Access Block](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html), and [Bedrock metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html) | Medium-high. Permissions, cost, API quotas, and evidence privacy still need design review. |
| Feasibility of next Azure evidence | Microsoft documentation for [Search security](https://learn.microsoft.com/en-us/azure/search/search-security-best-practices), [Search CMK](https://learn.microsoft.com/en-us/azure/search/search-security-manage-encryption-keys), and [ML endpoint isolation](https://learn.microsoft.com/en-us/azure/machine-learning/concept-secure-online-endpoint) | Medium-high. Some Foundry/Search APIs are preview or capability-gated. |

## Final recommendation

Approve the 76-policy catalog as the Phase 1 scope. Treat E0, E1, and E2 as one production release commitment because all rely on metadata the connectors already collect. Treat the connector-enhancement tables as a separately measured next-target backlog, with early focus on effective IAM/RBAC, backing-store network/encryption, runtime consumption metrics, model/data provenance, and safe Search/MCP auth classification. This yields broad posture coverage now without pretending cloud configuration can prove prompt-injection resistance, hidden-context protection, output safety, or runtime behavior.
