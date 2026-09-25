# AI Grid coverage against the supplied 74-rule OWASP LLM Security set

**Assessment date:** 2026-09-23
**Compared set:** 74 `wc-id-*` rules supplied by the user
**AI Grid baseline:** 159 governed AGCF policies (76 generally available, 83 Phase 2 policies paused)

## Executive result

The supplied list is not 74 native OWASP controls. It is a vendor-specific set of cloud and attack-path rules whose results are grouped under the OWASP LLM Security Top 10. Therefore, this assessment measures **rule parity**, not OWASP compliance.

Using a strict comparison:

| Coverage class | Rules | Percentage | Meaning |
|---|---:|---:|---|
| Direct | 5 | 7% | An enabled AI Grid policy evaluates substantially the same end-to-end condition |
| Partial | 44 | 59% | AI Grid has relevant evidence or one or more component policies, but lacks a predicate, relationship, provider, or enabled Phase 2 policy needed for full parity |
| Gap | 25 | 34% | Required provider, asset, secret, vulnerability, behavioral, or graph evidence is not currently available to AI Grid |
| Direct + partial | 49 | 66% | Thematic or technical overlap; this must not be reported as effective coverage |

An indicative parity score that gives direct coverage full credit and partial coverage half credit is **36%**. The severity-weighted equivalent is approximately **35%**. These are planning indicators, not compliance scores.

The external list's stated 91% score should not be compared with AI Grid's percentage: it is a result generated under a different product's asset graph, connectors, definitions, and scoring method.

## Coverage by supplied severity

| Severity | Total | Direct | Partial | Gap | Adjusted parity |
|---|---:|---:|---:|---:|---:|
| Critical | 15 | 0 | 7 | 8 | 23% |
| High | 20 | 0 | 12 | 8 | 30% |
| Medium | 29 | 4 | 19 | 6 | 47% |
| Low | 9 | 1 | 6 | 2 | 44% |
| Informational | 1 | 0 | 0 | 1 | 0% |

The section headers in the supplied text say 19 High, 28 Medium, and 11 Low; the actual IDs present are 20 High, 29 Medium, and 9 Low. The file still contains exactly 74 unique IDs.

## Where AI Grid is strongest

- Bedrock agents without guardrails.
- Agents with sensitive retrieval paths but missing guardrail or PII-filter baselines.
- Broad or wildcard agent identity permissions reaching high-impact tools.
- Lambda or other high-impact tools with paths to sensitive data.
- Effective IAM/RBAC, cross-account access, MCP authentication, storage exposure, retrieval isolation, model provenance, and consumption controls—although many of these are Phase 2 and paused.

## Where AI Grid is weakest

- Cleartext OpenAI/cloud-key discovery and secret-to-privilege paths.
- Vulnerable VM, serverless, or container entry points connected to training/model buckets.
- Suspicious or malicious model detection.
- Repository-to-package-to-image-to-runtime supply-chain paths.
- GCP Vertex AI, Salesforce Data Cloud, Claude Enterprise, and similar unsupported providers.
- Notebook public exposure and effective notebook privilege.
- Public-write semantics and third-party/universal-principal bucket access as complete end-to-end AI paths.
- MCP-server software vulnerabilities tied to the privileged host on which the server runs.

## Rule-level assessment

Legend: **D** = direct, **P** = partial, **G** = gap. “Paused” means that the closest policy exists but is not currently counted as effective coverage.

### Critical

| ID | Coverage | Closest AI Grid capability or missing evidence |
|---|---|---|
| wc-id-1431 | P | `AGCF-XSP-007` can correlate an effective public entry point to sensitive storage, but AI Grid lacks the initial-access vulnerability and training-bucket path |
| wc-id-1712 | G | No cleartext OpenAI-key/secret scanner or secret-in-public-bucket predicate |
| wc-id-1433 | G | No container-image vulnerability → container → AI training bucket attack path |
| wc-id-1430 | P | AWS effective-access policies 039–042 cover broad trust concepts, but do not prove a training-bucket service account assumable by all users; paused |
| wc-id-3529 | G | Salesforce Data Stream is not collected |
| wc-id-1586 | P | Bedrock dataset/storage linkage exists, but no vulnerable internet-facing compute → training bucket path |
| wc-id-1583 | G | GCP Vertex AI is unsupported |
| wc-id-1584 | P | AWS 069/070 cover authoritative S3 public access and sensitivity, but not public write-to-all plus custom-model lineage; paused |
| wc-id-3337 | G | No agent-code artifact → writable public bucket relationship |
| wc-id-1582 | G | GCP Vertex AI is unsupported |
| wc-id-1710 | G | No cleartext OpenAI-key plus vulnerable-container correlation |
| wc-id-1711 | G | No cleartext OpenAI-key plus vulnerable VM/serverless correlation |
| wc-id-1581 | P | AWS 070 covers sensitive data plus effective public content access, but the custom-model training relationship needs certification; paused |
| wc-id-1587 | P | Bedrock data evidence exists, but the exposed vulnerable-container path does not |
| wc-id-1427 | P | AWS 043/069 cover public access posture, but not training usage plus write-to-all semantics; paused |

### High

| ID | Coverage | Closest AI Grid capability or missing evidence |
|---|---|---|
| wc-id-2070 | G | No suspicious-model classifier tied to host privilege |
| wc-id-1706 | G | No cleartext cloud-key discovery in training data or secret-to-privilege resolution |
| wc-id-3317 | P | AWS 039–042 and Azure 033–036 cover effective excessive/admin privilege, but Phase 2 is paused and provider scope is narrower |
| wc-id-2776 | G | No repository logging weakness → build → container → bucket path |
| wc-id-1578 | P | AWS 069 covers authoritative public S3 access, but full custom-model bucket lineage is not certified; paused |
| wc-id-2928 | P | Public-entry and data relationships partially exist; initial-access vulnerability and training-bucket correlation do not |
| wc-id-3024 | P | Model SBOM/image vulnerability policies 058–059 and 068 provide downstream evidence, but no malicious package → repository → image path; paused |
| wc-id-1585 | P | Broad/cross-account access policies exist, but universal-assumable service account plus Bedrock training bucket is not an exact predicate; paused |
| wc-id-3336 | P | `AGCF-XSP-009` covers effective identity reach to a high-impact tool, but gateway → serverless tool hosting and admin privilege need authoritative edges; paused successor |
| wc-id-1428 | P | AWS 046 detects unapproved cross-account principals, but does not identify third-party vendor context; paused |
| wc-id-2275 | G | No vulnerable public compute → MLOps path |
| wc-id-3587 | G | Claude Enterprise discovery and organization-wide sharing are unsupported |
| wc-id-2931 | P | Public compute and custom-model data concepts overlap, but the initial-access vulnerability path is absent |
| wc-id-3023 | G | No malicious-package plus valid-cloud-key correlation |
| wc-id-3333 | P | Effective privilege policies can flag excessive identity access, but AI Gateway identity attachment is incomplete; paused |
| wc-id-1579 | G | GCP Vertex AI is unsupported |
| wc-id-2073 | G | No suspicious-model plus lateral-movement-to-admin path |
| wc-id-2745 | P | Macie/Purview sensitivity evidence and data-store policies exist, but model-bucket High/Critical finding correlation is not a dedicated policy |
| wc-id-2516 | P | Public S3 access policies exist, but model-hosting relationship and write-to-all semantics are incomplete; paused |
| wc-id-1705 | P | Dataset sensitivity and lineage facts exist, but fine-tuned-model → training dataset sensitivity is not an enabled end-to-end policy |

### Medium

| ID | Coverage | Closest AI Grid capability or missing evidence |
|---|---|---|
| wc-id-2742 | P | AWS 001 detects a Bedrock agent without a guardrail, but not every principal allowed to invoke a model outside a guardrail-enforced route |
| wc-id-3038 | P | Guardrail and effective-privilege policies exist separately; no enabled combined high-privilege-without-guardrail predicate |
| wc-id-2874 | D | `AGCF-XSP-002` evaluates a high-impact tool with a direct path to confirmed sensitive data; AWS 008 supplies action-target controls |
| wc-id-2878 | D | `AGCF-XSP-003` evaluates broad identity permission reaching a high-impact agent tool; AWS 005/008 cover wildcard role and Lambda target |
| wc-id-1411 | P | SageMaker notebook inventory exists, but current GA policy checks compute baseline rather than effective high privilege; Phase 2 IAM may supply components |
| wc-id-3217 | P | `AGCF-XSP-002/003` and effective-access policies cover tool-mediated sensitive/high privilege paths, but generic managed-agent privilege is broader |
| wc-id-2069 | G | No suspicious-model classifier |
| wc-id-3017 | G | No source-repository logging/auditing weakness → container-build lineage |
| wc-id-3039 | D | `AGCF-XSP-006` evaluates an agent that can retrieve sensitive data but lacks the required guardrail/PII-filter baseline |
| wc-id-1434 | P | Public entry and sensitive-store paths exist, but container → training-bucket relationship is absent |
| wc-id-1432 | P | Public entry and sensitive-store paths exist, but VM/serverless → training-bucket relationship is absent |
| wc-id-1435 | G | No cloud-key discovery inside training data or privilege resolution |
| wc-id-2274 | P | AWS 046 detects an unapproved cross-account principal, but third-party identity context and model-bucket linkage remain incomplete; paused |
| wc-id-3335 | P | High-impact tool, privilege, and sensitive-data correlations exist, but gateway → serverless-hosted tool edges are incomplete |
| wc-id-2905 | P | AWS 001/002/005 cover guardrails and privilege separately, but do not specifically prove a prompt-injection guardrail on a privileged agent |
| wc-id-2747 | P | Macie/Purview classification is collected; there is no dedicated “dataset has High/Critical findings” policy independent of exposure |
| wc-id-1429 | P | Dataset sensitivity is collected, but training-bucket usage plus sensitivity is not an enabled exact policy |
| wc-id-2877 | P | Agent-to-data relationships and sensitivity evidence exist; mere use of a sensitive dataset is not currently a dedicated finding |
| wc-id-2518 | G | No suspicious-model classifier for bucket-hosted models |
| wc-id-3127 | P | PII/content-filter policies and `AGCF-XSP-006` overlap, but current scalar facts do not consistently prove output-side filtering for every provider |
| wc-id-2875 | P | Agent/data relationships and sensitive classification exist, but the generic access condition is not a dedicated policy |
| wc-id-2071 | G | No suspicious-model plus host-sensitive-data predicate |
| wc-id-3022 | P | MCP inventory/auth and vulnerability inventory exist in the product, but no authoritative MCP server → vulnerable privileged host relationship |
| wc-id-2906 | D | `AGCF-XSP-006` plus AWS guardrail evidence directly covers sensitive retrieval without the required guardrail baseline |
| wc-id-2876 | P | Agent, dataset, S3, and sensitivity evidence overlap, but the exact end-to-end rule is not published |
| wc-id-3334 | P | Gateway auth plus effective privilege/sensitive-data paths overlap, but a single gateway-centric policy is absent |
| wc-id-2271 | P | Dataset sensitivity, dataset lineage, and model provenance are collected, but model-trained-on-sensitive-data is not an enabled correlation |
| wc-id-3218 | P | `AGCF-XSP-002/003/008/009` cover tool privilege and sensitive paths, but serverless hosting evidence is incomplete and successors are paused |
| wc-id-2072 | G | No cleartext cloud-key plus suspicious-model-on-host correlation |

### Low

| ID | Coverage | Closest AI Grid capability or missing evidence |
|---|---|---|
| wc-id-2272 | P | Agent effective permission and excessive-agency policies exist; “AI model with agency” needs a clearer agent/model boundary |
| wc-id-3136 | P | AWS public-bucket, dataset-lineage, and model-provenance policies overlap, but pipeline → dataset → deployed model is not an enabled correlation |
| wc-id-3123 | P | AWS 005 directly covers Bedrock wildcard execution roles; Phase 2 adds effective AWS/Azure access, but broader resource coverage is paused |
| wc-id-3135 | G | No AI pipeline → dataset database → public DB server graph |
| wc-id-3124 | G | No deployed model → AI pipeline → publicly accessible database graph |
| wc-id-2746 | D | `AGCF-AWS-001` directly detects a Bedrock agent with no guardrail attached |
| wc-id-2273 | P | Notebook inventory exists, but effective notebook agency/privilege is not evaluated end to end |
| wc-id-3216 | P | Agent/knowledge-base relationships and sensitivity evidence exist; no dedicated policy for sensitive KB access alone |
| wc-id-3126 | P | AWS public S3 access is evaluated, but hosted-model → bucket linkage and effective hosting semantics are incomplete |

### Informational

| ID | Coverage | Closest AI Grid capability or missing evidence |
|---|---|---|
| wc-id-2270 | G | No notebook public-exposure fact or policy |

## Recommended response

### 1. Do not attempt one-for-one parity with all 74 rules

Several rules belong to broader CNAPP/CSPM, secrets, vulnerability management, or software-supply-chain domains. AI Grid should consume those findings as graph evidence instead of rebuilding scanners.

### 2. Convert the highest-value partials into direct coverage

Prioritize these policy families:

1. **AI training/model data exposure** — model or pipeline → dataset/bucket → effective public read/write → sensitivity.
2. **Agent privilege plus missing guardrail** — effective admin/high privilege AND missing approved guardrail.
3. **Gateway/tool effective privilege** — agent/gateway → tool → runtime/hosting identity → consequential permissions.
4. **Model/dataset sensitivity lineage** — deployed/fine-tuned model → exact training dataset → classification state.
5. **Third-party/universal principal access** — effective external principal class, trust path, and approved-party context.
6. **MCP vulnerable hosting path** — MCP server → host/workload → vulnerability severity → effective privilege.

### 3. Reuse adjacent product capabilities for the large gaps

Add normalized evidence adapters rather than new scanners for:

- secret findings and exposed credentials;
- internet exposure and initial-access vulnerabilities;
- container image/package vulnerabilities;
- repository/build/image provenance;
- suspicious or untrusted model findings;
- lateral movement and effective privilege paths.

### 4. Treat provider expansion as a product decision

GCP Vertex AI, Claude Enterprise, and Salesforce-specific rules should remain `NOT_ASSESSED` until those connectors are intentionally added. They should not lower AWS/Azure policy precision or be inferred from generic assets.

## Proposed near-term target

Within the current AWS/Azure/AgentCore/Foundry/Copilot scope, a practical target is:

- increase direct parity from **5 to 20 controls**;
- reduce gaps from **25 to fewer than 18**;
- certify the relevant Phase 2 policies before counting them;
- expose provider and capability exclusions explicitly;
- report rule parity separately from OWASP category coverage.

This target can be reached primarily through new graph correlations and evidence adapters, without collecting raw prompts, responses, training records, tool arguments, or secrets.
