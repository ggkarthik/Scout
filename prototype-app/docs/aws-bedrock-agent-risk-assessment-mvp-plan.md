# AWS Bedrock Agent Risk Assessment MVP - Intern Scope

## 1. Purpose

This document defines the MVP scope for adding risk assessment, rules, findings, and scoring on top of the existing
AI discovery implementation in `/Users/ravikumarkanukollu/Documents/AIDiscovery`.

The current discovery code already discovers AWS Bedrock AI artefacts and stores agents, models, guardrails,
knowledge bases, Lambda action groups, identities, and datastores. The MVP should build the missing assessment layer
for AWS Bedrock agents first.

This is not the full AI Grid architecture. This is the first customer-validation slice.

## 2. MVP Goal

Build AWS Bedrock Agent Risk Assessment:

- evaluate discovered AWS Bedrock agents
- create persistent findings
- calculate per-agent risk score
- expose findings through API
- show findings in the UI
- support accept and resolve actions
- prepare the foundation for later MCP, model, and agent code scanning

## 3. Current State

Existing implementation already includes:

- `AwsBedrockConnector`
- `AiArtifact`
- `risk_signals` JSONB on `ai_artifacts`
- `RiskSignalDefinition`
- `PostureScoreService`
- artifact relationships for agent to Lambda, datastore, identity, model, guardrail, and knowledge base
- basic UI for AI artefacts

Main gap:

- there is no first-class `Finding` table or lifecycle
- rule logic is embedded in discovery code
- scoring is based on raw `risk_signals`
- no API exists for agent findings

## 4. MVP Scope

### Must Have

1. Assess only `AI_AGENT` artefacts discovered from AWS Bedrock.
2. Convert current agent risk signals into persistent findings.
3. Add a small agent rule engine.
4. Add finding lifecycle: `OPEN`, `RESOLVED`, `ACCEPTED`.
5. Compute per-agent score from findings.
6. Show agent findings in API and UI.
7. Keep the current AWS Bedrock discovery flow working.

### Out of Scope

- tenant/platform segmentation
- GCP, Azure, OpenAI, Hugging Face
- full AI Grid architecture
- ServiceNow integration
- full model file scanning implementation
- full MCP runtime inventory
- cross-tenant analytics
- advanced graph visualization

## 5. Rule Packs

The MVP should support four rule packs, implemented in stages.

## 6. Rule Pack 1 - AWS Bedrock Agent Cloud Risk

This is the first implementation priority because the current connector already collects most of the required evidence.

| Rule ID | Title | Severity | Category | Source |
|---|---|---|---|---|
| `AGENT-IAM-001` | Agent execution role has wildcard IAM permissions | HIGH | Agent Risk | `is_wildcard_role`, policy summary |
| `AGENT-DATA-001` | Agent can write to PII-tagged data resource | HIGH | Agent Risk | `pii_reachable_resources` |
| `AGENT-GRD-001` | Sensitive agent has no guardrail attached | HIGH | Agent Risk | missing `guardrail_id` and PII reachable |
| `AGENT-DATA-002` | Agent can write to untagged datastore | MEDIUM | Agent Risk | reachable S3/Dynamo write access |
| `AGENT-MCP-001` | Agent action group exposes unauthenticated MCP Lambda | HIGH | Agent Risk | Lambda URL auth type `NONE` |
| `AGENT-TOOL-001` | Agent has action group tool execution | MEDIUM | Agent Risk | `action_group_lambda_arns` not empty |
| `AGENT-MEM-001` | Agent has persistent memory enabled | MEDIUM | Agent Risk | Bedrock memory config |
| `AGENT-COLLAB-001` | Agent collaboration is enabled | MEDIUM | Agent Risk | `collaboration_mode != DISABLED` |

## 7. Rule Pack 2 - Agent Code and Config Risk

This pack scans repositories and configuration files. It should be implemented after the cloud-side Bedrock rules.

### Must Have Rules

| Rule | Severity |
|---|---|
| Claude SDK Permission Check Bypass | CRITICAL |
| Claude SDK Permission Mode Bypass | CRITICAL |
| Claude SDK Unsandboxed Commands Allowed | HIGH |
| CrewAI Unrestricted Code Execution | HIGH |
| LangChain Python REPL Tool | HIGH |
| LangChain Shell Tool | MEDIUM |
| OpenAI Agents Tool Approval Disabled | HIGH |
| OpenAI Agents Local Shell Tool | MEDIUM |
| Hardcoded API Keys in Agent Code | HIGH |
| Agent Using MCP Server with Wildcard Tool Auto-Approval | CRITICAL |
| Agent Using MCP Server with Unrestricted Filesystem and Command Access | HIGH |
| OpenClaw Sandbox Disabled | HIGH |
| Default Mode Set to Bypass Permissions | HIGH |
| Unrestricted Bash Execution | HIGH |
| Prompt Injection | HIGH |
| Output-Driven Injection | HIGH |
| Data Exposure | HIGH |
| Dangerous Capabilities | HIGH |
| Missing Guardrails | HIGH |

### Later Rules

- Claude SDK Weaker Nested Sandbox
- Claude SDK Unconditional Tool Allowance
- LangChain Secrets From Environment
- OpenAI Agents Input Guardrail Disabled
- OpenAI Agents Shell Tool Import
- Azure OpenAI Permissive Content Filter
- NeMo Guardrails Empty Rails Configuration
- Guardrails AI Failure Action NOOP
- No Plugin/Marketplace Restrictions
- Unrestricted WebFetch Permission
- Unrestricted File Read Permission

## 8. Rule Pack 3 - MCP Server Risk

MCP is a high-risk agent tool surface. The MVP should include basic MCP config and manifest scanning.

### Must Have Rules

| Rule | Severity |
|---|---|
| MCP Server Tool Poisoning: Malicious Injection | CRITICAL |
| MCP Server Reverse Shell / Command Injection | CRITICAL |
| MCP Server Network Exposure | HIGH |
| MCP Server Insecure Transport | HIGH |
| MCP Server Shell Execution | HIGH |
| MCP Server Suspicious Tool Descriptions | HIGH |
| MCP Server Data Exfiltration | HIGH |
| Agent Using MCP Server with Wildcard Tool Auto-Approval | CRITICAL |
| Agent Using MCP Server with Unrestricted Filesystem and Command Access | HIGH |
| No MCP Server Restrictions | MEDIUM |
| Auto-Enable All Project MCP Servers | MEDIUM |

### Later Rules

- MCP Server Secrets Logged
- MCP Server Weak Input Validation
- MCP Server Overly Permissive CORS
- Agent Using MCP Server with Unpinned Package Versions

## 9. Rule Pack 4 - Model Artifact Risk

This pack requires static inspection of model files or model repositories. It should start with critical arbitrary-code
execution risks.

### Must Have Critical Rules

| Rule | Severity |
|---|---|
| Pickle-based Model Arbitrary Code Execution | CRITICAL |
| PyTorch Model Arbitrary Code Execution | CRITICAL |
| CoreML Model Custom Layer Code Execution | CRITICAL |
| Caffe Model Custom Layer Code Execution | CRITICAL |
| NumPy File Contains Pickle-Serialized Objects | CRITICAL |
| Keras Model Arbitrary Code Execution | CRITICAL |
| SafeTensors Model Contains Dangerous Code Patterns | CRITICAL |
| GGUF Model Template Arbitrary Code Execution | CRITICAL |
| GGML Model Template Code Execution | CRITICAL |
| TensorFlow SavedModel Critical File Operations | CRITICAL |
| LiteRT Model Critical File Operations | CRITICAL |
| Archive Slip Path Traversal | CRITICAL |
| Model Config Arbitrary Code Execution via Hydra | CRITICAL |
| HuggingFace Model Requires `trust_remote_code` | CRITICAL |

### Later Rules

- Pickle Model Obfuscation Techniques
- Pickle Model Suspicious Code Patterns
- Pickle Model Exfiltration Risk
- PyTorch Model Obfuscation Techniques
- PyTorch Model Suspicious Code Patterns
- PyTorch Model Exfiltration Risk
- XGBoost Model Contains Custom Callback
- Keras Model Suspicious Patterns
- SafeTensors Model Contains Suspicious Layers
- SafeTensors Model Contains Moderate Risk Patterns
- GGUF Model Template Suspicious Patterns
- GGML Model Contains Suspicious Template Patterns
- TensorFlow SavedModel Unsafe Filesystem Operations
- TensorFlow SavedModel Custom Operators and File Read
- LiteRT Model Custom Operators
- HuggingFace Model Uses Custom Code Mapping
- Llamafile Contains Suspicious Code Patterns
- Model Has External Dependencies

## 10. Required Data Model

Add a first-class findings table. Do not rely on `risk_signals` as the final system of record.

```sql
CREATE TABLE ai_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id UUID NOT NULL REFERENCES ai_artifacts(id) ON DELETE CASCADE,
  rule_id VARCHAR(100) NOT NULL,
  title VARCHAR(500) NOT NULL,
  severity VARCHAR(30) NOT NULL,
  category VARCHAR(80) NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
  evidence JSONB,
  remediation TEXT,
  first_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ,
  accepted_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (artifact_id, rule_id)
);

CREATE INDEX idx_ai_findings_artifact_status ON ai_findings(artifact_id, status);
CREATE INDEX idx_ai_findings_rule ON ai_findings(rule_id);
CREATE INDEX idx_ai_findings_severity ON ai_findings(severity);
```

## 11. Backend Classes To Add

| Class | Purpose |
|---|---|
| `AiFinding` | JPA entity for `ai_findings` |
| `AiFindingRepository` | Query findings by artifact, status, severity, rule |
| `AgentRuleDefinition` | Enum of MVP Bedrock agent rules |
| `AgentAssessmentRule` | Interface for agent rule evaluation |
| `AiFindingDraft` | DTO returned by a rule before persistence |
| `AgentRiskAssessmentService` | Runs agent rules and persists findings |
| `AiFindingService` | Create, reopen, update, accept, and resolve findings |
| `StaticScanRequest` | DTO for repo/model/MCP scan input |
| `AgentCodeScannerService` | Static scan for agent code/config risks |
| `McpScannerService` | Static scan for MCP configs/manifests |
| `ModelArtifactScannerService` | Static scan for critical model artefact risks |

## 12. Rule Interface

```java
public interface AgentAssessmentRule {
    AgentRuleDefinition definition();
    Optional<AiFindingDraft> evaluate(AiArtifact agent);
}
```

`AiFindingDraft` should contain:

- `ruleId`
- `title`
- `severity`
- `category`
- `evidence`
- `remediation`

## 13. Finding Lifecycle

`AiFindingService` must follow this behavior:

| Condition | Action |
|---|---|
| Rule fires and no finding exists | create `OPEN` |
| Rule fires and finding is `RESOLVED` | reopen as `OPEN` |
| Rule fires and finding is `OPEN` | update `last_seen_at` and evidence |
| Rule fires and finding is `ACCEPTED` | update `last_seen_at`, keep accepted |
| Rule no longer fires | mark `RESOLVED` |

## 14. Risk Score

For MVP, use a simple 0-100 posture score where higher is better.

```text
Start at 100.

HIGH finding   = -25 each
MEDIUM finding = -12 each
LOW finding    = -5 each

Minimum score = 0.
```

Risk level:

```text
0-39   HIGH
40-69  MEDIUM
70-100 LOW
```

The score should be calculated from `ai_findings`, not `risk_signals`.

## 15. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/findings` | List findings with filters |
| `GET` | `/api/v1/artifacts/{id}/findings` | Findings for one agent |
| `POST` | `/api/v1/artifacts/{id}/assess` | Reassess one agent |
| `POST` | `/api/v1/agents/assess` | Reassess all active agents |
| `POST` | `/api/v1/findings/{id}/accept` | Accept risk |
| `POST` | `/api/v1/findings/{id}/resolve` | Manually resolve finding |
| `POST` | `/api/v1/static-scan/agent-code` | Scan agent repo/config path |
| `POST` | `/api/v1/static-scan/mcp` | Scan MCP config path |
| `POST` | `/api/v1/static-scan/model` | Scan model file or folder path |

## 16. Frontend Scope

Update the agent detail page to show:

- posture score
- risk level
- open findings
- accepted findings
- resolved findings
- evidence
- remediation
- accept action
- resolve action

Group findings by:

- Agent Risk
- MCP Risk
- Model Risk

## 17. Sequential Execution Plan

### Step 1 - Add Findings Table

Create Flyway migration for `ai_findings` and indexes.

### Step 2 - Add Entity and Repository

Implement `AiFinding` and `AiFindingRepository`.

### Step 3 - Add Rule Definitions

Create `AgentRuleDefinition` enum with the Bedrock agent cloud rules.

### Step 4 - Add Rule Interface and DTO

Create `AgentAssessmentRule` and `AiFindingDraft`.

### Step 5 - Implement Bedrock Agent Rules

Implement:

- `WildcardIamRoleRule`
- `WriteToPiiResourceRule`
- `NoGuardrailOnSensitiveAgentRule`
- `WriteToUntaggedDatastoreRule`
- `UnauthenticatedMcpLambdaRule`
- `ActionGroupToolExecutionRule`
- `MemoryEnabledRule`
- `CollaborationEnabledRule`

### Step 6 - Implement Finding Service

Implement create, reopen, update, accept, and resolve behavior.

### Step 7 - Implement Agent Assessment Service

Load active `AI_AGENT` artefacts and run all rules.

### Step 8 - Wire Assessment Into Discovery

After `AwsBedrockConnector` upserts each agent, call `AgentRiskAssessmentService.assess(agentArtifact.getId())`.

### Step 9 - Move Scoring to Findings

Update `PostureScoreService` to compute score from `ai_findings`. Keep `risk_signals` temporarily for backward compatibility.

### Step 10 - Add Findings APIs

Add list, artifact findings, assess, accept, and resolve endpoints.

### Step 11 - Update UI

Show findings and risk score on agent detail page.

### Step 12 - Add Static Scanner Foundation

Add static scan request DTOs and basic service skeletons for:

- agent code scanning
- MCP config scanning
- model artefact scanning

### Step 13 - Implement Critical Static Rules

Implement critical/high rules only:

- hardcoded API keys
- unrestricted shell/bash execution
- MCP wildcard tool auto-approval
- MCP command injection patterns
- pickle model execution risk
- PyTorch model execution risk
- HuggingFace `trust_remote_code`
- archive slip path traversal

### Step 14 - Add Tests

Minimum tests:

- each Bedrock rule fires when expected
- each Bedrock rule does not fire when evidence is absent
- finding is created
- finding is not duplicated
- finding is resolved when rule no longer fires
- accepted finding stays accepted
- score changes when findings change
- critical static scanner fixtures produce findings

### Step 15 - End-to-End Demo

Demo flow:

1. Run AWS Bedrock scan.
2. Open AI agent inventory.
3. Open one risky agent.
4. Show findings, evidence, remediation, and posture score.
5. Accept one finding.
6. Resolve one finding.
7. Re-run assessment and confirm lifecycle behavior.

## 18. Acceptance Criteria

MVP is complete when:

- AWS Bedrock discovery still works.
- Active `AI_AGENT` artefacts can be assessed.
- Findings are persisted in `ai_findings`.
- Reassessment does not create duplicates.
- Removed risks become `RESOLVED`.
- Accepted findings stay accepted.
- Agent score is calculated from findings.
- API exposes findings.
- UI shows agent findings and score.
- Critical static scanner foundation exists for agent code, MCP, and model artefacts.

## 19. Final Intern Assignment

Build the AWS Bedrock Agent Risk Assessment MVP:

- rules
- findings lifecycle
- risk score
- API
- UI
- static scanner foundation for critical agent, MCP, and model risks

This creates the foundation for the full AI Grid architecture without asking the intern to build the entire platform.
