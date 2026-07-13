# OpenLLMetry / Traceloop Analysis for Scout AI Grid

## 1. Executive Summary

OpenLLMetry should be used in Scout AI Grid as a runtime telemetry and evidence layer, not as the primary discovery
engine.

The existing AIDiscovery implementation already discovers AWS Bedrock AI artefacts and stores static posture facts:

- agents
- IAM roles
- Lambda action groups
- guardrails
- datastores
- knowledge bases
- relationships
- static `risk_signals`

OpenLLMetry adds a different capability: observing what AI applications actually do at runtime.

The right architecture is:

```text
AIDiscovery = what exists and how it is configured
OpenLLMetry = what is actually being used at runtime
Scout AI Grid findings = static posture + runtime evidence
```

This gives Scout a stronger customer story than static discovery alone: not just "what AI assets exist", but "what
they are doing in production".

## 2. What OpenLLMetry Provides

OpenLLMetry is built on OpenTelemetry and emits OTLP telemetry for LLM and agent applications. It can instrument common
AI providers, frameworks, vector databases, agents, tools, and workflows.

Relevant capabilities:

- model call traces
- prompt and completion spans
- tool call traces
- agent and workflow traces
- vector database calls
- framework instrumentation
- token and latency metadata
- error traces
- user/session/team association metadata
- OpenTelemetry Collector compatibility

OpenLLMetry is useful for runtime security because it can show actual model, tool, MCP, and retrieval behavior.

## 3. What OpenLLMetry Should Not Replace

OpenLLMetry should not replace AIDiscovery or static scanning.

Keep AIDiscovery as the source for:

- AWS Bedrock agent inventory
- IAM wildcard permissions
- Bedrock guardrail attachment
- Lambda function URL authentication
- datastore tags
- PII resource reachability
- cloud configuration drift
- static relationships between agents, tools, data, identity, and models

Keep static scanners as the source for:

- pickle / PyTorch / Keras / TensorFlow model file risks
- repository code scanning
- MCP manifest scanning
- hardcoded keys in agent code
- policy-as-code checks

## 4. Recommended Scout Architecture

```text
Customer AI App
  -> OpenLLMetry SDK / instrumentation
  -> OpenTelemetry Collector
  -> Scout Runtime Telemetry Ingest API
  -> Runtime event store
  -> Correlation with AIDiscovery ai_artifacts
  -> Runtime security rules
  -> ai_findings
  -> AI Grid dashboard / Findings
```

Use an OpenTelemetry Collector between customer applications and Scout. The collector gives filtering, sampling,
redaction, routing, and future flexibility.

## 5. Privacy and Data Handling

OpenLLMetry can capture prompts, completions, and embeddings in span attributes. That is useful for debugging but risky
for a security product.

Default Scout recommendation:

```bash
TRACELOOP_TRACE_CONTENT=false
```

Policy:

1. Default content tracing off.
2. Store metadata and redacted evidence by default.
3. Allow content tracing only when explicitly enabled by customer policy.
4. Never store raw prompts or completions by default.
5. Store hashes/redacted snippets where evidence is required.
6. Apply customer-controlled retention.

## 6. New Scout Components

### 6.1 Runtime Telemetry Ingest

Add a runtime ingestion path for OpenLLMetry events.

MVP endpoint:

```text
POST /api/v1/ai-runtime/events
```

Start with normalized JSON events. Full OTLP receiver support can come later.

### 6.2 Runtime Event Table

```sql
CREATE TABLE ai_runtime_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id UUID NULL REFERENCES ai_artifacts(id),
  trace_id VARCHAR(128),
  span_id VARCHAR(128),
  provider VARCHAR(100),
  model VARCHAR(255),
  operation VARCHAR(100),
  event_type VARCHAR(100),
  tool_name VARCHAR(255),
  vector_db VARCHAR(255),
  user_ref VARCHAR(255),
  session_ref VARCHAR(255),
  metadata JSONB,
  redacted_content JSONB,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Recommended indexes:

```sql
CREATE INDEX idx_ai_runtime_events_artifact ON ai_runtime_events(artifact_id);
CREATE INDEX idx_ai_runtime_events_trace ON ai_runtime_events(trace_id);
CREATE INDEX idx_ai_runtime_events_observed_at ON ai_runtime_events(observed_at DESC);
CREATE INDEX idx_ai_runtime_events_provider_model ON ai_runtime_events(provider, model);
CREATE INDEX idx_ai_runtime_events_tool ON ai_runtime_events(tool_name);
```

### 6.3 Runtime Correlation Service

Add:

```java
RuntimeTraceCorrelationService
```

Responsibilities:

- match runtime events to `AI_AGENT`, `AI_MODEL`, `AI_KB`, `AI_LAMBDA`, `AI_DATASTORE`, or `MCP_SERVER`
- use explicit Scout association metadata where available
- fall back to provider/model/tool names where needed
- mark unresolved activity as `UNKNOWN_RUNTIME_AI_ASSET`

Recommended correlation keys:

- `scout_agent_id`
- `scout_artifact_id`
- `app_id`
- `environment`
- `provider`
- `model`
- `tool_name`
- `mcp_server`
- `session_id`
- `user_id`
- `team`

### 6.4 Runtime Rule Engine

Add:

```java
RuntimeAiSecurityRuleService
RuntimeFindingService
```

Runtime findings should use the same `ai_findings` lifecycle as static findings.

## 7. Runtime Findings To Implement First

Start with runtime findings that do not require raw prompt text.

| Rule ID | Title | Severity | Evidence |
|---|---|---:|---|
| `RT-MODEL-001` | Runtime call to unapproved model | HIGH | provider/model from span |
| `RT-MODEL-002` | Runtime call to unknown model not in inventory | MEDIUM | model not linked to `AI_MODEL` |
| `RT-AGENT-001` | Agent executed tool not discovered in AIDiscovery | HIGH | tool span without known relation |
| `RT-MCP-001` | MCP tool invoked without registered MCP server | HIGH | MCP/tool span with no artifact |
| `RT-MCP-002` | High-risk MCP tool invoked | HIGH | shell/file/database tool name |
| `RT-DATA-001` | Runtime vector DB access not linked to approved KB | HIGH | vector DB span |
| `RT-GUARD-001` | Model call observed without guardrail route | MEDIUM | missing guardrail/gateway metadata |
| `RT-OBS-001` | Runtime trace missing agent or session association | LOW | missing association metadata |
| `RT-COST-001` | Abnormal token usage spike | MEDIUM | token counts over threshold |
| `RT-ERROR-001` | Agent/tool error rate above threshold | MEDIUM | span status/error count |

Add content-dependent rules only after privacy controls are implemented:

| Rule ID | Title | Severity | Evidence |
|---|---|---:|---|
| `RT-DATA-002` | Prompt or response contains secret pattern | HIGH | redacted content evidence |
| `RT-DATA-003` | Prompt or response contains PII | HIGH | redacted content evidence |
| `RT-PROMPT-001` | Prompt injection pattern detected | HIGH | redacted prompt snippet |

## 8. Customer Instrumentation Guidance

### Python

```python
from traceloop.sdk import Traceloop

Traceloop.init()
```

### Privacy-safe production defaults

```bash
TRACELOOP_TRACE_CONTENT=false
TRACELOOP_BASE_URL=https://<customer-otel-collector>:4318
```

### Association metadata

Customers should attach identifiers that help Scout correlate runtime traces with discovered assets.

```python
from traceloop.sdk import Traceloop

Traceloop.set_association_properties({
    "scout_agent_id": "agent-123",
    "scout_environment": "prod",
    "app_id": "claims-assistant",
    "team": "customer-ops"
})
```

## 9. OpenTelemetry Collector Pattern

Provide a reference collector deployment.

```yaml
receivers:
  otlp:
    protocols:
      http:
      grpc:

processors:
  batch:
  attributes:
    actions:
      - key: prompt
        action: delete
      - key: completion
        action: delete

exporters:
  otlphttp/scout:
    endpoint: https://scout.example.com/api/v1/ai-runtime/otlp

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [attributes, batch]
      exporters: [otlphttp/scout]
```

MVP can use a normalized JSON exporter instead of full OTLP ingest if faster to implement.

## 10. Integration With Existing AIDiscovery

Current AIDiscovery stores:

- `AiArtifact`
- `risk_signals`
- artifact relationships
- AWS Bedrock metadata
- posture scores

Recommended integration:

1. Keep AIDiscovery discovery unchanged.
2. Add first-class `ai_findings`.
3. Add `ai_runtime_events`.
4. Correlate runtime events to `AiArtifact`.
5. Create runtime findings into `ai_findings`.
6. Update posture score to include both static and runtime findings.

## 11. Sequential Implementation Plan

### Step 1 - Keep AIDiscovery as inventory

Do not rewrite current AWS Bedrock discovery. It already provides useful static artefacts and relationships.

### Step 2 - Add `ai_findings`

Create persistent findings lifecycle before adding telemetry findings.

### Step 3 - Add `ai_runtime_events`

Store normalized runtime observations from OpenLLMetry or the OpenTelemetry Collector.

### Step 4 - Add runtime ingest API

Start with normalized JSON event ingestion. Add full OTLP ingest later.

### Step 5 - Add OTel Collector reference config

Provide a sample collector config that receives OpenLLMetry OTLP and exports sanitized events to Scout.

### Step 6 - Add correlation service

Match runtime events to `ai_artifacts` using explicit association metadata, provider/model names, tool names, and
known relationships.

### Step 7 - Add runtime rule engine

Implement first runtime rules:

- unknown model
- unapproved model
- unknown tool
- high-risk MCP tool
- unknown vector DB
- missing association metadata
- token spike
- error spike

### Step 8 - Add privacy controls

Default content tracing off. Store only redacted content and hashes.

### Step 9 - Update UI

On agent detail page, show:

- static findings
- runtime findings
- recent model calls
- recent tool calls
- unknown runtime activity

### Step 10 - Add customer instrumentation guide

Provide Python/Node snippets and collector config for customer deployment.

## 12. MVP Recommendation

For Scout AI Grid MVP, implement OpenLLMetry integration as a runtime telemetry connector with these first outcomes:

1. Runtime model usage visibility.
2. Runtime tool/MCP invocation visibility.
3. Findings for unknown or unapproved runtime activity.
4. Runtime evidence attached to AI Grid findings.
5. Privacy-safe defaults with prompt/completion content disabled.

## 13. Final Verdict

OpenLLMetry is a strong fit for Scout AI Grid, but only as the runtime telemetry layer.

Use:

```text
AIDiscovery for static AI inventory and cloud posture.
OpenLLMetry for runtime AI behavior telemetry.
Scout findings for merged static and runtime risks.
```

This creates a differentiated AI security story for Scout: the product can show what AI assets exist, how they are
configured, and what they are actually doing in production.
