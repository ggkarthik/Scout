package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Read-only, metadata-only runtime API. It is always executed inside the selected tenant schema. */
@Service
public class AiAgentExecutionApiService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiAgentExecutionRelationshipProjectionService relationships;

    public AiAgentExecutionApiService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution,
                                      AiAgentExecutionRelationshipProjectionService relationships) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.relationships = relationships;
    }

    public PageResponse<ExecutionResponse> list(Tenant tenant, UUID agentId, UUID agentVersionId, String status, String source,
                                                Instant from, Instant to, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("tenantId", tenant.getId())
                    .addValue("agentId", agentId).addValue("agentVersionId", agentVersionId)
                    .addValue("status", blank(status)).addValue("source", blank(source))
                    .addValue("from", from == null ? null : Timestamp.from(from))
                    .addValue("to", to == null ? null : Timestamp.from(to))
                    .addValue("limit", safeSize).addValue("offset", safePage * safeSize);
            String where = """
                    where tenant_id = :tenantId
                      and (:agentId is null or agent_artifact_id = :agentId)
                      and (:agentVersionId is null or agent_version_artifact_id = :agentVersionId)
                      and (:status is null or status = :status)
                      and (:source is null or source = :source)
                      and (:from is null or evidence_time >= :from)
                      and (:to is null or evidence_time < :to)
                    """;
            var items = jdbc.query("""
                    select id, provider, agent_artifact_id, agent_version_artifact_id,correlation_status,correlation_diagnostic,source, started_at,
                           completed_at, status, outcome_category, approval_state, policy_state,
                           classification, api_version, token_count, latency_ms, retry_count,
                           spend_micros, evidence_time,environment_digest,deployment_digest,
                           acting_identity_digest,delegated_identity_digest,termination_reason,evidence_source,
                           evidence_class,evidence_confidence,step_count,spend_currency,spend_unit,collected_at,
                           provider_event_time,delivery_latency_ms
                      from ai_agent_executions
                    """ + where + " order by evidence_time desc, id limit :limit offset :offset", params,
                    (rs, n) -> new ExecutionResponse(rs.getObject("id", UUID.class), rs.getString("provider"),
                            rs.getObject("agent_artifact_id", UUID.class),rs.getObject("agent_version_artifact_id", UUID.class),
                            rs.getString("correlation_status"),rs.getString("correlation_diagnostic"),
                            rs.getString("source"), instant(rs.getTimestamp("started_at")), instant(rs.getTimestamp("completed_at")),
                            rs.getString("status"), rs.getString("outcome_category"), rs.getString("approval_state"),
                            rs.getString("policy_state"), rs.getString("classification"), rs.getString("api_version"),
                            (Long) rs.getObject("token_count"), (Long) rs.getObject("latency_ms"),
                            (Integer) rs.getObject("retry_count"), (Long) rs.getObject("spend_micros"),
                            instant(rs.getTimestamp("evidence_time")),rs.getString("environment_digest"),
                            rs.getString("deployment_digest"),rs.getString("acting_identity_digest"),
                            rs.getString("delegated_identity_digest"),rs.getString("termination_reason"),
                            rs.getString("evidence_source"),rs.getString("evidence_class"),
                            number(rs.getObject("evidence_confidence")),(Long) rs.getObject("step_count"),
                            rs.getString("spend_currency"),rs.getString("spend_unit"),
                            instant(rs.getTimestamp("collected_at")),instant(rs.getTimestamp("provider_event_time")),
                            (Long) rs.getObject("delivery_latency_ms")));
            long total = jdbc.queryForObject("select count(*) from ai_agent_executions " + where, params, Long.class);
            return new PageResponse<>(items, safePage, safeSize, total);
        });
    }

    public java.util.List<ExecutionEventResponse> timeline(Tenant tenant, UUID executionId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select e.id, e.execution_id, e.sequence, e.event_time, e.event_type, e.status,
                       e.classification, e.evidence_time,e.ingested_at,e.action_category,e.target_class,
                       e.tool_digest,e.tool_version_digest,e.target_digest,e.action_correlation_digest,
                       e.data_sensitivity,e.data_operation,e.approval_state,e.policy_state,e.decision_reason,
                       e.enforcement_point,e.action_outcome,e.evidence_class
                  from ai_agent_execution_events e
                  join ai_agent_executions x on x.id = e.execution_id
                 where e.tenant_id = :tenantId and x.tenant_id = :tenantId and e.execution_id = :executionId
                 order by e.sequence
                 limit 1000
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("executionId", executionId), (rs, n) -> new ExecutionEventResponse(
                rs.getObject("id", UUID.class), rs.getObject("execution_id", UUID.class), rs.getLong("sequence"),
                instant(rs.getTimestamp("event_time")), rs.getString("event_type"), rs.getString("status"),
                rs.getString("classification"), instant(rs.getTimestamp("evidence_time")),
                instant(rs.getTimestamp("ingested_at")),rs.getString("action_category"),rs.getString("target_class"),
                rs.getString("tool_digest"),rs.getString("tool_version_digest"),rs.getString("target_digest"),
                rs.getString("action_correlation_digest"),rs.getString("data_sensitivity"),rs.getString("data_operation"),
                rs.getString("approval_state"),rs.getString("policy_state"),rs.getString("decision_reason"),
                rs.getString("enforcement_point"),rs.getString("action_outcome"),rs.getString("evidence_class"))));
    }

    public java.util.List<ExecutionRelationshipResponse> relationships(Tenant tenant, UUID executionId) {
        return tenantExecution.run(tenant, () -> relationships.relationships(tenant.getId(), executionId).stream()
                .map(edge -> new ExecutionRelationshipResponse(edge.executionId(), edge.relationshipType(),
                        edge.artifactId(), edge.artifactName(), edge.participantRole())).toList());
    }

    private static String blank(String value) { return value == null || value.isBlank() ? null : value; }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }
    private static Double number(Object value) { return value == null ? null : ((Number) value).doubleValue(); }

    public record PageResponse<T>(java.util.List<T> items, int page, int size, long total) { }
    public record ExecutionResponse(UUID id, String provider, UUID agentArtifactId, UUID agentVersionArtifactId,
                                    String correlationStatus, String correlationDiagnostic,
                                    String source, Instant startedAt, Instant completedAt, String status,
                                    String outcomeCategory, String approvalState, String policyState,
                                    String classification, String apiVersion, Long tokenCount, Long latencyMs,
                                    Integer retryCount, Long spendMicros, Instant evidenceTime,
                                    String environmentDigest, String deploymentDigest, String actingIdentityDigest,
                                    String delegatedIdentityDigest, String terminationReason, String evidenceSource,
                                    String evidenceClass, Double evidenceConfidence, Long stepCount,
                                    String spendCurrency, String spendUnit, Instant collectedAt,
                                    Instant providerEventTime, Long deliveryLatencyMs) { }
    public record ExecutionEventResponse(UUID id, UUID executionId, long sequence, Instant eventTime,
                                         String eventType, String status, String classification, Instant evidenceTime,
                                         Instant ingestedAt, String actionCategory, String targetClass, String toolDigest,
                                         String toolVersionDigest, String targetDigest, String actionCorrelationDigest,
                                         String dataSensitivity, String dataOperation, String approvalState,
                                         String policyState, String decisionReason, String enforcementPoint,
                                         String actionOutcome, String evidenceClass) { }
    public record ExecutionRelationshipResponse(UUID executionId, String relationshipType, UUID artifactId,
                                                String artifactName, String participantRole) { }
}
