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

    public AiAgentExecutionApiService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
    }

    public PageResponse<ExecutionResponse> list(Tenant tenant, UUID agentId, String status, String source,
                                                Instant from, Instant to, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("tenantId", tenant.getId())
                    .addValue("agentId", agentId).addValue("status", blank(status)).addValue("source", blank(source))
                    .addValue("from", from == null ? null : Timestamp.from(from))
                    .addValue("to", to == null ? null : Timestamp.from(to))
                    .addValue("limit", safeSize).addValue("offset", safePage * safeSize);
            String where = """
                    where tenant_id = :tenantId
                      and (:agentId is null or agent_artifact_id = :agentId)
                      and (:status is null or status = :status)
                      and (:source is null or source = :source)
                      and (:from is null or evidence_time >= :from)
                      and (:to is null or evidence_time < :to)
                    """;
            var items = jdbc.query("""
                    select id, provider, provider_execution_id, agent_artifact_id, source, started_at,
                           completed_at, status, outcome_category, approval_state, policy_state,
                           classification, api_version, token_count, latency_ms, retry_count,
                           spend_micros, evidence_time
                      from ai_agent_executions
                    """ + where + " order by evidence_time desc, id limit :limit offset :offset", params,
                    (rs, n) -> new ExecutionResponse(rs.getObject("id", UUID.class), rs.getString("provider"),
                            rs.getString("provider_execution_id"), rs.getObject("agent_artifact_id", UUID.class),
                            rs.getString("source"), instant(rs.getTimestamp("started_at")), instant(rs.getTimestamp("completed_at")),
                            rs.getString("status"), rs.getString("outcome_category"), rs.getString("approval_state"),
                            rs.getString("policy_state"), rs.getString("classification"), rs.getString("api_version"),
                            (Long) rs.getObject("token_count"), (Long) rs.getObject("latency_ms"),
                            (Integer) rs.getObject("retry_count"), (Long) rs.getObject("spend_micros"),
                            instant(rs.getTimestamp("evidence_time"))));
            long total = jdbc.queryForObject("select count(*) from ai_agent_executions " + where, params, Long.class);
            return new PageResponse<>(items, safePage, safeSize, total);
        });
    }

    public java.util.List<ExecutionEventResponse> timeline(Tenant tenant, UUID executionId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select e.id, e.execution_id, e.sequence, e.event_time, e.event_type, e.status,
                       e.classification, e.evidence_time
                  from ai_agent_execution_events e
                  join ai_agent_executions x on x.id = e.execution_id
                 where e.tenant_id = :tenantId and x.tenant_id = :tenantId and e.execution_id = :executionId
                 order by e.sequence
                 limit 1000
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("executionId", executionId), (rs, n) -> new ExecutionEventResponse(
                rs.getObject("id", UUID.class), rs.getObject("execution_id", UUID.class), rs.getLong("sequence"),
                instant(rs.getTimestamp("event_time")), rs.getString("event_type"), rs.getString("status"),
                rs.getString("classification"), instant(rs.getTimestamp("evidence_time")))));
    }

    private static String blank(String value) { return value == null || value.isBlank() ? null : value; }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }

    public record PageResponse<T>(java.util.List<T> items, int page, int size, long total) { }
    public record ExecutionResponse(UUID id, String provider, String providerExecutionId, UUID agentArtifactId,
                                    String source, Instant startedAt, Instant completedAt, String status,
                                    String outcomeCategory, String approvalState, String policyState,
                                    String classification, String apiVersion, Long tokenCount, Long latencyMs,
                                    Integer retryCount, Long spendMicros, Instant evidenceTime) { }
    public record ExecutionEventResponse(UUID id, UUID executionId, long sequence, Instant eventTime,
                                         String eventType, String status, String classification, Instant evidenceTime) { }
}
