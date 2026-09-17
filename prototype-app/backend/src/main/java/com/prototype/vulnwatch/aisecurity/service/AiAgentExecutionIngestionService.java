package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Shared metadata-only runtime write boundary. Source collectors pass provider IDs only to this
 * method; they are HMACed before persistence, receipts, cursors, or diagnostics are constructed.
 */
@Service
public class AiAgentExecutionIngestionService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiSecurityDigestService digests;
    private final int maxEvents;
    private final int maxMetadataBytes;
    private final int lookbackDays;
    private final int overlapDays;

    public AiAgentExecutionIngestionService(NamedParameterJdbcTemplate jdbc,
                                            TenantSchemaExecutionService tenantExecution,
                                            TransactionTemplate transactions,
                                            AiSecurityDigestService digests,
                                            @Value("${app.ai-security.runtime.max-events-per-execution:1000}") int maxEvents,
                                            @Value("${app.ai-security.runtime.max-metadata-bytes-per-execution:16384}") int maxMetadataBytes,
                                            @Value("${app.ai-security.runtime.lookback-days:30}") int lookbackDays,
                                            @Value("${app.ai-security.runtime.overlap-days:3}") int overlapDays) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.digests = digests;
        this.maxEvents = Math.max(1, maxEvents);
        this.maxMetadataBytes = Math.max(256, maxMetadataBytes);
        this.lookbackDays = Math.max(1, lookbackDays);
        this.overlapDays = Math.max(0, Math.min(this.lookbackDays, overlapDays));
    }

    public Result ingest(Tenant tenant, UUID connectorId, RuntimeExecution observation) {
        validate(observation);
        return tenantExecution.run(tenant, () -> transactions.execute(status -> persist(tenant, connectorId, observation)));
    }

    /** Resolves a cursor without ever querying by the provider's plaintext scope identifier. */
    public Instant cursorTimestamp(Tenant tenant, UUID connectorId, String source, String providerScopeKey) {
        return cursor(tenant, connectorId, source, providerScopeKey).timestamp();
    }

    public CursorState cursor(Tenant tenant, UUID connectorId, String source, String providerScopeKey) {
        List<String> candidates = digests.identityCandidates(tenant, "runtime-scope:" + source, providerScopeKey)
                .stream().map(AiSecurityDigestService.Digest::value).toList();
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select provider_timestamp,lookback_days,overlap_days
                  from ai_agent_execution_cursors
                 where connector_id=:connectorId and source=:source and scope_key in (:scopeKeys)
                 order by provider_timestamp desc nulls last
                 limit 1
                """, new MapSqlParameterSource().addValue("connectorId", connectorId)
                .addValue("source", source).addValue("scopeKeys", candidates),
                rs -> rs.next() ? new CursorState(rs.getTimestamp(1) == null ? null : rs.getTimestamp(1).toInstant(),
                        rs.getInt(2), rs.getInt(3)) : new CursorState(null, lookbackDays, overlapDays)));
    }

    public UUID artifactId(Tenant tenant, String providerResourceId) {
        if (providerResourceId == null || providerResourceId.isBlank()) return null;
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id from ai_security_artifacts
                 where tenant_id=:tenantId and provider_resource_id=:providerResourceId and active=true
                 limit 1
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId())
                .addValue("providerResourceId", providerResourceId),
                rs -> rs.next() ? rs.getObject(1, UUID.class) : null));
    }

    /** Resolves provider references only against observed inventory; absence remains explicit. */
    public AgentResolution resolveAgent(Tenant tenant, String provider, String agentReference, String versionReference) {
        if (blank(agentReference)) return new AgentResolution(null, null, "UNRESOLVED", "AGENT_REFERENCE_MISSING");
        return tenantExecution.run(tenant, () -> {
            List<UUID> agents = jdbc.query("""
                    select id from ai_security_artifacts
                     where tenant_id=:tenantId and provider=:provider and artifact_type='AI_AGENT' and active=true
                       and (provider_resource_id=:reference or lower(name)=lower(:reference))
                     limit 2
                    """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("provider", provider)
                    .addValue("reference", agentReference), (rs, row) -> rs.getObject(1, UUID.class));
            if (agents.size() != 1) return new AgentResolution(null, null, "UNRESOLVED",
                    agents.isEmpty() ? "AGENT_REFERENCE_NOT_FOUND" : "AGENT_REFERENCE_AMBIGUOUS");
            UUID agentId = agents.get(0);
            List<UUID> versions = jdbc.query("""
                    select v.id
                      from ai_security_artifacts v
                      join ai_security_relationships r on r.source_artifact_id=v.id and r.target_artifact_id=:agentId
                       and r.relationship_type='VERSION_OF' and r.active=true
                     where v.active=true and (:version is null or v.provider_resource_id=:version
                            or v.attributes_json->>'version'=:version)
                     order by case when v.attributes_json->>'version'=:version then 0 else 1 end, v.last_observed_at desc
                     limit 2
                    """, new MapSqlParameterSource().addValue("agentId", agentId).addValue("version", versionReference),
                    (rs, row) -> rs.getObject(1, UUID.class));
            UUID versionId = versions.size() == 1 ? versions.get(0) : null;
            String diagnostic = versionReference != null && versionId == null ? "AGENT_VERSION_REFERENCE_NOT_FOUND" : null;
            return new AgentResolution(agentId, versionId, "RESOLVED", diagnostic);
        });
    }

    private Result persist(Tenant tenant, UUID connectorId, RuntimeExecution input) {
        List<AiSecurityDigestService.Digest> candidates = digests.identityCandidates(
                tenant, "provider-execution:" + input.provider(), input.providerExecutionId());
        AiSecurityDigestService.Digest executionId = candidates.get(0);
        AiSecurityDigestService.Digest scopeKey = digests.identityDigest(
                tenant, "runtime-scope:" + input.source(), input.scopeKey());
        String receiptMaterial = input.provider() + "|" + input.source() + "|" + scopeKey.value()
                + "|" + executionId.value();
        AiSecurityDigestService.Digest receipt = digests.identityDigest(tenant, "execution-receipt", receiptMaterial);
        UUID id = UUID.randomUUID();
        int receiptInserted = jdbc.update("""
                insert into ai_agent_execution_receipts
                    (id,tenant_id,connector_id,source,scope_key,idempotency_key,content_hash,execution_id)
                values (:id,:tenantId,:connectorId,:source,:scopeKey,:key,:hash,null)
                on conflict (tenant_id,idempotency_key) do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("connectorId", connectorId).addValue("source", input.source()).addValue("scopeKey", scopeKey.value())
                .addValue("key", receipt.value()).addValue("hash", receipt.value()));
        if (receiptInserted == 0) {
            UUID known = jdbc.query("""
                    select execution_id from ai_agent_execution_receipts
                     where tenant_id=:tenantId and idempotency_key=:key
                    """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("key", receipt.value()),
                    rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
            if (known == null) throw new IllegalStateException("Accepted runtime receipt is missing its execution");
            return new Result(known, true);
        }
        AiSecurityDigestService.Digest agentDigest = blank(input.providerAgentReference()) ? null
                : digests.identityDigest(tenant, "provider-agent:" + input.provider(), input.providerAgentReference());
        AiSecurityDigestService.Digest versionDigest = blank(input.providerAgentVersionReference()) ? null
                : digests.identityDigest(tenant, "provider-agent-version:" + input.provider(), input.providerAgentVersionReference());
        MapSqlParameterSource values = new MapSqlParameterSource()
                .addValue("id", id).addValue("tenantId", tenant.getId()).addValue("provider", input.provider())
                .addValue("executionDigest", executionId.value()).addValue("keyVersion", executionId.keyVersion())
                .addValue("agentId", input.agentArtifactId()).addValue("source", input.source())
                .addValue("agentVersionId", input.agentVersionArtifactId())
                .addValue("providerAgentDigest", agentDigest == null ? null : agentDigest.value())
                .addValue("providerAgentVersionDigest", versionDigest == null ? null : versionDigest.value())
                .addValue("correlationStatus", input.correlationStatus()).addValue("correlationDiagnostic", input.correlationDiagnostic())
                .addValue("startedAt", timestamp(input.startedAt())).addValue("completedAt", timestamp(input.completedAt()))
                .addValue("status", input.status()).addValue("outcome", input.outcomeCategory())
                .addValue("approval", input.approvalState()).addValue("policy", input.policyState())
                .addValue("classification", input.classification()).addValue("apiVersion", input.apiVersion())
                .addValue("tokenCount", input.tokenCount()).addValue("latencyMs", input.latencyMs())
                .addValue("retryCount", input.retryCount()).addValue("spendMicros", input.spendMicros())
                .addValue("evidenceTime", Timestamp.from(input.evidenceTime()));
        jdbc.update("""
                insert into ai_agent_executions (id,tenant_id,provider,provider_execution_digest,digest_key_version,
                    agent_artifact_id,agent_version_artifact_id,provider_agent_digest,provider_agent_version_digest,
                    correlation_status,correlation_diagnostic,source,started_at,completed_at,status,outcome_category,approval_state,policy_state,
                    classification,api_version,token_count,latency_ms,retry_count,spend_micros,evidence_time)
                values (:id,:tenantId,:provider,:executionDigest,:keyVersion,:agentId,
                    :agentVersionId,:providerAgentDigest,:providerAgentVersionDigest,:correlationStatus,:correlationDiagnostic,
                    :source,:startedAt,:completedAt,:status,:outcome,:approval,:policy,:classification,:apiVersion,:tokenCount,:latencyMs,:retryCount,
                    :spendMicros,:evidenceTime)
                """, values);
        for (RuntimeEvent event : input.events()) {
            jdbc.update("""
                    insert into ai_agent_execution_events (id,tenant_id,execution_id,sequence,event_time,event_type,status,
                        classification,evidence_time)
                    values (:id,:tenantId,:executionId,:sequence,:eventTime,:eventType,:status,:classification,:evidenceTime)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("executionId", id).addValue("sequence", event.sequence())
                    .addValue("eventTime", Timestamp.from(event.eventTime())).addValue("eventType", event.eventType())
                    .addValue("status", event.status()).addValue("classification", event.classification())
                    .addValue("evidenceTime", Timestamp.from(input.evidenceTime())));
        }
        jdbc.update("update ai_agent_execution_receipts set execution_id=:executionId where tenant_id=:tenantId and idempotency_key=:key",
                new MapSqlParameterSource().addValue("executionId", id).addValue("tenantId", tenant.getId()).addValue("key", receipt.value()));
        insertParticipants(tenant, id, input, input.evidenceTime());
        jdbc.update("""
                insert into ai_agent_execution_cursors (id,tenant_id,connector_id,source,scope_key,provider_timestamp,
                    provider_stable_digest,lookback_days,overlap_days)
                values (:id,:tenantId,:connectorId,:source,:scopeKey,:timestamp,:stableId,:lookbackDays,:overlapDays)
                on conflict (tenant_id,connector_id,source,scope_key) do update set
                    provider_timestamp=excluded.provider_timestamp, provider_stable_digest=excluded.provider_stable_digest,
                    updated_at=now()
                where ai_agent_execution_cursors.provider_timestamp is null
                   or excluded.provider_timestamp > ai_agent_execution_cursors.provider_timestamp
                   or (excluded.provider_timestamp = ai_agent_execution_cursors.provider_timestamp
                       and excluded.provider_stable_digest > ai_agent_execution_cursors.provider_stable_digest)
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("connectorId", connectorId).addValue("source", input.source()).addValue("scopeKey", scopeKey.value())
                .addValue("timestamp", Timestamp.from(input.evidenceTime())).addValue("stableId", executionId.value())
                .addValue("lookbackDays", lookbackDays).addValue("overlapDays", overlapDays));
        return new Result(id, false);
    }

    private void insertParticipants(Tenant tenant, UUID executionId, RuntimeExecution input, Instant evidenceTime) {
        UUID source = input.agentVersionArtifactId() != null ? input.agentVersionArtifactId() : input.agentArtifactId();
        if (source == null) return;
        jdbc.update("""
                insert into ai_agent_execution_participants (id,tenant_id,execution_id,artifact_id,participant_role,evidence_time)
                select gen_random_uuid(),:tenantId,:executionId,r.target_artifact_id,
                       case r.relationship_type when 'USES_MODEL' then 'MODEL' when 'USES_TOOL' then 'TOOL'
                            when 'USES_PROMPT' then 'PROMPT' else 'COMPONENT' end,:evidenceTime
                  from ai_security_relationships r
                 where r.source_artifact_id=:source and r.active=true
                   and r.relationship_type in ('USES_MODEL','USES_TOOL','USES_PROMPT','HAS_COMPONENT')
                on conflict (tenant_id,execution_id,artifact_id,participant_role) do nothing
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("executionId", executionId)
                .addValue("source", source).addValue("evidenceTime", Timestamp.from(evidenceTime)));
    }

    private void validate(RuntimeExecution input) {
        if (input == null || blank(input.provider()) || blank(input.providerExecutionId()) || blank(input.source())
                || blank(input.scopeKey()) || blank(input.status()) || input.evidenceTime() == null) {
            throw new IllegalArgumentException("Runtime execution requires provider, identifier, source, scope, status, and evidence time");
        }
        if (input.events() == null || input.events().size() > maxEvents) throw new IllegalArgumentException("Runtime event budget exceeded");
        if (input.events().stream().anyMatch(event -> event == null || event.eventTime() == null || blank(event.eventType()))) {
            throw new IllegalArgumentException("Runtime events require timestamp and type only");
        }
        if (estimatedBytes(input) > maxMetadataBytes) throw new IllegalArgumentException("Runtime metadata byte budget exceeded");
    }

    private static Timestamp timestamp(Instant value) { return value == null ? null : Timestamp.from(value); }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
    private static int estimatedBytes(RuntimeExecution value) {
        int bytes = safeLength(value.provider()) + safeLength(value.providerExecutionId()) + safeLength(value.source()) + safeLength(value.scopeKey())
                + safeLength(value.status()) + safeLength(value.outcomeCategory()) + safeLength(value.approvalState()) + safeLength(value.policyState())
                + safeLength(value.classification()) + safeLength(value.apiVersion());
        for (RuntimeEvent event : value.events()) bytes += safeLength(event.eventType()) + safeLength(event.status()) + safeLength(event.classification()) + 32;
        return bytes;
    }
    private static int safeLength(String value) { return value == null ? 0 : value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length; }

    public record RuntimeExecution(String provider, String providerExecutionId, UUID agentArtifactId, String source,
                                   String scopeKey, Instant startedAt, Instant completedAt, String status,
                                   String outcomeCategory, String approvalState, String policyState, String classification,
                                   String apiVersion, Long tokenCount, Long latencyMs, Integer retryCount, Long spendMicros,
                                   Instant evidenceTime, List<RuntimeEvent> events, UUID agentVersionArtifactId,
                                   String providerAgentReference, String providerAgentVersionReference,
                                   String correlationStatus, String correlationDiagnostic) { }
    public record RuntimeEvent(long sequence, Instant eventTime, String eventType, String status, String classification) { }
    public record Result(UUID executionId, boolean duplicate) { }
    public record AgentResolution(UUID agentArtifactId, UUID agentVersionArtifactId,
                                  String status, String diagnostic) { }
    public record CursorState(Instant timestamp, int lookbackDays, int overlapDays) { }
}
