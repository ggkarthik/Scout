package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Comparator;
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
            MapSqlParameterSource parameters = new MapSqlParameterSource()
                    .addValue("tenantId", tenant.getId()).addValue("provider", provider)
                    .addValue("reference", agentReference);
            List<ArtifactMatch> candidates = matches("""
                    artifact_type='AI_AGENT'
                    and (provider_resource_id=:reference or attributes_json->>'agentId'=:reference)
                    """, parameters);
            if (candidates.size() > 1) return ambiguous();
            ArtifactMatch match = candidates.stream().findFirst().orElse(null);
            if (match == null) {
                candidates = matches("""
                    native_kind='AWS_BEDROCK_AGENT_ALIAS'
                    and (provider_resource_id=:reference or attributes_json->>'aliasId'=:reference)
                    """, parameters);
                if (candidates.size() > 1) return ambiguous();
                match = candidates.stream().findFirst().orElse(null);
            }
            if (match == null) {
                candidates = matches("artifact_type='AI_AGENT_VERSION' and provider_resource_id=:reference", parameters);
                if (candidates.size() > 1) return ambiguous();
                match = candidates.stream().findFirst().orElse(null);
            }
            if (match == null) {
                candidates = matches("artifact_type='AI_AGENT' and lower(name)=lower(:reference)", parameters);
                if (candidates.size() > 1) return ambiguous();
                match = candidates.stream().findFirst().orElse(null);
            }
            if (match == null) return new AgentResolution(
                    null, null, "UNRESOLVED", "AGENT_REFERENCE_NOT_FOUND");

            UUID agentId;
            UUID referencedVersion = null;
            boolean alias = "AWS_BEDROCK_AGENT_ALIAS".equals(match.nativeKind());
            if ("AI_AGENT_VERSION".equals(match.artifactType())) {
                agentId = relatedArtifact(match.id(), "VERSION_OF", false);
                referencedVersion = match.id();
            } else if (alias) {
                agentId = relatedArtifact(match.id(), "HAS_COMPONENT", true);
            } else {
                agentId = match.id();
            }
            if (agentId == null) return new AgentResolution(null, null, "UNRESOLVED",
                    alias ? "AGENT_ALIAS_PARENT_NOT_FOUND" : "AGENT_PARENT_NOT_FOUND");

            if (alias) {
                List<UUID> routed = routedVersions(match.id(), versionReference);
                if (routed.size() > 1 && blank(versionReference)) return new AgentResolution(
                        agentId, null, "MULTI_TARGET", "AGENT_ALIAS_MULTIPLE_TARGETS");
                if (routed.size() != 1) return new AgentResolution(agentId, null, "UNRESOLVED",
                        blank(versionReference) ? "AGENT_ALIAS_ROUTE_NOT_FOUND" : "AGENT_VERSION_REFERENCE_NOT_FOUND");
                return new AgentResolution(agentId, routed.get(0), "RESOLVED", null);
            }

            if (!blank(versionReference)) {
                List<UUID> versions = childVersions(agentId, versionReference);
                if (versions.size() != 1) return new AgentResolution(agentId, null, "RESOLVED",
                        "AGENT_VERSION_REFERENCE_NOT_FOUND");
                referencedVersion = versions.get(0);
            }
            return new AgentResolution(agentId, referencedVersion, "RESOLVED", null);
        });
    }

    private List<ArtifactMatch> matches(String predicate, MapSqlParameterSource parameters) {
        return jdbc.query("""
                select id,artifact_type,native_kind from ai_security_artifacts
                 where tenant_id=:tenantId and provider=:provider and active=true and
                """ + predicate + " limit 2", parameters, (rs, row) -> new ArtifactMatch(
                rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3)));
    }

    private AgentResolution ambiguous() {
        return new AgentResolution(null, null, "UNRESOLVED", "AGENT_REFERENCE_AMBIGUOUS");
    }

    private List<UUID> routedVersions(UUID aliasId, String versionReference) {
        return jdbc.query("""
                select v.id from ai_security_relationships r
                  join ai_security_artifacts v on v.id=r.target_artifact_id and v.active=true
                 where r.source_artifact_id=:aliasId and r.relationship_type='SERVES_VERSION' and r.active=true
                   and (:version is null or v.provider_resource_id=:version or v.attributes_json->>'version'=:version)
                 order by v.id limit 3
                """, new MapSqlParameterSource().addValue("aliasId", aliasId)
                .addValue("version", blank(versionReference) ? null : versionReference),
                (rs, row) -> rs.getObject(1, UUID.class));
    }

    private List<UUID> childVersions(UUID agentId, String versionReference) {
        return jdbc.query("""
                select v.id from ai_security_artifacts v
                  join ai_security_relationships r on r.source_artifact_id=v.id and r.target_artifact_id=:agentId
                   and r.relationship_type='VERSION_OF' and r.active=true
                 where v.active=true and (v.provider_resource_id=:version or v.attributes_json->>'version'=:version)
                 order by v.id limit 2
                """, new MapSqlParameterSource().addValue("agentId", agentId).addValue("version", versionReference),
                (rs, row) -> rs.getObject(1, UUID.class));
    }

    private UUID relatedArtifact(UUID artifactId, String relationshipType, boolean artifactIsTarget) {
        String sql = artifactIsTarget ? """
                select source_artifact_id from ai_security_relationships
                 where target_artifact_id=:id and relationship_type=:type and active=true limit 2
                """ : """
                select target_artifact_id from ai_security_relationships
                 where source_artifact_id=:id and relationship_type=:type and active=true limit 2
                """;
        List<UUID> values = jdbc.query(sql, Map.of("id", artifactId, "type", relationshipType),
                (rs, row) -> rs.getObject(1, UUID.class));
        return values.size() == 1 ? values.get(0) : null;
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
                .addValue("environmentDigest", digestValue(tenant, input.provider(), "environment", input.environmentReference()))
                .addValue("deploymentDigest", digestValue(tenant, input.provider(), "deployment", input.deploymentReference()))
                .addValue("actingIdentityDigest", digestValue(tenant, input.provider(), "acting-identity", input.actingIdentityReference()))
                .addValue("delegatedIdentityDigest", digestValue(tenant, input.provider(), "delegated-identity", input.delegatedIdentityReference()))
                .addValue("identityDigestKeyVersion", identityKeyVersion(tenant, input.provider(), input))
                .addValue("terminationReason", input.terminationReason()).addValue("evidenceSource", input.evidenceSource())
                .addValue("evidenceClass", input.evidenceClass()).addValue("evidenceConfidence", input.evidenceConfidence())
                .addValue("stepCount", input.stepCount()).addValue("spendCurrency", input.spendCurrency())
                .addValue("spendUnit", input.spendUnit()).addValue("collectedAt", timestamp(input.collectedAt()))
                .addValue("providerEventTime", timestamp(input.providerEventTime()))
                .addValue("deliveryLatencyMs", input.deliveryLatencyMs())
                .addValue("evidenceTime", Timestamp.from(input.evidenceTime()));
        jdbc.update("""
                insert into ai_agent_executions (id,tenant_id,provider,provider_execution_digest,digest_key_version,
                    agent_artifact_id,agent_version_artifact_id,provider_agent_digest,provider_agent_version_digest,
                    correlation_status,correlation_diagnostic,source,started_at,completed_at,status,outcome_category,approval_state,policy_state,
                    classification,api_version,token_count,latency_ms,retry_count,spend_micros,evidence_time,
                    environment_digest,deployment_digest,acting_identity_digest,delegated_identity_digest,
                    identity_digest_key_version,termination_reason,evidence_source,evidence_class,evidence_confidence,
                    step_count,spend_currency,spend_unit,collected_at,provider_event_time,delivery_latency_ms)
                values (:id,:tenantId,:provider,:executionDigest,:keyVersion,:agentId,
                    :agentVersionId,:providerAgentDigest,:providerAgentVersionDigest,:correlationStatus,:correlationDiagnostic,
                    :source,:startedAt,:completedAt,:status,:outcome,:approval,:policy,:classification,:apiVersion,:tokenCount,:latencyMs,:retryCount,
                    :spendMicros,:evidenceTime,:environmentDigest,:deploymentDigest,:actingIdentityDigest,
                    :delegatedIdentityDigest,:identityDigestKeyVersion,:terminationReason,:evidenceSource,:evidenceClass,
                    :evidenceConfidence,:stepCount,:spendCurrency,:spendUnit,:collectedAt,:providerEventTime,:deliveryLatencyMs)
                """, values);
        List<EventWrite> events = input.events().stream().map(event -> eventWrite(tenant, input, event))
                .sorted(Comparator.comparing(EventWrite::eventTime).thenComparingLong(EventWrite::sequence)
                        .thenComparing(EventWrite::providerEventDigest))
                .toList();
        for (EventWrite event : events) {
            jdbc.update("""
                    insert into ai_agent_execution_events (id,tenant_id,execution_id,sequence,event_time,event_type,status,
                        classification,evidence_time,producer_id,provider_event_digest,digest_key_version,action_category,
                        target_class,tool_digest,tool_version_digest,target_digest,action_correlation_digest,data_sensitivity,
                        data_operation,approval_state,policy_state,decision_reason,enforcement_point,action_outcome,evidence_class)
                    values (:id,:tenantId,:executionId,:sequence,:eventTime,:eventType,:status,:classification,:evidenceTime,
                        :producerId,:providerEventDigest,:digestKeyVersion,:actionCategory,:targetClass,:toolDigest,
                        :toolVersionDigest,:targetDigest,:actionCorrelationDigest,:dataSensitivity,:dataOperation,
                        :approvalState,:policyState,:decisionReason,:enforcementPoint,:actionOutcome,:evidenceClass)
                    on conflict (tenant_id,producer_id,provider_event_digest,digest_key_version)
                        where producer_id is not null and provider_event_digest is not null and digest_key_version is not null
                        do nothing
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("executionId", id).addValue("sequence", event.sequence())
                    .addValue("eventTime", Timestamp.from(event.eventTime())).addValue("eventType", event.eventType())
                    .addValue("status", event.status()).addValue("classification", event.classification())
                    .addValue("producerId", input.source()).addValue("providerEventDigest", event.providerEventDigest())
                    .addValue("digestKeyVersion", event.digestKeyVersion()).addValue("actionCategory", event.actionCategory())
                    .addValue("targetClass", event.targetClass()).addValue("toolDigest", event.toolDigest())
                    .addValue("toolVersionDigest", event.toolVersionDigest()).addValue("targetDigest", event.targetDigest())
                    .addValue("actionCorrelationDigest", event.actionCorrelationDigest())
                    .addValue("dataSensitivity", event.dataSensitivity()).addValue("dataOperation", event.dataOperation())
                    .addValue("approvalState", event.approvalState()).addValue("policyState", event.policyState())
                    .addValue("decisionReason", event.decisionReason()).addValue("enforcementPoint", event.enforcementPoint())
                    .addValue("actionOutcome", event.actionOutcome()).addValue("evidenceClass", event.evidenceClass())
                    .addValue("evidenceTime", Timestamp.from(input.evidenceTime())));
        }
        jdbc.update("update ai_agent_execution_receipts set execution_id=:executionId where tenant_id=:tenantId and idempotency_key=:key",
                new MapSqlParameterSource().addValue("executionId", id).addValue("tenantId", tenant.getId()).addValue("key", receipt.value()));
        insertParticipants(tenant, id, input, input.evidenceTime());
        if (connectorId != null) jdbc.update("""
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
                  join ai_security_artifacts participant on participant.id=r.target_artifact_id
                 where r.source_artifact_id=:source and r.active=true
                   and r.relationship_type in ('USES_MODEL','USES_TOOL','USES_PROMPT','HAS_COMPONENT')
                   and participant.native_kind <> 'AWS_BEDROCK_AGENT_ALIAS'
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
        validateState(input.approvalState(), "approvalState",
                java.util.Set.of("APPROVED", "DENIED", "REQUIRED", "NOT_REQUIRED", "BYPASSED", "UNKNOWN"));
        validateState(input.policyState(), "policyState",
                java.util.Set.of("ALLOWED", "DENIED", "BLOCKED", "NOT_EVALUATED", "UNKNOWN"));
        if (input.evidenceConfidence() != null
                && (input.evidenceConfidence() < 0 || input.evidenceConfidence() > 1)) {
            throw new IllegalArgumentException("evidenceConfidence must be between zero and one");
        }
        for (RuntimeEvent event : input.events()) {
            if (blank(event.providerEventReference())) {
                throw new IllegalArgumentException("Runtime event requires providerEventReference");
            }
            validateState(event.actionCategory(), "actionCategory", java.util.Set.of(
                    "READ", "WRITE", "DELETE", "SEND", "EXECUTE", "ADMIN", "PAYMENT", "PUBLISH", "OTHER"));
            validateState(event.targetClass(), "targetClass", java.util.Set.of(
                    "INTERNAL", "EXTERNAL", "PUBLIC", "SENSITIVE_STORE", "CODE_RUNTIME", "IDENTITY_SYSTEM",
                    "FINANCIAL_SYSTEM", "UNKNOWN"));
            validateState(event.approvalState(), "event.approvalState",
                    java.util.Set.of("APPROVED", "DENIED", "REQUIRED", "NOT_REQUIRED", "BYPASSED", "UNKNOWN"));
            validateState(event.policyState(), "event.policyState",
                    java.util.Set.of("ALLOWED", "DENIED", "BLOCKED", "NOT_EVALUATED", "UNKNOWN"));
            validateState(event.actionOutcome(), "actionOutcome",
                    java.util.Set.of("SUCCEEDED", "FAILED", "DENIED", "BLOCKED", "CANCELLED", "UNKNOWN"));
            validateState(event.dataSensitivity(), "dataSensitivity",
                    java.util.Set.of("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"));
            validateState(event.dataOperation(), "dataOperation",
                    java.util.Set.of("READ", "WRITE", "DELETE", "TRANSFORM", "TRANSMIT", "NONE", "UNKNOWN"));
            requireMaximumLength(event.decisionReason(), "decisionReason", 512);
            requireMaximumLength(event.enforcementPoint(), "enforcementPoint", 128);
            requireMaximumLength(event.evidenceClass(), "event.evidenceClass", 64);
        }
        if (estimatedBytes(input) > maxMetadataBytes) throw new IllegalArgumentException("Runtime metadata byte budget exceeded");
    }

    private EventWrite eventWrite(Tenant tenant, RuntimeExecution execution, RuntimeEvent event) {
        AiSecurityDigestService.Digest providerEvent = digests.identityDigest(tenant,
                "provider-event:" + execution.provider() + ":" + execution.source(), event.providerEventReference());
        return new EventWrite(event.sequence(), event.eventTime(), event.eventType(), event.status(), event.classification(),
                providerEvent.value(), providerEvent.keyVersion(), event.actionCategory(), event.targetClass(),
                digestValue(tenant, execution.provider(), "tool", event.toolReference()),
                digestValue(tenant, execution.provider(), "tool-version", event.toolVersionReference()),
                digestValue(tenant, execution.provider(), "target", event.targetReference()),
                digestValue(tenant, execution.provider(), "action-correlation", event.actionCorrelationReference()),
                event.dataSensitivity(), event.dataOperation(), event.approvalState(), event.policyState(),
                event.decisionReason(), event.enforcementPoint(), event.actionOutcome(), event.evidenceClass());
    }

    private String digestValue(Tenant tenant, String provider, String family, String value) {
        return blank(value) ? null : digests.identityDigest(tenant, "runtime-" + family + ":" + provider, value).value();
    }

    private String identityKeyVersion(Tenant tenant, String provider, RuntimeExecution input) {
        if (!blank(input.actingIdentityReference())) {
            return digests.identityDigest(tenant, "runtime-acting-identity:" + provider,
                    input.actingIdentityReference()).keyVersion();
        }
        return blank(input.delegatedIdentityReference()) ? null
                : digests.identityDigest(tenant, "runtime-delegated-identity:" + provider,
                        input.delegatedIdentityReference()).keyVersion();
    }

    private static void validateState(String value, String field, java.util.Set<String> allowed) {
        if (value != null && (!value.equals(value.toUpperCase(java.util.Locale.ROOT)) || !allowed.contains(value))) {
            throw new IllegalArgumentException(field + " must use the governed runtime state vocabulary");
        }
    }

    private static void requireMaximumLength(String value, String field, int maximum) {
        if (value != null && value.length() > maximum) {
            throw new IllegalArgumentException(field + " exceeds the governed runtime length limit");
        }
    }

    private static Timestamp timestamp(Instant value) { return value == null ? null : Timestamp.from(value); }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
    private static int estimatedBytes(RuntimeExecution value) {
        int bytes = safeLength(value.provider()) + safeLength(value.providerExecutionId()) + safeLength(value.source()) + safeLength(value.scopeKey())
                + safeLength(value.status()) + safeLength(value.outcomeCategory()) + safeLength(value.approvalState()) + safeLength(value.policyState())
                + safeLength(value.classification()) + safeLength(value.apiVersion()) + safeLength(value.environmentReference())
                + safeLength(value.deploymentReference()) + safeLength(value.actingIdentityReference())
                + safeLength(value.delegatedIdentityReference()) + safeLength(value.terminationReason())
                + safeLength(value.evidenceSource()) + safeLength(value.evidenceClass());
        for (RuntimeEvent event : value.events()) {
            bytes += safeLength(event.eventType()) + safeLength(event.status()) + safeLength(event.classification())
                    + safeLength(event.providerEventReference()) + safeLength(event.actionCategory())
                    + safeLength(event.targetClass()) + safeLength(event.toolReference())
                    + safeLength(event.toolVersionReference()) + safeLength(event.targetReference())
                    + safeLength(event.actionCorrelationReference()) + safeLength(event.dataSensitivity())
                    + safeLength(event.dataOperation()) + safeLength(event.approvalState())
                    + safeLength(event.policyState()) + safeLength(event.decisionReason())
                    + safeLength(event.enforcementPoint()) + safeLength(event.actionOutcome())
                    + safeLength(event.evidenceClass()) + 32;
        }
        return bytes;
    }
    private static int safeLength(String value) { return value == null ? 0 : value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length; }

    public record RuntimeExecution(String provider, String providerExecutionId, UUID agentArtifactId, String source,
                                   String scopeKey, Instant startedAt, Instant completedAt, String status,
                                   String outcomeCategory, String approvalState, String policyState, String classification,
                                   String apiVersion, Long tokenCount, Long latencyMs, Integer retryCount, Long spendMicros,
                                   Instant evidenceTime, List<RuntimeEvent> events, UUID agentVersionArtifactId,
                                   String providerAgentReference, String providerAgentVersionReference,
                                   String correlationStatus, String correlationDiagnostic,
                                   String environmentReference, String deploymentReference,
                                   String actingIdentityReference, String delegatedIdentityReference,
                                   String terminationReason, String evidenceSource, String evidenceClass,
                                   Double evidenceConfidence, Long stepCount, String spendCurrency, String spendUnit,
                                   Instant collectedAt, Instant providerEventTime, Long deliveryLatencyMs) {
        public RuntimeExecution(String provider, String providerExecutionId, UUID agentArtifactId, String source,
                                String scopeKey, Instant startedAt, Instant completedAt, String status,
                                String outcomeCategory, String approvalState, String policyState, String classification,
                                String apiVersion, Long tokenCount, Long latencyMs, Integer retryCount, Long spendMicros,
                                Instant evidenceTime, List<RuntimeEvent> events, UUID agentVersionArtifactId,
                                String providerAgentReference, String providerAgentVersionReference,
                                String correlationStatus, String correlationDiagnostic) {
            this(provider, providerExecutionId, agentArtifactId, source, scopeKey, startedAt, completedAt, status,
                    outcomeCategory, approvalState, policyState, classification, apiVersion, tokenCount, latencyMs,
                    retryCount, spendMicros, evidenceTime, events, agentVersionArtifactId, providerAgentReference,
                    providerAgentVersionReference, correlationStatus, correlationDiagnostic, null, null, null, null,
                    null, null, null, null, null, null, null, null, null, null);
        }
    }
    public record RuntimeEvent(long sequence, Instant eventTime, String eventType, String status, String classification,
                               String providerEventReference, String actionCategory, String targetClass,
                               String toolReference, String toolVersionReference, String targetReference,
                               String actionCorrelationReference, String dataSensitivity, String dataOperation,
                               String approvalState, String policyState, String decisionReason,
                               String enforcementPoint, String actionOutcome, String evidenceClass) { }
    public record Result(UUID executionId, boolean duplicate) { }
    public record AgentResolution(UUID agentArtifactId, UUID agentVersionArtifactId,
                                  String status, String diagnostic) { }
    private record ArtifactMatch(UUID id, String artifactType, String nativeKind) { }
    private record EventWrite(long sequence, Instant eventTime, String eventType, String status, String classification,
                              String providerEventDigest, String digestKeyVersion, String actionCategory,
                              String targetClass, String toolDigest, String toolVersionDigest, String targetDigest,
                              String actionCorrelationDigest, String dataSensitivity, String dataOperation,
                              String approvalState, String policyState, String decisionReason,
                              String enforcementPoint, String actionOutcome, String evidenceClass) { }
    public record CursorState(Instant timestamp, int lookbackDays, int overlapDays) { }
}
