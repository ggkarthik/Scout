package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.Diagnostic;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.IngestionResult;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class AiSecurityObservationService {

    public static final String CONTRACT_VERSION = "1.0";
    private static final Set<String> RELATIONSHIP_TYPES = Set.of(
            "USES_MODEL", "USES_GUARDRAIL", "USES_KNOWLEDGE_BASE", "USES_DATA_SOURCE",
            "BACKED_BY_DATA_STORE", "USES_SEARCH_INDEX", "EXPOSES_MCP", "CONNECTS_TO_MCP",
            "CONTAINS_MCP_TARGET", "ROUTES_TO", "INVOKES_LAMBDA", "ASSUMES_ROLE", "READS_FROM_S3", "LOGS_TO", "SUPERVISES_AGENT",
            "CONTAINS_PROJECT", "DEPLOYS_MODEL", "USES_TOOL",
            "USES_MANAGED_IDENTITY", "HAS_PRIVATE_ENDPOINT", "USES_KEY_VAULT_KEY",
            "CONTAINS_RESOURCE", "HAS_DEPLOYMENT", "RUNS_PIPELINE", "HAS_CHANNEL",
            "HAS_ROLE_ASSIGNMENT", "CONTAINS", "USES_EXECUTION_ROLE", "USES_NETWORK",
            "USES_ENDPOINT_CONFIGURATION", "PRODUCES_MODEL", "USES_DATA_CONNECTION",
            "READS_FROM_STORAGE_ACCOUNT");

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactionTemplate;
    private final AiSecuritySyncRunFacade syncRunFacade;
    private final AiSecurityMetadataSanitizer metadataSanitizer;
    private AiGridPipelineService aiGridPipelineService;
    private AiGridCapabilityService aiGridCapabilityService;

    public AiSecurityObservationService(
            NamedParameterJdbcTemplate jdbc,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactionTemplate,
            AiSecuritySyncRunFacade syncRunFacade,
            AiSecurityMetadataSanitizer metadataSanitizer
    ) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.tenantExecution = tenantExecution;
        this.transactionTemplate = transactionTemplate;
        this.syncRunFacade = syncRunFacade;
        this.metadataSanitizer = metadataSanitizer;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAiGridPipelineService(AiGridPipelineService aiGridPipelineService) {
        this.aiGridPipelineService = aiGridPipelineService;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAiGridCapabilityService(AiGridCapabilityService aiGridCapabilityService) {
        this.aiGridCapabilityService = aiGridCapabilityService;
    }

    public IngestionResult ingest(Tenant tenant, ObservationEnvelopeV1 envelope) {
        validate(tenant, envelope);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> ingestCurrentTenant(tenant, envelope)));
    }

    public int countPersistedArtifacts(Tenant tenant, UUID runId) {
        syncRunFacade.loadForTenant(tenant.getId(), runId);
        return tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(distinct artifact_id)
                  from ai_security_artifact_sources
                 where run_id = :runId
                """, Map.of("runId", runId), Integer.class));
    }

    private IngestionResult ingestCurrentTenant(Tenant tenant, ObservationEnvelopeV1 envelope) {
        validateCurrentTenantOwnership(tenant, envelope);
        MapSqlParameterSource receipt = new MapSqlParameterSource()
                .addValue("id", UUID.randomUUID())
                .addValue("tenantId", tenant.getId())
                .addValue("runId", envelope.runId())
                .addValue("scopeKey", envelope.scopeKey())
                .addValue("sequence", envelope.chunkSequence())
                .addValue("idempotencyKey", envelope.idempotencyKey())
                .addValue("contentHash", envelope.contentHash());
        int inserted = jdbc.update("""
                insert into ai_security_observation_receipts (
                    id, tenant_id, run_id, scope_key, chunk_sequence, idempotency_key, content_hash
                ) values (
                    :id, :tenantId, :runId, :scopeKey, :sequence, :idempotencyKey, :contentHash
                ) on conflict do nothing
                """, receipt);
        if (inserted == 0) {
            ReceiptRow existing = loadConflictingReceipt(envelope);
            if (existing == null
                    || !existing.runId().equals(envelope.runId())
                    || !existing.scopeKey().equals(envelope.scopeKey())
                    || existing.chunkSequence() != envelope.chunkSequence()
                    || !existing.idempotencyKey().equals(envelope.idempotencyKey())
                    || !existing.contentHash().equals(envelope.contentHash())) {
                throw new IllegalArgumentException(
                        "AI Security observation replay conflicts with an accepted chunk");
            }
            ScopeRow scope = loadScope(envelope.runId(), envelope.scopeKey());
            return new IngestionResult(true, scope.status(), scope.acceptedChunks(), scope.expectedChunks(), diagnostics(envelope));
        }

        upsertScope(tenant, envelope);
        Map<String, UUID> artifactIds = new HashMap<>();
        List<Diagnostic> metadataDiagnostics = new ArrayList<>();
        for (ArtifactObservation artifact : safe(envelope.artifacts())) {
            AiSecurityMetadataSanitizer.Result sanitized = metadataSanitizer.sanitize(
                    envelope.provider(), artifact.nativeKind(), artifact.attributes());
            if (!sanitized.rejectedFieldNames().isEmpty()) {
                metadataDiagnostics.add(metadataDiagnostic(envelope, sanitized.rejectedFieldNames()));
            }
            UUID artifactId = upsertArtifact(tenant, envelope, artifact, sanitized.attributes());
            artifactIds.put(artifact.providerResourceId(), artifactId);
            upsertSource(tenant, envelope, artifact, artifactId);
        }

        List<Diagnostic> combinedDiagnostics = new ArrayList<>(diagnostics(envelope));
        combinedDiagnostics.addAll(metadataDiagnostics.stream().limit(1).toList());
        boolean unknownRelationship = false;
        for (RelationshipObservation relationship : safe(envelope.relationships())) {
            if (!RELATIONSHIP_TYPES.contains(relationship.relationshipType())) {
                unknownRelationship = true;
                combinedDiagnostics.add(new Diagnostic(
                        "UNKNOWN_RELATIONSHIP_TYPE",
                        "Relationship type is not present in ObservationEnvelopeV1 catalogue",
                        false,
                        List.of(),
                        envelope.runId().toString()));
                continue;
            }
            UUID sourceId = resolveArtifactId(tenant, artifactIds, relationship.sourceProviderResourceId());
            UUID targetId = resolveArtifactId(tenant, artifactIds, relationship.targetProviderResourceId());
            if (sourceId != null && targetId != null) {
                upsertRelationship(tenant, envelope, relationship, sourceId, targetId);
            }
        }

        int accepted = acceptedChunks(envelope.runId(), envelope.scopeKey());
        ScopeStatus finalStatus = ScopeStatus.PARTIAL;
        if (accepted >= envelope.expectedChunks()) {
            finalStatus = unknownRelationship || envelope.completionStatus() == null
                    ? ScopeStatus.PARTIAL
                    : envelope.completionStatus();
            finishScope(envelope, finalStatus, accepted, combinedDiagnostics);
            if (aiGridCapabilityService != null) aiGridCapabilityService.recordScope(tenant, envelope, finalStatus);
            if (finalStatus == ScopeStatus.COMPLETE) {
                reconcileCompleteScope(envelope);
                if (aiGridPipelineService != null) {
                    aiGridPipelineService.processCompleteScope(tenant, envelope);
                }
            }
        } else {
            updateAcceptedChunks(envelope, accepted);
        }
        return new IngestionResult(false, finalStatus, accepted, envelope.expectedChunks(), combinedDiagnostics);
    }

    private void validate(Tenant tenant, ObservationEnvelopeV1 envelope) {
        if (envelope == null || !CONTRACT_VERSION.equals(envelope.contractVersion())) {
            throw new IllegalArgumentException("Unsupported AI Security observation contract version");
        }
        if (tenant.getId() == null || !tenant.getId().equals(envelope.tenantId())) {
            throw new IllegalArgumentException("Observation tenant does not match claimed tenant");
        }
        if (envelope.runId() == null || envelope.connectorId() == null
                || blank(envelope.provider()) || blank(envelope.accountId()) || blank(envelope.region())
                || blank(envelope.resourceFamily()) || blank(envelope.scopeKey()) || blank(envelope.idempotencyKey())
                || blank(envelope.contentHash()) || envelope.chunkSequence() < 0 || envelope.expectedChunks() < 1
                || envelope.chunkSequence() >= envelope.expectedChunks()) {
            throw new IllegalArgumentException("Invalid AI Security observation envelope");
        }
        if ("AZURE".equalsIgnoreCase(envelope.provider()) && blank(envelope.providerTenantId())) {
            throw new IllegalArgumentException("Azure observation provider tenant assertion is required");
        }
    }

    void validateCurrentTenantOwnership(Tenant tenant, ObservationEnvelopeV1 envelope) {
        syncRunFacade.loadForTenant(tenant.getId(), envelope.runId());
        List<String> connectors = jdbc.query("""
                select provider_tenant_id
                  from ai_security_connector_configs
                 where id = :connectorId
                   and tenant_id = :tenantId
                   and provider = :provider
                   and account_id = :accountId
                """, new MapSqlParameterSource()
                .addValue("connectorId", envelope.connectorId())
                .addValue("tenantId", tenant.getId())
                .addValue("provider", envelope.provider())
                .addValue("accountId", envelope.accountId()),
                (rs, rowNum) -> rs.getString("provider_tenant_id"));
        if (connectors.size() != 1) {
            throw new IllegalArgumentException(
                    "Observation connector does not belong to the claimed tenant and account");
        }
        if ("AZURE".equalsIgnoreCase(envelope.provider())) {
            String configuredProviderTenant = connectors.get(0);
            if (blank(configuredProviderTenant)
                    || !configuredProviderTenant.equalsIgnoreCase(envelope.providerTenantId())) {
                throw new IllegalArgumentException(
                        "Azure observation provider tenant does not match the connector");
            }
        }
    }

    private ReceiptRow loadConflictingReceipt(ObservationEnvelopeV1 envelope) {
        List<ReceiptRow> rows = jdbc.query("""
                select run_id, scope_key, chunk_sequence, idempotency_key, content_hash
                  from ai_security_observation_receipts
                 where (run_id = :runId and scope_key = :scopeKey and chunk_sequence = :sequence)
                    or idempotency_key = :idempotencyKey
                 limit 2
                """, new MapSqlParameterSource()
                .addValue("runId", envelope.runId())
                .addValue("scopeKey", envelope.scopeKey())
                .addValue("sequence", envelope.chunkSequence())
                .addValue("idempotencyKey", envelope.idempotencyKey()), (rs, rowNum) -> new ReceiptRow(
                rs.getObject("run_id", UUID.class),
                rs.getString("scope_key"),
                rs.getInt("chunk_sequence"),
                rs.getString("idempotency_key"),
                rs.getString("content_hash")));
        return rows.size() == 1 ? rows.get(0) : null;
    }

    private void upsertScope(Tenant tenant, ObservationEnvelopeV1 envelope) {
        MapSqlParameterSource params = base(envelope)
                .addValue("id", UUID.randomUUID())
                .addValue("tenantId", tenant.getId())
                .addValue("startedAt", timestamp(envelope.observedAt()));
        jdbc.update("""
                insert into ai_security_snapshot_scopes (
                    id, tenant_id, run_id, provider, account_id, region, resource_family, scope_key,
                    status, expected_chunks, accepted_chunks, started_at
                ) values (
                    :id, :tenantId, :runId, :provider, :accountId, :region, :resourceFamily, :scopeKey,
                    'PARTIAL', :expectedChunks, 0, :startedAt
                ) on conflict (tenant_id, run_id, scope_key) do update
                    set expected_chunks = excluded.expected_chunks
                """, params);
    }

    private UUID upsertArtifact(Tenant tenant, ObservationEnvelopeV1 envelope, ArtifactObservation artifact,
                                Map<String, Object> attributes) {
        UUID id = UUID.randomUUID();
        MapSqlParameterSource params = base(envelope)
                .addValue("id", id)
                .addValue("tenantId", tenant.getId())
                .addValue("providerResourceId", artifact.providerResourceId())
                .addValue("artifactType", artifact.artifactType())
                .addValue("nativeKind", artifact.nativeKind())
                .addValue("name", artifact.name())
                .addValue("attributes", json(attributes))
                .addValue("piiScanStatus", artifact.piiScanStatus())
                .addValue("piiSource", artifact.piiSource())
                .addValue("piiInfoTypes", json(artifact.piiInfoTypes()))
                .addValue("piiFindingCount", artifact.piiFindingCount())
                .addValue("piiLastScannedAt", artifact.piiLastScannedAt() == null ? null : timestamp(artifact.piiLastScannedAt()))
                .addValue("observedAt", timestamp(envelope.observedAt()));
        return jdbc.queryForObject("""
                insert into ai_security_artifacts (
                    id, tenant_id, provider, provider_resource_id, artifact_type, native_kind, name,
                    account_id, region, active, attributes_json, first_observed_at, last_observed_at,
                    pii_scan_status, pii_source, pii_info_types, pii_finding_count, pii_last_scanned_at
                ) values (
                    :id, :tenantId, :provider, :providerResourceId, :artifactType, :nativeKind, :name,
                    :accountId, :region, true, cast(:attributes as jsonb), :observedAt, :observedAt,
                    :piiScanStatus, :piiSource, cast(:piiInfoTypes as jsonb), :piiFindingCount, :piiLastScannedAt
                ) on conflict (tenant_id, provider, provider_resource_id) do update
                    set artifact_type = excluded.artifact_type,
                        native_kind = excluded.native_kind,
                        name = excluded.name,
                        account_id = excluded.account_id,
                        region = case
                            when excluded.region = 'GLOBAL' and ai_security_artifacts.region <> 'GLOBAL'
                                then ai_security_artifacts.region
                            else excluded.region
                        end,
                        active = true,
                        attributes_json = ai_security_artifacts.attributes_json || excluded.attributes_json,
                        last_observed_at = excluded.last_observed_at,
                        deactivated_at = null,
                        pii_scan_status = excluded.pii_scan_status,
                        pii_source = excluded.pii_source,
                        pii_info_types = excluded.pii_info_types,
                        pii_finding_count = excluded.pii_finding_count,
                        pii_last_scanned_at = excluded.pii_last_scanned_at
                returning id
                """, params, UUID.class);
    }

    private void upsertSource(
            Tenant tenant, ObservationEnvelopeV1 envelope, ArtifactObservation artifact, UUID artifactId) {
        MapSqlParameterSource params = base(envelope)
                .addValue("id", UUID.randomUUID())
                .addValue("tenantId", tenant.getId())
                .addValue("artifactId", artifactId)
                .addValue("connectorId", envelope.connectorId())
                .addValue("observedAt", timestamp(envelope.observedAt()))
                .addValue("evidenceHash", sha256(envelope.contentHash() + ":" + artifact.providerResourceId()));
        jdbc.update("""
                insert into ai_security_artifact_sources (
                    id, tenant_id, artifact_id, connector_config_id, scope_key, run_id, observed_at, evidence_hash
                ) values (
                    :id, :tenantId, :artifactId, :connectorId, :scopeKey, :runId, :observedAt, :evidenceHash
                ) on conflict (tenant_id, artifact_id, scope_key) do update
                    set connector_config_id = excluded.connector_config_id,
                        run_id = excluded.run_id,
                        observed_at = excluded.observed_at,
                        evidence_hash = excluded.evidence_hash
                """, params);
    }

    private String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to hash AI Security evidence", exception);
        }
    }

    private void upsertRelationship(
            Tenant tenant,
            ObservationEnvelopeV1 envelope,
            RelationshipObservation relationship,
            UUID sourceId,
            UUID targetId
    ) {
        MapSqlParameterSource params = base(envelope)
                .addValue("id", UUID.randomUUID())
                .addValue("tenantId", tenant.getId())
                .addValue("sourceId", sourceId)
                .addValue("targetId", targetId)
                .addValue("type", relationship.relationshipType())
                .addValue("attributes", json(safeRelationshipAttributes(relationship, envelope)))
                .addValue("observedAt", timestamp(envelope.observedAt()));
        jdbc.update("""
                insert into ai_security_relationships (
                    id, tenant_id, source_artifact_id, target_artifact_id, relationship_type,
                    attributes_json, scope_key, run_id, active, first_observed_at, last_observed_at
                ) values (
                    :id, :tenantId, :sourceId, :targetId, :type,
                    cast(:attributes as jsonb), :scopeKey, :runId, true, :observedAt, :observedAt
                ) on conflict (tenant_id, source_artifact_id, target_artifact_id, relationship_type) do update
                    set attributes_json = excluded.attributes_json,
                        scope_key = excluded.scope_key,
                        run_id = excluded.run_id,
                        active = true,
                        last_observed_at = excluded.last_observed_at
                """, params);
    }

    /** Relationships may span independently collected scopes; resolve already-persisted endpoints safely. */
    private UUID resolveArtifactId(Tenant tenant, Map<String, UUID> currentArtifacts, String providerResourceId) {
        UUID current = currentArtifacts.get(providerResourceId);
        if (current != null) return current;
        List<UUID> persisted = jdbc.query("""
                select id from ai_security_artifacts
                 where tenant_id = :tenantId and provider_resource_id = :providerResourceId and active = true
                 limit 1
                """, Map.of("tenantId", tenant.getId(), "providerResourceId", providerResourceId),
                (rs, rowNum) -> rs.getObject("id", UUID.class));
        return persisted.isEmpty() ? null : persisted.get(0);
    }

    /** Adds non-sensitive provenance while allowing collectors to provide a precise API field reference. */
    private Map<String, Object> safeRelationshipAttributes(
            RelationshipObservation relationship, ObservationEnvelopeV1 envelope) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        if (relationship.attributes() != null) attributes.putAll(relationship.attributes());
        attributes.putIfAbsent("confidence", "DIRECT");
        attributes.putIfAbsent("evidence", Map.of("scopeKey", envelope.scopeKey()));
        return attributes;
    }

    private void reconcileCompleteScope(ObservationEnvelopeV1 envelope) {
        Map<String, Object> params = Map.of("runId", envelope.runId(), "scopeKey", envelope.scopeKey());
        jdbc.update("""
                update ai_security_artifacts a
                   set active = false, deactivated_at = now()
                 where a.active = true
                   and exists (
                       select 1 from ai_security_artifact_sources s
                        where s.artifact_id = a.id
                          and s.scope_key = :scopeKey
                          and s.run_id <> :runId
                   )
                   and not exists (
                       select 1 from ai_security_artifact_sources current_source
                        where current_source.artifact_id = a.id
                          and current_source.scope_key = :scopeKey
                          and current_source.run_id = :runId
                   )
                """, params);
        jdbc.update("""
                update ai_security_relationships
                   set active = false
                 where active = true
                   and scope_key = :scopeKey
                   and run_id <> :runId
                """, params);
    }

    private void finishScope(
            ObservationEnvelopeV1 envelope, ScopeStatus status, int accepted, List<Diagnostic> diagnostics) {
        MapSqlParameterSource params = base(envelope)
                .addValue("status", status.name())
                .addValue("accepted", accepted)
                .addValue("diagnosticCode", diagnostics.isEmpty() ? null : diagnostics.get(0).code())
                .addValue("diagnostics", json(Map.of("items", diagnostics)));
        jdbc.update("""
                update ai_security_snapshot_scopes
                   set status = :status,
                       accepted_chunks = :accepted,
                       diagnostic_code = :diagnosticCode,
                       diagnostic_json = cast(:diagnostics as jsonb),
                       completed_at = now()
                 where run_id = :runId and scope_key = :scopeKey
                """, params);
    }

    private void updateAcceptedChunks(ObservationEnvelopeV1 envelope, int accepted) {
        jdbc.update("""
                update ai_security_snapshot_scopes
                   set accepted_chunks = :accepted
                 where run_id = :runId and scope_key = :scopeKey
                """, Map.of("accepted", accepted, "runId", envelope.runId(), "scopeKey", envelope.scopeKey()));
    }

    private int acceptedChunks(UUID runId, String scopeKey) {
        Integer count = jdbc.queryForObject("""
                select count(*) from ai_security_observation_receipts
                 where run_id = :runId and scope_key = :scopeKey
                """, Map.of("runId", runId, "scopeKey", scopeKey), Integer.class);
        return count == null ? 0 : count;
    }

    private ScopeRow loadScope(UUID runId, String scopeKey) {
        return jdbc.queryForObject("""
                select status, accepted_chunks, expected_chunks
                  from ai_security_snapshot_scopes
                 where run_id = :runId and scope_key = :scopeKey
                """, Map.of("runId", runId, "scopeKey", scopeKey),
                (rs, rowNum) -> new ScopeRow(
                        ScopeStatus.valueOf(rs.getString("status")),
                        rs.getInt("accepted_chunks"),
                        rs.getInt("expected_chunks")));
    }

    private MapSqlParameterSource base(ObservationEnvelopeV1 envelope) {
        return new MapSqlParameterSource()
                .addValue("runId", envelope.runId())
                .addValue("provider", envelope.provider())
                .addValue("accountId", envelope.accountId())
                .addValue("region", envelope.region())
                .addValue("resourceFamily", envelope.resourceFamily())
                .addValue("scopeKey", envelope.scopeKey())
                .addValue("expectedChunks", envelope.expectedChunks());
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        } catch (Exception ex) {
            throw new IllegalArgumentException("AI Security observation contains invalid JSON data", ex);
        }
    }

    private Timestamp timestamp(Instant instant) {
        return Timestamp.from(instant == null ? Instant.now() : instant);
    }

    private List<Diagnostic> diagnostics(ObservationEnvelopeV1 envelope) {
        return envelope.diagnostics() == null ? List.of() : envelope.diagnostics();
    }

    private Diagnostic metadataDiagnostic(ObservationEnvelopeV1 envelope, List<String> fields) {
        List<String> bounded = fields.stream().sorted().limit(20).toList();
        return new Diagnostic("AI_METADATA_FIELDS_DROPPED",
                "Discarded " + fields.size() + " invalid metadata fields: " + String.join(",", bounded),
                false, List.of(), envelope.scopeKey());
    }

    private <T> List<T> safe(List<T> values) {
        return values == null ? List.of() : values;
    }

    private boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private record ScopeRow(ScopeStatus status, int acceptedChunks, int expectedChunks) {
    }

    private record ReceiptRow(
            UUID runId,
            String scopeKey,
            int chunkSequence,
            String idempotencyKey,
            String contentHash
    ) {
    }

}
