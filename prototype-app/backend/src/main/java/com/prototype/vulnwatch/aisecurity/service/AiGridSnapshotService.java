package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AiGridSnapshotService {

    private static final String SNAPSHOT_SCHEMA_VERSION = "1.0.0";
    private static final String FACT_SCHEMA_VERSION = "1.0.0";
    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "secret", "clientsecret", "password", "passwd", "token", "accesstoken", "refreshtoken",
            "credential", "credentials", "apikey", "accesskey", "secretkey", "privatekey",
            "prompt", "rawprompt", "inputtext", "outputtext", "completion");
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper canonicalMapper;
    private final List<AiGridFactProducer> factProducers;

    public AiGridSnapshotService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        this(jdbc, objectMapper, List.of(new AwsAiGridFactProducer(), new AzureAiGridFactProducer(),
                new CommonAiGridFactProducer(objectMapper)));
    }

    @Autowired
    public AiGridSnapshotService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                 List<AiGridFactProducer> factProducers) {
        this.jdbc = jdbc;
        this.canonicalMapper = objectMapper.copy().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        this.factProducers = List.copyOf(factProducers);
    }

    public List<SnapshotArtifact> commitScope(Tenant tenant, ObservationEnvelopeV1 envelope) {
        List<ArtifactRow> rows = jdbc.query("""
                select a.id, a.provider, a.provider_resource_id, a.artifact_type, a.native_kind,
                       a.name, a.account_id, a.region, a.attributes_json::text, a.pii_scan_status, a.pii_source
                  from ai_security_artifacts a
                  join ai_security_artifact_sources s on s.artifact_id = a.id
                 where s.run_id = :runId and s.scope_key = :scopeKey and a.active = true
                """, Map.of("runId", envelope.runId(), "scopeKey", envelope.scopeKey()),
                (rs, n) -> new ArtifactRow(rs.getObject("id", UUID.class), rs.getString("provider"),
                        rs.getString("provider_resource_id"), rs.getString("artifact_type"),
                        rs.getString("native_kind"), rs.getString("name"), rs.getString("account_id"),
                        rs.getString("region"), readTree(rs.getString("attributes_json")), rs.getString("pii_scan_status"),
                        rs.getString("pii_source")));
        List<SnapshotArtifact> committed = new ArrayList<>();
        for (ArtifactRow row : rows) {
            JsonNode safeAttributes = redactAttributes(row.attributes());
            Map<String, Object> snapshot = new LinkedHashMap<>();
            snapshot.put("provider", row.provider());
            snapshot.put("providerResourceId", row.providerResourceId());
            snapshot.put("artifactType", row.artifactType());
            snapshot.put("nativeKind", row.nativeKind());
            snapshot.put("name", row.name());
            snapshot.put("accountId", row.accountId());
            snapshot.put("region", row.region());
            snapshot.put("attributes", safeAttributes);
            String content = json(snapshot);
            String hash = sha256(content);
            UUID bodyId = jdbc.queryForObject("""
                    insert into ai_grid_snapshot_bodies
                        (id, tenant_id, content_hash, content_json, byte_size, redaction_profile, first_run_id,
                         retention_class, retain_until)
                    values (:id, :tenantId, :hash, cast(:content as jsonb), :bytes, 'STANDARD_V1', :runId,
                            'HOT', now() + (coalesce((select retain_days from ai_grid_retention_policies
                                                     where retention_class = 'HOT'), 90) * interval '1 day'))
                    on conflict (tenant_id, content_hash) do update set content_hash = excluded.content_hash
                    returning id
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId()).addValue("hash", hash).addValue("content", content)
                    .addValue("bytes", content.getBytes(StandardCharsets.UTF_8).length)
                    .addValue("runId", envelope.runId()), UUID.class);
            UUID manifestId = jdbc.queryForObject("""
                    insert into ai_grid_snapshot_manifests
                        (id, tenant_id, run_id, artifact_id, scope_key, body_id, schema_version, observed_at,
                         connector_config_id)
                    values (:id, :tenantId, :runId, :artifactId, :scopeKey, :bodyId, :version, :observedAt,
                            :connectorId)
                    on conflict (tenant_id, run_id, artifact_id, scope_key)
                    do update set body_id = ai_grid_snapshot_manifests.body_id
                    returning id
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId()).addValue("runId", envelope.runId())
                    .addValue("artifactId", row.id()).addValue("scopeKey", envelope.scopeKey())
                    .addValue("bodyId", bodyId).addValue("version", SNAPSHOT_SCHEMA_VERSION)
                    .addValue("connectorId", envelope.connectorId())
                    .addValue("observedAt", Timestamp.from(envelope.observedAt() == null ? Instant.now() : envelope.observedAt())), UUID.class);
            Map<String, AiGridFactProducer.ProducedFact> producedFacts = produceFacts(envelope, row, safeAttributes);
            Map<String, JsonNode> facts = new LinkedHashMap<>();
            for (AiGridFactProducer.ProducedFact fact : producedFacts.values()) {
                if (fact.value() != null) facts.put(fact.factKey(), fact.value());
                persistFact(tenant, envelope, row, manifestId, fact);
            }
            classify(tenant, row);
            outbox(tenant, "SNAPSHOT_COMMITTED", "ARTIFACT", row.id(), hash,
                    Map.of("manifestId", manifestId, "runId", envelope.runId()));
            committed.add(new SnapshotArtifact(row.id(), manifestId, facts));
        }
        commitRelationships(tenant, envelope);
        return committed;
    }

    private void commitRelationships(Tenant tenant, ObservationEnvelopeV1 envelope) {
        jdbc.update("""
                insert into ai_grid_relationship_snapshots
                    (id, tenant_id, run_id, source_artifact_id, target_artifact_id,
                     relationship_type, attributes_json, observed_at, valid_from)
                select gen_random_uuid(), :tenantId, :runId, source_artifact_id, target_artifact_id,
                       relationship_type, attributes_json, last_observed_at, last_observed_at
                  from ai_security_relationships
                 where run_id = :runId and scope_key = :scopeKey
                on conflict (tenant_id, run_id, source_artifact_id, target_artifact_id, relationship_type)
                do nothing
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId())
                .addValue("runId", envelope.runId()).addValue("scopeKey", envelope.scopeKey()));
        jdbc.update("""
                insert into ai_grid_facts
                    (id, tenant_id, run_id, artifact_id, snapshot_manifest_id, fact_key, value_type,
                     value_json, state, provenance, evidence_class, source, observed_at, confidence,
                     confidence_method, confidence_method_version, derivation_inputs_json, fact_schema_version)
                select gen_random_uuid(), :tenantId, :runId, r.source_artifact_id, m.id,
                       'data.source_linked', 'BOOLEAN', 'true'::jsonb, 'KNOWN', 'DERIVED',
                       'RELATIONSHIP_GRAPH', 'ai-grid-minimum-context-pack', max(r.observed_at), 1.0,
                       'DIRECT_PROVIDER_RELATIONSHIP', '1.0.0', jsonb_agg(r.id order by r.id), '1.0.0'
                  from ai_grid_relationship_snapshots r
                  join lateral (
                      select id from ai_grid_snapshot_manifests m
                       where m.run_id = r.run_id and m.artifact_id = r.source_artifact_id
                       order by m.observed_at desc, m.id limit 1
                  ) m on true
                 where r.run_id = :runId
                   and r.relationship_type in
                       ('USES_DATA_SOURCE','READS_FROM_S3','USES_KNOWLEDGE_BASE','USES_SEARCH_INDEX')
                 group by r.source_artifact_id, m.id
                on conflict (tenant_id, run_id, artifact_id, fact_key) do update set
                    value_json = excluded.value_json, state = excluded.state,
                    snapshot_manifest_id = excluded.snapshot_manifest_id,
                    observed_at = excluded.observed_at,
                    derivation_inputs_json = excluded.derivation_inputs_json
                """, Map.of("tenantId", tenant.getId(), "runId", envelope.runId()));
    }

    JsonNode redactAttributes(JsonNode source) {
        if (source == null || source.isNull()) return canonicalMapper.createObjectNode();
        if (source.isObject()) {
            ObjectNode safe = canonicalMapper.createObjectNode();
            source.fields().forEachRemaining(entry -> {
                if (!isSensitiveKey(entry.getKey())) {
                    safe.set(entry.getKey(), redactAttributes(entry.getValue()));
                }
            });
            return safe;
        }
        if (source.isArray()) {
            ArrayNode safe = canonicalMapper.createArrayNode();
            source.forEach(value -> safe.add(redactAttributes(value)));
            return safe;
        }
        return source.deepCopy();
    }

    private boolean isSensitiveKey(String key) {
        String normalized = key == null ? "" : key.replaceAll("[^A-Za-z0-9]", "").toLowerCase();
        return SENSITIVE_KEYS.contains(normalized)
                || normalized.endsWith("password")
                || normalized.endsWith("secret")
                || normalized.endsWith("token")
                || normalized.endsWith("apikey")
                || normalized.endsWith("privatekey");
    }

    /** Compatibility view for callers that only need normalized KNOWN values. */
    Map<String, JsonNode> normalize(JsonNode attributes, String artifactType, String piiScanStatus, String piiSource) {
        Map<String, JsonNode> facts = new LinkedHashMap<>();
        for (String provider : List.of("AWS", "AZURE")) {
            for (AiGridFactProducer producer : factProducers) {
                producer.produce(new AiGridFactProducer.FactInput(provider, "LEGACY", artifactType, null,
                        attributes, piiScanStatus, piiSource, Instant.now())).forEach(fact -> {
                    if (fact.value() != null) facts.putIfAbsent(fact.factKey(), fact.value());
                });
            }
        }
        return facts;
    }

    private Map<String, AiGridFactProducer.ProducedFact> produceFacts(ObservationEnvelopeV1 envelope,
                                                                        ArtifactRow row, JsonNode attributes) {
        Map<String, AiGridFactProducer.ProducedFact> facts = new LinkedHashMap<>();
        AiGridFactProducer.FactInput input = new AiGridFactProducer.FactInput(envelope.provider(),
                envelope.resourceFamily(), row.artifactType(), row.nativeKind(), attributes, row.piiScanStatus(),
                row.piiSource(), envelope.observedAt() == null ? Instant.now() : envelope.observedAt());
        for (AiGridFactProducer producer : factProducers) {
            for (AiGridFactProducer.ProducedFact fact : producer.produce(input)) {
                if (facts.putIfAbsent(fact.factKey(), fact) != null) {
                    throw new IllegalStateException("More than one AI Grid fact producer emitted " + fact.factKey());
                }
            }
        }
        return facts;
    }

    private void persistFact(Tenant tenant, ObservationEnvelopeV1 envelope, ArtifactRow row,
                             UUID manifestId, AiGridFactProducer.ProducedFact fact) {
        JsonNode value = fact.value();
        String valueType = value == null ? "UNKNOWN" : value.isBoolean() ? "BOOLEAN"
                : value.isNumber() ? "NUMBER" : value.isObject() ? "OBJECT"
                : value.isArray() ? "ARRAY" : "STRING";
        jdbc.update("""
                insert into ai_grid_facts (id, tenant_id, run_id, artifact_id, snapshot_manifest_id,
                    fact_key, value_type, value_json, state, provenance, evidence_class, source,
                    observed_at, valid_until, confidence, confidence_method, confidence_method_version,
                    derivation_inputs_json, fact_schema_version)
                values (:id, :tenantId, :runId, :artifactId, :manifestId, :factKey, :valueType,
                    cast(:value as jsonb), :state, :provenance, :evidenceClass, :source,
                    :observedAt, :validUntil, :confidence, :confidenceMethod, :confidenceMethodVersion,
                    cast(:derivationInputs as jsonb), :schemaVersion)
                on conflict (tenant_id, run_id, artifact_id, fact_key) do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("runId", envelope.runId()).addValue("artifactId", row.id()).addValue("manifestId", manifestId)
                .addValue("factKey", fact.factKey()).addValue("valueType", valueType)
                .addValue("value", value == null ? null : value.toString()).addValue("state", fact.state())
                .addValue("provenance", fact.provenance()).addValue("evidenceClass", fact.evidenceClass())
                .addValue("source", row.provider() + ":" + envelope.resourceFamily() + ":" + fact.sourceAttribute())
                .addValue("observedAt", Timestamp.from(envelope.observedAt() == null ? Instant.now() : envelope.observedAt()))
                .addValue("validUntil", Timestamp.from((envelope.observedAt() == null ? Instant.now() : envelope.observedAt()).plusSeconds(86400)))
                .addValue("confidence", fact.confidence()).addValue("confidenceMethod", fact.confidenceMethod())
                .addValue("confidenceMethodVersion", fact.confidenceMethodVersion())
                .addValue("derivationInputs", json(fact.derivationInputs()))
                .addValue("schemaVersion", fact.schemaVersion() == null ? FACT_SCHEMA_VERSION : fact.schemaVersion()));
    }

    private void classify(Tenant tenant, ArtifactRow row) {
        String technology = technology(row.provider(), row.nativeKind());
        String classificationState = "UNMAPPED_AI_TECHNOLOGY".equals(technology) ? "UNMAPPED" : "CLASSIFIED";
        jdbc.update("""
                insert into ai_grid_artifact_classifications
                    (id, tenant_id, artifact_id, technology_id, capability, primary_technology, state,
                     registry_version, evidence_json)
                values (:id, :tenantId, :artifactId, :technology, :capability, true, :classificationState, '1.0.0',
                        cast(:evidence as jsonb))
                on conflict (tenant_id, artifact_id, technology_id, capability) do update
                    set state = excluded.state, registry_version = excluded.registry_version,
                        evidence_json = excluded.evidence_json, classified_at = now()
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("artifactId", row.id()).addValue("technology", technology)
                .addValue("classificationState", classificationState)
                .addValue("capability", row.artifactType()).addValue("evidence", json(Map.of(
                        "provider", row.provider(), "nativeKind", row.nativeKind()))));
    }

    private String technology(String provider, String nativeKind) {
        if ("AWS".equalsIgnoreCase(provider)) return "AWS_BEDROCK";
        String kind = nativeKind == null ? "" : nativeKind;
        if (kind.startsWith("AZURE_AI_") || kind.startsWith("AZURE_RAI_")
                || "AZURE_DIAGNOSTIC_SETTINGS".equals(kind)) return "AZURE_AI_SERVICES";
        if (kind.startsWith("AZURE_FOUNDRY_")) return "AZURE_AI_FOUNDRY";
        if (kind.startsWith("AZURE_ML_")) return "AZURE_MACHINE_LEARNING";
        if (kind.startsWith("AZURE_SEARCH_")) return "AZURE_AI_SEARCH";
        if (kind.startsWith("AZURE_BOT_")) return "AZURE_BOT_SERVICE";
        return "UNMAPPED_AI_TECHNOLOGY";
    }

    void outbox(Tenant tenant, String type, String aggregateType, UUID aggregateId, String version, Object payload) {
        jdbc.update("""
                insert into ai_grid_outbox (id, tenant_id, event_type, aggregate_type, aggregate_id,
                    aggregate_version, payload_json)
                values (:id, :tenantId, :type, :aggregateType, :aggregateId, :version, cast(:payload as jsonb))
                on conflict do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("type", type).addValue("aggregateType", aggregateType).addValue("aggregateId", aggregateId)
                .addValue("version", version).addValue("payload", json(payload)));
    }

    private JsonNode readTree(String value) {
        try { return canonicalMapper.readTree(value == null ? "{}" : value); }
        catch (JsonProcessingException e) { throw new IllegalArgumentException("Invalid artifact JSON", e); }
    }
    private String json(Object value) {
        try { return canonicalMapper.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new IllegalArgumentException("Unable to serialize AI Grid evidence", e); }
    }
    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("Unable to hash AI Grid evidence", e); }
    }

    public record SnapshotArtifact(UUID artifactId, UUID manifestId, Map<String, JsonNode> facts) {}
    private record ArtifactRow(UUID id, String provider, String providerResourceId, String artifactType,
                               String nativeKind, String name, String accountId, String region, JsonNode attributes,
                               String piiScanStatus, String piiSource) {}
}
