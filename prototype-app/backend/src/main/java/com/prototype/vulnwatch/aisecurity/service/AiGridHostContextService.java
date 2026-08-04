package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Explicit integration ports for CIEM, DSPM, ASM, asset, and ownership evidence. */
@Service
public class AiGridHostContextService {
    private static final Set<String> PORTS = Set.of("IDENTITY", "DATA", "REACHABILITY", "ASSET", "OWNERSHIP");
    private static final Set<String> STATES = Set.of("KNOWN", "UNKNOWN", "ERROR", "STALE");
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public AiGridHostContextService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    public HostFact attest(Tenant tenant, UUID artifactId, AnalystFactInput input) {
        if (isValidating(input.factKey())) {
            throw new IllegalArgumentException("Analyst attestations cannot satisfy validating evidence");
        }
        return persist(tenant, artifactId, "ANALYST_ATTESTATION", new HostFactInput(input.factKey(), input.value(), input.state(),
                "ANALYST_ATTESTED", "CONFIGURATION", input.sourcePort(), input.evidenceReference(),
                input.observedAt(), input.validFrom(), input.validUntil(), "ANALYST_ATTESTATION", "1.0.0", null));
    }

    public HostFact ingestTrusted(Tenant tenant, UUID artifactId, String producerId, TrustedFactInput input) {
        Producer producer = PRODUCERS.get(producerId);
        if (producer == null || !producer.factKeys().contains(input.factKey()))
            throw new IllegalArgumentException("Producer is not authorized for this host-context fact");
        if (input.confidence() == null || input.confidence() < 0 || input.confidence() > 1)
            throw new IllegalArgumentException("Trusted validating evidence requires calibrated confidence");
        return persist(tenant, artifactId, producerId, new HostFactInput(input.factKey(), input.value(), input.state(),
                producer.provenance(), producer.evidenceClass(), producer.sourcePort(), input.evidenceReference(),
                input.observedAt(), input.validFrom(), input.validUntil(), producer.method(), producer.methodVersion(),
                input.confidence()));
    }

    private HostFact persist(Tenant tenant, UUID artifactId, String producerId, HostFactInput input) {
        if (!PORTS.contains(input.sourcePort())) throw new IllegalArgumentException("Invalid host-context port");
        if (!STATES.contains(input.state())) throw new IllegalArgumentException("Invalid host-context fact state");
        if (input.evidenceReference() == null || input.evidenceReference().isBlank())
            throw new IllegalArgumentException("Host-context evidence reference is required");
        Instant observedAt = input.observedAt() == null ? Instant.now() : input.observedAt();
        Instant validFrom = input.validFrom() == null ? observedAt : input.validFrom();
        if (input.validUntil() != null && input.validUntil().isBefore(validFrom))
            throw new IllegalArgumentException("Host-context validity interval is invalid");
        String valueType = valueType(input.value());
        Integer governed = jdbc.queryForObject("""
                select count(*) from platform.ai_grid_fact_definitions
                 where fact_key=:factKey and lifecycle='ACTIVE' and value_type=:valueType
                   and allowed_evidence_classes_json @> cast(:evidence as jsonb)
                """, new MapSqlParameterSource().addValue("factKey", input.factKey()).addValue("valueType", valueType)
                .addValue("evidence", jsonArray(input.evidenceClass())), Integer.class);
        if (governed == null || governed == 0)
            throw new IllegalArgumentException("Host-context fact or evidence class is not governed for this value type");
        if (isValidating(input.factKey())) {
            if (input.validUntil() == null) throw new IllegalArgumentException("Validating host-context evidence requires validUntil");
            if ("CONFIGURATION".equals(input.evidenceClass()))
                throw new IllegalArgumentException("Configuration proxy cannot satisfy validating evidence");
        }
        UUID id = jdbc.queryForObject("""
                insert into ai_grid_host_context_facts
                    (id,tenant_id,artifact_id,fact_key,value_type,value_json,state,provenance,evidence_class,
                     source_port,evidence_reference,observed_at,valid_from,valid_until,
                     confidence_method,confidence_method_version,confidence,producer_id)
                values (:id,:tenantId,:artifactId,:factKey,:valueType,cast(:value as jsonb),:state,:provenance,
                        :evidenceClass,:port,:reference,:observedAt,:validFrom,:validUntil,:method,:methodVersion,:confidence,
                        :producerId)
                on conflict (tenant_id,artifact_id,fact_key,source_port,observed_at) do update set
                    value_json=excluded.value_json,state=excluded.state,evidence_reference=excluded.evidence_reference,
                    valid_from=excluded.valid_from,valid_until=excluded.valid_until,confidence=excluded.confidence
                returning id
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("artifactId", artifactId).addValue("factKey", input.factKey())
                .addValue("valueType", valueType).addValue("value", json(input.value()))
                .addValue("state", input.state()).addValue("provenance", input.provenance())
                .addValue("evidenceClass", input.evidenceClass()).addValue("port", input.sourcePort())
                .addValue("reference", input.evidenceReference()).addValue("observedAt", Timestamp.from(observedAt))
                .addValue("validFrom", Timestamp.from(validFrom)).addValue("validUntil", input.validUntil() == null ? null : Timestamp.from(input.validUntil()))
                .addValue("method", input.confidenceMethod()).addValue("methodVersion", input.confidenceMethodVersion())
                .addValue("confidence", input.confidence()).addValue("producerId", producerId), UUID.class);
        return get(id);
    }

    private boolean isValidating(String factKey) {
        return factKey != null && (factKey.endsWith("_verified") || factKey.endsWith("_confirmed")
                || factKey.endsWith("_derived"));
    }

    private HostFact get(UUID id) {
        return jdbc.queryForObject("""
                select id,artifact_id,fact_key,value_json::text,state,provenance,evidence_class,source_port,
                       evidence_reference,observed_at,valid_from,valid_until,confidence_method,
                       confidence_method_version,confidence,producer_id
                  from ai_grid_host_context_facts where id=:id
                """, Map.of("id", id), (rs, n) -> new HostFact(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8),
                rs.getString(9), rs.getTimestamp(10).toInstant(), rs.getTimestamp(11).toInstant(),
                rs.getTimestamp(12) == null ? null : rs.getTimestamp(12).toInstant(), rs.getString(13),
                rs.getString(14), (Double) rs.getObject(15), rs.getString(16)));
    }

    private String valueType(JsonNode value) {
        if (value == null || value.isNull()) return "NULL";
        if (value.isBoolean()) return "BOOLEAN";
        if (value.isNumber()) return "NUMBER";
        if (value.isArray()) return "ARRAY";
        if (value.isObject()) return "OBJECT";
        return "STRING";
    }
    private String json(JsonNode value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid host-context value", e); }
    }
    private String jsonArray(String value) {
        try { return objectMapper.writeValueAsString(List.of(value)); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid evidence class", e); }
    }

    public record HostFactInput(String factKey, JsonNode value, String state, String provenance,
                                String evidenceClass, String sourcePort, String evidenceReference,
                                Instant observedAt, Instant validFrom, Instant validUntil,
                                String confidenceMethod, String confidenceMethodVersion, Double confidence) {}
    public record AnalystFactInput(String factKey, JsonNode value, String state, String sourcePort,
                                   String evidenceReference, Instant observedAt, Instant validFrom,
                                   Instant validUntil) {}
    public record TrustedFactInput(String factKey, JsonNode value, String state, String evidenceReference,
                                   Instant observedAt, Instant validFrom, Instant validUntil, Double confidence) {}
    public record HostFact(UUID id, UUID artifactId, String factKey, String valueJson, String state,
                           String provenance, String evidenceClass, String sourcePort, String evidenceReference,
                           Instant observedAt, Instant validFrom, Instant validUntil,
                           String confidenceMethod, String confidenceMethodVersion, Double confidence,
                           String producerId) {}

    private static final Map<String, Producer> PRODUCERS = Map.of(
            "SCOUT_REACHABILITY_GRAPH", new Producer("VERIFIED", "GRAPH_ANALYSIS", "REACHABILITY",
                    "SCOUT_REACHABILITY_GRAPH", "1.0.0", Set.of("network.internet_reachability_verified",
                    "identity.inadequate_authentication_verified")),
            "SCOUT_DATA_SECURITY", new Producer("CONFIRMED", "DSPM", "DATA",
                    "SCOUT_DATA_SECURITY", "1.0.0", Set.of("data.sensitive_access_confirmed")),
            "SCOUT_IDENTITY_GRAPH", new Producer("DERIVED", "GRAPH_ANALYSIS", "IDENTITY",
                    "SCOUT_IDENTITY_GRAPH", "1.0.0", Set.of("identity.effective_excessive_privilege_derived",
                    "impact.secret_or_consequential_access_confirmed")),
            "SCOUT_RUNTIME_CONTROL", new Producer("VERIFIED", "RUNTIME_OBSERVATION", "ASSET",
                    "SCOUT_RUNTIME_CONTROL", "1.0.0", Set.of("input.untrusted_path_verified",
                    "agent.autonomous_execution_verified", "control.execution_boundary_inadequate_verified"))
    );
    private record Producer(String provenance, String evidenceClass, String sourcePort, String method,
                            String methodVersion, Set<String> factKeys) {}
}
