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

    public HostFact upsert(Tenant tenant, UUID artifactId, HostFactInput input) {
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
        if (input.factKey().endsWith("_verified") || input.factKey().endsWith("_confirmed")
                || input.factKey().endsWith("_derived")) {
            if (input.validUntil() == null) throw new IllegalArgumentException("Validating host-context evidence requires validUntil");
            if ("CONFIGURATION".equals(input.evidenceClass()))
                throw new IllegalArgumentException("Configuration proxy cannot satisfy validating evidence");
        }
        UUID id = jdbc.queryForObject("""
                insert into ai_grid_host_context_facts
                    (id,tenant_id,artifact_id,fact_key,value_type,value_json,state,provenance,evidence_class,
                     source_port,evidence_reference,observed_at,valid_from,valid_until,
                     confidence_method,confidence_method_version,confidence)
                values (:id,:tenantId,:artifactId,:factKey,:valueType,cast(:value as jsonb),:state,:provenance,
                        :evidenceClass,:port,:reference,:observedAt,:validFrom,:validUntil,:method,:methodVersion,:confidence)
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
                .addValue("confidence", input.confidence()), UUID.class);
        return get(id);
    }

    private HostFact get(UUID id) {
        return jdbc.queryForObject("""
                select id,artifact_id,fact_key,value_json::text,state,provenance,evidence_class,source_port,
                       evidence_reference,observed_at,valid_from,valid_until,confidence_method,
                       confidence_method_version,confidence from ai_grid_host_context_facts where id=:id
                """, Map.of("id", id), (rs, n) -> new HostFact(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8),
                rs.getString(9), rs.getTimestamp(10).toInstant(), rs.getTimestamp(11).toInstant(),
                rs.getTimestamp(12) == null ? null : rs.getTimestamp(12).toInstant(), rs.getString(13),
                rs.getString(14), (Double) rs.getObject(15)));
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
    public record HostFact(UUID id, UUID artifactId, String factKey, String valueJson, String state,
                           String provenance, String evidenceClass, String sourcePort, String evidenceReference,
                           Instant observedAt, Instant validFrom, Instant validUntil,
                           String confidenceMethod, String confidenceMethodVersion, Double confidence) {}
}
