package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Resolves explicit owner states without promoting provider tags to authoritative ownership. */
@Service
public class AiGridOwnershipService {
    private static final String TAG_METHOD = "RESOURCE_TAG_OWNER_CANDIDATE";
    private static final String TAG_METHOD_VERSION = "1.0.0";
    private static final List<String> OWNER_TAGS = List.of(
            "owner", "ownedby", "owneremail", "team", "applicationowner", "businessowner");

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public AiGridOwnershipService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    public void resolveRun(Tenant tenant, UUID runId) {
        List<ArtifactOwner> artifacts = jdbc.query("""
                select distinct a.id, a.attributes_json::text, a.owner_name, a.owner_state
                  from ai_security_artifacts a
                  join ai_security_artifact_sources s on s.artifact_id = a.id and s.run_id = :runId
                 where a.active = true
                """, Map.of("runId", runId), (rs, n) -> new ArtifactOwner(rs.getObject("id", UUID.class),
                rs.getString("attributes_json"), rs.getString("owner_name"), rs.getString("owner_state")));
        for (ArtifactOwner artifact : artifacts) {
            if ("CONFIRMED".equals(artifact.state())) {
                resolveGap(tenant, artifact.id());
                continue;
            }
            TagOwner candidate = tagOwner(artifact.attributes());
            if (candidate == null) {
                update(tenant, artifact, null, "UNOWNED", "NO_OWNER_SIGNAL", null, null,
                        "ai-grid-owner-resolver", "No supported owner tag was observed");
                upsertGap(tenant, runId, artifact.id(), "UNOWNED",
                        "No authoritative or candidate owner signal is available");
            } else {
                update(tenant, artifact, candidate.value(), "CANDIDATE", "RESOURCE_TAG:" + candidate.key(),
                        TAG_METHOD, TAG_METHOD_VERSION, "ai-grid-owner-resolver",
                        "Provider tag produced a non-authoritative owner candidate");
                upsertGap(tenant, runId, artifact.id(), "CANDIDATE",
                        "Resource tag suggests an owner but requires confirmation");
            }
        }
    }

    public OwnerView confirm(Tenant tenant, UUID artifactId, String ownerName, String actor, String reason) {
        if (ownerName == null || ownerName.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ownerName is required");
        }
        List<ArtifactOwner> current = jdbc.query("""
                select id, attributes_json::text, owner_name, owner_state
                  from ai_security_artifacts where id = :id and tenant_id = :tenantId and active = true
                """, Map.of("id", artifactId, "tenantId", tenant.getId()), (rs, n) -> new ArtifactOwner(
                rs.getObject("id", UUID.class), rs.getString("attributes_json"), rs.getString("owner_name"),
                rs.getString("owner_state")));
        if (current.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI artifact not found");
        update(tenant, current.get(0), ownerName.trim(), "CONFIRMED", "MANUAL_CONFIRMATION", null, null,
                actor, reason == null || reason.isBlank() ? "Owner confirmed by authorized user" : reason.trim());
        resolveGap(tenant, artifactId);
        jdbc.update("""
                update findings f set owner_group = :owner, updated_at = now()
                 where f.tenant_id = :tenantId and exists (
                     select 1 from finding_subjects s where s.finding_id = f.id
                       and s.subject_type = 'ARTIFACT' and s.subject_id = :artifactId)
                """, Map.of("owner", ownerName.trim(), "tenantId", tenant.getId(), "artifactId", artifactId));
        return new OwnerView(artifactId, ownerName.trim(), "CONFIRMED", "MANUAL_CONFIRMATION", null, null, null);
    }

    private void update(Tenant tenant, ArtifactOwner previous, String ownerName, String state, String source,
                        String method, String methodVersion, String actor, String reason) {
        if (java.util.Objects.equals(previous.ownerName(), ownerName) && state.equals(previous.state())) return;
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("artifactId", previous.id())
                .addValue("tenantId", tenant.getId()).addValue("ownerName", ownerName).addValue("state", state)
                .addValue("source", source).addValue("method", method).addValue("methodVersion", methodVersion)
                .addValue("previousOwner", previous.ownerName()).addValue("previousState", previous.state())
                .addValue("actor", actor).addValue("reason", reason).addValue("historyId", UUID.randomUUID());
        jdbc.update("""
                update ai_security_artifacts set owner_name = :ownerName, owner_state = :state,
                    owner_source = :source, owner_confidence = null, owner_confidence_method = :method,
                    owner_confidence_method_version = :methodVersion, owner_updated_at = now()
                 where id = :artifactId and tenant_id = :tenantId
                """, params);
        jdbc.update("""
                insert into ai_grid_owner_history (id, tenant_id, artifact_id, previous_owner_name,
                    previous_owner_state, owner_name, owner_state, owner_source, confidence,
                    confidence_method, confidence_method_version, actor, reason)
                values (:historyId, :tenantId, :artifactId, :previousOwner, :previousState, :ownerName,
                    :state, :source, null, :method, :methodVersion, :actor, :reason)
                """, params);
    }

    private TagOwner tagOwner(String attributes) {
        try {
            JsonNode tags = objectMapper.readTree(attributes == null ? "{}" : attributes).path("tags");
            if (!tags.isObject()) return null;
            Iterator<Map.Entry<String, JsonNode>> fields = tags.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String normalized = field.getKey().replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
                String value = field.getValue().asText("").trim();
                if (OWNER_TAGS.contains(normalized) && !value.isBlank()) return new TagOwner(field.getKey(), value);
            }
            return null;
        } catch (Exception exception) {
            return null;
        }
    }

    private void upsertGap(Tenant tenant, UUID runId, UUID artifactId, String ownerState, String reason) {
        String fingerprint = sha256(tenant.getId() + "|" + artifactId + "|UNRESOLVED_OWNER");
        jdbc.update("""
                insert into ai_grid_coverage_gaps (id, tenant_id, fingerprint, run_id, artifact_id,
                    state, reason, required_action)
                values (:id, :tenantId, :fingerprint, :runId, :artifactId, 'UNRESOLVED_OWNER', :reason,
                    'Confirm an accountable owner or add an approved ownership mapping')
                on conflict (tenant_id, fingerprint) do update set run_id = excluded.run_id,
                    reason = excluded.reason, status = 'OPEN', last_observed_at = now(), resolved_at = null
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("fingerprint", fingerprint).addValue("runId", runId).addValue("artifactId", artifactId)
                .addValue("reason", ownerState + ": " + reason));
    }

    private void resolveGap(Tenant tenant, UUID artifactId) {
        jdbc.update("""
                update ai_grid_coverage_gaps set status = 'RESOLVED', resolved_at = now(), last_observed_at = now()
                 where tenant_id = :tenantId and artifact_id = :artifactId
                   and state = 'UNRESOLVED_OWNER' and status = 'OPEN'
                """, Map.of("tenantId", tenant.getId(), "artifactId", artifactId));
    }

    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("Unable to fingerprint ownership gap", e); }
    }

    private record ArtifactOwner(UUID id, String attributes, String ownerName, String state) {}
    private record TagOwner(String key, String value) {}
    public record OwnerView(UUID artifactId, String ownerName, String ownerState, String ownerSource,
                            Double confidence, String confidenceMethod, String confidenceMethodVersion) {}
}
