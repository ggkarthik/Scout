package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
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
    private static final String RULE_METHOD = "OWNERSHIP_RULE";
    private static final String RULE_METHOD_VERSION = "1.0.0";
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
                select distinct a.id, a.attributes_json::text, a.owner_name, a.owner_state,
                       a.provider, a.region, a.artifact_type, a.environment,
                       a.business_criticality, a.active
                  from ai_security_artifacts a
                  join ai_security_artifact_sources s on s.artifact_id = a.id and s.run_id = :runId
                 where a.active = true
                """, Map.of("runId", runId), (rs, n) -> mapArtifactOwner(rs));
        for (ArtifactOwner artifact : artifacts) {
            if ("CONFIRMED".equals(artifact.state())) {
                resolveGap(tenant, artifact.id());
                continue;
            }
            RuleOwner inferred = ruleOwner(artifact);
            if (inferred != null) {
                update(tenant, artifact, inferred.owner(), "INFERRED", "OWNERSHIP_RULE:" + inferred.ruleId(),
                        RULE_METHOD, RULE_METHOD_VERSION, 0.80, "ai-grid-owner-resolver",
                        "Approved ownership rule inferred the accountable owner");
                resolveGap(tenant, artifact.id());
                continue;
            }
            TagOwner candidate = tagOwner(artifact.attributes());
            if (candidate == null) {
                update(tenant, artifact, null, "UNOWNED", "NO_OWNER_SIGNAL", null, null, null,
                        "ai-grid-owner-resolver", "No supported owner tag was observed");
                upsertGap(tenant, runId, artifact.id(), "UNOWNED",
                        "No authoritative or candidate owner signal is available");
            } else {
                update(tenant, artifact, candidate.value(), "CANDIDATE", "RESOURCE_TAG:" + candidate.key(),
                        TAG_METHOD, TAG_METHOD_VERSION, null, "ai-grid-owner-resolver",
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
                select id, attributes_json::text, owner_name, owner_state, provider, region,
                       artifact_type, environment, business_criticality, active
                  from ai_security_artifacts where id = :id and tenant_id = :tenantId and active = true
                """, Map.of("id", artifactId, "tenantId", tenant.getId()), (rs, n) -> mapArtifactOwner(rs));
        if (current.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI artifact not found");
        update(tenant, current.get(0), ownerName.trim(), "CONFIRMED", "MANUAL_CONFIRMATION", null, null,
                1.0, actor, reason == null || reason.isBlank() ? "Owner confirmed by authorized user" : reason.trim());
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
                        String method, String methodVersion, Double confidence, String actor, String reason) {
        if (java.util.Objects.equals(previous.ownerName(), ownerName) && state.equals(previous.state())) return;
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("artifactId", previous.id())
                .addValue("tenantId", tenant.getId()).addValue("ownerName", ownerName).addValue("state", state)
                .addValue("source", source).addValue("method", method).addValue("methodVersion", methodVersion)
                .addValue("confidence", confidence)
                .addValue("previousOwner", previous.ownerName()).addValue("previousState", previous.state())
                .addValue("actor", actor).addValue("reason", reason).addValue("historyId", UUID.randomUUID());
        jdbc.update("""
                update ai_security_artifacts set owner_name = :ownerName, owner_state = :state,
                    owner_source = :source, owner_confidence = :confidence, owner_confidence_method = :method,
                    owner_confidence_method_version = :methodVersion, owner_updated_at = now()
                 where id = :artifactId and tenant_id = :tenantId
                """, params);
        jdbc.update("""
                insert into ai_grid_owner_history (id, tenant_id, artifact_id, previous_owner_name,
                    previous_owner_state, owner_name, owner_state, owner_source, confidence,
                    confidence_method, confidence_method_version, actor, reason)
                values (:historyId, :tenantId, :artifactId, :previousOwner, :previousState, :ownerName,
                    :state, :source, :confidence, :method, :methodVersion, :actor, :reason)
                """, params);
    }

    private RuleOwner ruleOwner(ArtifactOwner artifact) {
        Map<String, String> values = artifactValues(artifact);
        return jdbc.query("""
                select id, condition_json::text, user_group
                  from ownership_rules
                 order by execution_order, created_at, id
                """, (rs, n) -> new OwnershipRule(rs.getObject("id", UUID.class),
                rs.getString("condition_json"), rs.getString("user_group"))).stream()
                .filter(rule -> matchesRule(rule.conditionJson(), values))
                .map(rule -> new RuleOwner(rule.id(), rule.userGroup()))
                .findFirst().orElse(null);
    }

    private Map<String, String> artifactValues(ArtifactOwner artifact) {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("ASSET.businessCriticality", artifact.businessCriticality());
        values.put("ASSET.environment", artifact.environment());
        values.put("ASSET.assetType", artifact.artifactType());
        values.put("ASSET.status", artifact.active() ? "ACTIVE" : "INACTIVE");
        values.put("ASSET.region", artifact.region());
        values.put("ASSET.cloudProvider", artifact.provider());
        return values;
    }

    private boolean matchesRule(String conditionJson, Map<String, String> values) {
        try {
            JsonNode root = objectMapper.readTree(conditionJson == null ? "{}" : conditionJson);
            JsonNode conditions = root.path("conditions");
            if (!conditions.isArray() || conditions.isEmpty()) return false;
            boolean and = !"OR".equalsIgnoreCase(root.path("logic").asText("AND"));
            boolean matchedAny = false;
            for (JsonNode condition : conditions) {
                String table = condition.path("table").asText("");
                String column = condition.path("column").asText("");
                String operator = condition.path("operator").asText("");
                String expected = condition.path("value").asText("");
                String actual = values.get(table + "." + column);
                if (actual == null || operator.isBlank() || expected.isBlank()) {
                    if (and) return false;
                    continue;
                }
                matchedAny = true;
                boolean match = switch (operator.toLowerCase(Locale.ROOT)) {
                    case "is", "exact match", "=" -> actual.equalsIgnoreCase(expected);
                    case "is not", "!=" -> !actual.equalsIgnoreCase(expected);
                    case "contains" -> actual.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT));
                    case "not contains" -> !actual.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT));
                    default -> false;
                };
                if (and && !match) return false;
                if (!and && match) return true;
            }
            return and && matchedAny;
        } catch (Exception ignored) {
            return false;
        }
    }

    private TagOwner tagOwner(String attributes) {
        try {
            JsonNode tags = objectMapper.readTree(attributes == null ? "{}" : attributes).path("tags");
            if (!tags.isObject()) return null;
            Map<String, Map.Entry<String, JsonNode>> normalizedTags = new LinkedHashMap<>();
            tags.fields().forEachRemaining(field -> normalizedTags.putIfAbsent(
                    field.getKey().replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT), field));
            for (String preferred : OWNER_TAGS) {
                Map.Entry<String, JsonNode> field = normalizedTags.get(preferred);
                if (field == null) continue;
                String value = field.getValue().asText("").trim();
                if (!value.isBlank()) return new TagOwner(field.getKey(), value);
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

    private ArtifactOwner mapArtifactOwner(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new ArtifactOwner(rs.getObject("id", UUID.class), rs.getString("attributes_json"),
                rs.getString("owner_name"), rs.getString("owner_state"), rs.getString("provider"),
                rs.getString("region"), rs.getString("artifact_type"), rs.getString("environment"),
                rs.getString("business_criticality"), rs.getBoolean("active"));
    }

    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("Unable to fingerprint ownership gap", e); }
    }

    private record ArtifactOwner(UUID id, String attributes, String ownerName, String state,
                                 String provider, String region, String artifactType,
                                 String environment, String businessCriticality, boolean active) {}
    private record OwnershipRule(UUID id, String conditionJson, String userGroup) {}
    private record RuleOwner(UUID ruleId, String owner) {}
    private record TagOwner(String key, String value) {}
    public record OwnerView(UUID artifactId, String ownerName, String ownerState, String ownerSource,
                            Double confidence, String confidenceMethod, String confidenceMethodVersion) {}
}
