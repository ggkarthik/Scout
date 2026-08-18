package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.policy.AiGridPredicateEngine;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Platform-only import and distribution boundary for reviewed policy packages. */
@Service
public class AiGridPolicyCatalogService {
    private static final List<String> SELECTIONS = List.of("REQUIRED", "ENABLED", "PREVIEW", "DISABLED");
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final AiGridPredicateEngine predicates;
    private final AuditEventService audit;

    public AiGridPolicyCatalogService(NamedParameterJdbcTemplate jdbc, ObjectMapper mapper,
                                      AiGridPredicateEngine predicates, AuditEventService audit) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.predicates = predicates;
        this.audit = audit;
    }

    public PolicyVersion importDraft(PolicyPackageCommand command, String actor) {
        return TenantContext.runAsPlatform(() -> {
            require(command.policyId(), "policyId"); require(command.version(), "version");
            require(command.name(), "name"); require(command.description(), "description");
            require(command.severity(), "severity"); require(command.workflowClass(), "workflowClass");
            require(command.defaultSelection(), "defaultSelection"); require(command.artifactTypesJson(), "artifactTypesJson");
            require(command.requiredResourceFamiliesJson(), "requiredResourceFamiliesJson"); require(command.requiredFactsJson(), "requiredFactsJson");
            require(command.predicateJson(), "predicateJson"); require(command.reasonCode(), "reasonCode");
            require(command.remediation(), "remediation"); require(command.frameworkMappingsJson(), "frameworkMappingsJson");
            require(command.packageSourceRef(), "packageSourceRef");
            if (!List.of("CRITICAL", "HIGH", "MEDIUM", "LOW").contains(command.severity())) bad("Invalid severity");
            if (!List.of("POSTURE_FINDING", "EXPOSURE_HYPOTHESIS", "VALIDATED_EXPOSURE").contains(command.workflowClass())) bad("Invalid workflowClass");
            if (!SELECTIONS.contains(command.defaultSelection())) bad("Invalid defaultSelection");
            JsonNode facts = tree(command.requiredFactsJson(), "requiredFactsJson");
            JsonNode predicate = tree(command.predicateJson(), "predicateJson");
            JsonNode artifactTypes = tree(command.artifactTypesJson(), "artifactTypesJson");
            JsonNode families = tree(command.requiredResourceFamiliesJson(), "requiredResourceFamiliesJson");
            JsonNode mappings = tree(command.frameworkMappingsJson(), "frameworkMappingsJson");
            JsonNode parameterDefinitions = tree(defaultArray(command.parameterDefinitionsJson()), "parameterDefinitionsJson");
            if (!facts.isArray() || !artifactTypes.isArray() || !families.isArray() || !mappings.isObject()) bad("Invalid policy package shape");
            validateParameterDefinitions(parameterDefinitions, predicate);
            predicates.validate(predicate);
            facts.forEach(fact -> {
                String key = fact.path("factKey").asText();
                if (key.isBlank() || jdbc.queryForObject("select count(*) from platform.ai_grid_fact_definitions where fact_key=:key and lifecycle='ACTIVE'", Map.of("key", key), Integer.class) == 0) {
                    bad("Unknown or inactive fact: " + key);
                }
            });
            String digest = digest(command.digestMaterial());
            Integer existing = jdbc.queryForObject("select count(*) from platform.ai_grid_policy_versions where policy_id=:id and version=:version", Map.of("id", command.policyId(), "version", command.version()), Integer.class);
            if (existing != null && existing > 0) conflict("Policy version already exists and is immutable");
            jdbc.update("""
                    insert into platform.ai_grid_policy_versions
                    (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,
                     artifact_types_json,native_kinds_json,required_capabilities_json,required_relationships_json,
                     required_resource_families_json,required_facts_json,predicate_json,reason_code,remediation,
                     framework_mappings_json,scope_resolution,parameter_definitions_json,package_digest,package_source_ref,authored_by,release_notes)
                    values (:id,:version,:name,:description,:severity,'DRAFT',:workflow,:selection,
                     cast(:artifactTypes as jsonb),cast(:nativeKinds as jsonb),'[]'::jsonb,'[]'::jsonb,
                     cast(:families as jsonb),cast(:facts as jsonb),cast(:predicate as jsonb),:reason,:remediation,
                     cast(:mappings as jsonb),'STATIC',cast(:parameters as jsonb),:digest,:source,:actor,:notes)
                    """, new MapSqlParameterSource().addValue("id", command.policyId()).addValue("version", command.version())
                    .addValue("name", command.name()).addValue("description", command.description()).addValue("severity", command.severity())
                    .addValue("workflow", command.workflowClass()).addValue("selection", command.defaultSelection())
                    .addValue("artifactTypes", artifactTypes.toString()).addValue("nativeKinds", emptyArray(command.nativeKindsJson()))
                    .addValue("families", families.toString()).addValue("facts", facts.toString()).addValue("predicate", predicate.toString())
                    .addValue("reason", command.reasonCode()).addValue("remediation", command.remediation()).addValue("mappings", mappings.toString())
                    .addValue("parameters", parameterDefinitions.toString())
                    .addValue("digest", digest).addValue("source", command.packageSourceRef()).addValue("actor", actor).addValue("notes", command.releaseNotes()));
            audit.record("ai_grid.policy_package.imported", "ai_grid_policy", command.policyId() + ":" + command.version(), "{\"digest\":\"" + digest + "\"}");
            return version(command.policyId(), command.version());
        });
    }

    public Distribution updateDistribution(String policyId, DistributionCommand command, String actor) {
        return TenantContext.runAsPlatform(() -> {
            if (command == null) bad("Distribution command is required");
            if (!SELECTIONS.contains(command.defaultSelection())) bad("Invalid defaultSelection");
            if (!List.of("GENERAL_AVAILABILITY", "CANARY", "PAUSED", "RETIRED").contains(command.rolloutStage())) bad("Invalid rolloutStage");
            Integer policy = jdbc.queryForObject("select count(*) from platform.ai_grid_policy_versions where policy_id=:id and lifecycle='PUBLISHED'", Map.of("id", policyId), Integer.class);
            if (policy == null || policy == 0) notFound("Published policy not found");
            List<String> cohort = command.canaryTenantIds() == null ? List.of() : command.canaryTenantIds();
            if (new HashSet<>(cohort).size() != cohort.size()) bad("CANARY cohort contains duplicate tenant IDs");
            List<UUID> tenantIds = new java.util.ArrayList<>();
            for (String tenantId : cohort) {
                try { tenantIds.add(UUID.fromString(tenantId)); }
                catch (IllegalArgumentException ex) { bad("CANARY cohort contains an invalid tenant ID"); }
            }
            if ("CANARY".equals(command.rolloutStage()) && tenantIds.isEmpty()) bad("CANARY requires a non-empty cohort");
            if (!"CANARY".equals(command.rolloutStage())) cohort = List.of();
            if (!tenantIds.isEmpty()) {
                Integer active = jdbc.queryForObject("select count(*) from platform.tenants where id in (:ids) and status='ACTIVE' and deleted_at is null",
                        Map.of("ids", tenantIds), Integer.class);
                if (active == null || active != tenantIds.size()) bad("CANARY cohort contains an inactive or unknown tenant");
            }
            String pinned = blank(command.pinnedVersion());
            if (pinned != null) {
                Integer published = jdbc.queryForObject("select count(*) from platform.ai_grid_policy_versions where policy_id=:id and version=:version and lifecycle='PUBLISHED'",
                        Map.of("id", policyId, "version", pinned), Integer.class);
                if (published == null || published == 0) conflict("Pinned version must be a published version of this policy");
            }
            String before = distributionState(policyId);
            jdbc.update("""
                    insert into platform.ai_grid_policy_distribution (policy_id,available,default_selection,rollout_stage,canary_tenant_ids_json,pinned_version,updated_by)
                    values (:id,:available,:selection,:stage,cast(:cohort as jsonb),:pinned,:actor)
                    on conflict (policy_id) do update set available=excluded.available, default_selection=excluded.default_selection,
                    rollout_stage=excluded.rollout_stage, canary_tenant_ids_json=excluded.canary_tenant_ids_json,
                    pinned_version=excluded.pinned_version, updated_by=excluded.updated_by, updated_at=now()
                    """, new MapSqlParameterSource().addValue("id", policyId).addValue("available", command.available())
                    .addValue("selection", command.defaultSelection()).addValue("stage", command.rolloutStage())
                    .addValue("cohort", json(cohort)).addValue("pinned", pinned).addValue("actor", actor));
            audit.record("ai_grid.policy_distribution.updated", "ai_grid_policy", policyId,
                    "{\"before\":" + before + ",\"after\":" + distributionState(policyId)
                            + ",\"affectedTenantCount\":" + ("CANARY".equals(command.rolloutStage()) ? cohort.size() : "null") + "}");
            return distribution(policyId);
        });
    }

    private String distributionState(String policyId) {
        return jdbc.query("select row_to_json(d)::text from platform.ai_grid_policy_distribution d where policy_id=:id",
                Map.of("id", policyId), rs -> rs.next() ? rs.getString(1) : "null");
    }

    public List<Distribution> distributions() { return TenantContext.runAsPlatform(() -> jdbc.query("""
            select d.policy_id,d.available,d.default_selection,d.rollout_stage,d.canary_tenant_ids_json::text,d.pinned_version,d.updated_by,d.updated_at,
                   p.version,p.name,p.severity,p.lifecycle
              from platform.ai_grid_policy_distribution d join lateral (
                  select * from platform.ai_grid_policy_versions p where p.policy_id=d.policy_id
                  order by p.published_at desc nulls last,p.version desc limit 1) p on true order by p.severity,p.name
            """, (rs, n) -> new Distribution(rs.getString(1),rs.getBoolean(2),rs.getString(3),rs.getString(4),rs.getString(5),rs.getString(6),rs.getString(7),rs.getTimestamp(8).toInstant(),rs.getString(9),rs.getString(10),rs.getString(11),rs.getString(12)))); }

    private PolicyVersion version(String id, String version) { return jdbc.queryForObject("select policy_id,version,lifecycle,package_digest,package_source_ref from platform.ai_grid_policy_versions where policy_id=:id and version=:version", Map.of("id",id,"version",version), (rs,n) -> new PolicyVersion(rs.getString(1),rs.getString(2),rs.getString(3),rs.getString(4),rs.getString(5))); }
    private Distribution distribution(String id) { return distributions().stream().filter(row -> row.policyId().equals(id)).findFirst().orElseThrow(); }
    private JsonNode tree(String value, String field) { try { return mapper.readTree(value); } catch (Exception ex) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be valid JSON"); } }
    private String emptyArray(String value) { return value == null || value.isBlank() ? "[]" : tree(value, "nativeKindsJson").toString(); }
    private String defaultArray(String value) { return value == null || value.isBlank() ? "[]" : value; }
    private void validateParameterDefinitions(JsonNode definitions, JsonNode predicate) {
        if (!definitions.isArray()) bad("parameterDefinitionsJson must be an array");
        Set<String> keys = new HashSet<>();
        for (JsonNode definition : definitions) {
            String key = definition.path("key").asText();
            String type = definition.path("type").asText();
            if (key.isBlank() || !keys.add(key) || !Set.of("BOOLEAN", "NUMBER", "STRING", "ENUM").contains(type)
                    || !definition.has("defaultValue")) bad("Invalid parameter definition");
            if ("ENUM".equals(type) && (!definition.path("options").isArray() || definition.path("options").isEmpty()
                    || !contains(definition.path("options"), definition.get("defaultValue")))) bad("Invalid enum parameter definition");
        }
        validateParameterReferences(predicate, keys);
    }
    private boolean contains(JsonNode values, JsonNode expected) { for (JsonNode value : values) if (value.equals(expected)) return true; return false; }
    private void validateParameterReferences(JsonNode node, Set<String> keys) {
        if (node.has("all") || node.has("any")) { for (JsonNode child : node.has("all") ? node.get("all") : node.get("any")) validateParameterReferences(child, keys); return; }
        if (node.has("not")) { validateParameterReferences(node.get("not"), keys); return; }
        node.fields().forEachRemaining(field -> {
            JsonNode value = field.getValue();
            if (!"fact".equals(field.getKey()) && value.isObject() && value.hasNonNull("parameter") && !keys.contains(value.path("parameter").asText())) bad("Predicate references an undefined parameter");
        });
    }
    private String json(Object value) { try { return mapper.writeValueAsString(value == null ? List.of() : value); } catch (Exception ex) { throw new IllegalArgumentException(ex); } }
    private String digest(String value) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (Exception ex) { throw new IllegalStateException(ex); } }
    private String blank(String value) { return value == null || value.isBlank() ? null : value; }
    private void require(String value, String field) { if (value == null || value.isBlank()) bad(field + " is required"); }
    private void bad(String message) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private void notFound(String message) { throw new ResponseStatusException(HttpStatus.NOT_FOUND, message); }
    private void conflict(String message) { throw new ResponseStatusException(HttpStatus.CONFLICT, message); }

    public record PolicyPackageCommand(String policyId, String version, String name, String description, String severity,
            String workflowClass, String defaultSelection, String artifactTypesJson, String nativeKindsJson,
            String requiredResourceFamiliesJson, String requiredFactsJson, String predicateJson, String reasonCode,
            String remediation, String frameworkMappingsJson, String packageSourceRef, String releaseNotes, String parameterDefinitionsJson) {
        String digestMaterial() { return String.join("|", policyId, version, name, description, severity, workflowClass, defaultSelection, artifactTypesJson, nativeKindsJson == null ? "[]" : nativeKindsJson, requiredResourceFamiliesJson, requiredFactsJson, predicateJson, reasonCode, remediation, frameworkMappingsJson, packageSourceRef, parameterDefinitionsJson == null ? "[]" : parameterDefinitionsJson); }
    }
    public record PolicyVersion(String policyId, String version, String lifecycle, String packageDigest, String packageSourceRef) {}
    public record DistributionCommand(boolean available, String defaultSelection, String rolloutStage, List<String> canaryTenantIds, String pinnedVersion) {}
    public record Distribution(String policyId, boolean available, String defaultSelection, String rolloutStage, String canaryTenantIdsJson, String pinnedVersion, String updatedBy, java.time.Instant updatedAt, String version, String name, String severity, String lifecycle) {}
}
