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
            require(command.controlObjectiveId(), "controlObjectiveId"); require(command.provider(), "provider");
            require(command.evaluationMode(), "evaluationMode"); require(command.evaluationDefinitionJson(), "evaluationDefinitionJson");
            require(command.baseEvidenceTiersJson(), "baseEvidenceTiersJson"); require(command.releaseFamily(), "releaseFamily");
            require(command.releaseWave(), "releaseWave");
            if (!List.of("CRITICAL", "HIGH", "MEDIUM", "LOW").contains(command.severity())) bad("Invalid severity");
            if (!List.of("POSTURE_FINDING", "EXPOSURE_HYPOTHESIS", "VALIDATED_EXPOSURE").contains(command.workflowClass())) bad("Invalid workflowClass");
            if (!SELECTIONS.contains(command.defaultSelection())) bad("Invalid defaultSelection");
            JsonNode facts = tree(command.requiredFactsJson(), "requiredFactsJson");
            JsonNode predicate = tree(command.predicateJson(), "predicateJson");
            JsonNode artifactTypes = tree(command.artifactTypesJson(), "artifactTypesJson");
            JsonNode families = tree(command.requiredResourceFamiliesJson(), "requiredResourceFamiliesJson");
            JsonNode mappings = tree(command.frameworkMappingsJson(), "frameworkMappingsJson");
            JsonNode capabilities = tree(defaultArray(command.requiredCapabilitiesJson()), "requiredCapabilitiesJson");
            JsonNode relationships = tree(defaultArray(command.requiredRelationshipsJson()), "requiredRelationshipsJson");
            JsonNode parameterDefinitions = tree(defaultArray(command.parameterDefinitionsJson()), "parameterDefinitionsJson");
            JsonNode definition = tree(command.evaluationDefinitionJson(), "evaluationDefinitionJson");
            JsonNode evidenceTiers = tree(command.baseEvidenceTiersJson(), "baseEvidenceTiersJson");
            JsonNode conditionalCapabilities = tree(defaultArray(command.conditionalCapabilitiesJson()), "conditionalCapabilitiesJson");
            JsonNode certificationProfile = nullableTree(command.certificationParameterProfileJson(), "certificationParameterProfileJson");
            if (!facts.isArray() || !artifactTypes.isArray() || !families.isArray() || !capabilities.isArray()
                    || !relationships.isArray() || !conditionalCapabilities.isArray() || !evidenceTiers.isArray()
                    || !mappings.isArray() || mappings.isEmpty()) bad("Invalid policy package shape");
            validateMappings(mappings);
            validateParameterDefinitions(parameterDefinitions, predicate);
            if (!"CORRELATION_PATH".equals(command.evaluationMode())) predicates.validate(predicate);
            validateEvidenceTiers(evidenceTiers);
            validateCatalogReference(command.controlObjectiveId(), CatalogReference.OBJECTIVE);
            validateCatalogReferences(conditionalCapabilities, CatalogReference.CAPABILITY);
            validateEvaluationDefinition(command, definition, predicate);
            validateCertificationProfile(parameterDefinitions, certificationProfile);
            validatePhase1EvidenceContract(command, facts, predicate, artifactTypes);
            facts.forEach(fact -> {
                String key = fact.path("factKey").asText();
                if (key.isBlank() || jdbc.queryForObject("select count(*) from platform.ai_grid_fact_definitions where fact_key=:key and lifecycle='ACTIVE'", Map.of("key", key), Integer.class) == 0) {
                    bad("Unknown or inactive fact: " + key);
                }
            });
            validateCatalogReferences(families, CatalogReference.RESOURCE_FAMILY);
            validateCatalogReferences(capabilities, CatalogReference.CAPABILITY);
            validateCatalogReferences(relationships, CatalogReference.RELATIONSHIP);
            String digest = digest(command.digestMaterial());
            Integer existing = jdbc.queryForObject("select count(*) from platform.ai_grid_policy_versions where policy_id=:id and version=:version", Map.of("id", command.policyId(), "version", command.version()), Integer.class);
            if (existing != null && existing > 0) conflict("Policy version already exists and is immutable");
            jdbc.update("""
                    insert into platform.ai_grid_policy_versions
                    (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,
                     artifact_types_json,native_kinds_json,required_capabilities_json,required_relationships_json,
                     required_resource_families_json,required_facts_json,predicate_json,reason_code,remediation,
                     framework_mappings_json,scope_resolution,parameter_definitions_json,package_digest,package_source_ref,authored_by,release_notes,
                     control_objective_id,provider,evaluation_mode,evaluation_definition_json,base_evidence_tiers_json,
                     conditional_capabilities_json,certification_parameter_profile_json,release_family,release_wave)
                    values (:id,:version,:name,:description,:severity,'DRAFT',:workflow,:selection,
                     cast(:artifactTypes as jsonb),cast(:nativeKinds as jsonb),cast(:capabilities as jsonb),cast(:relationships as jsonb),
                     cast(:families as jsonb),cast(:facts as jsonb),cast(:predicate as jsonb),:reason,:remediation,
                     cast(:mappings as jsonb),'STATIC',cast(:parameters as jsonb),:digest,:source,:actor,:notes,
                     :objective,:provider,:evaluationMode,cast(:definition as jsonb),cast(:evidenceTiers as jsonb),
                     cast(:conditionalCapabilities as jsonb),cast(:certificationProfile as jsonb),:releaseFamily,:releaseWave)
                    """, new MapSqlParameterSource().addValue("id", command.policyId()).addValue("version", command.version())
                    .addValue("name", command.name()).addValue("description", command.description()).addValue("severity", command.severity())
                    .addValue("workflow", command.workflowClass()).addValue("selection", command.defaultSelection())
                    .addValue("artifactTypes", artifactTypes.toString()).addValue("nativeKinds", emptyArray(command.nativeKindsJson()))
                    .addValue("capabilities", capabilities.toString()).addValue("relationships", relationships.toString())
                    .addValue("families", families.toString()).addValue("facts", facts.toString()).addValue("predicate", predicate.toString())
                    .addValue("reason", command.reasonCode()).addValue("remediation", command.remediation()).addValue("mappings", mappings.toString())
                    .addValue("parameters", parameterDefinitions.toString())
                    .addValue("digest", digest).addValue("source", command.packageSourceRef()).addValue("actor", actor).addValue("notes", command.releaseNotes())
                    .addValue("objective", command.controlObjectiveId()).addValue("provider", command.provider())
                    .addValue("evaluationMode", command.evaluationMode()).addValue("definition", definition.toString())
                    .addValue("evidenceTiers", evidenceTiers.toString()).addValue("conditionalCapabilities", conditionalCapabilities.toString())
                    .addValue("certificationProfile", certificationProfile == null ? null : certificationProfile.toString())
                    .addValue("releaseFamily", command.releaseFamily()).addValue("releaseWave", command.releaseWave()));
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
            boolean requiresApproval = command.available() || List.of("GENERAL_AVAILABILITY", "CANARY").contains(command.rolloutStage()) || pinned != null;
            String targetVersion = pinned == null ? jdbc.queryForObject("""
                    select version from platform.ai_grid_policy_versions
                     where policy_id=:id and lifecycle='PUBLISHED'
                     order by published_at desc nulls last, version desc limit 1
                    """, Map.of("id", policyId), String.class) : pinned;
            String approvedDigest = null;
            UUID releaseDecisionId = null;
            if (requiresApproval) {
                Map<String, Object> approval = jdbc.query("""
                        select p.package_digest, d.id
                          from platform.ai_grid_policy_versions p
                          join platform.ai_grid_policy_release_decisions d
                            on d.policy_id=p.policy_id and d.policy_version=p.version
                           and d.decision='APPROVED' and d.package_digest=p.package_digest
                         where p.policy_id=:id and p.version=:version and p.lifecycle='PUBLISHED'
                         order by d.decided_at desc limit 1
                        """, new MapSqlParameterSource().addValue("id", policyId).addValue("version", targetVersion), rs ->
                        rs.next() ? Map.of("digest", rs.getString(1), "id", rs.getObject(2, UUID.class)) : Map.of());
                if (approval.isEmpty()) conflict("Distribution requires an exact APPROVED release decision for the selected package digest");
                approvedDigest = (String) approval.get("digest");
                releaseDecisionId = (UUID) approval.get("id");
            }
            String before = distributionState(policyId);
            jdbc.update("""
                    insert into platform.ai_grid_policy_distribution
                        (policy_id,available,default_selection,rollout_stage,canary_tenant_ids_json,pinned_version,
                         approved_package_digest,release_decision_id,updated_by)
                    values (:id,:available,:selection,:stage,cast(:cohort as jsonb),:pinned,:digest,:decisionId,:actor)
                    on conflict (policy_id) do update set available=excluded.available, default_selection=excluded.default_selection,
                    rollout_stage=excluded.rollout_stage, canary_tenant_ids_json=excluded.canary_tenant_ids_json,
                    pinned_version=excluded.pinned_version, approved_package_digest=excluded.approved_package_digest,
                    release_decision_id=excluded.release_decision_id, updated_by=excluded.updated_by, updated_at=now()
                    """, new MapSqlParameterSource().addValue("id", policyId).addValue("available", command.available())
                    .addValue("selection", command.defaultSelection()).addValue("stage", command.rolloutStage())
                    .addValue("cohort", json(cohort)).addValue("pinned", pinned).addValue("digest", approvedDigest)
                    .addValue("decisionId", releaseDecisionId).addValue("actor", actor));
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

    public List<Distribution> distributions() { return distributions(null, null); }

    /**
     * Platform catalog query. Distribution availability is intentionally not a predicate here:
     * platform owners must be able to inspect governed VALIDATED/PAUSED packages before tenant
     * publication. Tenant-facing catalog queries apply their own availability boundary.
     */
    public List<Distribution> distributions(String releaseFamily, String lifecycle) {
        String family = blank(releaseFamily);
        String lifecycleFilter = blank(lifecycle);
        return TenantContext.runAsPlatform(() -> jdbc.query("""
            select d.policy_id,d.available,d.default_selection,d.rollout_stage,d.canary_tenant_ids_json::text,d.pinned_version,d.updated_by,d.updated_at,
                   d.approved_package_digest,d.release_decision_id,
                   p.version,p.name,p.severity,p.lifecycle,p.control_objective_id,p.provider,p.evaluation_mode,
                   p.base_evidence_tiers_json::text,p.conditional_capabilities_json::text,p.framework_mappings_json::text,
                   p.release_family,p.release_wave
              from platform.ai_grid_policy_distribution d join lateral (
                  select * from platform.ai_grid_policy_versions p where p.policy_id=d.policy_id
                  order by p.published_at desc nulls last,p.version desc limit 1) p on true
             where (cast(:releaseFamily as text) is null or p.release_family = cast(:releaseFamily as text))
               and (cast(:lifecycle as text) is null or p.lifecycle = cast(:lifecycle as text))
             order by p.provider,p.policy_id
            """, new MapSqlParameterSource().addValue("releaseFamily", family).addValue("lifecycle", lifecycleFilter),
                (rs, n) -> new Distribution(rs.getString(1),rs.getBoolean(2),rs.getString(3),rs.getString(4),rs.getString(5),rs.getString(6),rs.getString(7),rs.getTimestamp(8).toInstant(),rs.getString(9),rs.getObject(10, UUID.class),rs.getString(11),rs.getString(12),rs.getString(13),rs.getString(14),rs.getString(15),rs.getString(16),rs.getString(17),rs.getString(18),rs.getString(19),rs.getString(20),rs.getString(21),rs.getString(22))));
    }

    public PolicyDetail detail(String policyId, String version) { return TenantContext.runAsPlatform(() -> {
        PolicyDetail result = jdbc.query("""
            select p.policy_id,p.version,p.name,p.description,p.severity,p.lifecycle,p.workflow_class,p.default_selection,
                   p.control_objective_id,o.name,o.security_intent,o.remediation_intent,p.provider,p.evaluation_mode,
                   p.evaluation_definition_json::text,p.base_evidence_tiers_json::text,p.conditional_capabilities_json::text,
                   p.required_capabilities_json::text,p.required_relationships_json::text,p.required_resource_families_json::text,
                   p.native_kinds_json::text,p.required_facts_json::text,p.framework_mappings_json::text,p.certification_parameter_profile_json::text,
                   p.package_digest,p.package_source_ref,p.release_family,p.release_wave
              from platform.ai_grid_policy_versions p
              left join platform.ai_grid_control_objectives o on o.control_objective_id=p.control_objective_id
             where p.policy_id=:id and p.version=:version
            """, Map.of("id", policyId, "version", version), rs -> rs.next() ? new PolicyDetail(
                    rs.getString(1),rs.getString(2),rs.getString(3),rs.getString(4),rs.getString(5),rs.getString(6),rs.getString(7),rs.getString(8),
                    rs.getString(9),rs.getString(10),rs.getString(11),rs.getString(12),rs.getString(13),rs.getString(14),
                    tree(rs.getString(15)),tree(rs.getString(16)),tree(rs.getString(17)),tree(rs.getString(18)),tree(rs.getString(19)),tree(rs.getString(20)),
                    tree(rs.getString(21)),tree(rs.getString(22)),tree(rs.getString(23)),nullableTree(rs.getString(24), "stored certification profile"),rs.getString(25),rs.getString(26),rs.getString(27),rs.getString(28)) : null);
        if (result == null) notFound("Policy version not found");
        return result;
    }); }

    private PolicyVersion version(String id, String version) { return jdbc.queryForObject("select policy_id,version,lifecycle,package_digest,package_source_ref from platform.ai_grid_policy_versions where policy_id=:id and version=:version", Map.of("id",id,"version",version), (rs,n) -> new PolicyVersion(rs.getString(1),rs.getString(2),rs.getString(3),rs.getString(4),rs.getString(5))); }
    private Distribution distribution(String id) { return distributions().stream().filter(row -> row.policyId().equals(id)).findFirst().orElseThrow(); }
    private JsonNode tree(String value) { return tree(value, "stored policy JSON"); }
    private JsonNode tree(String value, String field) { try { return mapper.readTree(value); } catch (Exception ex) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be valid JSON"); } }
    private String emptyArray(String value) { return value == null || value.isBlank() ? "[]" : tree(value, "nativeKindsJson").toString(); }
    private String defaultArray(String value) { return value == null || value.isBlank() ? "[]" : value; }
    private JsonNode nullableTree(String value, String field) { return value == null || value.isBlank() || "null".equals(value) ? null : tree(value, field); }
    private void validateEvidenceTiers(JsonNode tiers) {
        if (tiers.isEmpty()) bad("baseEvidenceTiersJson must be non-empty");
        Set<String> values = new HashSet<>();
        for (JsonNode tier : tiers) if (!tier.isTextual() || !Set.of("E0", "E1", "E2").contains(tier.asText()) || !values.add(tier.asText())) bad("Invalid base evidence tier");
    }
    private void validateEvaluationDefinition(PolicyPackageCommand command, JsonNode definition, JsonNode predicate) {
        if (!definition.isObject() || !command.evaluationMode().equals(definition.path("mode").asText())) bad("Evaluation mode does not match definition");
        List<String> payloads = List.of("artifactFacts", "directRelationship", "correlationPath").stream().filter(name -> definition.path(name).isObject()).toList();
        if (payloads.size() != 1) bad("Evaluation definition must contain exactly one payload");
        switch (command.evaluationMode()) {
            case "ARTIFACT_FACTS" -> { JsonNode definedPredicate = definition.path("artifactFacts").path("predicate"); if (!definedPredicate.isObject() || !definedPredicate.equals(predicate)) bad("Artifact-fact definition must match predicateJson"); }
            case "DIRECT_RELATIONSHIP" -> {
                JsonNode direct = definition.path("directRelationship"); JsonNode source = direct.path("sourcePredicate"); JsonNode target = direct.path("targetPredicate"); JsonNode edges = direct.path("edgeConstraints");
                if (!source.isObject() || !target.isObject() || !edges.isArray() || edges.isEmpty() || !Set.of("ONE_OR_MORE", "ANY").contains(direct.path("targetCardinality").asText())) bad("Invalid direct relationship definition");
                predicates.validate(source); predicates.validate(target); validateCatalogReferences(edges, CatalogReference.RELATIONSHIP);
                if (!"POSTURE_FINDING".equals(command.workflowClass())) bad("Direct relationship policies must be posture findings");
            }
            case "CORRELATION_PATH" -> {
                JsonNode correlation = definition.path("correlationPath"); String id = correlation.path("correlationId").asText(); String version = correlation.path("correlationVersion").asText();
                if (id.isBlank() || version.isBlank()) bad("Correlation path requires correlation identity");
                validateCatalogReference(id + "@" + version, CatalogReference.CORRELATION);
                if (!"MULTI_CLOUD".equals(command.provider()) || !"VALIDATED_EXPOSURE".equals(command.workflowClass())) bad("Correlation path policies must be multi-cloud validated exposures");
            }
            default -> bad("Invalid evaluationMode");
        }
    }
    private void validateCertificationProfile(JsonNode definitions, JsonNode profile) {
        if (definitions.isEmpty()) { if (profile != null) bad("Certification profile requires parameters"); return; }
        if (profile == null || !profile.isObject() || !profile.path("immutable").asBoolean(false) || !profile.has("pass") || !profile.has("fail") || !profile.has("invalid")) bad("Parameterized policies require an immutable certification profile");
    }
    private void validatePhase1EvidenceContract(PolicyPackageCommand command, JsonNode facts,
                                                JsonNode predicate, JsonNode artifactTypes) {
        if (!"AGCF_PHASE_1".equals(command.releaseFamily())) return;
        boolean posture = !"CORRELATION_PATH".equals(command.evaluationMode());
        if (posture && contains(artifactTypes, mapper.getNodeFactory().textNode("AI_ARTIFACT"))) {
            bad("Phase 1 posture policies require concrete native kinds; generic AI_ARTIFACT binding is forbidden");
        }
        JsonNode nativeKinds = tree(emptyArray(command.nativeKindsJson()), "nativeKindsJson");
        if (posture && (!nativeKinds.isArray() || nativeKinds.isEmpty())) {
            bad("Phase 1 posture policies require at least one concrete native kind");
        }
        if (!posture && !facts.isEmpty()) {
            bad("Phase 1 correlation policies must use governed correlation outputs, not synthetic required facts");
        }
        Map<String, String> factTypes = new java.util.LinkedHashMap<>();
        for (JsonNode fact : facts) {
            String key = fact.path("factKey").asText();
            String declaredType = fact.path("valueType").asText();
            if (key.matches("(?i)^agcf\\.agcf-(aws|azr|xsp)-\\d{3}\\.evidence$") || key.isBlank()) {
                bad("Phase 1 placeholder evidence facts are forbidden: " + key);
            }
            if (!Set.of("BOOLEAN", "STRING", "NUMBER", "OBJECT", "ARRAY", "TIMESTAMP").contains(declaredType)) {
                bad("Unsupported Phase 1 fact valueType for " + key);
            }
            String registeredType = jdbc.query("""
                    select value_type from platform.ai_grid_fact_definitions
                     where fact_key=:key and lifecycle='ACTIVE'
                     order by version desc limit 1
                    """, Map.of("key", key), rs -> rs.next() ? rs.getString(1) : null);
            if (registeredType == null || !registeredType.equals(declaredType)) {
                bad("Phase 1 fact type does not match its active definition: " + key);
            }
            if (factTypes.put(key, declaredType) != null) bad("Duplicate required fact: " + key);
        }
        if (posture) validatePredicateTypes(predicate, factTypes);
    }

    private void validatePredicateTypes(JsonNode node, Map<String, String> factTypes) {
        if (node.has("all") || node.has("any")) {
            for (JsonNode child : node.has("all") ? node.get("all") : node.get("any")) validatePredicateTypes(child, factTypes);
            return;
        }
        if (node.has("not")) { validatePredicateTypes(node.get("not"), factTypes); return; }
        String key = node.path("fact").asText();
        String type = factTypes.get(key);
        if (type == null) bad("Predicate references an undeclared required fact: " + key);
        String operator = null;
        var fields = node.fieldNames();
        while (fields.hasNext()) {
            String field = fields.next();
            if (!"fact".equals(field)) operator = field;
        }
        Set<String> allowed = switch (type) {
            case "BOOLEAN" -> Set.of("exists", "eq", "neq");
            case "NUMBER" -> Set.of("exists", "eq", "neq", "in", "gt", "gte", "lt", "lte",
                    "count_gt", "count_gte", "count_lt", "count_lte", "count_eq");
            case "STRING" -> Set.of("exists", "eq", "neq", "in", "empty", "non_empty", "strength_lt");
            case "TIMESTAMP" -> Set.of("exists", "eq", "neq", "age_gt_seconds", "age_gte_seconds");
            case "ARRAY", "OBJECT" -> Set.of("exists", "eq", "neq", "empty", "non_empty",
                    "count_gt", "count_gte", "count_lt", "count_lte", "count_eq");
            default -> Set.of();
        };
        if (!allowed.contains(operator)) bad("Predicate operator " + operator + " is incompatible with " + type + " fact " + key);
    }
    private void validateParameterDefinitions(JsonNode definitions, JsonNode predicate) {
        if (!definitions.isArray()) bad("parameterDefinitionsJson must be an array");
        Set<String> keys = new HashSet<>();
        for (JsonNode definition : definitions) {
            String key = definition.path("key").asText();
            String type = definition.path("type").asText();
            if (key.isBlank() || !keys.add(key) || !Set.of("BOOLEAN", "NUMBER", "STRING", "STRING_LIST", "ENUM").contains(type)
                    || !definition.has("defaultValue")) bad("Invalid parameter definition");
            if ("STRING_LIST".equals(type) && (!definition.path("defaultValue").isArray()
                    || !allTextual(definition.path("defaultValue")))) bad("Invalid string-list parameter definition");
            if ("ENUM".equals(type) && (!definition.path("options").isArray() || definition.path("options").isEmpty()
                    || !contains(definition.path("options"), definition.get("defaultValue")))) bad("Invalid enum parameter definition");
        }
        validateParameterReferences(predicate, keys);
    }
    private void validateMappings(JsonNode mappings) {
        if (mappings.isObject()) return; // Legacy read compatibility is retained for one release.
        for (JsonNode mapping : mappings) {
            String framework = mapping.path("framework").asText();
            String version = mapping.path("frameworkVersion").asText();
            String type = mapping.path("mappingType").asText();
            if (!(("CSA_AICM".equals(framework) && "1.1".equals(version))
                    || ("OWASP_GENAI_LLM_TOP_10".equals(framework) && "2026".equals(version)))
                    || mapping.path("controlId").asText().isBlank() || mapping.path("rationale").asText().isBlank()
                    || !Set.of("DIRECT", "PARTIAL", "INFORMATIVE").contains(type)) {
                bad("Invalid or unversioned framework mapping");
            }
        }
    }
    private void validateCatalogReferences(JsonNode values, CatalogReference reference) {
        for (JsonNode value : values) {
            if (!value.isTextual()) bad("Invalid " + reference.label);
            validateCatalogReference(value.asText(), reference);
        }
    }
    private void validateCatalogReference(String value, CatalogReference reference) {
        if (value == null || value.isBlank()) bad("Invalid " + reference.label);
        Integer known = jdbc.queryForObject(reference.activeLookup, Map.of("value", value), Integer.class);
        if (known == null || known == 0) bad("Unknown or inactive " + reference.label + ": " + value);
    }
    private boolean contains(JsonNode values, JsonNode expected) { for (JsonNode value : values) if (value.equals(expected)) return true; return false; }
    private boolean allTextual(JsonNode values) { for (JsonNode value : values) if (!value.isTextual()) return false; return true; }
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

    private enum CatalogReference {
        OBJECTIVE("control objective", "select count(*) from platform.ai_grid_control_objectives where control_objective_id=:value and lifecycle='ACTIVE'"),
        RESOURCE_FAMILY("resource family", "select count(*) from platform.ai_grid_resource_family_definitions where resource_family=:value and lifecycle='ACTIVE'"),
        CAPABILITY("capability", "select count(*) from platform.ai_grid_capability_definitions where capability_id=:value and lifecycle='ACTIVE'"),
        RELATIONSHIP("relationship", "select count(*) from platform.ai_grid_relationship_definitions where relationship_type=:value and lifecycle='ACTIVE'"),
        CORRELATION("correlation", "select count(*) from platform.ai_grid_correlation_versions where correlation_id || '@' || version=:value and lifecycle='PUBLISHED'");

        private final String label;
        private final String activeLookup;

        CatalogReference(String label, String activeLookup) {
            this.label = label;
            this.activeLookup = activeLookup;
        }
    }

    public record PolicyPackageCommand(String policyId, String version, String name, String description, String severity,
            String workflowClass, String defaultSelection, String artifactTypesJson, String nativeKindsJson,
            String requiredResourceFamiliesJson, String requiredFactsJson, String predicateJson, String reasonCode,
            String remediation, String frameworkMappingsJson, String packageSourceRef, String releaseNotes, String parameterDefinitionsJson,
            String requiredCapabilitiesJson, String requiredRelationshipsJson, String controlObjectiveId, String provider,
            String evaluationMode, String evaluationDefinitionJson, String baseEvidenceTiersJson, String conditionalCapabilitiesJson,
            String certificationParameterProfileJson, String releaseFamily, String releaseWave) {
        String digestMaterial() { return String.join("|", policyId, version, name, description, severity, workflowClass, defaultSelection, artifactTypesJson, nativeKindsJson == null ? "[]" : nativeKindsJson, requiredCapabilitiesJson == null ? "[]" : requiredCapabilitiesJson, requiredRelationshipsJson == null ? "[]" : requiredRelationshipsJson, requiredResourceFamiliesJson, requiredFactsJson, predicateJson, reasonCode, remediation, frameworkMappingsJson, packageSourceRef, parameterDefinitionsJson == null ? "[]" : parameterDefinitionsJson, controlObjectiveId, provider, evaluationMode, evaluationDefinitionJson, baseEvidenceTiersJson, conditionalCapabilitiesJson == null ? "[]" : conditionalCapabilitiesJson, certificationParameterProfileJson == null ? "null" : certificationParameterProfileJson, releaseFamily, releaseWave); }
    }
    public record PolicyVersion(String policyId, String version, String lifecycle, String packageDigest, String packageSourceRef) {}
    public record DistributionCommand(boolean available, String defaultSelection, String rolloutStage, List<String> canaryTenantIds, String pinnedVersion) {}
    public record Distribution(String policyId, boolean available, String defaultSelection, String rolloutStage, String canaryTenantIdsJson, String pinnedVersion, String updatedBy, java.time.Instant updatedAt, String approvedPackageDigest, UUID releaseDecisionId, String version, String name, String severity, String lifecycle, String controlObjectiveId, String provider, String evaluationMode, String baseEvidenceTiersJson, String conditionalCapabilitiesJson, String frameworkMappingsJson, String releaseFamily, String releaseWave) {}
    public record PolicyDetail(String policyId, String version, String name, String description, String severity, String lifecycle, String workflowClass, String defaultSelection, String controlObjectiveId, String objectiveName, String securityIntent, String remediationIntent, String provider, String evaluationMode, JsonNode evaluationDefinition, JsonNode baseEvidenceTiers, JsonNode conditionalCapabilities, JsonNode requiredCapabilities, JsonNode requiredRelationships, JsonNode requiredResourceFamilies, JsonNode nativeKinds, JsonNode requiredFacts, JsonNode frameworkMappings, JsonNode certificationParameterProfile, String packageDigest, String packageSourceRef, String releaseFamily, String releaseWave) {}
}
