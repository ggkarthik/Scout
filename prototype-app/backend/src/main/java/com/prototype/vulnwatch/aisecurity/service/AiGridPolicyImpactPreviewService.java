package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.prototype.vulnwatch.aisecurity.policy.AiGridPredicateEngine;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityResourceFamilyCatalogue;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Read-only projection of a candidate policy against a tenant's latest collected facts. */
@Service
public class AiGridPolicyImpactPreviewService {
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final AiGridPredicateEngine predicates;
    private final AiGridAssessmentService assessments;
    private final AiSecurityResourceFamilyCatalogue families;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiGridCapabilityService capabilities;
    private final AiGridGraphEvidenceResolver graphEvidence;

    public AiGridPolicyImpactPreviewService(NamedParameterJdbcTemplate jdbc, ObjectMapper mapper,
                                            AiGridPredicateEngine predicates, TenantService tenants,
                                            TenantSchemaExecutionService tenantExecution, AiGridAssessmentService assessments, AiSecurityResourceFamilyCatalogue families,
                                            AiGridCapabilityService capabilities, AiGridGraphEvidenceResolver graphEvidence) {
        this.jdbc = jdbc; this.mapper = mapper; this.predicates = predicates; this.tenants = tenants; this.tenantExecution = tenantExecution; this.assessments = assessments; this.families = families; this.capabilities = capabilities; this.graphEvidence = graphEvidence;
    }

    public ImpactPreview preview(String policyId, String version, UUID tenantId) {
        Candidate candidate = TenantContext.runAsPlatform(() -> candidate(policyId, version));
        Tenant tenant = tenants.requireTenantUuid(tenantId);
        return tenantExecution.run(tenant, () -> evaluate(candidate, tenant));
    }

    private ImpactPreview evaluate(Candidate candidate, Tenant tenant) {
        List<Artifact> artifacts = jdbc.query("""
                select id,provider,native_kind,account_id,region from ai_security_artifacts
                 where active=true and (:allTypes or artifact_type in (:types))
                """, new org.springframework.jdbc.core.namedparam.MapSqlParameterSource()
                .addValue("allTypes", candidate.artifactTypes().isEmpty())
                .addValue("types", candidate.artifactTypes().isEmpty() ? List.of("__NO_ARTIFACT_TYPE__") : candidate.artifactTypes()),
                (rs, n) -> new Artifact(rs.getObject(1, UUID.class),rs.getString(2),rs.getString(3),rs.getString(4),rs.getString(5)));
        int pass = 0, fail = 0, noDecision = 0, notApplicable = 0;
        Map<String, Integer> missing = new LinkedHashMap<>();
        Map<AiGridCapabilityService.CapabilityKey, AiGridCapabilityService.CapabilityState> capabilityIndex = capabilities.latestIndex();
        for (Artifact artifact : artifacts) {
            if (!providerMatches(candidate.provider(), artifact.provider())) { notApplicable++; continue; }
            if (!candidate.nativeKinds().isEmpty() && !candidate.nativeKinds().contains(artifact.nativeKind())) { notApplicable++; continue; }
            List<String> capabilityGaps = capabilities.gaps(capabilityIndex, artifact.provider(), artifact.accountId(), artifact.region(), candidate.requiredCapabilities());
            if (!capabilityGaps.isEmpty()) { noDecision++; capabilityGaps.forEach(key -> missing.merge(key, 1, Integer::sum)); continue; }
            List<String> scopeGaps = missingScopes(candidate, artifact);
            if (!scopeGaps.isEmpty()) { noDecision++; scopeGaps.forEach(key -> missing.merge("scope:" + key, 1, Integer::sum)); continue; }
            AiGridGraphEvidenceResolver.DirectEvidence relationshipEvidence = graphEvidence.resolveLatest(
                    artifact.id(), relationshipTypes(candidate), Instant.now());
            if (relationshipEvidence.status() == AiGridGraphEvidenceResolver.Status.ABSENT) { notApplicable++; continue; }
            if (relationshipEvidence.status() == AiGridGraphEvidenceResolver.Status.STALE) {
                noDecision++;
                relationshipEvidence.issues().forEach(type -> missing.merge("relationship:" + type + ":STALE", 1, Integer::sum));
                continue;
            }
            Map<String, AiGridAssessmentService.Fact> facts = latestFacts(artifact.id(), candidate.factKeys());
            Map<String, JsonNode> predicateFacts = new LinkedHashMap<>();
            List<String> issues = new ArrayList<>();
            for (AiGridAssessmentService.FactRequirement requirement : candidate.requirements()) {
                AiGridAssessmentService.Fact fact = facts.get(requirement.factKey());
                String issue = assessments.issue(fact, requirement, Instant.now());
                if (issue == null) predicateFacts.put(requirement.factKey(), fact.value());
                else issues.add("fact:" + requirement.factKey() + ":" + issue);
            }
            if (!issues.isEmpty()) {
                noDecision++;
                issues.forEach(key -> missing.merge(key, 1, Integer::sum));
            } else {
                DirectPreview direct = directPreview(candidate, relationshipEvidence.relationships(), predicateFacts, Instant.now());
                if (direct.noDecision()) {
                    noDecision++;
                    direct.missing().forEach(key -> missing.merge(key, 1, Integer::sum));
                } else if (direct.failure()) fail++;
                else pass++;
            }
        }
        return new ImpactPreview(policyId(candidate), candidate.version(), tenant.getId(), artifacts.size(), pass, fail, noDecision, notApplicable,
                Map.copyOf(missing), Instant.now());
    }

    private List<String> missingScopes(Candidate candidate, Artifact artifact) {
        List<String> required = new ArrayList<>(candidate.requiredFamilies());
        if ("NATIVE_KIND_PLUS_STATIC".equals(candidate.scopeResolution())) required.add(artifact.nativeKind());
        List<String> missing = new ArrayList<>();
        for (String family : required) {
            String region = families.requiredRegion(family, artifact.region()).orElse(null);
            if (region == null || count("select count(*) from ai_security_snapshot_scopes where account_id=:account and region=:region and resource_family=:family and status='COMPLETE'", Map.of("account",artifact.accountId(),"region",region,"family",family)) == 0) missing.add(family);
        }
        return missing;
    }

    private Map<String, AiGridAssessmentService.Fact> latestFacts(UUID artifactId, List<String> factKeys) {
        Map<String, AiGridAssessmentService.Fact> result = new LinkedHashMap<>();
        jdbc.query("""
                select distinct on (fact_key) id,fact_key,value_type,value_json::text,state,evidence_class,observed_at,confidence from ai_grid_facts
                 where artifact_id=:id and fact_key in (:keys)
                 order by fact_key,observed_at desc,id desc
                """, Map.of("id", artifactId, "keys", factKeys), rs -> {
            while (rs.next()) result.put(rs.getString("fact_key"), new AiGridAssessmentService.Fact(
                    rs.getObject("id", UUID.class), rs.getString("value_type"), parse(rs.getString("value_json")),
                    rs.getString("state"), rs.getString("evidence_class"), rs.getTimestamp("observed_at").toInstant(),
                    (Double) rs.getObject("confidence")));
            return null;
        });
        return result;
    }

    private DirectPreview directPreview(Candidate candidate, List<AiGridGraphEvidenceResolver.Relationship> relationships,
                                        Map<String, JsonNode> sourceFacts, Instant asOf) {
        if (!"DIRECT_RELATIONSHIP".equals(candidate.evaluationMode())) {
            return new DirectPreview(predicates.evaluate(candidate.predicate(), sourceFacts), false, List.of());
        }
        JsonNode direct = candidate.evaluationDefinition().path("directRelationship");
        JsonNode sourcePredicate = direct.path("sourcePredicate").isObject() ? direct.path("sourcePredicate") : candidate.predicate();
        JsonNode targetPredicate = direct.path("targetPredicate").isObject() ? direct.path("targetPredicate") : candidate.predicate();
        if (!predicates.evaluate(sourcePredicate, sourceFacts)) return new DirectPreview(false, false, List.of());
        boolean evaluated = false;
        List<String> missing = new ArrayList<>();
        for (AiGridGraphEvidenceResolver.Relationship relationship : relationships) {
            Map<String, AiGridAssessmentService.Fact> facts = latestFacts(relationship.targetArtifactId(), candidate.factKeys());
            Map<String, JsonNode> target = new LinkedHashMap<>();
            boolean ready = true;
            for (AiGridAssessmentService.FactRequirement requirement : candidate.requirements()) {
                AiGridAssessmentService.Fact fact = facts.get(requirement.factKey());
                String issue = assessments.issue(fact, requirement, asOf);
                if (issue != null) { ready = false; missing.add("relationship:" + relationship.id() + ":fact:" + requirement.factKey() + ":" + issue); }
                else target.put(requirement.factKey(), fact.value());
            }
            if (!ready) continue;
            evaluated = true;
            if (predicates.evaluate(targetPredicate, target)) return new DirectPreview(true, false, List.of());
        }
        return missing.isEmpty() && evaluated ? new DirectPreview(false, false, List.of())
                : new DirectPreview(false, true, List.copyOf(missing));
    }

    private List<String> relationshipTypes(Candidate candidate) {
        if (!"DIRECT_RELATIONSHIP".equals(candidate.evaluationMode())) return candidate.requiredRelationships();
        JsonNode edges = candidate.evaluationDefinition().path("directRelationship").path("edgeConstraints");
        List<String> values = new ArrayList<>();
        if (edges.isArray()) edges.forEach(value -> { if (value.isTextual()) values.add(value.asText()); });
        return values.isEmpty() ? candidate.requiredRelationships() : List.copyOf(values);
    }

    private Candidate candidate(String policyId, String version) {
        Candidate candidate = jdbc.query("""
                select policy_id,version,artifact_types_json::text,native_kinds_json::text,required_capabilities_json::text,required_relationships_json::text,required_resource_families_json::text,scope_resolution,required_facts_json::text,predicate_json::text,evaluation_mode,evaluation_definition_json::text,provider
                  from platform.ai_grid_policy_versions where policy_id=:id and version=:version
                """, Map.of("id", policyId, "version", version), rs -> rs.next()
                ? new Candidate(rs.getString(1), rs.getString(2), strings(rs.getString(3)), strings(rs.getString(4)), strings(rs.getString(5)), strings(rs.getString(6)), strings(rs.getString(7)), rs.getString(8), requirements(rs.getString(9)), parse(rs.getString(10)), rs.getString(11), parse(rs.getString(12)), rs.getString(13)) : null);
        if (candidate == null) throwNotFound();
        return candidate;
    }

    private Candidate throwNotFound() { throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Policy version not found"); }
    private boolean providerMatches(String policyProvider, String artifactProvider) {
        return policyProvider == null || policyProvider.isBlank()
                || "MULTI_CLOUD".equals(policyProvider)
                || policyProvider.equalsIgnoreCase(artifactProvider);
    }
    private String policyId(Candidate candidate) { return candidate.policyId(); }
    private JsonNode parse(String value) {
        if (value == null || value.isBlank()) return NullNode.getInstance();
        try { return mapper.readTree(value); } catch (Exception ex) { throw new IllegalArgumentException("Invalid stored policy JSON", ex); }
    }
    private List<String> strings(String value) { try { return mapper.readValue(value, new TypeReference<>() {}); } catch (Exception ex) { return List.of(); } }
    private List<AiGridAssessmentService.FactRequirement> requirements(String value) { try { return mapper.readValue(value, new TypeReference<>() {}); } catch (Exception ex) { return List.of(); } }
    private long count(String sql, Map<String, Object> params) { Long value=jdbc.queryForObject(sql,params,Long.class); return value==null?0:value; }
    private record Candidate(String policyId, String version, List<String> artifactTypes, List<String> nativeKinds, List<String> requiredCapabilities, List<String> requiredRelationships, List<String> requiredFamilies, String scopeResolution, List<AiGridAssessmentService.FactRequirement> requirements, JsonNode predicate, String evaluationMode, JsonNode evaluationDefinition, String provider) { List<String> factKeys() { return requirements.stream().map(AiGridAssessmentService.FactRequirement::factKey).toList(); } }
    private record Artifact(UUID id, String provider, String nativeKind, String accountId, String region) {}
    private record DirectPreview(boolean failure, boolean noDecision, List<String> missing) {}
    public record ImpactPreview(String policyId, String version, UUID tenantId, int applicableArtifacts, int expectedPass, int expectedFail, int expectedNoDecision, int expectedNotApplicable, Map<String, Integer> missingFacts, Instant generatedAt) {}
}
