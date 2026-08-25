package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.prototype.vulnwatch.aisecurity.policy.AiGridPredicateEngine;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ArtifactScopeFacts;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeCondition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeConfig;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityResourceFamilyCatalogue;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AiGridAssessmentService {
    private static final Logger LOG = LoggerFactory.getLogger(AiGridAssessmentService.class);
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final AiGridPredicateEngine predicates;
    private final AiSecurityResourceFamilyCatalogue families;
    private final AiGridFindingService findings;
    private final AiGridSnapshotService snapshots;
    private final AiGridCapabilityService capabilities;
    private final AiGridGraphEvidenceResolver graphEvidence;

    public AiGridAssessmentService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                   AiGridPredicateEngine predicates, AiSecurityResourceFamilyCatalogue families,
                                   AiGridFindingService findings, AiGridSnapshotService snapshots,
                                   AiGridCapabilityService capabilities, AiGridGraphEvidenceResolver graphEvidence) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.predicates = predicates;
        this.families = families;
        this.findings = findings;
        this.snapshots = snapshots;
        this.capabilities = capabilities;
        this.graphEvidence = graphEvidence;
    }

    public void evaluateRun(Tenant tenant, UUID runId) {
        List<Policy> policies = loadPublishedPolicies(tenant);
        Map<String, ScopeConfig> scopes = loadScopes();
        Map<String, Map<String, String>> overrides = loadOverrides();
        Map<String, Map<String, Object>> parameters = loadParameters();
        Map<String, String> selections = loadSelections();
        Map<AiGridCapabilityService.CapabilityKey, AiGridCapabilityService.CapabilityState> capabilityIndex = capabilities.forRun(runId);
        List<Artifact> artifacts = jdbc.query("""
                select distinct on (m.artifact_id)
                       m.artifact_id id,
                       b.content_json->>'artifactType' artifact_type,
                       b.content_json->>'nativeKind' native_kind,
                       b.content_json->>'accountId' account_id,
                       b.content_json->>'region' region,
                       a.provider,
                       a.name,
                       m.id manifest_id
                  from ai_grid_snapshot_manifests m
                  join ai_grid_snapshot_bodies b on b.id = m.body_id
                  join ai_security_artifacts a on a.id = m.artifact_id
                 where m.run_id = :runId
                   and (:allTypes or b.content_json->>'artifactType' in (:types))
                 order by m.artifact_id, m.observed_at desc, m.id
                """, new MapSqlParameterSource().addValue("runId", runId)
                .addValue("allTypes", policies.stream().anyMatch(policy -> policy.artifactTypes().isEmpty()))
                .addValue("types", policies.stream().flatMap(policy -> policy.artifactTypes().stream()).distinct().toList().isEmpty()
                        ? List.of("__NO_ARTIFACT_TYPE__")
                        : policies.stream().flatMap(policy -> policy.artifactTypes().stream()).distinct().toList()), (rs, n) -> new Artifact(rs.getObject("id", UUID.class),
                rs.getString("artifact_type"), rs.getString("native_kind"), rs.getString("account_id"), rs.getString("region"),
                rs.getString("provider"), rs.getString("name"), rs.getObject("manifest_id", UUID.class)));
        if (artifacts.isEmpty()) return;
        Instant evaluationAsOf = evaluationAsOf(runId);
        RunEvaluationCache cache = new RunEvaluationCache(runId);
        boolean findingChanged = false;
        for (Policy policy : policies) {
            predicates.validate(policy.predicate());
            for (Artifact artifact : artifacts) {
                if (!providerMatches(policy.provider(), artifact.provider())) continue;
                if (!policy.artifactTypes().isEmpty() && !policy.artifactTypes().contains(artifact.artifactType())) continue;
                if (!policy.nativeKinds().isEmpty() && !policy.nativeKinds().contains(artifact.nativeKind())) continue;
                Map<String, Object> effectiveParameters = new LinkedHashMap<>(policy.parameterDefaults());
                effectiveParameters.putAll(parameters.getOrDefault(policy.id(), Map.of()));
                findingChanged |= evaluateSubject(tenant, runId, evaluationAsOf, policy, artifact,
                        scopes.getOrDefault(policy.id(), ScopeConfig.all()),
                        selections.getOrDefault(policy.id(), policy.defaultSelection()), cache,
                        overrides.getOrDefault(policy.id(), Map.of()),
                        effectiveParameters, capabilityIndex);
            }
        }
        if (findingChanged) findings.refreshProjectionAfterCommit(tenant);
    }

    private boolean evaluateSubject(Tenant tenant, UUID runId, Instant evaluationAsOf,
                                    Policy policy, Artifact artifact, ScopeConfig policyScope,
                                    String selection, RunEvaluationCache cache,
                                    Map<String, String> overrides, Map<String, Object> parameters,
                                    Map<AiGridCapabilityService.CapabilityKey, AiGridCapabilityService.CapabilityState> capabilityIndex) {
        boolean inScope = AiSecurityPolicyScopeMatcher.isInScope(policyScope,
                new ArtifactScopeFacts(artifact.provider(), artifact.region(), artifact.accountId(),
                        artifact.artifactType(), artifact.nativeKind(), artifact.name()),
                overrides.get(artifact.id().toString()));
        if (!inScope) {
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, "DISABLED", "NOT_APPLICABLE", "READY", "NO_DECISION",
                    "OUT_OF_SCOPE", List.of(), Map.of());
            return findings.reconcile(tenant, result);
        }
        List<String> capabilityGaps = capabilities.gaps(capabilityIndex, artifact.provider(), artifact.accountId(),
                artifact.region(), policy.requiredCapabilities());
        if (!capabilityGaps.isEmpty()) {
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", "CAPABILITY_UNAVAILABLE", "NO_DECISION",
                    "CAPABILITY_UNAVAILABLE", capabilityGaps, Map.of());
            upsertGap(tenant, runId, artifact.id(), policy.id(), "CAPABILITY_UNAVAILABLE", capabilityGaps,
                    capabilities.remediation(policy.requiredCapabilities()));
            return findings.reconcile(tenant, result);
        }
        List<String> requiredScopes = new ArrayList<>(policy.requiredFamilies());
        if ("NATIVE_KIND_PLUS_STATIC".equals(policy.scopeResolution())) {
            requiredScopes.add(artifact.nativeKind());
        }
        List<String> distinctScopes = requiredScopes.stream().distinct().toList();
        List<String> missingScopes = distinctScopes.isEmpty() ? List.of()
                : missingScopes(artifact, distinctScopes, cache.completedScopes());
        if (!missingScopes.isEmpty()) {
            List<String> missing = missingScopes.stream().map(family -> "scope:" + family).toList();
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", "INCOMPLETE_SCOPE",
                    "NO_DECISION", "INCOMPLETE_SCOPE", missing, Map.of());
            upsertGap(tenant, runId, artifact.id(), policy.id(), "INCOMPLETE_SCOPE", missing);
            return findings.reconcile(tenant, result);
        }
        AiGridGraphEvidenceResolver.DirectEvidence relationships = cache.directEvidence(artifact.id(),
                relationshipTypes(policy), evaluationAsOf);
        if (relationships.status() == AiGridGraphEvidenceResolver.Status.ABSENT) {
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "NOT_APPLICABLE", "READY",
                    "NOT_APPLICABLE", "REQUIRED_RELATIONSHIP_ABSENT", relationships.issues(), Map.of());
            resolveGap(tenant, artifact.id(), policy.id());
            return findings.reconcile(tenant, result);
        }
        if (relationships.status() == AiGridGraphEvidenceResolver.Status.STALE) {
            List<String> missing = relationships.issues().stream().map(type -> "relationship:" + type + ":STALE").toList();
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", "STALE", "NO_DECISION",
                    "STALE_RELATIONSHIP_EVIDENCE", missing, Map.of());
            upsertGap(tenant, runId, artifact.id(), policy.id(), "STALE_EVIDENCE", missing);
            return findings.reconcile(tenant, result);
        }
        Map<String, Fact> availableFacts = cache.facts().getOrDefault(artifact.id(), Map.of());
        List<FactIssue> factIssues = new ArrayList<>();
        Map<String, JsonNode> predicateFacts = new LinkedHashMap<>();
        Map<String, Object> evidence = new LinkedHashMap<>();
        for (FactRequirement requirement : policy.requiredFacts()) {
            Fact fact = availableFacts.get(requirement.factKey());
            if (fact != null) {
                Map<String, Object> factEvidence = new LinkedHashMap<>();
                factEvidence.put("value", fact.value());
                factEvidence.put("state", fact.state());
                factEvidence.put("evidenceClass", fact.evidenceClass());
                factEvidence.put("observedAt", fact.observedAt().toString());
                factEvidence.put("factId", fact.id());
                if (fact.confidence() != null) factEvidence.put("confidence", fact.confidence());
                evidence.put(requirement.factKey(), factEvidence);
            }
            String issue = issue(fact, requirement, evaluationAsOf);
            if (issue != null) {
                factIssues.add(new FactIssue(requirement.factKey(), issue));
                continue;
            }
            predicateFacts.put(requirement.factKey(), fact.value());
        }
        if (!factIssues.isEmpty()) {
            List<String> missing = new ArrayList<>(missingScopes.stream().map(scope -> "scope:" + scope).toList());
            missing.addAll(factIssues.stream().map(issue -> "fact:" + issue.factKey() + ":" + issue.kind()).toList());
            String readiness = readiness(missingScopes, factIssues);
            String decision = factIssues.stream().anyMatch(issue -> "ERROR".equals(issue.kind()))
                    ? "ERROR" : "NO_DECISION";
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", readiness,
                    decision, decision.equals("ERROR") ? "FACT_COLLECTION_ERROR" : readiness, missing, evidence);
            upsertGap(tenant, runId, artifact.id(), policy.id(), gapState(readiness), missing);
            return findings.reconcile(tenant, result);
        }
        DirectDecision direct = directDecision(policy, evaluationAsOf, predicateFacts, parameters, cache.facts(),
                relationships.relationships(), evidence);
        if (direct != null && !"READY".equals(direct.readiness())) {
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", direct.readiness(), direct.decision(),
                    direct.reason(), direct.missing(), evidence);
            upsertGap(tenant, runId, artifact.id(), policy.id(), gapState(direct.readiness()), direct.missing());
            return findings.reconcile(tenant, result);
        }
        boolean failure = direct == null ? evaluatePredicate(policy.predicate(), predicateFacts, parameters) : direct.failure();
        String decision = failure ? "FAIL" : "PASS";
        AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                policy, artifact, selection,
                "APPLICABLE", "READY", decision, failure ? policy.reasonCode() : "CONTROL_SATISFIED",
                List.of(), evidence);
        resolveGap(tenant, artifact.id(), policy.id());
        return findings.reconcile(tenant, result);
    }

    private boolean evaluatePredicate(JsonNode predicate, Map<String, JsonNode> facts, Map<String, Object> parameters) {
        return predicates.evaluate(predicate, facts, parameters);
    }

    private AiGridFindingService.AssessmentResult persist(Tenant tenant, UUID runId, Instant evaluationAsOf,
            Policy policy,
            Artifact artifact, String selection, String applicability, String readiness, String decision,
            String reason, List<String> missing, Map<String, Object> evidence) {
        UUID assessmentId = UUID.randomUUID();
        String findingFingerprint = postureFindingFingerprint(tenant.getId(), policy.id(), artifact.id());
        String decisionFingerprint = decisionFingerprint(policy.version(), decision, evidence);
        UUID persisted = jdbc.queryForObject("""
                insert into ai_grid_assessments (id, tenant_id, run_id, policy_id, policy_version,
                    subject_type, subject_id, snapshot_manifest_id, selection, applicability,
                    evidence_readiness, decision, reason_code, missing_evidence_json, input_facts_json,
                    fingerprint, evaluation_as_of, decision_fingerprint)
                values (:id, :tenantId, :runId, :policyId, :policyVersion, 'ARTIFACT', :subjectId,
                    :manifestId, :selection, :applicability, :readiness, :decision, :reason,
                    cast(:missing as jsonb), cast(:evidence as jsonb), :findingFingerprint,
                    :evaluationAsOf, :decisionFingerprint)
                on conflict (tenant_id, run_id, policy_id, subject_type, subject_id) do update set
                    policy_version = excluded.policy_version, snapshot_manifest_id = excluded.snapshot_manifest_id,
                    selection = excluded.selection, applicability = excluded.applicability,
                    evidence_readiness = excluded.evidence_readiness, decision = excluded.decision,
                    reason_code = excluded.reason_code, missing_evidence_json = excluded.missing_evidence_json,
                    input_facts_json = excluded.input_facts_json, fingerprint = excluded.fingerprint,
                    evaluation_as_of = excluded.evaluation_as_of,
                    decision_fingerprint = excluded.decision_fingerprint,
                    evaluated_at = now()
                returning id
                """, new MapSqlParameterSource().addValue("id", assessmentId).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("policyId", policy.id()).addValue("policyVersion", policy.version())
                .addValue("subjectId", artifact.id()).addValue("manifestId", artifact.manifestId())
                .addValue("selection", selection).addValue("applicability", applicability).addValue("readiness", readiness)
                .addValue("decision", decision).addValue("reason", reason).addValue("missing", json(missing))
                .addValue("evidence", json(evidence)).addValue("findingFingerprint", findingFingerprint)
                .addValue("evaluationAsOf", Timestamp.from(evaluationAsOf))
                .addValue("decisionFingerprint", decisionFingerprint), UUID.class);
        snapshots.outbox(tenant, "ASSESSMENT_COMPLETED", "ASSESSMENT", persisted,
                decisionFingerprint, Map.of("decision", decision, "subjectId", artifact.id(),
                        "decisionFingerprint", decisionFingerprint));
        return new AiGridFindingService.AssessmentResult(persisted, runId, policy.id(), policy.version(), policy.name(),
                policy.severity(), selection, decision, reason, artifact.id(), findingFingerprint, evidence);
    }

    private Instant evaluationAsOf(UUID runId) {
        Instant asOf = jdbc.queryForObject("""
                select max(observed_at) from ai_grid_snapshot_manifests where run_id = :runId
                """, Map.of("runId", runId), (rs, n) -> {
                    Timestamp value = rs.getTimestamp(1);
                    return value == null ? null : value.toInstant();
                });
        if (asOf == null) throw new IllegalArgumentException("AI Grid run has no immutable snapshot");
        return asOf;
    }

    private List<Policy> loadPublishedPolicies(Tenant tenant) {
        return jdbc.query("""
                select distinct on (policy_id)
                       p.policy_id, p.version, p.name, p.severity, coalesce(d.default_selection,p.default_selection) default_selection, p.artifact_types_json::text,
                       native_kinds_json::text, scope_resolution,
                       required_capabilities_json::text, required_relationships_json::text, required_resource_families_json::text,
                       required_facts_json::text, predicate_json::text, parameter_definitions_json::text, reason_code,
                       evaluation_mode,evaluation_definition_json::text,p.provider
                  from platform.ai_grid_policy_versions p
                  join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id and d.available=true
                 where p.lifecycle = 'PUBLISHED'
                   and (d.rollout_stage = 'GENERAL_AVAILABILITY'
                        or (d.rollout_stage = 'CANARY' and jsonb_exists(d.canary_tenant_ids_json, cast(:tenantId as text))))
                 order by p.policy_id, p.published_at desc, p.version desc
                """, Map.of("tenantId", tenant.getId().toString()), (rs, n) -> new Policy(rs.getString("policy_id"), rs.getString("version"), rs.getString("name"),
                rs.getString("severity"), rs.getString("default_selection"), strings(rs.getString("artifact_types_json")),
                strings(rs.getString("native_kinds_json")), rs.getString("scope_resolution"),
                strings(rs.getString("required_capabilities_json")), strings(rs.getString("required_relationships_json")), strings(rs.getString("required_resource_families_json")),
                requirements(rs.getString("required_facts_json")), tree(rs.getString("predicate_json")), defaults(rs.getString("parameter_definitions_json")),
                rs.getString("reason_code"), rs.getString("evaluation_mode"), tree(rs.getString("evaluation_definition_json")), rs.getString("provider")));
    }

    private Map<String, String> loadSelections() {
        return jdbc.query("select policy_id, selection from ai_grid_policy_selections", rs -> {
            Map<String, String> result = new LinkedHashMap<>();
            while (rs.next()) result.putIfAbsent(rs.getString(1), rs.getString(2));
            return result;
        });
    }
    private boolean providerMatches(String policyProvider, String artifactProvider) {
        // Policies authored before the Phase 1 catalog did not declare a provider.  They
        // remain provider-unscoped while the Phase 1 catalog is paused, preserving their
        // pre-catalog evaluation behavior.
        return policyProvider == null || policyProvider.isBlank()
                || "MULTI_CLOUD".equals(policyProvider)
                || policyProvider.equalsIgnoreCase(artifactProvider);
    }

    private Map<String, ScopeConfig> loadScopes() {
        return jdbc.query("""
                select policy_id, mode, condition_logic, conditions_json::text
                  from ai_grid_policy_scopes
                """, rs -> {
            Map<String, ScopeConfig> result = new LinkedHashMap<>();
            while (rs.next()) {
                result.put(rs.getString("policy_id"), scopeConfig(
                        rs.getString("mode"), rs.getString("condition_logic"), rs.getString("conditions_json")));
            }
            return result;
        });
    }

    private ScopeConfig scopeConfig(String mode, String logic, String json) {
        try {
            List<Map<String, Object>> raw = objectMapper.readValue(json, new TypeReference<>() {});
            List<ScopeCondition> conditions = raw.stream()
                    .map(row -> new ScopeCondition(String.valueOf(row.get("field")),
                            String.valueOf(row.get("operator")), String.valueOf(row.get("value"))))
                    .toList();
            return new ScopeConfig(mode, logic, conditions);
        } catch (Exception ex) {
            return ScopeConfig.all();
        }
    }

    private Map<String, Map<String, String>> loadOverrides() {
        return jdbc.query("""
                select policy_id, artifact_id, override
                  from ai_grid_policy_artifact_overrides
                """, rs -> {
            Map<String, Map<String, String>> result = new LinkedHashMap<>();
            while (rs.next()) {
                result.computeIfAbsent(rs.getString("policy_id"), ignored -> new LinkedHashMap<>())
                        .put(rs.getString("artifact_id"), rs.getString("override"));
            }
            return result;
        });
    }

    private Map<String, Map<String, Object>> loadParameters() {
        return jdbc.query("""
                select policy_id, parameters_json::text
                  from ai_grid_policy_parameters
                """, rs -> {
            Map<String, Map<String, Object>> result = new LinkedHashMap<>();
            while (rs.next()) {
                result.put(rs.getString("policy_id"), readMap(rs.getString("parameters_json")));
            }
            return result;
        });
    }
    private List<String> missingScopes(Artifact artifact, List<String> required, Set<ScopeKey> completedScopes) {
        List<String> missing = new ArrayList<>();
        for (String family : required) {
            String region = families.requiredRegion(family, artifact.region()).orElse(null);
            if (region == null) { missing.add(family); continue; }
            if (!completedScopes.contains(new ScopeKey(artifact.accountId(), region, family))) missing.add(family);
        }
        return missing;
    }
    private Map<UUID, Map<String, Fact>> loadFactIndex(UUID runId) {
        Map<UUID, Map<String, Fact>> result = new LinkedHashMap<>();
        jdbc.query("""
                select artifact_id,id, fact_key, value_type, value_json::text, state, evidence_class, observed_at, confidence
                  from ai_grid_facts where run_id = :runId
                 order by artifact_id,fact_key,observed_at desc,id desc
                """, Map.of("runId", runId), rs -> {
            while (rs.next()) result.computeIfAbsent(rs.getObject("artifact_id", UUID.class), ignored -> new LinkedHashMap<>())
                    .putIfAbsent(rs.getString("fact_key"), new Fact(rs.getObject("id", UUID.class),
                    rs.getString("value_type"), tree(rs.getString("value_json")), rs.getString("state"), rs.getString("evidence_class"),
                    rs.getTimestamp("observed_at").toInstant(), (Double) rs.getObject("confidence")));
            return result;
        });
        return result;
    }
    private Set<ScopeKey> loadCompletedScopes(UUID runId) {
        return jdbc.query("""
                select account_id,region,resource_family from ai_security_snapshot_scopes
                 where run_id=:runId and status='COMPLETE'
                """, Map.of("runId", runId), rs -> {
            Set<ScopeKey> result = new HashSet<>();
            while (rs.next()) result.add(new ScopeKey(rs.getString(1), rs.getString(2), rs.getString(3)));
            return Set.copyOf(result);
        });
    }

    /** Evaluates a strictly one-hop source/target posture condition; it never creates exposure state. */
    private DirectDecision directDecision(Policy policy, Instant asOf, Map<String, JsonNode> sourceFacts,
                                          Map<String, Object> parameters,
                                          Map<UUID, Map<String, Fact>> factIndex,
                                          List<AiGridGraphEvidenceResolver.Relationship> relationships,
                                          Map<String, Object> evidence) {
        if (!"DIRECT_RELATIONSHIP".equals(policy.evaluationMode())) return null;
        DirectDefinition definition = directDefinition(policy);
        if (!evaluatePredicate(definition.sourcePredicate(), sourceFacts, parameters)) {
            return DirectDecision.ready(false);
        }
        List<Boolean> targetFailures = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        for (AiGridGraphEvidenceResolver.Relationship relationship : relationships) {
            evidence.put("relationship:" + relationship.id(), Map.of("relationshipId", relationship.id(),
                    "relationshipType", relationship.type(), "targetArtifactId", relationship.targetArtifactId(),
                    "observedAt", relationship.observedAt().toString()));
            Map<String, Fact> targetFacts = factIndex.getOrDefault(relationship.targetArtifactId(), Map.of());
            Map<String, JsonNode> targetPredicateFacts = new LinkedHashMap<>();
            boolean targetReady = true;
            for (FactRequirement requirement : policy.requiredFacts()) {
                Fact targetFact = targetFacts.get(requirement.factKey());
                String issue = issue(targetFact, requirement, asOf);
                if (issue != null) {
                    targetReady = false;
                    missing.add("relationship:" + relationship.id() + ":fact:" + requirement.factKey() + ":" + issue);
                    continue;
                }
                targetPredicateFacts.put(requirement.factKey(), targetFact.value());
                evidence.put("target:" + relationship.targetArtifactId() + ":" + requirement.factKey(), factEvidence(targetFact));
            }
            if (!targetReady) continue;
            targetFailures.add(evaluatePredicate(definition.targetPredicate(), targetPredicateFacts, parameters));
        }
        return decideDirectTargets(targetFailures, missing);
    }

    static DirectDecision decideDirectTargets(List<Boolean> targetFailures, List<String> missing) {
        if (targetFailures.stream().anyMatch(Boolean::booleanValue)) return DirectDecision.ready(true);
        if (!missing.isEmpty()) return new DirectDecision(false, "NO_DECISION", "MISSING_FACTS",
                "DIRECT_RELATIONSHIP_TARGET_UNAVAILABLE", List.copyOf(missing));
        if (!targetFailures.isEmpty()) return DirectDecision.ready(false);
        return new DirectDecision(false, "NO_DECISION", "MISSING_FACTS", "DIRECT_RELATIONSHIP_TARGET_UNAVAILABLE",
                List.of("relationship:target:MISSING"));
    }

    private DirectDefinition directDefinition(Policy policy) {
        JsonNode direct = policy.evaluationDefinition().path("directRelationship");
        JsonNode source = direct.path("sourcePredicate");
        JsonNode target = direct.path("targetPredicate");
        return new DirectDefinition(source.isObject() ? source : policy.predicate(),
                target.isObject() ? target : policy.predicate(), strings(direct.path("edgeConstraints")));
    }

    private List<String> relationshipTypes(Policy policy) {
        if (!"DIRECT_RELATIONSHIP".equals(policy.evaluationMode())) return policy.requiredRelationships();
        List<String> declared = directDefinition(policy).edgeConstraints();
        return declared.isEmpty() ? policy.requiredRelationships() : declared;
    }

    private Map<String, Object> factEvidence(Fact fact) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("value", fact.value()); result.put("state", fact.state()); result.put("evidenceClass", fact.evidenceClass());
        result.put("observedAt", fact.observedAt().toString()); result.put("factId", fact.id());
        if (fact.confidence() != null) result.put("confidence", fact.confidence());
        return result;
    }
    String issue(Fact fact, FactRequirement requirement, Instant evaluationAsOf) {
        if (fact == null || "UNKNOWN".equals(fact.state())) return "MISSING";
        if ("ERROR".equals(fact.state())) return "ERROR";
        if ("STALE".equals(fact.state())) return "STALE";
        if (!requirement.valueType().equals(fact.valueType())
                || !requirement.evidenceClasses().contains(fact.evidenceClass())) return "UNSUPPORTED";
        if (requirement.minConfidence() != null
                && (fact.confidence() == null || fact.confidence() < requirement.minConfidence())) {
            LOG.debug("AI Grid fact {} rejected: confidence {} is below required {}", requirement.factKey(),
                    fact.confidence(), requirement.minConfidence());
            return "LOW_CONFIDENCE";
        }
        long ageSeconds = Math.max(0, Duration.between(fact.observedAt(), evaluationAsOf).getSeconds());
        if (ageSeconds > requirement.maxAgeSeconds()) return "STALE";
        return null;
    }
    private String readiness(List<String> missingScopes, List<FactIssue> issues) {
        if (!missingScopes.isEmpty()) return "INCOMPLETE_SCOPE";
        if (issues.stream().anyMatch(issue -> "ERROR".equals(issue.kind()))) return "COLLECTION_ERROR";
        if (issues.stream().anyMatch(issue -> "STALE".equals(issue.kind()))) return "STALE";
        if (issues.stream().anyMatch(issue -> "LOW_CONFIDENCE".equals(issue.kind()))) return "LOW_CONFIDENCE";
        if (issues.stream().anyMatch(issue -> "UNSUPPORTED".equals(issue.kind()))) return "UNSUPPORTED";
        return "MISSING_FACTS";
    }
    private String gapState(String readiness) {
        return switch (readiness) {
            case "STALE" -> "STALE_EVIDENCE";
            case "UNSUPPORTED" -> "UNSUPPORTED";
            case "LOW_CONFIDENCE" -> "LOW_CONFIDENCE";
            case "COLLECTION_ERROR" -> "COLLECTION_ERROR";
            default -> readiness;
        };
    }
    private void upsertGap(Tenant tenant, UUID runId, UUID artifactId, String policyId, String state, List<String> missing) {
        upsertGap(tenant, runId, artifactId, policyId, state, missing,
                "Restore required permissions or evidence and run a complete reassessment");
    }

    private void upsertGap(Tenant tenant, UUID runId, UUID artifactId, String policyId, String state,
                           List<String> missing, String requiredAction) {
        String fingerprint = sha256(tenant.getId() + "|" + artifactId + "|" + policyId + "|" + state);
        jdbc.update("""
                update ai_grid_coverage_gaps set status = 'RESOLVED', resolved_at = now(), last_observed_at = now()
                 where tenant_id = :tenantId and artifact_id = :artifactId and policy_id = :policyId
                   and state <> :state and status = 'OPEN'
                """, Map.of("tenantId", tenant.getId(), "artifactId", artifactId,
                "policyId", policyId, "state", state));
        jdbc.update("""
                insert into ai_grid_coverage_gaps (id, tenant_id, fingerprint, run_id, artifact_id, policy_id,
                    state, reason, required_action)
                values (:id, :tenantId, :fingerprint, :runId, :artifactId, :policyId, :state, :reason,
                    :requiredAction)
                on conflict (tenant_id, fingerprint) do update set run_id = excluded.run_id,
                    status = 'OPEN', reason = excluded.reason, last_observed_at = now(), resolved_at = null
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("fingerprint", fingerprint).addValue("runId", runId).addValue("artifactId", artifactId)
                .addValue("policyId", policyId).addValue("state", state).addValue("reason", String.join(", ", missing))
                .addValue("requiredAction", requiredAction));
    }
    private void resolveGap(Tenant tenant, UUID artifactId, String policyId) {
        jdbc.update("""
                update ai_grid_coverage_gaps set status = 'RESOLVED', resolved_at = now(), last_observed_at = now()
                 where tenant_id = :tenantId and artifact_id = :artifactId and policy_id = :policyId and status = 'OPEN'
                """, Map.of("tenantId", tenant.getId(), "artifactId", artifactId, "policyId", policyId));
    }

    private List<String> strings(String json) { try { return objectMapper.readValue(json, new TypeReference<>() {}); } catch (Exception e) { throw new IllegalArgumentException("Invalid catalog list", e); } }
    private List<String> strings(JsonNode node) { if (node == null || !node.isArray()) return List.of(); List<String> values = new ArrayList<>(); node.forEach(value -> { if (value.isTextual()) values.add(value.asText()); }); return List.copyOf(values); }
    List<FactRequirement> requirements(String json) { try { return objectMapper.readValue(json, new TypeReference<>() {}); } catch (Exception e) { throw new IllegalArgumentException("Invalid fact requirements", e); } }
    private JsonNode tree(String json) {
        if (json == null || json.isBlank()) return NullNode.getInstance();
        try { return objectMapper.readTree(json); } catch (Exception e) { throw new IllegalArgumentException("Invalid catalog JSON", e); }
    }
    private Map<String, Object> readMap(String json) { try { return objectMapper.readValue(json, new TypeReference<>() {}); } catch (Exception e) { return Map.of(); } }
    private Map<String, Object> defaults(String json) { try { List<Map<String,Object>> definitions=objectMapper.readValue(json,new TypeReference<>() {}); Map<String,Object> result=new LinkedHashMap<>(); definitions.forEach(definition -> { if(definition.get("key") != null && definition.get("defaultValue") != null) result.put(String.valueOf(definition.get("key")), definition.get("defaultValue")); }); return result; } catch(Exception e) { return Map.of(); } }
    private String json(Object value) { try { return objectMapper.writeValueAsString(value); } catch (Exception e) { throw new IllegalArgumentException("Invalid assessment JSON", e); } }
    private String decisionFingerprint(String policyVersion, String decision, Map<String, Object> evidence) {
        Map<String, Object> inputFacts = new TreeMap<>();
        evidence.forEach((key, raw) -> {
            if (raw instanceof Map<?, ?> details) {
                Map<String, Object> decisionMaterial = new TreeMap<>();
                for (String field : List.of("value", "state", "evidenceClass", "observedAt", "confidence", "factId", "relationshipId", "relationshipType", "targetArtifactId")) {
                    if (details.containsKey(field)) decisionMaterial.put(field, details.get(field));
                }
                inputFacts.put(key, decisionMaterial);
            }
        });
        Map<String, Object> material = new TreeMap<>();
        material.put("decision", decision);
        material.put("inputFacts", inputFacts);
        material.put("policyVersion", policyVersion);
        return sha256(json(material));
    }
    private String sha256(String value) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (Exception e) { throw new IllegalStateException("Unable to fingerprint assessment", e); } }

    /**
     * Stable identity of an AI posture finding: tenant + policy + subject artifact.
     * Shared with {@code AiGridPhase1PolicyMigrationService} so that re-keying a legacy
     * finding to its replacement policy yields the exact fingerprint the replacement
     * adapter will compute on its next assessment — the finding is reconciled, not duplicated.
     */
    public static String postureFindingFingerprint(UUID tenantId, String policyId, UUID subjectId) {
        try {
            String value = tenantId + "|AI_POSTURE|" + policyId + "|ARTIFACT|" + subjectId;
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to fingerprint AI posture finding", e);
        }
    }

    private final class RunEvaluationCache {
        private final UUID runId;
        private Map<UUID, Map<String, Fact>> facts;
        private Set<ScopeKey> completedScopes;
        private AiGridGraphEvidenceResolver.DirectIndex directRelationships;

        private RunEvaluationCache(UUID runId) { this.runId = runId; }
        Map<UUID, Map<String, Fact>> facts() {
            if (facts == null) facts = loadFactIndex(runId);
            return facts;
        }
        Set<ScopeKey> completedScopes() {
            if (completedScopes == null) completedScopes = loadCompletedScopes(runId);
            return completedScopes;
        }
        AiGridGraphEvidenceResolver.DirectEvidence directEvidence(UUID sourceArtifactId, List<String> requiredTypes, Instant asOf) {
            if (requiredTypes == null || requiredTypes.isEmpty()) return graphEvidence.resolveDirect(runId, sourceArtifactId, requiredTypes, asOf);
            if (directRelationships == null) directRelationships = graphEvidence.directIndexForRun(runId, asOf);
            return graphEvidence.resolveDirect(directRelationships, sourceArtifactId, requiredTypes, asOf);
        }
    }

    private record Policy(String id, String version, String name, String severity, String defaultSelection,
                          List<String> artifactTypes, List<String> nativeKinds, String scopeResolution,
                          List<String> requiredCapabilities, List<String> requiredRelationships, List<String> requiredFamilies,
                          List<FactRequirement> requiredFacts, JsonNode predicate, Map<String,Object> parameterDefaults, String reasonCode,
                          String evaluationMode, JsonNode evaluationDefinition, String provider) {}
    private record DirectDefinition(JsonNode sourcePredicate, JsonNode targetPredicate, List<String> edgeConstraints) {}
    record DirectDecision(boolean failure, String decision, String readiness, String reason, List<String> missing) {
        static DirectDecision ready(boolean failure) { return new DirectDecision(failure, failure ? "FAIL" : "PASS", "READY", "", List.of()); }
    }
    public record FactRequirement(String factKey, String valueType, Set<String> evidenceClasses,
                                  long maxAgeSeconds, Double minConfidence) {}
    private record FactIssue(String factKey, String kind) {}
    private record Artifact(UUID id, String artifactType, String nativeKind, String accountId, String region,
                            String provider, String name, UUID manifestId) {}
    private record ScopeKey(String accountId, String region, String resourceFamily) {}
    record Fact(UUID id, String valueType, JsonNode value, String state, String evidenceClass,
                Instant observedAt, Double confidence) {}
}
