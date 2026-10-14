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

    private org.springframework.transaction.support.TransactionTemplate isolated;
    private com.prototype.vulnwatch.service.AuditEventService audit;

    @org.springframework.beans.factory.annotation.Autowired
    void configureIsolation(org.springframework.transaction.PlatformTransactionManager manager,
                            com.prototype.vulnwatch.service.AuditEventService audit) {
        isolated = new org.springframework.transaction.support.TransactionTemplate(manager);
        isolated.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.audit = audit;
    }

    public AssessmentSummary evaluateCurrent(Tenant tenant, UUID runId, Set<String> policyIds, Runnable deliveryGuard) {
        return evaluateIsolated(tenant, runId, policyIds, true, deliveryGuard);
    }

    private AssessmentSummary evaluateIsolated(Tenant tenant, UUID runId, Set<String> filter,
                                               boolean current, Runnable deliveryGuard) {
        List<String> policyIds = jdbc.query("select policy_id from " + AiGridPolicyResolution.versions(":tenantId")
                + " p where policy_id not in ('AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL',"
                + "'AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL') order by policy_id",
                Map.of("tenantId", tenant.getId()), (rs, row) -> rs.getString(1));
        int subjects = 0;
        int evaluated = 0;
        List<PolicyFailure> failures = new ArrayList<>();
        for (String policyId : policyIds) {
            if (filter != null && !filter.isEmpty() && !filter.contains(policyId)) continue;
            try {
                // Provider/type filtering happens before creating a policy persistence context.
                Integer applicable = jdbc.queryForObject("""
                        select count(*) from %s m join ai_grid_snapshot_bodies b on b.id=m.body_id
                          join ai_security_artifacts a on a.id=m.artifact_id
                          join %s p on p.policy_id=:policyId
                         where (:current or m.run_id=:runId)
                           and (p.provider is null or p.provider in ('','ANY','MULTI_CLOUD') or p.provider=a.provider)
                           and (jsonb_array_length(p.artifact_types_json)=0
                                or jsonb_exists(p.artifact_types_json,b.content_json->>'artifactType'))
                           and (jsonb_array_length(p.native_kinds_json)=0
                                or jsonb_exists(p.native_kinds_json,b.content_json->>'nativeKind'))
                        """.formatted(current ? "(" + AiGridCurrentEvidence.MANIFESTS + ")" : "ai_grid_snapshot_manifests",
                        AiGridPolicyResolution.versions(":tenantId")),
                        new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("policyId", policyId)
                                .addValue("runId", runId).addValue("current", current), Integer.class);
                if (applicable == null || applicable == 0) continue;
                Integer count = isolated.execute(status -> {
                    lockTenant(tenant);
                    deliveryGuard.run();
                    return evaluatePolicyRun(tenant, runId, Set.of(policyId), current);
                });
                subjects += count == null ? 0 : count;
                evaluated++;
                if (current) isolated.executeWithoutResult(status -> {
                    lockTenant(tenant);
                    deliveryGuard.run();
                    jdbc.update("delete from ai_grid_assessments where policy_id=:policyId and subject_type='POLICY' and reason_code='POLICY_EVALUATION_ERROR'",Map.of("policyId",policyId));
                    jdbc.update("update ai_grid_coverage_gaps set status='RESOLVED',resolved_at=now() "
                            + "where policy_id=:policyId and artifact_id is null and state='POLICY_EVALUATION_ERROR'",
                            Map.of("policyId", policyId));
                });
            } catch (RuntimeException error) {
                if (error instanceof AiGridAssessmentWorker.LeaseLostException) throw error;
                PolicyFailure failure = PolicyFailure.from(policyId, error);
                failures.add(failure);
                isolated.executeWithoutResult(status -> {
                    lockTenant(tenant);
                    deliveryGuard.run();
                    if (current) recordFailure(tenant, runId, failure);
                    else audit.recordExplicitActor(tenant.getId(),"ai-grid-assessment","SYSTEM","ai_grid.policy.historical_evaluation_failed",
                            "ai_security_policy",policyId,json(failure),"FAILURE");
                });
            }
        }
        return new AssessmentSummary(evaluated, subjects, List.copyOf(failures));
    }

    void lockTenant(Tenant tenant) {
        jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))",
                Map.of("tenantId", tenant.getId()), rs -> null);
    }

    void recordFailure(Tenant tenant, UUID runId, PolicyFailure failure) {
        String fingerprint = sha256(tenant.getId() + "|POLICY_EVALUATION_ERROR|" + failure.policyId());
        jdbc.update("""
                insert into ai_grid_coverage_gaps(id,tenant_id,fingerprint,run_id,policy_id,state,reason,required_action)
                values (:id,:tenantId,:fingerprint,:runId,:policyId,'POLICY_EVALUATION_ERROR',:reason,
                        'Repair the policy configuration or retry the assessment request')
                on conflict(tenant_id,fingerprint) do update set run_id=excluded.run_id,status='OPEN',
                    reason=excluded.reason,last_observed_at=now(),resolved_at=null
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("fingerprint", fingerprint).addValue("runId", runId).addValue("policyId", failure.policyId())
                .addValue("reason", failure.summary()));
        jdbc.update("""
                insert into ai_grid_assessments(id,tenant_id,run_id,policy_id,policy_version,subject_type,subject_id,
                    selection,applicability,evidence_readiness,decision,reason_code,missing_evidence_json,
                    input_facts_json,fingerprint,evaluation_as_of,decision_fingerprint)
                select :id,:tenantId,:runId,p.policy_id,p.version,'POLICY',:subjectId,
                    case when s.configuration_source='TENANT_OVERRIDE' then s.selection else p.resolved_default_selection end,
                    'APPLICABLE','COLLECTION_ERROR','ERROR','POLICY_EVALUATION_ERROR','["POLICY_EVALUATION_ERROR"]'::jsonb,
                    '{}'::jsonb,:fingerprint,now(),:fingerprint
                  from %s p left join ai_grid_policy_selections s on s.policy_id=p.policy_id where p.policy_id=:policyId
                on conflict(tenant_id,run_id,policy_id,subject_type,subject_id,fingerprint) do update set
                    decision='ERROR',reason_code='POLICY_EVALUATION_ERROR',evaluated_at=now(),evaluation_as_of=now()
                """.formatted(AiGridPolicyResolution.versions(":tenantId")),
                new MapSqlParameterSource().addValue("id",UUID.randomUUID()).addValue("tenantId",tenant.getId())
                .addValue("runId",runId).addValue("policyId",failure.policyId()).addValue("fingerprint",fingerprint)
                .addValue("subjectId",UUID.nameUUIDFromBytes(failure.policyId().getBytes(StandardCharsets.UTF_8))));
        audit.recordExplicitActor(tenant.getId(), "ai-grid-assessment", "SYSTEM", "ai_grid.policy.evaluation_failed",
                "ai_security_policy", failure.policyId(), json(failure), "FAILURE");
    }

    void withdrawPolicy(Tenant tenant,String policyId) { findings.closeForPolicy(tenant,policyId); }

    public void preflight(Tenant tenant, String policyId, Map<String, Object> proposedParameters) {
        try {
            Policy policy = loadPublishedPolicies(tenant, Set.of(policyId)).stream().findFirst().orElseThrow(
                    () -> new IllegalArgumentException("Distributed policy is unavailable"));
            if (!"CORRELATION_PATH".equals(policy.evaluationMode())) {
                predicates.validate(policy.predicate());
                if ("DIRECT_RELATIONSHIP".equals(policy.evaluationMode())) {
                    predicates.validate(directDefinition(policy).sourcePredicate());
                    predicates.validate(directDefinition(policy).targetPredicate());
                }
                Map<String,Object> overrides=new LinkedHashMap<>(loadParameters(Set.of(policyId)).getOrDefault(policyId,Map.of()));
                if (proposedParameters!=null) overrides.putAll(proposedParameters);
                Map<String,Object> parameters=effectiveParameters(policy,overrides);
                predicates.validateParameters(policy.predicate(), parameters);
            }
        } catch (IllegalArgumentException error) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST, "Policy configuration cannot evaluate: " + error.getMessage());
        }
    }

    public record PolicyFailure(String policyId, String code, String summary, boolean retryable) {
        static PolicyFailure from(String policyId, RuntimeException error) {
            String code = AiGridAssessmentWorker.retryable(error) ? "TRANSIENT_DATABASE_FAILURE" :
                    error instanceof IllegalArgumentException ? "INVALID_POLICY_CONFIGURATION" : "POLICY_EVALUATION_ERROR";
            return new PolicyFailure(policyId, code, "Policy evaluation failed (" + code + ")", AiGridAssessmentWorker.retryable(error));
        }
    }
    public record AssessmentSummary(int evaluatedPolicies, int assessedSubjects, List<PolicyFailure> failures) {
        public int failedPolicies() { return failures.size(); }
        public String assessmentStatus() {
            return failures.isEmpty() ? "COMPLETE" : evaluatedPolicies > 0 ? "PARTIAL" : "FAILED";
        }
    }

    public void evaluateRun(Tenant tenant, UUID runId) {
        evaluateRun(tenant, runId, Set.of());
    }

    /** Historical replay retains captured time and cannot reconcile current findings. */
    public int evaluateRun(Tenant tenant, UUID runId, Set<String> policyIds) {
        return evaluateIsolated(tenant, runId, policyIds, true, () -> {}).assessedSubjects();
    }

    public int evaluateHistorical(Tenant tenant, UUID runId) {
        return evaluateIsolated(tenant,runId,Set.of(),false,() -> {}).assessedSubjects();
    }

    private int evaluatePolicyRun(Tenant tenant, UUID runId, Set<String> policyIds, boolean current) {
        List<Policy> policies = loadPublishedPolicies(tenant, policyIds);
        // Runtime policies have an EXECUTION subject and read the runtime metadata tables, not
        // snapshot facts. Evaluating them in the artifact loop would bind them to the wrong
        // subject and run their predicate through the leaf fact engine.
        policies = policies.stream().filter(policy -> !isRuntimeMode(policy.evaluationMode()))
                // Baseline approvals can change after immutable snapshot facts were committed.
                // Their current-state evaluator owns reconciliation and stable finding identity.
                .filter(policy -> !"AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL".equals(policy.id())
                        && !"AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL".equals(policy.id())).toList();
        Map<String, ScopeConfig> scopes = loadScopes(policyIds);
        Map<String, Map<String, String>> overrides = loadOverrides();
        Map<String, Map<String, Object>> parameters = loadParameters(policyIds);
        Map<String, String> selections = loadSelections();
        Map<AiGridCapabilityService.CapabilityKey, AiGridCapabilityService.CapabilityState> capabilityIndex = current ? capabilities.latestIndex() : capabilities.forRun(runId);
        List<Artifact> artifacts = jdbc.query("""
                select distinct on (m.artifact_id)
                       m.artifact_id id,
                       b.content_json->>'artifactType' artifact_type,
                       b.content_json->>'nativeKind' native_kind,
                       b.content_json->>'accountId' account_id,
                       b.content_json->>'region' region,
                       a.provider,
                       a.name,
                       m.id manifest_id, m.run_id source_run_id
                  from %s m
                  join ai_grid_snapshot_bodies b on b.id = m.body_id
                  join ai_security_artifacts a on a.id = m.artifact_id
                 where (:current or m.run_id = :runId)
                   and (:allTypes or b.content_json->>'artifactType' in (:types))
                 order by m.artifact_id, m.observed_at desc, m.id
                """.formatted(current ? "(" + AiGridCurrentEvidence.MANIFESTS + ")" : "ai_grid_snapshot_manifests"), new MapSqlParameterSource().addValue("runId", runId).addValue("current", current)
                .addValue("allTypes", policies.stream().anyMatch(policy -> policy.artifactTypes().isEmpty()))
                .addValue("types", policies.stream().flatMap(policy -> policy.artifactTypes().stream()).distinct().toList().isEmpty()
                        ? List.of("__NO_ARTIFACT_TYPE__")
                        : policies.stream().flatMap(policy -> policy.artifactTypes().stream()).distinct().toList()), (rs, n) -> new Artifact(rs.getObject("id", UUID.class),
                rs.getString("artifact_type"), rs.getString("native_kind"), rs.getString("account_id"), rs.getString("region"),
                rs.getString("provider"), rs.getString("name"), rs.getObject("manifest_id", UUID.class), rs.getObject("source_run_id", UUID.class)));
        if (artifacts.isEmpty()) return 0;
        Instant evaluationAsOf = current ? Instant.now() : evaluationAsOf(runId);
        RunEvaluationCache cache = new RunEvaluationCache(runId, current);
        boolean findingChanged = false;
        int assessedSubjects = 0;
        for (Policy policy : policies) {
            // Correlation-path policies are evaluated by the graph evidence resolver and
            // intentionally have no artifact predicate. Only artifact-fact policies require
            // validation by the leaf predicate engine.
            if (!"CORRELATION_PATH".equals(policy.evaluationMode())) {
                predicates.validateParameters(policy.predicate(), effectiveParameters(policy,parameters.getOrDefault(policy.id(),Map.of())));
            }
            for (Artifact artifact : artifacts) {
                if (!providerMatches(policy.provider(), artifact.provider())) continue;
                if (!policy.artifactTypes().isEmpty() && !policy.artifactTypes().contains(artifact.artifactType())) continue;
                if (!policy.nativeKinds().isEmpty() && !policy.nativeKinds().contains(artifact.nativeKind())) continue;
                Map<String, Object> effectiveParameters = effectiveParameters(policy,parameters.getOrDefault(policy.id(),Map.of()));
                assessedSubjects++;
                findingChanged |= evaluateSubject(tenant, current ? artifact.sourceRunId() : runId, evaluationAsOf, policy, artifact,
                        scopes.getOrDefault(policy.id(), ScopeConfig.all()),
                        selections.getOrDefault(policy.id(), policy.defaultSelection()), cache,
                        overrides.getOrDefault(policy.id(), Map.of()),
                        effectiveParameters, capabilityIndex);
            }
        }

        return assessedSubjects;
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
            return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
        }
        List<String> capabilityGaps = capabilities.gaps(capabilityIndex, artifact.provider(), artifact.accountId(),
                artifact.region(), policy.requiredCapabilities(),evaluationAsOf);
        if (!capabilityGaps.isEmpty()) {
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", "CAPABILITY_UNAVAILABLE", "NO_DECISION",
                    "CAPABILITY_UNAVAILABLE", capabilityGaps, Map.of());
            if (cache.current) upsertGap(tenant, runId, artifact.id(), policy.id(), "CAPABILITY_UNAVAILABLE", capabilityGaps,
                    capabilities.remediation(policy.requiredCapabilities()));
            return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
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
            if (cache.current) upsertGap(tenant, runId, artifact.id(), policy.id(), "INCOMPLETE_SCOPE", missing);
            return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
        }
        if (cache.current) {
            Map<String,Object> scopeAges=new LinkedHashMap<>();
            List<String> staleScopes=new ArrayList<>();
            for (String family:distinctScopes) {
                String region=families.requiredRegion(family,artifact.region()).orElse(artifact.region());
                Instant observed=cache.scopeObservedAt(new ScopeKey(artifact.provider(),artifact.accountId(),region,family));
                if (observed!=null && observed.plusSeconds(86400).isBefore(evaluationAsOf)) {
                    staleScopes.add("scope:"+family+":STALE");
                    scopeAges.put("scope:"+family,Map.of("observedAt",observed.toString(),"ageSeconds",Math.max(0,Duration.between(observed,evaluationAsOf).getSeconds())));
                }
            }
            if (!staleScopes.isEmpty()) {
                var result=persist(tenant,runId,evaluationAsOf,policy,artifact,selection,"APPLICABLE","STALE","NO_DECISION","STALE_SCOPE_EVIDENCE",staleScopes,scopeAges);
                upsertGap(tenant,runId,artifact.id(),policy.id(),"STALE_EVIDENCE",staleScopes);
                return findings.reconcile(tenant,result);
            }
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
                factEvidence.put("ageSeconds",Math.max(0,Duration.between(fact.observedAt(),evaluationAsOf).getSeconds()));
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
            if (cache.current) upsertGap(tenant, runId, artifact.id(), policy.id(), gapState(readiness), missing);
            return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
        }
        // Graph access is deliberately after capability and fact readiness. A
        // posture policy with no relationship contract must not pay for a graph
        // query, and an unavailable capability must never trigger traversal.
        AiGridGraphEvidenceResolver.DirectEvidence relationships = policy.requiredRelationships().isEmpty()
                ? AiGridGraphEvidenceResolver.DirectEvidence.ready(List.of())
                : cache.directEvidence(artifact.id(), relationshipTypes(policy), evaluationAsOf);
        if (relationships.status() == AiGridGraphEvidenceResolver.Status.ABSENT) {
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "NOT_APPLICABLE", "READY",
                    "NOT_APPLICABLE", "REQUIRED_RELATIONSHIP_ABSENT", relationships.issues(), Map.of());
            if (cache.current) resolveGap(tenant, artifact.id(), policy.id());
            return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
        }
        if (relationships.status() == AiGridGraphEvidenceResolver.Status.STALE) {
            List<String> missing = relationships.issues().stream().map(type -> "relationship:" + type + ":STALE").toList();
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", "STALE", "NO_DECISION",
                    "STALE_RELATIONSHIP_EVIDENCE", missing, Map.of());
            if (cache.current) upsertGap(tenant, runId, artifact.id(), policy.id(), "STALE_EVIDENCE", missing);
            return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
        }
        DirectDecision direct = directDecision(policy, evaluationAsOf, predicateFacts, parameters, cache.facts(),
                relationships.relationships(), evidence);
        if (direct != null && !"READY".equals(direct.readiness())) {
            AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                    policy, artifact, selection, "APPLICABLE", direct.readiness(), direct.decision(),
                    direct.reason(), direct.missing(), evidence);
            if (cache.current) upsertGap(tenant, runId, artifact.id(), policy.id(), gapState(direct.readiness()), direct.missing());
            return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
        }
        boolean failure = direct == null ? evaluatePredicate(policy.predicate(), predicateFacts, parameters,evaluationAsOf) : direct.failure();
        String decision = failure ? "FAIL" : "PASS";
        AiGridFindingService.AssessmentResult result = persist(tenant, runId, evaluationAsOf,
                policy, artifact, selection,
                "APPLICABLE", "READY", decision, failure ? policy.reasonCode() : "CONTROL_SATISFIED",
                List.of(), evidence);
        if (cache.current) resolveGap(tenant, artifact.id(), policy.id());
        return cache.current && !"SUPERSEDED".equals(result.reasonCode()) && findings.reconcile(tenant, result);
    }

    private Map<String,Object> effectiveParameters(Policy policy,Map<String,Object> overrides) {
        Map<String,Object> values=new LinkedHashMap<>(policy.parameterDefaults());
        overrides.forEach((key,value) -> {
            Object baseline=values.get(key);
            if (value instanceof String text && baseline instanceof Number) {
                try { value=new java.math.BigDecimal(text); }
                catch (NumberFormatException error) { throw new IllegalArgumentException("Invalid numeric policy parameter: " + key); }
            }
            if (value instanceof String text && baseline instanceof Boolean) {
                if (!text.equalsIgnoreCase("true") && !text.equalsIgnoreCase("false")) throw new IllegalArgumentException("Invalid boolean policy parameter: " + key);
                value=Boolean.valueOf(text);
            }
            values.put(key,value);
        });
        return values;
    }

    private boolean evaluatePredicate(JsonNode predicate, Map<String, JsonNode> facts, Map<String, Object> parameters,Instant evaluationAsOf) {
        return predicates.evaluate(predicate, facts, parameters,evaluationAsOf);
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
                on conflict (tenant_id, run_id, policy_id, subject_type, subject_id, fingerprint) do update set
                    policy_version = excluded.policy_version, snapshot_manifest_id = excluded.snapshot_manifest_id,
                    selection = excluded.selection, applicability = excluded.applicability,
                    evidence_readiness = excluded.evidence_readiness, decision = excluded.decision,
                    reason_code = excluded.reason_code, missing_evidence_json = excluded.missing_evidence_json,
                    input_facts_json = excluded.input_facts_json, fingerprint = excluded.fingerprint,
                    evaluation_as_of = excluded.evaluation_as_of,
                    decision_fingerprint = excluded.decision_fingerprint,
                    evaluated_at = now()
                where ai_grid_assessments.evaluation_as_of <= excluded.evaluation_as_of
                returning id
                """, new MapSqlParameterSource().addValue("id", assessmentId).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("policyId", policy.id()).addValue("policyVersion", policy.version())
                .addValue("subjectId", artifact.id()).addValue("manifestId", artifact.manifestId())
                .addValue("selection", selection).addValue("applicability", applicability).addValue("readiness", readiness)
                .addValue("decision", decision).addValue("reason", reason).addValue("missing", json(missing))
                .addValue("evidence", json(evidence)).addValue("findingFingerprint", findingFingerprint)
                .addValue("evaluationAsOf", Timestamp.from(evaluationAsOf))
                .addValue("decisionFingerprint", decisionFingerprint), UUID.class);
        if (persisted == null) return new AiGridFindingService.AssessmentResult(assessmentId, runId, policy.id(), policy.version(), policy.name(), policy.severity(), "PREVIEW", "NO_DECISION", "SUPERSEDED", artifact.id(), findingFingerprint, evidence);
        snapshots.outbox(tenant, "ASSESSMENT_COMPLETED", "ASSESSMENT", persisted,
                decisionFingerprint, Map.of("decision", decision, "subjectId", artifact.id(),
                        "decisionFingerprint", decisionFingerprint));
        return new AiGridFindingService.AssessmentResult(persisted, runId, policy.id(), policy.version(), policy.name(),
                policy.severity(), selection, decision, reason, artifact.id(), findingFingerprint, evidence);
    }

    static boolean isRuntimeMode(String evaluationMode) {
        return "RUNTIME_FACTS".equals(evaluationMode)
                || "RUNTIME_SEQUENCE".equals(evaluationMode)
                || "RUNTIME_AGGREGATE".equals(evaluationMode)
                || "RUNTIME_COVERAGE".equals(evaluationMode);
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

    private List<Policy> loadPublishedPolicies(Tenant tenant, Set<String> policyIds) {
        return jdbc.query("""
                select distinct on (policy_id)
                       p.policy_id, p.version, p.name, p.severity, coalesce(d.default_selection,p.default_selection) default_selection, p.artifact_types_json::text,
                       native_kinds_json::text, scope_resolution,
                       required_capabilities_json::text, required_relationships_json::text, required_resource_families_json::text,
                       required_facts_json::text, predicate_json::text, parameter_definitions_json::text, reason_code,
                       evaluation_mode,evaluation_definition_json::text,p.provider
                  from %s p
                  join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id and d.available=true
                where p.policy_id in (:policyIds)
                   and (p.release_family is null or p.release_family in ('AGCF_PHASE_1','AGCF_PHASE_2'))
                   and p.lifecycle in ('VALIDATED', 'APPROVED', 'PUBLISHED', 'CANARY')
                   and platform.ai_grid_policy_visible_to_tenant(
                           d.available, d.rollout_stage, d.canary_tenant_ids_json, cast(:tenantId as uuid))
                 order by p.policy_id, p.published_at desc, p.version desc
                """.formatted(AiGridPolicyResolution.versions(":tenantId")), Map.of("tenantId", tenant.getId().toString(), "policyIds", policyIds), (rs, n) -> new Policy(rs.getString("policy_id"), rs.getString("version"), rs.getString("name"),
                rs.getString("severity"), rs.getString("default_selection"), strings(rs.getString("artifact_types_json")),
                strings(rs.getString("native_kinds_json")), rs.getString("scope_resolution"),
                strings(rs.getString("required_capabilities_json")), strings(rs.getString("required_relationships_json")), strings(rs.getString("required_resource_families_json")),
                requirements(rs.getString("required_facts_json")), tree(rs.getString("predicate_json")), defaults(rs.getString("parameter_definitions_json")),
                rs.getString("reason_code"), rs.getString("evaluation_mode"), tree(rs.getString("evaluation_definition_json")), rs.getString("provider")));
    }

    private Map<String, String> loadSelections() {
        return jdbc.query("select policy_id, selection from ai_grid_policy_selections where configuration_source='TENANT_OVERRIDE'", rs -> {
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
                || "ANY".equals(policyProvider) || "MULTI_CLOUD".equals(policyProvider)
                || policyProvider.equalsIgnoreCase(artifactProvider);
    }

    private Map<String, ScopeConfig> loadScopes(Set<String> policyIds) {
        return jdbc.query("""
                select policy_id, mode, condition_logic, conditions_json::text
                  from ai_grid_policy_scopes where policy_id in (:policyIds)
                """, Map.of("policyIds", policyIds), rs -> {
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
            throw new IllegalArgumentException("Invalid policy scope configuration",ex);
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

    private Map<String, Map<String, Object>> loadParameters() { return loadParameters(Set.of()); }
    private Map<String, Map<String, Object>> loadParameters(Set<String> policyIds) {
        return jdbc.query("""
                select policy_id, parameters_json::text
                  from ai_grid_policy_parameters where (:allPolicies or policy_id in (:policyIds))
                """, Map.of("allPolicies", policyIds.isEmpty(), "policyIds", policyIds.isEmpty() ? Set.of("__NONE__") : policyIds), rs -> {
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
            if (!completedScopes.contains(new ScopeKey(artifact.provider(),artifact.accountId(), region, family))) missing.add(family);
        }
        return missing;
    }
    private Map<UUID, Map<String, Fact>> loadFactIndex(UUID runId, boolean current) {
        Map<UUID, Map<String, Fact>> result = new LinkedHashMap<>();
        jdbc.query("""
                select artifact_id,id, fact_key, value_type, value_json::text, state, evidence_class, observed_at, confidence, valid_until
                  from ai_grid_facts where %s
                 order by artifact_id,fact_key,observed_at desc,id desc
                """.formatted(current ? "snapshot_manifest_id in (select id from (" + AiGridCurrentEvidence.SCOPE_MANIFESTS + ") heads)" : "run_id=:runId"), Map.of("runId", runId), rs -> {
            while (rs.next()) result.computeIfAbsent(rs.getObject("artifact_id", UUID.class), ignored -> new LinkedHashMap<>())
                    .putIfAbsent(rs.getString("fact_key"), new Fact(rs.getObject("id", UUID.class),
                    rs.getString("value_type"), tree(rs.getString("value_json")), rs.getString("state"), rs.getString("evidence_class"),
                    rs.getTimestamp("observed_at").toInstant(), (Double) rs.getObject("confidence"),
                    rs.getTimestamp("valid_until")==null ? null : rs.getTimestamp("valid_until").toInstant()));
            return result;
        });
        return result;
    }
    private Map<ScopeKey,Instant> loadScopeTimes(UUID runId,boolean current) {
        return jdbc.query("""
                select provider,account_id,region,resource_family,completed_at from %s scope
                 where (:current or run_id=:runId) and status='COMPLETE'
                """.formatted(current ? "(select distinct on(scope_key) * from ai_security_snapshot_scopes where status='COMPLETE' order by scope_key,completed_at desc nulls last,run_id desc)" : "ai_security_snapshot_scopes"),
                Map.of("runId",runId,"current",current),rs -> {
            Map<ScopeKey,Instant> result=new LinkedHashMap<>();
            while (rs.next()) {
                Timestamp completed=rs.getTimestamp(5);
                result.merge(new ScopeKey(rs.getString(1),rs.getString(2),rs.getString(3),rs.getString(4)),completed==null ? Instant.MIN : completed.toInstant(),
                        (left,right) -> left.isAfter(right) ? left : right);
            }
            return result;
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
        if (!evaluatePredicate(definition.sourcePredicate(), sourceFacts, parameters,asOf)) {
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
            targetFailures.add(evaluatePredicate(definition.targetPredicate(), targetPredicateFacts, parameters,asOf));
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
        if (fact.observedAt().isAfter(evaluationAsOf) || (fact.validUntil()!=null && fact.validUntil().isBefore(evaluationAsOf))) return "STALE";
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
     * Stable across re-assessment so an existing posture finding is reconciled rather
     * than duplicated when its policy is evaluated again.
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
        private final boolean current;
        private Map<UUID, Map<String, Fact>> facts;
        private Map<ScopeKey,Instant> scopeTimes;
        private AiGridGraphEvidenceResolver.DirectIndex directRelationships;

        private RunEvaluationCache(UUID runId, boolean current) { this.runId = runId; this.current = current; }
        Map<UUID, Map<String, Fact>> facts() {
            if (facts == null) facts = loadFactIndex(runId, current);
            return facts;
        }
        Set<ScopeKey> completedScopes() {
            if (scopeTimes==null) scopeTimes=loadScopeTimes(runId,current);
            return scopeTimes.keySet();
        }
        Instant scopeObservedAt(ScopeKey scope) { completedScopes(); return scopeTimes.get(scope); }
        AiGridGraphEvidenceResolver.DirectEvidence directEvidence(UUID sourceArtifactId, List<String> requiredTypes, Instant asOf) {
            if (requiredTypes == null || requiredTypes.isEmpty()) return graphEvidence.resolveDirect(runId, sourceArtifactId, requiredTypes, asOf);
            if (directRelationships == null) directRelationships = current ? graphEvidence.directIndexForCurrent(asOf) : graphEvidence.directIndexForRun(runId, asOf);
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
                            String provider, String name, UUID manifestId, UUID sourceRunId) {}
    private record ScopeKey(String provider,String accountId, String region, String resourceFamily) {}
    record Fact(UUID id, String valueType, JsonNode value, String state, String evidenceClass,
                Instant observedAt, Double confidence, Instant validUntil) {
        Fact(UUID id,String valueType,JsonNode value,String state,String evidenceClass,Instant observedAt,Double confidence) {
            this(id,valueType,value,state,evidenceClass,observedAt,confidence,null);
        }
    }
}
