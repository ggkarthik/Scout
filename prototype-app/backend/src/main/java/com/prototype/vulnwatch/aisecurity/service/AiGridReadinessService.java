package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Separates tenant policy selection from evidence readiness and produces a prioritized setup queue. */
@Service
public class AiGridReadinessService {
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiGridCoverageService coverage;

    public AiGridReadinessService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                  TenantSchemaExecutionService tenantExecution,
                                  AiGridCoverageService coverage) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.tenantExecution = tenantExecution;
        this.coverage = coverage;
    }

    public void compute(Tenant tenant, UUID runId) {
        compute(tenant, runId, null, coverage.expectedCandidates(runId));
    }

    public void compute(Tenant tenant, UUID runId,
                        List<AiGridCoverageService.CoverageItem> candidates) {
        compute(tenant, runId, null, candidates);
    }

    public void computeCurrent(Tenant tenant, UUID epochId, UUID triggerRunId) {
        compute(tenant, triggerRunId, epochId, coverage.currentCandidates());
    }

    private void compute(Tenant tenant, UUID runId, UUID epochId,
                         List<AiGridCoverageService.CoverageItem> candidates) {
        List<PolicySpec> policies = jdbc.query("""
                select distinct on (p.policy_id) p.policy_id, p.version,
                       coalesce(s.selection, p.default_selection) selection,
                       p.required_facts_json::text
                  from platform.ai_grid_policy_versions p
                  left join ai_grid_policy_selections s on s.policy_id = p.policy_id
                 where p.lifecycle = 'PUBLISHED'
                 order by p.policy_id, p.published_at desc, p.version desc
                """, (rs, n) -> new PolicySpec(rs.getString("policy_id"), rs.getString("version"),
                rs.getString("selection"), rs.getString("required_facts_json")));
        Map<UUID, AssessmentState> assessments = new HashMap<>();
        candidates.stream().filter(AiGridCoverageService.CoverageItem::assessmentPresent).forEach(candidate ->
                assessments.put(candidate.assessmentId(), new AssessmentState(candidate.applicability(),
                        candidate.decision(), tree(candidate.missingEvidenceJson()), tree(candidate.inputFactsJson()))));
        Map<String, List<AiGridCoverageService.CoverageItem>> byPolicy = new HashMap<>();
        for (AiGridCoverageService.CoverageItem candidate : candidates) {
            byPolicy.computeIfAbsent(candidate.policyId(), ignored -> new ArrayList<>()).add(candidate);
        }

        for (PolicySpec policy : policies) {
            List<AiGridCoverageService.CoverageItem> policyCandidates = byPolicy.getOrDefault(policy.id(), List.of());
            long applicable = 0;
            long notApplicable = 0;
            long decisionReady = 0;
            long noDecision = 0;
            long errors = 0;
            long missingAssessments = 0;
            Set<String> availableFacts = new LinkedHashSet<>();
            Set<String> missingEvidence = new LinkedHashSet<>();
            for (AiGridCoverageService.CoverageItem candidate : policyCandidates) {
                if (!candidate.assessmentPresent()) {
                    missingAssessments++;
                    missingEvidence.add("assessment:" + candidate.artifactId());
                    continue;
                }
                AssessmentState assessment = assessments.get(candidate.assessmentId());
                if (assessment == null) {
                    missingAssessments++;
                    missingEvidence.add("assessment:" + candidate.artifactId());
                    continue;
                }
                if ("NOT_APPLICABLE".equals(assessment.applicability())) notApplicable++;
                if ("APPLICABLE".equals(assessment.applicability())) applicable++;
                if (List.of("PASS", "FAIL").contains(assessment.decision())) decisionReady++;
                if ("NO_DECISION".equals(assessment.decision())) noDecision++;
                if ("ERROR".equals(assessment.decision())) errors++;
                assessment.missing().forEach(node -> missingEvidence.add(node.asText()));
                assessment.inputs().fieldNames().forEachRemaining(availableFacts::add);
            }
            long decisionRequired = Math.max(0, policyCandidates.size() - notApplicable);
            String readiness;
            if (policyCandidates.isEmpty()) readiness = "NO_RESOURCES";
            else if (decisionRequired == 0 && missingAssessments == 0) readiness = "NOT_APPLICABLE";
            else if (missingAssessments == 0 && decisionReady == decisionRequired) readiness = "READY";
            else if (decisionReady > 0) readiness = "PARTIAL";
            else readiness = "BLOCKED";
            jdbc.update("""
                    insert into ai_grid_policy_readiness
                        (id, tenant_id, run_id, coverage_epoch_id, policy_id, policy_version, selection, readiness,
                         candidate_count, applicable_count, decision_required_count, decision_ready_count,
                         no_decision_count, error_count, missing_assessment_count, required_facts_json,
                         available_facts_json, missing_evidence_json)
                    values (:id, :tenantId, :runId, :epochId, :policyId, :version, :selection, :readiness,
                            :candidates, :applicable, :required, :ready, :noDecision, :errors, :missingAssessments,
                            cast(:requiredFacts as jsonb), cast(:available as jsonb), cast(:missing as jsonb))
                    on conflict (tenant_id, run_id, policy_id) do update set
                        coverage_epoch_id = excluded.coverage_epoch_id,
                        policy_version = excluded.policy_version, selection = excluded.selection,
                        readiness = excluded.readiness, candidate_count = excluded.candidate_count,
                        applicable_count = excluded.applicable_count,
                        decision_required_count = excluded.decision_required_count,
                        decision_ready_count = excluded.decision_ready_count,
                        no_decision_count = excluded.no_decision_count, error_count = excluded.error_count,
                        missing_assessment_count = excluded.missing_assessment_count,
                        required_facts_json = excluded.required_facts_json,
                        available_facts_json = excluded.available_facts_json,
                        missing_evidence_json = excluded.missing_evidence_json, computed_at = now()
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId()).addValue("runId", runId).addValue("epochId", epochId)
                    .addValue("policyId", policy.id()).addValue("version", policy.version())
                    .addValue("selection", policy.selection()).addValue("readiness", readiness)
                    .addValue("candidates", policyCandidates.size()).addValue("applicable", applicable)
                    .addValue("required", decisionRequired).addValue("ready", decisionReady)
                    .addValue("noDecision", noDecision).addValue("errors", errors)
                    .addValue("missingAssessments", missingAssessments)
                    .addValue("requiredFacts", policy.requiredFactsJson())
                    .addValue("available", json(availableFacts.stream().sorted().toList()))
                    .addValue("missing", json(missingEvidence.stream().sorted().toList())));
        }
        if (epochId != null) synchronizeSetupActions(tenant, runId, epochId);
    }

    public List<PolicyReadinessView> latestReadiness(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            AiGridCoverageService.CurrentState state = coverage.currentState();
            if (state == null) return List.of();
            return jdbc.query("""
                    select run_id, policy_id, policy_version, selection, readiness, candidate_count,
                           applicable_count, decision_required_count, decision_ready_count,
                           no_decision_count, error_count, missing_assessment_count,
                           required_facts_json::text, available_facts_json::text,
                           missing_evidence_json::text, computed_at
                      from ai_grid_policy_readiness where coverage_epoch_id = :epochId
                     order by case selection when 'REQUIRED' then 1 when 'ENABLED' then 2
                              when 'PREVIEW' then 3 else 4 end, policy_id
                    """, Map.of("epochId", state.epochId()), (rs, n) -> new PolicyReadinessView(
                    rs.getObject("run_id", UUID.class), rs.getString("policy_id"),
                    rs.getString("policy_version"), rs.getString("selection"), rs.getString("readiness"),
                    rs.getLong("candidate_count"), rs.getLong("applicable_count"),
                    rs.getLong("decision_required_count"), rs.getLong("decision_ready_count"),
                    rs.getLong("no_decision_count"), rs.getLong("error_count"),
                    rs.getLong("missing_assessment_count"), rs.getString("required_facts_json"),
                    rs.getString("available_facts_json"), rs.getString("missing_evidence_json"),
                    rs.getTimestamp("computed_at").toInstant()));
        });
    }

    public List<SetupActionView> latestSetupActions(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            AiGridCoverageService.CurrentState state = coverage.currentState();
            if (state == null) return List.of();
            return jdbc.query("""
                    select id, run_id, artifact_id, policy_id, priority, category, action_code,
                           title, detail, evidence_key, status, first_observed_at, last_observed_at
                      from ai_grid_setup_actions where coverage_epoch_id = :epochId and status = 'OPEN'
                     order by priority, category, policy_id nulls last, artifact_id nulls last
                    """, Map.of("epochId", state.epochId()), (rs, n) -> new SetupActionView(
                    rs.getObject("id", UUID.class), rs.getObject("run_id", UUID.class),
                    rs.getObject("artifact_id", UUID.class), rs.getString("policy_id"),
                    rs.getInt("priority"), rs.getString("category"), rs.getString("action_code"),
                    rs.getString("title"), rs.getString("detail"), rs.getString("evidence_key"),
                    rs.getString("status"), rs.getTimestamp("first_observed_at").toInstant(),
                    rs.getTimestamp("last_observed_at").toInstant()));
        });
    }

    private void synchronizeSetupActions(Tenant tenant, UUID runId, UUID epochId) {
        jdbc.update("""
                update ai_grid_setup_actions set status = 'RESOLVED', resolved_at = now(), last_observed_at = now()
                 where coverage_epoch_id is not null and status = 'OPEN'
                """, Map.of());
        List<Gap> gaps = jdbc.query("""
                select fingerprint, artifact_id, policy_id, state, reason, required_action
                  from ai_grid_coverage_gaps where coverage_epoch_id = :epochId and status = 'OPEN'
                """, Map.of("epochId", epochId), (rs, n) -> new Gap(rs.getString("fingerprint"),
                rs.getObject("artifact_id", UUID.class), rs.getString("policy_id"), rs.getString("state"),
                rs.getString("reason"), rs.getString("required_action")));
        gaps.stream().map(this::action).sorted(Comparator.comparingInt(Action::priority)).forEach(action -> {
            String fingerprint = sha256(tenant.getId() + "|" + action.gap().fingerprint()
                    + "|" + action.code());
            jdbc.update("""
                    insert into ai_grid_setup_actions
                        (id, tenant_id, run_id, coverage_epoch_id, artifact_id, policy_id, fingerprint, priority,
                         category, action_code, title, detail, evidence_key)
                    values (:id, :tenantId, :runId, :epochId, :artifactId, :policyId, :fingerprint, :priority,
                            :category, :code, :title, :detail, :evidenceKey)
                    on conflict (tenant_id, fingerprint) do update set run_id = excluded.run_id,
                        coverage_epoch_id = excluded.coverage_epoch_id, priority = excluded.priority,
                        category = excluded.category, title = excluded.title, detail = excluded.detail,
                        evidence_key = excluded.evidence_key, status = 'OPEN', resolved_at = null,
                        last_observed_at = now()
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId()).addValue("runId", runId).addValue("epochId", epochId)
                    .addValue("artifactId", action.gap().artifactId()).addValue("policyId", action.gap().policyId())
                    .addValue("fingerprint", fingerprint).addValue("priority", action.priority())
                    .addValue("category", action.category()).addValue("code", action.code())
                    .addValue("title", action.title()).addValue("detail", action.detail())
                    .addValue("evidenceKey", action.gap().reason()));
        });
    }

    private Action action(Gap gap) {
        return switch (gap.state()) {
            case "MISSING_ASSESSMENT" -> new Action(gap, 1, "PIPELINE", "REPAIR_ASSESSMENT_OMISSION",
                    "Repair missing policy assessment", detail(gap));
            case "COLLECTION_ERROR" -> new Action(gap, 3, "CONNECTOR", "FIX_COLLECTION_ERROR",
                    "Fix evidence collection error", detail(gap));
            case "INCOMPLETE_SCOPE" -> new Action(gap, 5, "PERMISSIONS", "RESTORE_SCOPE_ACCESS",
                    "Restore required discovery scope", detail(gap));
            case "MISSING_FACTS" -> new Action(gap, 10, "EVIDENCE", "ENABLE_EVIDENCE_COLLECTION",
                    "Enable required evidence collection", detail(gap));
            case "UNSUPPORTED" -> new Action(gap, 15, "CONNECTOR", "UPGRADE_CONNECTOR_CAPABILITY",
                    "Add connector evidence capability", detail(gap));
            case "STALE_EVIDENCE" -> new Action(gap, 20, "EVIDENCE", "REFRESH_EVIDENCE",
                    "Refresh stale security evidence", detail(gap));
            case "LOW_CONFIDENCE" -> new Action(gap, 25, "EVIDENCE", "IMPROVE_EVIDENCE_CONFIDENCE",
                    "Improve evidence confidence", detail(gap));
            case "UNKNOWN_TECHNOLOGY" -> new Action(gap, 30, "CLASSIFICATION", "MAP_TECHNOLOGY",
                    "Map the artifact technology", detail(gap));
            case "NO_POLICY_COVERAGE" -> new Action(gap, 40, "COVERAGE", "ADD_POLICY_COVERAGE",
                    "Add applicable governed policy coverage", detail(gap));
            case "UNRESOLVED_OWNER" -> new Action(gap, 50, "OWNERSHIP", "CONFIRM_OWNER",
                    "Confirm an accountable owner", detail(gap));
            default -> new Action(gap, 60, "EVIDENCE", "REVIEW_COVERAGE_GAP",
                    "Review unresolved coverage gap", detail(gap));
        };
    }

    private String detail(Gap gap) {
        return gap.requiredAction() == null || gap.requiredAction().isBlank() ? gap.reason() : gap.requiredAction();
    }

    private UUID latestRunId() {
        return jdbc.query("""
                select run_id from ai_grid_snapshot_manifests group by run_id
                 order by max(observed_at) desc, run_id desc limit 1
                """, Map.of(), rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
    }

    private JsonNode tree(String value) {
        try { return objectMapper.readTree(value == null ? "{}" : value); }
        catch (Exception exception) { throw new IllegalStateException("Stored AI Grid evidence JSON is invalid", exception); }
    }

    private String json(Object value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (Exception exception) { throw new IllegalArgumentException("Unable to serialize AI Grid readiness", exception); }
    }

    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception exception) { throw new IllegalStateException("Unable to fingerprint setup action", exception); }
    }

    private record PolicySpec(String id, String version, String selection, String requiredFactsJson) {}
    private record AssessmentState(String applicability, String decision, JsonNode missing, JsonNode inputs) {}
    private record Gap(String fingerprint, UUID artifactId, String policyId, String state,
                       String reason, String requiredAction) {}
    private record Action(Gap gap, int priority, String category, String code, String title, String detail) {}

    public record PolicyReadinessView(UUID runId, String policyId, String policyVersion, String selection,
                                      String readiness, long candidateCount, long applicableCount,
                                      long decisionRequiredCount, long decisionReadyCount, long noDecisionCount,
                                      long errorCount, long missingAssessmentCount, String requiredFactsJson,
                                      String availableFactsJson, String missingEvidenceJson, Instant computedAt) {}
    public record SetupActionView(UUID id, UUID runId, UUID artifactId, String policyId, int priority,
                                  String category, String actionCode, String title, String detail,
                                  String evidenceKey, String status, Instant firstObservedAt, Instant lastObservedAt) {}
}
