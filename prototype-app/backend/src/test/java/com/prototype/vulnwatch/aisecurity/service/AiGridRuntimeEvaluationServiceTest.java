package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

class AiGridRuntimeEvaluationServiceTest {
    private static final String SEQUENCE_DEFINITION = """
            {"mode":"RUNTIME_SEQUENCE","runtimeSequence":{
              "steps":[{"conditions":[
                         {"field":"event.policy_state","operator":"EQ","value":"DENIED"},
                         {"field":"event.action_outcome","operator":"EQ","value":"SUCCEEDED"}]}],
              "maximumDurationSeconds":3600,"allowedLatenessSeconds":0,
              "deduplicationKey":"execution.source","maximumEventsExamined":100,
              "explanationFields":["event.enforcement_point"]}}""";
    private static final String FACTS_DEFINITION = """
            {"mode":"RUNTIME_FACTS","runtimeFacts":{
              "conditions":[{"field":"execution.correlation_status","operator":"IN",
                             "value":["AMBIGUOUS","UNRESOLVED"]}],
              "explanationFields":["execution.correlation_status"]}}""";
    private static final String AGGREGATE_DEFINITION = """
            {"mode":"RUNTIME_AGGREGATE","runtimeAggregate":{
              "metric":"RETRIES","lookbackSeconds":86400,"groupingKey":"execution.agent_artifact_id",
              "operator":"GT","threshold":5,"maximumRowsExamined":100,"maximumEventsExamined":1000,
              "explanationFields":[]}}""";
    private static final String COVERAGE_DEFINITION = """
            {"mode":"RUNTIME_COVERAGE","runtimeCoverage":{"lookbackSeconds":86400,
              "windowSeconds":3600,"maximumRowsExamined":100,"sampleSize":10}}""";

    private NamedParameterJdbcTemplate jdbc;
    private AiGridFindingService findings;
    private AiGridSnapshotService snapshots;
    private AiGridCapabilityService capabilities;
    private AiGridRuntimeEvaluationService service;
    private Tenant tenant;
    private final UUID runId = UUID.randomUUID();
    private final UUID executionId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        jdbc = mock(NamedParameterJdbcTemplate.class);
        findings = mock(AiGridFindingService.class);
        snapshots = mock(AiGridSnapshotService.class);
        capabilities = mock(AiGridCapabilityService.class);
        when(capabilities.runtimeGaps(any(), any(), any())).thenReturn(List.of());
        service = new AiGridRuntimeEvaluationService(jdbc, new ObjectMapper(), findings, snapshots,
                capabilities, 14);
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(jdbc.queryForObject(contains("insert into ai_grid_assessments"), any(SqlParameterSource.class),
                eq(UUID.class))).thenReturn(UUID.randomUUID());
    }

    @Test
    void policyDeniedActionThatSucceededFailsTheSequence() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        stubCandidates();
        stubEvents(List.of(event("DENIED", "SUCCEEDED", Instant.now().minus(30, ChronoUnit.MINUTES))));

        service.evaluateRun(tenant, runId);

        assertEquals("FAIL", capturedDecision());
        verify(findings).reconcile(any(Tenant.class), any(AiGridFindingService.AssessmentResult.class));
    }

    @Test
    void absentDecisionFieldYieldsUnknownRatherThanPass() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        stubCandidates();
        stubEvents(List.of(event(null, null, Instant.now().minus(30, ChronoUnit.MINUTES))));

        service.evaluateRun(tenant, runId);

        AiGridFindingService.AssessmentResult result = capturedResult();
        assertEquals("NO_DECISION", result.decision());
        assertEquals("RUNTIME_FIELD_UNPOPULATED", result.reasonCode());
        assertEquals("UNKNOWN", result.assessmentState());
    }

    @Test
    void unmatchedSequenceOnPopulatedEvidencePasses() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        stubCandidates();
        stubEvents(List.of(event("ALLOWED", "SUCCEEDED", Instant.now().minus(30, ChronoUnit.MINUTES))));

        service.evaluateRun(tenant, runId);

        assertEquals("PASS", capturedDecision());
    }

    @Test
    void latenessUsesNewestIngestionRatherThanNewestEventTime() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION.replace(
                "\"allowedLatenessSeconds\":0", "\"allowedLatenessSeconds\":60"), "ENABLED");
        stubRegistry();
        stubCandidates();
        Map<String, Object> lateOldEvent = event(
                "ALLOWED", "SUCCEEDED", Instant.now().minus(2, ChronoUnit.HOURS));
        lateOldEvent.put("ingested_at", Timestamp.from(Instant.now().minusSeconds(5)));
        Map<String, Object> newerEvent = event(
                "ALLOWED", "SUCCEEDED", Instant.now().minus(30, ChronoUnit.MINUTES));
        newerEvent.put("ingested_at", Timestamp.from(Instant.now().minus(20, ChronoUnit.MINUTES)));
        stubEvents(List.of(lateOldEvent, newerEvent));

        service.evaluateRun(tenant, runId);

        assertEquals("AWAITING_LATENESS_WINDOW", capturedReason());
    }

    @Test
    void compoundStepDoesNotJoinDecisionsFromUnrelatedEvents() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        stubCandidates();
        stubEvents(List.of(
                event("DENIED", "FAILED", Instant.now().minus(30, ChronoUnit.MINUTES)),
                event("ALLOWED", "SUCCEEDED", Instant.now().minus(29, ChronoUnit.MINUTES))));

        service.evaluateRun(tenant, runId);

        assertEquals("PASS", capturedDecision());
    }

    @Test
    void eventBudgetOverflowYieldsUnknown() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        stubCandidates();
        List<Map<String, Object>> events = new ArrayList<>();
        for (int index = 0; index <= 100; index++) {
            events.add(event("DENIED", "SUCCEEDED", Instant.now().minus(30, ChronoUnit.MINUTES)));
        }
        stubEvents(events);

        service.evaluateRun(tenant, runId);

        AiGridFindingService.AssessmentResult result = capturedResult();
        assertEquals("EVALUATION_BOUND_EXCEEDED", result.reasonCode());
        assertEquals("UNKNOWN", result.assessmentState());
    }

    @Test
    void previewSelectionIsNotEvaluated() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "PREVIEW");
        stubRegistry();

        assertEquals(0, service.evaluateRun(tenant, runId));
        verify(findings, never()).reconcile(any(Tenant.class), any(AiGridFindingService.AssessmentResult.class));
    }

    @Test
    void executionScopedSequenceStepIsNotAssessed() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION.replace("event.policy_state", "execution.policy_state"),
                "ENABLED");
        stubRegistry();

        service.evaluateRun(tenant, runId);

        assertEquals("DECISION_SCOPE_UNSUPPORTED", capturedReason());
        // A contract gap is recorded against the policy, never as a per-execution assessment.
        verify(findings, never()).reconcile(any(Tenant.class), any(AiGridFindingService.AssessmentResult.class));
    }

    @Test
    void executionDecisionWithoutEventDecisionIsNotAssessed() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        stubCandidates();
        stubEvents(List.of(event(null, "SUCCEEDED", Instant.now().minus(30, ChronoUnit.MINUTES))));
        when(jdbc.queryForObject(contains("policy_state is not null"), any(Map.class), eq(Boolean.class)))
                .thenReturn(true);

        service.evaluateRun(tenant, runId);

        AiGridFindingService.AssessmentResult result = capturedResult();
        assertEquals("DECISION_SCOPE_UNSUPPORTED", result.reasonCode());
        assertEquals("NOT_ASSESSED", result.assessmentState());
    }

    @Test
    void evaluatorFailurePersistsUnknownAssessment() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        when(jdbc.query(contains("dedup_value"), any(SqlParameterSource.class), any(RowMapper.class)))
                .thenThrow(new IllegalStateException("broken evaluator read"));

        service.evaluateRun(tenant, runId);

        assertEquals("RUNTIME_EVALUATION_FAILED", capturedReason());
    }

    @Test
    void explanationContainsValuesFromTheMatchedEvent() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        stubCandidates();
        Map<String, Object> matched = event(
                "DENIED", "SUCCEEDED", Instant.now().minus(30, ChronoUnit.MINUTES));
        matched.put("enforcement_point", "gateway-a");
        stubEvents(List.of(matched));

        service.evaluateRun(tenant, runId);

        assertEquals(Map.of("value", List.of("gateway-a")),
                capturedResult().inputFacts().get("explanationField:event.enforcement_point"));
    }

    @Test
    void staleRuntimeCapabilityIsNotAssessedRatherThanPassed() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED");
        stubRegistry();
        when(capabilities.runtimeGaps(any(), any(), any()))
                .thenReturn(List.of("capability:RUNTIME_EVENT_DECISIONS:STALE"));
        when(capabilities.remediation(any())).thenReturn("Enable the provider decision source.");

        service.evaluateRun(tenant, runId);

        assertEquals("CAPABILITY_UNAVAILABLE", capturedReason());
        // A stale capability is a coverage gap, so nothing is asserted per execution.
        verify(findings, never()).reconcile(any(Tenant.class), any(AiGridFindingService.AssessmentResult.class));
    }

    @Test
    void multiCloudPolicyChecksCapabilitiesForEachObservedProvider() {
        stubPolicy("RUNTIME_SEQUENCE", SEQUENCE_DEFINITION, "ENABLED", "MULTI_CLOUD");
        stubRegistry();
        when(jdbc.queryForList(contains("select distinct provider"), any(Map.class), eq(String.class)))
                .thenReturn(List.of("AWS", "AZURE_FOUNDRY"));
        when(capabilities.runtimeGaps(any(), eq("AWS"), any())).thenReturn(List.of());
        when(capabilities.runtimeGaps(any(), eq("AZURE_FOUNDRY"), any()))
                .thenReturn(List.of("capability:RUNTIME_EVENT_DECISIONS:MISSING_OR_STALE"));
        when(capabilities.remediation(any())).thenReturn("Enable provider decision evidence.");
        stubCandidates();
        stubEvents(List.of(event("DENIED", "SUCCEEDED", Instant.now().minus(30, ChronoUnit.MINUTES))));

        service.evaluateRun(tenant, runId);

        assertTrue(capturedReasons().contains("CAPABILITY_UNAVAILABLE"));
        assertTrue(capturedReasons().contains("RUNTIME_POLICY_DENIED_ACTION_SUCCEEDED"));
        verify(capabilities).runtimeGaps(any(), eq("AWS"), any());
        verify(capabilities).runtimeGaps(any(), eq("AZURE_FOUNDRY"), any());
    }

    @Test
    void unresolvedCorrelationFailsTheRuntimeFactsConjunction() {
        stubPolicy("RUNTIME_FACTS", FACTS_DEFINITION, "ENABLED");
        stubRegistry();
        when(jdbc.queryForList(contains("from ai_agent_executions"), any(SqlParameterSource.class)))
                .thenReturn(List.of(execution("AMBIGUOUS")));

        service.evaluateRun(tenant, runId);

        assertEquals("FAIL", capturedDecision());
    }

    @Test
    void runtimeFactsWithUnpopulatedConditionFieldIsUnknown() {
        stubPolicy("RUNTIME_FACTS", FACTS_DEFINITION, "ENABLED");
        stubRegistry();
        when(jdbc.queryForList(contains("from ai_agent_executions"), any(SqlParameterSource.class)))
                .thenReturn(List.of(execution(null)));

        service.evaluateRun(tenant, runId);

        assertEquals("RUNTIME_FIELD_UNPOPULATED", capturedReason());
    }

    @Test
    void resolvedCorrelationPassesRuntimeFacts() {
        stubPolicy("RUNTIME_FACTS", FACTS_DEFINITION, "ENABLED");
        stubRegistry();
        when(jdbc.queryForList(contains("from ai_agent_executions"), any(SqlParameterSource.class)))
                .thenReturn(List.of(execution("RESOLVED")));

        service.evaluateRun(tenant, runId);

        assertEquals("PASS", capturedDecision());
    }

    @Test
    void aggregateBreachFailsAndUnpopulatedMetricIsUnknown() {
        stubPolicy("RUNTIME_AGGREGATE", AGGREGATE_DEFINITION, "ENABLED");
        stubRegistry();
        UUID agent = UUID.randomUUID();
        stubAggregateScope(4, 0);
        when(jdbc.queryForList(contains("with scoped as"), any(SqlParameterSource.class)))
                .thenReturn(List.of(group(agent, 9L, 0L, 4L), group(UUID.randomUUID(), null, 2L, 3L)));

        service.evaluateRun(tenant, runId);

        List<String> decisions = capturedDecisions();
        assertTrue(decisions.contains("FAIL"), "breaching group must fail: " + decisions);
        assertTrue(capturedReasons().contains("RUNTIME_METRIC_UNPOPULATED"),
                "partially populated metric must not settle: " + capturedReasons());
    }

    @Test
    void aggregateRowBudgetOverflowYieldsUnknown() {
        stubPolicy("RUNTIME_AGGREGATE", AGGREGATE_DEFINITION, "ENABLED");
        stubRegistry();
        stubAggregateScope(101, 0);

        service.evaluateRun(tenant, runId);

        assertEquals("EVALUATION_BOUND_EXCEEDED", capturedReason());
    }

    @Test
    void aggregateEventBudgetOverflowYieldsUnknown() {
        stubPolicy("RUNTIME_AGGREGATE", AGGREGATE_DEFINITION, "ENABLED");
        stubRegistry();
        stubAggregateScope(4, 1001);

        service.evaluateRun(tenant, runId);

        assertEquals("EVALUATION_BOUND_EXCEEDED", capturedReason());
    }

    @Test
    void coveragePolicyAggregatesOneFindingPerSourceFamilyWindow() {
        stubPolicy("RUNTIME_COVERAGE", COVERAGE_DEFINITION, "ENABLED");
        stubRegistry();
        UUID anchor = UUID.randomUUID();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("provider", "AZURE_FOUNDRY");
        row.put("workspace", "workspace-a");
        row.put("capability_family", "RUNTIME_EVENT_DECISIONS");
        row.put("window_start", Timestamp.from(Instant.now().minus(1, ChronoUnit.HOURS)));
        row.put("raw_count", 7L);
        row.put("affected_count", 3L);
        row.put("sample_execution_ids", new UUID[]{anchor});
        row.put("anchor_execution_id", anchor);
        when(jdbc.queryForList(contains("with incomplete as"), any(SqlParameterSource.class)))
                .thenReturn(List.of(row));

        service.evaluateRun(tenant, runId);

        assertEquals("FAIL", capturedDecision());
        verify(findings).reconcile(any(Tenant.class), any(AiGridFindingService.AssessmentResult.class));
    }

    @Test
    void coverageFamiliesSharingAnAnchorKeepDistinctAssessmentFingerprints() {
        stubPolicy("RUNTIME_COVERAGE", COVERAGE_DEFINITION, "ENABLED");
        stubRegistry();
        UUID anchor = UUID.randomUUID();
        Timestamp window = Timestamp.from(Instant.now().minus(1, ChronoUnit.HOURS));
        Map<String, Object> decisions = coverageRow(anchor, window, "RUNTIME_EVENT_DECISIONS");
        Map<String, Object> outcomes = coverageRow(anchor, window, "RUNTIME_ACTION_OUTCOMES");
        when(jdbc.queryForList(contains("with incomplete as"), any(SqlParameterSource.class)))
                .thenReturn(List.of(decisions, outcomes));

        service.evaluateRun(tenant, runId);

        List<String> fingerprints = capturedValues("fingerprint");
        assertEquals(2, fingerprints.size());
        assertEquals(2, fingerprints.stream().distinct().count());
        verify(jdbc, org.mockito.Mockito.atLeastOnce()).queryForObject(
                contains("subject_id, fingerprint) do update"), any(SqlParameterSource.class), eq(UUID.class));
    }

    // ------------------------------------------------------------------ stubs

    @SuppressWarnings("unchecked")
    private void stubPolicy(String mode, String definition, String selection) {
        stubPolicy(mode, definition, selection, "AZURE_FOUNDRY");
    }

    @SuppressWarnings("unchecked")
    private void stubPolicy(String mode, String definition, String selection, String provider) {
        when(jdbc.query(contains("p.evaluation_mode in ('RUNTIME_FACTS'"), any(Map.class), any(RowMapper.class)))
                .thenReturn(List.of(new AiGridRuntimeEvaluationService.RuntimePolicy(
                        "AGCF-RT-001", "1.0.0", "Runtime policy", "HIGH", provider,
                        "RUNTIME_POLICY_DENIED_ACTION_SUCCEEDED", mode, readTree(definition), "PREVIEW")));
        when(jdbc.query(eq("select policy_id, selection from ai_grid_policy_selections"),
                any(ResultSetExtractor.class)))
                .thenReturn(Map.of("AGCF-RT-001", selection));
    }

    /** Mirrors the rows the V3 platform schema publishes into the runtime field registry. */
    @SuppressWarnings("unchecked")
    private void stubRegistry() {
        Map<String, AiGridRuntimeEvaluationService.RuntimeField> rows = new LinkedHashMap<>();
        rows.put("event.policy_state", field("ai_agent_execution_events", "policy_state", "STRING"));
        rows.put("event.action_outcome", field("ai_agent_execution_events", "action_outcome", "STRING"));
        rows.put("event.enforcement_point", field("ai_agent_execution_events", "enforcement_point", "STRING"));
        rows.put("execution.source", field("ai_agent_executions", "source", "STRING"));
        rows.put("execution.policy_state", field("ai_agent_executions", "policy_state", "STRING"));
        rows.put("execution.correlation_status", field("ai_agent_executions", "correlation_status", "STRING"));
        rows.put("execution.agent_artifact_id", field("ai_agent_executions", "agent_artifact_id", "UUID"));
        when(jdbc.query(contains("from platform.ai_grid_runtime_field_definitions"), any(ResultSetExtractor.class)))
                .thenReturn(rows);
    }

    private static AiGridRuntimeEvaluationService.RuntimeField field(String table, String column, String type) {
        return new AiGridRuntimeEvaluationService.RuntimeField(table, column, type, true);
    }

    @SuppressWarnings("unchecked")
    private void stubCandidates() {
        when(jdbc.query(contains("dedup_value"), any(SqlParameterSource.class), any(RowMapper.class)))
                .thenAnswer(invocation -> {
                    RowMapper<Object> mapper = invocation.getArgument(2);
                    java.sql.ResultSet rs = mock(java.sql.ResultSet.class);
                    when(rs.getObject("id", UUID.class)).thenReturn(executionId);
                    when(rs.getString("dedup_value")).thenReturn("AZURE_FOUNDRY_RUNTIME");
                    when(rs.getTimestamp("evidence_time")).thenReturn(Timestamp.from(Instant.now()));
                    return List.of(mapper.mapRow(rs, 0));
                });
    }

    private void stubEvents(List<Map<String, Object>> events) {
        when(jdbc.queryForList(contains("from ai_agent_execution_events"), any(SqlParameterSource.class)))
                .thenReturn(events);
    }

    private void stubAggregateScope(int executions, int events) {
        List<UUID> executionIds = java.util.stream.IntStream.range(0, executions)
                .mapToObj(ignored -> UUID.randomUUID()).toList();
        List<UUID> eventIds = java.util.stream.IntStream.range(0, events)
                .mapToObj(ignored -> UUID.randomUUID()).toList();
        when(jdbc.queryForList(contains("select id from ai_agent_executions"),
                any(SqlParameterSource.class), eq(UUID.class))).thenReturn(executionIds);
        when(jdbc.queryForList(contains("select id from ai_agent_execution_events"),
                any(SqlParameterSource.class), eq(UUID.class))).thenReturn(eventIds);
    }

    private static Map<String, Object> event(String policyState, String actionOutcome, Instant at) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("id", UUID.randomUUID());
        event.put("event_time", Timestamp.from(at));
        event.put("policy_state", policyState);
        event.put("action_outcome", actionOutcome);
        event.put("action_category", "WRITE");
        return event;
    }

    private static Map<String, Object> execution(String correlationStatus) {
        Map<String, Object> execution = new LinkedHashMap<>();
        execution.put("id", UUID.randomUUID());
        execution.put("correlation_status", correlationStatus);
        execution.put("evidence_time", Timestamp.from(Instant.now()));
        return execution;
    }

    private static Map<String, Object> group(UUID groupValue, Long measured, long nullContributors, long rows) {
        Map<String, Object> group = new LinkedHashMap<>();
        group.put("group_value", groupValue);
        group.put("measured", measured);
        group.put("null_contributors", nullContributors);
        group.put("examined_rows", rows);
        group.put("anchor_execution_id", UUID.randomUUID());
        group.put("anchor_evidence_time", Timestamp.from(Instant.now()));
        return group;
    }

    private static Map<String, Object> coverageRow(UUID anchor, Timestamp window, String family) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("provider", "AZURE_FOUNDRY");
        row.put("workspace", "workspace-a");
        row.put("capability_family", family);
        row.put("window_start", window);
        row.put("raw_count", 1L);
        row.put("affected_count", 1L);
        row.put("sample_execution_ids", new UUID[]{anchor});
        row.put("anchor_execution_id", anchor);
        return row;
    }

    // ------------------------------------------------------------- assertions

    private String capturedDecision() {
        List<String> decisions = capturedDecisions();
        assertEquals(1, decisions.size(), "expected exactly one assessment: " + decisions);
        return decisions.get(0);
    }

    private String capturedReason() {
        List<String> reasons = capturedReasons();
        assertEquals(1, reasons.size(), "expected exactly one assessment: " + reasons);
        return reasons.get(0);
    }

    private List<String> capturedDecisions() {
        return capturedValues("decision");
    }

    private List<String> capturedReasons() {
        return capturedValues("reason");
    }

    private List<String> capturedValues(String parameter) {
        ArgumentCaptor<SqlParameterSource> captor = ArgumentCaptor.forClass(SqlParameterSource.class);
        verify(jdbc, org.mockito.Mockito.atLeastOnce()).queryForObject(
                contains("insert into ai_grid_assessments"), captor.capture(), eq(UUID.class));
        return captor.getAllValues().stream().map(values -> (String) values.getValue(parameter)).toList();
    }

    private AiGridFindingService.AssessmentResult capturedResult() {
        ArgumentCaptor<AiGridFindingService.AssessmentResult> captor =
                ArgumentCaptor.forClass(AiGridFindingService.AssessmentResult.class);
        verify(findings).reconcile(any(Tenant.class), captor.capture());
        return captor.getValue();
    }

    private static com.fasterxml.jackson.databind.JsonNode readTree(String value) {
        try {
            return new ObjectMapper().readTree(value);
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

}
