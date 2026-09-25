package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.policy.AiGridPredicateEngine;
import com.prototype.vulnwatch.service.AuditEventService;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.web.server.ResponseStatusException;

class AiGridPolicyCatalogServiceTest {
    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
    private final AiGridPolicyCatalogService service = new AiGridPolicyCatalogService(jdbc, new ObjectMapper(),
            new AiGridPredicateEngine(), mock(AuditEventService.class));

    @Test
    void rejectsAResourceFamilyThatIsNotInTheGovernedCatalog() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, String.class).contains("resource_family_definitions") ? 0 : 1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(command(), "test-actor"));

        verify(jdbc).queryForObject(contains("ai_grid_resource_family_definitions"),
                org.mockito.ArgumentMatchers.eq(Map.of("value", "UNRECOGNIZED_FAMILY")),
                org.mockito.ArgumentMatchers.eq(Integer.class));
    }

    @Test
    void platformCatalogFiltersByReleaseFamilyAndLifecycleWithoutFilteringAvailability() {
        service.distributions("AGCF_PHASE_1", "VALIDATED");

        verify(jdbc).query(contains("d.approved_package_digest"),
                any(SqlParameterSource.class), any(org.springframework.jdbc.core.RowMapper.class));
        verify(jdbc).query(contains("p.release_family = cast(:releaseFamily as text)"),
                any(SqlParameterSource.class), any(org.springframework.jdbc.core.RowMapper.class));
        verify(jdbc, org.mockito.Mockito.never()).query(contains("d.available = true"),
                any(SqlParameterSource.class), any(org.springframework.jdbc.core.RowMapper.class));
    }

    @Test
    void rejectsGenericPhase1PostureBindings() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenReturn(1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(
                command("AGCF_PHASE_1", "[\"AI_ARTIFACT\"]", "[]", "[{\"factKey\":\"test.fact\",\"valueType\":\"BOOLEAN\"}]"), "test-actor"));
    }

    @Test
    void rejectsSyntheticPhase1EvidenceKeys() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenReturn(1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(
                command("AGCF_PHASE_1", "[]", "[\"AWS_BEDROCK_AGENT\"]",
                        "[{\"factKey\":\"agcf.agcf-aws-007.evidence\",\"valueType\":\"BOOLEAN\"}]"), "test-actor"));
    }

    @Test
    void rejectsLegacyInformativeMappingOnNewPackageWrites() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenReturn(1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(
                command("TEST_RELEASE", "[\"AI_ARTIFACT\"]", "[]", "[{\"factKey\":\"test.fact\",\"valueType\":\"BOOLEAN\"}]",
                        "[{\"framework\":\"CSA_AICM\",\"frameworkVersion\":\"1.1\",\"controlId\":\"AIS-01\",\"mappingType\":\"INFORMATIVE\",\"rationale\":\"Legacy-only mapping.\"}]"),
                "test-actor"));
    }

    @Test
    void rejectsGenericRationaleOnlyForANewMappingTuple() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenReturn(1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(
                command("TEST_RELEASE", "[\"AI_ARTIFACT\"]", "[]", "[{\"factKey\":\"test.fact\",\"valueType\":\"BOOLEAN\"}]",
                        "[{\"framework\":\"CSA_AICM\",\"frameworkVersion\":\"1.1\",\"controlId\":\"AIS-01\",\"mappingType\":\"SUPPORTING\",\"rationale\":\"This control is independently mapped to the policy's stated security intent.\"}]"),
                "test-actor"));
    }

    @Test
    void rejectsProviderTemplateRationaleForANewMappingTuple() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenReturn(1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(
                command("TEST_RELEASE", "[\"AI_ARTIFACT\"]", "[]", "[{\"factKey\":\"test.fact\",\"valueType\":\"BOOLEAN\"}]",
                        "[{\"framework\":\"CSA_AICM\",\"frameworkVersion\":\"1.1\",\"controlId\":\"AIS-01\",\"mappingType\":\"SUPPORTING\",\"rationale\":\"AWS STORE normalized evidence contributes to this control.\"}]"),
                "test-actor"));
    }

    @Test
    void rejectsUnqualifiedRuntimeDecisionField() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenReturn(1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(runtimeCommand(
                "{\"mode\":\"RUNTIME_SEQUENCE\",\"runtimeSequence\":{\"steps\":[{\"field\":\"approval_state\",\"operator\":\"EQ\",\"value\":\"APPROVED\"}],\"maximumDurationSeconds\":300,\"allowedLatenessSeconds\":30,\"deduplicationKey\":\"execution.source\",\"maximumEventsExamined\":1000,\"explanationFields\":[]}}"), "test-actor"));
    }

    @Test
    void acceptsBoundedRuntimeSequenceWithRegisteredQualifiedFields() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, String.class)
                        .contains("policy_id=:id and version=:version") ? 0 : 1);

        assertDoesNotThrow(() -> service.importDraft(runtimeCommand(
                "{\"mode\":\"RUNTIME_SEQUENCE\",\"runtimeSequence\":{\"steps\":[{\"field\":\"event.approval_state\",\"operator\":\"EQ\",\"value\":\"APPROVED\"}],\"maximumDurationSeconds\":300,\"allowedLatenessSeconds\":30,\"deduplicationKey\":\"execution.source\",\"maximumEventsExamined\":1000,\"explanationFields\":[\"event.action_outcome\"]}}"), "test-actor"));
    }

    @Test
    void rejectsExecutionScopedSequenceStep() {
        // Registered and predicate-eligible, but not event-scoped: a run-level decision cannot
        // establish the ordering a sequence step asserts.
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, String.class)
                        .contains("source_table='ai_agent_execution_events'") ? 0 : 1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(runtimeCommand(
                "{\"mode\":\"RUNTIME_SEQUENCE\",\"runtimeSequence\":{\"steps\":[{\"field\":\"execution.policy_state\",\"operator\":\"EQ\",\"value\":\"DENIED\"}],\"maximumDurationSeconds\":300,\"allowedLatenessSeconds\":30,\"deduplicationKey\":\"execution.source\",\"maximumEventsExamined\":1000,\"explanationFields\":[]}}"),
                "test-actor"));
    }

    @Test
    void rejectsAggregateGroupingKeyThatIsNotAUuidExecutionField() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, String.class)
                        .contains("value_type='UUID'") ? 0 : 1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(runtimeAggregateCommand(
                "{\"mode\":\"RUNTIME_AGGREGATE\",\"runtimeAggregate\":{\"metric\":\"RETRIES\",\"lookbackSeconds\":86400,\"groupingKey\":\"execution.source\",\"operator\":\"GT\",\"threshold\":5,\"maximumRowsExamined\":100,\"maximumEventsExamined\":1000,\"explanationFields\":[]}}"),
                "test-actor"));
    }

    @Test
    void acceptsBoundedRuntimeAggregateGroupedByAgentArtifact() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, String.class)
                        .contains("policy_id=:id and version=:version") ? 0 : 1);

        assertDoesNotThrow(() -> service.importDraft(runtimeAggregateCommand(
                "{\"mode\":\"RUNTIME_AGGREGATE\",\"runtimeAggregate\":{\"metric\":\"RETRIES\",\"lookbackSeconds\":86400,\"groupingKey\":\"execution.agent_artifact_id\",\"operator\":\"GT\",\"threshold\":5,\"maximumRowsExamined\":100,\"maximumEventsExamined\":1000,\"explanationFields\":[]}}"),
                "test-actor"));
    }

    @Test
    void rejectsDerivedExecutionFieldAsSequenceDeduplicationKey() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, String.class).contains("physical_column=true") ? 0 : 1);

        assertThrows(ResponseStatusException.class, () -> service.importDraft(runtimeCommand(
                "{\"mode\":\"RUNTIME_SEQUENCE\",\"runtimeSequence\":{\"steps\":[{\"field\":\"event.approval_state\",\"operator\":\"EQ\",\"value\":\"APPROVED\"}],\"maximumDurationSeconds\":300,\"allowedLatenessSeconds\":30,\"deduplicationKey\":\"execution.version_approval_state\",\"maximumEventsExamined\":1000,\"explanationFields\":[]}}"), "test-actor"));
    }

    @Test
    void runtimeCoverageRequiresItsDeclaredAggregationGrain() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenReturn(1);
        String definition = "{\"mode\":\"RUNTIME_COVERAGE\",\"runtimeCoverage\":{\"lookbackSeconds\":86400,\"windowSeconds\":3600,\"maximumRowsExamined\":100,\"sampleSize\":10}}";

        assertThrows(ResponseStatusException.class, () -> service.importDraft(
                runtimeCommand("RUNTIME_COVERAGE", definition, null), "test-actor"));
    }

    @Test
    void acceptsRuntimeCoverageWithItsDeclaredAggregationGrain() {
        when(jdbc.queryForObject(anyString(), any(Map.class), org.mockito.ArgumentMatchers.eq(Integer.class)))
                .thenAnswer(invocation -> invocation.getArgument(0, String.class)
                        .contains("policy_id=:id and version=:version") ? 0 : 1);
        String definition = "{\"mode\":\"RUNTIME_COVERAGE\",\"runtimeCoverage\":{\"lookbackSeconds\":86400,\"windowSeconds\":3600,\"maximumRowsExamined\":100,\"sampleSize\":10}}";

        assertDoesNotThrow(() -> service.importDraft(
                runtimeCommand("RUNTIME_COVERAGE", definition, "PROVIDER_WINDOW_CAPABILITY_FAMILY"),
                "test-actor"));
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand command() {
        return command("TEST_RELEASE", "[\"AI_ARTIFACT\"]", "[]", "[{\"factKey\":\"test.fact\"}]");
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand command(
            String releaseFamily, String artifactTypes, String nativeKinds, String requiredFacts) {
        return command(releaseFamily, artifactTypes, nativeKinds, requiredFacts,
                "[{\"framework\":\"CSA_AICM\",\"frameworkVersion\":\"1.1\",\"controlId\":\"AIS-01\",\"mappingType\":\"DIRECT\",\"rationale\":\"Test mapping.\"}]");
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand command(
            String releaseFamily, String artifactTypes, String nativeKinds, String requiredFacts, String mappings) {
        return new AiGridPolicyCatalogService.PolicyPackageCommand(
                "TEST-CATALOG-001", "1.0.0", "Catalog test", "Reject unknown governed references.", "LOW",
                "POSTURE_FINDING", "REQUIRED", artifactTypes.replace("AI_ARTIFACT", "AI_AGENT"), nativeKinds, "[\"UNRECOGNIZED_FAMILY\"]",
                requiredFacts, "{\"fact\":\"test.fact\",\"exists\":true}", "TEST_REASON",
                "Use a registered family.", mappings, "test://catalog", null, "[]", "[]", "[]",
                "TEST-OBJECTIVE", "AWS", "ARTIFACT_FACTS", "{\"mode\":\"ARTIFACT_FACTS\",\"artifactFacts\":{\"predicate\":{\"fact\":\"test.fact\",\"exists\":true}}}", "[\"E0\"]", "[]", null, releaseFamily, "TEST_WAVE", null);
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand runtimeAggregateCommand(String definition) {
        return runtimeCommand("RUNTIME_AGGREGATE", definition);
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand runtimeCommand(String definition) {
        return runtimeCommand("RUNTIME_SEQUENCE", definition);
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand runtimeCommand(String mode, String definition) {
        return runtimeCommand(mode, definition, null);
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand runtimeCommand(
            String mode, String definition, String findingAggregationGrain) {
        return new AiGridPolicyCatalogService.PolicyPackageCommand(
                "TEST-RUNTIME-001", "1.0.0", "Runtime catalog test", "Validate runtime references.", "HIGH",
                "POSTURE_FINDING", "PREVIEW", "[\"AI_AGENT\"]", "[]", "[]", "[]", "{}",
                "RUNTIME_TEST", "Review the runtime action.",
                "[{\"framework\":\"CSA_AICM\",\"frameworkVersion\":\"1.1\",\"controlId\":\"AIS-01\",\"mappingType\":\"DIRECT\",\"rationale\":\"Runtime decision enforcement is directly tested.\"}]",
                "test://runtime-catalog", null, "[]", "[]", "[]", "TEST-OBJECTIVE", "AWS",
                mode, definition, "[\"E1\"]", "[]", null, "AGCF_PHASE_2", "WAVE_2B",
                findingAggregationGrain);
    }
}
