package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
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

        verify(jdbc).query(contains("where (cast(:releaseFamily as text) is null or p.release_family = cast(:releaseFamily as text))"),
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

    private AiGridPolicyCatalogService.PolicyPackageCommand command() {
        return command("TEST_RELEASE", "[\"AI_ARTIFACT\"]", "[]", "[{\"factKey\":\"test.fact\"}]");
    }

    private AiGridPolicyCatalogService.PolicyPackageCommand command(
            String releaseFamily, String artifactTypes, String nativeKinds, String requiredFacts) {
        return new AiGridPolicyCatalogService.PolicyPackageCommand(
                "TEST-CATALOG-001", "1.0.0", "Catalog test", "Reject unknown governed references.", "LOW",
                "POSTURE_FINDING", "REQUIRED", artifactTypes, nativeKinds, "[\"UNRECOGNIZED_FAMILY\"]",
                requiredFacts, "{\"fact\":\"test.fact\",\"exists\":true}", "TEST_REASON",
                "Use a registered family.", "[{\"framework\":\"CSA_AICM\",\"frameworkVersion\":\"1.1\",\"controlId\":\"AIS-01\",\"mappingType\":\"DIRECT\",\"rationale\":\"Test mapping.\"}]", "test://catalog", null, "[]", "[]", "[]",
                "TEST-OBJECTIVE", "AWS", "ARTIFACT_FACTS", "{\"mode\":\"ARTIFACT_FACTS\",\"artifactFacts\":{\"predicate\":{\"fact\":\"test.fact\",\"exists\":true}}}", "[\"E0\"]", "[]", null, releaseFamily, "TEST_WAVE");
    }
}
