package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.policy.AiGridPredicateEngine;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityResourceFamilyCatalogue;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridAssessmentServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final AiGridAssessmentService service = new AiGridAssessmentService(
            mock(NamedParameterJdbcTemplate.class), mapper, new AiGridPredicateEngine(),
            new AiSecurityResourceFamilyCatalogue(), mock(AiGridFindingService.class),
            mock(AiGridSnapshotService.class));

    @Test
    void declaredMinimumConfidenceRejectsMissingAndInsufficientConfidence() throws Exception {
        var requirement = service.requirements("""
                [{"factKey":"derived.reachability","valueType":"BOOLEAN",
                  "evidenceClasses":["GRAPH_ANALYSIS"],"maxAgeSeconds":3600,"minConfidence":0.9}]
                """).get(0);
        Instant asOf = Instant.parse("2026-08-02T12:00:00Z");

        assertEquals(0.9, requirement.minConfidence());
        assertEquals("LOW_CONFIDENCE", service.issue(new AiGridAssessmentService.Fact(
                UUID.randomUUID(), "BOOLEAN", mapper.readTree("true"), "KNOWN", "GRAPH_ANALYSIS",
                asOf.minusSeconds(60), null), requirement, asOf));
        assertEquals("LOW_CONFIDENCE", service.issue(new AiGridAssessmentService.Fact(
                UUID.randomUUID(), "BOOLEAN", mapper.readTree("true"), "KNOWN", "GRAPH_ANALYSIS",
                asOf.minusSeconds(60), 0.89), requirement, asOf));
        assertEquals(null, service.issue(new AiGridAssessmentService.Fact(
                UUID.randomUUID(), "BOOLEAN", mapper.readTree("true"), "KNOWN", "GRAPH_ANALYSIS",
                asOf.minusSeconds(60), 0.9), requirement, asOf));
    }
}
