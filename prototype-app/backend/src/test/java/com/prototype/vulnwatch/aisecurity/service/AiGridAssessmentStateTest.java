package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AiGridAssessmentStateTest {

    @Test
    void derivesFourStateApiOutcomeWithoutPersistingAnotherColumn() {
        assertEquals("PASS", result("PASS", null).assessmentState());
        assertEquals("FAIL", result("FAIL", null).assessmentState());
        assertEquals("UNKNOWN", result("ERROR", "FACT_COLLECTION_ERROR").assessmentState());
        assertEquals("UNKNOWN", result("NO_DECISION", "STALE").assessmentState());
        assertEquals("UNKNOWN", result("NO_DECISION", "INCOMPLETE_SCOPE").assessmentState());
        assertEquals("UNKNOWN", result("NO_DECISION", "STALE_RELATIONSHIP_EVIDENCE").assessmentState());
        assertEquals("NOT_ASSESSED", result("NO_DECISION", "OUT_OF_SCOPE").assessmentState());
        assertEquals("NOT_ASSESSED", result("NO_DECISION", "CAPABILITY_UNAVAILABLE").assessmentState());
        assertEquals("NOT_ASSESSED", result("NOT_APPLICABLE", "REQUIRED_RELATIONSHIP_ABSENT").assessmentState());
        assertEquals("UNKNOWN", result("UNEXPECTED", "UNEXPECTED").assessmentState());
    }

    private AiGridFindingService.AssessmentResult result(String decision, String reason) {
        return new AiGridFindingService.AssessmentResult(UUID.randomUUID(), UUID.randomUUID(), "POLICY", "1.0.0",
                "Policy", "HIGH", "ENABLED", decision, reason, UUID.randomUUID(), "fingerprint", Map.of());
    }
}
