package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AiSecurityDecisionCoverageGateTest {

    @Test
    void criticalPolicyRequiresCompleteDecisionCoverage() {
        var blocked = AiSecurityApiService.coverageGate("CRITICAL", 98, 1, 1);
        var passed = AiSecurityApiService.coverageGate("CRITICAL", 99, 1, 0);

        assertEquals(1.0, blocked.threshold());
        assertEquals("FAIL", blocked.status());
        assertEquals("PASS", passed.status());
    }

    @Test
    void highAndMediumPoliciesRequireNinetyFivePercentCoverage() {
        var passed = AiSecurityApiService.coverageGate("HIGH", 94, 1, 5);
        var blocked = AiSecurityApiService.coverageGate("MEDIUM", 93, 1, 6);

        assertEquals(0.95, passed.threshold());
        assertEquals("PASS", passed.status());
        assertEquals("FAIL", blocked.status());
        assertEquals(100, blocked.evaluatedArtifacts());
        assertEquals(6, blocked.noDecisionCount());
    }

    @Test
    void unevaluatedPolicyIsExplicitlyNoData() {
        var gate = AiSecurityApiService.coverageGate("CRITICAL", 0, 0, 0);

        assertEquals("NO_DATA", gate.status());
        assertEquals(0, gate.evaluatedArtifacts());
    }
}
