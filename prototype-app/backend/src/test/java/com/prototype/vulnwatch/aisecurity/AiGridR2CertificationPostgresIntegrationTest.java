package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.service.AiGridR2CertificationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridR2CertificationService.PrecisionCommand;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class AiGridR2CertificationPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_r2_certification");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private AiGridR2CertificationService certification;

    @Test
    void allThreeTemplateThresholdsAreSeparateAndOperationalGatesRemainComputed() {
        var initial = certification.readiness();
        assertFalse(initial.ready());
        assertTrue(initial.gates().stream().anyMatch(g ->
                "TEMPLATE_PRECISION".equals(g.code()) && "BLOCKED".equals(g.status())));

        for (String id : List.of("R2_EXTERNAL_SENSITIVE_ACCESS", "R2_EXCESSIVE_TOOL_PRIVILEGE",
                "R2_UNTRUSTED_AUTONOMOUS_EXECUTION")) {
            var review = certification.recordPrecision(new PrecisionCommand(id, "1.0.0", 100, 100,
                    "evidence://" + id), "platform-owner");
            assertEquals("PASSED", review.status());
        }

        var readiness = certification.readiness();
        assertFalse(readiness.ready(), "precision evidence must not override platform-computed operational gates");
        assertTrue(readiness.gates().stream().anyMatch(g ->
                "TEMPLATE_PRECISION".equals(g.code()) && "PASS".equals(g.status())));
        assertTrue(readiness.gates().stream().anyMatch(g -> "EXPLAINABILITY".equals(g.code())));
        assertTrue(readiness.gates().stream().anyMatch(g -> "OWNER_AND_SLA_ROUTING".equals(g.code())));
        assertTrue(readiness.gates().stream().anyMatch(g -> "STALE_EVIDENCE_DEMOTION".equals(g.code())));
        assertTrue(readiness.gates().stream().anyMatch(g -> "COMPLETE_REASSESSMENT_CLOSURE".equals(g.code())));
        assertEquals("BLOCKED", certification.decide("platform-owner").decision());
    }
}
