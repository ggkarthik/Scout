package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.service.AiGridR1CertificationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridR1CertificationService.EvidenceCommand;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

@PostgresIntegrationTest
class AiGridR1CertificationPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_r1_certification");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private AiGridR1CertificationService certification;

    @Test
    void externalEvidenceCannotOverridePlatformProducedReleaseGates() {
        var initial = certification.readiness();
        assertFalse(initial.ready());
        assertTrue(initial.gates().stream().anyMatch(gate ->
                "AWS_ANSWER_KEY".equals(gate.code()) && "BLOCKED".equals(gate.status())));
        assertTrue(initial.gates().stream().anyMatch(gate ->
                "POLICY_RELEASE_GOVERNANCE".equals(gate.code()) && "BLOCKED".equals(gate.status())));

        assertThrows(ResponseStatusException.class, () -> certification.recordEvidence(new EvidenceCommand(
                "AWS_ANSWER_KEY", "PASS", "attempted-override", "Must be platform-derived",
                Instant.now().plus(1, ChronoUnit.DAYS)), "platform-owner"));

        List<String> externallyAttestable = List.of(
                "DISCOVERY_RECALL", "FIRST_RUN_UTILITY", "DETERMINISM_AND_ISOLATION",
                "ECONOMICS_AND_BUDGETS", "AWS_DESIGN_PARTNER_SOAK", "AZURE_DESIGN_PARTNER_SOAK");
        for (String gate : externallyAttestable) {
            certification.recordEvidence(new EvidenceCommand(gate, "PASS", "evidence://" + gate,
                    "Reviewed R1 release evidence", Instant.now().plus(30, ChronoUnit.DAYS)),
                    "platform-owner");
        }

        var readiness = certification.readiness();
        assertFalse(readiness.ready(), "external attestations must not make missing answer keys look complete");
        assertTrue(readiness.gates().stream()
                .filter(gate -> externallyAttestable.contains(gate.code()))
                .allMatch(gate -> "PASS".equals(gate.status())));

        var decision = certification.decide("platform-owner");
        assertEquals("BLOCKED", decision.decision());
        assertEquals("BLOCKED", certification.readiness().latestDecision());
    }
}
