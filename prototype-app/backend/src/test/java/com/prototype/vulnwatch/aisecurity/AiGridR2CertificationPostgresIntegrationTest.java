package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.prototype.vulnwatch.aisecurity.service.AiGridR2CertificationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridR2CertificationService.PrecisionReviewCommand;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
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
    @Autowired private NamedParameterJdbcTemplate jdbc;

    @Test
    void allThreeTemplateThresholdsAreSeparateAndOperationalGatesRemainComputed() {
        var initial = certification.readiness();
        assertFalse(initial.ready());
        assertTrue(initial.gates().stream().anyMatch(g ->
                "TEMPLATE_PRECISION".equals(g.code()) && "BLOCKED".equals(g.status())));

        UUID environmentId = UUID.randomUUID();
        UUID answerKeyRunId = UUID.randomUUID();
        jdbc.update("""
                insert into platform.ai_grid_answer_key_environments
                    (id,environment_key,version,provider,resource_family,lifecycle,engineering_owner,
                     security_reviewer,change_summary,review_due_at,created_by)
                values (:id,:key,'1.0.0','AWS','R2','CERTIFIED','engineering','security','R2 cohort',
                        now()+interval '30 days','platform-owner')
                """, Map.of("id", environmentId, "key", "r2-" + environmentId));
        jdbc.update("""
                insert into platform.ai_grid_answer_key_runs
                    (id,environment_id,catalog_digest,status,total_cases,matched_cases,executed_by,
                     started_at,provenance_state)
                values (:id,:environment,'r2','PASS',30,30,'platform-owner',now(),'PLATFORM_RUN_BOUND')
                """, Map.of("id", answerKeyRunId, "environment", environmentId));

        assertThrows(IllegalArgumentException.class, () -> certification.createPrecisionReview(
                new PrecisionReviewCommand("R2_EXTERNAL_SENSITIVE_ACCESS", "1.0.0", "all", "random",
                        1, 0.95, "R2-LABELS-1", answerKeyRunId), "platform-owner"));

        for (String id : List.of("R2_EXTERNAL_SENSITIVE_ACCESS", "R2_EXCESSIVE_TOOL_PRIVILEGE",
                "R2_UNTRUSTED_AUTONOMOUS_EXECUTION")) {
            var review = certification.createPrecisionReview(new PrecisionReviewCommand(id, "1.0.0",
                    "Representative provider and resource-family cohort", "stratified-random", 30, 0.95,
                    "R2-LABELS-1", answerKeyRunId), "platform-owner");
            jdbc.update("""
                    update platform.ai_grid_precision_reviews set status='PASSED',bias_status='PASSED',
                        resolved_positive_samples=30,true_positives=30,false_positives=0,
                        precision_value=1.0,confidence_lower=.96,confidence_upper=1.0,finalized_at=now()
                     where id=:id
                    """, Map.of("id", review.id()));
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
