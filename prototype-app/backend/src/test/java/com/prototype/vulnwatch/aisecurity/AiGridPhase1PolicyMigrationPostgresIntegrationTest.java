package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.aisecurity.service.AiGridAssessmentService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPhase1PolicyMigrationService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Verifies that applying the Phase 1 legacy ledger reconciles a legacy detector's open findings
 * onto its ONE_TO_ONE replacement instead of orphaning them and letting the successor adapter
 * open duplicates. Uses the real seeded ledger entry AWS_BEDROCK_WEAK_GUARDRAIL -> AGCF-AWS-002.
 */
@PostgresIntegrationTest
class AiGridPhase1PolicyMigrationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_phase_1_policy_migration");

    private static final String LEGACY = "AWS_BEDROCK_WEAK_GUARDRAIL";
    private static final String SUCCESSOR = "AGCF-AWS-002";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService tenantSchemaMigrationService;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private AiGridPhase1PolicyMigrationService migration;
    @Autowired private NamedParameterJdbcTemplate jdbc;

    @Test
    void oneToOneReplacementReKeysOpenFindingToSuccessorWithoutDuplicating() {
        Tenant tenant = provision("Reconcile Co", "reconcile-co");
        publishSuccessor();
        UUID subject = UUID.randomUUID();
        UUID findingId = seedOpenFinding(tenant, LEGACY, subject, "AIF-RK-1");
        seedSelection(tenant, LEGACY, "ENABLED");

        migration.apply(tenant.getId(), "tester");

        String successorFingerprint =
                AiGridAssessmentService.postureFindingFingerprint(tenant.getId(), SUCCESSOR, subject);
        assertEquals(SUCCESSOR, findingColumn(tenant, findingId, "policy_id"),
                "legacy finding must be re-keyed to the replacement policy");
        assertEquals("OPEN", findingColumn(tenant, findingId, "status"),
                "reconciliation preserves the open finding rather than closing it");
        assertEquals(successorFingerprint, findingColumn(tenant, findingId, "fingerprint"),
                "re-keyed fingerprint must equal what the successor adapter will compute");
        assertEquals(1, findingCountForSubject(tenant, subject),
                "no duplicate finding may be created for the artifact");
    }

    @Test
    void reKeyThatWouldCollideWithAnExistingSuccessorFindingClosesTheLegacyDuplicate() {
        Tenant tenant = provision("Collision Co", "collision-co");
        publishSuccessor();
        UUID subject = UUID.randomUUID();
        String successorFingerprint =
                AiGridAssessmentService.postureFindingFingerprint(tenant.getId(), SUCCESSOR, subject);
        // Successor already owns this artifact's finding (unique (tenant_id, fingerprint)).
        UUID successorFinding = seedOpenFinding(tenant, SUCCESSOR, successorFingerprint, subject, "AIF-CO-1");
        UUID legacyFinding = seedOpenFinding(tenant, LEGACY, subject, "AIF-CO-2");
        seedSelection(tenant, LEGACY, "ENABLED");

        migration.apply(tenant.getId(), "tester");

        assertEquals("AUTO_CLOSED", findingColumn(tenant, legacyFinding, "status"),
                "the legacy duplicate must be closed, not re-keyed onto the collision");
        assertEquals("SUPERSEDED_BY_REPLACEMENT", findingColumn(tenant, legacyFinding, "closed_reason"));
        assertEquals("OPEN", findingColumn(tenant, successorFinding, "status"),
                "the pre-existing successor finding is left intact");
        assertEquals(1, findingCountForSubject(tenant, subject));
    }

    @Test
    void previewPlansReconciliationWithoutMutatingState() {
        Tenant tenant = provision("Preview Co", "preview-co");
        publishSuccessor();
        UUID subject = UUID.randomUUID();
        UUID findingId = seedOpenFinding(tenant, LEGACY, subject, "AIF-PV-1");
        seedSelection(tenant, LEGACY, "ENABLED");

        AiGridPhase1PolicyMigrationService.MigrationPreview preview = migration.preview(tenant.getId());

        assertEquals(0, preview.blockers().size(), "a published successor must not block the plan");
        assertEquals(1, preview.openFindingsReconciled(), "preview must count the open finding it will re-key");
        AiGridPhase1PolicyMigrationService.MigrationAction action = preview.actions().stream()
                .filter(a -> LEGACY.equals(a.legacyDetectorId())).findFirst().orElseThrow();
        assertEquals("ONE_TO_ONE_REPLACEMENT", action.disposition());
        assertEquals(SUCCESSOR, action.reconcileToPolicyId());
        assertEquals(1, action.openFindingsToReconcile());

        // Preview must be side-effect free: the finding is untouched.
        assertEquals(LEGACY, findingColumn(tenant, findingId, "policy_id"));
        assertEquals("OPEN", findingColumn(tenant, findingId, "status"));
    }

    private void publishSuccessor() {
        String digest = jdbc.queryForObject("""
                select package_digest from platform.ai_grid_policy_versions
                 where policy_id = :id and version = '1.0.0'
                """, Map.of("id", SUCCESSOR), String.class);
        UUID decisionId = UUID.randomUUID();
        jdbc.update("""
                insert into platform.ai_grid_policy_release_decisions
                    (id, policy_id, policy_version, package_digest, decision, reason, decided_by)
                values (:id, :policyId, '1.0.0', :digest, 'APPROVED',
                        'Test approval for migration successor', 'test-release-owner')
                """, Map.of("id", decisionId, "policyId", SUCCESSOR, "digest", digest));
        jdbc.update("""
                update platform.ai_grid_policy_versions
                   set lifecycle = 'PUBLISHED'
                 where policy_id = :id and version = '1.0.0'
                """, Map.of("id", SUCCESSOR));
        jdbc.update("""
                update platform.ai_grid_policy_distribution
                   set available = true, rollout_stage = 'GENERAL_AVAILABILITY', pinned_version = '1.0.0',
                       approved_package_digest = :digest, release_decision_id = :decisionId
                 where policy_id = :id
                """, Map.of("id", SUCCESSOR, "digest", digest, "decisionId", decisionId));
    }

    private UUID seedOpenFinding(Tenant tenant, String policyId, UUID subject, String displayId) {
        String fingerprint = AiGridAssessmentService.postureFindingFingerprint(tenant.getId(), policyId, subject);
        return seedOpenFinding(tenant, policyId, fingerprint, subject, displayId);
    }

    private UUID seedOpenFinding(Tenant tenant, String policyId, String fingerprint, UUID subject, String displayId) {
        UUID findingId = UUID.randomUUID();
        tenantExecution.run(tenant, () -> {
            jdbc.update("""
                    insert into findings (id, tenant_id, created_at, updated_at, creation_source, display_id,
                        matched_by, risk_score, status, finding_kind, workflow_class, fingerprint,
                        policy_id, policy_version, title)
                    values (:id, :tenantId, now(), now(), 'AUTOMATIC', :displayId, 'ai-grid', 0, 'OPEN',
                        'AI_POSTURE', 'POSTURE_FINDING', :fingerprint, :policyId, '1.0.0', 'Test posture finding')
                    """, new MapSqlParameterSource().addValue("id", findingId).addValue("tenantId", tenant.getId())
                    .addValue("displayId", displayId).addValue("fingerprint", fingerprint)
                    .addValue("policyId", policyId));
            jdbc.update("""
                    insert into finding_subjects (id, tenant_id, finding_id, subject_type, subject_id, subject_role)
                    values (:id, :tenantId, :findingId, 'ARTIFACT', :subjectId, 'PRIMARY')
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("findingId", findingId).addValue("subjectId", subject));
            return null;
        });
        return findingId;
    }

    private void seedSelection(Tenant tenant, String policyId, String selection) {
        tenantExecution.run(tenant, () -> jdbc.update("""
                insert into ai_grid_policy_selections (policy_id, tenant_id, selection, updated_by, reason)
                values (:policyId, :tenantId, :selection, 'tester', 'test seed')
                on conflict (policy_id) do update set selection = excluded.selection
                """, new MapSqlParameterSource().addValue("policyId", policyId).addValue("tenantId", tenant.getId())
                .addValue("selection", selection)));
    }

    private String findingColumn(Tenant tenant, UUID findingId, String column) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select " + column + " from findings where id = :id", Map.of("id", findingId), String.class));
    }

    private int findingCountForSubject(Tenant tenant, UUID subject) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) from findings f
                 join finding_subjects s on s.finding_id = f.id and s.subject_type = 'ARTIFACT'
                where s.subject_id = :subjectId and f.status = 'OPEN'
                """, Map.of("subjectId", subject), Integer.class));
    }

    private Tenant provision(String name, String slug) {
        Tenant tenant = tenantService.createTenant(name, slug, "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        return tenant;
    }
}
