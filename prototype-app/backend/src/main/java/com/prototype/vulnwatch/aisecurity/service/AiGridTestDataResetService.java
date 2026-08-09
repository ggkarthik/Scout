package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Deliberately irreversible clean-slate action for a single AI Security test cycle. */
@Service
public class AiGridTestDataResetService {
    public static final String CONFIRMATION = "ERASE AI SECURITY TEST DATA";
    private static final String TENANT_AI_TABLES = """
            ai_grid_budget_alerts, ai_grid_budget_admissions, ai_grid_budget_config,
            ai_grid_current_coverage_artifacts, ai_grid_current_coverage_state, ai_grid_current_expected_candidates,
            ai_grid_evidence_holds, ai_grid_exposure_associations, ai_grid_exposure_dispositions,
            ai_grid_exposure_executions, ai_grid_exposure_observations, ai_grid_exposure_paths,
            ai_grid_system_lineage_participants, ai_grid_system_lineage_events, ai_grid_system_membership_overrides,
            ai_grid_system_membership_decisions, ai_grid_system_memberships, ai_grid_system_revisions, ai_grid_systems,
            ai_grid_policy_readiness, ai_grid_setup_actions, ai_grid_run_scope_metrics, ai_grid_run_metrics,
            ai_grid_owner_history, ai_grid_relationship_snapshots, ai_grid_coverage_gaps, ai_grid_assessments,
            ai_grid_policy_selection_history, ai_grid_policy_selections, ai_grid_artifact_classifications,
            ai_grid_facts, ai_grid_host_context_facts, ai_grid_snapshot_bodies, ai_grid_snapshot_manifests,
            ai_grid_outbox, ai_grid_retention_purge_audit, ai_grid_retention_decisions, ai_grid_retention_policies,
            ai_grid_scan_cadence_rules, ai_security_finding_reviews, ai_security_findings,
            ai_security_policy_artifact_overrides, ai_security_policy_parameters, ai_security_policy_scopes,
            ai_security_policy_evaluations, ai_security_policy_settings, ai_security_observation_receipts,
            ai_security_snapshot_scopes, ai_security_relationships, ai_security_artifact_sources, ai_security_artifacts
            """.replaceAll("\\s+", " ").trim();
    /** Validation artefacts are reset; policy catalog, distribution and portfolio are deliberately retained. */
    private static final String PLATFORM_VALIDATION_TABLES = """
            platform.ai_grid_release_gate_evidence, platform.ai_grid_release_manifest_items,
            platform.ai_grid_release_decisions, platform.ai_grid_policy_release_decisions,
            platform.ai_grid_precision_adjudications, platform.ai_grid_precision_labels, platform.ai_grid_precision_samples,
            platform.ai_grid_precision_reviews, platform.ai_grid_answer_key_results, platform.ai_grid_answer_key_runs,
            platform.ai_grid_answer_key_cases, platform.ai_grid_answer_key_environments,
            platform.ai_grid_correlation_precision_reviews
            """.replaceAll("\\s+", " ").trim();

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final AuditEventService audit;

    public AiGridTestDataResetService(NamedParameterJdbcTemplate jdbc, TenantService tenants,
                                      TenantSchemaExecutionService tenantExecution, AuditEventService audit) {
        this.jdbc = jdbc; this.tenants = tenants; this.tenantExecution = tenantExecution; this.audit = audit;
    }

    public ResetResult reset(String confirmation, String actor) {
        if (!CONFIRMATION.equals(confirmation)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Confirmation must exactly match: " + CONFIRMATION);
        }
        return TenantContext.runAsPlatform(() -> {
            Integer prior = jdbc.queryForObject("select count(*) from platform.ai_grid_test_data_reset_log", Map.of(), Integer.class);
            if (prior != null && prior > 0) throw new ResponseStatusException(HttpStatus.CONFLICT, "The one-time AI Security test reset has already been used");
            List<Tenant> activeTenants = tenants.listActiveTenants();
            for (Tenant tenant : activeTenants) {
                tenantExecution.run(tenant, () -> {
                    jdbc.update("delete from findings where finding_kind in ('AI_POSTURE','AI_EXPOSURE')", Map.of());
                    jdbc.getJdbcTemplate().execute("truncate table " + TENANT_AI_TABLES + " restart identity cascade");
                    return null;
                });
            }
            jdbc.getJdbcTemplate().execute("truncate table " + PLATFORM_VALIDATION_TABLES + " restart identity cascade");
            jdbc.update("insert into platform.ai_grid_test_data_reset_log (reset_by,tenant_count,confirmation_digest) values (:actor,:count,:digest)",
                    Map.of("actor", actor, "count", activeTenants.size(), "digest", digest(confirmation)));
            audit.record("ai_grid.test_data.reset", "ai_grid_test_data", "all-tenants", "{\"tenantCount\":" + activeTenants.size() + "}");
            return new ResetResult(activeTenants.size(), Instant.now(), true);
        });
    }

    private String digest(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception ex) { throw new IllegalStateException(ex); }
    }
    public record ResetResult(int tenantCount, Instant resetAt, boolean connectorConfigurationsPreserved) {}
}
