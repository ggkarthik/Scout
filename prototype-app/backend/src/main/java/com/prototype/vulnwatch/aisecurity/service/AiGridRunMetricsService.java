package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Persists reproducible scan economics without inventing unavailable provider-call measurements. */
@Service
public class AiGridRunMetricsService {
    private final NamedParameterJdbcTemplate jdbc;
    private final AiGridCoverageService coverage;

    public AiGridRunMetricsService(NamedParameterJdbcTemplate jdbc, AiGridCoverageService coverage) {
        this.jdbc = jdbc;
        this.coverage = coverage;
    }

    public void recordCompleteScope(Tenant tenant, UUID runId, String scopeKey, long durationMs) {
        recordCompleteScope(tenant, runId, scopeKey, durationMs, coverage.expectedCandidates(runId));
    }

    public void recordCompleteScope(Tenant tenant, UUID runId, String scopeKey, long durationMs,
                                    List<AiGridCoverageService.CoverageItem> candidates) {
        jdbc.update("""
                insert into ai_grid_run_scope_metrics
                    (id, tenant_id, run_id, scope_key, processing_duration_ms)
                values (:id, :tenantId, :runId, :scopeKey, :durationMs)
                on conflict (tenant_id, run_id, scope_key) do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("scopeKey", scopeKey).addValue("durationMs", durationMs));

        jdbc.update("""
                insert into ai_grid_run_metrics (
                    run_id, tenant_id, completed_scope_count, processing_duration_ms,
                    provider_api_calls, provider_call_measurement_state, artifact_count,
                    snapshot_manifest_count, snapshot_bytes, new_snapshot_bytes, fact_count,
                    assessment_count, pass_count, fail_count, no_decision_count, open_gap_count,
                    first_inventory_at, first_decision_at, first_finding_at, first_gap_at)
                select :runId, :tenantId,
                       (select count(*) from ai_grid_run_scope_metrics where run_id = :runId),
                       (select coalesce(sum(processing_duration_ms), 0) from ai_grid_run_scope_metrics where run_id = :runId),
                       null, 'UNAVAILABLE',
                       (select count(distinct artifact_id) from ai_grid_snapshot_manifests where run_id = :runId),
                       (select count(*) from ai_grid_snapshot_manifests where run_id = :runId),
                       (select coalesce(sum(b.byte_size), 0) from ai_grid_snapshot_manifests m
                          join ai_grid_snapshot_bodies b on b.id = m.body_id where m.run_id = :runId),
                       (select coalesce(sum(byte_size), 0) from ai_grid_snapshot_bodies where first_run_id = :runId),
                       (select count(*) from ai_grid_facts where run_id = :runId),
                       (select count(*) from ai_grid_assessments where run_id = :runId),
                       (select count(*) from ai_grid_assessments where run_id = :runId and decision = 'PASS'),
                       (select count(*) from ai_grid_assessments where run_id = :runId and decision = 'FAIL'),
                       (select count(*) from ai_grid_assessments where run_id = :runId and decision = 'NO_DECISION'),
                       (select count(*) from ai_grid_coverage_gaps where run_id = :runId and status = 'OPEN'),
                       (select min(created_at) from ai_grid_snapshot_manifests where run_id = :runId),
                       (select min(evaluated_at) from ai_grid_assessments where run_id = :runId
                           and decision in ('PASS','FAIL')),
                       (select min(f.created_at) from findings f join ai_grid_assessments a on a.id = f.assessment_id
                           where a.run_id = :runId),
                       (select min(first_observed_at) from ai_grid_coverage_gaps where run_id = :runId)
                on conflict (run_id) do update set
                    completed_scope_count = excluded.completed_scope_count,
                    processing_duration_ms = excluded.processing_duration_ms,
                    artifact_count = excluded.artifact_count,
                    snapshot_manifest_count = excluded.snapshot_manifest_count,
                    snapshot_bytes = excluded.snapshot_bytes,
                    new_snapshot_bytes = excluded.new_snapshot_bytes,
                    fact_count = excluded.fact_count,
                    assessment_count = excluded.assessment_count,
                    pass_count = excluded.pass_count,
                    fail_count = excluded.fail_count,
                    no_decision_count = excluded.no_decision_count,
                    open_gap_count = excluded.open_gap_count,
                    first_inventory_at = coalesce(ai_grid_run_metrics.first_inventory_at, excluded.first_inventory_at),
                    first_decision_at = coalesce(ai_grid_run_metrics.first_decision_at, excluded.first_decision_at),
                    first_finding_at = coalesce(ai_grid_run_metrics.first_finding_at, excluded.first_finding_at),
                    first_gap_at = coalesce(ai_grid_run_metrics.first_gap_at, excluded.first_gap_at),
                    updated_at = now()
                """, Map.of("runId", runId, "tenantId", tenant.getId()));
        refreshUtilityMetrics(tenant, runId, candidates);
    }

    public void refreshUtilityMetrics(Tenant tenant, UUID runId) {
        refreshUtilityMetrics(tenant, runId, coverage.expectedCandidates(runId));
    }

    public void refreshUtilityMetrics(Tenant tenant, UUID runId,
                                      List<AiGridCoverageService.CoverageItem> candidates) {
        long expected = candidates.size();
        long missing = candidates.stream().filter(item -> !item.assessmentPresent()).count();
        long decisions = candidates.stream().filter(item -> List.of("PASS", "FAIL").contains(item.decision())).count();
        long ownerExpected = candidates.stream()
                .filter(item -> List.of("REQUIRED", "ENABLED").contains(item.selection()))
                .filter(item -> !"NOT_APPLICABLE".equals(item.applicability())).count();
        long ownerDecisions = candidates.stream()
                .filter(item -> List.of("REQUIRED", "ENABLED").contains(item.selection()))
                .filter(item -> List.of("PASS", "FAIL").contains(item.decision())).count();
        double reachability = percentage(decisions, expected);
        double ownerUtility = percentage(ownerDecisions, ownerExpected);
        UUID connectorId = jdbc.query("""
                select connector_config_id from ai_grid_snapshot_manifests
                 where run_id = :runId and connector_config_id is not null
                 order by created_at, id limit 1
                """, Map.of("runId", runId), rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
        Boolean baseline = jdbc.queryForObject("""
                select not exists (
                    select 1 from ai_grid_snapshot_manifests other
                     where other.run_id <> :runId
                       and other.connector_config_id = :connectorId
                       and other.created_at < (select min(created_at) from ai_grid_snapshot_manifests
                                                where run_id = :runId))
                """, new MapSqlParameterSource().addValue("runId", runId)
                .addValue("connectorId", connectorId), Boolean.class);
        java.time.Instant ownerFinding = jdbc.queryForObject("""
                select min(f.created_at) from findings f
                  join ai_grid_assessments a on a.id = f.assessment_id
                 where a.run_id = :runId and f.owner_group is not null
                """, Map.of("runId", runId), (rs, n) -> instant(rs, 1));
        java.time.Instant exposure = jdbc.queryForObject("""
                select min(observed_at) from ai_grid_exposure_observations
                 where run_id = :runId and state in ('EXPOSURE_HYPOTHESIS','VALIDATED_EXPOSURE')
                """, Map.of("runId", runId), (rs, n) -> instant(rs, 1));
        jdbc.update("""
                update ai_grid_run_metrics set connector_config_id = :connectorId,
                    expected_assessment_count = :expected,
                    missing_assessment_count = :missing, decision_reachable_count = :decisions,
                    owner_facing_expected_count = :ownerExpected,
                    owner_facing_decision_count = :ownerDecisions,
                    decision_reachability_percent = :reachability,
                    owner_facing_utility_percent = :ownerUtility,
                    baseline_run = :baseline,
                    first_run_target_met = case when :baseline and :ownerExpected > 0
                                                then :ownerUtility >= first_run_target_percent else null end,
                    first_owner_routed_finding_at = coalesce(first_owner_routed_finding_at, :ownerFinding),
                    first_exposure_hypothesis_at = coalesce(first_exposure_hypothesis_at, :exposure),
                    updated_at = now()
                 where run_id = :runId and tenant_id = :tenantId
                """, new MapSqlParameterSource().addValue("expected", expected).addValue("missing", missing)
                .addValue("decisions", decisions).addValue("ownerExpected", ownerExpected)
                .addValue("ownerDecisions", ownerDecisions).addValue("reachability", reachability)
                .addValue("ownerUtility", ownerUtility).addValue("baseline", Boolean.TRUE.equals(baseline))
                .addValue("connectorId", connectorId)
                .addValue("ownerFinding", ownerFinding == null ? null : java.sql.Timestamp.from(ownerFinding))
                .addValue("exposure", exposure == null ? null : java.sql.Timestamp.from(exposure))
                .addValue("runId", runId).addValue("tenantId", tenant.getId()));
    }

    public void recordProviderCalls(Tenant tenant, UUID runId, String provider, long providerApiCalls) {
        jdbc.update("""
                insert into ai_grid_run_metrics
                    (run_id, tenant_id, provider, provider_api_calls, provider_call_measurement_state)
                values (:runId, :tenantId, :provider, :calls, 'MEASURED')
                on conflict (run_id) do update set provider = excluded.provider,
                    provider_api_calls = excluded.provider_api_calls,
                    provider_call_measurement_state = 'MEASURED', updated_at = now()
                """, Map.of("tenantId", tenant.getId(), "provider", provider,
                "calls", providerApiCalls, "runId", runId));
    }

    public RunMetrics metrics(UUID runId) {
        return jdbc.query("""
                select run_id, connector_config_id, provider, completed_scope_count, processing_duration_ms, provider_api_calls,
                       provider_call_measurement_state, artifact_count, snapshot_manifest_count,
                       snapshot_bytes, new_snapshot_bytes, retained_snapshot_bytes, budget_state,
                       fact_count, assessment_count, pass_count,
                       fail_count, no_decision_count, open_gap_count, first_inventory_at,
                       first_decision_at, first_finding_at, first_gap_at,
                       expected_assessment_count, missing_assessment_count, decision_reachable_count,
                       owner_facing_expected_count, owner_facing_decision_count,
                       decision_reachability_percent, owner_facing_utility_percent, baseline_run,
                       first_run_target_percent, first_run_target_met,
                       first_owner_routed_finding_at, first_exposure_hypothesis_at,
                       graph_recomputed_node_count, graph_recomputed_edge_count,
                       graph_traversed_path_count, exposure_path_count, graph_recompute_duration_ms
                  from ai_grid_run_metrics where run_id = :runId
                """, Map.of("runId", runId), (rs, n) -> new RunMetrics(rs.getObject("run_id", UUID.class),
                rs.getObject("connector_config_id", UUID.class),
                rs.getString("provider"), rs.getLong("completed_scope_count"), rs.getLong("processing_duration_ms"),
                (Long) rs.getObject("provider_api_calls"), rs.getString("provider_call_measurement_state"),
                rs.getLong("artifact_count"), rs.getLong("snapshot_manifest_count"), rs.getLong("snapshot_bytes"),
                rs.getLong("new_snapshot_bytes"), rs.getLong("retained_snapshot_bytes"), rs.getString("budget_state"),
                rs.getLong("fact_count"), rs.getLong("assessment_count"),
                rs.getLong("pass_count"), rs.getLong("fail_count"), rs.getLong("no_decision_count"),
                rs.getLong("open_gap_count"), instant(rs, "first_inventory_at"), instant(rs, "first_decision_at"),
                instant(rs, "first_finding_at"), instant(rs, "first_gap_at"),
                rs.getLong("expected_assessment_count"), rs.getLong("missing_assessment_count"),
                rs.getLong("decision_reachable_count"), rs.getLong("owner_facing_expected_count"),
                rs.getLong("owner_facing_decision_count"), rs.getDouble("decision_reachability_percent"),
                rs.getDouble("owner_facing_utility_percent"), rs.getBoolean("baseline_run"),
                rs.getDouble("first_run_target_percent"), (Boolean) rs.getObject("first_run_target_met"),
                instant(rs, "first_owner_routed_finding_at"), instant(rs, "first_exposure_hypothesis_at"),
                rs.getLong("graph_recomputed_node_count"), rs.getLong("graph_recomputed_edge_count"),
                rs.getLong("graph_traversed_path_count"), rs.getLong("exposure_path_count"),
                rs.getLong("graph_recompute_duration_ms")))
                .stream().findFirst().orElse(null);
    }

    private java.time.Instant instant(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        java.sql.Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private java.time.Instant instant(java.sql.ResultSet rs, int column) throws java.sql.SQLException {
        java.sql.Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private double percentage(long numerator, long denominator) {
        return denominator == 0 ? 0.0 : Math.round((10000.0 * numerator) / denominator) / 100.0;
    }

    public record RunMetrics(UUID runId, UUID connectorConfigId, String provider,
                             long completedScopeCount, long processingDurationMs,
                             Long providerApiCalls,
                             String providerCallMeasurementState, long artifactCount, long snapshotManifestCount,
                             long snapshotBytes, long newSnapshotBytes, long retainedSnapshotBytes, String budgetState,
                             long factCount, long assessmentCount,
                             long passCount, long failCount, long noDecisionCount, long openGapCount,
                             java.time.Instant firstInventoryAt, java.time.Instant firstDecisionAt,
                             java.time.Instant firstFindingAt, java.time.Instant firstGapAt,
                             long expectedAssessmentCount, long missingAssessmentCount,
                             long decisionReachableCount, long ownerFacingExpectedCount,
                             long ownerFacingDecisionCount, double decisionReachabilityPercent,
                             double ownerFacingUtilityPercent, boolean baselineRun,
                             double firstRunTargetPercent, Boolean firstRunTargetMet,
                             java.time.Instant firstOwnerRoutedFindingAt,
                             java.time.Instant firstExposureHypothesisAt,
                             long graphRecomputedNodeCount, long graphRecomputedEdgeCount,
                             long graphTraversedPathCount, long exposurePathCount,
                             long graphRecomputeDurationMs) {}
}
