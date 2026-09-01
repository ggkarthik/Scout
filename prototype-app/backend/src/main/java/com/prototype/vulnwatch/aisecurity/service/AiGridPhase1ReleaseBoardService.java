package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Release-wide promotion guard. Evidence is derived from real tenant runs or an executed distribution drill. */
@Service
public class AiGridPhase1ReleaseBoardService {
    private static final List<String> REQUIRED_GATES = List.of(
            "CANARY_AWS", "CANARY_AZURE", "CANARY_MULTI_CLOUD", "PERFORMANCE",
            "ROLLBACK_AWS", "ROLLBACK_AZURE", "ROLLBACK_MULTI_CLOUD");
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiGridValidationGovernanceService governance;
    private final ObjectMapper mapper;

    public AiGridPhase1ReleaseBoardService(NamedParameterJdbcTemplate jdbc, TenantService tenants,
                                           TenantSchemaExecutionService tenantExecution, TransactionTemplate transactions,
                                           AiGridValidationGovernanceService governance, ObjectMapper mapper) {
        this.jdbc = jdbc; this.tenants = tenants; this.tenantExecution = tenantExecution;
        this.transactions = transactions; this.governance = governance; this.mapper = mapper;
    }

    public Board board() {
        return TenantContext.runAsPlatform(() -> {
            var certification = governance.phase1CertificationReadiness();
            List<Gate> gates = REQUIRED_GATES.stream().map(this::latestGate).toList();
            List<String> blockers = new ArrayList<>();
            if (certification.releaseReadyPolicies() != certification.totalPolicies()) {
                blockers.add("CERTIFICATION:" + certification.releaseReadyPolicies() + "/" + certification.totalPolicies());
            }
            gates.stream().filter(gate -> !"PASSED".equals(gate.status())).forEach(gate -> blockers.add(gate.gateKey()));
            return new Board(certification.totalPolicies(), certification.releaseReadyPolicies(), gates, List.copyOf(blockers));
        });
    }

    public Gate recordCanaryRun(UUID tenantId, UUID runId, String actor) {
        Tenant tenant = tenants.requireTenantUuid(tenantId);
        CanaryEvidence evidence = tenantExecution.run(tenant, () -> jdbc.query("""
                select coalesce(m.provider, 'MULTI_CLOUD') provider, m.owner_facing_utility_percent,
                       m.owner_facing_expected_count, m.no_decision_count,
                       (select count(*) from ai_grid_assessments a where a.run_id = :runId and a.decision = 'NO_DECISION'
                           and (a.reason_code is null or btrim(a.reason_code) = '')) unexplained
                  from ai_grid_run_metrics m where m.run_id = :runId
                """, Map.of("runId", runId), rs -> rs.next() ? new CanaryEvidence(rs.getString(1), rs.getDouble(2),
                rs.getLong(3), rs.getLong(4), rs.getLong(5)) : null));
        if (evidence == null || evidence.expected() == 0) throw new ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                "runId has no eligible, platform-computed assessment metrics");
        String provider = normalizeProvider(evidence.provider());
        boolean passed = evidence.utility() >= 95.0 && evidence.unexplained() == 0;
        return record("CANARY_" + provider, passed ? "PASSED" : "FAILED", Map.of("tenantId", tenantId, "runId", runId,
                "provider", provider, "decisivePercent", evidence.utility(), "eligibleAssessments", evidence.expected(),
                "noDecisionCount", evidence.noDecisions(), "unexplainedNoDecisionCount", evidence.unexplained()), actor);
    }

    /**
     * Compares two real runs of the same connector and assessment population. Database writes are
     * measured as persisted rows in the AI Grid run-owned tables, not an unobservable engine-I/O estimate.
     */
    public Gate recordPerformanceComparison(UUID tenantId, UUID baselineRunId, UUID candidateRunId, String actor) {
        if (baselineRunId.equals(candidateRunId)) throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,
                "baselineRunId and candidateRunId must differ");
        Tenant tenant = tenants.requireTenantUuid(tenantId);
        List<RunPerformance> runs = tenantExecution.run(tenant, () -> jdbc.query("""
                select m.run_id, m.connector_config_id, m.processing_duration_ms, m.expected_assessment_count,
                       (select count(*) from ai_grid_snapshot_manifests x where x.run_id=m.run_id)
                     + (select count(*) from ai_grid_facts x where x.run_id=m.run_id)
                     + (select count(*) from ai_grid_assessments x where x.run_id=m.run_id)
                     + (select count(*) from ai_grid_coverage_gaps x where x.run_id=m.run_id)
                     + (select count(*) from findings f join ai_grid_assessments x on x.id=f.assessment_id where x.run_id=m.run_id)
                     + (select count(*) from ai_grid_relationship_snapshots x where x.run_id=m.run_id)
                     + (select count(*) from ai_grid_exposure_observations x where x.run_id=m.run_id) persisted_rows
                  from ai_grid_run_metrics m where m.run_id in (:ids)
                """, Map.of("ids", List.of(baselineRunId, candidateRunId)), (rs, n) -> new RunPerformance(
                rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getLong(3), rs.getLong(4), rs.getLong(5))));
        RunPerformance baseline = runs.stream().filter(run -> baselineRunId.equals(run.runId())).findFirst().orElse(null);
        RunPerformance candidate = runs.stream().filter(run -> candidateRunId.equals(run.runId())).findFirst().orElse(null);
        if (baseline == null || candidate == null || baseline.connectorId() == null || !baseline.connectorId().equals(candidate.connectorId())
                || baseline.assessments() <= 0 || baseline.assessments() != candidate.assessments()) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                    "Performance runs must have the same connector and comparable non-zero assessment population");
        }
        double durationRegression = ratio(candidate.durationMs(), baseline.durationMs());
        double writeRegression = ratio(candidate.persistedRows(), baseline.persistedRows());
        boolean passed = durationRegression <= 1.20 && writeRegression <= 1.20;
        Map<String, Object> evidence = new java.util.LinkedHashMap<>();
        evidence.put("tenantId", tenantId); evidence.put("baselineRunId", baselineRunId); evidence.put("candidateRunId", candidateRunId);
        evidence.put("connectorConfigId", baseline.connectorId()); evidence.put("assessmentCount", baseline.assessments());
        evidence.put("baselineDurationMs", baseline.durationMs()); evidence.put("candidateDurationMs", candidate.durationMs());
        evidence.put("durationRegressionRatio", durationRegression); evidence.put("baselinePersistedRows", baseline.persistedRows());
        evidence.put("candidatePersistedRows", candidate.persistedRows()); evidence.put("persistedRowWriteRegressionRatio", writeRegression);
        return record("PERFORMANCE", passed ? "PASSED" : "FAILED", evidence, actor);
    }

    public Gate demonstrateRollback(String provider, String policyId, String actor) {
        String normalized = normalizeProvider(provider);
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            Distribution before = jdbc.query("""
                    select available, default_selection, rollout_stage, canary_tenant_ids_json::text, pinned_version,
                           approved_package_digest, release_decision_id
                      from platform.ai_grid_policy_distribution where policy_id = :id
                    """, Map.of("id", policyId), rs -> rs.next() ? new Distribution(rs.getBoolean(1), rs.getString(2),
                    rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6), rs.getObject(7, UUID.class)) : null);
            Integer valid = jdbc.queryForObject("""
                    select count(*) from platform.ai_grid_policy_versions
                     where policy_id = :id and provider = :provider and release_family = 'AGCF_PHASE_1'
                    """, Map.of("id", policyId, "provider", normalized), Integer.class);
            if (before == null || valid == null || valid == 0) throw new ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND,
                    "Phase 1 policy/provider distribution not found");
            jdbc.update("update platform.ai_grid_policy_distribution set available=false, rollout_stage='PAUSED', canary_tenant_ids_json='[]'::jsonb where policy_id=:id", Map.of("id", policyId));
            Integer paused = jdbc.queryForObject("select count(*) from platform.ai_grid_policy_distribution where policy_id=:id and available=false and rollout_stage='PAUSED'", Map.of("id", policyId), Integer.class);
            jdbc.update("""
                    update platform.ai_grid_policy_distribution set available=:available, default_selection=:selection,
                        rollout_stage=:stage, canary_tenant_ids_json=cast(:cohort as jsonb), pinned_version=:pinned,
                        approved_package_digest=:digest, release_decision_id=:decisionId where policy_id=:id
                    """, new MapSqlParameterSource().addValue("id", policyId).addValue("available", before.available())
                    .addValue("selection", before.selection()).addValue("stage", before.stage()).addValue("cohort", before.cohort())
                    .addValue("pinned", before.pinned()).addValue("digest", before.digest()).addValue("decisionId", before.decisionId()));
            Map<String, Object> evidence = new java.util.LinkedHashMap<>();
            evidence.put("policyId", policyId); evidence.put("provider", normalized);
            evidence.put("restoredRolloutStage", before.stage()); evidence.put("restoredPinnedVersion", before.pinned());
            return record("ROLLBACK_" + normalized, paused != null && paused == 1 ? "PASSED" : "FAILED", evidence, actor);
        }));
    }

    public Board promote(String actor) {
        throw new ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                "Bulk Phase 1 promotion is retired; publish each policy independently after fresh approval");
    }

    private Gate latestGate(String key) {
        Gate gate = jdbc.query("""
                select gate_key,status,evidence_json::text,recorded_at from platform.ai_grid_phase_1_release_gate_evidence
                 where gate_key=:key order by recorded_at desc limit 1
                """, Map.of("key", key), rs -> rs.next() ? new Gate(rs.getString(1), rs.getString(2), rs.getString(3),
                rs.getTimestamp(4).toInstant()) : null);
        return gate == null ? new Gate(key, "PENDING", null, null) : gate;
    }
    private Gate record(String key, String state, Map<String, Object> evidence, String actor) {
        try {
            UUID id = UUID.randomUUID(); String payload = mapper.writeValueAsString(evidence);
            jdbc.update("insert into platform.ai_grid_phase_1_release_gate_evidence (id,gate_key,status,evidence_json,recorded_by) values (:id,:key,:status,cast(:evidence as jsonb),:actor)",
                    new MapSqlParameterSource().addValue("id", id).addValue("key", key).addValue("status", state).addValue("evidence", payload).addValue("actor", actor));
            return latestGate(key);
        } catch (Exception exception) { throw new IllegalStateException("Unable to persist Phase 1 release-gate evidence", exception); }
    }
    private String normalizeProvider(String provider) {
        if ("AWS".equalsIgnoreCase(provider)) return "AWS";
        if ("AZURE".equalsIgnoreCase(provider)) return "AZURE";
        if ("MULTI_CLOUD".equalsIgnoreCase(provider)) return "MULTI_CLOUD";
        throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST, "provider must be AWS, AZURE, or MULTI_CLOUD");
    }
    private double ratio(long candidate, long baseline) {
        if (baseline == 0) return candidate == 0 ? 1.0 : Double.POSITIVE_INFINITY;
        return Math.round((candidate * 10000.0 / baseline)) / 10000.0;
    }
    private record CanaryEvidence(String provider, double utility, long expected, long noDecisions, long unexplained) {}
    private record Distribution(boolean available, String selection, String stage, String cohort, String pinned,
                                String digest, UUID decisionId) {}
    private record RunPerformance(UUID runId, UUID connectorId, long durationMs, long assessments, long persistedRows) {}
    public record Gate(String gateKey, String status, String evidenceJson, java.time.Instant recordedAt) {}
    public record Board(int totalPolicies, long releaseReadyPolicies, List<Gate> gates, List<String> blockers) {}
}
