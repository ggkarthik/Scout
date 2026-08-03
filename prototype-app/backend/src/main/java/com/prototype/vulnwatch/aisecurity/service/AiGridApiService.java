package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class AiGridApiService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiGridAssessmentService assessments;
    private final AiGridOwnershipService ownership;
    private final AiGridRunMetricsService metrics;
    private final AiGridCoverageService coverage;
    private final AiGridReconciliationService reconciliation;
    private final AiGridReadinessService readiness;

    public AiGridApiService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution,
                            TransactionTemplate transactions, AiGridAssessmentService assessments,
                            AiGridOwnershipService ownership, AiGridRunMetricsService metrics,
                            AiGridCoverageService coverage, AiGridReconciliationService reconciliation,
                            AiGridReadinessService readiness) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.assessments = assessments;
        this.ownership = ownership;
        this.metrics = metrics;
        this.coverage = coverage;
        this.reconciliation = reconciliation;
        this.readiness = readiness;
    }

    public List<SystemSummary> systems(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select s.id, s.name, s.status, s.current_revision, s.updated_at,
                       count(m.id) member_count
                  from ai_grid_systems s
                  left join ai_grid_system_revisions r on r.system_id = s.id and r.revision = s.current_revision
                  left join ai_grid_system_memberships m on m.system_revision_id = r.id
                 group by s.id, s.name, s.status, s.current_revision, s.updated_at
                 order by s.updated_at desc, s.id
                """, (rs, n) -> new SystemSummary(rs.getObject("id", UUID.class), rs.getString("name"),
                rs.getString("status"), rs.getInt("current_revision"), rs.getInt("member_count"),
                rs.getTimestamp("updated_at").toInstant())));
    }

    public SystemDetail system(Tenant tenant, UUID systemId) {
        return tenantExecution.run(tenant, () -> {
            List<SystemSummary> systems = jdbc.query("""
                    select s.id, s.name, s.status, s.current_revision, s.updated_at,
                           count(m.id) member_count
                      from ai_grid_systems s
                      left join ai_grid_system_revisions r on r.system_id = s.id and r.revision = s.current_revision
                      left join ai_grid_system_memberships m on m.system_revision_id = r.id
                     where s.id = :id group by s.id, s.name, s.status, s.current_revision, s.updated_at
                    """, Map.of("id", systemId), (rs, n) -> new SystemSummary(rs.getObject("id", UUID.class),
                    rs.getString("name"), rs.getString("status"), rs.getInt("current_revision"),
                    rs.getInt("member_count"), rs.getTimestamp("updated_at").toInstant()));
            if (systems.isEmpty()) throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "AI system not found");
            List<SystemMember> members = jdbc.query("""
                    select a.id, a.artifact_type, a.name, a.provider, a.provider_resource_id,
                           m.confidence, m.confidence_method
                      from ai_grid_systems s
                      join ai_grid_system_revisions r on r.system_id = s.id and r.revision = s.current_revision
                      join ai_grid_system_memberships m on m.system_revision_id = r.id
                      join ai_security_artifacts a on a.id = m.artifact_id
                     where s.id = :id order by a.artifact_type, a.name
                    """, Map.of("id", systemId), (rs, n) -> new SystemMember(rs.getObject("id", UUID.class),
                    rs.getString("artifact_type"), rs.getString("name"), rs.getString("provider"),
                    rs.getString("provider_resource_id"), rs.getDouble("confidence"), rs.getString("confidence_method")));
            return new SystemDetail(systems.get(0), members);
        });
    }

    public List<FactView> systemFacts(Tenant tenant, UUID systemId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select f.id, f.artifact_id, f.fact_key, f.value_json::text, f.state, f.provenance,
                       f.evidence_class, f.observed_at, f.fact_schema_version
                  from ai_grid_systems s
                  join ai_grid_system_revisions r on r.system_id = s.id and r.revision = s.current_revision
                  join ai_grid_system_memberships m on m.system_revision_id = r.id
                  join ai_grid_facts f on f.artifact_id = m.artifact_id
                 where s.id = :id and not exists (
                     select 1 from ai_grid_facts newer where newer.artifact_id = f.artifact_id
                       and newer.fact_key = f.fact_key and newer.observed_at > f.observed_at)
                 order by f.fact_key
                """, Map.of("id", systemId), (rs, n) -> new FactView(rs.getObject("id", UUID.class),
                rs.getObject("artifact_id", UUID.class), rs.getString("fact_key"), rs.getString("value_json"),
                rs.getString("state"), rs.getString("provenance"), rs.getString("evidence_class"),
                rs.getTimestamp("observed_at").toInstant(), rs.getString("fact_schema_version"))));
    }

    public AiGridCoverageService.Coverage coverage(Tenant tenant) { return coverage.coverage(tenant); }

    public List<AiGridCoverageService.CoverageItem> coverageDetails(Tenant tenant) {
        return coverage.details(tenant);
    }

    public List<AiGridCoverageService.CoverageDimension> coverageDimensions(Tenant tenant) {
        return coverage.dimensions(tenant);
    }

    public List<AiGridReadinessService.PolicyReadinessView> policyReadiness(Tenant tenant) {
        return readiness.latestReadiness(tenant);
    }

    public List<AiGridReadinessService.SetupActionView> setupActions(Tenant tenant) {
        return readiness.latestSetupActions(tenant);
    }

    public List<AssessmentRun> runs(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select run_id, min(evaluated_at) started_at, max(evaluated_at) completed_at,
                       count(*) assessments, count(*) filter (where decision = 'NO_DECISION') no_decision
                  from ai_grid_assessments group by run_id order by completed_at desc limit 100
                """, (rs, n) -> new AssessmentRun(rs.getObject("run_id", UUID.class),
                rs.getTimestamp("started_at").toInstant(), rs.getTimestamp("completed_at").toInstant(),
                rs.getLong("assessments"), rs.getLong("no_decision"))));
    }

    public AssessmentRun replay(Tenant tenant, UUID runId) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            Integer exists = jdbc.queryForObject("select count(*) from ai_grid_snapshot_manifests where run_id = :id",
                    Map.of("id", runId), Integer.class);
            if (exists == null || exists == 0) throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "Assessment run snapshot not found");
            assessments.evaluateRun(tenant, runId);
            List<AiGridCoverageService.CoverageItem> runCandidates = coverage.expectedCandidates(runId);
            reconciliation.reconcile(tenant, runId, runCandidates);
            readiness.compute(tenant, runId, runCandidates);
            UUID epochId = coverage.refreshCurrent(tenant, runId);
            reconciliation.reconcileCurrent(tenant, epochId, runId);
            readiness.computeCurrent(tenant, epochId, runId);
            metrics.refreshUtilityMetrics(tenant, runId, runCandidates);
            return runsCurrent().stream().filter(run -> run.runId().equals(runId)).findFirst().orElseThrow();
        }));
    }

    public AiGridRunMetricsService.RunMetrics runMetrics(Tenant tenant, UUID runId) {
        return tenantExecution.run(tenant, () -> {
            AiGridRunMetricsService.RunMetrics result = metrics.metrics(runId);
            if (result == null) throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "AI assessment run metrics not found");
            return result;
        });
    }

    public AiGridOwnershipService.OwnerView confirmOwner(Tenant tenant, UUID artifactId, String ownerName,
                                                          String actor, String reason) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            AiGridOwnershipService.OwnerView result = ownership.confirm(
                    tenant, artifactId, ownerName, actor, reason);
            UUID runId = jdbc.query("""
                    select run_id from ai_grid_snapshot_manifests where artifact_id = :artifactId
                     order by observed_at desc, created_at desc limit 1
                    """, Map.of("artifactId", artifactId), rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
            if (runId != null) metrics.refreshUtilityMetrics(tenant, runId);
            refreshCurrentProjection(tenant, runId);
            return result;
        }));
    }

    public List<PolicyView> policies(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select distinct on (p.policy_id)
                       p.policy_id, p.version, p.name, p.severity, p.lifecycle, p.workflow_class,
                       coalesce(s.selection, p.default_selection) selection
                  from platform.ai_grid_policy_versions p
                  left join ai_grid_policy_selections s on s.policy_id = p.policy_id
                 where p.lifecycle = 'PUBLISHED'
                 order by p.policy_id, p.published_at desc, p.version desc
                """, (rs, n) -> new PolicyView(rs.getString("policy_id"), rs.getString("version"),
                rs.getString("name"), rs.getString("severity"), rs.getString("lifecycle"),
                rs.getString("workflow_class"), rs.getString("selection"))));
    }

    public List<PolicyView> policyVersions(Tenant tenant, String policyId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select p.policy_id, p.version, p.name, p.severity, p.lifecycle, p.workflow_class,
                       coalesce(s.selection, p.default_selection) selection
                  from platform.ai_grid_policy_versions p
                  left join ai_grid_policy_selections s on s.policy_id = p.policy_id
                 where p.policy_id = :policyId
                   and p.lifecycle in ('PUBLISHED', 'RETIRED')
                 order by p.published_at desc nulls last, p.version desc
                """, Map.of("policyId", policyId), (rs, n) -> new PolicyView(rs.getString("policy_id"),
                rs.getString("version"), rs.getString("name"), rs.getString("severity"),
                rs.getString("lifecycle"), rs.getString("workflow_class"), rs.getString("selection"))));
    }

    public void updateSelection(Tenant tenant, String policyId, String selection, String actor, String reason) {
        if (!List.of("REQUIRED", "ENABLED", "PREVIEW", "DISABLED").contains(selection))
            throw new IllegalArgumentException("Invalid AI policy selection");
        tenantExecution.run(tenant, () -> transactions.executeWithoutResult(status -> {
            Integer publishedPolicy = jdbc.queryForObject("""
                    select count(*) from platform.ai_grid_policy_versions
                     where policy_id = :id and lifecycle = 'PUBLISHED'
                    """, Map.of("id", policyId), Integer.class);
            if (publishedPolicy == null || publishedPolicy == 0) {
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND, "Published AI policy not found");
            }
            List<String> current = jdbc.query("select selection from ai_grid_policy_selections where policy_id = :id",
                    Map.of("id", policyId), (rs, n) -> rs.getString(1));
            jdbc.update("""
                    insert into ai_grid_policy_selections (policy_id, tenant_id, selection, updated_by, reason)
                    values (:policyId, :tenantId, :selection, :actor, :reason)
                    on conflict (policy_id) do update set selection = excluded.selection,
                        updated_by = excluded.updated_by, reason = excluded.reason, updated_at = now()
                    """, new MapSqlParameterSource().addValue("policyId", policyId).addValue("tenantId", tenant.getId())
                    .addValue("selection", selection).addValue("actor", actor).addValue("reason", reason));
            jdbc.update("""
                    insert into ai_grid_policy_selection_history
                        (id, tenant_id, policy_id, previous_selection, selection, actor, reason)
                    values (:id, :tenantId, :policyId, :previous, :selection, :actor, :reason)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("policyId", policyId).addValue("previous", current.isEmpty() ? null : current.get(0))
                    .addValue("selection", selection).addValue("actor", actor).addValue("reason", reason));
            AiGridCoverageService.CurrentState currentCoverage = coverage.currentState();
            if (currentCoverage != null) refreshCurrentProjection(tenant, currentCoverage.triggerRunId());
        }));
    }

    private void refreshCurrentProjection(Tenant tenant, UUID preferredTriggerRunId) {
        AiGridCoverageService.CurrentState current = coverage.currentState();
        UUID triggerRunId = preferredTriggerRunId != null ? preferredTriggerRunId
                : current == null ? null : current.triggerRunId();
        if (triggerRunId == null) return;
        UUID epochId = coverage.refreshCurrent(tenant, triggerRunId);
        reconciliation.reconcileCurrent(tenant, epochId, triggerRunId);
        readiness.computeCurrent(tenant, epochId, triggerRunId);
    }

    private List<AssessmentRun> runsCurrent() {
        return jdbc.query("""
                select run_id, min(evaluated_at) started_at, max(evaluated_at) completed_at,
                       count(*) assessments, count(*) filter (where decision = 'NO_DECISION') no_decision
                  from ai_grid_assessments group by run_id order by completed_at desc limit 100
                """, (rs, n) -> new AssessmentRun(rs.getObject("run_id", UUID.class),
                rs.getTimestamp("started_at").toInstant(), rs.getTimestamp("completed_at").toInstant(),
                rs.getLong("assessments"), rs.getLong("no_decision")));
    }

    public record SystemSummary(UUID id, String name, String status, int revision, int memberCount, Instant updatedAt) {}
    public record SystemMember(UUID id, String artifactType, String name, String provider,
                               String providerResourceId, double confidence, String confidenceMethod) {}
    public record SystemDetail(SystemSummary system, List<SystemMember> members) {}
    public record FactView(UUID id, UUID artifactId, String factKey, String valueJson, String state,
                           String provenance, String evidenceClass, Instant observedAt, String schemaVersion) {}
    public record AssessmentRun(UUID runId, Instant startedAt, Instant completedAt,
                                long assessments, long noDecision) {}
    public record PolicyView(String policyId, String version, String name, String severity,
                             String lifecycle, String workflowClass, String selection) {}
}
