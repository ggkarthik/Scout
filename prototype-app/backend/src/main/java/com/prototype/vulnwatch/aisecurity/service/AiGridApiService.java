package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    private final AiGridExposureService exposures;
    private final AiGridSystemService systemService;
    private final AiGridHostContextService hostContext;

    public AiGridApiService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution,
                            TransactionTemplate transactions, AiGridAssessmentService assessments,
                            AiGridOwnershipService ownership, AiGridRunMetricsService metrics,
                            AiGridCoverageService coverage, AiGridReconciliationService reconciliation,
                            AiGridReadinessService readiness, AiGridExposureService exposures,
                            AiGridSystemService systemService, AiGridHostContextService hostContext) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.assessments = assessments;
        this.ownership = ownership;
        this.metrics = metrics;
        this.coverage = coverage;
        this.reconciliation = reconciliation;
        this.readiness = readiness;
        this.exposures = exposures;
        this.systemService = systemService;
        this.hostContext = hostContext;
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

    public SystemPage systems(Tenant tenant, String cursor, int requestedLimit) {
        int limit = Math.max(1, Math.min(200, requestedLimit));
        Cursor position = decodeCursor(cursor);
        return tenantExecution.run(tenant, () -> {
            List<SystemSummary> rows = jdbc.query("""
                    select s.id,s.name,s.status,s.current_revision,s.updated_at,count(m.id) member_count
                      from ai_grid_systems s
                      left join ai_grid_system_revisions r on r.system_id=s.id and r.revision=s.current_revision
                      left join ai_grid_system_memberships m on m.system_revision_id=r.id
                     where (cast(:cursorTime as timestamptz) is null
                        or (s.updated_at,s.id)<(cast(:cursorTime as timestamptz),cast(:cursorId as uuid)))
                     group by s.id order by s.updated_at desc,s.id desc limit :limit
                    """, cursorParameters(position, limit),
                    (rs, n) -> new SystemSummary(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                            rs.getInt(4), rs.getInt(6), rs.getTimestamp(5).toInstant()));
            boolean more = rows.size() > limit;
            List<SystemSummary> items = more ? rows.subList(0, limit) : rows;
            SystemSummary last = items.isEmpty() ? null : items.get(items.size() - 1);
            return new SystemPage(List.copyOf(items), more ? encodeCursor(last.updatedAt(), last.id()) : null);
        });
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
            exposures.verifyReplay(tenant, runId);
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

    public List<SystemLineage> systemLineage(Tenant tenant, UUID systemId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select e.id,e.event_type,e.run_id,e.rationale,e.actor,e.created_at,p.participant_role
                  from ai_grid_system_lineage_events e join ai_grid_system_lineage_participants p on p.event_id=e.id
                 where p.system_id=:id order by e.created_at desc,e.id
                """, Map.of("id", systemId), (rs, n) -> new SystemLineage(rs.getObject(1, UUID.class),
                rs.getString(2), rs.getObject(3, UUID.class), rs.getString(4), rs.getString(5),
                rs.getTimestamp(6).toInstant(), rs.getString(7))));
    }

    public List<GraphEdge> systemGraph(Tenant tenant, UUID systemId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select rel.id,rel.source_artifact_id,rel.target_artifact_id,rel.relationship_type,
                       rel.valid_from,rel.valid_until
                  from ai_grid_systems s join ai_grid_system_revisions r
                    on r.system_id=s.id and r.revision=s.current_revision
                  join ai_grid_system_memberships src on src.system_revision_id=r.id
                  join ai_grid_current_coverage_state state on true
                  join ai_grid_current_coverage_artifacts current_src
                    on current_src.epoch_id=state.epoch_id and current_src.artifact_id=src.artifact_id
                  join ai_grid_relationship_snapshots rel on rel.run_id=current_src.source_run_id
                    and rel.source_artifact_id=src.artifact_id
                  join ai_grid_system_memberships dst on dst.system_revision_id=r.id and dst.artifact_id=rel.target_artifact_id
                 where s.id=:id and rel.valid_from<=state.materialized_at
                   and (rel.valid_until is null or rel.valid_until>=state.materialized_at)
                 order by rel.source_artifact_id,rel.relationship_type,rel.target_artifact_id
                """, Map.of("id", systemId), (rs, n) -> new GraphEdge(rs.getObject(1, UUID.class),
                rs.getObject(2, UUID.class), rs.getObject(3, UUID.class), rs.getString(4),
                rs.getTimestamp(5).toInstant(), rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant())));
    }

    public List<SystemFinding> systemFindings(Tenant tenant, UUID systemId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select distinct f.id,f.finding_kind,f.title,f.severity_override,f.status,f.owner_group,
                       f.due_at,f.last_observed_at
                  from findings f join finding_subjects fs on fs.finding_id=f.id
                 where (fs.subject_type='AI_SYSTEM' and fs.subject_id=:id)
                    or (fs.subject_type='ARTIFACT' and fs.subject_id in (
                        select m.artifact_id from ai_grid_systems s join ai_grid_system_revisions r
                          on r.system_id=s.id and r.revision=s.current_revision
                        join ai_grid_system_memberships m on m.system_revision_id=r.id where s.id=:id))
                 order by f.last_observed_at desc,f.id
                """, Map.of("id", systemId), (rs, n) -> new SystemFinding(rs.getObject(1, UUID.class),
                rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6),
                rs.getTimestamp(7) == null ? null : rs.getTimestamp(7).toInstant(), rs.getTimestamp(8).toInstant())));
    }

    public int reviseMembership(Tenant tenant, UUID systemId, UUID artifactId, String decision,
                                String actor, String reason, String lineageType, List<UUID> relatedSystems) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> systemService.reviseMembership(
                tenant, systemId, artifactId, decision, actor, reason, lineageType, relatedSystems)));
    }

    public AiGridHostContextService.HostFact addHostContext(Tenant tenant, UUID artifactId,
                                                             AiGridHostContextService.AnalystFactInput input) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            AiGridHostContextService.HostFact fact = hostContext.attest(tenant, artifactId, input);
            AiGridCoverageService.CurrentState current = coverage.currentState();
            if (current != null) {
                UUID epochId = coverage.refreshCurrent(tenant, current.triggerRunId());
                systemService.deriveForCurrentEpoch(tenant, epochId, current.triggerRunId());
                exposures.correlateCurrentEpoch(tenant, epochId, current.triggerRunId(), Set.of(artifactId));
            }
            return fact;
        }));
    }

    public List<AiGridHostContextService.HostFact> ingestTrustedEvidence(
            Tenant tenant, String producerId, List<TrustedEvidenceItem> items) {
        if (items == null || items.isEmpty() || items.size() > 500)
            throw new IllegalArgumentException("Trusted evidence batch must contain 1-500 facts");
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            List<AiGridHostContextService.HostFact> facts = items.stream()
                    .map(item -> hostContext.ingestTrusted(tenant, item.artifactId(), producerId, item.fact()))
                    .toList();
            AiGridCoverageService.CurrentState current = coverage.currentState();
            if (current != null) {
                UUID epochId = coverage.refreshCurrent(tenant, current.triggerRunId());
                systemService.deriveForCurrentEpoch(tenant, epochId, current.triggerRunId());
                Set<UUID> changed = items.stream().map(TrustedEvidenceItem::artifactId).collect(java.util.stream.Collectors.toSet());
                exposures.correlateCurrentEpoch(tenant, epochId, current.triggerRunId(), changed);
            }
            return facts;
        }));
    }

    public ExposurePage exposures(Tenant tenant, String cursor, int requestedLimit) {
        int limit = Math.max(1, Math.min(200, requestedLimit));
        Cursor position = decodeCursor(cursor);
        return tenantExecution.run(tenant, () -> {
            List<ExposureSummary> rows = jdbc.query("""
                select p.id,p.correlation_id,p.correlation_version,p.title,p.severity,p.state,p.status,
                       p.confidence,p.root_cause_artifact_id,p.first_observed_at,p.last_observed_at,p.finding_id,
                       count(distinct a.system_id) filter (where a.system_id is not null) affected_systems,
                       p.impact,p.root_cause,p.breakpoint,p.confidence_method
                  from ai_grid_exposure_paths p left join ai_grid_exposure_associations a on a.exposure_path_id=p.id
                 where (cast(:cursorTime as timestamptz) is null
                    or (p.last_observed_at,p.id)<(cast(:cursorTime as timestamptz),cast(:cursorId as uuid)))
                 group by p.id order by p.last_observed_at desc,p.id desc limit :limit
                """, cursorParameters(position, limit),
                    (rs, n) -> new ExposureSummary(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getDouble(8),
                rs.getObject(9, UUID.class), rs.getTimestamp(10).toInstant(), rs.getTimestamp(11).toInstant(),
                rs.getObject(12, UUID.class), rs.getInt(13), rs.getString(14), rs.getString(15),
                rs.getString(16), rs.getString(17)));
            boolean more = rows.size() > limit;
            List<ExposureSummary> items = more ? rows.subList(0, limit) : rows;
            ExposureSummary last = items.isEmpty() ? null : items.get(items.size() - 1);
            return new ExposurePage(List.copyOf(items), more ? encodeCursor(last.lastObservedAt(), last.id()) : null);
        });
    }

    public ExposureDetail exposure(Tenant tenant, UUID exposureId) {
        return tenantExecution.run(tenant, () -> {
            List<ExposureSummary> summaries = jdbc.query("""
                    select p.id,p.correlation_id,p.correlation_version,p.title,p.severity,p.state,p.status,
                           p.confidence,p.root_cause_artifact_id,p.first_observed_at,p.last_observed_at,p.finding_id,
                           count(distinct a.system_id) filter (where a.system_id is not null),
                           p.impact,p.root_cause,p.breakpoint,p.confidence_method
                      from ai_grid_exposure_paths p left join ai_grid_exposure_associations a on a.exposure_path_id=p.id
                     where p.id=:id group by p.id
                    """, Map.of("id", exposureId), (rs, n) -> new ExposureSummary(rs.getObject(1, UUID.class),
                    rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6),
                    rs.getString(7), rs.getDouble(8), rs.getObject(9, UUID.class), rs.getTimestamp(10).toInstant(),
                    rs.getTimestamp(11).toInstant(), rs.getObject(12, UUID.class), rs.getInt(13),
                    rs.getString(14), rs.getString(15), rs.getString(16), rs.getString(17)));
            if (summaries.isEmpty()) throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "AI exposure not found");
            List<ExposureObservation> observations = jdbc.query("""
                    select id,run_id,state,entry_artifact_id,system_id,path_json::text,evidence_json::text,
                           temporal_valid_from,temporal_valid_until,confidence,observed_at
                      from ai_grid_exposure_observations where exposure_path_id=:id
                     order by observed_at desc,id
                    """, Map.of("id", exposureId), (rs, n) -> new ExposureObservation(rs.getObject(1, UUID.class),
                    rs.getObject(2, UUID.class), rs.getString(3), rs.getObject(4, UUID.class),
                    rs.getObject(5, UUID.class), rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant(),
                    rs.getTimestamp(9) == null ? null : rs.getTimestamp(9).toInstant(), rs.getDouble(10),
                    rs.getTimestamp(11).toInstant()));
            List<ExposureAssociation> associations = jdbc.query("""
                    select system_id,artifact_id,association_role from ai_grid_exposure_associations
                     where exposure_path_id=:id order by association_role,system_id,artifact_id
                    """, Map.of("id", exposureId), (rs, n) -> new ExposureAssociation(
                    rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3)));
            return new ExposureDetail(summaries.get(0), observations, associations);
        });
    }

    public void dispositionExposure(Tenant tenant, UUID exposureId, String disposition, String actor, String reason) {
        if (!List.of("ACCEPTED", "REJECTED", "RISK_ACCEPTED", "NEEDS_EVIDENCE").contains(disposition))
            throw new IllegalArgumentException("Invalid exposure disposition");
        tenantExecution.run(tenant, () -> transactions.executeWithoutResult(status -> {
            Integer exists = jdbc.queryForObject("select count(*) from ai_grid_exposure_paths where id=:id",
                    Map.of("id", exposureId), Integer.class);
            if (exists == null || exists == 0) throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "AI exposure not found");
            jdbc.update("""
                    insert into ai_grid_exposure_dispositions
                        (id,tenant_id,exposure_path_id,disposition,reason,actor)
                    values (:id,:tenantId,:exposureId,:disposition,:reason,:actor)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("exposureId", exposureId).addValue("disposition", disposition)
                    .addValue("reason", reason).addValue("actor", actor));
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

    private Cursor decodeCursor(String cursor) {
        if (cursor == null || cursor.isBlank()) return null;
        try {
            String decoded = new String(java.util.Base64.getUrlDecoder().decode(cursor), java.nio.charset.StandardCharsets.UTF_8);
            int separator = decoded.lastIndexOf('|');
            return new Cursor(Instant.parse(decoded.substring(0, separator)), UUID.fromString(decoded.substring(separator + 1)));
        } catch (RuntimeException error) { throw new IllegalArgumentException("Invalid exposure cursor", error); }
    }
    private String encodeCursor(Instant time, UUID id) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                (time + "|" + id).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private MapSqlParameterSource cursorParameters(Cursor position, int limit) {
        return new MapSqlParameterSource()
                .addValue("cursorTime", position == null ? null : java.sql.Timestamp.from(position.time()),
                        java.sql.Types.TIMESTAMP)
                .addValue("cursorId", position == null ? null : position.id(), java.sql.Types.OTHER)
                .addValue("limit", limit + 1, java.sql.Types.INTEGER);
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
    public record SystemPage(List<SystemSummary> items, String nextCursor) {}
    public record SystemMember(UUID id, String artifactType, String name, String provider,
                               String providerResourceId, double confidence, String confidenceMethod) {}
    public record SystemDetail(SystemSummary system, List<SystemMember> members) {}
    public record FactView(UUID id, UUID artifactId, String factKey, String valueJson, String state,
                           String provenance, String evidenceClass, Instant observedAt, String schemaVersion) {}
    public record AssessmentRun(UUID runId, Instant startedAt, Instant completedAt,
                                long assessments, long noDecision) {}
    public record PolicyView(String policyId, String version, String name, String severity,
                             String lifecycle, String workflowClass, String selection) {}
    public record SystemLineage(UUID eventId, String eventType, UUID runId, String rationale,
                                String actor, Instant createdAt, String participantRole) {}
    public record GraphEdge(UUID id, UUID sourceArtifactId, UUID targetArtifactId, String relationshipType,
                            Instant validFrom, Instant validUntil) {}
    public record SystemFinding(UUID id, String findingKind, String title, String severity, String status,
                                String ownerGroup, Instant dueAt, Instant lastObservedAt) {}
    public record ExposureSummary(UUID id, String correlationId, String correlationVersion, String title,
                                  String severity, String state, String status, double confidence,
                                  UUID rootCauseArtifactId, Instant firstObservedAt, Instant lastObservedAt,
                                  UUID findingId, int affectedSystems, String impact, String rootCause,
                                  String breakpoint, String confidenceMethod) {}
    public record ExposurePage(List<ExposureSummary> items, String nextCursor) {}
    public record TrustedEvidenceItem(UUID artifactId, AiGridHostContextService.TrustedFactInput fact) {}
    public record ExposureObservation(UUID id, UUID runId, String state, UUID entryArtifactId, UUID systemId,
                                      String pathJson, String evidenceJson, Instant validFrom, Instant validUntil,
                                      double confidence, Instant observedAt) {}
    public record ExposureAssociation(UUID systemId, UUID artifactId, String role) {}
    public record ExposureDetail(ExposureSummary exposure, List<ExposureObservation> observations,
                                 List<ExposureAssociation> associations) {}
    private record Cursor(Instant time, UUID id) {}
}
