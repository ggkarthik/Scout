package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Idempotent, tenant-isolated rollout executor for immutable policy versions. */
@Service
public class AiGridPolicyRolloutService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiGridAssessmentService assessments;

    public AiGridPolicyRolloutService(NamedParameterJdbcTemplate jdbc, TenantService tenants,
                                      TenantSchemaExecutionService tenantExecution,
                                      TransactionTemplate transactions, AiGridAssessmentService assessments) {
        this.jdbc = jdbc;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.assessments = assessments;
    }

    public List<Rollout> rollouts() {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                select id,release_id,release_type,policy_id,previous_version,new_version,package_digest,status,created_at,completed_at
                  from platform.ai_grid_policy_rollouts order by created_at desc, policy_id
                """, (rs, row) -> new Rollout(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8),
                rs.getTimestamp(9).toInstant(), rs.getTimestamp(10) == null ? null : rs.getTimestamp(10).toInstant())));
    }

    public RolloutDetail rollout(UUID rolloutId) {
        Rollout value = rollouts().stream().filter(item -> item.id().equals(rolloutId)).findFirst()
                .orElseThrow(() -> new ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND, "Policy rollout not found"));
        List<RolloutTask> tasks = TenantContext.runAsPlatform(() -> jdbc.query("""
                select id,tenant_id,status,attempts,next_retry_at,source_snapshot_run_id,assessment_run_id,failure_detail,updated_at
                  from platform.ai_grid_policy_rollout_tasks where rollout_id=:id order by created_at
                """, Map.of("id", rolloutId), (rs, row) -> new RolloutTask(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                rs.getString(3), rs.getInt(4), instant(rs, 5), rs.getObject(6, UUID.class), rs.getObject(7, UUID.class), rs.getString(8), instant(rs, 9))));
        return new RolloutDetail(value, tasks);
    }

    public void retry(UUID rolloutId) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status='PENDING', next_retry_at=null,
                       failure_detail=null, updated_at=now() where rollout_id=:id and status in ('FAILED','WAITING_FOR_SNAPSHOT')
                """, Map.of("id", rolloutId)));
    }

    @Scheduled(fixedDelayString = "${app.ai-grid.policy-rollout.delay-ms:5000}")
    public void processPendingTasks() {
        try {
            discoverShippedVersions();
            for (int index = 0; index < 25; index++) {
                ClaimedTask task = claim();
                if (task == null) return;
                process(task);
            }
        } catch (RuntimeException ignored) {
            // A failed task is recorded below; the scheduler must remain alive for other tenants.
        }
    }

    /** Detects a reviewed migration that has installed a newer immutable package. */
    private void discoverShippedVersions() {
        TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            jdbc.update("""
                    with candidates as (
                      select distinct on (p.policy_id) p.policy_id,p.version,p.package_digest,d.pinned_version previous_version,
                             d.available,d.default_selection,d.rollout_stage,d.canary_tenant_ids_json
                        from platform.ai_grid_policy_versions p
                        join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                       where p.lifecycle='PUBLISHED' and p.package_source_ref like 'policy-packages/agcf/%'
                         and p.version <> d.pinned_version
                       order by p.policy_id,p.published_at desc nulls last,p.version desc
                    ), created as (
                      insert into platform.ai_grid_policy_rollouts
                        (id,release_id,release_type,policy_id,previous_version,new_version,package_digest,distribution_snapshot_json,status)
                      select md5('AUTO_POLICY_VERSION:' || policy_id || ':' || version)::uuid,
                             'AUTO_POLICY_VERSION:' || policy_id || ':' || version, 'POLICY_VERSION', policy_id,
                             previous_version,version,package_digest,
                             jsonb_build_object('available',available,'defaultSelection',default_selection,
                               'rolloutStage',rollout_stage,'canaryTenantIds',canary_tenant_ids_json,'pinnedVersion',version), 'PENDING'
                        from candidates
                      on conflict (release_id,policy_id,new_version) do nothing
                      returning policy_id,previous_version,new_version
                    )
                    update platform.ai_grid_policy_distribution d set pinned_version=c.new_version,updated_by='ai-grid-rollout-worker',updated_at=now()
                      from created c where d.policy_id=c.policy_id
                    """, Map.of());
            jdbc.update("""
                    insert into platform.ai_grid_policy_rollout_tasks (id,rollout_id,tenant_id)
                    select md5(r.id::text || ':' || t.id::text)::uuid,r.id,t.id
                      from platform.ai_grid_policy_rollouts r cross join platform.tenants t
                     where r.release_type='POLICY_VERSION' and t.status='ACTIVE' and t.deleted_at is null
                    on conflict (rollout_id,tenant_id) do nothing
                    """, Map.of());
            return null;
        }));
    }

    private ClaimedTask claim() {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> jdbc.query("""
                select t.id,t.tenant_id,t.rollout_id,r.policy_id,r.previous_version,r.new_version
                  from platform.ai_grid_policy_rollout_tasks t
                  join platform.ai_grid_policy_rollouts r on r.id=t.rollout_id
                 where t.status in ('PENDING','FAILED') and (t.next_retry_at is null or t.next_retry_at <= now())
                 order by t.created_at for update of t skip locked limit 1
                """, rs -> {
            if (!rs.next()) return null;
            ClaimedTask task = new ClaimedTask(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                    rs.getObject(3, UUID.class), rs.getString(4), rs.getString(5), rs.getString(6));
            jdbc.update("update platform.ai_grid_policy_rollout_tasks set status='PROCESSING', attempts=attempts+1, "
                    + "started_at=coalesce(started_at,now()), updated_at=now() where id=:id", Map.of("id", task.id()));
            return task;
        })));
    }

    private void process(ClaimedTask task) {
        Tenant tenant = tenants.requireTenantUuid(task.tenantId());
        try {
            UUID runId = tenantExecution.run(tenant, () -> transactions.execute(status -> latestSnapshotRun()));
            if (runId == null) {
                updateWaiting(task.id());
                return;
            }
            tenantExecution.run(tenant, () -> transactions.execute(status -> {
                closeSuperseded(task.policyId(), task.previousVersion());
                assessments.evaluateRun(tenant, runId);
                return null;
            }));
            complete(task.id(), runId);
        } catch (RuntimeException ex) {
            fail(task.id(), ex.getMessage());
        }
    }

    private UUID latestSnapshotRun() {
        return jdbc.query("""
                select run_id from ai_grid_snapshot_manifests group by run_id
                 order by max(observed_at) desc limit 1
                """, rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
    }

    private void closeSuperseded(String policyId, String previousVersion) {
        if (previousVersion == null || previousVersion.isBlank()) return;
        jdbc.update("""
                update findings set status='AUTO_CLOSED', decision_state='NOT_AFFECTED', closed_at=now(),
                       closed_reason='AUTO_POLICY_VERSION_SUPERSEDED', updated_at=now()
                 where finding_kind='AI_POSTURE' and status='OPEN' and policy_id=:policyId and policy_version=:version
                """, Map.of("policyId", policyId, "version", previousVersion));
    }

    private void updateWaiting(UUID taskId) { update(taskId, "WAITING_FOR_SNAPSHOT", null, null, null); }
    private void complete(UUID taskId, UUID runId) { update(taskId, "COMPLETED", runId, runId, null); }
    private void fail(UUID taskId, String detail) { update(taskId, "FAILED", null, null, detail == null ? "rollout execution failed" : detail); }
    private void update(UUID taskId, String state, UUID sourceRun, UUID assessmentRun, String detail) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                update platform.ai_grid_policy_rollout_tasks set status=:state, source_snapshot_run_id=coalesce(:sourceRun,source_snapshot_run_id),
                    assessment_run_id=coalesce(:assessmentRun,assessment_run_id), failure_detail=:detail,
                    next_retry_at=case when :state='FAILED' then now() + interval '1 minute' else null end,
                    completed_at=case when :state='COMPLETED' then now() else null end, updated_at=now() where id=:id
                """, new MapSqlParameterSource().addValue("id", taskId).addValue("state", state).addValue("sourceRun", sourceRun)
                .addValue("assessmentRun", assessmentRun).addValue("detail", detail)));
        if ("COMPLETED".equals(state)) {
            TenantContext.runAsPlatform(() -> jdbc.update("""
                    update platform.ai_grid_policy_rollouts r set status='COMPLETED', completed_at=now()
                     where r.id=(select rollout_id from platform.ai_grid_policy_rollout_tasks where id=:taskId)
                       and not exists (select 1 from platform.ai_grid_policy_rollout_tasks t
                                        where t.rollout_id=r.id and t.status <> 'COMPLETED')
                    """, Map.of("taskId", taskId)));
        }
    }

    private static Instant instant(java.sql.ResultSet rs, int column) throws java.sql.SQLException {
        java.sql.Timestamp value = rs.getTimestamp(column); return value == null ? null : value.toInstant();
    }
    public record Rollout(UUID id, String releaseId, String releaseType, String policyId, String previousVersion,
                          String newVersion, String packageDigest, String status, Instant createdAt, Instant completedAt) {}
    public record RolloutTask(UUID id, UUID tenantId, String status, int attempts, Instant nextRetryAt,
                              UUID sourceSnapshotRunId, UUID assessmentRunId, String failureDetail, Instant updatedAt) {}
    public record RolloutDetail(Rollout rollout, List<RolloutTask> tasks) {}
    private record ClaimedTask(UUID id, UUID tenantId, UUID rolloutId, String policyId, String previousVersion, String newVersion) {}
}
