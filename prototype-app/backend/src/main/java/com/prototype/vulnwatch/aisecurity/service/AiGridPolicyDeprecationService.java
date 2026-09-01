package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Logical policy deprecation with durable, tenant-scoped finding inactivation. */
@Service
public class AiGridPolicyDeprecationService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiGridFindingService findings;

    public AiGridPolicyDeprecationService(NamedParameterJdbcTemplate jdbc, TenantService tenants,
                                           TenantSchemaExecutionService tenantExecution,
                                           TransactionTemplate transactions, AiGridFindingService findings) {
        this.jdbc = jdbc;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.findings = findings;
    }

    /** Compatibility entry point: only the active pinned revision may be supplied. */
    public void deprecate(String policyId, String version, String actor) {
        TenantContext.runAsPlatform(() -> {
            String pinned = jdbc.query("select pinned_version from platform.ai_grid_policy_distribution where policy_id=:id",
                    Map.of("id", policyId), rs -> rs.next() ? rs.getString(1) : null);
            if (pinned == null || !pinned.equals(version)) {
                throw new ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                        "Deprecation must target the active pinned policy revision");
            }
            deprecateLogical(policyId, actor);
        });
    }

    public void deprecateLogical(String policyId, String actor) {
        TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            Map<String, Object> policy = jdbc.query("""
                    select d.pinned_version, p.package_digest, d.approved_package_digest, d.release_decision_id, p.lifecycle
                      from platform.ai_grid_policy_distribution d
                      join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.version=d.pinned_version
                     where d.policy_id=:id for update
                    """, Map.of("id", policyId), rs -> {
                if (!rs.next()) return Map.of();
                return Map.of("version", rs.getString(1), "lifecycle", rs.getString(5));
            });
            if (policy.isEmpty()) throw new ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND, "Policy distribution not found");
            String lifecycle = (String) policy.get("lifecycle");
            if ("DEPRECATED".equals(lifecycle)) return null;
            if (!"PUBLISHED".equals(lifecycle) && !"CANARY".equals(lifecycle)) {
                throw new ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT, "Only an active published policy can be deprecated");
            }
            String version = (String) policy.get("version");
            jdbc.update("update platform.ai_grid_policy_versions set lifecycle='DEPRECATED' where policy_id=:id and version=:version",
                    Map.of("id", policyId, "version", version));
            jdbc.update("""
                    update platform.ai_grid_policy_distribution
                       set available=false, rollout_stage='PAUSED', default_selection='DISABLED',
                           canary_tenant_ids_json='[]'::jsonb, updated_by=:actor, updated_at=now()
                     where policy_id=:id
                    """, Map.of("id", policyId, "actor", actor));
            jdbc.update("""
                    insert into platform.ai_grid_policy_inactivation_tasks (id, policy_id, tenant_id, reason)
                    select md5(:policyId || ':' || t.id::text)::uuid, :policyId, t.id, 'PLATFORM_DEPRECATED'
                      from platform.tenants t where t.status='ACTIVE' and t.deleted_at is null
                    on conflict (policy_id, tenant_id) do update set status=case when status='COMPLETED' then status else 'PENDING' end,
                        next_retry_at=null, failure_detail=null, updated_at=now()
                    """, Map.of("policyId", policyId));
            return null;
        }));
    }

    @Scheduled(fixedDelayString = "${app.ai-grid.policy-inactivation.delay-ms:5000}")
    public void processInactivationTasks() {
        for (int i = 0; i < 25; i++) {
            Inactivation task = claim();
            if (task == null) return;
            try {
                Tenant tenant = tenants.requireTenantUuid(task.tenantId());
                tenantExecution.run(tenant, () -> transactions.execute(status -> {
                    findings.closeForPolicy(tenant, task.policyId(), FindingCloseReason.AUTO_POLICY_PLATFORM_DEPRECATED);
                    return null;
                }));
                update(task.id(), "COMPLETED", null);
            } catch (RuntimeException ex) {
                update(task.id(), "FAILED", ex.getMessage() == null ? "inactivation failed" : ex.getMessage());
            }
        }
    }

    private Inactivation claim() {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> jdbc.query("""
                select id, policy_id, tenant_id from platform.ai_grid_policy_inactivation_tasks
                 where status in ('PENDING','FAILED') and attempts < 3
                   and (next_retry_at is null or next_retry_at <= now())
                 order by queued_at for update skip locked limit 1
                """, rs -> {
            if (!rs.next()) return null;
            Inactivation task = new Inactivation(rs.getObject(1, UUID.class), rs.getString(2), rs.getObject(3, UUID.class));
            jdbc.update("""
                    update platform.ai_grid_policy_inactivation_tasks set status='PROCESSING', attempts=attempts+1,
                        started_at=coalesce(started_at,now()), updated_at=now() where id=:id
                    """, Map.of("id", task.id()));
            return task;
        })));
    }

    private void update(UUID id, String state, String detail) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                update platform.ai_grid_policy_inactivation_tasks set status=:state, failure_detail=:detail,
                    next_retry_at=case when :state='FAILED' then now() + interval '1 minute' else null end,
                    completed_at=case when :state='COMPLETED' then now() else null end, updated_at=now() where id=:id
                """, new MapSqlParameterSource().addValue("id", id).addValue("state", state).addValue("detail", detail)));
    }

    private record Inactivation(UUID id, String policyId, UUID tenantId) {}
}
