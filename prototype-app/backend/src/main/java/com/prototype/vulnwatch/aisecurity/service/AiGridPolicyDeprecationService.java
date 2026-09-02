package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Explicit, non-rekeying retirement of a logical AI Grid policy. */
@Service
public class AiGridPolicyDeprecationService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final FindingRepository findings;
    private final FindingWorkflowService workflow;
    private final AuditEventService audit;

    public AiGridPolicyDeprecationService(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions,
                                          TenantService tenants, TenantSchemaExecutionService tenantExecution,
                                          FindingRepository findings, FindingWorkflowService workflow,
                                          AuditEventService audit) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.findings = findings;
        this.workflow = workflow;
        this.audit = audit;
    }

    public Deprecation deprecate(String policyId, DeprecationCommand command, String actor) {
        require(policyId, "policyId");
        if (command == null) throw badRequest("Deprecation command is required");
        require(command.reason(), "reason");
        require(command.idempotencyKey(), "idempotencyKey");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            Deprecation existing = byIdempotencyKey(command.idempotencyKey());
            if (existing != null) {
                if (!existing.policyId().equals(policyId)) throw conflict("Idempotency key belongs to another policy");
                return existing;
            }
            List<String> versions = jdbc.query("""
                    select version from platform.ai_grid_policy_versions
                     where policy_id = :policyId and lifecycle <> 'DEPRECATED'
                     order by created_at desc, version desc for update
                    """, Map.of("policyId", policyId), (rs, row) -> rs.getString(1));
            if (versions.isEmpty()) throw notFound("AI Grid policy not found or already deprecated");
            String version = versions.get(0);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    update platform.ai_grid_policy_versions
                       set lifecycle = 'DEPRECATED', published_at = null
                     where policy_id = :policyId and lifecycle <> 'DEPRECATED'
                    """, Map.of("policyId", policyId));
            jdbc.update("""
                    insert into platform.ai_grid_policy_distribution
                        (policy_id, available, default_selection, rollout_stage, canary_tenant_ids_json, pinned_version, updated_by)
                    values (:policyId, false, 'DISABLED', 'PAUSED', '[]'::jsonb, null, :actor)
                    on conflict (policy_id) do update set available = false, default_selection = 'DISABLED',
                        rollout_stage = 'PAUSED', canary_tenant_ids_json = '[]'::jsonb, pinned_version = null,
                        updated_by = excluded.updated_by, updated_at = now()
                    """, Map.of("policyId", policyId, "actor", actor));
            jdbc.update("""
                    insert into platform.ai_grid_policy_deprecations
                        (id, policy_id, policy_version, reason, successor_policy_id, deprecated_by, idempotency_key)
                    values (:id, :policyId, :version, :reason, :successor, :actor, :idempotencyKey)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("policyId", policyId)
                    .addValue("version", version).addValue("reason", command.reason().trim())
                    .addValue("successor", blank(command.successorPolicyId())).addValue("actor", actor)
                    .addValue("idempotencyKey", command.idempotencyKey().trim()));
            jdbc.update("""
                    insert into platform.ai_grid_policy_deprecation_tasks (id, deprecation_id, tenant_id)
                    select md5(:deprecationId || ':' || t.id::text)::uuid, :id, t.id
                      from platform.tenants t
                     where t.status = 'ACTIVE' and t.deleted_at is null
                    on conflict (deprecation_id, tenant_id) do nothing
                    """, Map.of("id", id, "deprecationId", id.toString()));
            audit.recordExplicitActor(null, actor, "PLATFORM_OWNER", "ai_grid.policy.deprecated", "ai_grid_policy",
                    policyId, "{\"successorPolicyId\":" + jsonString(blank(command.successorPolicyId())) + "}", "SUCCESS");
            return byId(id);
        }));
    }

    @Scheduled(fixedDelayString = "${app.ai-grid.policy-deprecation.delay-ms:5000}")
    public void processPendingTasks() {
        for (int index = 0; index < 25; index++) {
            ClaimedTask task = claim();
            if (task == null) return;
            try {
                Tenant tenant = tenants.requireTenantUuid(task.tenantId());
                tenantExecution.run(tenant, () -> transactions.execute(status -> {
                    for (Finding finding : findings.findOpenAiFindingsByTenantAndPolicy(tenant, task.policyId())) {
                        workflow.autoCloseFinding(finding, FindingCloseReason.AUTO_POLICY_PLATFORM_DEPRECATED,
                                "Finding closed because its AI Grid policy was deprecated",
                                Map.of("policyId", task.policyId(), "deprecationId", task.deprecationId().toString()), Instant.now());
                        findings.save(finding);
                    }
                    return null;
                }));
                complete(task.id());
            } catch (RuntimeException ex) {
                fail(task.id(), ex.getMessage());
            }
        }
    }

    private ClaimedTask claim() {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> jdbc.query("""
                select task.id, task.tenant_id, task.deprecation_id, deprecation.policy_id
                  from platform.ai_grid_policy_deprecation_tasks task
                  join platform.ai_grid_policy_deprecations deprecation on deprecation.id = task.deprecation_id
                 where task.state in ('PENDING', 'FAILED')
                   and (task.next_retry_at is null or task.next_retry_at <= now())
                 order by task.created_at for update of task skip locked limit 1
                """, rs -> {
            if (!rs.next()) return null;
            ClaimedTask task = new ClaimedTask(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                    rs.getObject(3, UUID.class), rs.getString(4));
            jdbc.update("update platform.ai_grid_policy_deprecation_tasks set state='PROCESSING', attempts=attempts+1, "
                    + "started_at=coalesce(started_at,now()), updated_at=now() where id=:id", Map.of("id", task.id()));
            return task;
        })));
    }

    private void complete(UUID taskId) { updateTask(taskId, "COMPLETED", null); }
    private void fail(UUID taskId, String detail) { updateTask(taskId, "FAILED", detail == null ? "deprecation task failed" : detail); }
    private void updateTask(UUID taskId, String state, String detail) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                update platform.ai_grid_policy_deprecation_tasks
                   set state=:state, failure_detail=:detail,
                       next_retry_at=case when :state='FAILED' then now() + interval '1 minute' else null end,
                       completed_at=case when :state='COMPLETED' then now() else null end, updated_at=now()
                 where id=:id and state='PROCESSING'
                """, new MapSqlParameterSource().addValue("id", taskId).addValue("state", state).addValue("detail", detail)));
    }

    private Deprecation byIdempotencyKey(String key) {
        return jdbc.query("select * from platform.ai_grid_policy_deprecations where idempotency_key=:key",
                Map.of("key", key.trim()), rs -> rs.next() ? map(rs) : null);
    }

    private Deprecation byId(UUID id) {
        return jdbc.query("select * from platform.ai_grid_policy_deprecations where id=:id", Map.of("id", id),
                rs -> rs.next() ? map(rs) : null);
    }

    private Deprecation map(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new Deprecation(rs.getObject("id", UUID.class), rs.getString("policy_id"), rs.getString("policy_version"),
                rs.getString("reason"), rs.getString("successor_policy_id"), rs.getString("deprecated_by"),
                rs.getTimestamp("deprecated_at").toInstant(), rs.getString("idempotency_key"));
    }

    private static String blank(String value) { return value == null || value.isBlank() ? null : value.trim(); }
    private static void require(String value, String field) { if (value == null || value.isBlank()) throw badRequest(field + " is required"); }
    private static String jsonString(String value) { return value == null ? "null" : "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }
    private static ResponseStatusException badRequest(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private static ResponseStatusException conflict(String message) { return new ResponseStatusException(HttpStatus.CONFLICT, message); }
    private static ResponseStatusException notFound(String message) { return new ResponseStatusException(HttpStatus.NOT_FOUND, message); }

    private record ClaimedTask(UUID id, UUID tenantId, UUID deprecationId, String policyId) {}
    public record DeprecationCommand(String reason, String successorPolicyId, String idempotencyKey) {}
    public record Deprecation(UUID id, String policyId, String policyVersion, String reason, String successorPolicyId,
                              String deprecatedBy, Instant deprecatedAt, String idempotencyKey) {}
}
