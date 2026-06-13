package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class DemoTenantPurgeService {

    private final TenantRepository tenantRepository;
    private final JdbcTemplate resetJdbcTemplate;
    private final AuditEventService auditEventService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final TenantSchemaService tenantSchemaService;
    private final DemoTenantPurgePlanner demoTenantPurgePlanner;

    public DemoTenantPurgeService(
            TenantRepository tenantRepository,
            @Qualifier("prototypeResetJdbcTemplate")
            JdbcTemplate resetJdbcTemplate,
            AuditEventService auditEventService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            TenantSchemaService tenantSchemaService,
            DemoTenantPurgePlanner demoTenantPurgePlanner
    ) {
        this.tenantRepository = tenantRepository;
        this.resetJdbcTemplate = resetJdbcTemplate;
        this.auditEventService = auditEventService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.tenantSchemaService = tenantSchemaService;
        this.demoTenantPurgePlanner = demoTenantPurgePlanner;
    }

    public void processExpiredTenant(UUID tenantId, Instant now) {
        Tenant tenant = tenantRepository.findById(tenantId).orElse(null);
        if (!demoTenantPurgePlanner.isEligibleForAutomaticPurge(tenant, now)) {
            return;
        }

        if (!"DELETED".equalsIgnoreCase(tenant.getStatus())) {
            markExpired(tenant, now);
        }
        if (tenant.getPurgedAt() != null) {
            return;
        }

        purgeTenantInternal(tenant, now, "EXPIRED", "demo.tenant.purged", "demo.tenant.purge_failed");
    }

    public void deleteTenant(UUID tenantId, Instant now) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Unknown tenant: " + tenantId));
        if (TenantService.DEFAULT_TENANT_NAME.equalsIgnoreCase(tenant.getName())) {
            throw new ResponseStatusException(BAD_REQUEST, "Default workspace cannot be deleted");
        }
        if (tenant.getPurgedAt() != null || "DELETED".equalsIgnoreCase(tenant.getStatus())) {
            return;
        }
        purgeTenantInternal(tenant, now, normalizedFailureStatus(tenant), "tenant.deleted", "tenant.delete_failed");
    }

    private void purgeTenantInternal(
            Tenant tenant,
            Instant now,
            String failureStatus,
            String successAuditAction,
            String failureAuditAction
    ) {
        List<UUID> memberUserIds = resetJdbcTemplate.query(
                "select distinct user_id from platform.tenant_memberships where tenant_id = ?",
                (rs, rowNum) -> UUID.fromString(rs.getString(1)),
                tenant.getId());

        tenant.setStatus("PURGING");
        tenant.setPurgeStatus("IN_PROGRESS");
        tenant.setPurgeStartedAt(tenant.getPurgeStartedAt() == null ? now : tenant.getPurgeStartedAt());
        tenant.setPurgeError(null);
        tenant.setUpdatedAt(now);
        tenantRepository.save(tenant);

        try {
            purgeTenantRows(tenant);
            scrubDemoUserCredentials(memberUserIds, now);
            auditEventService.record(successAuditAction, "tenant", tenant.getId().toString(), null);
        } catch (RuntimeException ex) {
            tenant.setStatus(failureStatus);
            tenant.setPurgeStatus("FAILED");
            tenant.setPurgeError(truncate(ex.getMessage(), 2000));
            tenant.setUpdatedAt(Instant.now());
            tenantRepository.save(tenant);
            auditEventService.record(
                    failureAuditAction,
                    "tenant",
                    tenant.getId().toString(),
                    "{\"error\":\"" + escapeJson(truncate(ex.getMessage(), 512)) + "\"}");
            throw new ResponseStatusException(BAD_REQUEST, "Tenant delete failed: " + truncate(ex.getMessage(), 500), ex);
        }
    }

    private void markExpired(Tenant tenant, Instant now) {
        if (tenant.getExpiredAt() == null) {
            tenant.setExpiredAt(now);
        }
        if ("ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
            tenant.setStatus("EXPIRED");
        }
        if (tenant.getSuspendedAt() == null) {
            tenant.setSuspendedAt(now);
        }
        tenant.setUpdatedAt(now);
        tenantRepository.save(tenant);
        auditEventService.record("demo.tenant.expired", "tenant", tenant.getId().toString(), null);
    }

    private void purgeTenantRows(Tenant tenant) {
        UUID tenantId = tenant.getId();
        tenantSchemaService.dropTenantSchema(tenant.getSchemaName());
        purgeSharedTenantRows(tenantId);
        resetJdbcTemplate.update(
                "update tenant_default.demo_requests set tenant_id = null where tenant_id = ?",
                tenantId);
        resetJdbcTemplate.update("delete from platform.tenants where id = ?", tenantId);
    }

    private void purgeSharedTenantRows(UUID tenantId) {
        List<String> tableNames = resetJdbcTemplate.queryForList("""
                select distinct concat(kcu.table_schema, '.', kcu.table_name)
                from information_schema.table_constraints tc
                join information_schema.key_column_usage kcu
                  on tc.constraint_name = kcu.constraint_name
                 and tc.table_schema = kcu.table_schema
                join information_schema.constraint_column_usage ccu
                  on ccu.constraint_name = tc.constraint_name
                 and ccu.constraint_schema = tc.constraint_schema
                where tc.constraint_type = 'FOREIGN KEY'
                  and ccu.table_schema = 'platform'
                  and ccu.table_name = 'tenants'
                  and ccu.column_name = 'id'
                  and kcu.column_name = 'tenant_id'
                order by 1 desc
                """, String.class);
        for (String tableName : tableNames) {
            if (!hasText(tableName) || "platform.tenants".equalsIgnoreCase(tableName)) {
                continue;
            }
            resetJdbcTemplate.update("delete from " + tableName + " where tenant_id = ?", tenantId);
        }
    }

    private void scrubDemoUserCredentials(List<UUID> userIds, Instant now) {
        for (UUID userId : userIds) {
            resetJdbcTemplate.update("""
                    update platform.app_users u
                    set password_hash = null,
                        password_set_at = null,
                        password_setup_token_hash = null,
                        password_setup_token_expires_at = null,
                        status = case
                            when u.platform_owner = false
                                 and not exists (select 1 from platform.tenant_memberships tm where tm.user_id = u.id)
                            then 'INACTIVE'
                            else u.status
                        end,
                        updated_at = ?
                    where u.id = ?
                      and u.platform_owner = false
                    """, now, userId);
        }
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private String escapeJson(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String normalizedFailureStatus(Tenant tenant) {
        if (tenant == null || tenant.getStatus() == null || tenant.getStatus().isBlank()) {
            return "ACTIVE";
        }
        return tenant.getStatus().trim().toUpperCase();
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

}
