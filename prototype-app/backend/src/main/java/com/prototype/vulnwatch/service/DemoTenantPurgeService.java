package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DemoTenantPurgeService {

    private final TenantRepository tenantRepository;
    private final JdbcTemplate resetJdbcTemplate;
    private final JdbcTemplate tenantJdbcTemplate;
    private final AuditEventService auditEventService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final TenantSchemaService tenantSchemaService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public DemoTenantPurgeService(
            TenantRepository tenantRepository,
            @Qualifier("prototypeResetJdbcTemplate")
            JdbcTemplate resetJdbcTemplate,
            JdbcTemplate tenantJdbcTemplate,
            AuditEventService auditEventService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            TenantSchemaService tenantSchemaService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.tenantRepository = tenantRepository;
        this.resetJdbcTemplate = resetJdbcTemplate;
        this.tenantJdbcTemplate = tenantJdbcTemplate;
        this.auditEventService = auditEventService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.tenantSchemaService = tenantSchemaService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void processExpiredTenant(UUID tenantId, Instant now) {
        Tenant tenant = tenantRepository.findById(tenantId).orElse(null);
        if (tenant == null || tenant.getPurgedAt() != null || !tenantLifecycleGuardService.isDemoTenant(tenant)) {
            return;
        }
        if (tenant.getDemoExpiresAt() == null || tenant.getDemoExpiresAt().isAfter(now)) {
            return;
        }

        if (!"DELETED".equalsIgnoreCase(tenant.getStatus())) {
            markExpired(tenant, now);
        }
        if (tenant.getPurgedAt() != null) {
            return;
        }

        List<UUID> memberUserIds = resetJdbcTemplate.query(
                "select distinct user_id from platform.tenant_memberships where tenant_id = ?",
                (rs, rowNum) -> UUID.fromString(rs.getString(1)),
                tenantId);

        tenant.setStatus("PURGING");
        tenant.setPurgeStatus("IN_PROGRESS");
        tenant.setPurgeStartedAt(tenant.getPurgeStartedAt() == null ? now : tenant.getPurgeStartedAt());
        tenant.setPurgeError(null);
        tenant.setUpdatedAt(now);
        tenantRepository.save(tenant);

        try {
            purgeTenantRows(tenant, now);
            scrubDemoUserCredentials(memberUserIds, now);
            tenant.setStatus("DELETED");
            tenant.setDeletedAt(now);
            tenant.setPurgedAt(now);
            tenant.setPurgeStatus("COMPLETED");
            tenant.setPurgeError(null);
            tenant.setUpdatedAt(now);
            tenantRepository.save(tenant);
            auditEventService.record("demo.tenant.purged", "tenant", tenantId.toString(), null);
        } catch (RuntimeException ex) {
            tenant.setStatus("EXPIRED");
            tenant.setPurgeStatus("FAILED");
            tenant.setPurgeError(truncate(ex.getMessage(), 2000));
            tenant.setUpdatedAt(Instant.now());
            tenantRepository.save(tenant);
            auditEventService.record(
                    "demo.tenant.purge_failed",
                    "tenant",
                    tenantId.toString(),
                    "{\"error\":\"" + escapeJson(truncate(ex.getMessage(), 512)) + "\"}");
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

    private void purgeTenantRows(Tenant tenant, Instant now) {
        UUID tenantId = tenant.getId();
        tenantSchemaExecutionService.run(tenant, () -> {
            tenantJdbcTemplate.update(
                    "update demo_invites set status = ?, expires_at = least(expires_at, ?::timestamptz) where tenant_id = ? and upper(status) <> 'ACCEPTED'",
                    "TENANT_EXPIRED",
                    now,
                    tenantId);
        });

        tenantSchemaService.resetTenantSchema(tenant.getSchemaName());

        resetJdbcTemplate.update("delete from platform.tenant_support_grants where tenant_id = ?", tenantId);
        resetJdbcTemplate.update("delete from platform.tenant_memberships where tenant_id = ?", tenantId);
    }

    private void scrubDemoUserCredentials(List<UUID> userIds, Instant now) {
        for (UUID userId : userIds) {
            resetJdbcTemplate.update("""
                    update app_users u
                    set password_hash = null,
                        password_set_at = null,
                        password_setup_token_hash = null,
                        password_setup_token_expires_at = null,
                        status = case
                            when u.platform_owner = false
                                 and not exists (select 1 from tenant_memberships tm where tm.user_id = u.id)
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
}
