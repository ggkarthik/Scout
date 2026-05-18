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
    private final JdbcTemplate jdbcTemplate;
    private final AuditEventService auditEventService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;

    public DemoTenantPurgeService(
            TenantRepository tenantRepository,
            @Qualifier("prototypeResetJdbcTemplate")
            JdbcTemplate jdbcTemplate,
            AuditEventService auditEventService,
            TenantLifecycleGuardService tenantLifecycleGuardService
    ) {
        this.tenantRepository = tenantRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.auditEventService = auditEventService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
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

        List<UUID> memberUserIds = jdbcTemplate.query(
                "select distinct user_id from tenant_memberships where tenant_id = ?",
                (rs, rowNum) -> UUID.fromString(rs.getString(1)),
                tenantId);

        tenant.setStatus("PURGING");
        tenant.setPurgeStatus("IN_PROGRESS");
        tenant.setPurgeStartedAt(tenant.getPurgeStartedAt() == null ? now : tenant.getPurgeStartedAt());
        tenant.setPurgeError(null);
        tenant.setUpdatedAt(now);
        tenantRepository.save(tenant);

        try {
            purgeTenantRows(tenantId, now);
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

    private void purgeTenantRows(UUID tenantId, Instant now) {
        jdbcTemplate.update(
                "update demo_invites set status = ?, expires_at = least(expires_at, ?::timestamptz) where tenant_id = ? and upper(status) <> 'ACCEPTED'",
                "TENANT_EXPIRED",
                now,
                tenantId);

        jdbcTemplate.update("delete from finding_comments where finding_id in (select id from findings where tenant_id = ?)", tenantId);
        jdbcTemplate.update("delete from finding_events where finding_id in (select id from findings where tenant_id = ?)", tenantId);
        jdbcTemplate.update("delete from finding_delta_queue where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from investigation_attachments where investigation_id in (select id from investigations where tenant_id = ?)", tenantId);
        jdbcTemplate.update("delete from investigation_activities where investigation_id in (select id from investigations where tenant_id = ?)", tenantId);

        jdbcTemplate.update("delete from applicability_assessments where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from investigations where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from fix_records where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from suppression_rules where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from risk_policies where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from findings where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from component_vulnerability_states where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from org_cve_records where tenant_id = ?", tenantId);

        jdbcTemplate.update("delete from inventory_component_cpe_map where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from software_inventory_items where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from software_instances where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from software_identity_metadata where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from ci_aliases where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from discovery_models where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from cis where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from sbom_uploads where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from inventory_components where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from assets where tenant_id = ?", tenantId);

        jdbcTemplate.update("delete from aws_discovery_targets where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from aws_discovery_configs where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from servicenow_cmdb_configs where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from sccm_cmdb_configs where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from github_sbom_sources where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from sync_runs where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from vulnerability_source_filter_configs where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from tenant_support_grants where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from service_accounts where tenant_id = ?", tenantId);
        jdbcTemplate.update("delete from tenant_memberships where tenant_id = ?", tenantId);
    }

    private void scrubDemoUserCredentials(List<UUID> userIds, Instant now) {
        for (UUID userId : userIds) {
            jdbcTemplate.update("""
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
