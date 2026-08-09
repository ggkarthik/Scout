package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

/** Non-destructive reconciliation report for retiring legacy AI policy reads. */
@Service
public class AiGridPolicyMigrationService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final AuditEventService audit;
    private final boolean legacyFallbackEnabled;
    public AiGridPolicyMigrationService(NamedParameterJdbcTemplate jdbc, TenantService tenants, TenantSchemaExecutionService tenantExecution, AuditEventService audit,
                                        @Value("${app.features.ai-grid-legacy-policy-fallback-enabled:false}") boolean legacyFallbackEnabled) {
        this.jdbc = jdbc; this.tenants = tenants; this.tenantExecution = tenantExecution; this.audit = audit; this.legacyFallbackEnabled = legacyFallbackEnabled;
    }

    public List<TenantReconciliation> reconciliation() {
        return tenants.listActiveTenants().stream().map(tenant -> tenantExecution.run(tenant, () -> report(tenant))).toList();
    }

    public List<TenantReconciliation> migrateLegacySelections(String actor) {
        for (Tenant tenant : tenants.listActiveTenants()) {
            tenantExecution.run(tenant, () -> {
                jdbc.update("""
                        insert into ai_grid_policy_selections (policy_id,tenant_id,selection,updated_by,reason)
                        select legacy.policy_id,legacy.tenant_id,
                               case when p.default_selection='REQUIRED' then 'REQUIRED'
                                    when legacy.enabled then 'ENABLED' else 'DISABLED' end,
                               :actor,'Migrated from legacy ai_security_policy_settings'
                          from ai_security_policy_settings legacy join lateral (
                               select default_selection from platform.ai_grid_policy_versions p
                                where p.policy_id=legacy.policy_id and p.lifecycle='PUBLISHED'
                                order by p.published_at desc nulls last,p.version desc limit 1) p on true
                        on conflict (policy_id) do nothing
                        """, Map.of("actor", actor));
                return null;
            });
        }
        audit.record("ai_grid.policy_legacy_selections.migrated", "ai_grid_policy_catalog", "all-tenants", "{\"mode\":\"non_destructive\"}");
        return reconciliation();
    }

    private TenantReconciliation report(Tenant tenant) {
        long legacySelections = count("select count(*) from ai_security_policy_settings");
        long governedSelections = count("select count(*) from ai_grid_policy_selections");
        long unmappedLegacySelections = count("""
                select count(*) from ai_security_policy_settings l where not exists (
                    select 1 from platform.ai_grid_policy_versions p where p.policy_id=l.policy_id and p.lifecycle='PUBLISHED')
                """);
        long unmappedScopes = count("""
                select count(*) from ai_security_policy_scopes s where not exists (
                    select 1 from platform.ai_grid_policy_versions p where p.policy_id=s.policy_id and p.lifecycle='PUBLISHED')
                """);
        long unmappedExceptions = count("""
                select count(*) from ai_security_policy_artifact_overrides o where not exists (
                    select 1 from platform.ai_grid_policy_versions p where p.policy_id=o.policy_id and p.lifecycle='PUBLISHED')
                """);
        long unmappedParameters = count("""
                select count(*) from ai_security_policy_parameters x where not exists (
                    select 1 from platform.ai_grid_policy_versions p where p.policy_id=x.policy_id and p.lifecycle='PUBLISHED')
                """);
        long unmappedFindings = count("""
                select count(*) from findings f where f.finding_kind in ('AI_POSTURE','AI_EXPOSURE') and f.policy_id is not null
                  and not exists (select 1 from platform.ai_grid_policy_versions p where p.policy_id=f.policy_id)
                """);
        return new TenantReconciliation(tenant.getId(), tenant.getName(), legacySelections, governedSelections,
                unmappedLegacySelections, unmappedScopes, unmappedExceptions, unmappedParameters, unmappedFindings, Instant.now());
    }
    private long count(String sql) { Long value = jdbc.queryForObject(sql, Map.of(), Long.class); return value == null ? 0 : value; }
    public RetirementStatus retirementStatus() {
        List<TenantReconciliation> rows = reconciliation();
        long unmapped = rows.stream().mapToLong(row -> row.unmappedLegacySelections() + row.unmappedScopes() + row.unmappedExceptions() + row.unmappedParameters() + row.unmappedFindings()).sum();
        return new RetirementStatus(legacyFallbackEnabled, unmapped == 0, rows.size(), unmapped);
    }
    public record TenantReconciliation(UUID tenantId, String tenantName, long legacySelections, long governedSelections,
                                       long unmappedLegacySelections, long unmappedScopes, long unmappedExceptions,
                                       long unmappedParameters, long unmappedFindings, Instant generatedAt) {}
    public record RetirementStatus(boolean legacyFallbackEnabled, boolean eligibleForRetirement, int activeTenantCount, long unmappedRecordCount) {}
}
