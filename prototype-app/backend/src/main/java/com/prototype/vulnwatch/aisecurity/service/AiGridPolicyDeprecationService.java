package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Applies platform policy deprecation to the catalog and every active tenant. */
@Service
public class AiGridPolicyDeprecationService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiGridFindingService findings;

    public AiGridPolicyDeprecationService(NamedParameterJdbcTemplate jdbc, TenantService tenants,
                                           TenantSchemaExecutionService tenantExecution,
                                           AiGridFindingService findings) {
        this.jdbc = jdbc;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.findings = findings;
    }

    @Transactional
    public void deprecate(String policyId, String version, String actor) {
        Map<String, Object> release = jdbc.query("""
                select p.package_digest, r.id
                  from platform.ai_grid_policy_versions p
                  left join lateral (
                      select id from platform.ai_grid_policy_release_decisions
                       where policy_id=p.policy_id and policy_version=p.version
                         and decision='APPROVED' and package_digest=p.package_digest
                       order by decided_at desc limit 1
                  ) r on true
                 where p.policy_id=:id and p.version=:version
                """, Map.of("id", policyId, "version", version), rs -> {
                    if (!rs.next()) return Map.of();
                    Map<String, Object> result = new java.util.HashMap<>();
                    result.put("digest", rs.getString(1));
                    result.put("decisionId", rs.getObject(2, UUID.class));
                    return result;
                });
        if (release.isEmpty()) throw new IllegalArgumentException("Policy version not found");
        jdbc.update("""
                update platform.ai_grid_policy_versions
                   set lifecycle='DEPRECATED', approved_by=:actor, approved_at=coalesce(approved_at, now())
                 where policy_id=:id and version=:version and lifecycle in ('PUBLISHED','CANARY')
                """, Map.of("id", policyId, "version", version, "actor", actor));
        if (!release.containsKey("decisionId") || release.get("decisionId") == null) {
            jdbc.update("""
                    update platform.ai_grid_policy_distribution
                       set available=false, rollout_stage='PAUSED', canary_tenant_ids_json='[]'::jsonb,
                           updated_by=:actor, updated_at=now()
                     where policy_id=:id
                    """, Map.of("id", policyId, "actor", actor));
        } else {
            jdbc.update("""
                    update platform.ai_grid_policy_distribution
                       set available=true, rollout_stage='PAUSED', default_selection='DISABLED',
                           canary_tenant_ids_json='[]'::jsonb, approved_package_digest=:digest,
                           release_decision_id=:decisionId, updated_by=:actor, updated_at=now()
                     where policy_id=:id
                    """, new MapSqlParameterSource().addValue("id", policyId).addValue("actor", actor)
                    .addValue("digest", release.get("digest")).addValue("decisionId", release.get("decisionId")));
        }
        for (Tenant tenant : tenants.listActiveTenants()) {
            tenantExecution.run(tenant, () -> findings.closeForPolicy(tenant, policyId,
                    FindingCloseReason.AUTO_POLICY_PLATFORM_DEPRECATED));
        }
    }
}
