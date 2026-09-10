package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Seeds the tenant boundary from the published platform catalog without overwriting tenant decisions. */
@Service
public class AiGridTenantPolicyDefaultsService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;

    public AiGridTenantPolicyDefaultsService(NamedParameterJdbcTemplate jdbc,
                                              TenantSchemaExecutionService tenantExecution) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
    }

    public void ensureDefaults(Tenant tenant) {
        List<Baseline> baselines = TenantContext.runAsPlatform(() -> jdbc.query("""
                select p.policy_id, p.version, d.default_selection
                  from platform.ai_grid_policy_versions p
                  join platform.ai_grid_policy_distribution d on d.policy_id = p.policy_id
                   and (d.pinned_version is null or d.pinned_version = p.version)
                 where p.lifecycle in ('PUBLISHED', 'CANARY')
                   and d.available = true
                   and (d.rollout_stage = 'GENERAL_AVAILABILITY'
                        or (d.rollout_stage in ('CANARY', 'DEV')
                            and jsonb_exists(d.canary_tenant_ids_json, cast(:tenantId as text))))
                 order by p.policy_id, p.version desc
                """, Map.of("tenantId", tenant.getId().toString()), (rs, row) ->
                new Baseline(rs.getString("policy_id"), rs.getString("version"), rs.getString("default_selection"))));
        tenantExecution.run(tenant, () -> {
            for (Baseline baseline : baselines) {
                String selection = "REQUIRED".equals(baseline.platformDefault()) ? "REQUIRED" : "ENABLED";
                jdbc.update("""
                        insert into ai_grid_policy_selections
                            (policy_id, tenant_id, selection, updated_by, reason,
                             platform_policy_version, platform_default_selection, configuration_source)
                        values (:policyId, :tenantId, :selection, 'platform-policy-defaults',
                                'Initialized from platform policy catalog', :version, :platformDefault, 'PLATFORM_DEFAULT')
                        on conflict (policy_id) do update set
                            platform_policy_version = excluded.platform_policy_version,
                            platform_default_selection = excluded.platform_default_selection
                        where ai_grid_policy_selections.configuration_source = 'PLATFORM_DEFAULT'
                        """, new MapSqlParameterSource()
                        .addValue("policyId", baseline.policyId())
                        .addValue("tenantId", tenant.getId())
                        .addValue("selection", selection)
                        .addValue("version", baseline.version())
                        .addValue("platformDefault", baseline.platformDefault()));
            }
        });
    }

    private record Baseline(String policyId, String version, String platformDefault) {}
}
