package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Seeds the tenant boundary from the published platform catalog without overwriting tenant decisions. */
@Service
public class AiGridTenantPolicyDefaultsService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final AuditEventService audit;

    public AiGridTenantPolicyDefaultsService(NamedParameterJdbcTemplate jdbc,
                                              TenantSchemaExecutionService tenantExecution,
                                              AuditEventService audit) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.audit = audit;
    }

    public SynchronizationResult ensureDefaults(Tenant tenant) {
        List<Baseline> baselines = TenantContext.runAsPlatform(() -> jdbc.query("""
                select d.policy_id, p.version, d.default_selection
                  from platform.ai_grid_policy_distribution d
                  join lateral (
                        select candidate.version
                          from platform.ai_grid_policy_versions candidate
                         where candidate.policy_id = d.policy_id
                           and candidate.lifecycle in ('PUBLISHED', 'CANARY')
                           and (d.pinned_version is null or d.pinned_version = candidate.version)
                         order by candidate.published_at desc nulls last,
                                  candidate.created_at desc,
                                  candidate.version desc
                         limit 1
                  ) p on true
                 where platform.ai_grid_policy_visible_to_tenant(
                           d.available, d.rollout_stage, d.canary_tenant_ids_json, cast(:tenantId as uuid))
                 order by d.policy_id
                """, Map.of("tenantId", tenant.getId().toString()), (rs, row) ->
                new Baseline(rs.getString("policy_id"), rs.getString("version"), rs.getString("default_selection"))));
        return tenantExecution.run(tenant, () -> {
            Map<String, CurrentSelection> current = new HashMap<>();
            List<CurrentSelectionRow> currentRows = jdbc.query("""
                    select policy_id, selection, configuration_source
                      from ai_grid_policy_selections
                    """, Map.of(), (rs, row) -> new CurrentSelectionRow(
                    rs.getString("policy_id"), rs.getString("selection"),
                    rs.getString("configuration_source")));
            currentRows.forEach(row -> current.put(row.policyId(),
                    new CurrentSelection(row.selection(), row.configurationSource())));
            int restrictiveMoves = (int) baselines.stream().filter(baseline -> {
                CurrentSelection selection = current.get(baseline.policyId());
                return selection != null
                        && "PLATFORM_DEFAULT".equals(selection.configurationSource())
                        && "ENABLED".equals(selection.selection())
                        && ("DISABLED".equals(baseline.platformDefault())
                            || "PREVIEW".equals(baseline.platformDefault()));
            }).count();
            if (restrictiveMoves > 0) {
                audit.recordExplicitActor(tenant.getId(), "platform-policy-defaults", "SYSTEM",
                        "ai_grid.policy_defaults.backfill_planned", "tenant", tenant.getId().toString(),
                        "{\"enabledToDisabledOrPreview\":" + restrictiveMoves + "}", "SUCCESS");
            }

            int inserted = 0;
            int realigned = 0;
            for (Baseline baseline : baselines) {
                CurrentSelection previous = current.get(baseline.policyId());
                jdbc.update("""
                        insert into ai_grid_policy_selections
                            (policy_id, tenant_id, selection, updated_by, reason,
                             platform_policy_version, platform_default_selection, configuration_source)
                        values (:policyId, :tenantId, :selection, 'platform-policy-defaults',
                                'Initialized from platform policy catalog', :version, :platformDefault, 'PLATFORM_DEFAULT')
                        on conflict (policy_id) do update set
                            selection = case
                                when ai_grid_policy_selections.configuration_source = 'PLATFORM_DEFAULT'
                                    then excluded.selection
                                else ai_grid_policy_selections.selection
                            end,
                            updated_by = case
                                when ai_grid_policy_selections.configuration_source = 'PLATFORM_DEFAULT'
                                    then excluded.updated_by
                                else ai_grid_policy_selections.updated_by
                            end,
                            reason = case
                                when ai_grid_policy_selections.configuration_source = 'PLATFORM_DEFAULT'
                                    then 'Realigned with platform policy default'
                                else ai_grid_policy_selections.reason
                            end,
                            updated_at = case
                                when ai_grid_policy_selections.configuration_source = 'PLATFORM_DEFAULT'
                                    then now()
                                else ai_grid_policy_selections.updated_at
                            end,
                            platform_policy_version = excluded.platform_policy_version,
                            platform_default_selection = excluded.platform_default_selection
                        """, new MapSqlParameterSource()
                        .addValue("policyId", baseline.policyId())
                        .addValue("tenantId", tenant.getId())
                        .addValue("selection", baseline.platformDefault())
                        .addValue("version", baseline.version())
                        .addValue("platformDefault", baseline.platformDefault()));
                if (previous == null) {
                    inserted++;
                } else if ("PLATFORM_DEFAULT".equals(previous.configurationSource())
                        && !baseline.platformDefault().equals(previous.selection())) {
                    realigned++;
                    jdbc.update("""
                            insert into ai_grid_policy_selection_history
                                (id, tenant_id, policy_id, previous_selection, selection, actor, reason)
                            values (:id, :tenantId, :policyId, :previous, :selection,
                                    'platform-policy-defaults', 'Realigned with platform policy default')
                            """, new MapSqlParameterSource()
                            .addValue("id", UUID.randomUUID())
                            .addValue("tenantId", tenant.getId())
                            .addValue("policyId", baseline.policyId())
                            .addValue("previous", previous.selection())
                            .addValue("selection", baseline.platformDefault()));
                    audit.recordExplicitActor(tenant.getId(), "platform-policy-defaults", "SYSTEM",
                            "ai_grid.policy_default.realigned", "ai_grid_policy", baseline.policyId(),
                            "{\"previousSelection\":\"" + previous.selection()
                                    + "\",\"selection\":\"" + baseline.platformDefault()
                                    + "\",\"platformPolicyVersion\":\"" + baseline.version() + "\"}",
                            "SUCCESS");
                }
            }
            return new SynchronizationResult(baselines.size(), inserted, realigned, restrictiveMoves);
        });
    }

    private record Baseline(String policyId, String version, String platformDefault) {}
    private record CurrentSelectionRow(String policyId, String selection, String configurationSource) {}
    private record CurrentSelection(String selection, String configurationSource) {}
    public record SynchronizationResult(int distributedPolicies, int insertedPolicies,
                                        int realignedPolicies, int enabledToDisabledOrPreview) {}
}
