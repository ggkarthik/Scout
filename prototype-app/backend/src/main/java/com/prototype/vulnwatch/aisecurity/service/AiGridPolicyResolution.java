package com.prototype.vulnwatch.aisecurity.service;

/** Shared SQL contract for distributed static policy versions and effective tenant selections. */
public final class AiGridPolicyResolution {
    private AiGridPolicyResolution() {}

    public static String selection(String selectionAlias, String distributionAlias, String policyAlias) {
        return "case when " + selectionAlias + ".configuration_source='TENANT_OVERRIDE' then "
                + selectionAlias + ".selection else coalesce(" + distributionAlias
                + ".default_selection," + policyAlias + ".default_selection) end";
    }

    /** The tenant expression is supplied by trusted application code, never request input. */
    public static String versions(String tenantExpression) { return versions(tenantExpression,true); }
    public static String catalogVersions(String tenantExpression) { return versions(tenantExpression,false); }
    private static String versions(String tenantExpression,boolean visible) {
        return "(" + """
                select distinct on (v.policy_id) v.*,
                       coalesce(d.default_selection,v.default_selection) resolved_default_selection
                  from platform.ai_grid_policy_versions v
                  join platform.ai_grid_policy_distribution d on d.policy_id=v.policy_id
                 where (v.evaluation_mode is null or v.evaluation_mode not like 'RUNTIME_%%')
                   and v.policy_id not like 'AGCF-RT-%%'
                   and (v.release_family is null or v.release_family in ('AGCF_PHASE_1','AGCF_PHASE_2'))
                   and ((d.pinned_version is not null and v.version=d.pinned_version
                         and v.lifecycle in ('VALIDATED','APPROVED','PUBLISHED','CANARY'))
                        or (d.pinned_version is null and v.lifecycle in ('PUBLISHED','CANARY')))
                   and (d.approved_package_digest is null or d.approved_package_digest=v.package_digest)
                   and (d.release_decision_id is null or exists (
                        select 1 from platform.ai_grid_policy_release_decisions decision
                         where decision.id=d.release_decision_id and decision.policy_id=v.policy_id
                           and decision.policy_version=v.version and decision.decision='APPROVED'
                           and decision.revoked_at is null and decision.package_digest=v.package_digest
                           and (decision.approved_package_digest is null
                                or decision.approved_package_digest=v.package_digest)))
                   and (not exists (select 1 from platform.ai_grid_policy_release_bindings binding
                         where binding.policy_id=v.policy_id and binding.policy_version=v.version)
                        or exists (select 1 from platform.ai_grid_policy_release_bindings binding
                         join platform.ai_grid_policy_release_decisions decision
                           on decision.id=binding.approval_decision_id
                        where binding.policy_id=v.policy_id and binding.policy_version=v.version
                          and binding.state='ACTIVE' and decision.decision='APPROVED'
                          and decision.revoked_at is null
                          and binding.approved_package_digest=v.package_digest
                          and decision.approved_package_digest=binding.approved_package_digest
                          and (%s)))
                   and (%s)
                 order by v.policy_id,v.published_at desc nulls last,v.created_at desc nulls last,v.version desc
                """.formatted(visible ? "jsonb_exists(binding.target_tenant_ids_json,cast(" + tenantExpression + " as text))" : "true",
                        visible ? "platform.ai_grid_policy_visible_to_tenant(d.available,d.rollout_stage,d.canary_tenant_ids_json,cast(" + tenantExpression + " as uuid))" : "true") + ")";
    }

    public static String currentVersions() {
        return versions("nullif(current_setting('app.current_tenant_id',true),'')");
    }
}
