package com.prototype.vulnwatch.aisecurity.service;

/** Immutable evidence bindings for the union of complete connector scope heads. */
final class AiGridCurrentEvidence {
    private AiGridCurrentEvidence() {}
    static final String MANIFESTS = """
            with heads as (
                select distinct on (scope_key) scope_key,run_id,provider,account_id,region,resource_family
                  from ai_security_snapshot_scopes where status='COMPLETE'
                 order by scope_key,completed_at desc nulls last,run_id desc
            )
            select distinct on (m.artifact_id) m.* from heads h
              join ai_grid_snapshot_manifests m on m.scope_key=h.scope_key and m.run_id=h.run_id
             order by m.artifact_id,case when h.region='GLOBAL' then 1 else 0 end,m.observed_at desc,m.id desc
            """;    static final String SCOPE_MANIFESTS = """
            with heads as (
                select distinct on(scope_key) scope_key,run_id from ai_security_snapshot_scopes
                 where status='COMPLETE' order by scope_key,completed_at desc nulls last,run_id desc
            )
            select m.* from heads h join ai_grid_snapshot_manifests m on m.scope_key=h.scope_key and m.run_id=h.run_id
            """;

}
