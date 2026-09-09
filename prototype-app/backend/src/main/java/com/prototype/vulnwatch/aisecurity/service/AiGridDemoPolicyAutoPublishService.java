package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.service.TenantContext;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Demo-only convenience bootstrap for the bundled AI Grid catalog.
 *
 * This does not weaken the platform governance APIs. It creates an explicit,
 * digest-bound approval record and then uses the same lifecycle and distribution
 * constraints as a normal publication. The feature is opt-in and must be
 * disabled before real customer onboarding.
 */
@Service
public class AiGridDemoPolicyAutoPublishService {
    private static final Logger LOG = LoggerFactory.getLogger(AiGridDemoPolicyAutoPublishService.class);
    private static final String ACTOR = "ai-grid-demo-auto-publish";
    private static final String BUNDLED_SOURCE = "policy-packages/agcf/%";

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final boolean enabled;

    public AiGridDemoPolicyAutoPublishService(
            NamedParameterJdbcTemplate jdbc,
            TransactionTemplate transactions,
            @Value("${app.ai-security.grid.demo-auto-publish-bundled-policies:false}") boolean enabled) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.enabled = enabled;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void autoPublishBundledPolicies() {
        if (!enabled) {
            return;
        }
        TenantContext.runAsPlatform(() -> transactions.executeWithoutResult(status -> {
            List<Policy> policies = jdbc.query("""
                    select distinct on (p.policy_id)
                           p.policy_id,p.version,p.package_digest,p.default_selection
                      from platform.ai_grid_policy_versions p
                     where p.package_source_ref like :source
                       and p.package_digest is not null
                       and p.lifecycle in ('VALIDATED','APPROVED','PUBLISHED','CANARY')
                     order by p.policy_id,p.published_at desc nulls last,p.version desc
                    """, Map.of("source", BUNDLED_SOURCE), (rs, row) -> new Policy(
                    rs.getString("policy_id"), rs.getString("version"),
                    rs.getString("package_digest"), rs.getString("default_selection")));
            String activeTenantIds = jdbc.queryForObject("""
                    select coalesce(jsonb_agg(id order by id), '[]'::jsonb)::text
                      from platform.tenants
                     where status='ACTIVE' and deleted_at is null
                    """, Map.of(), String.class);

            for (Policy policy : policies) {
                UUID decisionId = ensureApproval(policy);
                jdbc.update("""
                        update platform.ai_grid_policy_versions
                           set lifecycle='PUBLISHED', approved_by=:actor,
                               approved_at=coalesce(approved_at,now()),
                               published_at=coalesce(published_at,now())
                         where policy_id=:policyId and version=:version
                        """, Map.of("policyId", policy.policyId(), "version", policy.version(), "actor", ACTOR));

                ensureReleaseBinding(policy, decisionId, activeTenantIds);

                jdbc.update("""
                        insert into platform.ai_grid_policy_distribution
                            (policy_id,available,default_selection,rollout_stage,canary_tenant_ids_json,
                             pinned_version,approved_package_digest,release_decision_id,updated_by)
                        values (:policyId,true,:selection,'GENERAL_AVAILABILITY','[]'::jsonb,
                                :version,:digest,:decisionId,:actor)
                        on conflict (policy_id) do update set
                            available=true,
                            default_selection=excluded.default_selection,
                            rollout_stage='GENERAL_AVAILABILITY',
                            canary_tenant_ids_json='[]'::jsonb,
                            pinned_version=excluded.pinned_version,
                            approved_package_digest=excluded.approved_package_digest,
                            release_decision_id=excluded.release_decision_id,
                            updated_by=excluded.updated_by,
                            updated_at=now()
                        """, new MapSqlParameterSource()
                        .addValue("policyId", policy.policyId())
                        .addValue("selection", policy.defaultSelection())
                        .addValue("version", policy.version())
                        .addValue("digest", policy.packageDigest())
                        .addValue("decisionId", decisionId)
                        .addValue("actor", ACTOR));
            }

            LOG.warn("Demo AI Grid auto-publication enabled: published {} bundled policies to all tenants; disable APP_AI_GRID_DEMO_AUTO_PUBLISH_BUNDLED_POLICIES before customer onboarding", policies.size());
        }));
    }

    private UUID ensureApproval(Policy policy) {
        UUID existing = jdbc.query("""
                select id
                  from platform.ai_grid_policy_release_decisions
                 where policy_id=:policyId and policy_version=:version
                   and decision='APPROVED' and package_digest=:digest and revoked_at is null
                 order by decided_at desc limit 1
                """, new MapSqlParameterSource()
                .addValue("policyId", policy.policyId())
                .addValue("version", policy.version())
                .addValue("digest", policy.packageDigest()),
                rs -> rs.next() ? rs.getObject("id", UUID.class) : null);
        if (existing != null) {
            return existing;
        }

        UUID decisionId = UUID.nameUUIDFromBytes((ACTOR + ":" + policy.policyId() + ":"
                + policy.version() + ":" + policy.packageDigest()).getBytes(StandardCharsets.UTF_8));
        jdbc.update("""
                insert into platform.ai_grid_policy_release_decisions
                    (id,policy_id,policy_version,decision,reason,decided_by,package_digest,approved_package_digest)
                values (:id,:policyId,:version,'APPROVED',:reason,:actor,:digest,:digest)
                on conflict (id) do nothing
                """, new MapSqlParameterSource()
                .addValue("id", decisionId)
                .addValue("policyId", policy.policyId())
                .addValue("version", policy.version())
                .addValue("reason", "Demo catalog auto-approval; governed publication remains enabled for future releases")
                .addValue("actor", ACTOR)
                .addValue("digest", policy.packageDigest()));
        return decisionId;
    }

    private void ensureReleaseBinding(Policy policy, UUID decisionId, String activeTenantIds) {
        UUID bindingId = UUID.nameUUIDFromBytes((ACTOR + ":binding:" + policy.policyId() + ":"
                + policy.version() + ":" + policy.packageDigest()).getBytes(StandardCharsets.UTF_8));
        String distribution = "{\"available\":true,\"rolloutStage\":\"GENERAL_AVAILABILITY\","
                + "\"canaryTenantIds\":[],\"targetTenantIds\":" + activeTenantIds
                + ",\"pinnedVersion\":\"" + policy.version() + "\"}";
        jdbc.update("""
                insert into platform.ai_grid_policy_release_bindings
                    (id,approval_decision_id,policy_id,policy_version,approved_package_digest,
                     distribution_snapshot_json,target_tenant_ids_json,bound_by)
                values (:id,:decisionId,:policyId,:version,:digest,cast(:distribution as jsonb),
                        cast(:targets as jsonb),:actor)
                on conflict (policy_id,policy_version,approved_package_digest) do nothing
                """, new MapSqlParameterSource()
                .addValue("id", bindingId)
                .addValue("decisionId", decisionId)
                .addValue("policyId", policy.policyId())
                .addValue("version", policy.version())
                .addValue("digest", policy.packageDigest())
                .addValue("distribution", distribution)
                .addValue("targets", activeTenantIds)
                .addValue("actor", ACTOR));
    }

    private record Policy(String policyId, String version, String packageDigest, String defaultSelection) {}
}
