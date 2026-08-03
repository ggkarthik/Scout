package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Materializes and reports the deletion-safe union of the latest complete connector scope heads. */
@Service
public class AiGridCoverageService {
    private static final String RUN_EXPECTED_CTE = """
            with artifacts as (
                select distinct on (m.artifact_id) m.artifact_id,
                       b.content_json ->> 'artifactType' artifact_type,
                       b.content_json ->> 'nativeKind' native_kind
                  from ai_grid_snapshot_manifests m
                  join ai_grid_snapshot_bodies b on b.id = m.body_id
                 where m.run_id = :runId
                 order by m.artifact_id, m.observed_at desc, m.id
            ), policies as (
                select distinct on (p.policy_id) p.policy_id, p.version, p.default_selection,
                       p.artifact_types_json, p.native_kinds_json, p.framework_mappings_json
                  from platform.ai_grid_policy_versions p
                 where p.lifecycle = 'PUBLISHED'
                 order by p.policy_id, p.published_at desc, p.version desc
            ), expected as (
                select a.artifact_id, a.artifact_type, a.native_kind, p.policy_id, p.version,
                       p.framework_mappings_json,
                       coalesce(s.selection, p.default_selection) selection
                  from artifacts a
                  cross join policies p
                  left join ai_grid_policy_selections s on s.policy_id = p.policy_id
                 where jsonb_exists(p.artifact_types_json, a.artifact_type)
                   and (jsonb_array_length(p.native_kinds_json) = 0
                        or jsonb_exists(p.native_kinds_json, a.native_kind))
            )
            """;

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;

    public AiGridCoverageService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
    }

    /** Refreshes current posture atomically. Historical run snapshots and assessments are never rewritten. */
    @Transactional
    public UUID refreshCurrent(Tenant tenant, UUID triggerRunId) {
        UUID epochId = UUID.randomUUID();
        MapSqlParameterSource parameters = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("epochId", epochId)
                .addValue("triggerRunId", triggerRunId);
        jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text), 0))",
                parameters, rs -> null);
        jdbc.update("delete from ai_grid_current_expected_candidates", Map.of());
        jdbc.update("delete from ai_grid_current_coverage_artifacts", Map.of());
        jdbc.update("""
                insert into ai_grid_current_coverage_artifacts
                    (tenant_id, epoch_id, artifact_id, source_run_id, snapshot_manifest_id,
                     provider, account_id, region, resource_family, artifact_type, native_kind,
                     technology_id, environment, owner_name, observed_at)
                with scope_heads as (
                    select distinct on (scope_key) scope_key, run_id, provider, account_id,
                           region, resource_family, completed_at
                      from ai_security_snapshot_scopes
                     where status = 'COMPLETE'
                     order by scope_key, completed_at desc, run_id desc
                ), authoritative as (
                    select distinct on (m.artifact_id) m.artifact_id, m.run_id, m.id manifest_id,
                           m.observed_at, h.provider, h.account_id, h.region, h.resource_family
                      from scope_heads h
                      join ai_grid_snapshot_manifests m
                        on m.run_id = h.run_id and m.scope_key = h.scope_key
                     order by m.artifact_id, m.observed_at desc, m.id desc
                )
                select :tenantId, :epochId, a.id, h.run_id, h.manifest_id,
                       h.provider, h.account_id, h.region, h.resource_family,
                       a.artifact_type, a.native_kind,
                       coalesce(c.technology_id, 'UNCLASSIFIED'),
                       coalesce(nullif(a.environment, ''),
                                nullif(a.attributes_json #>> '{tags,environment}', ''),
                                nullif(a.attributes_json ->> 'environment', ''), 'UNSPECIFIED'),
                       coalesce(nullif(a.owner_name, ''), 'UNOWNED'), h.observed_at
                  from authoritative h
                  join ai_security_artifacts a on a.id = h.artifact_id
                  left join lateral (
                      select technology_id from ai_grid_artifact_classifications c
                       where c.artifact_id = a.id and c.state = 'CLASSIFIED'
                       order by c.primary_technology desc, c.classified_at desc, c.technology_id
                       limit 1
                  ) c on true
                """, parameters);
        jdbc.update("""
                insert into ai_grid_current_expected_candidates
                    (tenant_id, epoch_id, trigger_run_id, artifact_id, source_run_id,
                     snapshot_manifest_id, provider, account_id, region, resource_family,
                     artifact_type, native_kind, technology_id, environment, owner_name,
                     policy_id, policy_version, selection, framework_mappings_json,
                     assessment_id, applicability, evidence_readiness, decision,
                     missing_evidence_json, input_facts_json)
                with policies as (
                    select distinct on (p.policy_id) p.policy_id, p.version, p.default_selection,
                           p.artifact_types_json, p.native_kinds_json, p.framework_mappings_json
                      from platform.ai_grid_policy_versions p
                     where p.lifecycle = 'PUBLISHED'
                     order by p.policy_id, p.published_at desc, p.version desc
                )
                select :tenantId, :epochId, :triggerRunId, a.artifact_id, a.source_run_id,
                       a.snapshot_manifest_id, a.provider, a.account_id, a.region, a.resource_family,
                       a.artifact_type, a.native_kind, a.technology_id, a.environment, a.owner_name,
                       p.policy_id, p.version, coalesce(s.selection, p.default_selection),
                       p.framework_mappings_json, x.id, x.applicability, x.evidence_readiness, x.decision,
                       coalesce(x.missing_evidence_json, '[]'::jsonb),
                       coalesce(x.input_facts_json, '{}'::jsonb)
                  from ai_grid_current_coverage_artifacts a
                  cross join policies p
                  left join ai_grid_policy_selections s on s.policy_id = p.policy_id
                  left join ai_grid_assessments x
                    on x.run_id = a.source_run_id and x.policy_id = p.policy_id
                   and x.policy_version = p.version and x.subject_type = 'ARTIFACT'
                   and x.subject_id = a.artifact_id
                 where jsonb_exists(p.artifact_types_json, a.artifact_type)
                   and (jsonb_array_length(p.native_kinds_json) = 0
                        or jsonb_exists(p.native_kinds_json, a.native_kind))
                """, parameters);
        jdbc.update("""
                insert into ai_grid_current_coverage_state
                    (tenant_id, epoch_id, trigger_run_id, scope_head_count, artifact_count, candidate_count)
                values (:tenantId, :epochId, :triggerRunId,
                        (select count(*) from (select distinct on (scope_key) scope_key
                                                from ai_security_snapshot_scopes where status = 'COMPLETE'
                                                order by scope_key, completed_at desc, run_id desc) heads),
                        (select count(*) from ai_grid_current_coverage_artifacts),
                        (select count(*) from ai_grid_current_expected_candidates))
                on conflict (tenant_id) do update set
                    epoch_id = excluded.epoch_id, trigger_run_id = excluded.trigger_run_id,
                    scope_head_count = excluded.scope_head_count, artifact_count = excluded.artifact_count,
                    candidate_count = excluded.candidate_count, materialized_at = now()
                """, parameters);
        return epochId;
    }

    public Coverage coverage(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            CurrentState state = currentState();
            if (state == null) return Coverage.empty();
            return jdbc.queryForObject("""
                    select count(*) expected_assessments,
                           count(assessment_id) recorded_assessments,
                           count(*) filter (where assessment_id is null) missing_assessments,
                           count(*) filter (where applicability = 'APPLICABLE') applicable_published,
                           count(*) filter (where selection = 'REQUIRED') required,
                           count(*) filter (where selection = 'ENABLED') tenant_enabled,
                           count(*) filter (where selection = 'PREVIEW') preview,
                           count(*) filter (where selection = 'DISABLED') tenant_disabled,
                           count(*) filter (where evidence_readiness = 'READY') evidence_ready,
                           count(*) filter (where decision = 'PASS') evaluated_pass,
                           count(*) filter (where decision = 'FAIL') evaluated_fail,
                           count(*) filter (where decision in ('PASS','FAIL')
                                                and selection in ('REQUIRED','ENABLED')) owner_facing_decisions,
                           count(*) filter (where selection in ('REQUIRED','ENABLED')
                                                and applicability is distinct from 'NOT_APPLICABLE') owner_facing_expected,
                           count(*) filter (where decision = 'NO_DECISION') no_decision,
                           count(*) filter (where applicability = 'NOT_APPLICABLE') not_applicable,
                           count(*) filter (where evidence_readiness = 'STALE') stale,
                           count(*) filter (where evidence_readiness = 'UNSUPPORTED') unsupported,
                           count(*) filter (where applicability = 'APPLICABLE'
                                                and selection in ('PREVIEW','DISABLED')) applicable_not_enabled,
                           count(distinct policy_id) policies_with_resources
                      from ai_grid_current_expected_candidates where epoch_id = :epochId
                    """, Map.of("epochId", state.epochId()), (rs, n) -> coverage(state, rs));
        });
    }

    public List<CoverageItem> details(Tenant tenant) {
        return tenantExecution.run(tenant, this::currentCandidates);
    }

    public List<CoverageDimension> dimensions(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            CurrentState state = currentState();
            if (state == null) return List.of();
            return jdbc.query("""
                    with expanded as (
                        select c.*, d.dimension, d.value
                          from ai_grid_current_expected_candidates c
                          cross join lateral (values
                            ('TECHNOLOGY', c.technology_id), ('PROVIDER', c.provider),
                            ('FAMILY', c.resource_family), ('ACCOUNT', c.account_id),
                            ('ENVIRONMENT', c.environment), ('OWNER', c.owner_name),
                            ('POLICY', c.policy_id)) d(dimension, value)
                         where c.epoch_id = :epochId
                        union all
                        select c.*, 'FRAMEWORK', framework.key
                          from ai_grid_current_expected_candidates c
                          cross join lateral jsonb_each(c.framework_mappings_json) framework
                         where c.epoch_id = :epochId
                    )
                    select dimension, value, count(*) expected,
                           count(assessment_id) recorded,
                           count(*) filter (where assessment_id is null) missing,
                           count(*) filter (where decision = 'PASS') pass,
                           count(*) filter (where decision = 'FAIL') fail,
                           count(*) filter (where decision = 'NO_DECISION') no_decision
                      from expanded
                     group by dimension, value order by dimension, value
                    """, Map.of("epochId", state.epochId()), (rs, n) -> new CoverageDimension(
                    state.epochId(), rs.getString("dimension"), rs.getString("value"),
                    rs.getLong("expected"), rs.getLong("recorded"), rs.getLong("missing"),
                    rs.getLong("pass"), rs.getLong("fail"), rs.getLong("no_decision")));
        });
    }

    List<CoverageItem> currentCandidates() {
        CurrentState state = currentState();
        if (state == null) return List.of();
        return jdbc.query("""
                select source_run_id, artifact_id, artifact_type, native_kind, policy_id, policy_version,
                       selection, assessment_id, applicability, evidence_readiness, decision,
                       case when assessment_id is null then 'MISSING_ASSESSMENT' end gap_state,
                       provider, account_id, region, resource_family, technology_id, environment, owner_name,
                       framework_mappings_json::text, missing_evidence_json::text, input_facts_json::text
                  from ai_grid_current_expected_candidates where epoch_id = :epochId
                 order by provider, resource_family, artifact_type, artifact_id, policy_id
                """, Map.of("epochId", state.epochId()), this::coverageItem);
    }

    List<CoverageItem> expectedCandidates(UUID runId) {
        return jdbc.query(RUN_EXPECTED_CTE + """
                select :runId::uuid source_run_id, e.artifact_id, e.artifact_type, e.native_kind,
                       e.policy_id, e.version policy_version, e.selection,
                       x.id assessment_id, x.applicability, x.evidence_readiness, x.decision,
                       case when x.id is null then 'MISSING_ASSESSMENT' end gap_state,
                       null::varchar provider, null::varchar account_id, null::varchar region,
                       null::varchar resource_family, null::varchar technology_id,
                       null::varchar environment, null::varchar owner_name,
                       e.framework_mappings_json::text framework_mappings_json,
                       coalesce(x.missing_evidence_json, '[]'::jsonb)::text missing_evidence_json,
                       coalesce(x.input_facts_json, '{}'::jsonb)::text input_facts_json
                  from expected e
                  left join ai_grid_assessments x
                    on x.run_id = :runId and x.policy_id = e.policy_id and x.policy_version = e.version
                   and x.subject_type = 'ARTIFACT' and x.subject_id = e.artifact_id
                 order by e.artifact_type, e.artifact_id, e.policy_id
                """, Map.of("runId", runId), this::coverageItem);
    }

    CurrentState currentState() {
        return jdbc.query("""
                select epoch_id, trigger_run_id, scope_head_count, artifact_count, candidate_count, materialized_at
                  from ai_grid_current_coverage_state
                """, Map.of(), rs -> rs.next() ? new CurrentState(
                rs.getObject("epoch_id", UUID.class), rs.getObject("trigger_run_id", UUID.class),
                rs.getLong("scope_head_count"), rs.getLong("artifact_count"), rs.getLong("candidate_count"),
                rs.getTimestamp("materialized_at").toInstant()) : null);
    }

    private CoverageItem coverageItem(java.sql.ResultSet rs, int n) throws java.sql.SQLException {
        return new CoverageItem(rs.getObject("source_run_id", UUID.class), rs.getObject("artifact_id", UUID.class),
                rs.getString("artifact_type"), rs.getString("native_kind"), rs.getString("policy_id"),
                rs.getString("policy_version"), rs.getString("selection"),
                rs.getObject("assessment_id", UUID.class), rs.getString("applicability"),
                rs.getString("evidence_readiness"), rs.getString("decision"), rs.getString("gap_state"),
                rs.getString("provider"), rs.getString("account_id"), rs.getString("region"),
                rs.getString("resource_family"), rs.getString("technology_id"), rs.getString("environment"),
                rs.getString("owner_name"), rs.getString("framework_mappings_json"),
                rs.getString("missing_evidence_json"), rs.getString("input_facts_json"));
    }

    private Coverage coverage(CurrentState state, java.sql.ResultSet rs) throws java.sql.SQLException {
        long expected = rs.getLong("expected_assessments");
        long ownerExpected = rs.getLong("owner_facing_expected");
        long decisions = rs.getLong("evaluated_pass") + rs.getLong("evaluated_fail");
        Long published = jdbc.queryForObject("""
                select count(distinct policy_id) from platform.ai_grid_policy_versions where lifecycle = 'PUBLISHED'
                """, Map.of(), Long.class);
        long publishedPolicies = published == null ? 0 : published;
        long policiesWithResources = rs.getLong("policies_with_resources");
        return new Coverage(state.triggerRunId(), state.epochId(), state.scopeHeadCount(), state.artifactCount(),
                publishedPolicies, policiesWithResources, Math.max(0, publishedPolicies - policiesWithResources), expected,
                rs.getLong("recorded_assessments"), rs.getLong("missing_assessments"),
                rs.getLong("applicable_published"), rs.getLong("required"), rs.getLong("tenant_enabled"),
                rs.getLong("preview"), rs.getLong("tenant_disabled"), rs.getLong("evidence_ready"),
                rs.getLong("evaluated_pass"), rs.getLong("evaluated_fail"), rs.getLong("no_decision"),
                rs.getLong("not_applicable"), rs.getLong("stale"), rs.getLong("unsupported"),
                rs.getLong("applicable_not_enabled"), percentage(decisions, expected),
                percentage(rs.getLong("owner_facing_decisions"), ownerExpected));
    }

    private static double percentage(long numerator, long denominator) {
        return denominator == 0 ? 0.0 : Math.round((10000.0 * numerator) / denominator) / 100.0;
    }

    public record CurrentState(UUID epochId, UUID triggerRunId, long scopeHeadCount,
                               long artifactCount, long candidateCount, java.time.Instant materializedAt) {}
    public record Coverage(UUID runId, UUID coverageEpochId, long authoritativeScopeHeads, long currentArtifacts,
                           long publishedPolicies, long policiesWithResources, long noResourcePolicies,
                           long expectedAssessments, long recordedAssessments, long missingAssessments,
                           long applicablePublished, long required, long tenantEnabled, long preview,
                           long tenantDisabled, long evidenceReady, long evaluatedPass, long evaluatedFail,
                           long noDecision, long notApplicable, long stale, long unsupported,
                           long applicableNotEnabled, double decisionReachabilityPercent,
                           double ownerFacingDecisionReachabilityPercent) {
        static Coverage empty() {
            return new Coverage(null, null, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
    }
    public record CoverageItem(UUID runId, UUID artifactId, String artifactType, String nativeKind,
                               String policyId, String policyVersion, String selection, UUID assessmentId,
                               String applicability, String evidenceReadiness, String decision, String gapState,
                               String provider, String accountId, String region, String resourceFamily,
                               String technologyId, String environment, String ownerName, String frameworkMappingsJson,
                               String missingEvidenceJson, String inputFactsJson) {
        public boolean assessmentPresent() { return assessmentId != null; }
    }
    public record CoverageDimension(UUID coverageEpochId, String dimension, String value, long expected,
                                    long recorded, long missing, long pass, long fail, long noDecision) {}
}
