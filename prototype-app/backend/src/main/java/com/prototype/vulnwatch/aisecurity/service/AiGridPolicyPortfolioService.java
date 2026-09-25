package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AiGridPolicyPortfolioService {
    private final NamedParameterJdbcTemplate jdbc; private final ObjectMapper mapper; private final AuditEventService audit;
    private final TenantSchemaExecutionService tenantExecution;
    public AiGridPolicyPortfolioService(NamedParameterJdbcTemplate jdbc, ObjectMapper mapper, AuditEventService audit,
                                        TenantSchemaExecutionService tenantExecution) {
        this.jdbc=jdbc; this.mapper=mapper; this.audit=audit; this.tenantExecution=tenantExecution;
    }
    /**
     * Per-control coverage for a framework version, built from the structured mapping model
     * ({framework, frameworkVersion, controlId, mappingType, rationale}). Coverage status is
     * derived only from what the pinned coverage epoch proves. REQUIRED/ENABLED policies may
     * become EFFECTIVE; PREVIEW is reported separately; mapped but undistributed policies remain
     * BREADTH_ONLY; and a tenant below schema V2 receives NOT_ASSESSED with an explicit blocker.
     */
    public FrameworkCoverage frameworkCoverage(Tenant tenant, String framework, String version, UUID requestedEpoch) {
        return tenantExecution.run(tenant, () -> {
            Integer registeredFramework = jdbc.queryForObject("""
                    select count(*) from platform.ai_grid_frameworks
                     where framework_key=:framework and framework_version=:version and lifecycle='ACTIVE'
                    """, Map.of("framework", framework, "version", version), Integer.class);
            if (registeredFramework == null || registeredFramework != 1) {
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND, "AI Grid framework version was not found");
            }
            UUID epoch = requestedEpoch == null ? jdbc.query("""
                    select epoch_id from ai_grid_current_coverage_state where tenant_id=:tenantId
                    """, Map.of("tenantId", tenant.getId()), rs -> rs.next() ? rs.getObject(1, UUID.class) : null) : requestedEpoch;
            UUID runId = epoch == null ? null : jdbc.query(requestedEpoch == null ? """
                    select trigger_run_id from ai_grid_current_coverage_state
                     where tenant_id=:tenantId and epoch_id=:epoch
                    """ : """
                    select run_id from ai_grid_policy_readiness
                     where tenant_id=:tenantId and coverage_epoch_id=:epoch
                     group by run_id order by max(computed_at) desc limit 1
                    """, Map.of("tenantId", tenant.getId(), "epoch", epoch),
                    rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
            if (requestedEpoch != null && runId == null) throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "AI Grid coverage epoch was not found");
            Boolean schemaReady = jdbc.query("""
                    select current_version >= 2 and status='CURRENT' from platform.tenant_schema_versions
                     where tenant_id=:tenantId
                    """, Map.of("tenantId", tenant.getId()), rs -> rs.next() && rs.getBoolean(1));
            boolean tenantSchemaReady = Boolean.TRUE.equals(schemaReady);

            List<ControlCoverage> controls = jdbc.query("""
                    with latest as (
                        select distinct on (p.policy_id) p.*
                          from platform.ai_grid_policy_versions p
                          left join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                         where p.release_family in ('AGCF_PHASE_1','AGCF_PHASE_2')
                           and p.lifecycle in ('VALIDATED','APPROVED','CANARY','PUBLISHED')
                         order by p.policy_id,(p.version=d.pinned_version) desc,
                                  p.published_at desc nulls last,p.created_at desc,p.version desc
                    ), mapped as (
                        select p.policy_id,p.version,p.provider,p.lifecycle,d.available,d.rollout_stage,
                               d.canary_tenant_ids_json,
                               mapping->>'controlId' control_id,mapping->>'mappingType' mapping_type,
                               mapping->>'rationale' rationale
                          from latest p
                          left join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                          cross join lateral jsonb_array_elements(case
                              when jsonb_typeof(p.framework_mappings_json)='array' then p.framework_mappings_json
                              else '[]'::jsonb end) mapping
                         where mapping->>'framework'=:framework and mapping->>'frameworkVersion'=:version
                    ), readiness as (
                        select policy_id,policy_version,selection,readiness,applicable_count,decision_ready_count,
                               no_decision_count,error_count,missing_evidence_json
                          from ai_grid_policy_readiness
                         where coverage_epoch_id=cast(:epoch as uuid)
                    ), blockers as (
                        select m.control_id,jsonb_agg(distinct blocker.value) blockers
                          from mapped m
                          join readiness r on r.policy_id=m.policy_id and r.policy_version=m.version
                          cross join lateral jsonb_array_elements_text(coalesce(r.missing_evidence_json,'[]'::jsonb)) blocker
                         where r.selection in ('REQUIRED','ENABLED','PREVIEW')
                           and platform.ai_grid_policy_visible_to_tenant(
                               m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))
                         group by m.control_id
                    )
                    select c.control_id,c.name,
                           count(m.policy_id) mapped_count,
                           count(m.policy_id) filter (where platform.ai_grid_policy_visible_to_tenant(
                               m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))) distributed_count,
                           count(m.policy_id) filter (where r.selection in ('REQUIRED','ENABLED')
                               and platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))) selected_count,
                           count(m.policy_id) filter (where r.selection in ('REQUIRED','ENABLED')
                               and r.readiness='PARTIAL' and platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))) partial_count,
                           count(m.policy_id) filter (where r.selection='PREVIEW'
                               and platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))) preview_count,
                           count(m.policy_id) filter (where r.selection='PREVIEW' and r.decision_ready_count>0
                               and platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))) preview_ready_count,
                           count(m.policy_id) filter (where r.selection in ('REQUIRED','ENABLED')
                               and platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))
                               and r.readiness='READY' and r.decision_ready_count>0) effective_count,
                           coalesce(sum(r.decision_ready_count) filter (where r.selection in ('REQUIRED','ENABLED')
                               and platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))),0) decision_ready_count,
                           coalesce(sum(r.applicable_count) filter (where r.selection in ('REQUIRED','ENABLED')
                               and platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))),0) applicable_count,
                           count(m.policy_id) filter (where m.rollout_stage='PAUSED') paused_count,
                           coalesce(b.blockers,'[]'::jsonb)::text blockers,
                           coalesce(jsonb_agg(distinct jsonb_build_object(
                               'policyId',m.policy_id,'policyVersion',m.version,'mappingType',m.mapping_type,
                               'rationale',m.rationale,'selection',r.selection,'readiness',r.readiness,
                               'distributed',platform.ai_grid_policy_visible_to_tenant(
                                   m.available,m.rollout_stage,m.canary_tenant_ids_json,cast(:tenantId as uuid))))
                               filter (where m.policy_id is not null),'[]'::jsonb)::text mapping_details
                      from platform.ai_grid_framework_controls c
                      left join mapped m on m.control_id=c.control_id
                      left join readiness r on r.policy_id=m.policy_id and r.policy_version=m.version
                      left join blockers b on b.control_id=c.control_id
                     where c.framework_key=:framework and c.framework_version=:version
                     group by c.control_id,c.name,c.display_order,b.blockers order by c.display_order
                    """, new MapSqlParameterSource().addValue("framework", framework).addValue("version", version)
                    .addValue("tenantId", tenant.getId()).addValue("epoch", epoch), (rs, row) -> {
                long mapped = rs.getLong("mapped_count");
                long distributed = rs.getLong("distributed_count");
                long effective = rs.getLong("effective_count");
                long preview = rs.getLong("preview_count");
                long partial = rs.getLong("partial_count");
                String status = !tenantSchemaReady || epoch == null ? "NOT_ASSESSED"
                        : mapped == 0 ? "NOT_COVERED" : effective > 0 ? "EFFECTIVE"
                        : distributed == 0 ? "BREADTH_ONLY" : partial > 0 ? "PARTIAL"
                        : preview > 0 ? "PREVIEW" : "NOT_ASSESSED";
                List<String> blockers = strings(rs.getString("blockers"));
                if (!tenantSchemaReady) blockers = List.of("TENANT_SCHEMA_VERSION_UNAVAILABLE");
                else if (epoch == null) blockers = List.of("NO_COVERAGE_EPOCH");
                else if (effective > 0) blockers = List.of();
                else if (mapped > 0 && distributed == 0) blockers = rs.getLong("paused_count") > 0
                        ? List.of("POLICY_PAUSED_PENDING_EVIDENCE") : List.of("POLICY_NOT_DISTRIBUTED");
                return new ControlCoverage(rs.getString("control_id"), rs.getString("name"), status, mapped,
                        distributed, rs.getLong("selected_count"), preview, rs.getLong("preview_ready_count"),
                        effective, rs.getLong("applicable_count"), rs.getLong("decision_ready_count"), blockers,
                        mappingDetails(rs.getString("mapping_details")));
            });
            LegacyCompatibility legacy = jdbc.queryForObject("""
                    select count(distinct p.policy_id) total,
                           count(distinct p.policy_id) filter (where platform.ai_grid_policy_visible_to_tenant(
                               d.available,d.rollout_stage,d.canary_tenant_ids_json,cast(:tenantId as uuid))) distributed,
                           count(distinct p.policy_id) filter (where coalesce(s.selection,d.default_selection)='REQUIRED'
                               and platform.ai_grid_policy_visible_to_tenant(
                                   d.available,d.rollout_stage,d.canary_tenant_ids_json,cast(:tenantId as uuid))) required,
                           count(distinct p.policy_id) filter (where coalesce(s.selection,d.default_selection)='ENABLED'
                               and platform.ai_grid_policy_visible_to_tenant(
                                   d.available,d.rollout_stage,d.canary_tenant_ids_json,cast(:tenantId as uuid))) enabled,
                           count(distinct p.policy_id) filter (where coalesce(s.selection,d.default_selection)='PREVIEW'
                               and platform.ai_grid_policy_visible_to_tenant(
                                   d.available,d.rollout_stage,d.canary_tenant_ids_json,cast(:tenantId as uuid))) preview
                      from platform.ai_grid_policy_versions p
                      join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                      left join ai_grid_policy_selections s on s.policy_id=p.policy_id
                     where p.release_family is null
                    """, Map.of("tenantId", tenant.getId()), (rs, row) -> new LegacyCompatibility(
                    rs.getLong("total"), rs.getLong("distributed"), rs.getLong("required"),
                    rs.getLong("enabled"), rs.getLong("preview")));
            return new FrameworkCoverage(framework, version, epoch, runId, tenantSchemaReady,
                    !tenantSchemaReady ? List.of("TENANT_SCHEMA_VERSION_UNAVAILABLE")
                            : epoch == null ? List.of("NO_COVERAGE_EPOCH") : List.of(),
                    controls, legacy);
        });
    }

    public List<FrameworkDefinition> frameworks() {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                select f.framework_key,f.framework_version,f.display_name,
                       c.control_id,c.name,c.display_order
                  from platform.ai_grid_frameworks f
                  join platform.ai_grid_framework_controls c
                    on c.framework_key=f.framework_key and c.framework_version=f.framework_version
                 where f.lifecycle='ACTIVE'
                 order by f.framework_key,c.display_order
                """, (rs, row) -> new FrameworkControlRow(rs.getString(1), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getInt(6))).stream()
                .collect(java.util.stream.Collectors.groupingBy(row -> row.frameworkKey() + "\u0000" + row.frameworkVersion(),
                        java.util.LinkedHashMap::new, java.util.stream.Collectors.toList()))
                .values().stream().map(rows -> new FrameworkDefinition(rows.get(0).frameworkKey(),
                        rows.get(0).frameworkVersion(), rows.get(0).displayName(), rows.stream()
                        .map(row -> new FrameworkControl(row.controlId(), row.controlName(), row.displayOrder())).toList()))
                .toList());
    }

    public List<Candidate> candidates() { return TenantContext.runAsPlatform(() -> jdbc.query("""
            select id,title,source_type,status,technology_id,rationale,framework_mappings_json::text,risk_score,reach_score,evidence_maturity,remediation_clarity,owner,created_by,created_at,updated_at
              from platform.ai_grid_policy_candidates order by (risk_score*35+reach_score*20+evidence_maturity*30+remediation_clarity*15) desc,created_at desc
            """, (rs,n) -> new Candidate(rs.getObject(1, UUID.class),rs.getString(2),rs.getString(3),rs.getString(4),rs.getString(5),rs.getString(6),rs.getString(7),rs.getInt(8),rs.getInt(9),rs.getInt(10),rs.getInt(11),rs.getString(12),rs.getString(13),rs.getTimestamp(14).toInstant(),rs.getTimestamp(15).toInstant()))); }
    public Candidate create(CandidateCommand command, String actor) { return TenantContext.runAsPlatform(() -> {
        UUID id=UUID.randomUUID(); jdbc.update("""
            insert into platform.ai_grid_policy_candidates (id,title,source_type,status,technology_id,rationale,framework_mappings_json,risk_score,reach_score,evidence_maturity,remediation_clarity,owner,created_by)
            values (:id,:title,:source,:status,:technology,:rationale,cast(:mappings as jsonb),:risk,:reach,:evidence,:clarity,:owner,:actor)
            """, new MapSqlParameterSource().addValue("id",id).addValue("title",command.title()).addValue("source",command.sourceType()).addValue("status",command.status()).addValue("technology",command.technologyId()).addValue("rationale",command.rationale()).addValue("mappings",json(command.frameworkMappings())).addValue("risk",score(command.riskScore())).addValue("reach",score(command.reachScore())).addValue("evidence",score(command.evidenceMaturity())).addValue("clarity",score(command.remediationClarity())).addValue("owner",command.owner()).addValue("actor",actor));
        audit.record("ai_grid.policy_candidate.created","ai_grid_policy_candidate",id.toString(),"{\"source\":\""+command.sourceType()+"\"}"); return candidates().stream().filter(candidate -> candidate.id().equals(id)).findFirst().orElseThrow(); }); }
    private int score(int value) { if(value<1||value>5) throw new IllegalArgumentException("Candidate scores must be between 1 and 5"); return value; }
    private String json(Map<String,Object> value) { try{return mapper.writeValueAsString(value==null?Map.of():value);}catch(Exception ex){throw new IllegalArgumentException(ex);} }
    private List<String> strings(String value) {
        try { return mapper.readValue(value == null ? "[]" : value, new com.fasterxml.jackson.core.type.TypeReference<>() {}); }
        catch (Exception ex) { throw new IllegalStateException("Invalid stored framework coverage blockers", ex); }
    }
    private List<PolicyMapping> mappingDetails(String value) {
        try { return mapper.readValue(value == null ? "[]" : value,
                mapper.getTypeFactory().constructCollectionType(List.class, PolicyMapping.class)); }
        catch (Exception ex) { throw new IllegalStateException("Invalid stored framework policy mappings", ex); }
    }
    public record FrameworkCoverage(String framework, String frameworkVersion, UUID coverageEpochId, UUID runId,
                                    boolean tenantSchemaReady, List<String> blockers,
                                    List<ControlCoverage> controls, LegacyCompatibility legacyCompatibility) {}
    public record LegacyCompatibility(long policies, long distributed, long required, long enabled, long preview) {}
    public record ControlCoverage(String controlId, String name, String coverageStatus, long mappedPolicies,
                                  long distributedPolicies, long selectedPolicies, long previewPolicies,
                                  long previewDecisionReadyPolicies, long effectivePolicies,
                                  long applicableCount, long decisionReadyCount, List<String> blockers,
                                  List<PolicyMapping> mappings) {}
    public record PolicyMapping(String policyId, String policyVersion, String mappingType, String rationale,
                                String selection, String readiness, boolean distributed) {}
    public record FrameworkDefinition(String framework, String frameworkVersion, String displayName,
                                      List<FrameworkControl> controls) {}
    public record FrameworkControl(String controlId, String name, int displayOrder) {}
    private record FrameworkControlRow(String frameworkKey, String frameworkVersion, String displayName,
                                       String controlId, String controlName, int displayOrder) {}
    public record Candidate(UUID id,String title,String sourceType,String status,String technologyId,String rationale,String frameworkMappingsJson,int riskScore,int reachScore,int evidenceMaturity,int remediationClarity,String owner,String createdBy,Instant createdAt,Instant updatedAt) { public int priorityScore(){return riskScore*35+reachScore*20+evidenceMaturity*30+remediationClarity*15;} }
    public record CandidateCommand(String title,String sourceType,String status,String technologyId,String rationale,Map<String,Object> frameworkMappings,int riskScore,int reachScore,int evidenceMaturity,int remediationClarity,String owner) {}
}
