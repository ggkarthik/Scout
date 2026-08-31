package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AiGridPolicyPortfolioService {
    private static final List<String> OWASP = List.of("LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10");
    private final NamedParameterJdbcTemplate jdbc; private final ObjectMapper mapper; private final AuditEventService audit;
    public AiGridPolicyPortfolioService(NamedParameterJdbcTemplate jdbc, ObjectMapper mapper, AuditEventService audit) { this.jdbc=jdbc; this.mapper=mapper; this.audit=audit; }
    /**
     * Per-control coverage for a framework version, built from the structured mapping model
     * ({framework, frameworkVersion, controlId, mappingType, rationale}). Coverage status is
     * derived only from what the data proves: AUTOMATED when a mapped published policy needs no
     * optional capability, CONDITIONAL_AUTOMATED when every mapped policy depends on one, and
     * NOT_COVERED when nothing maps. Editorial statuses (PREVENTIVE_ONLY, REQUIRES_RUNTIME_OR_TEST)
     * are intentionally not fabricated from data; the UI renders whichever status it receives.
     */
    public List<ControlCoverage> frameworkCoverage(String framework, String version) {
        return TenantContext.runAsPlatform(() -> {
            List<ControlMappingRow> rows = jdbc.query("""
                    select p.policy_id, p.provider,
                           coalesce(mapping->>'controlId','') control_id,
                           coalesce(mapping->>'mappingType','') mapping_type,
                           coalesce(mapping->>'rationale','') rationale,
                           coalesce(p.conditional_capabilities_json::text,'[]') conditional_capabilities,
                           coalesce(p.base_evidence_tiers_json::text,'[]') base_evidence_tiers
                      from platform.ai_grid_policy_versions p,
                           lateral jsonb_array_elements(
                               case when jsonb_typeof(p.framework_mappings_json)='array'
                                    then p.framework_mappings_json else '[]'::jsonb end) mapping
                     where p.lifecycle='PUBLISHED'
                       and mapping->>'framework'=:framework
                       and mapping->>'frameworkVersion'=:version
                     order by control_id, p.policy_id
                    """, Map.of("framework", framework, "version", version),
                    (rs, n) -> new ControlMappingRow(rs.getString("control_id"), rs.getString("policy_id"),
                            rs.getString("provider"), rs.getString("mapping_type"), rs.getString("rationale"),
                            hasConditionalCapability(rs.getString("conditional_capabilities")),
                            rs.getString("base_evidence_tiers")));

            java.util.Map<String, List<ControlMappingRow>> byControl = new java.util.LinkedHashMap<>();
            // For OWASP, enumerate the canonical set so uncovered risks surface as NOT_COVERED.
            if ("OWASP_GENAI_LLM_TOP_10".equals(framework)) OWASP.forEach(id -> byControl.put(id, new java.util.ArrayList<>()));
            for (ControlMappingRow row : rows) byControl.computeIfAbsent(row.controlId(), ignored -> new java.util.ArrayList<>()).add(row);

            return byControl.entrySet().stream().map(entry -> {
                List<ControlMappingRow> mapped = entry.getValue();
                String status = mapped.isEmpty() ? "NOT_COVERED"
                        : mapped.stream().anyMatch(row -> !row.conditional()) ? "AUTOMATED" : "CONDITIONAL_AUTOMATED";
                List<PolicyControlMapping> policies = mapped.stream()
                        .map(row -> new PolicyControlMapping(row.policyId(), row.provider(), row.mappingType(),
                                row.rationale(), row.conditional(), row.baseEvidenceTiersJson()))
                        .toList();
                return new ControlCoverage(entry.getKey(), status, policies);
            }).toList();
        });
    }

    private boolean hasConditionalCapability(String conditionalCapabilitiesJson) {
        try { return !mapper.readTree(conditionalCapabilitiesJson == null ? "[]" : conditionalCapabilitiesJson).isEmpty(); }
        catch (Exception ex) { return false; }
    }

    @Deprecated
    public List<FrameworkCoverage> owaspCoverage() { return TenantContext.runAsPlatform(() -> OWASP.stream().map(id -> new FrameworkCoverage(id, count("""
            select count(*) from platform.ai_grid_policy_versions p
             where p.lifecycle='PUBLISHED' and (
                   p.framework_mappings_json->'OWASP_LLM_TOP_10' ? :id
                   or (jsonb_typeof(p.framework_mappings_json)='array' and exists (
                       select 1 from jsonb_array_elements(p.framework_mappings_json) mapping
                        where mapping->>'framework'='OWASP_GENAI_LLM_TOP_10'
                          and mapping->>'frameworkVersion'='2026'
                          and mapping->>'controlId'=:id)))
            """, Map.of("id", id)))).toList()); }
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
    private long count(String sql, Map<String,Object> params) { Long result=jdbc.queryForObject(sql,params,Long.class); return result==null?0:result; }
    private String json(Map<String,Object> value) { try{return mapper.writeValueAsString(value==null?Map.of():value);}catch(Exception ex){throw new IllegalArgumentException(ex);} }
    public record FrameworkCoverage(String owaspId,long publishedPolicyCount) {}
    public record ControlCoverage(String controlId, String coverageStatus, List<PolicyControlMapping> policies) {}
    public record PolicyControlMapping(String policyId, String provider, String mappingType, String rationale,
                                       boolean conditional, String baseEvidenceTiersJson) {}
    private record ControlMappingRow(String controlId, String policyId, String provider, String mappingType,
                                     String rationale, boolean conditional, String baseEvidenceTiersJson) {}
    public record Candidate(UUID id,String title,String sourceType,String status,String technologyId,String rationale,String frameworkMappingsJson,int riskScore,int reachScore,int evidenceMaturity,int remediationClarity,String owner,String createdBy,Instant createdAt,Instant updatedAt) { public int priorityScore(){return riskScore*35+reachScore*20+evidenceMaturity*30+remediationClarity*15;} }
    public record CandidateCommand(String title,String sourceType,String status,String technologyId,String rationale,Map<String,Object> frameworkMappings,int riskScore,int reachScore,int evidenceMaturity,int remediationClarity,String owner) {}
}
