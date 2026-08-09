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
    public List<FrameworkCoverage> owaspCoverage() { return TenantContext.runAsPlatform(() -> OWASP.stream().map(id -> new FrameworkCoverage(id, count("""
            select count(*) from platform.ai_grid_policy_versions p
             where p.lifecycle='PUBLISHED' and p.framework_mappings_json->'OWASP_LLM_TOP_10' ? :id
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
    public record Candidate(UUID id,String title,String sourceType,String status,String technologyId,String rationale,String frameworkMappingsJson,int riskScore,int reachScore,int evidenceMaturity,int remediationClarity,String owner,String createdBy,Instant createdAt,Instant updatedAt) { public int priorityScore(){return riskScore*35+reachScore*20+evidenceMaturity*30+remediationClarity*15;} }
    public record CandidateCommand(String title,String sourceType,String status,String technologyId,String rationale,Map<String,Object> frameworkMappings,int riskScore,int reachScore,int evidenceMaturity,int remediationClarity,String owner) {}
}
