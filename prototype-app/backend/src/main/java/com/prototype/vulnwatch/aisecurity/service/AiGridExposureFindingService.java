package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.FindingSlaService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.RiskPolicyService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Bridges only validated R2 exposures into the canonical SLA-bound finding workflow. */
@Service
public class AiGridExposureFindingService {
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final FindingRepository findings;
    private final RiskPolicyService riskPolicies;
    private final FindingSlaService sla;
    private final FindingWorkflowService workflow;

    public AiGridExposureFindingService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                        FindingRepository findings, RiskPolicyService riskPolicies,
                                        FindingSlaService sla, FindingWorkflowService workflow) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.findings = findings;
        this.riskPolicies = riskPolicies;
        this.sla = sla;
        this.workflow = workflow;
    }

    private AiGridFindingService canonical;
    @org.springframework.beans.factory.annotation.Autowired
    void configureProjection(AiGridFindingService canonical) { this.canonical=canonical; }

    void refreshProjection(Tenant tenant) { canonical.refreshProjectionAfterCommit(tenant); }

    /** Attach every constituent path after all path observations have been persisted. */
    void attachPath(Tenant tenant, UUID findingId, ExposureFinding input) {
        jdbc.update("update ai_grid_exposure_paths set finding_id=:findingId where id=:id",
                Map.of("findingId",findingId,"id",input.exposureId()));
        link(tenant,findingId,"EXPOSURE_PATH",input.exposureId(),"PRIMARY",null);
        link(tenant,findingId,"AI_SYSTEM",input.systemId(),"AFFECTED",input.systemRevision());
        link(tenant,findingId,"ARTIFACT",input.entryArtifactId(),"ENTRY_POINT",null);
        link(tenant,findingId,"ARTIFACT",input.rootCauseArtifactId(),"ROOT_CAUSE",null);
    }

    void reconcileAggregate(Tenant tenant, UUID runId) {
        List<UUID> ids=jdbc.query("select distinct finding_id from ai_grid_exposure_paths where finding_id is not null order by finding_id",
                (rs,row) -> rs.getObject(1,UUID.class));
        for (UUID id:ids) {
            List<UUID> open=jdbc.query("select id from ai_grid_exposure_paths where finding_id=:id and status='OPEN' "
                    + "order by case state when 'VALIDATED_EXPOSURE' then 0 else 1 end,last_observed_at desc,id",
                    Map.of("id",id),(rs,row) -> rs.getObject(1,UUID.class));
            if (open.isEmpty()) {
                UUID path=jdbc.queryForObject("select id from ai_grid_exposure_paths where finding_id=:id order by last_observed_at desc,id limit 1",Map.of("id",id),UUID.class);
                closeVerified(tenant,id,runId,path);
            } else markNeedsEvidence(open.get(0),runId);
        }
    }

    private SlaState savedSla(UUID findingId) {
        return jdbc.query("""
                select details_json::text from finding_events
                 where finding_id=:id and event_type in ('EXPOSURE_SLA_PAUSED','EXPOSURE_SLA_RECOVERED')
                   and created_at>coalesce((select max(created_at) from finding_events
                         where finding_id=:id and event_type='RESOLVED_BY_VERIFIED_REASSESSMENT'),'-infinity'::timestamptz)
                 order by created_at desc,id desc limit 1
                """,Map.of("id",findingId),rs -> {
            if (!rs.next()) return new SlaState(null,false);
            try {
                var details=objectMapper.readTree(rs.getString(1));
                String deadline=details.path("savedDeadline").asText("");
                return new SlaState(deadline.isBlank() ? null : Instant.parse(deadline),details.path("resetConsumed").asBoolean());
            } catch (java.io.IOException error) { throw new IllegalStateException("Invalid saved exposure deadline",error); }
        });
    }
    private void recoverSla(Tenant tenant,Finding finding,Instant now,double risk) {
        SlaState saved=savedSla(finding.getId());
        Instant deadline=saved.deadline();
        boolean mayReset=!saved.consumed() && deadline!=null && deadline.isAfter(now);
        if (mayReset) deadline=dueAt(tenant,now,risk);
        finding.setDueAt(deadline);
        workflow.appendEvent(finding,"EXPOSURE_SLA_RECOVERED","ai-grid-correlation","Validating evidence recovered",
                Map.of("savedDeadline",deadline==null ? "" : deadline.toString(),"resetConsumed",true,"freshReset",mayReset));
    }
    private record SlaState(Instant deadline,boolean consumed) {}

    public UUID reconcileValidated(Tenant tenant, ExposureFinding input) {
        Instant now = Instant.now();
        Finding finding = findings.findByTenantAndFingerprint(tenant, input.fingerprint()).orElse(null);
        if (finding == null) {
            List<UUID> sharedRootFinding = jdbc.query("""
                    select f.id from findings f join finding_subjects fs on fs.finding_id=f.id
                     where f.finding_kind='AI_EXPOSURE' and f.policy_id=:correlationId
                       and fs.subject_type='ARTIFACT' and fs.subject_role='ROOT_CAUSE'
                       and fs.subject_id=:rootCause order by f.created_at,f.id limit 1
                    """, Map.of("correlationId", input.correlationId(), "rootCause", input.rootCauseArtifactId()),
                    (rs, n) -> rs.getObject(1, UUID.class));
            if (!sharedRootFinding.isEmpty()) finding = findings.findById(sharedRootFinding.get(0)).orElse(null);
        }
        String evidence = json(Map.of("exposurePathId", input.exposureId(), "runId", input.runId(),
                "correlationId", input.correlationId(), "path", input.path(), "evidence", input.evidence()));
        double risk = risk(input.severity());
        if (finding == null) {
            finding = new Finding();
            finding.setTenant(tenant);
            finding.setFindingKind("AI_EXPOSURE");
            finding.setFingerprint(input.fingerprint());
            finding.setWorkflowClass("VALIDATED_EXPOSURE");
            finding.setStatus(FindingStatus.OPEN);
            finding.setDecisionState(FindingDecisionState.AFFECTED);
            finding.setCreationSource(FindingCreationSource.AI_SECURITY);
            finding.setMatchedBy("ai-grid-correlation");
            finding.setFirstObservedAt(now);
            finding.setDueAt(dueAt(tenant, now, risk));
        } else {
            boolean suppressionActive=finding.getStatus()==FindingStatus.SUPPRESSED
                    && (finding.getSuppressedUntil()==null || finding.getSuppressedUntil().isAfter(now));
            boolean verifiedRecurrence=finding.getStatus()==FindingStatus.RESOLVED
                    && finding.getClosedReason()==com.prototype.vulnwatch.domain.FindingCloseReason.VERIFIED_REMEDIATION;
            if (verifiedRecurrence) finding.setDueAt(dueAt(tenant,now,risk));
            else if ("NEEDS_EVIDENCE".equals(finding.getWorkflowClass())) recoverSla(tenant,finding,now,risk);
            if (!suppressionActive && finding.getStatus()!=FindingStatus.OPEN) workflow.reopenByObservation(finding,now,input.runId());
        }
        finding.setTitle(input.title());
        finding.setWorkflowClass("VALIDATED_EXPOSURE");
        finding.setPolicyId(input.correlationId());
        finding.setPolicyVersion(input.correlationVersion());
        finding.setReasonCode("VALIDATED_EXPOSURE");
        finding.setRiskScore(risk);
        finding.setConfidenceScore(input.confidence());
        finding.setSeverityOverride(input.severity());
        finding.setEvidence(evidence);
        String owner = authoritativeOwner(input.systemId());
        if (owner != null) finding.setOwnerGroup(owner);
        workflow.markObserved(finding, now, input.runId());
        finding.touch();
        finding = findings.saveAndFlush(finding);
        link(tenant, finding.getId(), "EXPOSURE_PATH", input.exposureId(), "PRIMARY", null);
        link(tenant, finding.getId(), "AI_SYSTEM", input.systemId(), "AFFECTED", input.systemRevision());
        link(tenant, finding.getId(), "ARTIFACT", input.entryArtifactId(), "ENTRY_POINT", null);
        link(tenant, finding.getId(), "ARTIFACT", input.rootCauseArtifactId(), "ROOT_CAUSE", null);
        return finding.getId();
    }

    public void markNeedsEvidence(UUID exposureId, UUID runId) {
        UUID findingId = jdbc.query("select finding_id from ai_grid_exposure_paths where id=:id",
                Map.of("id", exposureId), rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
        if (findingId == null) return;
        Finding finding = findings.findById(findingId).orElse(null);
        if (finding == null || finding.getStatus()==FindingStatus.RESOLVED || "NEEDS_EVIDENCE".equals(finding.getWorkflowClass())) return;
        Integer validating=jdbc.queryForObject("select count(*) from ai_grid_exposure_paths where finding_id=:id and status='OPEN' and state='VALIDATED_EXPOSURE'",Map.of("id",findingId),Integer.class);
        if (validating!=null && validating>0) return;
        SlaState saved=savedSla(findingId);
        Instant deadline=finding.getDueAt()==null ? saved.deadline() : finding.getDueAt();
        workflow.appendEvent(finding,"EXPOSURE_SLA_PAUSED","ai-grid-correlation","SLA paused while validating evidence is unavailable",
                Map.of("savedDeadline",deadline==null ? "" : deadline.toString(),"resetConsumed",saved.consumed()));
        finding.setWorkflowClass("NEEDS_EVIDENCE");
        finding.setReasonCode("VALIDATING_EVIDENCE_EXPIRED");
        finding.setDueAt(null);
        finding.setEvidence(json(Map.of("exposurePathId", exposureId, "runId", runId,
                "state", "NEEDS_EVIDENCE", "slaPaused", true)));
        finding.touch();
        findings.save(finding);
    }

    public void closeVerified(Tenant tenant, UUID findingId, UUID runId, UUID exposureId) {
        if (findingId == null) return;
        Finding finding = findings.findById(findingId).orElse(null);
        if (finding == null || finding.getStatus() == FindingStatus.RESOLVED) return;
        finding.setEvidence(json(Map.of("exposurePathId", exposureId, "runId", runId,
                "closure", "COMPLETE_REASSESSMENT_PATH_ABSENT")));
        workflow.resolveByVerifiedReassessment(finding, exposureId, Instant.now(), runId);
        findings.save(finding);
    }

    private String authoritativeOwner(UUID systemId) {
        List<String> owners = jdbc.query("""
                select a.owner_name from ai_grid_systems s
                join ai_grid_system_revisions r on r.system_id=s.id and r.revision=s.current_revision
                join ai_grid_system_memberships m on m.system_revision_id=r.id
                join ai_security_artifacts a on a.id=m.artifact_id
                where s.id=:id and a.owner_state in ('CONFIRMED','INFERRED') and a.owner_name is not null
                order by case a.owner_state when 'CONFIRMED' then 0 else 1 end, a.id limit 1
                """, Map.of("id", systemId), (rs, n) -> rs.getString(1));
        return owners.isEmpty() ? null : owners.get(0);
    }

    private void link(Tenant tenant, UUID findingId, String type, UUID subjectId, String role, Integer revision) {
        if (subjectId == null) return;
        jdbc.update("""
                insert into finding_subjects
                    (id,tenant_id,finding_id,subject_type,subject_id,subject_revision,subject_role)
                values (:id,:tenantId,:findingId,:type,:subjectId,:revision,:role) on conflict do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("findingId", findingId).addValue("type", type).addValue("subjectId", subjectId)
                .addValue("revision", revision == null ? null : revision.toString()).addValue("role", role));
    }

    private Instant dueAt(Tenant tenant, Instant observedAt, double risk) {
        RiskPolicy policy = riskPolicies.getOrCreate(tenant);
        return sla.deriveDueAt(observedAt, risk, null, policy);
    }
    private double risk(String severity) {
        return switch (severity) { case "CRITICAL" -> 9.5; case "HIGH" -> 8.0; case "MEDIUM" -> 5.5; default -> 3.0; };
    }
    private String json(Object value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalArgumentException("Unable to serialize exposure finding", e); }
    }

    public record ExposureFinding(UUID exposureId, UUID runId, String fingerprint, String correlationId,
                                  String correlationVersion, String title, String severity, double confidence,
                                  UUID systemId, int systemRevision, UUID entryArtifactId,
                                  UUID rootCauseArtifactId, Object path, Object evidence) {}
}
