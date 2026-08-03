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

    public UUID reconcileValidated(Tenant tenant, ExposureFinding input) {
        Instant now = Instant.now();
        Finding finding = findings.findByTenantAndFingerprint(tenant, input.fingerprint()).orElse(null);
        if (finding == null) {
            List<UUID> sharedRootFinding = jdbc.query("""
                    select f.id from findings f join finding_subjects fs on fs.finding_id=f.id
                     where f.finding_kind='AI_EXPOSURE' and f.policy_id=:correlationId
                       and fs.subject_type='ARTIFACT' and fs.subject_role='ROOT_CAUSE'
                       and fs.subject_id=:rootCause order by f.created_at limit 1
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
        } else if (finding.getStatus() != FindingStatus.OPEN) {
            workflow.reopenByObservation(finding, now, input.runId());
            finding.setDueAt(dueAt(tenant, now, risk));
        }
        finding.setTitle(input.title());
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
