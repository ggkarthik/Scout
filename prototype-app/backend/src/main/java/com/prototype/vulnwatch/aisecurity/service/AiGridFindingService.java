package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.FindingListProjectionService;
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
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Graduates governed AI assessments into the canonical host finding lifecycle. */
@Service
public class AiGridFindingService {
    private static final Logger LOG = LoggerFactory.getLogger(AiGridFindingService.class);
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final FindingRepository findings;
    private final RiskPolicyService riskPolicies;
    private final FindingSlaService sla;
    private final FindingWorkflowService workflow;
    private final FindingListProjectionService projections;

    public AiGridFindingService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                FindingRepository findings, RiskPolicyService riskPolicies,
                                FindingSlaService sla, FindingWorkflowService workflow,
                                FindingListProjectionService projections) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.findings = findings;
        this.riskPolicies = riskPolicies;
        this.sla = sla;
        this.workflow = workflow;
        this.projections = projections;
    }

    public boolean reconcile(Tenant tenant, AssessmentResult assessment) {
        boolean workflowEnabled = "REQUIRED".equals(assessment.selection())
                || "ENABLED".equals(assessment.selection());
        if (!workflowEnabled) return closeForPolicyDowngrade(tenant, assessment);
        if ("FAIL".equals(assessment.decision())) return openOrUpdate(tenant, assessment);
        if ("PASS".equals(assessment.decision())) return closeVerified(tenant, assessment);
        return false;
    }

    /**
     * Closes owner-facing AI findings when a policy is no longer available or enabled.
     * This keeps policy administration on the canonical finding workflow.
     */
    @Transactional
    public int closeForPolicy(Tenant tenant, String policyId) {
        List<Finding> candidates = findings.findOpenAiFindingsByTenantAndPolicy(tenant, policyId);
        Instant closedAt = Instant.now();
        for (Finding finding : candidates) {
            workflow.autoCloseFinding(
                    finding,
                    FindingCloseReason.AUTO_POLICY_NOT_OWNER_FACING,
                    "AI finding auto-closed because its policy is no longer owner-facing",
                    Map.of("policyId", policyId),
                    closedAt);
        }
        if (!candidates.isEmpty()) {
            findings.saveAll(candidates);
            refreshProjectionAfterCommit(tenant);
        }
        return candidates.size();
    }

    private boolean openOrUpdate(Tenant tenant, AssessmentResult assessment) {
        Instant observedAt = Instant.now();
        double risk = risk(assessment.severity());
        String owner = authoritativeOwner(assessment.subjectId());
        String evidence = json(Map.of("assessmentId", assessment.assessmentId(),
                "runId", assessment.runId(), "policyId", assessment.policyId(),
                "policyVersion", assessment.policyVersion(), "facts", assessment.inputFacts()));
        Finding finding = findings.findByTenantAndFingerprint(tenant, assessment.fingerprint()).orElse(null);
        if (finding == null) {
            finding = new Finding();
            finding.setTenant(tenant);
            finding.setFindingKind("AI_POSTURE");
            finding.setFingerprint(assessment.fingerprint());
            finding.setWorkflowClass("POSTURE_FINDING");
            finding.setStatus(FindingStatus.OPEN);
            finding.setDecisionState(FindingDecisionState.AFFECTED);
            finding.setCreationSource(FindingCreationSource.AI_SECURITY);
            finding.setMatchedBy("ai-grid-policy");
            finding.setConfidenceScore(1.0);
            finding.setFirstObservedAt(observedAt);
            finding.setSeverityOverride(assessment.severity());
            finding.setOwnerGroup(owner);
            finding.setDueAt(dueAt(tenant, observedAt, risk));
            applyAssessment(finding, assessment, risk, evidence);
            workflow.markObserved(finding, observedAt, assessment.runId());
            finding = findings.saveAndFlush(finding);
            workflow.appendEvent(finding, "CREATED_BY_AI_ASSESSMENT", "ai-grid-policy",
                    "AI posture finding created from a complete governed assessment",
                    Map.of("assessmentId", assessment.assessmentId(), "runId", assessment.runId()));
        } else {
            boolean suppressionActive = finding.getStatus() == FindingStatus.SUPPRESSED
                    && (finding.getSuppressedUntil() == null || finding.getSuppressedUntil().isAfter(observedAt));
            if (!suppressionActive && finding.getStatus() != FindingStatus.OPEN) {
                workflow.reopenByObservation(finding, observedAt, assessment.runId());
                finding.setDueAt(dueAt(tenant, observedAt, risk));
            } else {
                workflow.markObserved(finding, observedAt, assessment.runId());
            }
            applyAssessment(finding, assessment, risk, evidence);
            if (owner != null) finding.setOwnerGroup(owner);
            finding.touch();
            finding = findings.save(finding);
        }
        linkSubject(tenant, finding.getId(), assessment.subjectId());
        return true;
    }

    private boolean closeVerified(Tenant tenant, AssessmentResult assessment) {
        Finding finding = findings.findByTenantAndFingerprint(tenant, assessment.fingerprint()).orElse(null);
        if (finding == null || finding.getStatus() == FindingStatus.RESOLVED) return false;
        Instant observedAt = Instant.now();
        finding.setEvidence(json(Map.of("assessmentId", assessment.assessmentId(),
                "runId", assessment.runId(), "policyId", assessment.policyId(),
                "policyVersion", assessment.policyVersion(), "facts", assessment.inputFacts(),
                "closure", "VERIFIED_REMEDIATION")));
        finding.setPolicyVersion(assessment.policyVersion());
        finding.setReasonCode(assessment.reasonCode());
        workflow.resolveByVerifiedReassessment(finding, assessment.assessmentId(), observedAt, assessment.runId());
        findings.save(finding);
        return true;
    }

    private boolean closeForPolicyDowngrade(Tenant tenant, AssessmentResult assessment) {
        Finding finding = findings.findByTenantAndFingerprint(tenant, assessment.fingerprint()).orElse(null);
        if (finding == null || (finding.getStatus() == FindingStatus.AUTO_CLOSED
                && finding.getClosedReason() == FindingCloseReason.AUTO_POLICY_NOT_OWNER_FACING)) {
            return false;
        }
        workflow.autoCloseFinding(finding, FindingCloseReason.AUTO_POLICY_NOT_OWNER_FACING,
                "AI finding auto-closed because its policy is no longer owner-facing",
                Map.of("policyId", assessment.policyId(), "selection", assessment.selection(),
                        "assessmentId", assessment.assessmentId(), "runId", assessment.runId()), Instant.now());
        finding.setAssessmentId(assessment.assessmentId());
        finding.setPolicyVersion(assessment.policyVersion());
        finding.setReasonCode("POLICY_" + assessment.selection());
        findings.save(finding);
        return true;
    }

    public void refreshProjectionAfterCommit(Tenant tenant) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            projections.refreshTenant(tenant);
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    projections.refreshTenant(tenant);
                } catch (RuntimeException ex) {
                    LOG.warn("AI Grid finding projection refresh failed after commit for tenant {}: {}",
                            tenant.getId(), ex.getMessage());
                }
            }
        });
    }

    private void applyAssessment(Finding finding, AssessmentResult assessment, double risk, String evidence) {
        finding.setTitle(assessment.title());
        finding.setPolicyId(assessment.policyId());
        finding.setPolicyVersion(assessment.policyVersion());
        finding.setReasonCode(assessment.reasonCode());
        finding.setAssessmentId(assessment.assessmentId());
        finding.setRiskScore(risk);
        finding.setSeverityOverride(assessment.severity());
        finding.setEvidence(evidence);
    }

    private Instant dueAt(Tenant tenant, Instant observedAt, double risk) {
        RiskPolicy policy = riskPolicies.getOrCreate(tenant);
        return sla.deriveDueAt(observedAt, risk, null, policy);
    }

    private void linkSubject(Tenant tenant, UUID findingId, UUID subjectId) {
        jdbc.update("""
                insert into finding_subjects (id, tenant_id, finding_id, subject_type, subject_id, subject_role)
                values (:id, :tenantId, :findingId, 'ARTIFACT', :subjectId, 'PRIMARY')
                on conflict do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("findingId", findingId).addValue("subjectId", subjectId));
    }

    private String authoritativeOwner(UUID artifactId) {
        List<String> owners = jdbc.query("""
                select owner_name from ai_security_artifacts
                 where id = :id and owner_state in ('CONFIRMED','INFERRED') and owner_name is not null
                """, Map.of("id", artifactId), (rs, n) -> rs.getString(1));
        return owners.isEmpty() ? null : owners.get(0);
    }

    private double risk(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 9.5;
            case "HIGH" -> 8.0;
            case "MEDIUM" -> 5.5;
            default -> 3.0;
        };
    }

    private String json(Object value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid finding evidence", e); }
    }

    public record AssessmentResult(UUID assessmentId, UUID runId, String policyId, String policyVersion,
                                   String title, String severity, String selection, String decision,
                                   String reasonCode, UUID subjectId, String fingerprint,
                                   Map<String, Object> inputFacts) {}
}
