package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.AnalystDisposition;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.ApplicabilityAssessmentRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import com.prototype.vulnwatch.util.LogUtil;

@Service
@RequiredArgsConstructor
@Slf4j
public class ApplicabilityAssessmentService {

    private final ApplicabilityAssessmentRepository assessmentRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    @Transactional(readOnly = true)
    public ApplicabilityAssessment getAssessment(Long tenantId, Long assessmentId) {
        return getAssessment(resolveTenant(tenantId), assessmentId);
    }

    @Transactional(readOnly = true)
    public ApplicabilityAssessment getAssessment(UUID tenantId, Long assessmentId) {
        return getAssessment(resolveTenant(tenantId), assessmentId);
    }

    @Transactional(readOnly = true)
    public List<ApplicabilityAssessment> getAssessmentsByCve(Long tenantId, String cveId) {
        return getAssessmentsByCve(resolveTenant(tenantId), cveId);
    }

    @Transactional(readOnly = true)
    public List<ApplicabilityAssessment> getAssessmentsByCve(UUID tenantId, String cveId) {
        return getAssessmentsByCve(resolveTenant(tenantId), cveId);
    }

    @Transactional(readOnly = true)
    public Page<ApplicabilityAssessment> getAssessments(Long tenantId, Pageable pageable) {
        return getAssessments(resolveTenant(tenantId), pageable);
    }

    @Transactional(readOnly = true)
    public Page<ApplicabilityAssessment> getAssessments(UUID tenantId, Pageable pageable) {
        return getAssessments(resolveTenant(tenantId), pageable);
    }

    @Transactional
    public ApplicabilityAssessment createAssessment(Long tenantId, String cveId, String assessedBy) {
        return createAssessment(resolveTenant(tenantId), cveId, assessedBy);
    }

    @Transactional
    public ApplicabilityAssessment createAssessment(UUID tenantId, String cveId, String assessedBy) {
        return createAssessment(resolveTenant(tenantId), cveId, assessedBy);
    }

    @Transactional
    public ApplicabilityAssessment updateAssessment(Long tenantId, Long assessmentId, AssessmentUpdateRequest request) {
        ApplicabilityAssessment assessment = getAssessment(tenantId, assessmentId);
        return updateAssessment(assessment, assessmentId, request);
    }

    @Transactional
    public ApplicabilityAssessment updateAssessment(UUID tenantId, Long assessmentId, AssessmentUpdateRequest request) {
        ApplicabilityAssessment assessment = getAssessment(tenantId, assessmentId);
        return updateAssessment(assessment, assessmentId, request);
    }

    @Transactional
    public ApplicabilityAssessment completeAssessment(Long tenantId, Long assessmentId,
                                                     ApplicabilityAssessment.AssessmentResult result,
                                                     ApplicabilityAssessment.ConfidenceLevel confidence,
                                                     String justification, String recommendedAction) {
        ApplicabilityAssessment assessment = getAssessment(tenantId, assessmentId);
        return completeAssessment(assessment, assessmentId, result, confidence, justification, recommendedAction);
    }

    @Transactional
    public ApplicabilityAssessment completeAssessment(UUID tenantId, Long assessmentId,
                                                     ApplicabilityAssessment.AssessmentResult result,
                                                     ApplicabilityAssessment.ConfidenceLevel confidence,
                                                     String justification, String recommendedAction) {
        ApplicabilityAssessment assessment = getAssessment(tenantId, assessmentId);
        return completeAssessment(assessment, assessmentId, result, confidence, justification, recommendedAction);
    }

    @Transactional
    public ApplicabilityAssessment submitAssessment(Long tenantId, String cveId, SubmitAssessmentRequest request, String userId) {
        return submitAssessment(resolveTenant(tenantId), cveId, request, userId);
    }

    @Transactional
    public ApplicabilityAssessment submitAssessment(UUID tenantId, String cveId, SubmitAssessmentRequest request, String userId) {
        return submitAssessment(resolveTenant(tenantId), cveId, request, userId);
    }

    @Transactional
    public void deleteAssessment(Long tenantId, Long assessmentId) {
        deleteAssessment(resolveTenant(tenantId), assessmentId);
    }

    @Transactional
    public void deleteAssessment(UUID tenantId, Long assessmentId) {
        deleteAssessment(resolveTenant(tenantId), assessmentId);
    }

    private ApplicabilityAssessment getAssessment(Tenant tenant, Long assessmentId) {
        return tenantSchemaExecutionService.run(tenant, () -> assessmentRepository.findById(assessmentId))
                .orElseThrow(() -> new IllegalArgumentException("Assessment not found: " + assessmentId));
    }

    private List<ApplicabilityAssessment> getAssessmentsByCve(Tenant tenant, String cveId) {
        return tenantSchemaExecutionService.run(tenant, () -> assessmentRepository.findByCveId(cveId));
    }

    private Page<ApplicabilityAssessment> getAssessments(Tenant tenant, Pageable pageable) {
        return tenantSchemaExecutionService.run(tenant, () -> assessmentRepository.findAll(pageable));
    }

    private ApplicabilityAssessment createAssessment(Tenant tenant, String cveId, String assessedBy) {
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("Vulnerability not found: " + cveId));

        ApplicabilityAssessment assessment = new ApplicabilityAssessment();
        assessment.setVulnerability(vulnerability);
        assessment.setTenant(tenant);
        assessment.setStatus(ApplicabilityAssessment.AssessmentStatus.IN_PROGRESS);
        assessment.setAssessedBy(assessedBy);

        ApplicabilityAssessment saved = assessmentRepository.save(assessment);
        log.info("Created assessment {} for CVE {} by user {}", saved.getId(), LogUtil.safe(cveId), LogUtil.safe(assessedBy));
        return saved;
    }

    private ApplicabilityAssessment updateAssessment(ApplicabilityAssessment assessment, Long assessmentId, AssessmentUpdateRequest request) {
        // Step 1: Software Detection
        if (request.getSoftwareDetected() != null) {
            assessment.setSoftwareDetected(request.getSoftwareDetected());
        }
        if (request.getDetectionMethod() != null) {
            assessment.setDetectionMethod(request.getDetectionMethod());
        }
        if (request.getAffectedComponents() != null) {
            assessment.setAffectedComponents(request.getAffectedComponents());
        }

        // Step 2: Version Check
        if (request.getVulnerableVersionPresent() != null) {
            assessment.setVulnerableVersionPresent(request.getVulnerableVersionPresent());
        }
        if (request.getCurrentVersion() != null) {
            assessment.setCurrentVersion(request.getCurrentVersion());
        }
        if (request.getVulnerableVersionRange() != null) {
            assessment.setVulnerableVersionRange(request.getVulnerableVersionRange());
        }
        if (request.getFixedVersion() != null) {
            assessment.setFixedVersion(request.getFixedVersion());
        }

        // Step 3: Configuration Check
        if (request.getVulnerableConfiguration() != null) {
            assessment.setVulnerableConfiguration(request.getVulnerableConfiguration());
        }
        if (request.getConfigurationDetails() != null) {
            assessment.setConfigurationDetails(request.getConfigurationDetails());
        }
        if (request.getAttackVectorAccessible() != null) {
            assessment.setAttackVectorAccessible(request.getAttackVectorAccessible());
        }

        // Step 4: Assessment Result
        if (request.getFinalResult() != null) {
            assessment.setFinalResult(request.getFinalResult());
        }
        if (request.getConfidenceLevel() != null) {
            assessment.setConfidenceLevel(request.getConfidenceLevel());
        }
        if (request.getJustification() != null) {
            assessment.setJustification(request.getJustification());
        }
        if (request.getRecommendedAction() != null) {
            assessment.setRecommendedAction(request.getRecommendedAction());
        }

        // Update status
        if (request.getStatus() != null) {
            assessment.setStatus(request.getStatus());
            if (request.getStatus() == ApplicabilityAssessment.AssessmentStatus.COMPLETED) {
                assessment.setCompletedAt(Instant.now());
            }
        }

        ApplicabilityAssessment saved = assessmentRepository.save(assessment);
        log.info("Updated assessment {} for CVE {}", assessmentId, assessment.getVulnerability().getExternalId());
        return saved;
    }

    private ApplicabilityAssessment completeAssessment(ApplicabilityAssessment assessment, Long assessmentId,
                                                      ApplicabilityAssessment.AssessmentResult result,
                                                      ApplicabilityAssessment.ConfidenceLevel confidence,
                                                      String justification, String recommendedAction) {
        assessment.setStatus(ApplicabilityAssessment.AssessmentStatus.COMPLETED);
        assessment.setFinalResult(result);
        assessment.setConfidenceLevel(confidence);
        assessment.setJustification(justification);
        assessment.setRecommendedAction(recommendedAction);
        assessment.setCompletedAt(Instant.now());

        ApplicabilityAssessment saved = assessmentRepository.save(assessment);
        log.info("Completed assessment {} for CVE {} with result {}", assessmentId,
                assessment.getVulnerability().getExternalId(), result);
        return saved;
    }

    private ApplicabilityAssessment submitAssessment(Tenant tenant, String cveId, SubmitAssessmentRequest request, String userId) {
        // Find existing in-progress assessment or create new
        List<ApplicabilityAssessment> existing = tenantSchemaExecutionService.run(
                tenant,
                () -> assessmentRepository.findByCveId(cveId)
        );
        ApplicabilityAssessment assessment = existing.stream()
                .filter(a -> a.getStatus() == ApplicabilityAssessment.AssessmentStatus.IN_PROGRESS)
                .findFirst()
                .orElse(null);

        if (assessment == null) {
            Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                    .orElseThrow(() -> new IllegalArgumentException("Vulnerability not found: " + cveId));
            assessment = new ApplicabilityAssessment();
            assessment.setVulnerability(vulnerability);
            assessment.setTenant(tenant);
            assessment.setAssessedBy(userId);
        }

        if (request.getSoftwareDetected() != null) assessment.setSoftwareDetected(request.getSoftwareDetected());
        if (request.getDetectionMethod() != null) assessment.setDetectionMethod(request.getDetectionMethod());
        if (request.getAffectedComponents() != null) assessment.setAffectedComponents(request.getAffectedComponents());
        if (request.getVulnerableVersionPresent() != null) assessment.setVulnerableVersionPresent(request.getVulnerableVersionPresent());
        if (request.getFinalResult() != null) assessment.setFinalResult(request.getFinalResult());
        assessment.setConfidenceLevel(request.getConfidenceLevel() != null ? request.getConfidenceLevel() : ApplicabilityAssessment.ConfidenceLevel.MEDIUM);
        if (request.getJustification() != null) assessment.setJustification(request.getJustification());
        if (request.getRecommendedAction() != null) assessment.setRecommendedAction(request.getRecommendedAction());
        assessment.setStatus(ApplicabilityAssessment.AssessmentStatus.COMPLETED);
        assessment.setCompletedAt(Instant.now());

        ApplicabilityAssessment saved = assessmentRepository.save(assessment);
        log.info("Submitted assessment {} for CVE {} with result {}", saved.getId(), LogUtil.safe(cveId), request.getFinalResult());

        Map<String, String> analystDispositions = request.getComponentAnalystDispositions();
        if ((analystDispositions == null || analystDispositions.isEmpty())
                && request.getComponentImpactDecisions() != null
                && !request.getComponentImpactDecisions().isEmpty()) {
            analystDispositions = request.getComponentImpactDecisions();
        }

        // Persist per-component analyst dispositions without overwriting computed impact.
        if (analystDispositions != null && !analystDispositions.isEmpty()) {
            Vulnerability vulnerability = saved.getVulnerability();
            List<ComponentVulnerabilityState> states =
                    tenantSchemaExecutionService.run(
                            tenant,
                            () -> componentVulnerabilityStateRepository.findByVulnerability_Id(vulnerability.getId())
                    );
            boolean anyChanged = false;
            for (ComponentVulnerabilityState state : states) {
                if (state.getComponent() == null || state.getComponent().getId() == null) continue;
                String componentIdStr = state.getComponent().getId().toString();
                String decision = analystDispositions.get(componentIdStr);
                if (decision == null) continue;
                AnalystDisposition newDisposition = switch (decision.toUpperCase()) {
                    case "IMPACTED"     -> AnalystDisposition.IMPACTED;
                    case "NOT_IMPACTED" -> AnalystDisposition.NOT_IMPACTED;
                    default             -> AnalystDisposition.UNKNOWN;
                };
                if (state.getAnalystDisposition() != newDisposition
                        || !java.util.Objects.equals(state.getAnalystReason(), request.getJustification())
                        || !java.util.Objects.equals(state.getAnalystUpdatedBy(), userId)) {
                    state.setAnalystDisposition(newDisposition);
                    state.setAnalystReason(request.getJustification());
                    state.setAnalystUpdatedBy(userId);
                    state.setAnalystUpdatedAt(Instant.now());
                    state.touch();
                    anyChanged = true;
                }
            }
            if (anyChanged) {
                componentVulnerabilityStateRepository.saveAll(states);
                log.info("Updated analyst component dispositions for CVE {}", LogUtil.safe(cveId));
            }
        }

        return tenantSchemaExecutionService.run(tenant, () -> assessmentRepository.findById(saved.getId())).orElse(saved);
    }

    private void deleteAssessment(Tenant tenant, Long assessmentId) {
        ApplicabilityAssessment assessment = getAssessment(tenant, assessmentId);
        assessmentRepository.delete(assessment);
        log.info("Deleted assessment {} for tenant {}", assessmentId, tenant.getId());
    }

    private Tenant resolveTenant(Long tenantId) {
        return tenantService.resolveTenant(tenantId);
    }

    private Tenant resolveTenant(UUID tenantId) {
        return tenantService.resolveTenantUuid(tenantId);
    }

    // DTO for single-call submit (create-or-update-and-complete)
    @lombok.Data
    public static class SubmitAssessmentRequest {
        private Boolean softwareDetected;
        private String detectionMethod;
        private String affectedComponents;
        private Boolean vulnerableVersionPresent;
        private ApplicabilityAssessment.AssessmentResult finalResult;
        private ApplicabilityAssessment.ConfidenceLevel confidenceLevel;
        private String justification;
        private String recommendedAction;
        /** Legacy compatibility field. Persisted as analyst disposition only. */
        private Map<String, String> componentImpactDecisions;
        /** Per-component analyst dispositions: componentId → "IMPACTED" | "NOT_IMPACTED" | "UNKNOWN" */
        private Map<String, String> componentAnalystDispositions;
    }

    // DTO for update requests
    @lombok.Data
    public static class AssessmentUpdateRequest {
        // Step 1
        private Boolean softwareDetected;
        private String detectionMethod;
        private String affectedComponents;

        // Step 2
        private Boolean vulnerableVersionPresent;
        private String currentVersion;
        private String vulnerableVersionRange;
        private String fixedVersion;

        // Step 3
        private Boolean vulnerableConfiguration;
        private String configurationDetails;
        private Boolean attackVectorAccessible;

        // Step 4
        private ApplicabilityAssessment.AssessmentResult finalResult;
        private ApplicabilityAssessment.ConfidenceLevel confidenceLevel;
        private String justification;
        private String recommendedAction;

        private ApplicabilityAssessment.AssessmentStatus status;
    }
}
