package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.ImpactState;
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

@Service
@RequiredArgsConstructor
@Slf4j
public class ApplicabilityAssessmentService {

    private final ApplicabilityAssessmentRepository assessmentRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final TenantService tenantService;

    @Transactional(readOnly = true)
    public ApplicabilityAssessment getAssessment(Long tenantId, Long assessmentId) {
        Tenant tenant = tenantService.resolveTenant(tenantId);
        return assessmentRepository.findByIdAndTenantId(assessmentId, tenant.getId())
                .orElseThrow(() -> new IllegalArgumentException("Assessment not found: " + assessmentId));
    }

    @Transactional(readOnly = true)
    public List<ApplicabilityAssessment> getAssessmentsByCve(Long tenantId, String cveId) {
        Tenant tenant = tenantService.resolveTenant(tenantId);
        return assessmentRepository.findByTenantIdAndCveId(tenant.getId(), cveId);
    }

    @Transactional(readOnly = true)
    public Page<ApplicabilityAssessment> getAssessments(Long tenantId, Pageable pageable) {
        Tenant tenant = tenantService.resolveTenant(tenantId);
        return assessmentRepository.findByTenantId(tenant.getId(), pageable);
    }

    @Transactional
    public ApplicabilityAssessment createAssessment(Long tenantId, String cveId, String assessedBy) {
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("Vulnerability not found: " + cveId));
        Tenant tenant = tenantService.resolveTenant(tenantId);

        ApplicabilityAssessment assessment = new ApplicabilityAssessment();
        assessment.setVulnerability(vulnerability);
        assessment.setTenant(tenant);
        assessment.setStatus(ApplicabilityAssessment.AssessmentStatus.IN_PROGRESS);
        assessment.setAssessedBy(assessedBy);

        ApplicabilityAssessment saved = assessmentRepository.save(assessment);
        log.info("Created assessment {} for CVE {} by user {}", saved.getId(), cveId, assessedBy);
        return saved;
    }

    @Transactional
    public ApplicabilityAssessment updateAssessment(Long tenantId, Long assessmentId, AssessmentUpdateRequest request) {
        ApplicabilityAssessment assessment = getAssessment(tenantId, assessmentId);

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

    @Transactional
    public ApplicabilityAssessment completeAssessment(Long tenantId, Long assessmentId,
                                                     ApplicabilityAssessment.AssessmentResult result,
                                                     ApplicabilityAssessment.ConfidenceLevel confidence,
                                                     String justification, String recommendedAction) {
        ApplicabilityAssessment assessment = getAssessment(tenantId, assessmentId);

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

    @Transactional
    public ApplicabilityAssessment submitAssessment(Long tenantId, String cveId, SubmitAssessmentRequest request, String userId) {
        Tenant tenant = tenantService.resolveTenant(tenantId);

        // Find existing in-progress assessment or create new
        List<ApplicabilityAssessment> existing = assessmentRepository.findByTenantIdAndCveId(tenant.getId(), cveId);
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
        log.info("Submitted assessment {} for CVE {} with result {}", saved.getId(), cveId, request.getFinalResult());

        // Persist per-component impact decisions to ComponentVulnerabilityState
        if (request.getComponentImpactDecisions() != null && !request.getComponentImpactDecisions().isEmpty()) {
            Vulnerability vulnerability = saved.getVulnerability();
            List<ComponentVulnerabilityState> states =
                    componentVulnerabilityStateRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId());
            boolean anyChanged = false;
            for (ComponentVulnerabilityState state : states) {
                if (state.getComponent() == null || state.getComponent().getId() == null) continue;
                String componentIdStr = state.getComponent().getId().toString();
                String decision = request.getComponentImpactDecisions().get(componentIdStr);
                if (decision == null) continue;
                ImpactState newImpactState = switch (decision.toUpperCase()) {
                    case "IMPACTED"     -> ImpactState.IMPACTED;
                    case "NOT_IMPACTED" -> ImpactState.NOT_IMPACTED;
                    default             -> ImpactState.UNKNOWN;
                };
                if (state.getImpactState() != newImpactState) {
                    state.setImpactState(newImpactState);
                    state.setEligibleForFinding(newImpactState == ImpactState.IMPACTED || newImpactState == ImpactState.NO_PATCH);
                    anyChanged = true;
                }
            }
            if (anyChanged) {
                componentVulnerabilityStateRepository.saveAll(states);
                log.info("Updated component impact states for CVE {} based on analyst decisions", cveId);
            }
        }

        return assessmentRepository.findByIdAndTenantId(saved.getId(), tenant.getId()).orElse(saved);
    }

    @Transactional
    public void deleteAssessment(Long tenantId, Long assessmentId) {
        ApplicabilityAssessment assessment = getAssessment(tenantId, assessmentId);
        assessmentRepository.delete(assessment);
        log.info("Deleted assessment {} for tenant {}", assessmentId, tenantId);
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
        /** Per-component impact decisions: componentId → "IMPACTED" | "NOT_IMPACTED" | "UNKNOWN" */
        private Map<String, String> componentImpactDecisions;
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
