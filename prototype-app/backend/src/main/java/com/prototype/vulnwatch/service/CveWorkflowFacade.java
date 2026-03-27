package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.controller.CveDetailController;
import com.prototype.vulnwatch.domain.AnalystDisposition;
import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class CveWorkflowFacade {

    private final InvestigationService investigationService;
    private final ApplicabilityAssessmentService assessmentService;
    private final FindingDeltaQueueService findingDeltaQueueService;
    private final FindingWorkflowFacade findingWorkflowFacade;
    private final OrgCveRecordService orgCveRecordService;
    private final RequestActorService requestActorService;
    private final TenantService tenantService;
    private final VulnerabilityRepository vulnerabilityRepository;

    public CveWorkflowFacade(
            InvestigationService investigationService,
            ApplicabilityAssessmentService assessmentService,
            FindingDeltaQueueService findingDeltaQueueService,
            FindingWorkflowFacade findingWorkflowFacade,
            OrgCveRecordService orgCveRecordService,
            RequestActorService requestActorService,
            TenantService tenantService,
            VulnerabilityRepository vulnerabilityRepository
    ) {
        this.investigationService = investigationService;
        this.assessmentService = assessmentService;
        this.findingDeltaQueueService = findingDeltaQueueService;
        this.findingWorkflowFacade = findingWorkflowFacade;
        this.orgCveRecordService = orgCveRecordService;
        this.requestActorService = requestActorService;
        this.tenantService = tenantService;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    public ResponseEntity<CveDetailController.InvestigationDto> createInvestigation(
            String cveId,
            CveDetailController.CreateInvestigationRequest request
    ) {
        RequestActor actor = requestActorService.currentActor();
        Investigation investigation = investigationService.createInvestigation(
                actor.tenantId(),
                cveId,
                request.getPriority(),
                actor.userId()
        );
        return ResponseEntity.ok(toInvestigationDto(investigation));
    }

    public ResponseEntity<CveDetailController.InvestigationDto> updateInvestigation(
            Long investigationId,
            InvestigationService.InvestigationUpdateRequest request
    ) {
        RequestActor actor = requestActorService.currentActor();
        Investigation investigation = investigationService.updateInvestigation(
                actor.tenantId(),
                investigationId,
                request,
                actor.userId()
        );
        return ResponseEntity.ok(toInvestigationDto(investigation));
    }

    public ResponseEntity<CveDetailController.InvestigationDto> submitInvestigation(
            String cveId,
            InvestigationService.SubmitInvestigationRequest request
    ) {
        RequestActor actor = requestActorService.currentActor();
        Investigation investigation = investigationService.submitInvestigation(
                actor.tenantId(),
                cveId,
                request,
                actor.userId()
        );
        return ResponseEntity.ok(toInvestigationDto(investigation));
    }

    public ResponseEntity<CveDetailController.AssessmentDto> submitAssessment(
            String cveId,
            ApplicabilityAssessmentService.SubmitAssessmentRequest request
    ) {
        RequestActor actor = requestActorService.currentActor();
        ApplicabilityAssessment assessment = assessmentService.submitAssessment(
                actor.tenantId(),
                cveId,
                request,
                actor.userId()
        );
        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    public ResponseEntity<CveDetailController.AssessmentDto> createAssessment(String cveId) {
        RequestActor actor = requestActorService.currentActor();
        ApplicabilityAssessment assessment = assessmentService.createAssessment(actor.tenantId(), cveId, actor.userId());
        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    public ResponseEntity<CveDetailController.AssessmentDto> updateAssessment(
            Long assessmentId,
            ApplicabilityAssessmentService.AssessmentUpdateRequest request
    ) {
        ApplicabilityAssessment assessment = assessmentService.updateAssessment(
                requestActorService.currentActor().tenantId(),
                assessmentId,
                request
        );
        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    public ResponseEntity<CveDetailController.AssessmentDto> completeAssessment(
            Long assessmentId,
            CveDetailController.CompleteAssessmentRequest request
    ) {
        ApplicabilityAssessment assessment = assessmentService.completeAssessment(
                requestActorService.currentActor().tenantId(),
                assessmentId,
                request.getResult(),
                request.getConfidence(),
                request.getJustification(),
                request.getRecommendedAction()
        );
        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    public ResponseEntity<CveDetailController.ManualFindingResponse> createManualFinding(
            String cveId,
            CveDetailController.CreateManualFindingRequest request
    ) {
        RequestActor actor = requestActorService.currentActor();
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));
        Tenant tenant = tenantService.resolveTenantUuid(actor.tenantId());

        ManualFindingCreationResult result = findingWorkflowFacade.createManualFindingsForVulnerability(
                tenant,
                vulnerability,
                request.getJustification(),
                actor.userId(),
                parseComponentIds(request.getComponentIds()),
                parseApplicabilityDecisions(request.getComponentApplicabilityDecisions()),
                parseAnalystDispositions(request.getComponentAnalystDispositions())
        );

        CveDetailController.ManualFindingResponse response = new CveDetailController.ManualFindingResponse();
        response.setCveId(cveId);
        response.setEligibleComponentCount(result.eligibleComponentCount());
        response.setCreatedCount(result.createdCount());
        response.setReopenedCount(result.reopenedCount());
        response.setAlreadyOpenCount(result.alreadyOpenCount());
        String message;
        if (result.createdCount() + result.reopenedCount() > 0) {
            findingDeltaQueueService.enqueueNoiseReductionRefresh(tenant.getId(), "manual-finding");
            message = "Manual finding workflow completed.";
        } else if (result.alreadyOpenCount() > 0) {
            message = "Findings already open for all selected components. No duplicates created.";
        } else {
            message = "No eligible components found. Findings require either exact impacted or no-patch evidence, or an analyst override marking the component Applicable and Impacted.";
        }
        response.setMessage(message);
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<CveDetailController.SuppressionResponse> suppressCve(
            String cveId,
            CveDetailController.SuppressRequest request
    ) {
        RequestActor actor = requestActorService.currentActor();
        Tenant tenant = tenantService.resolveTenantUuid(actor.tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));
        if (!hasText(request.getReason()) || !hasText(request.getJustification())) {
            throw new IllegalArgumentException("Suppression reason and justification are required");
        }
        Instant suppressedAt = Instant.now();
        Instant expiresAt = resolveSuppressedUntil(request.getDuration(), suppressedAt);
        orgCveRecordService.suppress(
                tenant,
                vulnerability,
                request.getReason(),
                request.getJustification(),
                actor.userId(),
                suppressedAt,
                expiresAt
        );
        findingWorkflowFacade.suppressFindingsForVulnerability(
                tenant,
                vulnerability,
                request.getReason(),
                request.getJustification(),
                actor.userId(),
                expiresAt
        );

        CveDetailController.SuppressionResponse response = new CveDetailController.SuppressionResponse();
        response.setCveId(cveId);
        response.setSuppressed(true);
        response.setReason(request.getReason());
        response.setSuppressedBy(actor.userId());
        response.setSuppressedAt(suppressedAt);
        response.setExpiresAt(expiresAt);
        return ResponseEntity.ok(response);
    }

    private CveDetailController.InvestigationDto toInvestigationDto(Investigation investigation) {
        CveDetailController.InvestigationDto dto = new CveDetailController.InvestigationDto();
        dto.setId(investigation.getId());
        dto.setCveId(investigation.getVulnerability().getExternalId());
        dto.setStatus(investigation.getStatus());
        dto.setAssignedTo(investigation.getAssignedTo());
        dto.setPriority(investigation.getPriority());
        dto.setNotes(investigation.getNotes());
        dto.setCreatedAt(investigation.getCreatedAt());
        dto.setUpdatedAt(investigation.getUpdatedAt());
        return dto;
    }

    private CveDetailController.AssessmentDto toAssessmentDto(ApplicabilityAssessment assessment) {
        CveDetailController.AssessmentDto dto = new CveDetailController.AssessmentDto();
        dto.setId(assessment.getId());
        dto.setCveId(assessment.getVulnerability().getExternalId());
        dto.setStatus(assessment.getStatus());
        dto.setSoftwareDetected(assessment.getSoftwareDetected());
        dto.setVulnerableVersionPresent(assessment.getVulnerableVersionPresent());
        dto.setVulnerableConfiguration(assessment.getVulnerableConfiguration());
        dto.setFinalResult(assessment.getFinalResult());
        dto.setConfidenceLevel(assessment.getConfidenceLevel());
        dto.setJustification(assessment.getJustification());
        dto.setRecommendedAction(assessment.getRecommendedAction());
        dto.setCreatedAt(assessment.getCreatedAt());
        dto.setCompletedAt(assessment.getCompletedAt());
        return dto;
    }

    private Instant resolveSuppressedUntil(Integer durationDays, Instant suppressedAt) {
        if (durationDays == null || durationDays <= 0) {
            return null;
        }
        return suppressedAt.plusSeconds(durationDays.longValue() * 86400L);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private Set<UUID> parseComponentIds(java.util.List<String> componentIds) {
        if (componentIds == null || componentIds.isEmpty()) {
            return Set.of();
        }
        Set<UUID> parsed = new LinkedHashSet<>();
        for (String componentId : componentIds) {
            if (!hasText(componentId)) {
                continue;
            }
            try {
                parsed.add(UUID.fromString(componentId.trim()));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid componentId: " + componentId);
            }
        }
        return parsed;
    }

    private Map<UUID, ApplicabilityState> parseApplicabilityDecisions(Map<String, String> decisions) {
        if (decisions == null || decisions.isEmpty()) {
            return Map.of();
        }
        Map<UUID, ApplicabilityState> parsed = new HashMap<>();
        for (Map.Entry<String, String> entry : decisions.entrySet()) {
            if (!hasText(entry.getKey()) || !hasText(entry.getValue())) {
                continue;
            }
            UUID componentId;
            try {
                componentId = UUID.fromString(entry.getKey().trim());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid componentId: " + entry.getKey());
            }
            ApplicabilityState state = switch (entry.getValue().trim().toUpperCase()) {
                case "APPLICABLE" -> ApplicabilityState.APPLICABLE;
                case "NOT_APPLICABLE" -> ApplicabilityState.NOT_APPLICABLE;
                default -> ApplicabilityState.UNKNOWN;
            };
            parsed.put(componentId, state);
        }
        return parsed;
    }

    private Map<UUID, AnalystDisposition> parseAnalystDispositions(Map<String, String> decisions) {
        if (decisions == null || decisions.isEmpty()) {
            return Map.of();
        }
        Map<UUID, AnalystDisposition> parsed = new HashMap<>();
        for (Map.Entry<String, String> entry : decisions.entrySet()) {
            if (!hasText(entry.getKey()) || !hasText(entry.getValue())) {
                continue;
            }
            UUID componentId;
            try {
                componentId = UUID.fromString(entry.getKey().trim());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid componentId: " + entry.getKey());
            }
            AnalystDisposition disposition = switch (entry.getValue().trim().toUpperCase()) {
                case "IMPACTED" -> AnalystDisposition.IMPACTED;
                case "NOT_IMPACTED" -> AnalystDisposition.NOT_IMPACTED;
                default -> AnalystDisposition.UNKNOWN;
            };
            parsed.put(componentId, disposition);
        }
        return parsed;
    }
}
