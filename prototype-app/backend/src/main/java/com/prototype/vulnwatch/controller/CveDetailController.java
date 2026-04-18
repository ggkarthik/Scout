package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import com.prototype.vulnwatch.dto.SavedCveInvestigationSummaryResponse;
import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.service.ApplicabilityAssessmentService;
import com.prototype.vulnwatch.service.CveInvestigationAiSummaryService;
import com.prototype.vulnwatch.service.CveDetailQueryFacade;
import com.prototype.vulnwatch.service.CveInvestigationSummaryService;
import com.prototype.vulnwatch.service.CveInvestigationSummaryPersistenceService;
import com.prototype.vulnwatch.service.CveWorkflowFacade;
import com.prototype.vulnwatch.service.InvestigationService;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for CVE drill-down functionality
 */
@RestController
@RequestMapping("/api/cve-detail")
@RequiredArgsConstructor
public class CveDetailController {

    private final CveDetailQueryFacade queryFacade;
    private final CveWorkflowFacade workflowFacade;
    private final CveInvestigationSummaryService summaryService;
    private final CveInvestigationAiSummaryService aiSummaryService;
    private final CveInvestigationSummaryPersistenceService summaryPersistenceService;

    /**
     * GET /api/cve-detail/{cveId}
     * Get CVE detail with summary, key signals, and available actions
     */
    @GetMapping("/{cveId}")
    public ResponseEntity<CveDetailResponse> getCveDetail(
            @PathVariable String cveId) {
        return queryFacade.getCveDetail(cveId);
    }

    @GetMapping("/{cveId}/vex-evidence")
    public ResponseEntity<VexEvidenceResponse> getVexEvidence(
            @PathVariable String cveId,
            @RequestParam("componentId") UUID componentId) {
        return queryFacade.getVexEvidence(cveId, componentId);
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation
     * Create a new investigation for this CVE
     */
    @PostMapping("/{cveId}/investigation")
    public ResponseEntity<InvestigationDto> createInvestigation(
            @PathVariable String cveId,
            @RequestBody CreateInvestigationRequest request) {
        return workflowFacade.createInvestigation(cveId, request);
    }

    /**
     * PUT /api/cve-detail/investigation/{investigationId}
     * Update an existing investigation
     */
    @PutMapping("/investigation/{investigationId}")
    public ResponseEntity<InvestigationDto> updateInvestigation(
            @PathVariable Long investigationId,
            @RequestBody InvestigationService.InvestigationUpdateRequest request) {
        return workflowFacade.updateInvestigation(investigationId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation/submit
     * Create-or-update investigation in a single call (upsert semantics)
     */
    @PostMapping("/{cveId}/investigation/submit")
    public ResponseEntity<InvestigationDto> submitInvestigation(
            @PathVariable String cveId,
            @RequestBody InvestigationService.SubmitInvestigationRequest request) {
        return workflowFacade.submitInvestigation(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/assessment/submit
     * Create-or-update-and-complete assessment in a single call (upsert + complete)
     */
    @PostMapping("/{cveId}/assessment/submit")
    public ResponseEntity<AssessmentDto> submitAssessment(
            @PathVariable String cveId,
            @RequestBody ApplicabilityAssessmentService.SubmitAssessmentRequest request) {
        return workflowFacade.submitAssessment(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/applicability-assessment
     * Start applicability assessment wizard
     */
    @PostMapping("/{cveId}/applicability-assessment")
    public ResponseEntity<AssessmentDto> createAssessment(
            @PathVariable String cveId) {
        return workflowFacade.createAssessment(cveId);
    }

    /**
     * PUT /api/cve-detail/applicability-assessment/{assessmentId}
     * Update assessment (step by step)
     */
    @PutMapping("/applicability-assessment/{assessmentId}")
    public ResponseEntity<AssessmentDto> updateAssessment(
            @PathVariable Long assessmentId,
            @RequestBody ApplicabilityAssessmentService.AssessmentUpdateRequest request) {
        return workflowFacade.updateAssessment(assessmentId, request);
    }

    /**
     * POST /api/cve-detail/applicability-assessment/{assessmentId}/complete
     * Complete the assessment with final result
     */
    @PostMapping("/applicability-assessment/{assessmentId}/complete")
    public ResponseEntity<AssessmentDto> completeAssessment(
            @PathVariable Long assessmentId,
            @RequestBody CompleteAssessmentRequest request) {
        return workflowFacade.completeAssessment(assessmentId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/manual-finding
     * Create manual finding (add to backlog)
     */
    @PostMapping("/{cveId}/manual-finding")
    public ResponseEntity<ManualFindingResponse> createManualFinding(
            @PathVariable String cveId,
            @RequestBody CreateManualFindingRequest request) {
        return workflowFacade.createManualFinding(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/suppress
     * Suppress this CVE for the organization
     */
    @PostMapping("/{cveId}/suppress")
    public ResponseEntity<SuppressionResponse> suppressCve(
            @PathVariable String cveId,
            @RequestBody SuppressRequest request) {
        return workflowFacade.suppressCve(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/export
     * Export CVE report in various formats
     */
    @PostMapping("/{cveId}/export")
    public ResponseEntity<ExportResponse> exportCveReport(
            @PathVariable String cveId,
            @RequestBody ExportRequest request) {
        return queryFacade.exportCveReport(cveId, request);
    }

    @PostMapping("/{cveId}/investigation-summary")
    public ResponseEntity<CveInvestigationSummaryResponse> generateInvestigationSummary(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> request) {
        CveInvestigationSummaryResponse summary = summaryService.generateSummary(cveId, request);
        summaryPersistenceService.saveSummary(cveId, request, summary, "deterministic");
        return ResponseEntity.ok(summary);
    }

    @PostMapping("/{cveId}/investigation-ai-summary")
    public ResponseEntity<CveInvestigationSummaryResponse> generateInvestigationAiSummary(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> request) {
        CveInvestigationSummaryResponse summary = aiSummaryService.generateAiSummary(cveId, request);
        summaryPersistenceService.saveSummary(cveId, request, summary, "ai");
        return ResponseEntity.ok(summary);
    }

    @GetMapping("/{cveId}/saved-investigation-summary")
    public ResponseEntity<SavedCveInvestigationSummaryResponse> getSavedInvestigationSummary(
            @PathVariable String cveId) {
        return ResponseEntity.ok(summaryPersistenceService.getSavedSummary(cveId));
    }

    // DTOs

    @Data
    public static class CveDetailResponse {
        private CveSummary summary;
        private KeySignals signals;
        private List<InvestigationDto> investigations;
        private List<AssessmentDto> assessments;
        private List<MatchedSoftwareDto> matchedSoftware;
        private List<VendorIntelligenceDto> vendorIntelligence;
        private List<CveReference> references;
    }

    @Data
    public static class CveReference {
        private String url;
        private String source;
        private List<String> tags;
    }

    @Data
    public static class VendorIntelligenceDto {
        private String source;
        private String ecosystem;
        private String packageName;
        private String affectedVersions;
        private String fixedVersion;
        private String cpe;
        private String vexStatus;
    }

    @Data
    public static class CveSummary {
        private String externalId;
        private String title;
        private String description;
        private String severity;
        private Double cvssScore;
        private String cvssVector;
        private Double epssScore;
        private Double epssSevenDayDelta;
        /** BLG-016: when the EPSS score was last refreshed from the FIRST.org feed. */
        private Instant epssUpdatedAt;
        private String cweIds;
        private Instant publishedAt;
        private Instant modifiedAt;
        private VulnerabilitySource source;
        private Boolean inKev;
        private LocalDate kevDateAdded;
        private LocalDate kevDueDate;
        private String kevRequiredAction;
    }

    @Data
    public static class KeySignals {
        private boolean exploitAvailable;
        private String exploitReason;
        private boolean systemsImpacted;
        private long componentCount;
        private long softwareCount;
        private long assetCount;
        private boolean patchAvailable;
        private String patchVersions;
    }

    @Data
    public static class InvestigationDto {
        private Long id;
        private String cveId;
        private Investigation.InvestigationStatus status;
        private String assignedTo;
        private Investigation.InvestigationPriority priority;
        private String notes;
        private Instant createdAt;
        private Instant updatedAt;
    }

    @Data
    public static class AssessmentDto {
        private Long id;
        private String cveId;
        private ApplicabilityAssessment.AssessmentStatus status;
        private Boolean softwareDetected;
        private Boolean vulnerableVersionPresent;
        private Boolean vulnerableConfiguration;
        private ApplicabilityAssessment.AssessmentResult finalResult;
        private ApplicabilityAssessment.ConfidenceLevel confidenceLevel;
        private String justification;
        private String recommendedAction;
        private Instant createdAt;
        private Instant completedAt;
    }

    @Data
    public static class MatchedSoftwareDto {
        private UUID componentId;
        private UUID assetId;
        private String assetName;
        private String assetIdentifier;
        private String assetType;
        private String ecosystem;
        private String packageName;
        private String version;
        private ApplicabilityState applicabilityState;
        private String applicabilityReason;
        private String applicabilityReasonDetail;
        private ImpactState computedImpactState;
        private String computedImpactReason;
        private String computedImpactReasonDetail;
        private ImpactState impactState;
        private String impactReason;
        private String impactReasonDetail;
        private String vexStatus;
        private String vexProvider;
        private String vexFreshness;
        private String vexSource;
        private UUID matchedVexAssertionId;
        private String analystDisposition;
        private String analystReason;
        private String matchedBy;
        private boolean eligibleForFinding;
        private String findingEligibilityReason;
        private String findingEligibilityDetail;
        private String eolSlug;
        private String eolCycle;
        private java.time.LocalDate eolDate;
        private Boolean isEol;
        private Integer eolDaysRemaining;
        private java.time.LocalDate eolSupportEndDate;
        private String supportPhase;
    }

    @Data
    public static class VexEvidenceResponse {
        private UUID componentId;
        private String assetName;
        private String assetIdentifier;
        private String assetType;
        private String ecosystem;
        private String installedVersion;
        private String matchedBy;
        private String applicabilityState;
        private String applicabilityReason;
        private String applicabilityReasonDetail;
        private UUID matchedVexAssertionId;
        private String sourceSystem;
        private String provider;
        private String status;
        private String trustTier;
        private String freshness;
        private String documentId;
        private String packageName;
        private String normalizedProductKey;
        private String versionExact;
        private String versionStart;
        private Boolean startInclusive;
        private String versionEnd;
        private Boolean endInclusive;
        private String fixedVersion;
        private Instant publishedAt;
        private Instant lastSeenAt;
        private String evidenceUrl;
        private String computedImpactState;
        private String computedImpactReason;
        private String computedImpactReasonDetail;
        private String impactState;
        private String impactReason;
        private String impactReasonDetail;
        private Map<String, Object> evidence;
    }

    @Data
    public static class CreateInvestigationRequest {
        private Investigation.InvestigationPriority priority;
    }

    @Data
    public static class CreateManualFindingRequest {
        private String justification;
        private List<String> componentIds;
        private Map<String, String> componentApplicabilityDecisions;
        private Map<String, String> componentAnalystDispositions;
    }

    @Data
    public static class ManualFindingResponse {
        private String cveId;
        private int eligibleComponentCount;
        private int createdCount;
        private int reopenedCount;
        private int alreadyOpenCount;
        private String message;
    }

    @Data
    public static class CompleteAssessmentRequest {
        private ApplicabilityAssessment.AssessmentResult result;
        private ApplicabilityAssessment.ConfidenceLevel confidence;
        private String justification;
        private String recommendedAction;
    }

    @Data
    public static class SuppressRequest {
        private String reason;
        private String justification;
        private Integer duration; // days
    }

    @Data
    public static class SuppressionResponse {
        private String cveId;
        private boolean suppressed;
        private String reason;
        private String suppressedBy;
        private Instant suppressedAt;
        private Instant expiresAt;
    }

    @Data
    public static class ExportRequest {
        private String format; // pdf, csv, json, excel
    }

    @Data
    public static class ExportResponse {
        private String cveId;
        private String format;
        private String content;
        private Instant generatedAt;
    }
}
