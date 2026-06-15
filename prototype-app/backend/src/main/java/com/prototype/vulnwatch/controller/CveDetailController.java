package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import com.prototype.vulnwatch.dto.FixRecordResponse;
import com.prototype.vulnwatch.dto.SavedCveInvestigationSummaryResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.FixRecordService;
import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.service.ApplicabilityAssessmentService;
import com.prototype.vulnwatch.service.CveAiSolutionPersistenceService;
import com.prototype.vulnwatch.service.CveAiActionsService;
import com.prototype.vulnwatch.service.CveAiSolutionService;
import com.prototype.vulnwatch.service.CveDetailQueryFacade;
import com.prototype.vulnwatch.service.CveInvestigationAiSummaryService;
import com.prototype.vulnwatch.service.CveInvestigationSummaryService;
import com.prototype.vulnwatch.service.CveInvestigationSummaryPersistenceService;
import com.prototype.vulnwatch.service.CveWorkflowFacade;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.EntitlementGuard;
import com.prototype.vulnwatch.service.InvestigationService;
import com.prototype.vulnwatch.service.TenantEntitlementService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
    private final CveAiSolutionPersistenceService aiSolutionPersistenceService;
    private final CveAiSolutionService aiSolutionService;
    private final CveAiActionsService aiActionsService;
    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper;
    private final WorkspaceService workspaceService;
    private final EntitlementGuard entitlementGuard;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;
    private final FixRecordService fixRecordService;
    private final com.prototype.vulnwatch.service.InvestigationRunbookService investigationRunbookService;
    private final com.prototype.vulnwatch.service.InventoryResolutionService inventoryResolutionService;
    private final com.prototype.vulnwatch.service.FalsePositiveAnalysisService falsePositiveAnalysisService;
    private final com.prototype.vulnwatch.service.EolAnalysisService eolAnalysisService;
    private final com.prototype.vulnwatch.service.InvestigationAgentService investigationAgentService;

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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.investigation.created")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.investigation.updated")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.investigation.submitted")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.assessment.submitted")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.assessment.created")
    public ResponseEntity<AssessmentDto> createAssessment(
            @PathVariable String cveId) {
        return workflowFacade.createAssessment(cveId);
    }

    /**
     * PUT /api/cve-detail/applicability-assessment/{assessmentId}
     * Update assessment (step by step)
     */
    @PutMapping("/applicability-assessment/{assessmentId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.assessment.updated")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.assessment.completed")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.manual_finding.created")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.suppressed")
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
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')")
    public ResponseEntity<ExportResponse> exportCveReport(
            @PathVariable String cveId,
            @RequestBody ExportRequest request) {
        return queryFacade.exportCveReport(cveId, request);
    }

    @PostMapping("/{cveId}/investigation-summary")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<CveInvestigationSummaryResponse> generateInvestigationSummary(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> request) {
        CveInvestigationSummaryResponse summary = summaryService.generateSummary(cveId, request);
        summaryPersistenceService.saveSummary(cveId, request, summary, "deterministic");
        return ResponseEntity.ok(summary);
    }

    @PostMapping("/{cveId}/investigation-ai-summary")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<CveInvestigationSummaryResponse> generateInvestigationAiSummary(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> request) {
        assertDemoAllowsAiAction();
        assertEntitled(TenantEntitlementService.AI_INVESTIGATION_SUMMARY,
                "AI investigation summaries are available on the Enterprise plan.");
        CveInvestigationSummaryResponse summary = aiSummaryService.generateAiSummary(cveId, request);
        summaryPersistenceService.saveSummary(cveId, request, summary, "ai");
        return ResponseEntity.ok(summary);
    }

    @GetMapping("/{cveId}/saved-investigation-summary")
    public ResponseEntity<SavedCveInvestigationSummaryResponse> getSavedInvestigationSummary(
            @PathVariable String cveId) {
        SavedCveInvestigationSummaryResponse savedSummary = summaryPersistenceService.getSavedSummary(cveId);
        if ("ai".equalsIgnoreCase(savedSummary.mode())) {
            assertEntitled(TenantEntitlementService.AI_INVESTIGATION_SUMMARY,
                    "AI investigation summaries are available on the Enterprise plan.");
        }
        return ResponseEntity.ok(savedSummary);
    }

    /**
     * GET /api/cve-detail/{cveId}/fixes
     * Return previously generated fix records for this CVE.
     */
    @GetMapping("/{cveId}/fixes")
    public ResponseEntity<List<FixRecordResponse>> getFixRecords(@PathVariable String cveId) {
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        return ResponseEntity.ok(fixRecordService.getFixRecords(tenant, cveId));
    }

    /**
     * GET /api/cve-detail/software-fixes?software={name}
     * Return all fix records for the tenant where softwareEntities contains the given software name.
     */
    @GetMapping("/software-fixes")
    public ResponseEntity<List<FixRecordResponse>> getFixRecordsBySoftware(
            @org.springframework.web.bind.annotation.RequestParam(required = false) String software) {
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        return ResponseEntity.ok(fixRecordService.getFixRecordsBySoftware(tenant, software));
    }

    /**
     * POST /api/cve-detail/{cveId}/generate-fixes
     * Generate (or regenerate) fix records for this CVE using references + OpenAI.
     */
    public record GenerateFixesRequest(
            java.util.List<GenerateFixesSoftwareEntry> additionalSoftware
    ) {}
    public record GenerateFixesSoftwareEntry(
            String name, String vendor, String version, int assetCount
    ) {}

    @PostMapping("/{cveId}/generate-fixes")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<List<FixRecordResponse>> generateFixRecords(
            @PathVariable String cveId,
            @org.springframework.web.bind.annotation.RequestBody(required = false) GenerateFixesRequest body
    ) {
        assertDemoAllowsAiAction();
        assertEntitled(TenantEntitlementService.AI_FIX_GENERATION,
                "AI fix generation is available on the Enterprise plan.");
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        java.util.List<GenerateFixesSoftwareEntry> extra = body != null && body.additionalSoftware() != null
                ? body.additionalSoftware() : java.util.List.of();
        return ResponseEntity.ok(fixRecordService.generateFixRecords(tenant, cveId, extra));
    }

    /**
     * POST /api/cve-detail/{cveId}/analyst-fixes
     * Save analyst-entered solution text as fix records (one per software row).
     * Replaces any previous ANALYST-sourced fix records for this CVE.
     */
    public record AnalystFixesRequest(
            java.util.List<FixRecordService.AnalystFixEntry> solutions
    ) {}

    @PostMapping("/{cveId}/analyst-fixes")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<List<FixRecordResponse>> saveAnalystFixes(
            @PathVariable String cveId,
            @RequestBody AnalystFixesRequest body) {
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        java.util.List<FixRecordService.AnalystFixEntry> solutions =
                body.solutions() != null ? body.solutions() : java.util.List.of();
        return ResponseEntity.ok(fixRecordService.saveAnalystFixes(tenant, cveId, solutions));
    }

    /**
     * GET /api/cve-detail/{cveId}/ai-solution
     * Return the previously saved AI remediation recommendation for this CVE.
     */
    @GetMapping("/{cveId}/ai-solution")
    public ResponseEntity<AiSolutionResponse> getSavedAiSolution(@PathVariable String cveId) {
        assertEntitled(TenantEntitlementService.AI_SOLUTION_GENERATION,
                "AI remediation recommendations are available on the Enterprise plan.");
        java.util.Optional<CveAiSolutionPersistenceService.SavedAiSolution> saved =
                aiSolutionPersistenceService.getSavedAiSolution(cveId);
        if (saved.isEmpty()) return ResponseEntity.notFound().build();
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(saved.get().contentJson(), Map.class);
            AiSolutionResponse r = new AiSolutionResponse();
            r.success = true;
            r.data = parsed;
            r.generatedAt = saved.get().generatedAt();
            return ResponseEntity.ok(r);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * POST /api/cve-detail/{cveId}/ai-solution
     * Generate and persist a comprehensive structured remediation recommendation using OpenAI.
     */
    @PostMapping("/{cveId}/ai-solution")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AiSolutionResponse> generateAiSolution(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> recommendationContext) {
        assertDemoAllowsAiAction();
        assertEntitled(TenantEntitlementService.AI_SOLUTION_GENERATION,
                "AI remediation recommendations are available on the Enterprise plan.");
        return ResponseEntity.ok(aiSolutionService.generate(cveId, recommendationContext));
    }

    /**
     * GET /api/cve-detail/{cveId}/ai-actions
     * Return previously persisted AI-generated required actions for this CVE.
     */
    @GetMapping("/{cveId}/ai-actions")
    public ResponseEntity<AiActionsResponse> getSavedAiActions(@PathVariable String cveId) {
        assertEntitled(TenantEntitlementService.AI_REQUIRED_ACTIONS,
                "AI required actions are available on the Enterprise plan.");
        return aiSolutionPersistenceService.getSavedAiActions(cveId)
                .map(saved -> {
                    try {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> parsed = objectMapper.readValue(saved.contentJson(), Map.class);
                        AiActionsResponse r = new AiActionsResponse();
                        r.success = true;
                        r.data = parsed;
                        r.generatedAt = saved.generatedAt();
                        return ResponseEntity.ok(r);
                    } catch (Exception e) {
                        return ResponseEntity.ok(new AiActionsResponse());
                    }
                })
                .orElseGet(() -> {
                    AiActionsResponse r = new AiActionsResponse();
                    r.success = false;
                    return ResponseEntity.ok(r);
                });
    }

    /**
     * POST /api/cve-detail/{cveId}/ai-actions
     * Generate top 3 prioritised analyst actions using OpenAI based on full CVE context.
     */
    @PostMapping("/{cveId}/ai-actions")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AiActionsResponse> generateAiActions(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> context) {
        assertDemoAllowsAiAction();
        assertEntitled(TenantEntitlementService.AI_REQUIRED_ACTIONS,
                "AI required actions are available on the Enterprise plan.");
        return ResponseEntity.ok(aiActionsService.generate(cveId, context));
    }

    // DTOs

    @Data
    public static class AiActionsResponse {
        public boolean success;
        public Map<String, Object> data;
        public String error;
        public Instant generatedAt;
    }

    private void assertDemoAllowsAiAction() {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsAiAction(workspaceService.getWorkspace());
        }
    }

    @Data
    public static class CveDetailResponse {
        public CveSummary summary;
        public KeySignals signals;
        public List<InvestigationDto> investigations;
        public List<AssessmentDto> assessments;
        public List<MatchedSoftwareDto> matchedSoftware;
        public List<VendorIntelligenceDto> vendorIntelligence;
        public List<CveReference> references;
        public List<FixRecordResponse> fixes;
        public java.util.UUID suppressedByRuleId;
        public String suppressedByRuleName;
        public List<com.prototype.vulnwatch.dto.VulnerabilityIntelSourceRecordResponse> sourceRecords;
        public List<com.prototype.vulnwatch.dto.VulnerabilityIntelRelationResponse> relations;
    }

    @Data
    public static class CveReference {
        public String url;
        public String source;
        public List<String> tags;
    }

    @Data
    public static class VendorIntelligenceDto {
        public String source;
        public String ecosystem;
        public String packageName;
        public String affectedVersions;
        public String fixedVersion;
        public String cpe;
        public String vexStatus;
    }

    @Data
    public static class CveSummary {
        public String externalId;
        public String title;
        public String description;
        public String severity;
        public Double cvssScore;
        public String cvssVector;
        public Double epssScore;
        public Double epssSevenDayDelta;
        /** BLG-016: when the EPSS score was last refreshed from the FIRST.org feed. */
        public Instant epssUpdatedAt;
        public String cweIds;
        public Instant publishedAt;
        public Instant modifiedAt;
        public VulnerabilitySource source;
        public Boolean inKev;
        public LocalDate kevDateAdded;
        public LocalDate kevDueDate;
        public String kevRequiredAction;
    }

    @Data
    public static class KeySignals {
        public boolean exploitAvailable;
        public String exploitReason;
        public boolean systemsImpacted;
        public long componentCount;
        public long softwareCount;
        public long assetCount;
        public boolean patchAvailable;
        public String patchVersions;
    }

    @Data
    public static class InvestigationDto {
        public Long id;
        public String cveId;
        public Investigation.InvestigationStatus status;
        public String assignedTo;
        public Investigation.InvestigationPriority priority;
        public String notes;
        public Instant createdAt;
        public Instant updatedAt;
    }

    @Data
    public static class AssessmentDto {
        public Long id;
        public String cveId;
        public ApplicabilityAssessment.AssessmentStatus status;
        public Boolean softwareDetected;
        public Boolean vulnerableVersionPresent;
        public Boolean vulnerableConfiguration;
        public ApplicabilityAssessment.AssessmentResult finalResult;
        public ApplicabilityAssessment.ConfidenceLevel confidenceLevel;
        public String justification;
        public String recommendedAction;
        public Instant createdAt;
        public Instant completedAt;
    }

    @Data
    public static class MatchedSoftwareDto {
        public UUID componentId;
        public UUID assetId;
        public String assetName;
        public String assetIdentifier;
        public String assetType;
        public String ecosystem;
        public String packageName;
        public String version;
        public ApplicabilityState applicabilityState;
        public String applicabilityReason;
        public String applicabilityReasonDetail;
        public ImpactState computedImpactState;
        public String computedImpactReason;
        public String computedImpactReasonDetail;
        public ImpactState impactState;
        public String impactReason;
        public String impactReasonDetail;
        public String vexStatus;
        public String vexProvider;
        public String vexFreshness;
        public String vexSource;
        public UUID matchedVexAssertionId;
        public String analystDisposition;
        public String analystReason;
        public String matchedBy;
        public boolean eligibleForFinding;
        public String findingEligibilityReason;
        public String findingEligibilityDetail;
        public String eolSlug;
        public String eolCycle;
        public java.time.LocalDate eolDate;
        public Boolean isEol;
        public Integer eolDaysRemaining;
        public java.time.LocalDate eolSupportEndDate;
        public String supportPhase;
        public String supportGroup;
        public UUID softwareIdentityId;
    }

    @Data
    public static class VexEvidenceResponse {
        public UUID componentId;
        public String assetName;
        public String assetIdentifier;
        public String assetType;
        public String ecosystem;
        public String installedVersion;
        public String matchedBy;
        public String applicabilityState;
        public String applicabilityReason;
        public String applicabilityReasonDetail;
        public UUID matchedVexAssertionId;
        public String sourceSystem;
        public String provider;
        public String status;
        public String trustTier;
        public String freshness;
        public String documentId;
        public String packageName;
        public String normalizedProductKey;
        public String versionExact;
        public String versionStart;
        public Boolean startInclusive;
        public String versionEnd;
        public Boolean endInclusive;
        public String fixedVersion;
        public Instant publishedAt;
        public Instant lastSeenAt;
        public String evidenceUrl;
        public String computedImpactState;
        public String computedImpactReason;
        public String computedImpactReasonDetail;
        public String impactState;
        public String impactReason;
        public String impactReasonDetail;
        public Map<String, Object> evidence;
    }

    @Data
    public static class CreateInvestigationRequest {
        public Investigation.InvestigationPriority priority;
    }

    @Data
    public static class CreateManualFindingRequest {
        public String justification;
        public List<String> componentIds;
        public Map<String, String> componentApplicabilityDecisions;
        public Map<String, String> componentAnalystDispositions;
        public String severity;
        public String dueDate;
        /** ASSET_CVE (default) or CVE_FIX */
        public String findingCreationMode;
        /** ADD_TO_EXISTING (default) or CREATE_NEW — only relevant for CVE_FIX mode */
        public String existingFindingBehavior;
    }

    @Data
    public static class ManualFindingResponse {
        public String cveId;
        public int eligibleComponentCount;
        public int createdCount;
        public int reopenedCount;
        public int alreadyOpenCount;
        public String message;
    }

    @Data
    public static class CompleteAssessmentRequest {
        public ApplicabilityAssessment.AssessmentResult result;
        public ApplicabilityAssessment.ConfidenceLevel confidence;
        public String justification;
        public String recommendedAction;
    }

    @Data
    public static class SuppressRequest {
        public String reason;
        public String justification;
        public Integer duration; // days
    }

    @Data
    public static class SuppressionResponse {
        public String cveId;
        public boolean suppressed;
        public String reason;
        public String suppressedBy;
        public Instant suppressedAt;
        public Instant expiresAt;
    }

    @Data
    public static class ExportRequest {
        public String format; // pdf, csv, json, excel
    }

    @Data
    public static class ExportResponse {
        public String cveId;
        public String format;
        public String content;
        public Instant generatedAt;
    }

    @Data
    public static class AiSolutionResponse {
        public boolean success;
        public String error;
        /** Plain-text fallback when JSON parsing fails or OpenAI unavailable. */
        public String recommendation;
        /** Structured JSON content from OpenAI JSON mode. */
        public Map<String, Object> data;
        /** Timestamp when this recommendation was generated/saved. */
        public Instant generatedAt;
    }

    // -------------------------------------------------------------------------
    // Investigation Runbook endpoints (Phase 2)
    // -------------------------------------------------------------------------

    /**
     * GET /api/cve-detail/{cveId}/investigation/runbook
     * Returns the persisted runbook state for the CVE, or an empty shell if none exists yet.
     */
    @GetMapping("/{cveId}/investigation/runbook")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<com.prototype.vulnwatch.dto.InvestigationRunbookResponse> getRunbook(
            @PathVariable String cveId) {
        return ResponseEntity.ok(investigationRunbookService.getRunbook(cveId));
    }

    /**
     * PUT /api/cve-detail/{cveId}/investigation/runbook
     * Idempotent upsert — replaces the full runbook state for the CVE.
     */
    @PutMapping("/{cveId}/investigation/runbook")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.investigation.runbook.saved")
    public ResponseEntity<com.prototype.vulnwatch.dto.InvestigationRunbookResponse> saveRunbook(
            @PathVariable String cveId,
            @RequestBody com.prototype.vulnwatch.dto.InvestigationRunbookRequest request) {
        return ResponseEntity.ok(investigationRunbookService.saveRunbook(cveId, request));
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation/log
     * Appends a single log entry to the runbook. Creates the runbook record if absent.
     */
    @PostMapping("/{cveId}/investigation/log")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cve_detail.investigation.log.added")
    public ResponseEntity<com.prototype.vulnwatch.dto.RunbookLogEntryResponse> appendLog(
            @PathVariable String cveId,
            @RequestBody com.prototype.vulnwatch.dto.RunbookLogEntryRequest request) {
        return ResponseEntity.ok(investigationRunbookService.appendLogEntry(cveId, request));
    }

    // -------------------------------------------------------------------------
    // Investigation analysis endpoints (Phase 3)
    // -------------------------------------------------------------------------

    /**
     * POST /api/cve-detail/{cveId}/investigation/resolve-inventory
     * Resolves asset criteria against the tenant software inventory.
     */
    @PostMapping("/{cveId}/investigation/resolve-inventory")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<com.prototype.vulnwatch.dto.InventoryResolutionResponse> resolveInventory(
            @PathVariable String cveId,
            @RequestBody com.prototype.vulnwatch.dto.InventoryResolutionRequest request) {
        return ResponseEntity.ok(
                inventoryResolutionService.resolveInventory(request.criteria()));
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation/false-positive-analysis
     * Checks VEX correlation data for false-positive signals per software/version.
     */
    @PostMapping("/{cveId}/investigation/false-positive-analysis")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<com.prototype.vulnwatch.dto.FalsePositiveAnalysisResponse> analyzeFalsePositives(
            @PathVariable String cveId,
            @RequestBody com.prototype.vulnwatch.dto.FalsePositiveAnalysisRequest request) {
        return ResponseEntity.ok(
                falsePositiveAnalysisService.analyzeFalsePositives(cveId, request.criteria()));
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation/eol-analysis
     * Returns EOL lifecycle status for each criterion matched against inventory.
     */
    @PostMapping("/{cveId}/investigation/eol-analysis")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<com.prototype.vulnwatch.dto.EolAnalysisResponse> analyzeEol(
            @PathVariable String cveId,
            @RequestBody com.prototype.vulnwatch.dto.EolAnalysisRequest request) {
        return ResponseEntity.ok(
                eolAnalysisService.analyzeEol(request.criteria()));
    }

    @PostMapping("/{cveId}/investigation/run-agent")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<com.prototype.vulnwatch.dto.AgentRunResponse> runAgent(
            @PathVariable String cveId,
            @RequestBody com.prototype.vulnwatch.dto.AgentRunRequest request) {
        assertDemoAllowsAiAction();
        assertEntitled(TenantEntitlementService.AI_INVESTIGATION_AGENT,
                "AI investigation agent workflows are available on the Enterprise plan.");
        return ResponseEntity.ok(investigationAgentService.runAgent(cveId, request));
    }

    private void assertEntitled(String entitlementKey, String message) {
        entitlementGuard.assertEnabled(workspaceService.getWorkspace(), entitlementKey, message);
    }
}
