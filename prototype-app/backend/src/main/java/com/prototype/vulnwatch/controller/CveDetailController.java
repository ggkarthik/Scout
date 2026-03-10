package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.ApplicabilityAssessmentService;
import com.prototype.vulnwatch.service.FindingService;
import com.prototype.vulnwatch.service.InvestigationService;
import com.prototype.vulnwatch.service.OrgCveRecordService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.util.CvssUtil;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Controller for CVE drill-down functionality
 */
@RestController
@RequestMapping("/api/cve-detail")
@RequiredArgsConstructor
@Slf4j
public class CveDetailController {

    private final VulnerabilityRepository vulnerabilityRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final InvestigationService investigationService;
    private final ApplicabilityAssessmentService assessmentService;
    private final FindingService findingService;
    private final OrgCveRecordService orgCveRecordService;
    private final TenantService tenantService;

    /**
     * GET /api/cve-detail/{cveId}
     * Get CVE detail with summary, key signals, and available actions
     */
    @GetMapping("/{cveId}")
    public ResponseEntity<CveDetailResponse> getCveDetail(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId) {

        log.info("Fetching CVE detail for {} (tenant {})", cveId, tenantId);
        Tenant tenant = tenantService.resolveTenant(tenantId);

        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));

        OrgCveRecord orgCveRecord = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElse(null);
        UUID matchedSoftwareTenantId = orgCveRecord != null
                && orgCveRecord.getTenant() != null
                && orgCveRecord.getTenant().getId() != null
                ? orgCveRecord.getTenant().getId()
                : tenant.getId();
        List<MatchedSoftwareDto> matchedSoftware = componentVulnerabilityStateRepository
                .findByTenant_IdAndVulnerability_Id(matchedSoftwareTenantId, vulnerability.getId()).stream()
                .filter(state -> state.getComponent() != null)
                .filter(state -> state.getComponent().getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .map(this::toMatchedSoftwareDto)
                .toList();

        CveDetailResponse response = new CveDetailResponse();

        // CVE Summary
        response.setSummary(buildSummary(vulnerability));

        // Fetch targets once — used by both signals and vendor intelligence
        List<VulnerabilityTarget> targets = vulnerabilityTargetRepository.findByVulnerability(vulnerability);

        // Key Signals
        response.setSignals(buildSignals(vulnerability, orgCveRecord, matchedSoftware, targets));
        response.setMatchedSoftware(matchedSoftware);
        response.setVendorIntelligence(buildVendorIntelligence(vulnerability, targets));

        // Related Records
        response.setInvestigations(investigationService.getInvestigationsByCve(tenantId, cveId).stream()
                .map(this::toInvestigationDto)
                .collect(Collectors.toList()));

        response.setAssessments(assessmentService.getAssessmentsByCve(tenantId, cveId).stream()
                .map(this::toAssessmentDto)
                .collect(Collectors.toList()));

        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation
     * Create a new investigation for this CVE
     */
    @PostMapping("/{cveId}/investigation")
    public ResponseEntity<InvestigationDto> createInvestigation(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestHeader("X-User-ID") String userId,
            @RequestBody CreateInvestigationRequest request) {

        log.info("Creating investigation for CVE {} by user {}", cveId, userId);

        Investigation investigation = investigationService.createInvestigation(
                tenantId, cveId, request.getPriority(), userId);

        return ResponseEntity.ok(toInvestigationDto(investigation));
    }

    /**
     * PUT /api/cve-detail/investigation/{investigationId}
     * Update an existing investigation
     */
    @PutMapping("/investigation/{investigationId}")
    public ResponseEntity<InvestigationDto> updateInvestigation(
            @PathVariable Long investigationId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestHeader("X-User-ID") String userId,
            @RequestBody InvestigationService.InvestigationUpdateRequest request) {

        log.info("Updating investigation {} by user {}", investigationId, userId);

        Investigation investigation = investigationService.updateInvestigation(
                tenantId, investigationId, request, userId);

        return ResponseEntity.ok(toInvestigationDto(investigation));
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation/submit
     * Create-or-update investigation in a single call (upsert semantics)
     */
    @PostMapping("/{cveId}/investigation/submit")
    public ResponseEntity<InvestigationDto> submitInvestigation(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestHeader("X-User-ID") String userId,
            @RequestBody InvestigationService.SubmitInvestigationRequest request) {

        log.info("Submitting investigation for CVE {} by user {}", cveId, userId);
        Investigation investigation = investigationService.submitInvestigation(tenantId, cveId, request, userId);
        return ResponseEntity.ok(toInvestigationDto(investigation));
    }

    /**
     * POST /api/cve-detail/{cveId}/assessment/submit
     * Create-or-update-and-complete assessment in a single call (upsert + complete)
     */
    @PostMapping("/{cveId}/assessment/submit")
    public ResponseEntity<AssessmentDto> submitAssessment(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestHeader("X-User-ID") String userId,
            @RequestBody ApplicabilityAssessmentService.SubmitAssessmentRequest request) {

        log.info("Submitting assessment for CVE {} by user {}", cveId, userId);
        ApplicabilityAssessment assessment = assessmentService.submitAssessment(tenantId, cveId, request, userId);
        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    /**
     * POST /api/cve-detail/{cveId}/applicability-assessment
     * Start applicability assessment wizard
     */
    @PostMapping("/{cveId}/applicability-assessment")
    public ResponseEntity<AssessmentDto> createAssessment(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestHeader("X-User-ID") String userId) {

        log.info("Creating applicability assessment for CVE {} by user {}", cveId, userId);

        ApplicabilityAssessment assessment = assessmentService.createAssessment(tenantId, cveId, userId);

        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    /**
     * PUT /api/cve-detail/applicability-assessment/{assessmentId}
     * Update assessment (step by step)
     */
    @PutMapping("/applicability-assessment/{assessmentId}")
    public ResponseEntity<AssessmentDto> updateAssessment(
            @PathVariable Long assessmentId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestBody ApplicabilityAssessmentService.AssessmentUpdateRequest request) {

        log.info("Updating assessment {}", assessmentId);

        ApplicabilityAssessment assessment = assessmentService.updateAssessment(tenantId, assessmentId, request);

        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    /**
     * POST /api/cve-detail/applicability-assessment/{assessmentId}/complete
     * Complete the assessment with final result
     */
    @PostMapping("/applicability-assessment/{assessmentId}/complete")
    public ResponseEntity<AssessmentDto> completeAssessment(
            @PathVariable Long assessmentId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestBody CompleteAssessmentRequest request) {

        log.info("Completing assessment {} with result {}", assessmentId, request.getResult());

        ApplicabilityAssessment assessment = assessmentService.completeAssessment(
                tenantId, assessmentId, request.getResult(), request.getConfidence(),
                request.getJustification(), request.getRecommendedAction());

        return ResponseEntity.ok(toAssessmentDto(assessment));
    }

    /**
     * POST /api/cve-detail/{cveId}/manual-finding
     * Create manual finding (add to backlog)
     */
    @PostMapping("/{cveId}/manual-finding")
    public ResponseEntity<ManualFindingResponse> createManualFinding(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestHeader("X-User-ID") String userId,
            @RequestBody CreateManualFindingRequest request) {

        log.info("Creating manual finding for CVE {} by user {}", cveId, userId);

        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));
        Tenant tenant = tenantService.resolveTenant(tenantId);

        FindingService.ManualFindingCreationResult result = findingService.createManualFindingsForVulnerability(
                tenant,
                vulnerability,
                request.getJustification(),
                userId,
                parseComponentIds(request.getComponentIds())
        );

        ManualFindingResponse response = new ManualFindingResponse();
        response.setCveId(cveId);
        response.setEligibleComponentCount(result.eligibleComponentCount());
        response.setCreatedCount(result.createdCount());
        response.setReopenedCount(result.reopenedCount());
        response.setAlreadyOpenCount(result.alreadyOpenCount());
        String message;
        if (result.createdCount() + result.reopenedCount() > 0) {
            message = "Manual finding workflow completed.";
        } else if (result.alreadyOpenCount() > 0) {
            message = "Findings already open for all selected components. No duplicates created.";
        } else {
            message = "No eligible components found. Ensure components are correlated and marked as impacted.";
        }
        response.setMessage(message);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/cve-detail/{cveId}/suppress
     * Suppress this CVE for the organization
     */
    @PostMapping("/{cveId}/suppress")
    public ResponseEntity<SuppressionResponse> suppressCve(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestHeader("X-User-ID") String userId,
            @RequestBody SuppressRequest request) {

        log.info("Suppressing CVE {} for tenant {} by user {}", cveId, tenantId, userId);
        Tenant tenant = tenantService.resolveTenant(tenantId);

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
                userId,
                suppressedAt,
                expiresAt
        );
        findingService.suppressFindingsForVulnerability(
                tenant,
                vulnerability,
                request.getReason(),
                request.getJustification(),
                userId,
                expiresAt
        );

        SuppressionResponse response = new SuppressionResponse();
        response.setCveId(cveId);
        response.setSuppressed(true);
        response.setReason(request.getReason());
        response.setSuppressedBy(userId);
        response.setSuppressedAt(suppressedAt);
        response.setExpiresAt(expiresAt);

        log.info("Suppressed CVE {} for {} days", cveId, request.getDuration());

        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/cve-detail/{cveId}/export
     * Export CVE report in various formats
     */
    @PostMapping("/{cveId}/export")
    public ResponseEntity<ExportResponse> exportCveReport(
            @PathVariable String cveId,
            @RequestHeader("X-Tenant-ID") Long tenantId,
            @RequestBody ExportRequest request) {

        log.info("Exporting CVE {} in format {}", cveId, request.getFormat());
        Tenant tenant = tenantService.resolveTenant(tenantId);

        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));

        OrgCveRecord orgCveRecord = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElse(null);

        // Generate report based on format
        String reportContent = generateReport(vulnerability, orgCveRecord, request.getFormat());

        ExportResponse response = new ExportResponse();
        response.setCveId(cveId);
        response.setFormat(request.getFormat());
        response.setContent(reportContent);
        response.setGeneratedAt(Instant.now());

        return ResponseEntity.ok(response);
    }

    // Helper methods

    private CveSummary buildSummary(Vulnerability vulnerability) {
        CveSummary summary = new CveSummary();
        summary.setExternalId(vulnerability.getExternalId());
        summary.setTitle(vulnerability.getTitle());
        summary.setDescription(vulnerability.getDescriptionSnippet());
        summary.setSeverity(vulnerability.getSeverity());
        summary.setCvssScore(vulnerability.getCvssScore());
        summary.setCvssVector(vulnerability.getCvssVector());
        summary.setEpssScore(vulnerability.getEpssScore());
        summary.setCweIds(vulnerability.getCweIds());
        summary.setPublishedAt(vulnerability.getPublishedAt());
        summary.setModifiedAt(vulnerability.getModifiedAt());
        summary.setSource(vulnerability.getSource());
        summary.setInKev(vulnerability.getInKev());
        return summary;
    }

    private KeySignals buildSignals(
            Vulnerability vulnerability,
            OrgCveRecord orgCveRecord,
            List<MatchedSoftwareDto> matchedSoftware,
            List<VulnerabilityTarget> targets
    ) {
        KeySignals signals = new KeySignals();

        // Signal 1: Exploit Available
        boolean exploitAvailable = vulnerability.getInKev() ||
                (vulnerability.getEpssScore() != null && vulnerability.getEpssScore() > 0.7);
        signals.setExploitAvailable(exploitAvailable);
        signals.setExploitReason(exploitAvailable ?
                (vulnerability.getInKev() ? "In CISA KEV Catalog" :
                        "High EPSS Score (" + String.format("%.1f%%", vulnerability.getEpssScore() * 100) + ")") :
                "No known exploits");

        // Signal 2: Systems Impacted
        if (orgCveRecord != null) {
            signals.setSystemsImpacted(true);
            signals.setComponentCount(orgCveRecord.getMatchedComponentCount());
            signals.setSoftwareCount(orgCveRecord.getMatchedSoftwareCount());
            signals.setAssetCount(matchedSoftware.stream()
                    .map(MatchedSoftwareDto::getAssetId)
                    .filter(java.util.Objects::nonNull)
                    .distinct()
                    .count());
        } else {
            signals.setSystemsImpacted(false);
            signals.setComponentCount(0L);
            signals.setSoftwareCount(0L);
            signals.setAssetCount(0L);
        }

        // Signal 3: Patch Available
        boolean patchAvailable = targets.stream().anyMatch(t -> t.getFixedVersion() != null);
        signals.setPatchAvailable(patchAvailable);
        if (patchAvailable) {
            signals.setPatchVersions(targets.stream()
                    .filter(t -> t.getFixedVersion() != null)
                    .map(VulnerabilityTarget::getFixedVersion)
                    .distinct()
                    .collect(Collectors.joining(", ")));
        }

        return signals;
    }

    private List<VendorIntelligenceDto> buildVendorIntelligence(Vulnerability vulnerability, List<VulnerabilityTarget> targets) {
        List<VendorIntelligenceDto> rows = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        for (VulnerabilityTarget t : targets) {
            VendorIntelligenceDto dto = new VendorIntelligenceDto();

            String src = (t.getSource() == null || t.getSource().isBlank() || "unknown".equalsIgnoreCase(t.getSource()))
                    ? (vulnerability.getSource() != null ? vulnerability.getSource().name() : "ADVISORY")
                    : t.getSource().toUpperCase();
            dto.setSource(src);
            dto.setEcosystem(t.getEcosystem());
            dto.setPackageName(t.getPackageName());

            String affectedVersions = formatVersionRange(t);
            dto.setAffectedVersions(affectedVersions);
            dto.setFixedVersion(t.getFixed() != null && !t.getFixed().isBlank() ? t.getFixed() : null);
            dto.setCpe(t.getCpe() != null && !t.getCpe().isBlank() ? t.getCpe() : null);
            dto.setVexStatus(parseVexStatus(t.getQualifiersJson()));

            String dedupeKey = src + "|" + nullToEmpty(t.getPackageName()) + "|" + affectedVersions + "|" + nullToEmpty(t.getFixed());
            if (seen.add(dedupeKey)) {
                rows.add(dto);
            }
        }
        return rows;
    }

    private String formatVersionRange(VulnerabilityTarget t) {
        if (t.getVersionExact() != null && !t.getVersionExact().isBlank()) {
            return t.getVersionExact();
        }
        StringBuilder sb = new StringBuilder();
        if (t.getIntroduced() != null && !t.getIntroduced().isBlank()) {
            sb.append(">= ").append(t.getIntroduced());
        } else if (t.getVersionStart() != null && !t.getVersionStart().isBlank()) {
            Boolean inc = t.getStartInclusive();
            sb.append(inc == null || inc ? ">= " : "> ").append(t.getVersionStart());
        }
        if (t.getFixed() != null && !t.getFixed().isBlank()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append("< ").append(t.getFixed());
        } else if (t.getVersionEnd() != null && !t.getVersionEnd().isBlank()) {
            if (sb.length() > 0) sb.append(", ");
            Boolean inc = t.getEndInclusive();
            sb.append(inc != null && inc ? "<= " : "< ").append(t.getVersionEnd());
        }
        return sb.length() > 0 ? sb.toString() : "All versions";
    }

    private String parseVexStatus(String qualifiersJson) {
        if (qualifiersJson == null || qualifiersJson.isBlank()) return null;
        try {
            int idx = qualifiersJson.indexOf("\"vexStatus\"");
            if (idx < 0) return null;
            int colon = qualifiersJson.indexOf(':', idx);
            if (colon < 0) return null;
            int start = qualifiersJson.indexOf('"', colon + 1);
            if (start < 0) return null;
            int end = qualifiersJson.indexOf('"', start + 1);
            if (end < 0) return null;
            String val = qualifiersJson.substring(start + 1, end).trim();
            return val.isBlank() ? null : val;
        } catch (Exception e) {
            return null;
        }
    }

    private String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private InvestigationDto toInvestigationDto(Investigation investigation) {
        InvestigationDto dto = new InvestigationDto();
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

    private AssessmentDto toAssessmentDto(ApplicabilityAssessment assessment) {
        AssessmentDto dto = new AssessmentDto();
        dto.setId(assessment.getId());
        dto.setCveId(assessment.getVulnerability().getExternalId());
        dto.setStatus(assessment.getStatus());
        dto.setSoftwareDetected(assessment.getSoftwareDetected());
        dto.setVulnerableVersionPresent(assessment.getVulnerableVersionPresent());
        dto.setVulnerableConfiguration(assessment.getVulnerableConfiguration());
        dto.setFinalResult(assessment.getFinalResult());
        dto.setConfidenceLevel(assessment.getConfidenceLevel());
        dto.setCreatedAt(assessment.getCreatedAt());
        dto.setCompletedAt(assessment.getCompletedAt());
        return dto;
    }

    private FindingDto toFindingDto(Finding finding) {
        FindingDto dto = new FindingDto();
        dto.setId(finding.getId());
        dto.setCveId(finding.getVulnerability().getExternalId());
        dto.setTitle(finding.getVulnerability().getTitle());
        dto.setState(finding.getDecisionState());
        dto.setStatus(finding.getStatus());
        dto.setSeverity(finding.getVulnerability().getSeverity());
        dto.setCreatedAt(finding.getCreatedAt());
        return dto;
    }

    private MatchedSoftwareDto toMatchedSoftwareDto(ComponentVulnerabilityState state) {
        MatchedSoftwareDto dto = new MatchedSoftwareDto();
        dto.setComponentId(state.getComponent().getId());
        dto.setAssetId(state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getId());
        dto.setAssetName(state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getName());
        dto.setAssetIdentifier(state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getIdentifier());
        dto.setEcosystem(state.getComponent().getEcosystem());
        dto.setPackageName(state.getComponent().getPackageName());
        dto.setVersion(state.getComponent().getVersion());
        dto.setApplicabilityState(state.getApplicabilityState());
        dto.setImpactState(state.getImpactState());
        dto.setMatchedBy(state.getMatchedBy());
        dto.setEligibleForFinding(state.isEligibleForFinding());
        return dto;
    }

    private String generateReport(Vulnerability vulnerability, OrgCveRecord orgCveRecord, String format) {
        // Simple report generation
        StringBuilder report = new StringBuilder();

        if ("json".equalsIgnoreCase(format)) {
            report.append("{\n");
            report.append("  \"cveId\": \"").append(vulnerability.getExternalId()).append("\",\n");
            report.append("  \"severity\": \"").append(vulnerability.getSeverity()).append("\",\n");
            report.append("  \"cvssScore\": ").append(vulnerability.getCvssScore()).append(",\n");
            report.append("  \"description\": \"").append(vulnerability.getDescriptionSnippet()).append("\"\n");
            report.append("}");
        } else {
            // Plain text format
            report.append("CVE Report: ").append(vulnerability.getExternalId()).append("\n\n");
            report.append("Severity: ").append(vulnerability.getSeverity()).append("\n");
            report.append("CVSS Score: ").append(vulnerability.getCvssScore()).append("\n");
            report.append("Description: ").append(vulnerability.getDescriptionSnippet()).append("\n");
        }

        return report.toString();
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
        private String cweIds;
        private Instant publishedAt;
        private Instant modifiedAt;
        private VulnerabilitySource source;
        private Boolean inKev;
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
        private Instant createdAt;
        private Instant completedAt;
    }

    @Data
    public static class FindingDto {
        private UUID id;
        private String cveId;
        private String title;
        private FindingDecisionState state;
        private FindingStatus status;
        private String severity;
        private Instant createdAt;
    }

    @Data
    public static class MatchedSoftwareDto {
        private UUID componentId;
        private UUID assetId;
        private String assetName;
        private String assetIdentifier;
        private String ecosystem;
        private String packageName;
        private String version;
        private ApplicabilityState applicabilityState;
        private ImpactState impactState;
        private String matchedBy;
        private boolean eligibleForFinding;
    }

    @Data
    public static class CreateInvestigationRequest {
        private Investigation.InvestigationPriority priority;
    }

    @Data
    public static class CreateManualFindingRequest {
        private String title;
        private FindingStatus status;
        private String justification;
        private List<String> componentIds;
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
        private Boolean requiresApproval;
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

    private Instant resolveSuppressedUntil(Integer durationDays, Instant suppressedAt) {
        if (durationDays == null || durationDays <= 0) {
            return null;
        }
        return suppressedAt.plusSeconds(durationDays.longValue() * 86400L);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private Set<UUID> parseComponentIds(List<String> componentIds) {
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
}
