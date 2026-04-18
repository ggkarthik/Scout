package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.controller.CveDetailController;
import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VexAssertion;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityIntelObservation;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class CveDetailQueryFacade {

    private static final double HIGH_EPSS_EXPLOIT_THRESHOLD = 0.7;

    private final VulnerabilityRepository vulnerabilityRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final VexAssertionRepository vexAssertionRepository;
    private final VulnerabilityIntelObservationRepository observationRepository;
    private final InvestigationService investigationService;
    private final ApplicabilityAssessmentService assessmentService;
    private final RequestActorService requestActorService;
    private final TenantService tenantService;
    private final VulnerabilityIntelQueryService vulnerabilityIntelQueryService;
    private final EpssTrendService epssTrendService;
    private final ObjectMapper objectMapper;

    public CveDetailQueryFacade(
            VulnerabilityRepository vulnerabilityRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            VexAssertionRepository vexAssertionRepository,
            VulnerabilityIntelObservationRepository observationRepository,
            InvestigationService investigationService,
            ApplicabilityAssessmentService assessmentService,
            RequestActorService requestActorService,
            TenantService tenantService,
            VulnerabilityIntelQueryService vulnerabilityIntelQueryService,
            EpssTrendService epssTrendService,
            ObjectMapper objectMapper
    ) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.vexAssertionRepository = vexAssertionRepository;
        this.observationRepository = observationRepository;
        this.investigationService = investigationService;
        this.assessmentService = assessmentService;
        this.requestActorService = requestActorService;
        this.tenantService = tenantService;
        this.vulnerabilityIntelQueryService = vulnerabilityIntelQueryService;
        this.epssTrendService = epssTrendService;
        this.objectMapper = objectMapper;
    }

    public ResponseEntity<CveDetailController.CveDetailResponse> getCveDetail(String cveId) {
        RequestActor actor = requestActorService.currentActor();
        UUID tenantId = actor.tenantId();
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);

        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));

        OrgCveRecord orgCveRecord = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElse(null);
        UUID matchedSoftwareTenantId = orgCveRecord != null
                && orgCveRecord.getTenant() != null
                && orgCveRecord.getTenant().getId() != null
                ? orgCveRecord.getTenant().getId()
                : tenant.getId();
        List<CveDetailController.MatchedSoftwareDto> matchedSoftware = componentVulnerabilityStateRepository
                .findByTenant_IdAndVulnerability_Id(matchedSoftwareTenantId, vulnerability.getId()).stream()
                .filter(state -> state.getComponent() != null)
                .filter(state -> state.getComponent().getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .map(this::toMatchedSoftwareDto)
                .toList();

        CveDetailController.CveDetailResponse response = new CveDetailController.CveDetailResponse();
        response.setSummary(buildSummary(vulnerability));

        List<VulnerabilityTarget> targets = vulnerabilityTargetRepository.findByVulnerability(vulnerability);
        response.setSignals(buildSignals(vulnerability, orgCveRecord, matchedSoftware, targets));
        response.setMatchedSoftware(matchedSoftware);
        response.setVendorIntelligence(buildVendorIntelligence(vulnerability, targets));
        response.setReferences(buildReferences(vulnerability));
        response.setInvestigations(investigationService.getInvestigationsByCve(tenantId, cveId).stream()
                .map(this::toInvestigationDto)
                .collect(Collectors.toList()));
        response.setAssessments(assessmentService.getAssessmentsByCve(tenantId, cveId).stream()
                .map(this::toAssessmentDto)
                .collect(Collectors.toList()));
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<CveDetailController.VexEvidenceResponse> getVexEvidence(String cveId, UUID componentId) {
        Tenant tenant = requestTenant();
        ComponentVulnerabilityState state = componentVulnerabilityStateRepository
                .findByTenant_IdAndVulnerability_ExternalIdAndComponent_Id(tenant.getId(), cveId, componentId)
                .orElse(null);
        if (state == null || state.getMatchedVexAssertionId() == null) {
            return ResponseEntity.notFound().build();
        }

        VexAssertion assertion = vexAssertionRepository.findById(state.getMatchedVexAssertionId())
                .filter(candidate -> candidate.getVulnerability() != null)
                .filter(candidate -> Objects.equals(candidate.getVulnerability().getExternalId(), cveId))
                .orElse(null);
        if (assertion == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(toVexEvidenceResponse(state, assertion));
    }

    public ResponseEntity<CveDetailController.ExportResponse> exportCveReport(
            String cveId,
            CveDetailController.ExportRequest request
    ) {
        Tenant tenant = requestTenant();
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));
        OrgCveRecord orgCveRecord = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElse(null);

        CveDetailController.ExportResponse response = new CveDetailController.ExportResponse();
        response.setCveId(cveId);
        response.setFormat(request.getFormat());
        response.setContent(generateReport(vulnerability, orgCveRecord, request.getFormat()));
        response.setGeneratedAt(Instant.now());
        return ResponseEntity.ok(response);
    }

    private Tenant requestTenant() {
        return tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
    }

    private CveDetailController.CveSummary buildSummary(Vulnerability vulnerability) {
        CveDetailController.CveSummary summary = new CveDetailController.CveSummary();
        String description = vulnerabilityIntelQueryService.resolveDetailDescription(vulnerability);
        summary.setExternalId(vulnerability.getExternalId());
        summary.setTitle(vulnerability.getTitle());
        summary.setDescription(description);
        summary.setSeverity(vulnerability.getSeverity());
        summary.setCvssScore(vulnerability.getCvssScore());
        summary.setCvssVector(vulnerability.getCvssVector());
        summary.setEpssScore(vulnerability.getEpssScore());
        summary.setEpssSevenDayDelta(
                epssTrendService.fetchSevenDayDelta(
                        vulnerability.getExternalId(),
                        vulnerability.getEpssScore(),
                        vulnerability.getEpssUpdatedAt()
                )
        );
        summary.setEpssUpdatedAt(vulnerability.getEpssUpdatedAt());
        summary.setCweIds(vulnerability.getCweIds());
        summary.setSource(vulnerability.getSource());
        summary.setInKev(vulnerability.getInKev());

        // Fetch all observations once to fill gaps in canonical fields
        List<VulnerabilityIntelObservation> observations =
                observationRepository.findByVulnerabilityOrderByLastSeenAtDesc(vulnerability);

        // NVD observation for publishedAt / modifiedAt / references
        VulnerabilityIntelObservation nvdObs = observations.stream()
                .filter(o -> "nvd".equalsIgnoreCase(o.getSourceSystem()))
                .findFirst().orElse(null);

        Instant publishedAt = vulnerability.getPublishedAt() != null
                ? vulnerability.getPublishedAt()
                : (nvdObs != null ? nvdObs.getPublishedAt() : null);
        summary.setPublishedAt(publishedAt);

        // Only use modifiedAt/publishedAt from actual NVD source dates — never from fallback sync timestamps.
        // If no NVD observation exists, these fields remain null so the UI doesn't show misleading dates.
        Instant modifiedAt = nvdObs != null ? nvdObs.getLastModifiedAt() : null;
        if (modifiedAt == null && vulnerability.getModifiedAt() != null && nvdObs != null) {
            // NVD obs exists but its lastModifiedAt is null — use what the entity has
            modifiedAt = vulnerability.getModifiedAt();
        }
        summary.setModifiedAt(modifiedAt);

        // KEV dates: prefer entity fields; fall back to raw payload parsing for legacy records
        LocalDate kevDateAdded = vulnerability.getKevDateAdded();
        LocalDate kevDueDate = vulnerability.getKevDueDate();
        String kevRequiredAction = vulnerability.getKevRequiredAction();

        if (Boolean.TRUE.equals(vulnerability.getInKev()) && (kevDateAdded == null || kevDueDate == null)) {
            VulnerabilityIntelObservation kevObs = observations.stream()
                    .filter(o -> "kev".equalsIgnoreCase(o.getSourceSystem()))
                    .findFirst().orElse(null);
            if (kevObs != null && kevObs.getRawPayload() != null) {
                try {
                    com.fasterxml.jackson.databind.JsonNode kev = objectMapper.readTree(kevObs.getRawPayload());
                    if (kevDateAdded == null) {
                        kevDateAdded = parseLocalDateOrNull(kev.path("dateAdded").asText(""));
                    }
                    if (kevDueDate == null) {
                        kevDueDate = parseLocalDateOrNull(kev.path("dueDate").asText(""));
                    }
                    if (kevRequiredAction == null) {
                        String ra = kev.path("requiredAction").asText(null);
                        if (ra != null && !ra.isBlank()) {
                            kevRequiredAction = ra.trim();
                        }
                    }
                } catch (Exception ignored) { /* raw payload unparseable */ }
            }
        }
        summary.setKevDateAdded(kevDateAdded);
        summary.setKevDueDate(kevDueDate);
        summary.setKevRequiredAction(kevRequiredAction);
        return summary;
    }

    private LocalDate parseLocalDateOrNull(String text) {
        if (text == null || text.isBlank()) return null;
        try {
            return LocalDate.parse(text.trim());
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }

    List<CveDetailController.CveReference> buildReferences(Vulnerability vulnerability) {
        String json = vulnerability.getReferencesJson();
        // Fall back to NVD observation's referencesJson if Vulnerability has none
        if (json == null || json.isBlank()) {
            json = observationRepository.findByVulnerabilityOrderByLastSeenAtDesc(vulnerability).stream()
                    .filter(o -> "nvd".equalsIgnoreCase(o.getSourceSystem()))
                    .map(VulnerabilityIntelObservation::getReferencesJson)
                    .filter(r -> r != null && !r.isBlank())
                    .findFirst().orElse(null);
        }
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            // Try parsing as array of objects {url, source, tags}
            List<Map<String, Object>> raw = objectMapper.readValue(json, new TypeReference<>() {});
            return raw.stream()
                    .filter(m -> m.get("url") instanceof String)
                    .map(m -> {
                        CveDetailController.CveReference ref = new CveDetailController.CveReference();
                        ref.setUrl((String) m.get("url"));
                        if (m.get("source") instanceof String s) {
                            ref.setSource(s);
                        }
                        Object tagsObj = m.get("tags");
                        if (tagsObj instanceof List<?> tagList) {
                            ref.setTags(tagList.stream()
                                    .filter(t -> t instanceof String)
                                    .map(t -> (String) t)
                                    .toList());
                        }
                        return ref;
                    })
                    .toList();
        } catch (Exception e) {
            // Fallback: old format was array of plain URL strings
            try {
                List<String> urls = objectMapper.readValue(json, new TypeReference<>() {});
                return urls.stream()
                        .filter(u -> u != null && !u.isBlank())
                        .map(u -> {
                            CveDetailController.CveReference ref = new CveDetailController.CveReference();
                            ref.setUrl(u);
                            return ref;
                        })
                        .toList();
            } catch (Exception ignored) {
                return List.of();
            }
        }
    }

    private CveDetailController.KeySignals buildSignals(
            Vulnerability vulnerability,
            OrgCveRecord orgCveRecord,
            List<CveDetailController.MatchedSoftwareDto> matchedSoftware,
            List<VulnerabilityTarget> targets
    ) {
        CveDetailController.KeySignals signals = new CveDetailController.KeySignals();
        boolean exploitAvailable = vulnerability.getInKev()
                || (vulnerability.getEpssScore() != null && vulnerability.getEpssScore() > HIGH_EPSS_EXPLOIT_THRESHOLD);
        signals.setExploitAvailable(exploitAvailable);
        signals.setExploitReason(exploitAvailable
                ? (vulnerability.getInKev()
                        ? "In CISA KEV Catalog"
                        : "High EPSS Score (" + String.format("%.1f%%", vulnerability.getEpssScore() * 100) + ")")
                : "No known exploits");

        if (orgCveRecord != null) {
            signals.setSystemsImpacted(true);
            signals.setComponentCount(orgCveRecord.getMatchedComponentCount());
            signals.setSoftwareCount(orgCveRecord.getMatchedSoftwareCount());
            signals.setAssetCount(matchedSoftware.stream()
                    .map(CveDetailController.MatchedSoftwareDto::getAssetId)
                    .filter(Objects::nonNull)
                    .distinct()
                    .count());
        } else {
            signals.setSystemsImpacted(false);
            signals.setComponentCount(0L);
            signals.setSoftwareCount(0L);
            signals.setAssetCount(0L);
        }

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

    private List<CveDetailController.VendorIntelligenceDto> buildVendorIntelligence(
            Vulnerability vulnerability,
            List<VulnerabilityTarget> targets
    ) {
        List<CveDetailController.VendorIntelligenceDto> rows = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        Map<UUID, String> vexStatusByTargetId = mapVexStatusByTargetId(targets);
        for (VulnerabilityTarget target : targets) {
            CveDetailController.VendorIntelligenceDto dto = new CveDetailController.VendorIntelligenceDto();
            String source = (target.getSource() == null || target.getSource().isBlank() || "unknown".equalsIgnoreCase(target.getSource()))
                    ? (vulnerability.getSource() != null ? vulnerability.getSource().name() : VulnerabilitySource.ADVISORY.name())
                    : target.getSource().toUpperCase();
            dto.setSource(source);
            dto.setEcosystem(target.getEcosystem());
            dto.setPackageName(target.getPackageName());
            String affectedVersions = formatVersionRange(target);
            dto.setAffectedVersions(affectedVersions);
            dto.setFixedVersion(target.getFixed() != null && !target.getFixed().isBlank() ? target.getFixed() : null);
            dto.setCpe(target.getCpe() != null && !target.getCpe().isBlank() ? target.getCpe() : null);
            dto.setVexStatus(vexStatusByTargetId.get(target.getId()));
            String dedupeKey = source + "|" + nullToEmpty(target.getPackageName()) + "|" + affectedVersions + "|" + nullToEmpty(target.getFixed());
            if (seen.add(dedupeKey)) {
                rows.add(dto);
            }
        }
        return rows;
    }

    private String formatVersionRange(VulnerabilityTarget target) {
        if (target.getVersionExact() != null && !target.getVersionExact().isBlank()) {
            return target.getVersionExact();
        }
        StringBuilder sb = new StringBuilder();
        if (target.getIntroduced() != null && !target.getIntroduced().isBlank()) {
            sb.append(">= ").append(target.getIntroduced());
        } else if (target.getVersionStart() != null && !target.getVersionStart().isBlank()) {
            Boolean inclusive = target.getStartInclusive();
            sb.append(inclusive == null || inclusive ? ">= " : "> ").append(target.getVersionStart());
        }
        if (target.getFixed() != null && !target.getFixed().isBlank()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("< ").append(target.getFixed());
        } else if (target.getVersionEnd() != null && !target.getVersionEnd().isBlank()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            Boolean inclusive = target.getEndInclusive();
            sb.append(inclusive != null && inclusive ? "<= " : "< ").append(target.getVersionEnd());
        }
        return sb.length() > 0 ? sb.toString() : "All versions";
    }

    private Map<UUID, String> mapVexStatusByTargetId(List<VulnerabilityTarget> targets) {
        if (targets == null || targets.isEmpty()) {
            return Map.of();
        }
        List<UUID> targetIds = targets.stream()
                .map(VulnerabilityTarget::getId)
                .filter(Objects::nonNull)
                .toList();
        if (targetIds.isEmpty()) {
            return Map.of();
        }
        return vexAssertionRepository.findByTarget_IdIn(targetIds).stream()
                .filter(assertion -> assertion.getTarget() != null && assertion.getTarget().getId() != null)
                .collect(Collectors.toMap(
                        assertion -> assertion.getTarget().getId(),
                        VexAssertion::getStatus,
                        this::preferNonBlank
                ));
    }

    private CveDetailController.VexEvidenceResponse toVexEvidenceResponse(ComponentVulnerabilityState state, VexAssertion assertion) {
        Map<String, Object> evidence = parseEvidenceJson(assertion.getEvidenceJson());
        CveDetailController.VexEvidenceResponse response = new CveDetailController.VexEvidenceResponse();
        response.setComponentId(state.getComponent() == null ? null : state.getComponent().getId());
        response.setAssetName(state.getComponent() != null && state.getComponent().getAsset() != null
                ? state.getComponent().getAsset().getName()
                : null);
        response.setAssetIdentifier(state.getComponent() != null && state.getComponent().getAsset() != null
                ? state.getComponent().getAsset().getIdentifier()
                : null);
        response.setAssetType(state.getComponent() != null
                && state.getComponent().getAsset() != null
                && state.getComponent().getAsset().getType() != null
                ? state.getComponent().getAsset().getType().name()
                : null);
        response.setEcosystem(state.getComponent() == null ? null : state.getComponent().getEcosystem());
        response.setInstalledVersion(state.getComponent() == null ? null : state.getComponent().getVersion());
        response.setMatchedBy(state.getMatchedBy());
        response.setApplicabilityState(state.getApplicabilityState() == null ? null : state.getApplicabilityState().name());
        response.setApplicabilityReason(state.getApplicabilityReason());
        response.setApplicabilityReasonDetail(state.getApplicabilityReasonDetail());
        response.setMatchedVexAssertionId(assertion.getId());
        response.setSourceSystem(assertion.getSourceSystem());
        response.setProvider(assertion.getProvider());
        response.setStatus(assertion.getStatus());
        response.setTrustTier(assertion.getTrustTier());
        response.setFreshness(assertion.getFreshness());
        response.setDocumentId(assertion.getDocumentId());
        response.setPackageName(assertion.getPackageName());
        response.setNormalizedProductKey(assertion.getNormalizedProductKey());
        response.setVersionExact(assertion.getVersionExact());
        response.setVersionStart(assertion.getVersionStart());
        response.setStartInclusive(assertion.getStartInclusive());
        response.setVersionEnd(assertion.getVersionEnd());
        response.setEndInclusive(assertion.getEndInclusive());
        response.setFixedVersion(assertion.getFixedVersion());
        response.setPublishedAt(assertion.getPublishedAt());
        response.setLastSeenAt(assertion.getLastSeenAt());
        response.setEvidenceUrl(extractEvidenceUrl(evidence));
        response.setComputedImpactState(state.getImpactState() == null ? null : state.getImpactState().name());
        response.setComputedImpactReason(state.getImpactReason());
        response.setComputedImpactReasonDetail(state.getImpactReasonDetail());
        if (state.getAnalystDisposition() != null) {
            response.setImpactState(state.getAnalystDisposition().name());
            response.setImpactReason(state.getAnalystReason());
            response.setImpactReasonDetail("Analyst override");
        } else {
            response.setImpactState(state.getImpactState() == null ? null : state.getImpactState().name());
            response.setImpactReason(state.getImpactReason());
            response.setImpactReasonDetail(state.getImpactReasonDetail());
        }
        response.setEvidence(evidence);
        return response;
    }

    private Map<String, Object> parseEvidenceJson(String evidenceJson) {
        if (evidenceJson == null || evidenceJson.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(evidenceJson, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ignored) {
            return Map.of("raw", evidenceJson);
        }
    }

    private String extractEvidenceUrl(Map<String, Object> evidence) {
        if (evidence == null || evidence.isEmpty()) {
            return null;
        }
        for (String key : List.of("advisoryUrl", "documentUrl", "url", "referenceUrl")) {
            Object value = evidence.get(key);
            if (value instanceof String text && !text.isBlank()) {
                return text;
            }
        }
        return null;
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

    private CveDetailController.MatchedSoftwareDto toMatchedSoftwareDto(ComponentVulnerabilityState state) {
        CveDetailController.MatchedSoftwareDto dto = new CveDetailController.MatchedSoftwareDto();
        dto.setComponentId(state.getComponent().getId());
        dto.setAssetId(state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getId());
        dto.setAssetName(state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getName());
        dto.setAssetIdentifier(state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getIdentifier());
        dto.setAssetType(state.getComponent().getAsset() != null && state.getComponent().getAsset().getType() != null
                ? state.getComponent().getAsset().getType().name()
                : null);
        dto.setEcosystem(state.getComponent().getEcosystem());
        dto.setPackageName(state.getComponent().getPackageName());
        dto.setVersion(state.getComponent().getVersion());
        dto.setApplicabilityState(state.getApplicabilityState());
        dto.setApplicabilityReason(state.getApplicabilityReason());
        dto.setApplicabilityReasonDetail(state.getApplicabilityReasonDetail());
        dto.setComputedImpactState(state.getImpactState());
        dto.setComputedImpactReason(state.getImpactReason());
        dto.setComputedImpactReasonDetail(state.getImpactReasonDetail());
        if (state.getAnalystDisposition() != null) {
            dto.setImpactState(ImpactState.valueOf(state.getAnalystDisposition().name()));
            dto.setImpactReason(state.getAnalystReason());
            dto.setImpactReasonDetail("Analyst override");
        } else {
            dto.setImpactState(state.getImpactState());
            dto.setImpactReason(state.getImpactReason());
            dto.setImpactReasonDetail(state.getImpactReasonDetail());
        }
        dto.setVexStatus(state.getVexStatus());
        dto.setVexProvider(state.getVexProvider());
        dto.setVexFreshness(state.getVexFreshness());
        dto.setVexSource(state.getVexSource());
        dto.setMatchedVexAssertionId(state.getMatchedVexAssertionId());
        dto.setAnalystDisposition(state.getAnalystDisposition() == null ? null : state.getAnalystDisposition().name());
        dto.setAnalystReason(state.getAnalystReason());
        dto.setMatchedBy(state.getMatchedBy());
        dto.setEligibleForFinding(state.isEligibleForFinding());
        dto.setFindingEligibilityReason(resolveFindingEligibilityReason(state));
        dto.setFindingEligibilityDetail(resolveFindingEligibilityDetail(state));
        dto.setEolSlug(state.getComponent().getEolSlug());
        dto.setEolCycle(state.getComponent().getEolCycle());
        LocalDate eolDate = state.getComponent().getEolDate();
        boolean effectiveEol = Boolean.TRUE.equals(state.getComponent().getIsEol())
                || (eolDate != null && !LocalDate.now().isBefore(eolDate));
        dto.setEolDate(eolDate);
        dto.setIsEol(effectiveEol);
        if (eolDate != null && !effectiveEol) {
            int daysRemaining = (int) ChronoUnit.DAYS.between(LocalDate.now(), eolDate);
            if (daysRemaining >= 0) {
                dto.setEolDaysRemaining(daysRemaining);
            }
        }
        dto.setEolSupportEndDate(state.getComponent().getEolSupportEndDate());
        dto.setSupportPhase(state.getComponent().getSupportPhase());
        return dto;
    }

    private String resolveFindingEligibilityReason(ComponentVulnerabilityState state) {
        if (state.isEligibleForFinding()) {
            return state.getImpactState() == ImpactState.NO_PATCH ? "exact_vex_no_patch" : "exact_vex_affected";
        }
        if (state.getApplicabilityState() != ApplicabilityState.APPLICABLE) {
            return "not_applicable";
        }
        return switch (state.getImpactState() == null ? ImpactState.UNKNOWN : state.getImpactState()) {
            case FIXED -> "vex_fixed";
            case NOT_IMPACTED -> "vex_not_affected";
            case UNDER_INVESTIGATION -> "vex_under_investigation";
            case UNKNOWN -> "awaiting_vex_assessment";
            default -> "not_finding_eligible";
        };
    }

    private String resolveFindingEligibilityDetail(ComponentVulnerabilityState state) {
        if (state.isEligibleForFinding()) {
            return state.getImpactState() == ImpactState.NO_PATCH
                    ? "Exact VEX evidence confirms the installed software is affected and no patch is currently available."
                    : "Exact VEX evidence confirms the installed software is affected for this asset and version.";
        }
        if (state.getApplicabilityState() != ApplicabilityState.APPLICABLE) {
            return "This component is not currently applicable after inventory correlation, so it cannot create a finding.";
        }
        return switch (state.getImpactState() == null ? ImpactState.UNKNOWN : state.getImpactState()) {
            case FIXED -> "Exact VEX evidence indicates the affected condition is fixed for this installed software/version.";
            case NOT_IMPACTED -> "Exact VEX evidence indicates this installed software/version is not affected.";
            case UNDER_INVESTIGATION -> "Vendor VEX has not resolved this software/version beyond under investigation.";
            case UNKNOWN -> "The component is applicable, but there is no exact VEX assertion proving affected or no-patch for this asset software version.";
            default -> state.getImpactReasonDetail();
        };
    }

    private String generateReport(Vulnerability vulnerability, OrgCveRecord orgCveRecord, String format) {
        if ("json".equalsIgnoreCase(format)) {
            try {
                Map<String, Object> data = new LinkedHashMap<>();
                data.put("cveId", vulnerability.getExternalId());
                data.put("severity", vulnerability.getSeverity());
                data.put("cvssScore", vulnerability.getCvssScore());
                data.put("description", vulnerability.getDescriptionSnippet());
                return objectMapper.writeValueAsString(data);
            } catch (Exception ignored) {
                return "{}";
            }
        }
        return "CVE Report: " + vulnerability.getExternalId() + "\n\n"
                + "Severity: " + vulnerability.getSeverity() + "\n"
                + "CVSS Score: " + vulnerability.getCvssScore() + "\n"
                + "Description: " + vulnerability.getDescriptionSnippet() + "\n";
    }

    private String preferNonBlank(String primary, String fallback) {
        return primary != null && !primary.isBlank() ? primary : fallback;
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
