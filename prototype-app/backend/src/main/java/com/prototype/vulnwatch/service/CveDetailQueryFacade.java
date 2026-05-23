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
import com.prototype.vulnwatch.repo.FixRecordRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import com.prototype.vulnwatch.domain.VulnerabilityIntelRelation;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelRelationRepository;
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
    private final FixRecordRepository fixRecordRepository;
    private final ObjectMapper objectMapper;
    private final VulnerabilityIntelDetailAssembler vulnerabilityIntelDetailAssembler;
    private final VulnerabilityIntelRelationRepository relationRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

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
            FixRecordRepository fixRecordRepository,
            ObjectMapper objectMapper,
            VulnerabilityIntelDetailAssembler vulnerabilityIntelDetailAssembler,
            VulnerabilityIntelRelationRepository relationRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService
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
        this.fixRecordRepository = fixRecordRepository;
        this.objectMapper = objectMapper;
        this.vulnerabilityIntelDetailAssembler = vulnerabilityIntelDetailAssembler;
        this.relationRepository = relationRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public ResponseEntity<CveDetailController.CveDetailResponse> getCveDetail(String cveId) {
        RequestActor actor = requestActorService.currentActor();
        UUID tenantId = actor.tenantId();
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);

        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("CVE not found: " + cveId));

        OrgCveRecord orgCveRecord = tenantSchemaExecutionService.run(
                tenant,
                () -> orgCveRecordRepository.findByVulnerability(vulnerability)
        ).orElse(null);
        UUID matchedSoftwareTenantId = orgCveRecord != null
                && orgCveRecord.getTenant() != null
                && orgCveRecord.getTenant().getId() != null
                ? orgCveRecord.getTenant().getId()
                : tenant.getId();
        List<CveDetailController.MatchedSoftwareDto> matchedSoftware = tenantSchemaExecutionService.run(
                tenant,
                () -> componentVulnerabilityStateRepository.findByVulnerability_Id(vulnerability.getId())
        ).stream()
                .filter(state -> state.getComponent() != null)
                .filter(state -> state.getComponent().getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .map(this::toMatchedSoftwareDto)
                .toList();

        CveDetailController.CveDetailResponse response = new CveDetailController.CveDetailResponse();
        response.summary = buildSummary(vulnerability);

        List<VulnerabilityTarget> targets = vulnerabilityTargetRepository.findByVulnerability(vulnerability);
        response.signals = buildSignals(vulnerability, orgCveRecord, matchedSoftware, targets);
        response.matchedSoftware = matchedSoftware;
        response.vendorIntelligence = buildVendorIntelligence(vulnerability, targets);
        response.references = buildReferences(vulnerability);
        response.fixes = tenantSchemaExecutionService.run(tenant, () -> fixRecordRepository.findByCveIdOrderByCreatedAtAsc(cveId))
                .stream()
                .map(r -> {
                    com.fasterxml.jackson.core.type.TypeReference<java.util.List<String>> strListType =
                            new com.fasterxml.jackson.core.type.TypeReference<>() {};
                    com.fasterxml.jackson.core.type.TypeReference<java.util.List<java.util.Map<String, Object>>> mapListType =
                            new com.fasterxml.jackson.core.type.TypeReference<>() {};
                    java.util.List<String> relatedCveIds = parseJsonList(r.getRelatedCveIdsJson(), strListType);
                    java.util.List<String> sourceUrls = parseJsonList(r.getSourceUrlsJson(), strListType);
                    java.util.List<com.prototype.vulnwatch.dto.FixRecordResponse.SoftwareEntity> entities =
                            parseSoftwareEntities(r.getSoftwareEntitiesJson(), mapListType);
                    return new com.prototype.vulnwatch.dto.FixRecordResponse(
                            r.getId(), r.getCveId(), relatedCveIds, r.getSummary(), r.getDescription(),
                            r.getFixType(), entities, r.getOsHint(), r.getRecommendationSource(),
                            sourceUrls, r.getGeneratedAt(), r.getCreatedAt());
                })
                .toList();
        if (orgCveRecord != null) {
            response.suppressedByRuleId = orgCveRecord.getSuppressedByRuleId();
            response.suppressedByRuleName = orgCveRecord.getSuppressedByRuleName();
        }
        List<VulnerabilityIntelObservation> observations =
                observationRepository.findByVulnerabilityOrderByLastSeenAtDesc(vulnerability);

        // Fetch cross-source relations where this vulnerability's observations are the target
        List<VulnerabilityIntelRelation> relations =
                relationRepository.findByToObservationVulnerabilityIdIn(List.of(vulnerability.getId()));

        // Include source-only observations (e.g. EUVD) from the from-side of relations
        // so they appear as sourceRecords on the CVE detail even though they carry no vulnerability FK
        Set<UUID> knownObsIds = observations.stream()
                .map(VulnerabilityIntelObservation::getId)
                .collect(java.util.stream.Collectors.toSet());
        List<VulnerabilityIntelObservation> allObservations = new ArrayList<>(observations);
        for (VulnerabilityIntelRelation relation : relations) {
            VulnerabilityIntelObservation fromObs = relation.getFromObservation();
            if (fromObs != null && !knownObsIds.contains(fromObs.getId())) {
                knownObsIds.add(fromObs.getId());
                allObservations.add(fromObs);
            }
        }

        response.sourceRecords = vulnerabilityIntelDetailAssembler.toSourceRecordResponses(allObservations);
        response.relations = vulnerabilityIntelDetailAssembler.toRelationResponses(relations);
        response.investigations = investigationService.getInvestigationsByCve(tenantId, cveId).stream()
                .map(this::toInvestigationDto)
                .collect(Collectors.toList());
        response.assessments = assessmentService.getAssessmentsByCve(tenantId, cveId).stream()
                .map(this::toAssessmentDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<CveDetailController.VexEvidenceResponse> getVexEvidence(String cveId, UUID componentId) {
        Tenant tenant = requestTenant();
        ComponentVulnerabilityState state = tenantSchemaExecutionService.run(
                tenant,
                () -> componentVulnerabilityStateRepository.findByVulnerability_ExternalIdAndComponent_Id(cveId, componentId)
        ).orElse(null);
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
        OrgCveRecord orgCveRecord = tenantSchemaExecutionService.run(
                tenant,
                () -> orgCveRecordRepository.findByVulnerability(vulnerability)
        ).orElse(null);

        CveDetailController.ExportResponse response = new CveDetailController.ExportResponse();
        response.cveId = cveId;
        response.format = request.format;
        response.content = generateReport(vulnerability, orgCveRecord, request.format);
        response.generatedAt = Instant.now();
        return ResponseEntity.ok(response);
    }

    private Tenant requestTenant() {
        return tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
    }

    private <T> java.util.List<T> parseJsonList(String json,
            com.fasterxml.jackson.core.type.TypeReference<java.util.List<T>> type) {
        if (json == null || json.isBlank()) return java.util.List.of();
        try {
            return objectMapper.readValue(json, type);
        } catch (Exception e) {
            return java.util.List.of();
        }
    }

    private java.util.List<com.prototype.vulnwatch.dto.FixRecordResponse.SoftwareEntity> parseSoftwareEntities(
            String json,
            com.fasterxml.jackson.core.type.TypeReference<java.util.List<java.util.Map<String, Object>>> type
    ) {
        if (json == null || json.isBlank()) return java.util.List.of();
        try {
            java.util.List<java.util.Map<String, Object>> raw = objectMapper.readValue(json, type);
            return raw.stream().map(m -> new com.prototype.vulnwatch.dto.FixRecordResponse.SoftwareEntity(
                    m.get("name") != null ? String.valueOf(m.get("name")) : "",
                    m.get("ecosystem") != null ? String.valueOf(m.get("ecosystem")) : "",
                    m.get("version") != null ? String.valueOf(m.get("version")) : null,
                    m.get("assetCount") instanceof Number n ? n.intValue() : 0
            )).toList();
        } catch (Exception e) {
            return java.util.List.of();
        }
    }

    private CveDetailController.CveSummary buildSummary(Vulnerability vulnerability) {
        CveDetailController.CveSummary summary = new CveDetailController.CveSummary();
        String description = vulnerabilityIntelQueryService.resolveDetailDescription(vulnerability);
        summary.externalId = vulnerability.getExternalId();
        summary.title = vulnerability.getTitle();
        summary.description = description;
        summary.severity = vulnerability.getSeverity();
        summary.cvssScore = vulnerability.getCvssScore();
        summary.cvssVector = vulnerability.getCvssVector();
        summary.epssScore = vulnerability.getEpssScore();
        summary.epssSevenDayDelta =
                epssTrendService.fetchSevenDayDelta(
                        vulnerability.getExternalId(),
                        vulnerability.getEpssScore(),
                        vulnerability.getEpssUpdatedAt()
                );
        summary.epssUpdatedAt = vulnerability.getEpssUpdatedAt();
        summary.cweIds = vulnerability.getCweIds();
        summary.source = vulnerability.getSource();
        summary.inKev = vulnerability.getInKev();

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
        summary.publishedAt = publishedAt;

        // Only use modifiedAt/publishedAt from actual NVD source dates — never from fallback sync timestamps.
        // If no NVD observation exists, these fields remain null so the UI doesn't show misleading dates.
        Instant modifiedAt = nvdObs != null ? nvdObs.getLastModifiedAt() : null;
        if (modifiedAt == null && vulnerability.getModifiedAt() != null && nvdObs != null) {
            // NVD obs exists but its lastModifiedAt is null — use what the entity has
            modifiedAt = vulnerability.getModifiedAt();
        }
        summary.modifiedAt = modifiedAt;

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
        summary.kevDateAdded = kevDateAdded;
        summary.kevDueDate = kevDueDate;
        summary.kevRequiredAction = kevRequiredAction;
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
                        ref.url = (String) m.get("url");
                        if (m.get("source") instanceof String s) {
                            ref.source = s;
                        }
                        Object tagsObj = m.get("tags");
                        if (tagsObj instanceof List<?> tagList) {
                            ref.tags = tagList.stream()
                                    .filter(t -> t instanceof String)
                                    .map(t -> (String) t)
                                    .toList();
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
                            ref.url = u;
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
        signals.exploitAvailable = exploitAvailable;
        signals.exploitReason = exploitAvailable
                ? (vulnerability.getInKev()
                        ? "In CISA KEV Catalog"
                        : "High EPSS Score (" + String.format("%.1f%%", vulnerability.getEpssScore() * 100) + ")")
                : "No known exploits";

        if (orgCveRecord != null) {
            signals.systemsImpacted = true;
            signals.componentCount = orgCveRecord.getMatchedComponentCount();
            signals.softwareCount = orgCveRecord.getMatchedSoftwareCount();
            signals.assetCount = matchedSoftware.stream()
                    .map(item -> item.assetId)
                    .filter(Objects::nonNull)
                    .distinct()
                    .count();
        } else {
            signals.systemsImpacted = false;
            signals.componentCount = 0L;
            signals.softwareCount = 0L;
            signals.assetCount = 0L;
        }

        boolean patchAvailable = targets.stream().anyMatch(t -> t.getFixedVersion() != null);
        signals.patchAvailable = patchAvailable;
        if (patchAvailable) {
            signals.patchVersions = targets.stream()
                    .filter(t -> t.getFixedVersion() != null)
                    .map(VulnerabilityTarget::getFixedVersion)
                    .distinct()
                    .collect(Collectors.joining(", "));
        }
        return signals;
    }

    private List<CveDetailController.VendorIntelligenceDto> buildVendorIntelligence(
            Vulnerability vulnerability,
            List<VulnerabilityTarget> targets
    ) {
        // Use a map keyed by dedupeKey so we can merge CPE from CPE-type targets
        // into the already-added COORD-type target DTO (COORD targets lack a CPE field).
        Map<String, CveDetailController.VendorIntelligenceDto> dtoByKey = new LinkedHashMap<>();
        Map<UUID, String> vexStatusByTargetId = mapVexStatusByTargetId(targets);
        for (VulnerabilityTarget target : targets) {
            CveDetailController.VendorIntelligenceDto dto = new CveDetailController.VendorIntelligenceDto();
            String source = (target.getSource() == null || target.getSource().isBlank() || "unknown".equalsIgnoreCase(target.getSource()))
                    ? (vulnerability.getSource() != null ? vulnerability.getSource().name() : VulnerabilitySource.ADVISORY.name())
                    : target.getSource().toUpperCase();
            dto.source = source;
            dto.ecosystem = target.getEcosystem();
            dto.packageName = target.getPackageName();
            String affectedVersions = formatVersionRange(target);
            dto.affectedVersions = affectedVersions;
            dto.fixedVersion = target.getFixed() != null && !target.getFixed().isBlank() ? target.getFixed() : null;
            String cpe = target.getCpe() != null && !target.getCpe().isBlank() ? target.getCpe() : null;
            dto.cpe = cpe;
            dto.vexStatus = vexStatusByTargetId.get(target.getId());
            String dedupeKey = source + "|" + nullToEmpty(target.getPackageName()) + "|" + affectedVersions + "|" + nullToEmpty(target.getFixed());
            CveDetailController.VendorIntelligenceDto existing = dtoByKey.get(dedupeKey);
            if (existing == null) {
                dtoByKey.put(dedupeKey, dto);
            } else if (cpe != null && existing.cpe == null) {
                // Merge CPE from this (CPE-type) target into the already-added DTO
                existing.cpe = cpe;
            }
        }
        return new ArrayList<>(dtoByKey.values());
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
        response.componentId = state.getComponent() == null ? null : state.getComponent().getId();
        response.assetName = state.getComponent() != null && state.getComponent().getAsset() != null
                ? state.getComponent().getAsset().getName()
                : null;
        response.assetIdentifier = state.getComponent() != null && state.getComponent().getAsset() != null
                ? state.getComponent().getAsset().getIdentifier()
                : null;
        response.assetType = state.getComponent() != null
                && state.getComponent().getAsset() != null
                && state.getComponent().getAsset().getType() != null
                ? state.getComponent().getAsset().getType().name()
                : null;
        response.ecosystem = state.getComponent() == null ? null : state.getComponent().getEcosystem();
        response.installedVersion = state.getComponent() == null ? null : state.getComponent().getVersion();
        response.matchedBy = state.getMatchedBy();
        response.applicabilityState = state.getApplicabilityState() == null ? null : state.getApplicabilityState().name();
        response.applicabilityReason = state.getApplicabilityReason();
        response.applicabilityReasonDetail = state.getApplicabilityReasonDetail();
        response.matchedVexAssertionId = assertion.getId();
        response.sourceSystem = assertion.getSourceSystem();
        response.provider = assertion.getProvider();
        response.status = assertion.getStatus();
        response.trustTier = assertion.getTrustTier();
        response.freshness = assertion.getFreshness();
        response.documentId = assertion.getDocumentId();
        response.packageName = assertion.getPackageName();
        response.normalizedProductKey = assertion.getNormalizedProductKey();
        response.versionExact = assertion.getVersionExact();
        response.versionStart = assertion.getVersionStart();
        response.startInclusive = assertion.getStartInclusive();
        response.versionEnd = assertion.getVersionEnd();
        response.endInclusive = assertion.getEndInclusive();
        response.fixedVersion = assertion.getFixedVersion();
        response.publishedAt = assertion.getPublishedAt();
        response.lastSeenAt = assertion.getLastSeenAt();
        response.evidenceUrl = extractEvidenceUrl(evidence);
        response.computedImpactState = state.getImpactState() == null ? null : state.getImpactState().name();
        response.computedImpactReason = state.getImpactReason();
        response.computedImpactReasonDetail = state.getImpactReasonDetail();
        if (state.getAnalystDisposition() != null) {
            response.impactState = state.getAnalystDisposition().name();
            response.impactReason = state.getAnalystReason();
            response.impactReasonDetail = "Analyst override";
        } else {
            response.impactState = state.getImpactState() == null ? null : state.getImpactState().name();
            response.impactReason = state.getImpactReason();
            response.impactReasonDetail = state.getImpactReasonDetail();
        }
        response.evidence = evidence;
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
        dto.id = investigation.getId();
        dto.cveId = investigation.getVulnerability().getExternalId();
        dto.status = investigation.getStatus();
        dto.assignedTo = investigation.getAssignedTo();
        dto.priority = investigation.getPriority();
        dto.notes = investigation.getNotes();
        dto.createdAt = investigation.getCreatedAt();
        dto.updatedAt = investigation.getUpdatedAt();
        return dto;
    }

    private CveDetailController.AssessmentDto toAssessmentDto(ApplicabilityAssessment assessment) {
        CveDetailController.AssessmentDto dto = new CveDetailController.AssessmentDto();
        dto.id = assessment.getId();
        dto.cveId = assessment.getVulnerability().getExternalId();
        dto.status = assessment.getStatus();
        dto.softwareDetected = assessment.getSoftwareDetected();
        dto.vulnerableVersionPresent = assessment.getVulnerableVersionPresent();
        dto.vulnerableConfiguration = assessment.getVulnerableConfiguration();
        dto.finalResult = assessment.getFinalResult();
        dto.confidenceLevel = assessment.getConfidenceLevel();
        dto.justification = assessment.getJustification();
        dto.recommendedAction = assessment.getRecommendedAction();
        dto.createdAt = assessment.getCreatedAt();
        dto.completedAt = assessment.getCompletedAt();
        return dto;
    }

    private CveDetailController.MatchedSoftwareDto toMatchedSoftwareDto(ComponentVulnerabilityState state) {
        CveDetailController.MatchedSoftwareDto dto = new CveDetailController.MatchedSoftwareDto();
        dto.componentId = state.getComponent().getId();
        dto.assetId = state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getId();
        dto.assetName = state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getName();
        dto.assetIdentifier = state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getIdentifier();
        dto.assetType = state.getComponent().getAsset() != null && state.getComponent().getAsset().getType() != null
                ? state.getComponent().getAsset().getType().name()
                : null;
        dto.ecosystem = state.getComponent().getEcosystem();
        dto.packageName = state.getComponent().getPackageName();
        dto.version = state.getComponent().getVersion();
        dto.applicabilityState = state.getApplicabilityState();
        dto.applicabilityReason = state.getApplicabilityReason();
        dto.applicabilityReasonDetail = state.getApplicabilityReasonDetail();
        dto.computedImpactState = state.getImpactState();
        dto.computedImpactReason = state.getImpactReason();
        dto.computedImpactReasonDetail = state.getImpactReasonDetail();
        if (state.getAnalystDisposition() != null) {
            dto.impactState = ImpactState.valueOf(state.getAnalystDisposition().name());
            dto.impactReason = state.getAnalystReason();
            dto.impactReasonDetail = "Analyst override";
        } else {
            dto.impactState = state.getImpactState();
            dto.impactReason = state.getImpactReason();
            dto.impactReasonDetail = state.getImpactReasonDetail();
        }
        dto.vexStatus = state.getVexStatus();
        dto.vexProvider = state.getVexProvider();
        dto.vexFreshness = state.getVexFreshness();
        dto.vexSource = state.getVexSource();
        dto.matchedVexAssertionId = state.getMatchedVexAssertionId();
        dto.analystDisposition = state.getAnalystDisposition() == null ? null : state.getAnalystDisposition().name();
        dto.analystReason = state.getAnalystReason();
        dto.matchedBy = state.getMatchedBy();
        dto.eligibleForFinding = state.isEligibleForFinding();
        dto.findingEligibilityReason = resolveFindingEligibilityReason(state);
        dto.findingEligibilityDetail = resolveFindingEligibilityDetail(state);
        dto.eolSlug = state.getComponent().getEolSlug();
        dto.eolCycle = state.getComponent().getEolCycle();
        LocalDate eolDate = state.getComponent().getEolDate();
        boolean effectiveEol = Boolean.TRUE.equals(state.getComponent().getIsEol())
                || (eolDate != null && !LocalDate.now().isBefore(eolDate));
        dto.eolDate = eolDate;
        dto.isEol = effectiveEol;
        if (eolDate != null && !effectiveEol) {
            int daysRemaining = (int) ChronoUnit.DAYS.between(LocalDate.now(), eolDate);
            if (daysRemaining >= 0) {
                dto.eolDaysRemaining = daysRemaining;
            }
        }
        dto.eolSupportEndDate = state.getComponent().getEolSupportEndDate();
        dto.supportPhase = state.getComponent().getSupportPhase();
        dto.supportGroup = state.getComponent().getAsset() == null ? null : state.getComponent().getAsset().getSupportGroup();
        dto.softwareIdentityId = state.getComponent().getSoftwareIdentity() == null ? null : state.getComponent().getSoftwareIdentity().getId();
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
