package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.EolRelease;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.ApplicationCveResponse;
import com.prototype.vulnwatch.dto.ApplicationRiskResponse;
import com.prototype.vulnwatch.dto.BomComponentCveSummary;
import com.prototype.vulnwatch.dto.BomComponentDetailResponse;
import com.prototype.vulnwatch.dto.BomComponentSummaryResponse;
import com.prototype.vulnwatch.dto.BomDashboardBreakdownItemResponse;
import com.prototype.vulnwatch.dto.EolReleaseSummary;
import com.prototype.vulnwatch.dto.BomDashboardResponse;
import com.prototype.vulnwatch.dto.BomComponentResponse;
import com.prototype.vulnwatch.dto.BomDetailResponse;
import com.prototype.vulnwatch.dto.BomInspectionResponse;
import com.prototype.vulnwatch.dto.BomInventoryItemResponse;
import com.prototype.vulnwatch.dto.BomLineageItemResponse;
import com.prototype.vulnwatch.dto.BomSupportMatrixResponse;
import com.prototype.vulnwatch.dto.BomWorkflowSummaryResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import com.prototype.vulnwatch.repo.BomComponentEvidenceRepository;
import com.prototype.vulnwatch.repo.BomComponentVulnerabilityLinkRepository;
import com.prototype.vulnwatch.repo.BomComponentWorkflowRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.util.PurlUtil;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class BomInventoryReadService {

    private final BomIngestionRecordRepository bomRecordRepository;
    private final BomComponentRepository bomComponentRepository;
    private final BomComponentEvidenceRepository bomComponentEvidenceRepository;
    private final BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository;
    private final BomComponentWorkflowRepository bomComponentWorkflowRepository;
    private final SbomParserService sbomParserService;
    private final AssetRepository assetRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final EolReleaseRepository eolReleaseRepository;
    private final VulnerabilityRepository vulnerabilityRepository;

    public BomInventoryReadService(
            BomIngestionRecordRepository bomRecordRepository,
            BomComponentRepository bomComponentRepository,
            BomComponentEvidenceRepository bomComponentEvidenceRepository,
            BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository,
            BomComponentWorkflowRepository bomComponentWorkflowRepository,
            SbomParserService sbomParserService,
            AssetRepository assetRepository,
            InventoryComponentRepository inventoryComponentRepository,
            EolReleaseRepository eolReleaseRepository,
            VulnerabilityRepository vulnerabilityRepository
    ) {
        this.bomRecordRepository = bomRecordRepository;
        this.bomComponentRepository = bomComponentRepository;
        this.bomComponentEvidenceRepository = bomComponentEvidenceRepository;
        this.bomComponentVulnerabilityLinkRepository = bomComponentVulnerabilityLinkRepository;
        this.bomComponentWorkflowRepository = bomComponentWorkflowRepository;
        this.sbomParserService = sbomParserService;
        this.assetRepository = assetRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.eolReleaseRepository = eolReleaseRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    @Transactional(readOnly = true)
    public List<BomInventoryItemResponse> listInventory(Tenant tenant, int page, int size) {
        Pageable pageable = PageRequest.of(page, Math.min(size, 200));
        List<BomIngestionRecord> records = bomRecordRepository
                .findByTenant_IdAndStatusOrderByIngestedAtDesc(tenant.getId(), BomStatus.ACTIVE, pageable);
        return records.stream().map(this::toInventoryItem).toList();
    }

    @Transactional(readOnly = true)
    public BomDashboardResponse getDashboard(Tenant tenant) {
        List<BomIngestionRecord> records = bomRecordRepository.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE);
        List<UUID> bomIds = records.stream().map(BomIngestionRecord::getId).toList();
        if (bomIds.isEmpty()) {
            return new BomDashboardResponse(0, 0, 0, 0, 0, 0, 0, 0, List.of(), List.of(), List.of(), List.of());
        }
        List<com.prototype.vulnwatch.domain.BomComponent> components = bomComponentRepository.findByBomIdInAndActiveTrue(bomIds);
        List<UUID> componentIds = components.stream().map(com.prototype.vulnwatch.domain.BomComponent::getId).toList();
        Map<UUID, Integer> evidenceCountByComponent = toCountMap(
                bomComponentEvidenceRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentEvidence::getBomComponentId
        );
        Map<UUID, Integer> vulnerabilityCountByComponent = toCountMap(
                bomComponentVulnerabilityLinkRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink::getBomComponentId
        );
        List<com.prototype.vulnwatch.domain.BomComponentWorkflow> workflows = bomComponentWorkflowRepository.findByBomComponentIdIn(componentIds);
        Map<UUID, String> latestWorkflowStatus = workflows.stream().collect(Collectors.toMap(
                com.prototype.vulnwatch.domain.BomComponentWorkflow::getBomComponentId,
                workflow -> workflow.getWorkflowStatus().name(),
                (left, right) -> right
        ));
        long componentCount = components.size();
        long evidenceCount = evidenceCountByComponent.values().stream().mapToLong(Integer::longValue).sum();
        long vulnerabilityLinkCount = vulnerabilityCountByComponent.values().stream().mapToLong(Integer::longValue).sum();
        long correlatedComponentCount = components.stream()
                .filter(component -> vulnerabilityCountByComponent.getOrDefault(component.getId(), 0) > 0)
                .count();
        long openRemediationCount = workflows.stream()
                .filter(workflow -> workflow.getWorkflowStatus() == com.prototype.vulnwatch.domain.BomWorkflowStatus.REMEDIATION_OPEN)
                .count();
        return new BomDashboardResponse(
                records.size(),
                componentCount,
                evidenceCount,
                vulnerabilityLinkCount,
                correlatedComponentCount,
                workflows.size(),
                openRemediationCount,
                records.stream().map(record -> coalesce(record.getSourceSystem(), record.getSourceType() != null ? record.getSourceType().name() : null))
                        .filter(value -> value != null && !value.isBlank())
                        .distinct()
                        .count(),
                toBreakdown(records.stream().collect(Collectors.groupingBy(
                        record -> record.getBomType() != null ? record.getBomType().name() : "UNKNOWN",
                        Collectors.counting()
                ))),
                toBreakdown(records.stream().collect(Collectors.groupingBy(
                        record -> record.getSpecFamily() != null ? record.getSpecFamily().name() : "UNKNOWN",
                        Collectors.counting()
                ))),
                toBreakdown(records.stream().collect(Collectors.groupingBy(
                        record -> {
                            String value = coalesce(record.getSourceSystem(), record.getSourceType() != null ? record.getSourceType().name() : null);
                            return value == null || value.isBlank() ? "UNKNOWN" : value;
                        },
                        Collectors.counting()
                ))),
                toBreakdown(workflows.stream().collect(Collectors.groupingBy(
                        workflow -> workflow.getWorkflowStatus().name(),
                        Collectors.counting()
                )))
        );
    }

    @Transactional(readOnly = true)
    public List<BomLineageItemResponse> getLineage(Tenant tenant, UUID bomId) {
        BomIngestionRecord seed = bomRecordRepository.findById(bomId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "BOM record not found"));
        Map<UUID, BomIngestionRecord> byId = bomRecordRepository.findByTenant_IdOrderByIngestedAtDesc(tenant.getId(), PageRequest.of(0, 500))
                .stream()
                .collect(Collectors.toMap(BomIngestionRecord::getId, Function.identity(), (left, right) -> left));
        List<BomLineageItemResponse> lineage = new java.util.ArrayList<>();
        BomIngestionRecord cursor = seed;
        while (cursor != null) {
            lineage.add(toLineageItem(cursor));
            UUID previousId = cursor.getPreviousBomId();
            cursor = previousId != null ? byId.get(previousId) : null;
        }
        UUID forward = seed.getSupersededBy();
        while (forward != null) {
            BomIngestionRecord next = byId.get(forward);
            if (next == null) {
                break;
            }
            lineage.add(0, toLineageItem(next));
            forward = next.getSupersededBy();
        }
        return lineage;
    }

    @Transactional(readOnly = true)
    public BomSupportMatrixResponse getSupportMatrix() {
        return sbomParserService.supportMatrix();
    }

    @Transactional(readOnly = true)
    public BomDetailResponse getDetail(Tenant tenant, UUID bomId) {
        BomIngestionRecord record = bomRecordRepository.findById(bomId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "BOM record not found"));

        Pageable pageable = PageRequest.of(0, 500);
        List<com.prototype.vulnwatch.domain.BomComponent> bomComponents = bomComponentRepository
                .findByBomIdAndActiveTrue(bomId, pageable);
        List<UUID> componentIds = bomComponents.stream().map(com.prototype.vulnwatch.domain.BomComponent::getId).toList();
        Map<UUID, Integer> evidenceCountByComponent = toCountMap(
                bomComponentEvidenceRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentEvidence::getBomComponentId
        );
        Map<UUID, Integer> vulnerabilityCountByComponent = toCountMap(
                bomComponentVulnerabilityLinkRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink::getBomComponentId
        );
        Map<UUID, String> workflowStatusByComponent = bomComponentWorkflowRepository.findByBomComponentIdIn(componentIds)
                .stream()
                .collect(Collectors.toMap(
                        com.prototype.vulnwatch.domain.BomComponentWorkflow::getBomComponentId,
                        workflow -> workflow.getWorkflowStatus().name(),
                        (left, right) -> right
                ));
        List<BomComponentResponse> components = bomComponents.stream()
                .map(component -> toComponentResponse(component, vulnerabilityCountByComponent, evidenceCountByComponent, workflowStatusByComponent))
                .toList();
        List<BomWorkflowSummaryResponse> workflowSummary = bomComponents.stream()
                .collect(Collectors.groupingBy(
                        component -> workflowStatusByComponent.getOrDefault(component.getId(), component.getWorkflowStatus().name()),
                        Collectors.counting()
                ))
                .entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> new BomWorkflowSummaryResponse(entry.getKey(), entry.getValue()))
                .toList();
        long evidenceCount = bomComponentEvidenceRepository.countByBomId(bomId);
        long vulnerabilityLinkCount = bomComponentVulnerabilityLinkRepository.countByBomId(bomId);
        long correlatedComponentCount = bomComponents.stream()
                .filter(component -> vulnerabilityCountByComponent.getOrDefault(component.getId(), 0) > 0)
                .count();
        BomInspectionResponse inspection = sbomParserService.inspectResolved(
                record.getFormat() != null ? record.getFormat().name() : null,
                record.getFormatVersion(),
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null
        );

        return new BomDetailResponse(
                record.getId(),
                record.getAssetId(),
                record.getBomType() != null ? record.getBomType().name() : null,
                record.getFormat() != null ? record.getFormat().name() : null,
                record.getFormatVersion(),
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null,
                record.getSerialNumber(),
                record.getSupplier(),
                record.getSourceMethod(),
                record.getSourceType() != null ? record.getSourceType().name() : null,
                record.getSourceSystem(),
                record.getSourceReference(),
                record.getSourceUrl(),
                record.getChecksumSha256(),
                inspection,
                record.getComponentCount(),
                evidenceCount,
                vulnerabilityLinkCount,
                correlatedComponentCount,
                record.getStatus().name(),
                record.getIngestedAt(),
                record.getIngestedBy(),
                workflowSummary,
                components
        );
    }

    @Transactional
    public void softDelete(Tenant tenant, UUID bomId) {
        BomIngestionRecord record = bomRecordRepository.findById(bomId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "BOM record not found"));
        bomComponentRepository.softDeleteByBomId(bomId);
        record.setStatus(BomStatus.DELETED);
        bomRecordRepository.save(record);
    }

    @Transactional(readOnly = true)
    public List<BomComponentSummaryResponse> getBomComponentSummaries(Tenant tenant, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(size, 2000));
        List<BomIngestionRecord> activeBoms = bomRecordRepository.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)
                .stream()
                .filter(b -> b.getAssetId() != null)
                .toList();
        if (activeBoms.isEmpty()) {
            return List.of();
        }
        Map<UUID, BomIngestionRecord> bomById = activeBoms.stream()
                .collect(Collectors.toMap(BomIngestionRecord::getId, Function.identity()));
        Map<UUID, Asset> assetById = assetRepository.findAllById(activeBoms.stream().map(BomIngestionRecord::getAssetId).toList())
                .stream()
                .filter(asset -> asset.getType() == AssetType.APPLICATION)
                .collect(Collectors.toMap(Asset::getId, Function.identity()));
        List<BomComponent> allComponents = bomComponentRepository.findByBomIdInAndActiveTrue(bomById.keySet()).stream()
                .filter(component -> {
                    BomIngestionRecord record = bomById.get(component.getBomId());
                    return record != null && assetById.containsKey(record.getAssetId());
                })
                .sorted(Comparator
                        .comparing((BomComponent component) -> assetById.get(bomById.get(component.getBomId()).getAssetId()).getName(), Comparator.nullsLast(String::compareToIgnoreCase))
                        .thenComparing(BomComponent::getName, Comparator.nullsLast(String::compareToIgnoreCase)))
                .toList();
        if (allComponents.isEmpty()) {
            return List.of();
        }

        int fromIndex = Math.min(safePage * safeSize, allComponents.size());
        int toIndex = Math.min(fromIndex + safeSize, allComponents.size());
        List<BomComponent> pageComponents = allComponents.subList(fromIndex, toIndex);
        Map<UUID, List<String>> bomTypesByAsset = activeBoms.stream()
                .collect(Collectors.groupingBy(
                        BomIngestionRecord::getAssetId,
                        Collectors.mapping(record -> record.getBomType() == null ? "UNKNOWN" : record.getBomType().name(), Collectors.toList())
                ));
        return buildComponentSummaries(tenant, pageComponents, bomById, assetById, bomTypesByAsset);
    }

    @Transactional(readOnly = true)
    public List<ApplicationRiskResponse> getApplicationRisk(Tenant tenant) {
        List<BomIngestionRecord> activeBoms = bomRecordRepository.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)
                .stream()
                .filter(b -> b.getAssetId() != null)
                .toList();
        if (activeBoms.isEmpty()) {
            return List.of();
        }
        Map<UUID, Asset> assetsById = assetRepository.findAllById(activeBoms.stream().map(BomIngestionRecord::getAssetId).toList())
                .stream()
                .filter(a -> a.getType() == AssetType.APPLICATION && a.getState() == AssetState.ACTIVE)
                .collect(Collectors.toMap(Asset::getId, Function.identity()));
        if (assetsById.isEmpty()) {
            return List.of();
        }
        List<BomIngestionRecord> applicationBoms = activeBoms.stream()
                .filter(b -> assetsById.containsKey(b.getAssetId()))
                .toList();
        Map<UUID, BomIngestionRecord> bomById = applicationBoms.stream()
                .collect(Collectors.toMap(BomIngestionRecord::getId, Function.identity()));
        Map<UUID, List<String>> bomTypesByAsset = applicationBoms.stream()
                .collect(Collectors.groupingBy(
                        BomIngestionRecord::getAssetId,
                        Collectors.mapping(
                                b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN",
                                Collectors.toList()
                        )
                ));
        Map<UUID, Instant> lastIngestedByAsset = activeBoms.stream()
                .collect(Collectors.toMap(
                        BomIngestionRecord::getAssetId,
                        BomIngestionRecord::getIngestedAt,
                        (a, b) -> a.isAfter(b) ? a : b
                ));

        Map<UUID, List<BomComponent>> componentsByAsset = bomComponentRepository.findByBomIdInAndActiveTrue(
                        applicationBoms.stream().map(BomIngestionRecord::getId).toList())
                .stream()
                .collect(Collectors.groupingBy(component -> bomById.get(component.getBomId()).getAssetId()));

        return assetsById.values().stream().map(asset -> {
            List<BomComponent> components = componentsByAsset.getOrDefault(asset.getId(), List.of());
            Map<UUID, List<BomComponentVulnerabilityLink>> linksByComponent = loadLinksByComponent(components);
            Map<String, Vulnerability> vulnerabilitiesByExternalId = loadVulnerabilitiesByExternalId(linksByComponent.values().stream().flatMap(List::stream).toList());
            Set<String> vulnerabilityKeys = new HashSet<>();
            int critical = 0;
            int high = 0;
            int medium = 0;
            int low = 0;
            int vulnerableComponents = 0;
            int eolComponents = 0;
            for (BomComponent component : components) {
                List<BomComponentVulnerabilityLink> links = linksByComponent.getOrDefault(component.getId(), List.of());
                if (!links.isEmpty()) {
                    vulnerableComponents++;
                }
                InventoryComponent inventoryComponent = resolveProjectedInventoryComponent(tenant, asset.getId(), component);
                if (inventoryComponent != null && Boolean.TRUE.equals(inventoryComponent.getIsEol())) {
                    eolComponents++;
                }
                for (BomComponentVulnerabilityLink link : links) {
                    if (!vulnerabilityKeys.add(link.getVulnerabilityKey())) {
                        continue;
                    }
                    Vulnerability vulnerability = vulnerabilitiesByExternalId.get(link.getVulnerabilityKey());
                    String severity = vulnerability == null || vulnerability.getSeverity() == null ? "UNKNOWN" : vulnerability.getSeverity();
                    switch (severity) {
                        case "CRITICAL" -> critical++;
                        case "HIGH" -> high++;
                        case "MEDIUM" -> medium++;
                        case "LOW", "NONE" -> low++;
                        default -> { }
                    }
                }
            }
            int total = vulnerabilityKeys.size();
            double riskScore = computeApplicationRiskScore(critical, high, medium, low);
            List<String> bomTypes = bomTypesByAsset.getOrDefault(asset.getId(), List.of())
                    .stream().distinct().sorted().toList();
            Instant lastIngested = lastIngestedByAsset.get(asset.getId());
            return new ApplicationRiskResponse(
                    asset.getId().toString(),
                    asset.getName(),
                    asset.getIdentifier(),
                    asset.getBusinessCriticality() != null ? asset.getBusinessCriticality().name() : "MEDIUM",
                    bomTypes,
                    components.size(),
                    vulnerableComponents,
                    eolComponents,
                    critical, high, medium, low, total,
                    riskScore,
                    toApplicationRiskLevel(riskScore),
                    lastIngested != null ? lastIngested.toString() : null
            );
        })
        .sorted(Comparator.comparingDouble(ApplicationRiskResponse::riskScore).reversed())
        .toList();
    }

    @Transactional(readOnly = true)
    public List<ApplicationCveResponse> getApplicationCves(Tenant tenant, UUID assetId) {
        List<BomIngestionRecord> activeBoms = bomRecordRepository.findByTenant_IdAndAssetIdAndStatusOrderByIngestedAtDesc(
                tenant.getId(),
                assetId,
                BomStatus.ACTIVE
        );
        if (activeBoms.isEmpty()) {
            return List.of();
        }
        List<BomComponent> components = bomComponentRepository.findByBomIdInAndActiveTrue(
                activeBoms.stream().map(BomIngestionRecord::getId).toList()
        );
        Map<UUID, List<BomComponentVulnerabilityLink>> linksByComponent = loadLinksByComponent(components);
        Map<String, Vulnerability> vulnerabilitiesByExternalId = loadVulnerabilitiesByExternalId(
                linksByComponent.values().stream().flatMap(List::stream).toList()
        );
        List<ApplicationCveResponse> responses = new ArrayList<>();
        for (BomComponent component : components) {
            for (BomComponentVulnerabilityLink link : linksByComponent.getOrDefault(component.getId(), List.of())) {
                Vulnerability vulnerability = vulnerabilitiesByExternalId.get(link.getVulnerabilityKey());
                responses.add(new ApplicationCveResponse(
                        vulnerability == null ? null : vulnerability.getId().toString(),
                        component.getId().toString(),
                        link.getVulnerabilityKey(),
                        vulnerability == null ? "UNKNOWN" : vulnerability.getSeverity(),
                        vulnerability == null ? null : vulnerability.getCvssScore(),
                        vulnerability == null ? null : vulnerability.getEpssScore(),
                        component.getName(),
                        component.getVersion(),
                        link.getUpdatedAt() != null ? link.getUpdatedAt().toString() : null
                ));
            }
        }
        return responses;
    }

    @Transactional(readOnly = true)
    public BomComponentDetailResponse getComponentDetail(Tenant tenant, UUID componentId) {
        BomComponent component = bomComponentRepository.findById(componentId)
                .filter(c -> c.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Component not found"));
        BomIngestionRecord record = bomRecordRepository.findById(component.getBomId())
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "BOM record not found"));
        Asset asset = record.getAssetId() == null ? null : assetRepository.findById(record.getAssetId()).orElse(null);
        List<BomIngestionRecord> assetBoms = record.getAssetId() == null
                ? List.of(record)
                : bomRecordRepository.findByTenant_IdAndAssetIdAndStatusOrderByIngestedAtDesc(tenant.getId(), record.getAssetId(), BomStatus.ACTIVE);
        List<String> bomTypes = assetBoms.stream()
                .map(b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN")
                .distinct().sorted().toList();
        List<BomComponentVulnerabilityLink> links = bomComponentVulnerabilityLinkRepository.findByBomComponentId(componentId);
        Map<String, Vulnerability> vulnerabilitiesByExternalId = loadVulnerabilitiesByExternalId(links);
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        for (BomComponentVulnerabilityLink link : links) {
            Vulnerability vulnerability = vulnerabilitiesByExternalId.get(link.getVulnerabilityKey());
            String severity = vulnerability == null || vulnerability.getSeverity() == null ? "UNKNOWN" : vulnerability.getSeverity();
            switch (severity) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
                case "MEDIUM" -> medium++;
                case "LOW", "NONE" -> low++;
                default -> { }
            }
        }
        double riskScore = computeApplicationRiskScore(critical, high, medium, low);
        String correlationState = links.isEmpty() ? "UNCHECKED" : "APPLICABLE";
        List<BomComponentCveSummary> cves = links.stream()
                .map(link -> vulnerabilitiesByExternalId.get(link.getVulnerabilityKey()))
                .filter(vulnerability -> vulnerability != null)
                .sorted(Comparator.comparing(vulnerability -> vulnerability.getSeverity() != null ? vulnerability.getSeverity() : ""))
                .map(vulnerability -> new BomComponentCveSummary(
                        vulnerability.getId().toString(),
                        vulnerability.getExternalId(),
                        vulnerability.getSeverity(),
                        vulnerability.getTitle(),
                        "APPLICABLE",
                        vulnerability.getEpssScore(),
                        vulnerability.getCvssScore()
                ))
                .toList();

        InventoryComponent projectedInventory = asset == null ? null : resolveProjectedInventoryComponent(tenant, asset.getId(), component);
        List<EolReleaseSummary> eolReleases = List.of();
        if (projectedInventory != null && projectedInventory.getEolSlug() != null && !projectedInventory.getEolSlug().isBlank()) {
            eolReleases = eolReleaseRepository.findByProductSlug(projectedInventory.getEolSlug()).stream()
                    .sorted(Comparator.comparing(EolRelease::getReleaseDate, Comparator.nullsLast(Comparator.reverseOrder())))
                    .map(r -> new EolReleaseSummary(
                            r.getCycle(),
                            r.getReleaseDate() != null ? r.getReleaseDate().toString() : null,
                            r.getEolDate() != null ? r.getEolDate().toString() : null,
                            r.getSupportEndDate() != null ? r.getSupportEndDate().toString() : null,
                            r.getLatestVersion(),
                            r.getLatestReleaseDate() != null ? r.getLatestReleaseDate().toString() : null,
                            r.isEol(),
                            r.isLts()
                    ))
                    .toList();
        }
        return new BomComponentDetailResponse(
                component.getId().toString(),
                component.getName(),
                component.getGroupName(),
                component.getVersion(),
                component.getPurl(),
                ecosystemFor(component),
                component.getLicense(),
                component.getScope(),
                normalizedNameFor(component),
                projectedInventory == null ? null : projectedInventory.getEolSlug(),
                projectedInventory == null ? null : projectedInventory.getEolCycle(),
                projectedInventory != null && Boolean.TRUE.equals(projectedInventory.getIsEol()),
                projectedInventory == null || projectedInventory.getEolDate() == null ? null : projectedInventory.getEolDate().toString(),
                projectedInventory == null || projectedInventory.getEolSupportEndDate() == null ? null : projectedInventory.getEolSupportEndDate().toString(),
                projectedInventory == null ? null : projectedInventory.getSupportPhase(),
                projectedInventory == null || projectedInventory.getEolCheckedAt() == null ? null : projectedInventory.getEolCheckedAt().toString(),
                record.getIngestedAt().toString(),
                record.getIngestedAt().toString(),
                asset == null ? null : asset.getId().toString(),
                asset == null ? null : asset.getName(),
                asset == null ? null : asset.getIdentifier(),
                asset == null || asset.getType() == null ? null : asset.getType().name(),
                bomTypes,
                correlationState,
                toApplicationRiskLevel(riskScore),
                critical, high, medium, low, links.size(),
                cves,
                eolReleases
        );
    }

    private double computeApplicationRiskScore(int critical, int high, int medium, int low) {
        int total = critical + high + medium + low;
        if (total == 0) {
            return 0.0;
        }
        double weighted = critical * 10.0 + high * 7.0 + medium * 4.0 + low * 1.0;
        return Math.min(10.0, weighted / total);
    }

    private String toApplicationRiskLevel(double score) {
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        if (score > 0.0) return "LOW";
        return "NONE";
    }

    private List<BomComponentSummaryResponse> buildComponentSummaries(
            Tenant tenant,
            List<BomComponent> components,
            Map<UUID, BomIngestionRecord> bomById,
            Map<UUID, Asset> assetById,
            Map<UUID, List<String>> bomTypesByAsset
    ) {
        Map<UUID, List<BomComponentVulnerabilityLink>> linksByComponent = loadLinksByComponent(components);
        Map<String, Vulnerability> vulnerabilitiesByExternalId = loadVulnerabilitiesByExternalId(
                linksByComponent.values().stream().flatMap(List::stream).toList()
        );
        return components.stream().map(component -> {
            BomIngestionRecord record = bomById.get(component.getBomId());
            Asset asset = record == null ? null : assetById.get(record.getAssetId());
            Map<String, Vulnerability> componentVulnerabilities = new HashMap<>();
            for (BomComponentVulnerabilityLink link : linksByComponent.getOrDefault(component.getId(), List.of())) {
                Vulnerability vulnerability = vulnerabilitiesByExternalId.get(link.getVulnerabilityKey());
                if (vulnerability != null) {
                    componentVulnerabilities.put(vulnerability.getExternalId(), vulnerability);
                }
            }
            int critical = (int) componentVulnerabilities.values().stream().filter(v -> "CRITICAL".equals(v.getSeverity())).count();
            int high = (int) componentVulnerabilities.values().stream().filter(v -> "HIGH".equals(v.getSeverity())).count();
            int medium = (int) componentVulnerabilities.values().stream().filter(v -> "MEDIUM".equals(v.getSeverity())).count();
            int low = (int) componentVulnerabilities.values().stream()
                    .filter(v -> "LOW".equals(v.getSeverity()) || "NONE".equals(v.getSeverity())).count();
            InventoryComponent projectedInventory = asset == null ? null : resolveProjectedInventoryComponent(tenant, asset.getId(), component);
            double score = computeApplicationRiskScore(critical, high, medium, low);
            return new BomComponentSummaryResponse(
                    component.getId().toString(),
                    component.getName(),
                    component.getVersion(),
                    component.getPurl(),
                    ecosystemFor(component),
                    component.getLicense(),
                    asset == null ? null : asset.getId().toString(),
                    asset == null ? null : asset.getName(),
                    asset == null ? List.of() : bomTypesByAsset.getOrDefault(asset.getId(), List.of()).stream().distinct().sorted().toList(),
                    projectedInventory != null && Boolean.TRUE.equals(projectedInventory.getIsEol()),
                    projectedInventory == null || projectedInventory.getEolSupportEndDate() == null ? null : projectedInventory.getEolSupportEndDate().toString(),
                    critical,
                    high,
                    medium,
                    low,
                    componentVulnerabilities.size(),
                    componentVulnerabilities.isEmpty() ? "UNCHECKED" : "APPLICABLE",
                    toApplicationRiskLevel(score)
            );
        }).toList();
    }

    private Map<UUID, List<BomComponentVulnerabilityLink>> loadLinksByComponent(List<BomComponent> components) {
        if (components.isEmpty()) {
            return Map.of();
        }
        return bomComponentVulnerabilityLinkRepository.findByBomComponentIdIn(
                        components.stream().map(BomComponent::getId).toList())
                .stream()
                .collect(Collectors.groupingBy(BomComponentVulnerabilityLink::getBomComponentId));
    }

    private Map<String, Vulnerability> loadVulnerabilitiesByExternalId(List<BomComponentVulnerabilityLink> links) {
        if (links == null || links.isEmpty()) {
            return Map.of();
        }
        return vulnerabilityRepository.findByExternalIdIn(
                        links.stream().map(BomComponentVulnerabilityLink::getVulnerabilityKey).distinct().toList())
                .stream()
                .collect(Collectors.toMap(Vulnerability::getExternalId, Function.identity(), (left, right) -> left));
    }

    private InventoryComponent resolveProjectedInventoryComponent(Tenant tenant, UUID assetId, BomComponent component) {
        if (assetId == null) {
            return null;
        }
        List<InventoryComponent> matches = inventoryComponentRepository.findActiveByTenantAssetAndComponentNameVersion(
                tenant.getId(),
                assetId,
                InventoryComponentStatus.ACTIVE,
                component.getName(),
                component.getVersion()
        );
        return matches.isEmpty() ? null : matches.get(0);
    }

    private String ecosystemFor(BomComponent component) {
        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(component.getPurl());
        if (parsedPurl != null && parsedPurl.ecosystem() != null && !"unknown".equals(parsedPurl.ecosystem())) {
            return parsedPurl.ecosystem();
        }
        return "generic";
    }

    private String normalizedNameFor(BomComponent component) {
        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(component.getPurl());
        if (parsedPurl != null && parsedPurl.packageName() != null && !"unknown".equals(parsedPurl.packageName())) {
            String namespace = parsedPurl.namespace();
            return namespace == null || namespace.isBlank()
                    ? parsedPurl.packageName()
                    : namespace + "/" + parsedPurl.packageName();
        }
        return component.getName();
    }

    private BomInventoryItemResponse toInventoryItem(BomIngestionRecord r) {
        long evidenceCount = bomComponentEvidenceRepository.countByBomId(r.getId());
        long vulnerabilityLinkCount = bomComponentVulnerabilityLinkRepository.countByBomId(r.getId());
        long correlatedComponentCount = bomComponentRepository.findByBomIdAndActiveTrue(r.getId()).stream()
                .filter(component -> component.getWorkflowStatus() != com.prototype.vulnwatch.domain.BomWorkflowStatus.DISCOVERED)
                .count();
        BomInspectionResponse inspection = sbomParserService.inspectResolved(
                r.getFormat() != null ? r.getFormat().name() : null,
                r.getFormatVersion(),
                r.getSpecFamily() != null ? r.getSpecFamily().name() : null,
                r.getDocumentFormat() != null ? r.getDocumentFormat().name() : null
        );
        return new BomInventoryItemResponse(
                r.getId(),
                r.getAssetId(),
                r.getBomType() != null ? r.getBomType().name() : null,
                r.getFormat() != null ? r.getFormat().name() : null,
                r.getFormatVersion(),
                r.getSpecFamily() != null ? r.getSpecFamily().name() : null,
                r.getDocumentFormat() != null ? r.getDocumentFormat().name() : null,
                r.getSerialNumber(),
                r.getSupplier(),
                r.getSourceMethod(),
                r.getSourceType() != null ? r.getSourceType().name() : null,
                r.getSourceSystem(),
                r.getSourceUrl(),
                inspection.supportLevel(),
                inspection.supported(),
                r.getComponentCount(),
                evidenceCount,
                vulnerabilityLinkCount,
                correlatedComponentCount,
                r.getStatus().name(),
                r.getIngestedAt(),
                r.getIngestedBy()
        );
    }

    private BomComponentResponse toComponentResponse(
            com.prototype.vulnwatch.domain.BomComponent c,
            Map<UUID, Integer> vulnerabilityCountByComponent,
            Map<UUID, Integer> evidenceCountByComponent,
            Map<UUID, String> workflowStatusByComponent
    ) {
        return new BomComponentResponse(
                c.getId(),
                c.getName(),
                c.getVersion(),
                c.getPurl(),
                c.getCpe(),
                c.getLicense(),
                c.getSupplier(),
                c.getComponentType(),
                c.getCategory() != null ? c.getCategory().name() : null,
                workflowStatusByComponent.getOrDefault(c.getId(), c.getWorkflowStatus().name()),
                vulnerabilityCountByComponent.getOrDefault(c.getId(), 0),
                evidenceCountByComponent.getOrDefault(c.getId(), 0),
                c.isActive()
        );
    }

    private <T> Map<UUID, Integer> toCountMap(Collection<T> rows, Function<T, UUID> idExtractor) {
        return rows.stream().collect(Collectors.toMap(
                idExtractor,
                row -> 1,
                Integer::sum
        ));
    }

    private List<BomDashboardBreakdownItemResponse> toBreakdown(Map<String, Long> counts) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .map(entry -> new BomDashboardBreakdownItemResponse(entry.getKey(), entry.getKey().replace('_', ' '), entry.getValue()))
                .toList();
    }

    private BomLineageItemResponse toLineageItem(BomIngestionRecord record) {
        return new BomLineageItemResponse(
                record.getId(),
                record.getPreviousBomId(),
                record.getSupersededBy(),
                record.getBomType() != null ? record.getBomType().name() : null,
                record.getStatus() != null ? record.getStatus().name() : null,
                record.getFormat() != null ? record.getFormat().name() : null,
                record.getFormatVersion(),
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null,
                record.getSourceType() != null ? record.getSourceType().name() : null,
                record.getSourceSystem(),
                record.getSourceReference(),
                record.getChecksumSha256(),
                record.getComponentCount(),
                record.getIngestedAt()
        );
    }

    private String coalesce(String left, String right) {
        return left != null && !left.isBlank() ? left : right;
    }
}
