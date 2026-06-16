package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.EolRelease;
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
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
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
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final EolReleaseRepository eolReleaseRepository;
    private final FindingRepository findingRepository;

    public BomInventoryReadService(
            BomIngestionRecordRepository bomRecordRepository,
            BomComponentRepository bomComponentRepository,
            BomComponentEvidenceRepository bomComponentEvidenceRepository,
            BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository,
            BomComponentWorkflowRepository bomComponentWorkflowRepository,
            SbomParserService sbomParserService,
            AssetRepository assetRepository,
            InventoryComponentRepository inventoryComponentRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            EolReleaseRepository eolReleaseRepository,
            FindingRepository findingRepository
    ) {
        this.bomRecordRepository = bomRecordRepository;
        this.bomComponentRepository = bomComponentRepository;
        this.bomComponentEvidenceRepository = bomComponentEvidenceRepository;
        this.bomComponentVulnerabilityLinkRepository = bomComponentVulnerabilityLinkRepository;
        this.bomComponentWorkflowRepository = bomComponentWorkflowRepository;
        this.sbomParserService = sbomParserService;
        this.assetRepository = assetRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.eolReleaseRepository = eolReleaseRepository;
        this.findingRepository = findingRepository;
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
        record.setStatus(BomStatus.SUPERSEDED);
        bomRecordRepository.save(record);
    }

    @Transactional(readOnly = true)
    public List<BomComponentSummaryResponse> getBomComponentSummaries(Tenant tenant, int page, int size) {
        Pageable pageable = PageRequest.of(page, Math.min(size, 2000));
        List<InventoryComponent> components = inventoryComponentRepository
                .findActiveApplicationComponentsWithAsset(tenant.getId(), InventoryComponentStatus.ACTIVE, pageable);
        if (components.isEmpty()) {
            return List.of();
        }

        List<UUID> componentIds = components.stream().map(InventoryComponent::getId).toList();
        List<UUID> assetIds = components.stream().map(c -> c.getAsset().getId()).distinct().toList();

        // Fetch all active BOM records once to build two lookup maps
        List<BomIngestionRecord> activeBomRecords = bomRecordRepository
                .findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE);

        // Primary: assetId → bomTypes (works when assetId is set on the record)
        Map<UUID, List<String>> bomTypesByAsset = activeBomRecords.stream()
                .filter(b -> b.getAssetId() != null && assetIds.contains(b.getAssetId()))
                .collect(Collectors.groupingBy(
                        BomIngestionRecord::getAssetId,
                        Collectors.mapping(
                                b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN",
                                Collectors.toList()
                        )
                ));

        // Fallback: sbomUploadId → bomType (for records where assetId is null)
        Map<UUID, String> bomTypeBySbomUpload = activeBomRecords.stream()
                .filter(b -> b.getSbomUploadId() != null)
                .collect(Collectors.toMap(
                        BomIngestionRecord::getSbomUploadId,
                        b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN",
                        (first, second) -> first
                ));

        Map<UUID, List<ComponentVulnerabilityState>> statesByComponent = new HashMap<>();
        componentVulnerabilityStateRepository
                .findWithVulnerabilityByTenantIdAndComponentIds(tenant.getId(), componentIds)
                .forEach(s -> statesByComponent
                        .computeIfAbsent(s.getComponent().getId(), k -> new ArrayList<>())
                        .add(s));

        // Count open findings by ecosystem+packageName (matches how FindingsTab queries)
        Map<String, Long> findingCountByPackageKey = findingRepository
                .countOpenByEcosystemPackageForTenant(tenant.getId())
                .stream()
                .collect(Collectors.toMap(
                        row -> ((String) row[0]) + ":" + ((String) row[1]),
                        row -> (Long) row[2]
                ));

        return components.stream().map(c -> {
            List<ComponentVulnerabilityState> states = statesByComponent.getOrDefault(c.getId(), List.of());
            List<ComponentVulnerabilityState> applicable = states.stream()
                    .filter(s -> s.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                    .toList();
            int critical = (int) applicable.stream()
                    .filter(s -> "CRITICAL".equals(s.getVulnerability().getSeverity())).count();
            int high = (int) applicable.stream()
                    .filter(s -> "HIGH".equals(s.getVulnerability().getSeverity())).count();
            int medium = (int) applicable.stream()
                    .filter(s -> "MEDIUM".equals(s.getVulnerability().getSeverity())).count();
            int low = (int) applicable.stream()
                    .filter(s -> "LOW".equals(s.getVulnerability().getSeverity())).count();

            String correlationState;
            if (!applicable.isEmpty()) {
                correlationState = "APPLICABLE";
            } else if (states.stream().anyMatch(s -> s.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE)) {
                correlationState = "NOT_APPLICABLE";
            } else if (!states.isEmpty()) {
                correlationState = "UNKNOWN";
            } else {
                correlationState = "UNCHECKED";
            }

            List<String> bomTypes = bomTypesByAsset.getOrDefault(c.getAsset().getId(), List.of());
            if (bomTypes.isEmpty() && c.getSbomUpload() != null) {
                String fallback = bomTypeBySbomUpload.get(c.getSbomUpload().getId());
                if (fallback != null) {
                    bomTypes = List.of(fallback);
                }
            }
            bomTypes = bomTypes.stream().distinct().sorted().toList();
            double score = computeApplicationRiskScore(critical, high, medium, low);

            String pkgKey = (c.getEcosystem() != null ? c.getEcosystem().toLowerCase() : "") + ":" + c.getPackageName().toLowerCase();
            int findingCount = findingCountByPackageKey.getOrDefault(pkgKey, 0L).intValue();

            return new BomComponentSummaryResponse(
                    c.getId().toString(),
                    c.getPackageName(),
                    c.getVersion(),
                    c.getPurl(),
                    c.getEcosystem(),
                    c.getLicense(),
                    c.getAsset().getId().toString(),
                    c.getAsset().getName(),
                    bomTypes,
                    Boolean.TRUE.equals(c.getIsEol()),
                    c.getEolSupportEndDate() != null ? c.getEolSupportEndDate().toString() : null,
                    critical, high, medium, low, applicable.size(),
                    correlationState,
                    toApplicationRiskLevel(score),
                    findingCount
            );
        }).toList();
    }

    @Transactional(readOnly = true)
    public List<ApplicationRiskResponse> getApplicationRisk(Tenant tenant) {
        List<Asset> assets = assetRepository.findByTenant(tenant).stream()
                .filter(a -> a.getType() == AssetType.APPLICATION && a.getState() == AssetState.ACTIVE)
                .toList();
        if (assets.isEmpty()) {
            return List.of();
        }
        List<UUID> assetIds = assets.stream().map(Asset::getId).toList();

        List<BomIngestionRecord> activeBoms = bomRecordRepository
                .findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)
                .stream()
                .filter(b -> b.getAssetId() != null && assetIds.contains(b.getAssetId()))
                .toList();
        Map<UUID, List<String>> bomTypesByAsset = activeBoms.stream()
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

        List<InventoryComponent> allComponents = inventoryComponentRepository.findByAsset_IdIn(assetIds);
        Map<UUID, Long> totalByAsset = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .collect(Collectors.groupingBy(c -> c.getAsset().getId(), Collectors.counting()));
        Map<UUID, Long> eolByAsset = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE
                        && Boolean.TRUE.equals(c.getIsEol()))
                .collect(Collectors.groupingBy(c -> c.getAsset().getId(), Collectors.counting()));

        List<UUID> allActiveComponentIds = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .map(InventoryComponent::getId)
                .toList();
        Map<UUID, UUID> componentToAsset = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .collect(Collectors.toMap(InventoryComponent::getId, c -> c.getAsset().getId()));
        Set<UUID> vulnerableComponentIds = new HashSet<>();
        if (!allActiveComponentIds.isEmpty()) {
            componentVulnerabilityStateRepository
                    .findSummariesByTenantIdAndComponentIds(tenant.getId(), allActiveComponentIds)
                    .stream()
                    .filter(s -> s.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                    .forEach(s -> vulnerableComponentIds.add(s.getComponentId()));
        }
        Map<UUID, Long> vulnerableByAsset = vulnerableComponentIds.stream()
                .filter(componentToAsset::containsKey)
                .collect(Collectors.groupingBy(componentToAsset::get, Collectors.counting()));

        Map<UUID, Long> findingCountByAsset = findingRepository
                .countOpenFindingsByAssetIds(tenant.getId(), assetIds)
                .stream()
                .collect(Collectors.toMap(
                        row -> (UUID) row[0],
                        row -> (Long) row[1]
                ));

        return assets.stream().map(asset -> {
            List<ComponentVulnerabilityStateRepository.HostApplicableCveRow> cves =
                    componentVulnerabilityStateRepository
                            .findHostApplicableCvesByTenantIdAndAssetId(tenant.getId(), asset.getId());
            Map<UUID, String> severityByVulnId = cves.stream()
                    .collect(Collectors.toMap(
                            ComponentVulnerabilityStateRepository.HostApplicableCveRow::getVulnerabilityId,
                            c -> c.getSeverity() != null ? c.getSeverity() : "UNKNOWN",
                            (a, b) -> a
                    ));
            int critical = (int) severityByVulnId.values().stream().filter("CRITICAL"::equals).count();
            int high = (int) severityByVulnId.values().stream().filter("HIGH"::equals).count();
            int medium = (int) severityByVulnId.values().stream().filter("MEDIUM"::equals).count();
            int low = (int) severityByVulnId.values().stream()
                    .filter(s -> "LOW".equals(s) || "NONE".equals(s)).count();
            int total = severityByVulnId.size();
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
                    totalByAsset.getOrDefault(asset.getId(), 0L).intValue(),
                    vulnerableByAsset.getOrDefault(asset.getId(), 0L).intValue(),
                    eolByAsset.getOrDefault(asset.getId(), 0L).intValue(),
                    critical, high, medium, low, total,
                    riskScore,
                    toApplicationRiskLevel(riskScore),
                    lastIngested != null ? lastIngested.toString() : null,
                    findingCountByAsset.getOrDefault(asset.getId(), 0L).intValue()
            );
        })
        .sorted(Comparator.comparingDouble(ApplicationRiskResponse::riskScore).reversed())
        .toList();
    }

    @Transactional(readOnly = true)
    public List<ApplicationCveResponse> getApplicationCves(Tenant tenant, UUID assetId) {
        return componentVulnerabilityStateRepository
                .findHostApplicableCvesByTenantIdAndAssetId(tenant.getId(), assetId)
                .stream()
                .map(r -> new ApplicationCveResponse(
                        r.getVulnerabilityId().toString(),
                        r.getComponentId().toString(),
                        r.getExternalId(),
                        r.getSeverity(),
                        r.getCvssScore(),
                        r.getEpssScore(),
                        r.getPackageName(),
                        r.getVersion(),
                        r.getLastEvaluatedAt() != null ? r.getLastEvaluatedAt().toString() : null
                ))
                .toList();
    }

    @Transactional(readOnly = true)
    public BomComponentDetailResponse getComponentDetail(Tenant tenant, UUID componentId) {
        InventoryComponent component = inventoryComponentRepository.findById(componentId)
                .filter(c -> c.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Component not found"));

        List<BomIngestionRecord> assetBoms = bomRecordRepository
                .findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)
                .stream()
                .filter(b -> b.getAssetId() != null && b.getAssetId().equals(component.getAsset().getId()))
                .toList();
        List<String> bomTypes = assetBoms.stream()
                .map(b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN")
                .distinct().sorted().toList();

        List<ComponentVulnerabilityState> states = componentVulnerabilityStateRepository
                .findWithVulnerabilityByTenantIdAndComponentIds(tenant.getId(), List.of(componentId));

        List<ComponentVulnerabilityState> applicable = states.stream()
                .filter(s -> s.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                .toList();
        int critical = (int) applicable.stream().filter(s -> "CRITICAL".equals(s.getVulnerability().getSeverity())).count();
        int high    = (int) applicable.stream().filter(s -> "HIGH".equals(s.getVulnerability().getSeverity())).count();
        int medium  = (int) applicable.stream().filter(s -> "MEDIUM".equals(s.getVulnerability().getSeverity())).count();
        int low     = (int) applicable.stream().filter(s -> "LOW".equals(s.getVulnerability().getSeverity())).count();
        double riskScore = computeApplicationRiskScore(critical, high, medium, low);

        String correlationState;
        if (!applicable.isEmpty()) {
            correlationState = "APPLICABLE";
        } else if (states.stream().anyMatch(s -> s.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE)) {
            correlationState = "NOT_APPLICABLE";
        } else if (!states.isEmpty()) {
            correlationState = "UNKNOWN";
        } else {
            correlationState = "UNCHECKED";
        }

        List<BomComponentCveSummary> cves = states.stream()
                .sorted(Comparator.comparing(s -> s.getVulnerability().getSeverity() != null ? s.getVulnerability().getSeverity() : ""))
                .map(s -> new BomComponentCveSummary(
                        s.getVulnerability().getId().toString(),
                        s.getVulnerability().getExternalId(),
                        s.getVulnerability().getSeverity(),
                        s.getVulnerability().getTitle(),
                        s.getApplicabilityState().name(),
                        s.getVulnerability().getEpssScore(),
                        s.getVulnerability().getCvssScore()
                ))
                .toList();

        List<EolReleaseSummary> eolReleases = List.of();
        if (component.getEolSlug() != null && !component.getEolSlug().isBlank()) {
            eolReleases = eolReleaseRepository.findByProductSlug(component.getEolSlug()).stream()
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

        Asset asset = component.getAsset();
        return new BomComponentDetailResponse(
                component.getId().toString(),
                component.getPackageName(),
                component.getPackageGroup(),
                component.getVersion(),
                component.getPurl(),
                component.getEcosystem(),
                component.getLicense(),
                component.getScope(),
                component.getNormalizedName(),
                component.getEolSlug(),
                component.getEolCycle(),
                Boolean.TRUE.equals(component.getIsEol()),
                component.getEolDate() != null ? component.getEolDate().toString() : null,
                component.getEolSupportEndDate() != null ? component.getEolSupportEndDate().toString() : null,
                component.getSupportPhase(),
                component.getEolCheckedAt() != null ? component.getEolCheckedAt().toString() : null,
                component.getIngestedAt().toString(),
                component.getLastObservedAt().toString(),
                asset.getId().toString(),
                asset.getName(),
                asset.getIdentifier(),
                asset.getType() != null ? asset.getType().name() : null,
                bomTypes,
                correlationState,
                toApplicationRiskLevel(riskScore),
                critical, high, medium, low, states.size(),
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
