package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomComponentEvidence;
import com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink;
import com.prototype.vulnwatch.domain.BomComponentWorkflow;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomEvidenceComponentResponse;
import com.prototype.vulnwatch.dto.BomEvidenceDocumentResponse;
import com.prototype.vulnwatch.dto.BomEvidenceSummaryResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentityAssetResponse;
import com.prototype.vulnwatch.repo.BomComponentEvidenceRepository;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import com.prototype.vulnwatch.repo.BomComponentVulnerabilityLinkRepository;
import com.prototype.vulnwatch.repo.BomComponentWorkflowRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class BomEvidenceReadService {

    private final BomIngestionRecordRepository bomIngestionRecordRepository;
    private final BomComponentRepository bomComponentRepository;
    private final BomComponentEvidenceRepository bomComponentEvidenceRepository;
    private final BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository;
    private final BomComponentWorkflowRepository bomComponentWorkflowRepository;

    public BomEvidenceReadService(
            BomIngestionRecordRepository bomIngestionRecordRepository,
            BomComponentRepository bomComponentRepository,
            BomComponentEvidenceRepository bomComponentEvidenceRepository,
            BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository,
            BomComponentWorkflowRepository bomComponentWorkflowRepository
    ) {
        this.bomIngestionRecordRepository = bomIngestionRecordRepository;
        this.bomComponentRepository = bomComponentRepository;
        this.bomComponentEvidenceRepository = bomComponentEvidenceRepository;
        this.bomComponentVulnerabilityLinkRepository = bomComponentVulnerabilityLinkRepository;
        this.bomComponentWorkflowRepository = bomComponentWorkflowRepository;
    }

    public BomEvidenceSummaryResponse summarizeForHost(Tenant tenant, UUID assetId) {
        if (tenant == null || tenant.getId() == null || assetId == null) {
            return emptySummary();
        }
        List<BomIngestionRecord> documents = bomIngestionRecordRepository
                .findByTenant_IdAndAssetIdInAndStatusOrderByIngestedAtDesc(tenant.getId(), List.of(assetId), BomStatus.ACTIVE);
        return buildSummary(documents, null);
    }

    public BomEvidenceSummaryResponse summarizeForSoftware(Tenant tenant, UUID softwareIdentityId, List<SoftwareIdentityAssetResponse> assets) {
        if (tenant == null || tenant.getId() == null || softwareIdentityId == null || assets == null || assets.isEmpty()) {
            return emptySummary();
        }
        Set<UUID> assetIds = assets.stream()
                .map(SoftwareIdentityAssetResponse::assetId)
                .collect(Collectors.toSet());
        if (assetIds.isEmpty()) {
            return emptySummary();
        }
        List<BomIngestionRecord> documents = bomIngestionRecordRepository
                .findByTenant_IdAndAssetIdInAndStatusOrderByIngestedAtDesc(tenant.getId(), assetIds, BomStatus.ACTIVE);
        if (documents.isEmpty()) {
            return emptySummary();
        }

        Set<String> packageNames = assets.stream()
                .flatMap(asset -> List.of(asset.packageName(), asset.version(), asset.sourceSystem()).stream())
                .filter(value -> value != null && !value.isBlank())
                .map(this::normalize)
                .collect(Collectors.toSet());
        return buildSummary(documents, packageNames);
    }

    private BomEvidenceSummaryResponse buildSummary(List<BomIngestionRecord> documents, Set<String> packageFilters) {
        if (documents == null || documents.isEmpty()) {
            return emptySummary();
        }
        List<UUID> bomIds = documents.stream().map(BomIngestionRecord::getId).toList();
        List<BomComponent> allComponents = bomComponentRepository.findByBomIdInAndActiveTrue(bomIds);
        List<BomComponent> matchedComponents = filterComponents(allComponents, packageFilters);
        if (packageFilters != null && matchedComponents.isEmpty()) {
            return emptySummary();
        }

        List<UUID> componentIds = matchedComponents.stream().map(BomComponent::getId).toList();
        Map<UUID, List<BomComponentEvidence>> evidenceByComponent = groupByComponent(
                bomComponentEvidenceRepository.findByBomComponentIdIn(componentIds)
        );
        Map<UUID, List<BomComponentVulnerabilityLink>> vulnerabilityByComponent = groupByComponentLink(
                bomComponentVulnerabilityLinkRepository.findByBomComponentIdIn(componentIds)
        );
        Map<UUID, List<BomComponentWorkflow>> workflowByComponent = groupByComponentWorkflow(
                bomComponentWorkflowRepository.findByBomComponentIdIn(componentIds)
        );

        List<BomEvidenceDocumentResponse> documentRows = buildDocumentRows(documents, matchedComponents, evidenceByComponent, vulnerabilityByComponent);
        List<BomEvidenceComponentResponse> componentRows = buildComponentRows(documents, matchedComponents, evidenceByComponent, vulnerabilityByComponent, workflowByComponent);

        long evidenceCount = componentRows.stream().mapToLong(BomEvidenceComponentResponse::evidenceCount).sum();
        long vulnerabilityLinkCount = componentRows.stream().mapToLong(BomEvidenceComponentResponse::vulnerabilityCount).sum();
        long componentsInWorkflow = componentRows.stream()
                .filter(component -> component.workflowStatus() != null && !component.workflowStatus().isBlank())
                .count();

        return new BomEvidenceSummaryResponse(
                documentRows.size(),
                componentRows.size(),
                evidenceCount,
                vulnerabilityLinkCount,
                componentsInWorkflow,
                documentRows,
                componentRows
        );
    }

    private List<BomComponent> filterComponents(List<BomComponent> components, Set<String> packageFilters) {
        if (packageFilters == null || packageFilters.isEmpty()) {
            return components;
        }
        return components.stream()
                .filter(component -> matchesPackageFilter(component, packageFilters))
                .toList();
    }

    private boolean matchesPackageFilter(BomComponent component, Set<String> packageFilters) {
        List<String> candidates = new ArrayList<>();
        candidates.add(component.getName());
        candidates.add(component.getVersion());
        candidates.add(component.getSupplier());
        candidates.add(component.getBomRef());
        candidates.add(component.getPurl());
        candidates.add(component.getCpe());
        candidates.add(component.getGroupName());
        return candidates.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(this::normalize)
                .anyMatch(candidate -> packageFilters.stream().anyMatch(filter ->
                        candidate.equals(filter) || candidate.contains(filter) || filter.contains(candidate)
                ));
    }

    private String normalize(String value) {
        return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "");
    }

    private Map<UUID, List<BomComponentEvidence>> groupByComponent(Collection<BomComponentEvidence> evidence) {
        Map<UUID, List<BomComponentEvidence>> grouped = new HashMap<>();
        for (BomComponentEvidence item : evidence) {
            grouped.computeIfAbsent(item.getBomComponentId(), ignored -> new ArrayList<>()).add(item);
        }
        return grouped;
    }

    private Map<UUID, List<BomComponentVulnerabilityLink>> groupByComponentLink(Collection<BomComponentVulnerabilityLink> links) {
        Map<UUID, List<BomComponentVulnerabilityLink>> grouped = new HashMap<>();
        for (BomComponentVulnerabilityLink item : links) {
            grouped.computeIfAbsent(item.getBomComponentId(), ignored -> new ArrayList<>()).add(item);
        }
        return grouped;
    }

    private Map<UUID, List<BomComponentWorkflow>> groupByComponentWorkflow(Collection<BomComponentWorkflow> workflows) {
        Map<UUID, List<BomComponentWorkflow>> grouped = new HashMap<>();
        for (BomComponentWorkflow item : workflows) {
            grouped.computeIfAbsent(item.getBomComponentId(), ignored -> new ArrayList<>()).add(item);
        }
        return grouped;
    }

    private List<BomEvidenceDocumentResponse> buildDocumentRows(
            List<BomIngestionRecord> documents,
            List<BomComponent> components,
            Map<UUID, List<BomComponentEvidence>> evidenceByComponent,
            Map<UUID, List<BomComponentVulnerabilityLink>> vulnerabilityByComponent
    ) {
        Map<UUID, List<BomComponent>> componentsByBom = components.stream()
                .collect(Collectors.groupingBy(BomComponent::getBomId, LinkedHashMap::new, Collectors.toList()));

        return documents.stream()
                .filter(document -> componentsByBom.containsKey(document.getId()))
                .map(document -> {
                    List<BomComponent> documentComponents = componentsByBom.getOrDefault(document.getId(), List.of());
                    long evidenceCount = documentComponents.stream()
                            .mapToLong(component -> evidenceByComponent.getOrDefault(component.getId(), List.of()).size())
                            .sum();
                    long vulnerabilityCount = documentComponents.stream()
                            .mapToLong(component -> vulnerabilityByComponent.getOrDefault(component.getId(), List.of()).size())
                            .sum();
                    return new BomEvidenceDocumentResponse(
                            document.getId(),
                            document.getAssetId(),
                            document.getBomType() == null ? null : document.getBomType().name(),
                            document.getSpecFamily() == null ? null : document.getSpecFamily().name(),
                            document.getDocumentFormat() == null ? null : document.getDocumentFormat().name(),
                            document.getSourceType() == null ? null : document.getSourceType().name(),
                            document.getSourceSystem(),
                            document.getSourceReference(),
                            document.getSourceLabel(),
                            document.getDocumentName(),
                            document.getChecksumSha256(),
                            documentComponents.size(),
                            evidenceCount,
                            vulnerabilityCount,
                            document.getIngestedAt()
                    );
                })
                .sorted(Comparator.comparing(BomEvidenceDocumentResponse::ingestedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();
    }

    private List<BomEvidenceComponentResponse> buildComponentRows(
            List<BomIngestionRecord> documents,
            List<BomComponent> components,
            Map<UUID, List<BomComponentEvidence>> evidenceByComponent,
            Map<UUID, List<BomComponentVulnerabilityLink>> vulnerabilityByComponent,
            Map<UUID, List<BomComponentWorkflow>> workflowByComponent
    ) {
        Map<UUID, BomIngestionRecord> documentById = documents.stream()
                .collect(Collectors.toMap(BomIngestionRecord::getId, document -> document));

        return components.stream()
                .map(component -> {
                    BomIngestionRecord document = documentById.get(component.getBomId());
                    List<BomComponentWorkflow> workflows = workflowByComponent.getOrDefault(component.getId(), List.of());
                    String workflowStatus = workflows.stream()
                            .map(BomComponentWorkflow::getWorkflowStatus)
                            .filter(java.util.Objects::nonNull)
                            .map(Enum::name)
                            .max(String::compareTo)
                            .orElseGet(() -> component.getWorkflowStatus() == null ? null : component.getWorkflowStatus().name());
                    return new BomEvidenceComponentResponse(
                            component.getId(),
                            component.getBomId(),
                            component.getName(),
                            component.getVersion(),
                            component.getSupplier(),
                            component.getPurl(),
                            component.getCpe(),
                            component.getLicense(),
                            workflowStatus,
                            evidenceByComponent.getOrDefault(component.getId(), List.of()).size(),
                            vulnerabilityByComponent.getOrDefault(component.getId(), List.of()).size(),
                            document == null ? null : document.getSourceSystem(),
                            document == null ? null : document.getSourceReference()
                    );
                })
                .sorted(Comparator
                        .comparing(BomEvidenceComponentResponse::vulnerabilityCount, Comparator.reverseOrder())
                        .thenComparing(BomEvidenceComponentResponse::name, Comparator.nullsLast(String::compareToIgnoreCase)))
                .limit(25)
                .toList();
    }

    private BomEvidenceSummaryResponse emptySummary() {
        return new BomEvidenceSummaryResponse(0L, 0L, 0L, 0L, 0L, List.of(), List.of());
    }
}
