package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareModel;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryComponentFilterValuesResponse;
import com.prototype.vulnwatch.dto.InventoryComponentPageResponse;
import com.prototype.vulnwatch.dto.InventoryComponentResponse;
import com.prototype.vulnwatch.dto.SoftwareModelPageResponse;
import com.prototype.vulnwatch.dto.SoftwareModelResponse;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SoftwareModelRepository;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InventoryService {

    private final InventoryComponentRepository inventoryComponentRepository;
    private final SoftwareModelRepository softwareModelRepository;

    public InventoryService(
            InventoryComponentRepository inventoryComponentRepository,
            SoftwareModelRepository softwareModelRepository
    ) {
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.softwareModelRepository = softwareModelRepository;
    }

    @Transactional(readOnly = true)
    public InventoryComponentPageResponse listComponentsPage(
            Tenant tenant,
            AssetType assetType,
            InventoryComponentStatus componentStatus,
            String sourceSystem,
            int page,
            int size
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(200, Math.max(1, size));
        String normalizedSourceSystem = sourceSystem == null || sourceSystem.isBlank()
                ? null
                : sourceSystem.trim();
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "lastObservedAt"));
        Page<InventoryComponent> componentPage = inventoryComponentRepository.findPageByFilters(
                tenant,
                assetType,
                componentStatus,
                normalizedSourceSystem,
                pageable
        );
        List<InventoryComponentResponse> items = componentPage.getContent().stream()
                .map(this::toInventoryComponentResponse)
                .toList();
        return new InventoryComponentPageResponse(
                items,
                componentPage.getNumber(),
                componentPage.getSize(),
                componentPage.getTotalElements(),
                componentPage.getTotalPages()
        );
    }

    @Transactional(readOnly = true)
    public SoftwareModelPageResponse listSoftwareModelsPage(Tenant tenant, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(200, Math.max(1, size));
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "updatedAt"));
        Page<SoftwareModel> modelPage = softwareModelRepository.findAll(pageable);
        List<SoftwareModel> models = modelPage.getContent();

        List<InventoryComponent> components = models.isEmpty()
                ? List.of()
                : inventoryComponentRepository.findByTenantAndSoftwareModel_IdIn(
                        tenant,
                        models.stream().map(SoftwareModel::getId).toList());

        Map<UUID, ModelStats> statsByModel = new HashMap<>();
        for (InventoryComponent component : components) {
            SoftwareModel model = component.getSoftwareModel();
            if (model == null) {
                continue;
            }
            ModelStats stats = statsByModel.computeIfAbsent(model.getId(), ignored -> new ModelStats());
            stats.totalComponents += 1;
            if (component.getComponentStatus() == InventoryComponentStatus.ACTIVE) {
                stats.activeComponents += 1;
            }
            if (component.getAsset() != null && component.getAsset().getId() != null) {
                stats.assetIds.add(component.getAsset().getId());
            }
        }

        List<SoftwareModelResponse> items = models.stream()
                .map(model -> {
                    ModelStats stats = statsByModel.getOrDefault(model.getId(), new ModelStats());
                    return new SoftwareModelResponse(
                            model.getId(),
                            model.getNormalizedKey(),
                            model.getCanonicalPublisher(),
                            model.getCanonicalProduct(),
                            model.getPrimaryIdentifierType(),
                            model.getPrimaryIdentifier(),
                            stats.totalComponents,
                            stats.activeComponents,
                            stats.assetIds.size(),
                            model.getCreatedAt(),
                            model.getUpdatedAt()
                    );
                })
                .toList();

        return new SoftwareModelPageResponse(
                items,
                modelPage.getNumber(),
                modelPage.getSize(),
                modelPage.getTotalElements(),
                modelPage.getTotalPages()
        );
    }

    @Transactional(readOnly = true)
    public InventoryComponentFilterValuesResponse listComponentFilterValues(Tenant tenant) {
        LinkedHashSet<String> assetTypes = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctAssetTypesByTenant(tenant).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(assetTypes::add);
        for (AssetType assetType : AssetType.values()) {
            assetTypes.add(assetType.name());
        }

        LinkedHashSet<String> componentStatuses = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctComponentStatusesByTenant(tenant).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(componentStatuses::add);
        for (InventoryComponentStatus status : InventoryComponentStatus.values()) {
            componentStatuses.add(status.name());
        }

        LinkedHashSet<String> sourceSystems = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctSourceSystemsByTenant(tenant).stream()
                .filter(this::hasText)
                .map(this::normalizeSourceSystem)
                .forEach(sourceSystems::add);
        sourceSystems.add("upload");
        sourceSystems.add("api");
        sourceSystems.add("github");

        return new InventoryComponentFilterValuesResponse(
                sortByPreferredOrder(assetTypes, List.of("APPLICATION", "HOST", "CONTAINER_IMAGE")),
                sortByPreferredOrder(componentStatuses, List.of("ACTIVE", "RETIRED")),
                sourceSystems.stream().sorted().toList()
        );
    }

    private InventoryComponentResponse toInventoryComponentResponse(InventoryComponent component) {
        SbomUpload upload = component.getSbomUpload();
        SoftwareIdentity identity = component.getSoftwareIdentity();
        return new InventoryComponentResponse(
                component.getId(),
                component.getAsset().getId(),
                component.getAsset().getName(),
                component.getAsset().getIdentifier(),
                component.getAsset().getType().name(),
                component.getComponentStatus().name(),
                component.getEcosystem(),
                component.getPackageName(),
                component.getVersion(),
                component.getNormalizedName(),
                component.getNormalizedVersion(),
                component.getSoftwareModelResult(),
                component.getPurl(),
                component.getComponentDigest(),
                identity == null ? null : identity.getDisplayName(),
                upload == null ? null : upload.getIngestionSourceSystem(),
                upload == null ? null : upload.getIngestionSourceType(),
                upload == null ? null : upload.getSourceReference(),
                upload == null ? null : upload.getUploadedAt(),
                component.getLastObservedAt(),
                component.getRetiredAt()
        );
    }

    private List<String> sortByPreferredOrder(Set<String> values, List<String> preferredOrder) {
        LinkedHashSet<String> remaining = new LinkedHashSet<>(values);
        List<String> sorted = new ArrayList<>();
        for (String preferredValue : preferredOrder) {
            if (remaining.remove(preferredValue)) {
                sorted.add(preferredValue);
            }
        }
        sorted.addAll(remaining.stream().sorted().toList());
        return sorted;
    }

    private String normalizeSourceSystem(String sourceSystem) {
        return sourceSystem.trim()
                .toLowerCase(Locale.ROOT)
                .replace('_', '-')
                .replace(' ', '-');
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static final class ModelStats {
        private int totalComponents;
        private int activeComponents;
        private final Set<UUID> assetIds = new HashSet<>();
    }
}
