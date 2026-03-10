package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryComponentFilterValuesResponse;
import com.prototype.vulnwatch.dto.InventoryComponentPageResponse;
import com.prototype.vulnwatch.dto.InventoryComponentResponse;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InventoryService {

    private final InventoryComponentRepository inventoryComponentRepository;

    public InventoryService(InventoryComponentRepository inventoryComponentRepository) {
        this.inventoryComponentRepository = inventoryComponentRepository;
    }

    @Transactional(readOnly = true)
    public InventoryComponentPageResponse listComponentsPage(
            Tenant tenant,
            List<AssetType> assetTypes,
            List<InventoryComponentStatus> componentStatuses,
            List<String> sourceSystems,
            List<String> ecosystems,
            String query,
            int page,
            int size
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(200, Math.max(1, size));
        List<AssetType> normalizedAssetTypes = sanitizeEnumValues(assetTypes);
        List<InventoryComponentStatus> normalizedComponentStatuses = sanitizeEnumValues(componentStatuses);
        List<String> normalizedSourceSystems = normalizeValueList(sourceSystems, this::normalizeSourceSystem);
        List<String> normalizedEcosystems = normalizeValueList(ecosystems, this::normalizeExactValue);
        String normalizedQueryPattern = buildQueryPattern(query);
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "lastObservedAt"));
        Page<InventoryComponent> componentPage = inventoryComponentRepository.findPageByFilters(
                tenant,
                normalizedAssetTypes,
                normalizedComponentStatuses,
                normalizedSourceSystems,
                normalizedEcosystems,
                normalizedQueryPattern,
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

        LinkedHashSet<String> ecosystems = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctEcosystemsByTenant(tenant).stream()
                .filter(this::hasText)
                .map(this::normalizeExactValue)
                .forEach(ecosystems::add);

        return new InventoryComponentFilterValuesResponse(
                sortByPreferredOrder(assetTypes, List.of("APPLICATION", "HOST", "CONTAINER_IMAGE")),
                sortByPreferredOrder(componentStatuses, List.of("ACTIVE", "RETIRED")),
                sourceSystems.stream().sorted().toList(),
                ecosystems.stream().sorted().toList()
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

    private String normalizeExactValue(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String buildQueryPattern(String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        return "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
    }

    private <T> List<T> sanitizeEnumValues(List<T> values) {
        if (values == null) {
            return null;
        }
        List<T> normalized = values.stream()
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        return normalized.isEmpty() ? null : normalized;
    }

    private List<String> normalizeValueList(List<String> values, java.util.function.Function<String, String> normalizer) {
        if (values == null) {
            return null;
        }
        List<String> normalized = values.stream()
                .filter(this::hasText)
                .map(normalizer)
                .filter(this::hasText)
                .distinct()
                .toList();
        return normalized.isEmpty() ? null : normalized;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
