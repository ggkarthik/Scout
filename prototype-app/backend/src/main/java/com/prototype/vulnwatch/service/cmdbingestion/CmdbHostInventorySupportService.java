package com.prototype.vulnwatch.service.cmdbingestion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.DiscoveryModel;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.DiscoveryModelRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SoftwareInstanceRepository;
import com.prototype.vulnwatch.service.CmdbIngestionService;
import com.prototype.vulnwatch.service.HostSoftwareNormalizationService;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.stereotype.Service;

@Service
public class CmdbHostInventorySupportService {

    private final DiscoveryModelRepository discoveryModelRepository;
    private final SoftwareInstanceRepository softwareInstanceRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final ObjectMapper objectMapper;

    public CmdbHostInventorySupportService(
            DiscoveryModelRepository discoveryModelRepository,
            SoftwareInstanceRepository softwareInstanceRepository,
            InventoryComponentRepository inventoryComponentRepository,
            SbomUploadRepository sbomUploadRepository,
            ObjectMapper objectMapper
    ) {
        this.discoveryModelRepository = discoveryModelRepository;
        this.softwareInstanceRepository = softwareInstanceRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.objectMapper = objectMapper;
    }

    public List<ImportedRow> toImportedRows(List<Map<String, String>> rows) {
        if (rows == null || rows.isEmpty()) {
            return List.of();
        }
        List<ImportedRow> importedRows = new ArrayList<>(rows.size());
        for (Map<String, String> row : rows) {
            if (row == null || row.isEmpty()) {
                continue;
            }
            Map<String, String> normalized = new LinkedHashMap<>();
            row.forEach((key, value) -> normalized.put(normalizeHeader(key), blankToNull(value)));
            importedRows.add(new ImportedRow(normalized));
        }
        return importedRows;
    }

    public Map<UUID, Map<String, SoftwareInstance>> preloadSoftwareInstances(Tenant tenant, List<ResolvedInstallRow> resolvedRows) {
        Map<UUID, Map<String, SoftwareInstance>> indexed = new LinkedHashMap<>();
        if (tenant == null || tenant.getId() == null || resolvedRows.isEmpty()) {
            return indexed;
        }

        Set<UUID> ciIds = new LinkedHashSet<>();
        for (ResolvedInstallRow resolved : resolvedRows) {
            if (resolved != null && resolved.ci() != null && resolved.ci().getId() != null) {
                ciIds.add(resolved.ci().getId());
                indexed.computeIfAbsent(resolved.ci().getId(), ignored -> new LinkedHashMap<>());
            }
        }
        if (ciIds.isEmpty()) {
            return indexed;
        }

        for (SoftwareInstance instance : softwareInstanceRepository.findByTenant_IdAndCi_IdIn(tenant.getId(), ciIds)) {
            if (instance.getCi() == null || instance.getCi().getId() == null) {
                continue;
            }
            indexed.computeIfAbsent(instance.getCi().getId(), ignored -> new LinkedHashMap<>())
                    .put(softwareInstanceKey(
                            instance.getNormalizedProduct(),
                            blankToNull(instance.getNormalizedVersion()),
                            blankToNull(instance.getVersionEvidence())
                    ), instance);
        }
        return indexed;
    }

    public Map<UUID, Map<String, InventoryComponent>> preloadInventoryComponents(List<ResolvedInstallRow> resolvedRows) {
        Map<UUID, Map<String, InventoryComponent>> indexed = new LinkedHashMap<>();
        Set<UUID> assetIds = new LinkedHashSet<>();
        for (ResolvedInstallRow resolved : resolvedRows) {
            Asset asset = resolved == null || resolved.ci() == null ? null : resolved.ci().getAsset();
            if (asset == null || asset.getId() == null) {
                continue;
            }
            assetIds.add(asset.getId());
            indexed.computeIfAbsent(asset.getId(), ignored -> new LinkedHashMap<>());
        }
        if (assetIds.isEmpty()) {
            return indexed;
        }

        for (InventoryComponent component : inventoryComponentRepository.findByAsset_IdIn(assetIds)) {
            if (component.getAsset() == null || component.getAsset().getId() == null) {
                continue;
            }
            indexed.computeIfAbsent(component.getAsset().getId(), ignored -> new LinkedHashMap<>())
                    .put(componentKey(component), component);
        }
        return indexed;
    }

    public Map<String, DiscoveryModel> upsertDiscoveryModels(Tenant tenant, List<ImportedRow> rows) {
        if (rows.isEmpty()) {
            return Map.of();
        }
        Set<String> keys = new LinkedHashSet<>();
        for (ImportedRow row : rows) {
            String primaryKey = row.get("primary_key", "discovery_model_pk");
            if (hasText(primaryKey)) {
                keys.add(normalizeKey(primaryKey));
            }
        }
        Map<String, DiscoveryModel> existingByKey = new LinkedHashMap<>();
        if (!keys.isEmpty() && tenant != null && tenant.getId() != null) {
            for (DiscoveryModel existing : discoveryModelRepository.findByTenant_IdAndPrimaryKeyIn(tenant.getId(), keys)) {
                existingByKey.put(normalizeKey(existing.getPrimaryKey()), existing);
            }
        }
        for (ImportedRow row : rows) {
            String primaryKey = row.get("primary_key", "discovery_model_pk");
            if (!hasText(primaryKey)) {
                continue;
            }
            String normalizedPrimaryKey = normalizeKey(primaryKey);
            DiscoveryModel model = existingByKey.get(normalizedPrimaryKey);
            if (model == null) {
                model = new DiscoveryModel();
                model.setTenant(tenant);
                model.setPrimaryKey(normalizedPrimaryKey);
            }
            model.setNormalizationStatus(blankToNull(row.get("normalization_status")));
            model.setApproved(parseBoolean(row.get("approved"), false));
            model.setLowConfidence(parseBoolean(row.get("low_confidence"), false));
            model.setNormalizedProduct(blankToNull(row.get("normalized_product")));
            model.setNormalizedPublisher(blankToNull(row.get("normalized_publisher")));
            model.setNormalizedVersion(blankToNull(row.get("normalized_version")));
            model.setProductHash(blankToNull(lower(row.get("product_hash"))));
            model.setVersionHash(blankToNull(lower(row.get("version_hash"))));
            model.setFullVersion(blankToNull(row.get("full_version", "version")));
            model.setPlatform(blankToNull(row.get("platform")));
            model.setLanguage(blankToNull(row.get("language")));
            model.setMlModelVersion(blankToNull(row.get("ml_model_version")));
            model.setDisplayName(blankToNull(row.get("display_name", "name")));
            model.touch();
            model = discoveryModelRepository.save(model);
            existingByKey.put(normalizedPrimaryKey, model);
        }
        return existingByKey;
    }

    public ComponentUpsertResult upsertInventoryComponent(
            Asset asset,
            SbomUpload upload,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            SoftwareIdentity identity,
            boolean activeInstall,
            Map<UUID, Map<String, InventoryComponent>> existingComponentsByAssetId,
            Instant now
    ) {
        Map<String, InventoryComponent> componentsByKey = existingComponentsByAssetId.computeIfAbsent(
                asset.getId(),
                ignored -> new LinkedHashMap<>()
        );

        String key = componentKey(normalized.normalizedPublisher(), normalized.normalizedProduct(), normalized.normalizedVersion());
        InventoryComponent component = componentsByKey.get(key);
        boolean created = component == null;
        boolean updated = false;
        if (component == null) {
            component = new InventoryComponent();
            component.setTenant(asset.getTenant());
            component.setAsset(asset);
            component.setIngestedAt(now);
            componentsByKey.put(key, component);
        }

        updated |= setIfChanged(component.getSbomUpload(), upload, component::setSbomUpload);
        updated |= setIfChanged(component.getEcosystem(), normalized.normalizedPublisher(), component::setEcosystem);
        updated |= setIfChanged(component.getPackageName(), normalized.normalizedProduct(), component::setPackageName);
        updated |= setIfChanged(component.getVersion(), blankToNull(normalized.normalizedVersion()), component::setVersion);
        updated |= setIfChanged(component.getPurl(), normalized.purl(), component::setPurl);
        updated |= setIfChanged(component.getNormalizedName(), normalized.normalizedProduct(), component::setNormalizedName);
        updated |= setIfChanged(component.getNormalizedVersion(), blankToNull(normalized.normalizedVersion()), component::setNormalizedVersion);
        updated |= setIfChanged(component.getSoftwareIdentity(), identity, component::setSoftwareIdentity);
        updated |= setIfChanged(
                component.getComponentStatus(),
                activeInstall ? InventoryComponentStatus.ACTIVE : InventoryComponentStatus.RETIRED,
                component::setComponentStatus
        );
        component.setLastObservedAt(now);
        component.setRetiredAt(activeInstall ? null : now);
        component = inventoryComponentRepository.save(component);
        componentsByKey.put(key, component);
        return new ComponentUpsertResult(component, created, updated || created);
    }

    public SoftwareInstance saveSoftwareInstance(SoftwareInstance instance) {
        return softwareInstanceRepository.save(instance);
    }

    public SbomUpload saveUpload(SbomUpload upload) {
        return sbomUploadRepository.save(upload);
    }

    public SbomUpload createHostInventoryUpload(
            Tenant tenant,
            Asset asset,
            String sourceSystem,
            CmdbIngestionService.HostInventorySourceDescriptor sourceDescriptor,
            Instant now
    ) {
        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.HOST_INVENTORY);
        upload.setStatus(SbomIngestionStatus.IN_PROGRESS);
        upload.setOriginalFilename(sourceDescriptor.originalFilename() == null ? sourceSystem + "-inventory" : sourceDescriptor.originalFilename());
        upload.setIngestionSourceType(sourceDescriptor.ingestionSourceType());
        upload.setIngestionSourceSystem(sourceSystem);
        upload.setSourceReference(hasText(sourceDescriptor.sourceReference()) ? sourceDescriptor.sourceReference() : asset.getIdentifier());
        upload.setSourceEndpoint(sourceDescriptor.sourceEndpoint());
        upload.setContentType(sourceDescriptor.contentType());
        upload.setContentLengthBytes(sourceDescriptor.contentLengthBytes());
        upload.setEvidenceJson(buildHostUploadEvidence(
                "IN_PROGRESS",
                sourceSystem,
                sourceDescriptor.originalFilename(),
                now,
                null,
                null,
                null,
                null,
                null,
                sourceDescriptor
        ));
        return sbomUploadRepository.save(upload);
    }

    public void markHostUploadsFailed(
            Collection<SbomUpload> uploads,
            String sourceSystem,
            String originalFilename,
            Instant startedAt,
            String errorMessage,
            CmdbIngestionService.HostInventorySourceDescriptor sourceDescriptor
    ) {
        if (uploads == null || uploads.isEmpty()) {
            return;
        }
        Instant failedAt = Instant.now();
        for (SbomUpload upload : uploads) {
            upload.setStatus(SbomIngestionStatus.FAILURE);
            upload.setEvidenceJson(buildHostUploadEvidence(
                    "FAILURE",
                    sourceSystem,
                    originalFilename,
                    startedAt,
                    failedAt,
                    upload.getComponentCount(),
                    upload.getFindingsGenerated(),
                    errorMessage,
                    upload.getEvidenceJson(),
                    sourceDescriptor
            ));
            sbomUploadRepository.save(upload);
        }
    }

    public BusinessCriticality parseBusinessCriticality(String value) {
        if (!hasText(value)) {
            return BusinessCriticality.MEDIUM;
        }
        try {
            return BusinessCriticality.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return BusinessCriticality.MEDIUM;
        }
    }

    public Instant parseInstant(String value) {
        if (!hasText(value)) {
            return null;
        }
        List<DateTimeFormatter> formatters = List.of(
                DateTimeFormatter.ISO_OFFSET_DATE_TIME,
                DateTimeFormatter.ISO_LOCAL_DATE_TIME,
                DateTimeFormatter.ISO_LOCAL_DATE
        );
        for (DateTimeFormatter formatter : formatters) {
            try {
                if (formatter == DateTimeFormatter.ISO_LOCAL_DATE) {
                    return LocalDate.parse(value.trim(), formatter).atStartOfDay().toInstant(ZoneOffset.UTC);
                }
                if (formatter == DateTimeFormatter.ISO_LOCAL_DATE_TIME) {
                    return LocalDateTime.parse(value.trim(), formatter).toInstant(ZoneOffset.UTC);
                }
                return Instant.from(formatter.parse(value.trim()));
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    public boolean parseBoolean(String value, boolean defaultValue) {
        if (!hasText(value)) {
            return defaultValue;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("true")
                || normalized.equals("yes")
                || normalized.equals("y")
                || normalized.equals("1")
                || normalized.equals("active");
    }

    public String extractHostName(ImportedRow row) {
        if (row == null) {
            return null;
        }
        return row.get(
                "installed_on",
                "installed_on_display_value",
                "installed_on_name",
                "host_name",
                "hostname",
                "device_name",
                "computer_name"
        );
    }

    public String softwareInstanceKey(String normalizedProduct, String normalizedVersion, String versionEvidence) {
        return lower(normalizedProduct) + "::" + lower(normalizedVersion) + "::" + lower(versionEvidence);
    }

    public String preferredValue(String first, String second) {
        return hasText(first) ? first : second;
    }

    public String normalizeSource(String value) {
        return value == null || value.isBlank() ? "servicenow" : value.trim().toLowerCase(Locale.ROOT);
    }

    public String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public String buildHostUploadEvidence(
            String status,
            String sourceSystem,
            String originalFilename,
            Instant startedAt,
            Instant completedAt,
            Integer componentCount,
            Integer findingsGenerated,
            String errorMessage,
            String previousEvidence,
            CmdbIngestionService.HostInventorySourceDescriptor sourceDescriptor
    ) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "cmdb-host-inventory");
        evidence.put("ingestionStatus", status);
        evidence.put("sourceSystem", sourceSystem);
        evidence.put("originalFilename", originalFilename);
        evidence.put("ingestionSourceType", sourceDescriptor == null ? null : sourceDescriptor.ingestionSourceType());
        evidence.put("sourceEndpoint", sourceDescriptor == null ? null : sourceDescriptor.sourceEndpoint());
        evidence.put("contentType", sourceDescriptor == null ? null : sourceDescriptor.contentType());
        evidence.put("contentLengthBytes", sourceDescriptor == null ? null : sourceDescriptor.contentLengthBytes());
        evidence.put("startedAt", startedAt);
        evidence.put("completedAt", completedAt);
        evidence.put("componentCount", componentCount);
        evidence.put("findingsGenerated", findingsGenerated);
        if (errorMessage != null && !errorMessage.isBlank()) {
            evidence.put("errorMessage", errorMessage);
        }
        if (previousEvidence != null && !previousEvidence.isBlank()) {
            evidence.put("previousEvidence", previousEvidence);
        }
        return toJson(evidence);
    }

    private String componentKey(InventoryComponent component) {
        return componentKey(component.getEcosystem(), component.getPackageName(), component.getVersion());
    }

    private String componentKey(String ecosystem, String packageName, String version) {
        return lower(ecosystem) + "::" + lower(packageName) + "::" + lower(version);
    }

    private String normalizeHeader(String value) {
        return value == null ? "" : value.trim()
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "_")
                .replaceAll("^_+|_+$", "");
    }

    private String normalizeKey(String value) {
        return lower(value);
    }

    private String lower(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private <T> boolean setIfChanged(T current, T next, Consumer<T> setter) {
        if (Objects.equals(current, next)) {
            return false;
        }
        setter.accept(next);
        return true;
    }

    public record ImportedRow(Map<String, String> values) {
        public String get(String... keys) {
            for (String key : keys) {
                if (key == null) {
                    continue;
                }
                String value = values.get(key);
                if (value != null && !value.isBlank()) {
                    return value;
                }
            }
            return null;
        }
    }

    public record ResolvedInstallRow(
            ImportedRow row,
            DiscoveryModel discoveryModel,
            Ci ci
    ) {
    }

    public record ComponentUpsertResult(
            InventoryComponent component,
            boolean created,
            boolean updated
    ) {
    }
}
