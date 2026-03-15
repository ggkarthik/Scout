package com.prototype.vulnwatch.service;

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
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.repo.DiscoveryModelRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SoftwareInstanceRepository;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CmdbIngestionService {

    private static final int INGEST_FLUSH_INTERVAL = 250;

    private final DiscoveryModelRepository discoveryModelRepository;
    private final SoftwareInstanceRepository softwareInstanceRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final HostSoftwareNormalizationService hostSoftwareNormalizationService;
    private final SoftwareIdentityService softwareIdentityService;
    private final CiResolutionService ciResolutionService;
    private final InventoryComponentCpeMappingService inventoryComponentCpeMappingService;
    private final SoftwareInventorySyncService softwareInventorySyncService;
    private final FindingService findingService;
    private final AssetLifecycleService assetLifecycleService;
    private final ObjectMapper objectMapper;
    private final EntityManager entityManager;

    public CmdbIngestionService(
            DiscoveryModelRepository discoveryModelRepository,
            SoftwareInstanceRepository softwareInstanceRepository,
            InventoryComponentRepository inventoryComponentRepository,
            SbomUploadRepository sbomUploadRepository,
            HostSoftwareNormalizationService hostSoftwareNormalizationService,
            SoftwareIdentityService softwareIdentityService,
            CiResolutionService ciResolutionService,
            InventoryComponentCpeMappingService inventoryComponentCpeMappingService,
            SoftwareInventorySyncService softwareInventorySyncService,
            FindingService findingService,
            AssetLifecycleService assetLifecycleService,
            ObjectMapper objectMapper,
            EntityManager entityManager
    ) {
        this.discoveryModelRepository = discoveryModelRepository;
        this.softwareInstanceRepository = softwareInstanceRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.hostSoftwareNormalizationService = hostSoftwareNormalizationService;
        this.softwareIdentityService = softwareIdentityService;
        this.ciResolutionService = ciResolutionService;
        this.inventoryComponentCpeMappingService = inventoryComponentCpeMappingService;
        this.softwareInventorySyncService = softwareInventorySyncService;
        this.findingService = findingService;
        this.assetLifecycleService = assetLifecycleService;
        this.objectMapper = objectMapper;
        this.entityManager = entityManager;
    }

    @Transactional
    public CmdbInventorySyncResponse ingestRows(
            Tenant tenant,
            String sourceSystem,
            List<Map<String, String>> installRowValues,
            List<Map<String, String>> discoveryRowValues,
            HostInventorySourceDescriptor sourceDescriptor
    ) {
        List<ImportedRow> installRows = toImportedRows(installRowValues);
        List<ImportedRow> discoveryRows = toImportedRows(discoveryRowValues);
        return ingestParsedRows(tenant, sourceSystem, installRows, discoveryRows, sourceDescriptor);
    }

    private CmdbInventorySyncResponse ingestParsedRows(
            Tenant tenant,
            String sourceSystem,
            List<ImportedRow> installRows,
            List<ImportedRow> discoveryRows,
            HostInventorySourceDescriptor sourceDescriptor
    ) {
        Instant now = Instant.now();
        String normalizedSource = normalizeSource(sourceSystem);
        Map<String, DiscoveryModel> discoveryModelsByKey = upsertDiscoveryModels(tenant, discoveryRows);
        Map<UUID, SbomUpload> uploadByAssetId = new HashMap<>();
        Map<UUID, Asset> changedAssetsById = new LinkedHashMap<>();
        Map<UUID, Set<String>> cpesByComponentId = new LinkedHashMap<>();
        Map<UUID, Integer> componentCountsByAssetId = new HashMap<>();
        List<InventoryComponent> touchedComponents = new ArrayList<>();
        List<ResolvedInstallRow> resolvedRows = new ArrayList<>();

        int unmatchedDiscoveryRows = 0;
        int ciCreated = 0;
        int ciAliasesCreated = 0;
        int softwareInstancesCreated = 0;
        int softwareInstancesUpdated = 0;
        int inventoryComponentsCreated = 0;
        int inventoryComponentsUpdated = 0;

        try {
            CiResolutionService.BatchResolutionContext resolutionContext = ciResolutionService.prepareBatchContext(
                    tenant,
                    normalizedSource,
                    installRows.stream()
                            .map(row -> new CiResolutionService.HostLookupInput(
                                    row.get("ci_sys_id", "installed_on_sys_id", "sys_id"),
                                    extractHostName(row)
                            ))
                            .toList()
            );

            int resolvedHostRows = 0;
            for (ImportedRow row : installRows) {
                String hostName = extractHostName(row);
                if (!hasText(hostName)) {
                    continue;
                }

                String discoveryKey = row.get(
                        "discovery_model_pk",
                        "discovery_model_primary_key",
                        "primary_key",
                        "discovery_model"
                );
                DiscoveryModel discoveryModel = hasText(discoveryKey)
                        ? discoveryModelsByKey.get(normalizeKey(discoveryKey))
                        : null;
                if (hasText(discoveryKey) && discoveryModel == null) {
                    unmatchedDiscoveryRows++;
                }

                BusinessCriticality businessCriticality = parseBusinessCriticality(
                        row.get("business_criticality", "criticality", "ci_criticality")
                );
                CiResolutionService.Resolution ciResolution = ciResolutionService.resolve(
                        resolutionContext,
                        tenant,
                        row.get("ci_sys_id", "installed_on_sys_id", "sys_id"),
                        hostName,
                        row.get("environment", "env"),
                        row.get("owner_email", "owner"),
                        businessCriticality,
                        normalizedSource
                );
                Ci ci = ciResolution.ci();
                if (ciResolution.created()) {
                    ciCreated++;
                }
                if (ciResolution.aliasCreated()) {
                    ciAliasesCreated++;
                }
                resolvedRows.add(new ResolvedInstallRow(row, discoveryModel, ci));
                resolvedHostRows++;
                if (resolvedHostRows % INGEST_FLUSH_INTERVAL == 0) {
                    entityManager.flush();
                }
            }

            entityManager.flush();
            entityManager.clear();
            Map<UUID, Map<String, SoftwareInstance>> existingInstancesByCiId = preloadSoftwareInstances(tenant, resolvedRows);
            Map<UUID, Map<String, InventoryComponent>> existingComponentsByAssetId = preloadInventoryComponents(resolvedRows);

            for (int index = 0; index < resolvedRows.size(); index++) {
                ResolvedInstallRow resolved = resolvedRows.get(index);
                ImportedRow row = resolved.row();
                Ci ci = resolved.ci();
                Asset asset = ci.getAsset();
                DiscoveryModel discoveryModel = resolved.discoveryModel();
                String discoveryKey = row.get(
                        "discovery_model_pk",
                        "discovery_model_primary_key",
                        "primary_key",
                        "discovery_model"
                );
                HostSoftwareNormalizationService.NormalizedHostSoftware normalized = hostSoftwareNormalizationService.normalize(
                        row.get("display_name", "software", "name", "product_name"),
                        row.get("publisher", "manufacturer", "vendor"),
                        row.get("version", "display_version"),
                        preferredValue(row.get("normalized_product"), discoveryModel == null ? null : discoveryModel.getNormalizedProduct()),
                        preferredValue(row.get("normalized_publisher"), discoveryModel == null ? null : discoveryModel.getNormalizedPublisher()),
                        preferredValue(row.get("normalized_version"), discoveryModel == null ? null : discoveryModel.getNormalizedVersion()),
                        row.get("version_evidence", "msi_product_code", "package_id", "group_id")
                );
                String normalizedVersion = blankToNull(normalized.normalizedVersion());
                String normalizedEvidence = blankToNull(normalized.normalizedEvidence());
                Map<String, SoftwareInstance> instancesByKey = existingInstancesByCiId.computeIfAbsent(ci.getId(), ignored -> new LinkedHashMap<>());
                String instanceKey = softwareInstanceKey(normalized.normalizedProduct(), normalizedVersion, normalizedEvidence);
                SoftwareInstance instance = instancesByKey.get(instanceKey);
                boolean createdInstance = instance == null;
                if (createdInstance) {
                    instance = new SoftwareInstance();
                    instance.setTenant(tenant);
                    instance.setCi(ci);
                }
                instance.setDiscoveryModel(discoveryModel);
                instance.setDisplayName(preferredValue(row.get("display_name", "software", "name", "product_name"), normalized.rawDisplayName()));
                instance.setPublisher(preferredValue(row.get("publisher", "manufacturer", "vendor"), normalized.rawPublisher()));
                instance.setVersion(blankToNull(preferredValue(row.get("version", "display_version"), normalized.rawVersion())));
                instance.setNormalizedPublisher(normalized.normalizedPublisher());
                instance.setNormalizedProduct(normalized.normalizedProduct());
                instance.setNormalizedVersion(normalizedVersion);
                instance.setInstallDate(parseInstant(row.get("install_date", "installed_at")));
                instance.setLastScanned(parseInstant(row.get("last_scanned", "last_discovered", "last_scan")));
                instance.setLastUsed(parseInstant(row.get("last_used")));
                instance.setActiveInstall(parseBoolean(row.get("active_install", "active"), true));
                instance.setUnlicensedInstall(parseBoolean(row.get("unlicensed_install"), false));
                instance.setDiscoveryModelPk(blankToNull(discoveryKey));
                instance.setVersionEvidence(normalizedEvidence);
                instance.setSourceSystem(normalizedSource);
                instance.touch();
                if (createdInstance) {
                    instance = softwareInstanceRepository.save(instance);
                    instancesByKey.put(instanceKey, instance);
                }

                SoftwareIdentityService.HostIdentityResolution identityResolution =
                        softwareIdentityService.resolveHostSoftwareIdentity(instance, discoveryModel, normalized, normalizedSource, false);
                instance.setSoftwareIdentity(identityResolution.identity());

                SbomUpload upload = uploadByAssetId.computeIfAbsent(
                        asset.getId(),
                        ignored -> createHostInventoryUpload(tenant, asset, normalizedSource, sourceDescriptor, now)
                );
                ComponentUpsertResult componentResult = upsertInventoryComponent(
                        asset,
                        upload,
                        normalized,
                        identityResolution.identity(),
                        instance.isActiveInstall(),
                        existingComponentsByAssetId,
                        now
                );
                instance.setInventoryComponent(componentResult.component());
                instance.touch();
                instance = softwareInstanceRepository.save(instance);
                instancesByKey.put(instanceKey, instance);

                if (createdInstance) {
                    softwareInstancesCreated++;
                } else {
                    softwareInstancesUpdated++;
                }
                if (componentResult.created()) {
                    inventoryComponentsCreated++;
                } else if (componentResult.updated()) {
                    inventoryComponentsUpdated++;
                }

                touchedComponents.add(componentResult.component());
                cpesByComponentId.computeIfAbsent(componentResult.component().getId(), ignored -> new LinkedHashSet<>())
                        .addAll(identityResolution.cpeCandidates());
                changedAssetsById.put(asset.getId(), asset);
                componentCountsByAssetId.merge(asset.getId(), 1, Integer::sum);
                if ((index + 1) % INGEST_FLUSH_INTERVAL == 0) {
                    entityManager.flush();
                    entityManager.clear();
                }
            }

            entityManager.flush();
            entityManager.clear();

            Map<UUID, InventoryComponent> uniqueComponents = new LinkedHashMap<>();
            for (InventoryComponent component : touchedComponents) {
                if (component != null && component.getId() != null) {
                    uniqueComponents.put(component.getId(), component);
                }
            }

            if (!uniqueComponents.isEmpty()) {
                inventoryComponentCpeMappingService.syncComponentMappings(uniqueComponents.values(), cpesByComponentId);
                softwareInventorySyncService.syncFromInventoryDelta(tenant, uniqueComponents.values(), now);
            }

            for (Asset asset : changedAssetsById.values()) {
                assetLifecycleService.markInventoryIngested(asset);
            }

            for (Map.Entry<UUID, SbomUpload> entry : uploadByAssetId.entrySet()) {
                SbomUpload upload = entry.getValue();
                upload.setComponentCount(componentCountsByAssetId.getOrDefault(entry.getKey(), 0));
                sbomUploadRepository.save(upload);
            }

            int findingsRecomputed = uniqueComponents.isEmpty()
                    ? 0
                    : recomputeTouchedComponents(tenant, uniqueComponents.keySet());

            Instant completedAt = Instant.now();
            for (Map.Entry<UUID, SbomUpload> entry : uploadByAssetId.entrySet()) {
                SbomUpload upload = entry.getValue();
                upload.setStatus(SbomIngestionStatus.SUCCESS);
                upload.setFindingsGenerated(findingsRecomputed);
                upload.setEvidenceJson(buildHostUploadEvidence(
                        "SUCCESS",
                        normalizedSource,
                        sourceDescriptor.originalFilename(),
                        now,
                        completedAt,
                        componentCountsByAssetId.getOrDefault(entry.getKey(), 0),
                        findingsRecomputed,
                        null,
                        upload.getEvidenceJson(),
                        sourceDescriptor
                ));
                sbomUploadRepository.save(upload);
            }

            return new CmdbInventorySyncResponse(
                    normalizedSource,
                    installRows.size(),
                    discoveryRows.size(),
                    unmatchedDiscoveryRows,
                    uploadByAssetId.size(),
                    ciCreated,
                    ciAliasesCreated,
                    softwareInstancesCreated,
                    softwareInstancesUpdated,
                    inventoryComponentsCreated,
                    inventoryComponentsUpdated,
                    findingsRecomputed,
                    "CMDB host software sync completed"
            );
        } catch (RuntimeException ex) {
            markHostUploadsFailed(uploadByAssetId.values(), normalizedSource, sourceDescriptor.originalFilename(), now, ex.getMessage(), sourceDescriptor);
            throw ex;
        }
    }

    private int recomputeTouchedComponents(Tenant tenant, Collection<UUID> componentIds) {
        if (tenant == null || tenant.getId() == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }

        List<UUID> orderedIds = componentIds.stream()
                .filter(id -> id != null)
                .distinct()
                .toList();
        if (orderedIds.isEmpty()) {
            return 0;
        }

        int findingsRecomputed = 0;
        for (int start = 0; start < orderedIds.size(); start += INGEST_FLUSH_INTERVAL) {
            int end = Math.min(start + INGEST_FLUSH_INTERVAL, orderedIds.size());
            findingsRecomputed += findingService.recomputeOnSoftwareDeltaBatch(
                    tenant.getId(),
                    orderedIds.subList(start, end)
            );
            entityManager.clear();
        }
        return findingsRecomputed;
    }

    private List<ImportedRow> toImportedRows(List<Map<String, String>> rows) {
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

    private Map<UUID, Map<String, SoftwareInstance>> preloadSoftwareInstances(Tenant tenant, List<ResolvedInstallRow> resolvedRows) {
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

    private Map<UUID, Map<String, InventoryComponent>> preloadInventoryComponents(List<ResolvedInstallRow> resolvedRows) {
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

    private Map<String, DiscoveryModel> upsertDiscoveryModels(Tenant tenant, List<ImportedRow> rows) {
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

    private ComponentUpsertResult upsertInventoryComponent(
            Asset asset,
            SbomUpload upload,
            HostSoftwareNormalizationService.NormalizedHostSoftware normalized,
            SoftwareIdentity identity,
            boolean activeInstall,
            Map<UUID, Map<String, InventoryComponent>> existingComponentsByAssetId,
            Instant now
    ) {
        Map<String, InventoryComponent> componentsByKey = existingComponentsByAssetId.computeIfAbsent(asset.getId(), ignored -> new LinkedHashMap<>());

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

    private SbomUpload createHostInventoryUpload(
            Tenant tenant,
            Asset asset,
            String sourceSystem,
            HostInventorySourceDescriptor sourceDescriptor,
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

    private void markHostUploadsFailed(
            Collection<SbomUpload> uploads,
            String sourceSystem,
            String originalFilename,
            Instant startedAt,
            String errorMessage,
            HostInventorySourceDescriptor sourceDescriptor
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

    private String buildHostUploadEvidence(
            String status,
            String sourceSystem,
            String originalFilename,
            Instant startedAt,
            Instant completedAt,
            Integer componentCount,
            Integer findingsGenerated,
            String errorMessage,
            String previousEvidence,
            HostInventorySourceDescriptor sourceDescriptor
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

    private BusinessCriticality parseBusinessCriticality(String value) {
        if (!hasText(value)) {
            return BusinessCriticality.MEDIUM;
        }
        try {
            return BusinessCriticality.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return BusinessCriticality.MEDIUM;
        }
    }

    private Instant parseInstant(String value) {
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

    private boolean parseBoolean(String value, boolean defaultValue) {
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

    private String extractHostName(ImportedRow row) {
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

    private String componentKey(InventoryComponent component) {
        return componentKey(component.getEcosystem(), component.getPackageName(), component.getVersion());
    }

    private String componentKey(String ecosystem, String packageName, String version) {
        return lower(ecosystem) + "::" + lower(packageName) + "::" + lower(version);
    }

    private String softwareInstanceKey(String normalizedProduct, String normalizedVersion, String versionEvidence) {
        return lower(normalizedProduct) + "::" + lower(normalizedVersion) + "::" + lower(versionEvidence);
    }

    private String preferredValue(String first, String second) {
        return hasText(first) ? first : second;
    }

    private String normalizeHeader(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_").replaceAll("^_+|_+$", "");
    }

    private String normalizeKey(String value) {
        return lower(value);
    }

    private String normalizeSource(String value) {
        return value == null || value.isBlank() ? "servicenow" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
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

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private <T> boolean setIfChanged(T current, T next, java.util.function.Consumer<T> setter) {
        if (java.util.Objects.equals(current, next)) {
            return false;
        }
        setter.accept(next);
        return true;
    }

    private record ImportedRow(Map<String, String> values) {
        String get(String... keys) {
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

    private record ResolvedInstallRow(
            ImportedRow row,
            DiscoveryModel discoveryModel,
            Ci ci
    ) {
    }

    private record ComponentUpsertResult(
            InventoryComponent component,
            boolean created,
            boolean updated
    ) {
    }

    public record HostInventorySourceDescriptor(
            String originalFilename,
            String ingestionSourceType,
            String sourceSystem,
            String sourceReference,
            String sourceEndpoint,
            String contentType,
            Long contentLengthBytes
    ) {
    }

}
