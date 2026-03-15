package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncRunResponse;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
public class SyncRunHistoryService {

    private static final String CATEGORY_ALL = "all";
    private static final String CATEGORY_INVENTORY = "inventory";
    private static final String CATEGORY_VULN_INTEL = "vuln-intel";
    private static final String CATEGORY_PROCESSING = "processing";
    private static final String RUN_DOMAIN_INVENTORY = "INVENTORY";
    private static final String RUN_DOMAIN_VULN_INTEL = "VULN_INTEL";
    private static final String RUN_DOMAIN_PROCESSING = "PROCESSING";
    private static final String RUN_CLASS_INGESTION = "INGESTION";
    private static final String RUN_CLASS_REPAIR = "REPAIR";
    private static final String RUN_CLASS_BACKFILL = "BACKFILL";
    private static final String RUN_CLASS_RECOMPUTE = "RECOMPUTE";
    private static final String SYNC_TYPE_GITHUB_REPOSITORY_SBOM = "GITHUB_REPOSITORY_SBOM";
    private static final String SYNC_TYPE_GITHUB_GHCR_SBOM = "GITHUB_GHCR_SBOM";
    private static final Set<String> PROCESSING_RUN_TYPES = Set.of(
            "VEX_ASSERTION_REPAIR",
            "VEX_ROLLOUT_BACKFILL"
    );
    private static final Duration LEGACY_GITHUB_GROUP_WINDOW = Duration.ofMinutes(2);
    private static final Duration LEGACY_DEDUPE_WINDOW = Duration.ofMinutes(5);

    private final SyncRunRepository syncRunRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final TenantService tenantService;
    private final ObjectMapper objectMapper;

    public SyncRunHistoryService(
            SyncRunRepository syncRunRepository,
            SbomUploadRepository sbomUploadRepository,
            TenantService tenantService,
            ObjectMapper objectMapper
    ) {
        this.syncRunRepository = syncRunRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.tenantService = tenantService;
        this.objectMapper = objectMapper;
    }

    public List<SyncRunResponse> list(String category, int limit) {
        String normalizedCategory = normalizeCategory(category);
        int normalizedLimit = Math.max(1, Math.min(200, limit));

        Map<UUID, Integer> queuePositions = activeQueuePositions(normalizedCategory);
        List<SyncRun> persistedRuns = syncRunRepository.findAll(Sort.by(Sort.Direction.DESC, "startedAt")).stream()
                .filter(run -> matchesCategory(run.getSyncType(), normalizedCategory))
                .toList();

        List<SyncRunResponse> combined = new ArrayList<>(persistedRuns.stream()
                .map(run -> toResponse(run, queuePositions.get(run.getId())))
                .toList());
        if (CATEGORY_ALL.equals(normalizedCategory) || CATEGORY_INVENTORY.equals(normalizedCategory)) {
            combined.addAll(synthesizeLegacyGithubRuns(persistedRuns));
        }

        return combined.stream()
                .sorted(Comparator
                        .comparing(SyncRunResponse::startedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(SyncRunResponse::completedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(SyncRunResponse::id, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(normalizedLimit)
                .toList();
    }

    private Map<UUID, Integer> activeQueuePositions(String category) {
        List<SyncRun> queue = syncRunRepository.findQueueByStatuses(List.of("queued", "running")).stream()
                .filter(run -> matchesCategory(run.getSyncType(), category))
                .sorted(Comparator
                        .comparingInt((SyncRun run) -> "running".equalsIgnoreCase(run.getStatus()) ? 0 : 1)
                        .thenComparing(SyncRun::getStartedAt))
                .toList();
        Map<UUID, Integer> queuePositions = new HashMap<>();
        for (int i = 0; i < queue.size(); i++) {
            queuePositions.put(queue.get(i).getId(), i + 1);
        }
        return queuePositions;
    }

    private List<SyncRunResponse> synthesizeLegacyGithubRuns(List<SyncRun> persistedRuns) {
        Tenant tenant = tenantService.getDefaultTenant();
        List<SbomUpload> uploads = sbomUploadRepository.findByTenantAndIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc(
                tenant,
                "github");
        if (uploads.isEmpty()) {
            return List.of();
        }

        List<LegacyGithubRunGroup> groups = groupLegacyGithubUploads(uploads);
        if (groups.isEmpty()) {
            return List.of();
        }

        return groups.stream()
                .filter(group -> !hasPersistedSyncRunOverlap(group, persistedRuns))
                .map(this::toResponse)
                .toList();
    }

    private List<LegacyGithubRunGroup> groupLegacyGithubUploads(List<SbomUpload> uploads) {
        List<LegacyGithubUploadDescriptor> descriptors = uploads.stream()
                .map(this::describeLegacyGithubUpload)
                .filter(descriptor -> descriptor != null && descriptor.uploadedAt() != null)
                .sorted(Comparator.comparing(LegacyGithubUploadDescriptor::uploadedAt))
                .toList();
        if (descriptors.isEmpty()) {
            return List.of();
        }

        List<LegacyGithubRunGroup> groups = new ArrayList<>();
        LegacyGithubRunGroup current = null;
        for (LegacyGithubUploadDescriptor descriptor : descriptors) {
            if (current == null || !current.canAccept(descriptor)) {
                current = new LegacyGithubRunGroup(descriptor);
                groups.add(current);
                continue;
            }
            current.add(descriptor);
        }
        return groups;
    }

    private LegacyGithubUploadDescriptor describeLegacyGithubUpload(SbomUpload upload) {
        String sourceType = normalize(upload.getIngestionSourceType());
        String syncType;
        if ("github_generated".equals(sourceType)) {
            syncType = SYNC_TYPE_GITHUB_REPOSITORY_SBOM;
        } else if ("github_attestation".equals(sourceType)) {
            syncType = SYNC_TYPE_GITHUB_GHCR_SBOM;
        } else {
            return null;
        }

        JsonNode evidence = parseJson(upload.getEvidenceJson());
        String owner = firstText(evidence, "owner");
        String repo = firstText(evidence, "repo");
        String imageRepository = firstText(evidence, "imageRepository");
        String sourceReference = safe(upload.getSourceReference());
        if (owner.isBlank()) {
            owner = deriveOwner(sourceReference, imageRepository);
        }
        if (repo.isBlank() && sourceReference.contains("/")) {
            repo = sourceReference.substring(sourceReference.indexOf('/') + 1);
        }

        String ownerGroup = owner.isBlank() ? "github" : owner.toLowerCase(Locale.ROOT);
        String assetType = upload.getAsset() != null && upload.getAsset().getType() != null
                ? upload.getAsset().getType().name()
                : null;
        String reference = !sourceReference.isBlank()
                ? sourceReference
                : (!repo.isBlank() ? owner + "/" + repo : (!imageRepository.isBlank() ? imageRepository : owner));
        String uploadStatus = upload.getStatus() == null ? "" : upload.getStatus().name();
        String failureMessage = firstText(evidence, "errorMessage");
        if (failureMessage.isBlank() && "FAILURE".equalsIgnoreCase(safe(uploadStatus))) {
            failureMessage = "GitHub ingestion failed";
        }

        return new LegacyGithubUploadDescriptor(
                syncType,
                ownerGroup,
                reference,
                assetType,
                upload.getUploadedAt(),
                safe(uploadStatus),
                defaultNumber(upload.getComponentCount()),
                defaultNumber(upload.getFindingsGenerated()),
                failureMessage,
                imageRepository
        );
    }

    private boolean hasPersistedSyncRunOverlap(LegacyGithubRunGroup group, Collection<SyncRun> persistedRuns) {
        Instant groupStart = group.startedAt().minus(LEGACY_DEDUPE_WINDOW);
        Instant groupEnd = group.completedAt().plus(LEGACY_DEDUPE_WINDOW);
        return persistedRuns.stream()
                .filter(run -> safe(run.getSyncType()).equalsIgnoreCase(group.syncType()))
                .anyMatch(run -> overlaps(groupStart, groupEnd, run, group.ownerGroup()));
    }

    private boolean overlaps(Instant groupStart, Instant groupEnd, SyncRun run, String ownerGroup) {
        Instant runStart = run.getStartedAt();
        Instant runEnd = run.getCompletedAt() == null ? runStart : run.getCompletedAt();
        if (runStart == null) {
            return false;
        }
        if (runEnd == null) {
            runEnd = runStart;
        }
        if (runEnd.isBefore(groupStart) || runStart.isAfter(groupEnd)) {
            return false;
        }
        String scope = extractScope(run.getMetadataJson());
        return scope.isBlank() || scope.toLowerCase(Locale.ROOT).contains(ownerGroup.toLowerCase(Locale.ROOT));
    }

    private SyncRunResponse toResponse(SyncRun run, Integer queuePosition) {
        SyncRunClassification classification = classifyRunType(run.getSyncType());
        return new SyncRunResponse(
                run.getId(),
                run.getSyncType(),
                classification.runDomain(),
                classification.runClass(),
                run.getStatus(),
                queuePosition,
                run.getRecordsFetched(),
                run.getRecordsInserted(),
                run.getRecordsUpdated(),
                run.getRecordsFailed(),
                run.getStartedAt(),
                run.getCompletedAt(),
                run.getErrorMessage(),
                run.getMetadataJson()
        );
    }

    private SyncRunResponse toResponse(LegacyGithubRunGroup group) {
        SyncRunClassification classification = classifyRunType(group.syncType());
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("sourceSystem", "github");
        metadata.put("legacyReconstructed", true);
        if (group.assetType() != null && !group.assetType().isBlank()) {
            metadata.put("assetType", group.assetType());
        }
        metadata.put("assetsDiscovered", group.totalAssets());
        metadata.put("assetsIngested", group.totalAssets());
        metadata.put("assetsFailed", group.failedAssets());
        metadata.put("componentsIngested", group.componentsIngested());
        metadata.put("findingsGenerated", group.findingsGenerated());
        metadata.put("scope", group.scope());
        metadata.put("message", "Recovered from legacy GitHub ingestion evidence recorded before sync-run history existed.");
        String metadataJson = toJson(metadata);
        return new SyncRunResponse(
                deterministicUuid("legacy-github-run:" + group.syncType() + ":" + group.startedAt() + ":" + group.scope()),
                group.syncType(),
                classification.runDomain(),
                classification.runClass(),
                group.status(),
                null,
                group.totalAssets(),
                group.componentsIngested(),
                group.findingsGenerated(),
                group.failedAssets(),
                group.startedAt(),
                group.completedAt(),
                group.errorMessage(),
                metadataJson
        );
    }

    private boolean matchesCategory(String syncType, String category) {
        SyncRunClassification classification = classifyRunType(syncType);
        return switch (category) {
            case CATEGORY_INVENTORY -> RUN_DOMAIN_INVENTORY.equals(classification.runDomain());
            case CATEGORY_VULN_INTEL -> RUN_DOMAIN_VULN_INTEL.equals(classification.runDomain());
            case "vulnerability", "vuln" -> !RUN_DOMAIN_INVENTORY.equals(classification.runDomain());
            case CATEGORY_PROCESSING -> RUN_DOMAIN_PROCESSING.equals(classification.runDomain());
            default -> true;
        };
    }

    private boolean isInventoryRunType(String syncType) {
        String normalizedType = safe(syncType).toUpperCase(Locale.ROOT);
        return normalizedType.startsWith("GITHUB_") || "SERVICENOW_CMDB".equals(normalizedType);
    }

    private String normalizeCategory(String category) {
        String normalized = safe(category).toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            return CATEGORY_ALL;
        }
        return normalized;
    }

    private SyncRunClassification classifyRunType(String syncType) {
        String normalizedType = safe(syncType).toUpperCase(Locale.ROOT);
        if (isInventoryRunType(normalizedType)) {
            return new SyncRunClassification(RUN_DOMAIN_INVENTORY, RUN_CLASS_INGESTION);
        }
        if (PROCESSING_RUN_TYPES.contains(normalizedType)) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, classifyRunClass(normalizedType));
        }
        if (normalizedType.contains("RECOMPUTE")) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, RUN_CLASS_RECOMPUTE);
        }
        if (normalizedType.contains("BACKFILL")) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, RUN_CLASS_BACKFILL);
        }
        if (normalizedType.contains("REPAIR")) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, RUN_CLASS_REPAIR);
        }
        return new SyncRunClassification(RUN_DOMAIN_VULN_INTEL, RUN_CLASS_INGESTION);
    }

    private String classifyRunClass(String normalizedType) {
        if (normalizedType.contains("RECOMPUTE")) {
            return RUN_CLASS_RECOMPUTE;
        }
        if (normalizedType.contains("BACKFILL")) {
            return RUN_CLASS_BACKFILL;
        }
        if (normalizedType.contains("REPAIR")) {
            return RUN_CLASS_REPAIR;
        }
        return RUN_CLASS_INGESTION;
    }

    private JsonNode parseJson(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String extractScope(String metadataJson) {
        JsonNode metadata = parseJson(metadataJson);
        return firstText(metadata, "scope");
    }

    private String toJson(Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String deriveOwner(String sourceReference, String imageRepository) {
        if (sourceReference != null && sourceReference.contains("/")) {
            return sourceReference.substring(0, sourceReference.indexOf('/'));
        }
        if (imageRepository != null && imageRepository.startsWith("ghcr.io/")) {
            String remainder = imageRepository.substring("ghcr.io/".length());
            int slash = remainder.indexOf('/');
            return slash > 0 ? remainder.substring(0, slash) : remainder;
        }
        return safe(sourceReference);
    }

    private String firstText(JsonNode node, String fieldName) {
        if (node == null || fieldName == null) {
            return "";
        }
        JsonNode child = node.get(fieldName);
        if (child == null || child.isNull()) {
            return "";
        }
        return safe(child.asText());
    }

    private int defaultNumber(Integer value) {
        return value == null ? 0 : value;
    }

    private UUID deterministicUuid(String value) {
        return UUID.nameUUIDFromBytes(safe(value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private String normalize(String value) {
        return safe(value).toLowerCase(Locale.ROOT).replace('-', '_');
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private record LegacyGithubUploadDescriptor(
            String syncType,
            String ownerGroup,
            String sourceReference,
            String assetType,
            Instant uploadedAt,
            String status,
            int componentCount,
            int findingsGenerated,
            String errorMessage,
            String imageRepository
    ) {
    }

    private record SyncRunClassification(String runDomain, String runClass) {
    }

    private static final class LegacyGithubRunGroup {
        private final String syncType;
        private final String ownerGroup;
        private Instant startedAt;
        private Instant completedAt;
        private final Set<String> sourceReferences = new LinkedHashSet<>();
        private final Set<String> assetTypes = new LinkedHashSet<>();
        private final List<String> failureMessages = new ArrayList<>();
        private final Set<String> imageRepositories = new LinkedHashSet<>();
        private int totalAssets;
        private int failedAssets;
        private int componentsIngested;
        private int findingsGenerated;

        private LegacyGithubRunGroup(LegacyGithubUploadDescriptor first) {
            this.syncType = first.syncType();
            this.ownerGroup = first.ownerGroup();
            add(first);
        }

        private boolean canAccept(LegacyGithubUploadDescriptor descriptor) {
            if (!syncType.equalsIgnoreCase(descriptor.syncType())) {
                return false;
            }
            if (!ownerGroup.equalsIgnoreCase(descriptor.ownerGroup())) {
                return false;
            }
            return !descriptor.uploadedAt().isAfter(completedAt.plus(LEGACY_GITHUB_GROUP_WINDOW));
        }

        private void add(LegacyGithubUploadDescriptor descriptor) {
            if (startedAt == null || descriptor.uploadedAt().isBefore(startedAt)) {
                startedAt = descriptor.uploadedAt();
            }
            if (completedAt == null || descriptor.uploadedAt().isAfter(completedAt)) {
                completedAt = descriptor.uploadedAt();
            }
            totalAssets++;
            componentsIngested += descriptor.componentCount();
            findingsGenerated += descriptor.findingsGenerated();
            if ("FAILURE".equalsIgnoreCase(descriptor.status())) {
                failedAssets++;
                if (!descriptor.errorMessage().isBlank()) {
                    failureMessages.add(descriptor.sourceReference() + ": " + descriptor.errorMessage());
                }
            }
            if (!descriptor.sourceReference().isBlank()) {
                sourceReferences.add(descriptor.sourceReference());
            }
            if (descriptor.assetType() != null && !descriptor.assetType().isBlank()) {
                assetTypes.add(descriptor.assetType());
            }
            if (descriptor.imageRepository() != null && !descriptor.imageRepository().isBlank()) {
                imageRepositories.add(descriptor.imageRepository());
            }
        }

        private String syncType() {
            return syncType;
        }

        private String ownerGroup() {
            return ownerGroup;
        }

        private Instant startedAt() {
            return startedAt;
        }

        private Instant completedAt() {
            return completedAt;
        }

        private int totalAssets() {
            return totalAssets;
        }

        private int failedAssets() {
            return failedAssets;
        }

        private int componentsIngested() {
            return componentsIngested;
        }

        private int findingsGenerated() {
            return findingsGenerated;
        }

        private String assetType() {
            return assetTypes.size() == 1 ? assetTypes.iterator().next() : null;
        }

        private String status() {
            if (failedAssets >= totalAssets) {
                return "failed";
            }
            if (failedAssets > 0) {
                return "partial_success";
            }
            return "completed";
        }

        private String scope() {
            if (SYNC_TYPE_GITHUB_GHCR_SBOM.equals(syncType) && !imageRepositories.isEmpty()) {
                return imageRepositories.size() == 1
                        ? imageRepositories.iterator().next()
                        : "ghcr.io/" + ownerGroup;
            }
            if (sourceReferences.isEmpty()) {
                return ownerGroup;
            }
            if (sourceReferences.size() == 1) {
                return sourceReferences.iterator().next();
            }
            return ownerGroup + "/*";
        }

        private String errorMessage() {
            if (failureMessages.isEmpty()) {
                return null;
            }
            int previewCount = Math.min(3, failureMessages.size());
            List<String> preview = failureMessages.subList(0, previewCount);
            if (failureMessages.size() == previewCount) {
                return String.join(" | ", preview);
            }
            return String.join(" | ", preview) + " | +" + (failureMessages.size() - previewCount) + " more failures";
        }
    }
}
