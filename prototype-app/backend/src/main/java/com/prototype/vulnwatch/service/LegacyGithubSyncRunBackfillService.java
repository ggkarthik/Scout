package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
public class LegacyGithubSyncRunBackfillService {

    private static final String SYNC_TYPE_GITHUB_REPOSITORY_SBOM = "GITHUB_REPOSITORY_SBOM";
    private static final String SYNC_TYPE_GITHUB_GHCR_SBOM = "GITHUB_GHCR_SBOM";
    private static final Duration LEGACY_GITHUB_GROUP_WINDOW = Duration.ofMinutes(2);
    private static final Duration LEGACY_DEDUPE_WINDOW = Duration.ofMinutes(5);

    private final SyncRunRepository syncRunRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final ObjectMapper objectMapper;
    private final boolean backfillOnStartup;

    public LegacyGithubSyncRunBackfillService(
            SyncRunRepository syncRunRepository,
            SbomUploadRepository sbomUploadRepository,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            ObjectMapper objectMapper,
            @Value("${app.sync-runs.legacy-github-backfill-on-startup:true}") boolean backfillOnStartup
    ) {
        this.syncRunRepository = syncRunRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.objectMapper = objectMapper;
        this.backfillOnStartup = backfillOnStartup;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void backfillOnStartup() {
        if (!backfillOnStartup) {
            return;
        }
        backfillMissingRuns();
    }

    public int backfillMissingRuns() {
        return TenantContext.runAsPlatform(() -> {
            List<SyncRun> backfilledRuns = new ArrayList<>();
            List<SyncRun> persistedRuns = new ArrayList<>(syncRunRepository.findAll(Sort.by(Sort.Direction.DESC, "startedAt")));
            for (Tenant tenant : tenantService.listActiveTenants()) {
                List<SbomUpload> uploads = tenantSchemaExecutionService.run(
                        tenant,
                        () -> sbomUploadRepository.findByIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc("github")
                );
                if (uploads.isEmpty()) {
                    continue;
                }
                List<LegacyGithubRunGroup> groups = groupLegacyGithubUploads(uploads);
                for (LegacyGithubRunGroup group : groups) {
                    if (hasPersistedSyncRunOverlap(group, persistedRuns)) {
                        continue;
                    }
                    SyncRun run = toSyncRun(tenant, group);
                    backfilledRuns.add(run);
                    persistedRuns.add(run);
                }
            }
            if (backfilledRuns.isEmpty()) {
                return 0;
            }
            syncRunRepository.saveAll(backfilledRuns);
            return backfilledRuns.size();
        });
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
        if (failureMessage.isBlank() && "FAILURE".equalsIgnoreCase(uploadStatus)) {
            failureMessage = "GitHub ingestion failed";
        }

        return new LegacyGithubUploadDescriptor(
                syncType,
                ownerGroup,
                reference,
                assetType,
                upload.getUploadedAt(),
                uploadStatus,
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

    private SyncRun toSyncRun(Tenant tenant, LegacyGithubRunGroup group) {
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
        metadata.put("message", "Backfilled from legacy GitHub ingestion evidence recorded before sync-run history existed.");

        SyncRun run = new SyncRun();
        run.setTenant(tenant);
        run.setSyncType(group.syncType());
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus(group.status());
        run.setRecordsFetched(group.totalAssets());
        run.setRecordsInserted(group.componentsIngested());
        run.setRecordsUpdated(group.findingsGenerated());
        run.setRecordsFailed(group.failedAssets());
        run.setStartedAt(group.startedAt());
        run.setCompletedAt(group.completedAt());
        run.setErrorMessage(group.errorMessage());
        run.setMetadataJson(toJson(metadata));
        return run;
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
            if (sourceReferences.isEmpty()) {
                return ownerGroup + "/*";
            }
            if (imageRepositories.isEmpty()) {
                return ownerGroup + "/*";
            }
            return String.join(", ", sourceReferences);
        }

        private String errorMessage() {
            if (failureMessages.isEmpty()) {
                return null;
            }
            return String.join(" | ", failureMessages);
        }
    }
}
