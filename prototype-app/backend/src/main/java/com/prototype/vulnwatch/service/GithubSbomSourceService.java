package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GithubTokenProvider;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.GithubIngestionFrequency;
import com.prototype.vulnwatch.domain.GithubSbomSource;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.GithubSbomSourceRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.core.task.TaskExecutor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
public class GithubSbomSourceService {

    public static final String PATH_REPOSITORY_SBOM = "dependency-graph/sbom";
    public static final String PATH_GHCR_ATTESTATIONS = "ghcr/attestations";
    public static final String SYNC_TYPE_GITHUB_REPOSITORY_SBOM = "GITHUB_REPOSITORY_SBOM";
    public static final String SYNC_TYPE_GITHUB_GHCR_SBOM = "GITHUB_GHCR_SBOM";
    private static final String SOURCE_STATUS_QUEUED = "QUEUED";
    private static final String SOURCE_STATUS_RUNNING = "RUNNING";

    private final GithubSbomSourceRepository githubSbomSourceRepository;
    private final SyncRunRepository syncRunRepository;
    private final SbomIngestionService sbomIngestionService;
    private final WorkspaceService workspaceService;
    private final GithubTokenProvider githubTokenProvider;
    private final TaskExecutor ingestionExecutor;
    private final TransactionTemplate transactionTemplate;
    private final ObjectMapper objectMapper;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public GithubSbomSourceService(
            GithubSbomSourceRepository githubSbomSourceRepository,
            SyncRunRepository syncRunRepository,
            SbomIngestionService sbomIngestionService,
            WorkspaceService workspaceService,
            GithubTokenProvider githubTokenProvider,
            TaskExecutor ingestionExecutor,
            TransactionTemplate transactionTemplate,
            ObjectMapper objectMapper,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.githubSbomSourceRepository = githubSbomSourceRepository;
        this.syncRunRepository = syncRunRepository;
        this.sbomIngestionService = sbomIngestionService;
        this.workspaceService = workspaceService;
        this.githubTokenProvider = githubTokenProvider;
        this.ingestionExecutor = ingestionExecutor;
        this.transactionTemplate = transactionTemplate;
        this.objectMapper = objectMapper;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional(readOnly = true)
    public List<GithubSbomSourceResponse> list() {
        return githubSbomSourceRepository.findAllByOrderByCreatedAtAsc().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public GithubSbomSourceResponse create(GithubSbomSourceRequest request) {
        Tenant tenant = currentTenant();
        GithubSbomSource source = new GithubSbomSource();
        source.setTenant(tenant);
        apply(source, request);
        return toResponse(githubSbomSourceRepository.save(source));
    }

    @Transactional
    public GithubSbomSourceResponse update(UUID id, GithubSbomSourceRequest request) {
        GithubSbomSource source = githubSbomSourceRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + id));
        apply(source, request);
        source.touch();
        return toResponse(githubSbomSourceRepository.save(source));
    }

    @Transactional
    public void delete(UUID id) {
        GithubSbomSource source = githubSbomSourceRepository.findByIdForUpdate(id)
                .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + id));
        if (isSourceInFlight(source)) {
            throw new IllegalStateException("GitHub SBOM source is already queued or running and cannot be deleted");
        }
        githubSbomSourceRepository.delete(source);
    }

    public SyncTriggerResponse trigger(UUID id) {
        ensureGhcrTokenConfiguredIfNeeded(id);
        Tenant tenant = currentTenant();
        ClaimedGithubSourceRun claimed = claimSourceRun(tenant, id, false, true);
        ingestionExecutor.execute(() -> executeSource(claimed.tenantId(), claimed.sourceId(), claimed.runId()));
        return new SyncTriggerResponse(claimed.runId(), "queued", "GitHub ingestion queued");
    }

    public SyncTriggerResponse triggerGhcrRunOnce(String owner) {
        ensureGhcrTokenConfigured();
        Tenant tenant = currentTenant();
        String normalizedOwner = owner == null ? "" : owner.trim();
        if (normalizedOwner.isBlank()) {
            throw new IllegalArgumentException("GitHub owner is required");
        }
        SyncRun run = transactionTemplate.execute(status -> createQueuedRun(SYNC_TYPE_GITHUB_GHCR_SBOM, tenant));
        ingestionExecutor.execute(() -> executeGhcrRunOnce(tenant.getId(), run.getId(), normalizedOwner));
        return new SyncTriggerResponse(run.getId(), run.getStatus(), "GitHub GHCR ingestion queued");
    }

    public SyncTriggerResponse triggerRepositoryRunOnce(GithubSbomIngestionRequest request) {
        Tenant tenant = currentTenant();
        GithubSbomIngestionRequest normalizedRequest = normalizeRepositoryRequest(request);
        String normalizedOwner = normalizedRequest.owner() == null ? "" : normalizedRequest.owner().trim();
        if (normalizedOwner.isBlank()) {
            throw new IllegalArgumentException("GitHub owner is required");
        }
        SyncRun run = transactionTemplate.execute(status -> createQueuedRun(SYNC_TYPE_GITHUB_REPOSITORY_SBOM, tenant));
        ingestionExecutor.execute(() -> executeRepositoryRunOnce(tenant.getId(), run.getId(), normalizedRequest));
        return new SyncTriggerResponse(run.getId(), run.getStatus(), "GitHub repository ingestion queued");
    }

    @Scheduled(cron = "0 */5 * * * *")
    public void runScheduledSources() {
        List<ClaimedGithubSourceRun> scheduledSources = new ArrayList<>();
        for (Tenant tenant : tenantService.listTenants()) {
            tenantSchemaExecutionService.run(tenant, () -> {
                scheduledSources.addAll(githubSbomSourceRepository.findByEnabledTrueOrderByCreatedAtAsc()
                        .stream()
                        .map(source -> new ClaimedGithubSourceRun(tenant.getId(), source.getId(), null))
                        .toList());
                return null;
            });
        }
        for (ClaimedGithubSourceRun source : scheduledSources) {
            ClaimedGithubSourceRun claimed = tenantSchemaExecutionService.run(source.tenantId(), () ->
                    claimSourceRun(currentTenant(), source.sourceId(), true, false));
            if (claimed == null) {
                continue;
            }
            ingestionExecutor.execute(() -> executeSource(claimed.tenantId(), claimed.sourceId(), claimed.runId()));
        }
    }

    public void executeSource(UUID tenantId, UUID sourceId, UUID runId) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            GithubSbomSourceExecution snapshot = markSourceRunRunning(tenantId, sourceId, runId);
            if (snapshot == null) {
                return null;
            }
            if (snapshot.githubToken() != null) {
                githubTokenProvider.setOverrideToken(snapshot.githubToken());
            }
            try {
                Tenant tenant = workspaceService.getWorkspace();
                if (isGhcrSourcePath(snapshot.path())) {
                    SbomIngestionService.GithubGhcrIngestionSummary summary =
                            sbomIngestionService.ingestAllFromGithubContainerRegistry(tenant, snapshot.owner());
                    completeGhcrSourceRun(sourceId, runId, summary);
                } else {
                    var summary = sbomIngestionService.ingestFromGithub(tenant, new GithubSbomIngestionRequest(
                            snapshot.owner(),
                            snapshot.repo(),
                            false,
                            AssetType.APPLICATION,
                            snapshot.assetName(),
                            snapshot.assetIdentifier()
                    ));
                    completeRepositorySourceRun(sourceId, runId, summary);
                }
            } catch (Exception e) {
                failSourceRun(sourceId, runId, e.getMessage());
            } finally {
                githubTokenProvider.clearOverrideToken();
            }
            return null;
        });
    }

    public void executeGhcrRunOnce(UUID tenantId, UUID runId, String owner) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            markStandaloneRunRunning(runId);
            try {
                Tenant tenant = workspaceService.getWorkspace();
                SbomIngestionService.GithubGhcrIngestionSummary summary =
                        sbomIngestionService.ingestAllFromGithubContainerRegistry(tenant, owner);
                completeStandaloneGhcrRun(runId, owner, summary);
            } catch (Exception e) {
                failStandaloneRun(runId, e.getMessage());
            }
            return null;
        });
    }

    public void executeRepositoryRunOnce(UUID tenantId, UUID runId, GithubSbomIngestionRequest request) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            markStandaloneRunRunning(runId);
            try {
                Tenant tenant = workspaceService.getWorkspace();
                var summary = sbomIngestionService.ingestFromGithub(tenant, request);
                completeStandaloneRepositoryRun(runId, request, summary);
            } catch (Exception e) {
                failStandaloneRun(runId, e.getMessage());
            }
            return null;
        });
    }

    private boolean isDue(GithubSbomSource source, Instant now) {
        if (source.getFrequency() == GithubIngestionFrequency.ONCE) {
            return source.getLastRunAt() == null;
        }
        if (source.getLastRunAt() == null) {
            return true;
        }
        int minutes = source.getIntervalMinutes() == null ? 60 : Math.max(5, source.getIntervalMinutes());
        Duration elapsed = Duration.between(source.getLastRunAt(), now);
        return elapsed.toMinutes() >= minutes;
    }

    private void apply(GithubSbomSource source, GithubSbomSourceRequest request) {
        String name = request.name() == null ? "" : request.name().trim();
        String owner = request.owner() == null ? "" : request.owner().trim();
        if (name.isBlank()) {
            throw new IllegalArgumentException("Pipeline name is required");
        }
        if (owner.isBlank()) {
            throw new IllegalArgumentException("GitHub owner is required");
        }

        String path = normalizeSourcePath(request.path());
        boolean ghcrSource = isGhcrSourcePath(path);
        String repo = request.repo() == null ? "" : request.repo().trim();
        if (!ghcrSource && repo.isBlank()) {
            throw new IllegalArgumentException("GitHub repository is required for repository SBOM sources");
        }

        String defaultAssetName = ghcrSource
                ? defaultGhcrScopeAssetName(owner)
                : owner + "/" + repo;
        String defaultAssetIdentifier = ghcrSource
                ? defaultGhcrScopeAssetIdentifier(owner)
                : "github:" + owner.toLowerCase(Locale.ROOT) + "/" + repo.toLowerCase(Locale.ROOT);

        source.setName(name);
        source.setOwner(owner);
        source.setRepo(ghcrSource ? "" : repo);
        source.setPath(path);
        source.setAssetType(assetTypeForPath(path));
        source.setAssetName(
                request.assetName() == null || request.assetName().isBlank()
                        ? defaultAssetName
                        : request.assetName().trim());
        source.setAssetIdentifier(
                request.assetIdentifier() == null || request.assetIdentifier().isBlank()
                        ? defaultAssetIdentifier
                        : request.assetIdentifier().trim());
        source.setFrequency(request.frequency() == null ? GithubIngestionFrequency.ONCE : request.frequency());
        source.setIntervalMinutes(request.intervalMinutes() == null ? 60 : Math.max(5, request.intervalMinutes()));
        source.setEnabled(request.enabled() == null || request.enabled());
        if (request.githubToken() != null) {
            source.setGithubToken(request.githubToken());
        }
    }

    private String normalizeSourcePath(String path) {
        if (path == null || path.isBlank()) {
            return PATH_REPOSITORY_SBOM;
        }
        String normalized = path.trim().toLowerCase(Locale.ROOT);
        return isGhcrSourcePath(normalized) ? PATH_GHCR_ATTESTATIONS : PATH_REPOSITORY_SBOM;
    }

    private boolean isGhcrSourcePath(String path) {
        return PATH_GHCR_ATTESTATIONS.equalsIgnoreCase(path == null ? "" : path.trim());
    }

    private String defaultGhcrScopeAssetName(String owner) {
        return "ghcr.io/" + owner.toLowerCase(Locale.ROOT);
    }

    private String defaultGhcrScopeAssetIdentifier(String owner) {
        return "ghcr:" + owner.toLowerCase(Locale.ROOT);
    }

    private AssetType assetTypeForPath(String path) {
        return isGhcrSourcePath(path) ? AssetType.CONTAINER_IMAGE : AssetType.APPLICATION;
    }

    private GithubSbomIngestionRequest normalizeRepositoryRequest(GithubSbomIngestionRequest request) {
        return new GithubSbomIngestionRequest(
                request.owner(),
                request.repo(),
                request.includeAllRepos(),
                AssetType.APPLICATION,
                request.assetName(),
                request.assetIdentifier()
        );
    }

    private String syncTypeForPath(String path) {
        return isGhcrSourcePath(path) ? SYNC_TYPE_GITHUB_GHCR_SBOM : SYNC_TYPE_GITHUB_REPOSITORY_SBOM;
    }

    private ClaimedGithubSourceRun claimSourceRun(Tenant tenant, UUID sourceId, boolean requireDue, boolean failWhenUnavailable) {
        return transactionTemplate.execute(status -> {
            GithubSbomSource source = githubSbomSourceRepository.findByIdForUpdate(sourceId)
                    .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + sourceId));
            if (!source.isEnabled()) {
                if (failWhenUnavailable) {
                    throw new IllegalStateException("GitHub SBOM source is disabled");
                }
                return null;
            }
            if (isSourceInFlight(source)) {
                if (failWhenUnavailable) {
                    throw new IllegalStateException("GitHub SBOM source is already queued or running");
                }
                return null;
            }

            Instant now = Instant.now();
            if (requireDue && !isDue(source, now)) {
                return null;
            }

            source.setLastRunStatus(SOURCE_STATUS_QUEUED);
            source.setLastError(null);
            source.setLastRunAt(now);
            source.touch();
            githubSbomSourceRepository.save(source);

            SyncRun run = createQueuedRun(syncTypeForPath(source.getPath()), tenant);
            return new ClaimedGithubSourceRun(tenant.getId(), source.getId(), run.getId());
        });
    }

    private GithubSbomSourceExecution markSourceRunRunning(UUID tenantId, UUID sourceId, UUID runId) {
        return transactionTemplate.execute(status -> {
            GithubSbomSource source = githubSbomSourceRepository.findByIdForUpdate(sourceId)
                    .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + sourceId));
            SyncRun run = requireRun(runId);

            if (!source.isEnabled()) {
                source.setLastRunStatus("FAILURE");
                source.setLastError("GitHub SBOM source is disabled");
                source.setLastRunAt(Instant.now());
                source.touch();
                githubSbomSourceRepository.save(source);
                completeRun(run, "failed", 0, 0, 0, 0, "GitHub SBOM source is disabled", Map.of(
                        "sourceSystem", "github",
                        "syncType", run.getSyncType(),
                        "state", "failed"
                ));
                return null;
            }

            markRunRunning(run);
            source.setLastRunStatus(SOURCE_STATUS_RUNNING);
            source.setLastError(null);
            source.touch();
            githubSbomSourceRepository.save(source);
            return new GithubSbomSourceExecution(
                    source.getOwner(),
                    source.getRepo(),
                    source.getPath(),
                    assetTypeForPath(source.getPath()),
                    source.getAssetName(),
                    source.getAssetIdentifier(),
                    source.getGithubToken()
            );
        });
    }

    private void completeGhcrSourceRun(
            UUID sourceId,
            UUID runId,
            SbomIngestionService.GithubGhcrIngestionSummary summary
    ) {
        transactionTemplate.executeWithoutResult(status -> {
            GithubSbomSource source = githubSbomSourceRepository.findByIdForUpdate(sourceId)
                    .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + sourceId));
            SyncRun run = requireRun(runId);
            String errorMessage = buildGhcrFailureMessage(summary);
            source.setLastRunStatus(summary.imagesFailed() > 0 ? "PARTIAL_SUCCESS" : "SUCCESS");
            source.setLastError(errorMessage);
            source.setLastRunAt(Instant.now());
            source.touch();
            githubSbomSourceRepository.save(source);
            completeRun(
                    run,
                    summary.imagesFailed() > 0 ? "partial_success" : "completed",
                    summary.imagesDiscovered(),
                    summary.componentsIngested(),
                    summary.findingsGenerated(),
                    summary.imagesFailed(),
                    errorMessage,
                    Map.of(
                            "sourceSystem", "github",
                            "assetType", "CONTAINER_IMAGE",
                            "assetsDiscovered", summary.imagesDiscovered(),
                            "assetsIngested", summary.imagesProcessed(),
                            "assetsFailed", summary.imagesFailed(),
                            "componentsIngested", summary.componentsIngested(),
                            "findingsGenerated", summary.findingsGenerated()
                    ));
        });
    }

    private void completeRepositorySourceRun(
            UUID sourceId,
            UUID runId,
            com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse summary
    ) {
        transactionTemplate.executeWithoutResult(status -> {
            GithubSbomSource source = githubSbomSourceRepository.findByIdForUpdate(sourceId)
                    .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + sourceId));
            SyncRun run = requireRun(runId);
            String errorMessage = summary.repositoriesFailed() > 0
                    ? "Failed " + summary.repositoriesFailed() + " of " + summary.repositoriesProcessed() + " repositories"
                    : null;
            source.setLastRunStatus(summary.repositoriesFailed() > 0 ? "PARTIAL_SUCCESS" : "SUCCESS");
            source.setLastError(errorMessage);
            source.setLastRunAt(Instant.now());
            source.touch();
            githubSbomSourceRepository.save(source);
            completeRun(
                    run,
                    summary.repositoriesFailed() > 0 ? "partial_success" : "completed",
                    summary.repositoriesDiscovered(),
                    summary.componentsIngested(),
                    summary.findingsGenerated(),
                    summary.repositoriesFailed(),
                    errorMessage,
                    Map.of(
                            "sourceSystem", "github",
                            "assetType", assetTypeForPath(source.getPath()).name(),
                            "assetsDiscovered", summary.repositoriesDiscovered(),
                            "assetsIngested", summary.repositoriesProcessed(),
                            "assetsFailed", summary.repositoriesFailed(),
                            "componentsIngested", summary.componentsIngested(),
                            "findingsGenerated", summary.findingsGenerated(),
                            "scope", source.getOwner() + "/" + source.getRepo()
                    ));
        });
    }

    private void failSourceRun(UUID sourceId, UUID runId, String errorMessage) {
        transactionTemplate.executeWithoutResult(status -> {
            GithubSbomSource source = githubSbomSourceRepository.findByIdForUpdate(sourceId)
                    .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + sourceId));
            SyncRun run = requireRun(runId);
            source.setLastRunStatus("FAILURE");
            source.setLastError(errorMessage);
            source.setLastRunAt(Instant.now());
            source.touch();
            githubSbomSourceRepository.save(source);
            completeRun(run, "failed", 0, 0, 0, 0, errorMessage, Map.of(
                    "sourceSystem", "github",
                    "syncType", run.getSyncType(),
                    "state", "failed"
            ));
        });
    }

    private void markStandaloneRunRunning(UUID runId) {
        transactionTemplate.executeWithoutResult(status -> markRunRunning(requireRun(runId)));
    }

    private void completeStandaloneGhcrRun(UUID runId, String owner, SbomIngestionService.GithubGhcrIngestionSummary summary) {
        transactionTemplate.executeWithoutResult(status -> completeRun(
                requireRun(runId),
                summary.imagesFailed() > 0 ? "partial_success" : "completed",
                summary.imagesDiscovered(),
                summary.componentsIngested(),
                summary.findingsGenerated(),
                summary.imagesFailed(),
                buildGhcrFailureMessage(summary),
                Map.of(
                        "sourceSystem", "github",
                        "assetType", "CONTAINER_IMAGE",
                        "assetsDiscovered", summary.imagesDiscovered(),
                        "assetsIngested", summary.imagesProcessed(),
                        "assetsFailed", summary.imagesFailed(),
                        "componentsIngested", summary.componentsIngested(),
                        "findingsGenerated", summary.findingsGenerated(),
                        "scope", "ghcr.io/" + owner.toLowerCase(Locale.ROOT)
                )));
    }

    private void completeStandaloneRepositoryRun(
            UUID runId,
            GithubSbomIngestionRequest request,
            com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse summary
    ) {
        String owner = request.owner() == null ? "" : request.owner().trim();
        String repo = request.repo() == null ? "" : request.repo().trim();
        String errorMessage = summary.repositoriesFailed() > 0
                ? "Failed " + summary.repositoriesFailed() + " of " + summary.repositoriesProcessed() + " repositories"
                : null;
        String scope = repo.isBlank() ? owner : owner + "/" + repo;
        transactionTemplate.executeWithoutResult(status -> completeRun(
                requireRun(runId),
                summary.repositoriesFailed() > 0 ? "partial_success" : "completed",
                summary.repositoriesDiscovered(),
                summary.componentsIngested(),
                summary.findingsGenerated(),
                summary.repositoriesFailed(),
                errorMessage,
                Map.of(
                        "sourceSystem", "github",
                        "assetType", (request.assetType() == null ? AssetType.APPLICATION : request.assetType()).name(),
                        "assetsDiscovered", summary.repositoriesDiscovered(),
                        "assetsIngested", summary.repositoriesProcessed(),
                        "assetsFailed", summary.repositoriesFailed(),
                        "componentsIngested", summary.componentsIngested(),
                        "findingsGenerated", summary.findingsGenerated(),
                        "scope", scope
                )));
    }

    private void failStandaloneRun(UUID runId, String errorMessage) {
        transactionTemplate.executeWithoutResult(status -> completeRun(requireRun(runId), "failed", 0, 0, 0, 0, errorMessage, Map.of(
                "sourceSystem", "github",
                "state", "failed"
        )));
    }

    private SyncRun createQueuedRun(String syncType, Tenant tenant) {
        SyncRun run = new SyncRun();
        run.setTenant(tenant);
        run.setSyncType(syncType);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of(
                "sourceSystem", "github",
                "syncType", syncType
        )));
        return syncRunRepository.save(run);
    }

    private SyncRun requireRun(UUID runId) {
        return syncRunRepository.findById(runId)
                .orElseThrow(() -> new EntityNotFoundException("Sync run not found: " + runId));
    }

    private void markRunRunning(SyncRun run) {
        run.setStatus("running");
        run.setMetadataJson(toJson(Map.of(
                "sourceSystem", "github",
                "syncType", run.getSyncType(),
                "state", "running"
        )));
        syncRunRepository.save(run);
    }

    private void completeRun(
            SyncRun run,
            String status,
            int fetched,
            int inserted,
            int updated,
            int failed,
            String error,
            Map<String, Object> metadata
    ) {
        run.setStatus(status);
        run.setRecordsFetched(fetched);
        run.setRecordsInserted(inserted);
        run.setRecordsUpdated(updated);
        run.setRecordsFailed(failed);
        run.setErrorMessage(error);
        run.setCompletedAt(Instant.now());
        if (metadata != null && !metadata.isEmpty()) {
            run.setMetadataJson(toJson(metadata));
        }
        syncRunRepository.save(run);
    }

    private String toJson(Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to serialize sync run metadata", e);
        }
    }

    private String buildGhcrFailureMessage(SbomIngestionService.GithubGhcrIngestionSummary summary) {
        if (summary.imagesFailed() <= 0) {
            return null;
        }
        if (summary.failureSummary() != null && !summary.failureSummary().isBlank()) {
            return summary.failureSummary();
        }
        return "Failed " + summary.imagesFailed() + " of " + summary.imagesProcessed() + " images";
    }

    private void ensureGhcrTokenConfiguredIfNeeded(UUID sourceId) {
        GithubSbomSource source = githubSbomSourceRepository.findById(sourceId)
                .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + sourceId));
        if (isGhcrSourcePath(source.getPath())) {
            ensureGhcrTokenConfigured();
        }
    }

    private Tenant currentTenant() {
        return workspaceService.getWorkspace();
    }

    private UUID currentTenantId() {
        return currentTenant().getId();
    }

    private void ensureGhcrTokenConfigured() {
        if (githubTokenProvider.hasToken()) {
            return;
        }
        throw new ResponseStatusException(
                BAD_REQUEST,
                "GitHub GHCR discovery requires a GitHub token with at least read:packages access. "
                        + githubTokenProvider.configurationHint()
        );
    }

    private boolean isSourceInFlight(GithubSbomSource source) {
        if (source == null || source.getLastRunStatus() == null) {
            return false;
        }
        String status = source.getLastRunStatus().trim().toUpperCase(Locale.ROOT);
        return SOURCE_STATUS_QUEUED.equals(status) || SOURCE_STATUS_RUNNING.equals(status);
    }

    private GithubSbomSourceResponse toResponse(GithubSbomSource source) {
        return new GithubSbomSourceResponse(
                source.getId(),
                source.getName(),
                source.getOwner(),
                source.getRepo(),
                source.getPath(),
                assetTypeForPath(source.getPath()).name(),
                source.getAssetName(),
                source.getAssetIdentifier(),
                source.getFrequency().name(),
                source.getIntervalMinutes(),
                source.isEnabled(),
                source.getLastRunAt(),
                source.getLastRunStatus(),
                source.getLastError(),
                source.hasGithubToken()
        );
    }

    private record ClaimedGithubSourceRun(
            UUID tenantId,
            UUID sourceId,
            UUID runId
    ) {
    }

    private record GithubSbomSourceExecution(
            String owner,
            String repo,
            String path,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            String githubToken
    ) {
    }
}
