package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.GithubAdvisorySyncStateEntity;
import com.prototype.vulnwatch.dto.GithubAdvisorySyncStatusResponse;
import com.prototype.vulnwatch.repo.GithubAdvisorySyncStateRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class GithubAdvisoryPlatformService {

    private static final String SYNC_TYPE_GITHUB_GHSA = "GITHUB_GHSA";

    private final GithubAdvisorySyncStateRepository syncStateRepository;

    public GithubAdvisoryPlatformService(GithubAdvisorySyncStateRepository syncStateRepository) {
        this.syncStateRepository = syncStateRepository;
    }

    @Transactional
    public GithubAdvisorySyncStatusResponse getPlatformSyncStatus() {
        log.debug("Fetching platform GHSA sync status");
        GithubAdvisorySyncStateEntity syncState = syncStateRepository
                .findBySyncType(SYNC_TYPE_GITHUB_GHSA)
                .orElseGet(() -> createNewSyncState());

        return toSyncStatusResponse(syncState);
    }

    @Transactional
    public GithubAdvisorySyncStatusResponse initiatePlatformSync() {
        log.info("Initiating platform GHSA sync");
        GithubAdvisorySyncStateEntity syncState = syncStateRepository
                .findBySyncType(SYNC_TYPE_GITHUB_GHSA)
                .orElseGet(this::createNewSyncState);

        if ("SYNCING".equals(syncState.getStatus())) {
            log.warn("GHSA sync already in progress");
            return toSyncStatusResponse(syncState);
        }

        syncState.setStatus("SYNCING");
        syncState.setUpdatedAt(Instant.now());
        syncStateRepository.save(syncState);

        log.info("Platform GHSA sync initiated with ID: {}", syncState.getId());
        return toSyncStatusResponse(syncState);
    }

    @Transactional
    public void completePlatformSync(int advisoriesSynced, int newlyFound, int updated, long durationMs) {
        log.info("Completing platform GHSA sync - synced: {}, new: {}, updated: {}, duration: {}ms",
                advisoriesSynced, newlyFound, updated, durationMs);

        GithubAdvisorySyncStateEntity syncState = syncStateRepository
                .findBySyncType(SYNC_TYPE_GITHUB_GHSA)
                .orElseGet(this::createNewSyncState);

        syncState.setStatus("IDLE");
        syncState.setLastFullSyncAt(Instant.now());
        syncState.setSyncComplete(true);
        syncState.setAdvisoriesSynced(advisoriesSynced);
        syncState.setAdvisoriesNewlyFound(newlyFound);
        syncState.setAdvisoriesUpdated(updated);
        syncState.setSyncDurationMs((int) durationMs);
        syncState.setConsecutiveErrors(0);
        syncState.setLastError(null);
        syncState.setUpdatedAt(Instant.now());

        syncStateRepository.save(syncState);
        log.info("Platform GHSA sync completed successfully");
    }

    @Transactional
    public void recordSyncError(String errorMessage, int errorCount) {
        log.error("Recording GHSA sync error (count: {}): {}", errorCount, errorMessage);

        GithubAdvisorySyncStateEntity syncState = syncStateRepository
                .findBySyncType(SYNC_TYPE_GITHUB_GHSA)
                .orElseGet(this::createNewSyncState);

        syncState.setStatus("ERROR");
        syncState.setLastError(errorMessage);
        syncState.setConsecutiveErrors(errorCount);
        syncState.setUpdatedAt(Instant.now());

        syncStateRepository.save(syncState);
    }

    @Transactional(readOnly = true)
    public Optional<GithubAdvisorySyncStatusResponse> getLatestSyncStatus() {
        return syncStateRepository
                .findBySyncType(SYNC_TYPE_GITHUB_GHSA)
                .map(this::toSyncStatusResponse);
    }

    @Transactional(readOnly = true)
    public boolean isSyncInProgress() {
        return syncStateRepository
                .findBySyncType(SYNC_TYPE_GITHUB_GHSA)
                .map(state -> "SYNCING".equals(state.getStatus()))
                .orElse(false);
    }

    private GithubAdvisorySyncStatusResponse toSyncStatusResponse(GithubAdvisorySyncStateEntity entity) {
        GithubAdvisorySyncStatusResponse response = GithubAdvisorySyncStatusResponse.builder()
                .id(entity.getId())
                .syncType(entity.getSyncType())
                .status(entity.getStatus())
                .lastFullSyncAt(entity.getLastFullSyncAt())
                .lastIncrementalSyncAt(entity.getLastIncrementalSyncAt())
                .nextScheduledSyncAt(entity.getNextScheduledSyncAt())
                .syncComplete(entity.getSyncComplete())
                .advisoriesSynced(entity.getAdvisoriesSynced())
                .advisoriesNewlyFound(entity.getAdvisoriesNewlyFound())
                .advisoriesUpdated(entity.getAdvisoriesUpdated())
                .syncDurationMs(entity.getSyncDurationMs())
                .lastError(entity.getLastError())
                .consecutiveErrors(entity.getConsecutiveErrors())
                .createdAt(entity.getCreatedAt())
                .updatedAt(entity.getUpdatedAt())
                .build();

        if (entity.getLastFullSyncAt() != null) {
            long minutesSince = ChronoUnit.MINUTES.between(entity.getLastFullSyncAt(), Instant.now());
            response.setElapsedMinutesSinceLastSync(minutesSince);
        }

        return response;
    }

    private GithubAdvisorySyncStateEntity createNewSyncState() {
        log.debug("Creating new GHSA sync state entity");
        GithubAdvisorySyncStateEntity syncState = new GithubAdvisorySyncStateEntity();
        syncState.setId(UUID.randomUUID());
        syncState.setSyncType(SYNC_TYPE_GITHUB_GHSA);
        syncState.setStatus("IDLE");
        syncState.setSyncComplete(false);
        syncState.setAdvisoriesSynced(0);
        syncState.setAdvisoriesNewlyFound(0);
        syncState.setAdvisoriesUpdated(0);
        syncState.setConsecutiveErrors(0);
        syncState.setCreatedAt(Instant.now());
        syncState.setUpdatedAt(Instant.now());
        return syncStateRepository.save(syncState);
    }
}
