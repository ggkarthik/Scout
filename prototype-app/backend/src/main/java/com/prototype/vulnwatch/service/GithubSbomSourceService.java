package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.GithubSbomSource;
import com.prototype.vulnwatch.domain.GithubIngestionFrequency;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceResponse;
import com.prototype.vulnwatch.repo.GithubSbomSourceRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class GithubSbomSourceService {

    private final GithubSbomSourceRepository githubSbomSourceRepository;
    private final SbomIngestionService sbomIngestionService;
    private final TenantService tenantService;
    private final TaskExecutor ingestionExecutor;

    public GithubSbomSourceService(
            GithubSbomSourceRepository githubSbomSourceRepository,
            SbomIngestionService sbomIngestionService,
            TenantService tenantService,
            TaskExecutor ingestionExecutor
    ) {
        this.githubSbomSourceRepository = githubSbomSourceRepository;
        this.sbomIngestionService = sbomIngestionService;
        this.tenantService = tenantService;
        this.ingestionExecutor = ingestionExecutor;
    }

    @Transactional(readOnly = true)
    public List<GithubSbomSourceResponse> list() {
        return githubSbomSourceRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public GithubSbomSourceResponse create(GithubSbomSourceRequest request) {
        GithubSbomSource source = new GithubSbomSource();
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
    public void trigger(UUID id) {
        GithubSbomSource source = githubSbomSourceRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + id));
        ingestionExecutor.execute(() -> executeSource(source.getId()));
    }

    @Scheduled(cron = "0 */5 * * * *")
    @Transactional
    public void runScheduledSources() {
        Instant now = Instant.now();
        List<GithubSbomSource> sources = githubSbomSourceRepository.findByEnabledTrueOrderByCreatedAtAsc();
        for (GithubSbomSource source : sources) {
            if (!isDue(source, now)) {
                continue;
            }
            ingestionExecutor.execute(() -> executeSource(source.getId()));
        }
    }

    @Transactional
    public void executeSource(UUID sourceId) {
        GithubSbomSource source = githubSbomSourceRepository.findById(sourceId)
                .orElseThrow(() -> new EntityNotFoundException("GitHub SBOM source not found: " + sourceId));
        if (!source.isEnabled()) {
            return;
        }
        source.setLastRunStatus("running");
        source.setLastError(null);
        source.setLastRunAt(Instant.now());
        source.touch();
        githubSbomSourceRepository.save(source);

        Tenant tenant = tenantService.getDefaultTenant();
        try {
            sbomIngestionService.ingestFromGithub(tenant, new GithubSbomIngestionRequest(
                    source.getOwner(),
                    source.getRepo(),
                    false,
                    source.getAssetType(),
                    source.getAssetName(),
                    source.getAssetIdentifier()
            ));
            source.setLastRunStatus("completed");
            source.setLastError(null);
        } catch (Exception e) {
            source.setLastRunStatus("failed");
            source.setLastError(e.getMessage());
        }
        source.setLastRunAt(Instant.now());
        source.touch();
        githubSbomSourceRepository.save(source);
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
        String owner = request.owner().trim();
        String repo = request.repo().trim();
        String defaultAssetName = owner + "/" + repo;
        String defaultAssetIdentifier = "github:" + owner.toLowerCase(Locale.ROOT) + "/" + repo.toLowerCase(Locale.ROOT);

        source.setName(request.name().trim());
        source.setOwner(owner);
        source.setRepo(repo);
        source.setPath("dependency-graph/sbom");
        source.setAssetType(request.assetType() == null ? AssetType.APPLICATION : request.assetType());
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
    }

    private GithubSbomSourceResponse toResponse(GithubSbomSource source) {
        return new GithubSbomSourceResponse(
                source.getId(),
                source.getName(),
                source.getOwner(),
                source.getRepo(),
                source.getPath(),
                source.getAssetType().name(),
                source.getAssetName(),
                source.getAssetIdentifier(),
                source.getFrequency().name(),
                source.getIntervalMinutes(),
                source.isEnabled(),
                source.getLastRunAt(),
                source.getLastRunStatus(),
                source.getLastError()
        );
    }
}
