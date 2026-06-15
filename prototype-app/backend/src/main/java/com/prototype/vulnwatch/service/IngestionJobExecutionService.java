package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class IngestionJobExecutionService {

    private final SbomIngestionService sbomIngestionService;
    private final GithubSbomSourceService githubSbomSourceService;
    private final IngestionJobService ingestionJobService;

    public IngestionJobExecutionService(
            SbomIngestionService sbomIngestionService,
            GithubSbomSourceService githubSbomSourceService,
            IngestionJobService ingestionJobService
    ) {
        this.sbomIngestionService = sbomIngestionService;
        this.githubSbomSourceService = githubSbomSourceService;
        this.ingestionJobService = ingestionJobService;
    }

    public ExecutionOutcome execute(Tenant tenant, IngestionJob job) throws IOException {
        return switch (job.getJobType()) {
            case IngestionJobService.JOB_TYPE_REMOTE_ENDPOINT -> executeEndpointJob(tenant, job);
            case IngestionJobService.JOB_TYPE_GITHUB_REPOSITORY -> executeGithubRepositoryJob(tenant, job);
            case IngestionJobService.JOB_TYPE_GITHUB_GHCR -> executeGithubGhcrJob(tenant, job);
            default -> throw new IOException("Unsupported ingestion job type: " + job.getJobType());
        };
    }

    private ExecutionOutcome executeEndpointJob(Tenant tenant, IngestionJob job) throws IOException {
        IngestionJobPayloads.EndpointIngestionPayload payload = ingestionJobService.readPayload(
                job,
                IngestionJobPayloads.EndpointIngestionPayload.class
        );
        SbomEndpointIngestionRequest request = new SbomEndpointIngestionRequest(
                payload.assetType(),
                payload.assetName(),
                payload.assetIdentifier(),
                payload.sourceUrl(),
                payload.sourceLabel(),
                ingestionJobService.decrypt(payload.encryptedAuthorizationHeader())
        );
        SbomIngestionResponse response = sbomIngestionService.executeEndpointJob(tenant, request);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("assetId", response.assetId());
        result.put("sbomUploadId", response.sbomUploadId());
        result.put("componentsIngested", response.componentsIngested());
        result.put("findingsGenerated", response.findingsGenerated());
        SbomUpload sbomUpload = sbomIngestionService.getSbomUpload(tenant, response.sbomUploadId());
        return new ExecutionOutcome(sbomUpload, ingestionJobService.toJson(result));
    }

    private ExecutionOutcome executeGithubRepositoryJob(Tenant tenant, IngestionJob job) throws IOException {
        IngestionJobPayloads.GithubRepositoryIngestionPayload payload = ingestionJobService.readPayload(
                job,
                IngestionJobPayloads.GithubRepositoryIngestionPayload.class
        );
        githubSbomSourceService.processRepositoryJob(
                tenant,
                payload.syncRunId(),
                payload.sourceId(),
                new GithubSbomIngestionRequest(
                        payload.owner(),
                        payload.repo(),
                        payload.includeAllRepos(),
                        payload.assetType(),
                        payload.assetName(),
                        payload.assetIdentifier()
                )
        );
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("syncRunId", payload.syncRunId());
        result.put("sourceId", payload.sourceId());
        return new ExecutionOutcome(null, ingestionJobService.toJson(result));
    }

    private ExecutionOutcome executeGithubGhcrJob(Tenant tenant, IngestionJob job) throws IOException {
        IngestionJobPayloads.GithubGhcrIngestionPayload payload = ingestionJobService.readPayload(
                job,
                IngestionJobPayloads.GithubGhcrIngestionPayload.class
        );
        githubSbomSourceService.processGhcrJob(tenant, payload.syncRunId(), payload.sourceId(), payload.owner());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("syncRunId", payload.syncRunId());
        result.put("sourceId", payload.sourceId());
        result.put("owner", payload.owner());
        return new ExecutionOutcome(null, ingestionJobService.toJson(result));
    }

    public record ExecutionOutcome(
            SbomUpload sbomUpload,
            String resultJson
    ) {
    }
}
