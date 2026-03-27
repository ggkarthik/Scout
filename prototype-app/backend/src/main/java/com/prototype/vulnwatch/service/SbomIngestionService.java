package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.service.sbomingestion.GithubSbomIngestionCoordinator;
import com.prototype.vulnwatch.service.sbomingestion.SbomContentIngestionService;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchResult;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchService;
import com.prototype.vulnwatch.service.sbomingestion.SbomIngestionLockService;
import com.prototype.vulnwatch.service.sbomingestion.SbomUploadSupportService;
import java.io.IOException;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SbomIngestionService {

    private final SbomEndpointFetchService sbomEndpointFetchService;
    private final SbomContentIngestionService sbomContentIngestionService;
    private final GithubSbomIngestionCoordinator githubSbomIngestionCoordinator;
    private final SbomIngestionLockService sbomIngestionLockService;
    private final SbomUploadSupportService sbomUploadSupportService;

    public SbomIngestionService(
            SbomEndpointFetchService sbomEndpointFetchService,
            SbomContentIngestionService sbomContentIngestionService,
            GithubSbomIngestionCoordinator githubSbomIngestionCoordinator,
            SbomIngestionLockService sbomIngestionLockService,
            SbomUploadSupportService sbomUploadSupportService
    ) {
        this.sbomEndpointFetchService = sbomEndpointFetchService;
        this.sbomContentIngestionService = sbomContentIngestionService;
        this.githubSbomIngestionCoordinator = githubSbomIngestionCoordinator;
        this.sbomIngestionLockService = sbomIngestionLockService;
        this.sbomUploadSupportService = sbomUploadSupportService;
    }

    @Transactional
    public SbomIngestionResponse ingestFromEndpoint(Tenant tenant, SbomEndpointIngestionRequest request) throws IOException {
        SbomEndpointFetchResult fetchResult = sbomEndpointFetchService.fetch(request);
        return sbomIngestionLockService.withAssetLock(tenant, request.assetIdentifier(), () ->
                sbomContentIngestionService.ingestBytes(
                        tenant,
                        request.assetType(),
                        request.assetName(),
                        request.assetIdentifier(),
                        fetchResult.content(),
                        "endpoint-sbom.json",
                        fetchResult.metadata(),
                        null
                ));
    }

    @Transactional
    public GithubSbomIngestionBatchResponse ingestFromGithub(Tenant tenant, com.prototype.vulnwatch.dto.GithubSbomIngestionRequest request)
            throws IOException {
        return githubSbomIngestionCoordinator.ingestFromGithub(tenant, request);
    }

    @Transactional
    public GithubGhcrIngestionSummary ingestAllFromGithubContainerRegistry(Tenant tenant, String owner) throws IOException {
        return githubSbomIngestionCoordinator.ingestAllFromGithubContainerRegistry(tenant, owner);
    }

    @Transactional(readOnly = true)
    public List<SbomUploadEvidenceResponse> listUploads(Tenant tenant, String sourceSystem) {
        return sbomUploadSupportService.listUploads(tenant, sourceSystem);
    }

    public record GithubGhcrIngestionSummary(
            int imagesDiscovered,
            int imagesProcessed,
            int imagesSucceeded,
            int imagesFailed,
            int componentsIngested,
            int findingsGenerated,
            String failureSummary,
            List<GithubGhcrImageIngestionResult> results
    ) {
    }

    public record GithubGhcrImageIngestionResult(
            String imageRepository,
            String assetIdentifier,
            String status,
            Integer componentsIngested,
            Integer findingsGenerated,
            String message
    ) {
    }
}
