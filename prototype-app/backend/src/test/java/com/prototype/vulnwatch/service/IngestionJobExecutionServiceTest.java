package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import java.io.IOException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IngestionJobExecutionServiceTest {

    @Mock
    private SbomIngestionService sbomIngestionService;
    @Mock
    private GithubSbomSourceService githubSbomSourceService;
    @Mock
    private IngestionJobService ingestionJobService;

    @Test
    void executeEndpointJobRehydratesPayloadAndReturnsSbomUploadResult() throws Exception {
        Tenant tenant = tenant();
        IngestionJob job = job(IngestionJobService.JOB_TYPE_REMOTE_ENDPOINT);
        IngestionJobPayloads.EndpointIngestionPayload payload = new IngestionJobPayloads.EndpointIngestionPayload(
                AssetType.CONTAINER_IMAGE,
                "Payments API",
                "asset-1",
                "https://example.com/sbom.json",
                "nightly",
                "enc-token"
        );
        UUID assetId = UUID.randomUUID();
        UUID sbomUploadId = UUID.randomUUID();
        SbomUpload sbomUpload = new SbomUpload();
        setId(sbomUpload, sbomUploadId);
        when(ingestionJobService.readPayload(job, IngestionJobPayloads.EndpointIngestionPayload.class)).thenReturn(payload);
        when(ingestionJobService.decrypt("enc-token")).thenReturn("Bearer token");
        when(sbomIngestionService.executeEndpointJob(any(Tenant.class), any(SbomEndpointIngestionRequest.class)))
                .thenReturn(new SbomIngestionResponse(assetId, sbomUploadId, 42, 0));
        when(sbomIngestionService.getSbomUpload(tenant, sbomUploadId)).thenReturn(sbomUpload);
        when(ingestionJobService.toJson(any())).thenAnswer(invocation -> invocation.getArgument(0).toString());

        IngestionJobExecutionService service = new IngestionJobExecutionService(
                sbomIngestionService,
                githubSbomSourceService,
                ingestionJobService
        );

        IngestionJobExecutionService.ExecutionOutcome outcome = service.execute(tenant, job);

        assertEquals(sbomUpload, outcome.sbomUpload());
        assertNotNull(outcome.resultJson());
        verify(sbomIngestionService).executeEndpointJob(
                any(Tenant.class),
                any(SbomEndpointIngestionRequest.class)
        );
    }

    @Test
    void executeGithubRepositoryJobDelegatesToGithubSourceService() throws Exception {
        Tenant tenant = tenant();
        IngestionJob job = job(IngestionJobService.JOB_TYPE_GITHUB_REPOSITORY);
        UUID syncRunId = UUID.randomUUID();
        UUID sourceId = UUID.randomUUID();
        IngestionJobPayloads.GithubRepositoryIngestionPayload payload = new IngestionJobPayloads.GithubRepositoryIngestionPayload(
                "acme",
                "payments",
                false,
                AssetType.APPLICATION,
                "Payments API",
                "asset-1",
                syncRunId,
                sourceId
        );
        when(ingestionJobService.readPayload(job, IngestionJobPayloads.GithubRepositoryIngestionPayload.class)).thenReturn(payload);
        when(ingestionJobService.toJson(any())).thenAnswer(invocation -> invocation.getArgument(0).toString());

        IngestionJobExecutionService service = new IngestionJobExecutionService(
                sbomIngestionService,
                githubSbomSourceService,
                ingestionJobService
        );

        IngestionJobExecutionService.ExecutionOutcome outcome = service.execute(tenant, job);

        assertEquals(null, outcome.sbomUpload());
        verify(githubSbomSourceService).processRepositoryJob(
                tenant,
                syncRunId,
                sourceId,
                new GithubSbomIngestionRequest("acme", "payments", false, AssetType.APPLICATION, "Payments API", "asset-1")
        );
    }

    @Test
    void executeRejectsUnsupportedJobType() {
        Tenant tenant = tenant();
        IngestionJob job = job("LEGACY_SYNC");
        IngestionJobExecutionService service = new IngestionJobExecutionService(
                sbomIngestionService,
                githubSbomSourceService,
                ingestionJobService
        );

        IOException error = assertThrows(IOException.class, () -> service.execute(tenant, job));

        assertEquals("Unsupported ingestion job type: LEGACY_SYNC", error.getMessage());
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Acme");
        return tenant;
    }

    private IngestionJob job(String jobType) {
        IngestionJob job = new IngestionJob();
        job.setJobType(jobType);
        job.setSourceType("github");
        job.setAssetIdentifier("asset-1");
        return job;
    }

    private void setId(SbomUpload sbomUpload, UUID id) throws Exception {
        java.lang.reflect.Field idField = SbomUpload.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(sbomUpload, id);
    }
}
