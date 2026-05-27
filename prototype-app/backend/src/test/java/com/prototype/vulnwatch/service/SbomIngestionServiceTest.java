package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.service.sbomingestion.GithubSbomIngestionCoordinator;
import com.prototype.vulnwatch.service.sbomingestion.SbomContentIngestionService;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchResult;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchService;
import com.prototype.vulnwatch.service.sbomingestion.SbomIngestionLockService;
import com.prototype.vulnwatch.service.sbomingestion.SbomIngestionSourceMetadata;
import com.prototype.vulnwatch.service.sbomingestion.SbomUploadSupportService;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SbomIngestionServiceTest {

    @Mock private SbomEndpointFetchService sbomEndpointFetchService;
    @Mock private SbomContentIngestionService sbomContentIngestionService;
    @Mock private GithubSbomIngestionCoordinator githubSbomIngestionCoordinator;
    @Mock private SbomIngestionLockService sbomIngestionLockService;
    @Mock private SbomUploadSupportService sbomUploadSupportService;

    private SbomIngestionService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        service = new SbomIngestionService(
                sbomEndpointFetchService,
                sbomContentIngestionService,
                githubSbomIngestionCoordinator,
                sbomIngestionLockService,
                sbomUploadSupportService
        );
        tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        tenant.setName("default");
    }

    @Test
    @SuppressWarnings("unchecked")
    void ingestFromEndpointFetchesThenIngestsViaLock() throws Exception {
        byte[] content = "{\"bomFormat\":\"CycloneDX\"}".getBytes();
        SbomIngestionSourceMetadata metadata = new SbomIngestionSourceMetadata(
                "endpoint", null, null, "https://example.com/sbom.json", 200, "application/json", null, null);
        SbomEndpointFetchResult fetchResult = new SbomEndpointFetchResult(content, metadata);
        SbomIngestionResponse expected = new SbomIngestionResponse(
                UUID.randomUUID(), UUID.randomUUID(), 5, 2);

        SbomEndpointIngestionRequest request = new SbomEndpointIngestionRequest(
                AssetType.HOST, "web-prod-01", "web-prod-01.example.com",
                "https://example.com/sbom.json", null, null);

        when(sbomEndpointFetchService.fetch(request)).thenReturn(fetchResult);
        when(sbomIngestionLockService.withAssetLock(eq(tenant), eq("web-prod-01.example.com"), any(Callable.class)))
                .thenAnswer(inv -> ((Callable<?>) inv.getArgument(2)).call());
        when(sbomContentIngestionService.ingestBytes(
                eq(tenant), eq(AssetType.HOST), eq("web-prod-01"), eq("web-prod-01.example.com"),
                eq(content), eq("endpoint-sbom.json"), eq(metadata), isNull()
        )).thenReturn(expected);

        SbomIngestionResponse result = service.ingestFromEndpoint(tenant, request);

        assertSame(expected, result);
        verify(sbomEndpointFetchService).fetch(request);
        verify(sbomIngestionLockService).withAssetLock(eq(tenant), eq("web-prod-01.example.com"), any(Callable.class));
        verify(sbomContentIngestionService).ingestBytes(
                eq(tenant), eq(AssetType.HOST), eq("web-prod-01"), eq("web-prod-01.example.com"),
                eq(content), eq("endpoint-sbom.json"), eq(metadata), isNull());
    }

    @Test
    void ingestFromGithubDelegatesToCoordinator() throws Exception {
        GithubSbomIngestionRequest request = new GithubSbomIngestionRequest(
                "acme-org", "api-service", false, AssetType.HOST, null, null);
        GithubSbomIngestionBatchResponse expected = new GithubSbomIngestionBatchResponse(
                1, 1, 1, 0, 10, 2, List.of());
        when(githubSbomIngestionCoordinator.ingestFromGithub(tenant, request)).thenReturn(expected);

        GithubSbomIngestionBatchResponse result = service.ingestFromGithub(tenant, request);

        assertSame(expected, result);
        verify(githubSbomIngestionCoordinator).ingestFromGithub(tenant, request);
    }

    @Test
    void listUploadsDelegatesToSupportService() {
        List<SbomUploadEvidenceResponse> expected = List.of();
        when(sbomUploadSupportService.listUploads(tenant, "github")).thenReturn(expected);

        List<SbomUploadEvidenceResponse> result = service.listUploads(tenant, "github");

        assertSame(expected, result);
        verify(sbomUploadSupportService).listUploads(tenant, "github");
    }

    @Test
    void listUploadsWithNullSourceDelegatesToSupportService() {
        List<SbomUploadEvidenceResponse> expected = List.of();
        when(sbomUploadSupportService.listUploads(tenant, null)).thenReturn(expected);

        List<SbomUploadEvidenceResponse> result = service.listUploads(tenant, null);

        assertSame(expected, result);
        verify(sbomUploadSupportService).listUploads(tenant, null);
    }
}
