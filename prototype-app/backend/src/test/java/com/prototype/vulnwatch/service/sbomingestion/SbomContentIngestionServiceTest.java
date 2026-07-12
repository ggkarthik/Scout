package com.prototype.vulnwatch.service.sbomingestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ParsedComponent;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.InventoryComponentCpeMappingService;
import com.prototype.vulnwatch.service.SbomParserService;
import com.prototype.vulnwatch.service.SoftwareIdentitySummaryProjectionService;
import com.prototype.vulnwatch.service.SoftwareInventorySyncService;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

class SbomContentIngestionServiceTest {

    @Test
    void ingestBytes_setsAssetActiveAndInventoryTimestamp_withoutOpeningNestedTransaction() throws Exception {
        // Regression test for a deadlock: SbomContentIngestionService previously called
        // AssetLifecycleService.markInventoryIngested(asset), which opens a
        // PROPAGATION_REQUIRES_NEW transaction on a separate DB connection to re-save the
        // same asset row this method's own (still-open, uncommitted) outer transaction had
        // just created. For brand-new assets that nested save blocked in Postgres waiting on
        // this transaction to commit, while this transaction's thread was itself blocked
        // waiting on the nested save to return -- a permanent cross-connection deadlock that
        // left the per-asset SbomIngestionLockService lock held forever, so every retry for
        // the same asset failed with "An SBOM ingestion is already in progress for this asset."
        SbomParserService sbomParserService = mock(SbomParserService.class);
        SbomUploadRepository sbomUploadRepository = mock(SbomUploadRepository.class);
        InventoryComponentRepository inventoryComponentRepository = mock(InventoryComponentRepository.class);
        IdentityGraphService identityGraphService = mock(IdentityGraphService.class);
        InventoryComponentCpeMappingService inventoryComponentCpeMappingService =
                mock(InventoryComponentCpeMappingService.class);
        SoftwareInventorySyncService softwareInventorySyncService = mock(SoftwareInventorySyncService.class);
        FindingDeltaQueueService findingDeltaQueueService = mock(FindingDeltaQueueService.class);
        SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService =
                mock(SoftwareIdentitySummaryProjectionService.class);
        SbomUploadSupportService sbomUploadSupportService = mock(SbomUploadSupportService.class);
        EntityManager entityManager = mock(EntityManager.class);

        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        Asset newAsset = new Asset();
        newAsset.setTenant(tenant);
        newAsset.setIdentifier("pkg:npm/kanra-mobile@1.0.0");
        // Simulate a brand-new asset resolved (but not yet flushed/committed) by resolveAsset().
        newAsset.setState(AssetState.ACTIVE);

        when(sbomUploadSupportService.resolveAsset(tenant, AssetType.APPLICATION, "kanra-mobile", "pkg:npm/kanra-mobile@1.0.0"))
                .thenReturn(newAsset);
        when(sbomUploadSupportService.saveAsset(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sbomUploadRepository.save(any(SbomUpload.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sbomParserService.detectFormat(any(byte[].class))).thenReturn(com.prototype.vulnwatch.domain.SbomFormat.UNKNOWN);
        when(sbomParserService.parse(any(byte[].class))).thenReturn(List.<ParsedComponent>of());
        when(identityGraphService.resolveFromComponents(any())).thenReturn(Map.of());
        when(inventoryComponentRepository.findByAsset(any(Asset.class))).thenReturn(List.of());

        SbomContentIngestionService service = new SbomContentIngestionService(
                sbomParserService,
                sbomUploadRepository,
                inventoryComponentRepository,
                identityGraphService,
                inventoryComponentCpeMappingService,
                softwareInventorySyncService,
                findingDeltaQueueService,
                softwareIdentitySummaryProjectionService,
                sbomUploadSupportService
        );
        ReflectionTestUtils.setField(service, "entityManager", entityManager);

        service.ingestBytes(
                tenant,
                AssetType.APPLICATION,
                "kanra-mobile",
                "pkg:npm/kanra-mobile@1.0.0",
                "{}".getBytes(),
                "kanra-mobile-sbom.json",
                new SbomIngestionSourceMetadata("UPLOAD", "bom-upload", "kanra-mobile-sbom.json", null, null, null, 2L, null),
                null
        );

        ArgumentCaptor<Asset> savedAssetCaptor = ArgumentCaptor.forClass(Asset.class);
        Mockito.verify(sbomUploadSupportService).saveAsset(savedAssetCaptor.capture());
        Asset savedAsset = savedAssetCaptor.getValue();
        assertEquals(AssetState.ACTIVE, savedAsset.getState());
        assertNotNull(savedAsset.getLastInventoryAt());
    }
}
