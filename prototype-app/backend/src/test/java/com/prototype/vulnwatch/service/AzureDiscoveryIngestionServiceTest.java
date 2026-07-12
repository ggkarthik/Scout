package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureResourceRecord;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AzureDiscoveryIngestionServiceTest {

    private static final String SUBSCRIPTION_ID = "sub-1";
    private static final String VM_RESOURCE_ID =
            "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1";

    @Test
    void ingestAll_createsCiRecordForHostAsset() {
        Tenant tenant = tenant();
        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        when(assetRepository.findByIdentifier(anyString())).thenReturn(Optional.empty());
        when(assetRepository.findAll()).thenReturn(List.of());
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.findBySysId(anyString())).thenReturn(Optional.empty());
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AzureDiscoveryIngestionService service = service(assetRepository, ciRepository);

        AzureDiscoveryIngestionService.IngestionResult result = service.ingestAll(
                List.of(vmRecord(VM_RESOURCE_ID, "eastus2")),
                config(tenant),
                tenant,
                Instant.parse("2026-04-24T00:00:00Z"),
                SUBSCRIPTION_ID
        );

        assertEquals(1, result.assetsUpserted());
        org.mockito.Mockito.verify(ciRepository).save(any(Ci.class));
    }

    @Test
    void ingestAll_doesNotCreateCiForNonHostResource() {
        Tenant tenant = tenant();
        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        when(assetRepository.findByIdentifier(anyString())).thenReturn(Optional.empty());
        when(assetRepository.findAll()).thenReturn(List.of());
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AzureDiscoveryIngestionService service = service(assetRepository, ciRepository);

        String webAppResourceId = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Web/sites/app-1";
        AzureResourceRecord webAppRecord = new AzureResourceRecord(
                SUBSCRIPTION_ID,
                webAppResourceId,
                "app-1",
                "Microsoft.Web/sites",
                "rg1",
                "eastus2",
                null,
                "Succeeded",
                Map.of()
        );

        service.ingestAll(List.of(webAppRecord), config(tenant), tenant, Instant.parse("2026-04-24T00:00:00Z"), SUBSCRIPTION_ID);

        org.mockito.Mockito.verifyNoInteractions(ciRepository);
    }

    @Test
    void ingestAll_marksOnlyObservedScopeAssetsInSameSubscriptionAsStale() {
        Tenant tenant = tenant();
        Instant runStart = Instant.parse("2026-04-24T00:00:00Z");
        Asset staleVmSameScope = cloudAsset(tenant, "/subscriptions/sub-1/.../virtualMachines/vm-stale",
                "Microsoft.Compute/virtualMachines", "eastus2", SUBSCRIPTION_ID, runStart.minusSeconds(60));
        Asset differentSubscription = cloudAsset(tenant, "/subscriptions/sub-2/.../virtualMachines/vm-other",
                "Microsoft.Compute/virtualMachines", "eastus2", "sub-2", runStart.minusSeconds(60));
        Asset differentScope = cloudAsset(tenant, "/subscriptions/sub-1/.../sites/app-other",
                "Microsoft.Web/sites", "eastus2", SUBSCRIPTION_ID, runStart.minusSeconds(60));

        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        when(assetRepository.findByIdentifier(anyString())).thenReturn(Optional.empty());
        when(assetRepository.findAll()).thenReturn(List.of(staleVmSameScope, differentSubscription, differentScope));
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.findBySysId(anyString())).thenReturn(Optional.empty());
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AzureDiscoveryIngestionService service = service(assetRepository, ciRepository);

        AzureDiscoveryIngestionService.IngestionResult result = service.ingestAll(
                List.of(vmRecord(VM_RESOURCE_ID, "eastus2")),
                config(tenant),
                tenant,
                runStart,
                SUBSCRIPTION_ID
        );

        assertEquals(1, result.assetsMarkedInactive());
        assertEquals(AssetState.INACTIVE, staleVmSameScope.getState());
        assertEquals(AssetState.ACTIVE, differentSubscription.getState());
        assertEquals(AssetState.ACTIVE, differentScope.getState());
    }

    private AzureDiscoveryIngestionService service(AssetRepository assetRepository, CiRepository ciRepository) {
        TenantSchemaExecutionService tenantSchemaExecutionService = mock(TenantSchemaExecutionService.class);
        doAnswer(invocation -> invocation.<Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(Supplier.class));
        return new AzureDiscoveryIngestionService(assetRepository, ciRepository, tenantSchemaExecutionService, new ObjectMapper());
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");
        return tenant;
    }

    private AzureDiscoveryConfig config(Tenant tenant) {
        AzureDiscoveryConfig config = new AzureDiscoveryConfig();
        config.setTenant(tenant);
        config.setSubscriptionIdsJson("[\"" + SUBSCRIPTION_ID + "\"]");
        return config;
    }

    private AzureResourceRecord vmRecord(String resourceId, String location) {
        return new AzureResourceRecord(
                SUBSCRIPTION_ID,
                resourceId,
                "vm-1",
                "Microsoft.Compute/virtualMachines",
                "rg1",
                location,
                null,
                "Succeeded",
                Map.of("env", "prod")
        );
    }

    private Asset cloudAsset(Tenant tenant, String identifier, String resourceType, String region, String subscriptionId, Instant lastSyncAt) {
        Asset asset = new Asset();
        ReflectionTestUtils.setField(asset, "id", UUID.randomUUID());
        asset.setTenant(tenant);
        asset.setType("Microsoft.Compute/virtualMachines".equals(resourceType) ? AssetType.HOST : AssetType.CLOUD_RESOURCE);
        asset.setName(identifier);
        asset.setIdentifier(identifier);
        asset.setState(AssetState.ACTIVE);
        asset.setCloudProvider("azure");
        asset.setCloudAccountId(subscriptionId);
        asset.setCloudResourceType(resourceType);
        asset.setCloudRegion(region);
        asset.setCloudArn(identifier);
        asset.setLastInventoryAt(lastSyncAt);
        asset.setLastCmdbSyncAt(lastSyncAt);
        return asset;
    }
}
