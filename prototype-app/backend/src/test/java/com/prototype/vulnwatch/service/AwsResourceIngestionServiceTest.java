package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsResourceRecord;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AwsResourceIngestionServiceTest {

    private static final String ACCOUNT_ID = "123456789012";
    private static final String BLANK_ACCOUNT_EC2_ARN = "arn:aws:ec2:us-east-1::instance/i-0123456789abcdef0";
    private static final String CANONICAL_EC2_ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0";

    @Test
    void ingestAll_marksOnlyObservedResourceScopesStale() {
        Tenant tenant = tenant();
        Instant runStart = Instant.parse("2026-04-24T00:00:00Z");
        Asset staleEc2 = cloudAsset(tenant, "arn:aws:ec2:us-east-1:123456789012:instance/i-stale", "EC2", "us-east-1", runStart.minusSeconds(60));
        Asset otherCloudAsset = cloudAsset(tenant, "azure:/subscriptions/demo/resourceGroups/rg/providers/Microsoft.Sql/servers/stale", "AZURE_SQL", "eastus", runStart.minusSeconds(60));
        otherCloudAsset.setCloudProvider("azure");
        AwsResourceIngestionService service = service(tenant, List.of(staleEc2, otherCloudAsset));

        AwsResourceIngestionService.IngestionResult result = service.ingestAll(
                List.of(ec2Record(BLANK_ACCOUNT_EC2_ARN)),
                config(tenant),
                tenant,
                runStart
        );

        assertEquals(1, result.assetsMarkedInactive());
        assertEquals(AssetState.INACTIVE, staleEc2.getState());
        assertEquals(AssetState.ACTIVE, otherCloudAsset.getState());
    }

    @Test
    void ingestAll_upgradesBlankAccountEc2ArnWithoutCreatingANewCi() {
        Tenant tenant = tenant();
        Instant runStart = Instant.parse("2026-04-24T00:00:00Z");
        Asset existingAsset = cloudAsset(tenant, BLANK_ACCOUNT_EC2_ARN, "EC2", "us-east-1", runStart.minusSeconds(60));
        Ci existingCi = new Ci();
        existingCi.setTenant(tenant);
        existingCi.setAsset(existingAsset);
        existingCi.setSysId(BLANK_ACCOUNT_EC2_ARN);
        existingCi.setDisplayName("old-host");

        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        when(assetRepository.findByIdentifier(CANONICAL_EC2_ARN)).thenReturn(Optional.empty());
        when(assetRepository.findByIdentifier(BLANK_ACCOUNT_EC2_ARN)).thenReturn(Optional.of(existingAsset));
        when(assetRepository.findAll()).thenReturn(List.of());
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.findBySysId(CANONICAL_EC2_ARN)).thenReturn(Optional.empty());
        when(ciRepository.findByAsset_Id(eq(existingAsset.getId()))).thenReturn(Optional.of(existingCi));
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AwsResourceIngestionService service = service(assetRepository, ciRepository);

        service.ingestAll(List.of(ec2Record(BLANK_ACCOUNT_EC2_ARN)), config(tenant), tenant, runStart);

        assertEquals(CANONICAL_EC2_ARN, existingAsset.getIdentifier());
        assertEquals(CANONICAL_EC2_ARN, existingAsset.getCloudArn());
        assertEquals(CANONICAL_EC2_ARN, existingCi.getSysId());
        assertEquals(existingAsset, existingCi.getAsset());
    }

    private AwsResourceIngestionService service(Tenant tenant, List<Asset> existingAssets) {
        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        when(assetRepository.findByIdentifier(anyString())).thenReturn(Optional.empty());
        when(assetRepository.findAll()).thenReturn(existingAssets);
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.findBySysId(anyString())).thenReturn(Optional.empty());
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));
        return service(assetRepository, ciRepository);
    }

    private AwsResourceIngestionService service(AssetRepository assetRepository, CiRepository ciRepository) {
        TenantSchemaExecutionService tenantSchemaExecutionService = mock(TenantSchemaExecutionService.class);
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));
        return new AwsResourceIngestionService(
                assetRepository,
                ciRepository,
                mock(CmdbIngestionService.class),
                new ObjectMapper(),
                mock(EntityManager.class),
                tenantSchemaExecutionService
        );
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");
        return tenant;
    }

    private AwsDiscoveryConfig config(Tenant tenant) {
        AwsDiscoveryConfig config = new AwsDiscoveryConfig();
        config.setTenant(tenant);
        config.setAwsAccountId(ACCOUNT_ID);
        return config;
    }

    private Asset cloudAsset(Tenant tenant, String identifier, String resourceType, String region, Instant lastSyncAt) {
        Asset asset = new Asset();
        ReflectionTestUtils.setField(asset, "id", UUID.randomUUID());
        asset.setTenant(tenant);
        asset.setType("EC2".equals(resourceType) ? AssetType.HOST : AssetType.CLOUD_RESOURCE);
        asset.setName(identifier);
        asset.setIdentifier(identifier);
        asset.setState(AssetState.ACTIVE);
        asset.setCloudProvider("aws");
        asset.setCloudAccountId(ACCOUNT_ID);
        asset.setCloudResourceType(resourceType);
        asset.setCloudRegion(region);
        asset.setCloudArn(identifier);
        asset.setLastCmdbSyncAt(lastSyncAt);
        return asset;
    }

    private AwsResourceRecord ec2Record(String arn) {
        return new AwsResourceRecord(
                "EC2",
                arn,
                "app-01",
                "us-east-1",
                "us-east-1a",
                "",
                "t3.medium",
                "vpc-1",
                "subnet-1",
                "Linux/UNIX",
                "running",
                Instant.parse("2026-04-23T00:00:00Z"),
                Map.of("Name", "app-01"),
                "arn:aws:iam::" + ACCOUNT_ID + ":instance-profile/EC2-SSM-Profile"
        );
    }
}
