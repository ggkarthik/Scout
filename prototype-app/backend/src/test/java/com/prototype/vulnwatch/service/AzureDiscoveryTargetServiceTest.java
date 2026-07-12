package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureDiscoveryClient;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.AzureDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryTargetRepository;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AzureDiscoveryTargetServiceTest {

    @Test
    void create_persistsTargetWithSubscriptionFields() {
        Tenant tenant = tenant();
        AzureDiscoveryConfig config = config(tenant);
        AzureDiscoveryTargetRepository targetRepository = mock(AzureDiscoveryTargetRepository.class);
        AzureDiscoveryConfigRepository configRepository = mock(AzureDiscoveryConfigRepository.class);
        when(configRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "azure"))
                .thenReturn(Optional.of(config));
        when(targetRepository.countByConfig(config)).thenReturn(1L);
        when(targetRepository.save(any(AzureDiscoveryTarget.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AzureDiscoveryTargetService service = service(configRepository, targetRepository);

        AzureDiscoveryTargetResponse response = service.create(tenant,
                new AzureDiscoveryTargetRequest("sub-1", "Sub One", true, "[\"eastus\"]"));

        assertEquals("sub-1", response.subscriptionId());
        assertEquals("Sub One", response.subscriptionName());
        assertTrue(response.enabled());
        assertEquals("[\"eastus\"]", response.regionsJson());
        assertEquals(0L, response.hostCount());
    }

    @Test
    void update_appliesRequestFieldsAndTouchesTarget() {
        Tenant tenant = tenant();
        AzureDiscoveryConfig config = config(tenant);
        AzureDiscoveryTarget existing = target(tenant, config, "sub-1", "Old Name");
        AzureDiscoveryTargetRepository targetRepository = mock(AzureDiscoveryTargetRepository.class);
        when(targetRepository.findByIdAndTenant_Id(existing.getId(), tenant.getId())).thenReturn(Optional.of(existing));
        when(targetRepository.save(any(AzureDiscoveryTarget.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AzureDiscoveryTargetService service = service(mock(AzureDiscoveryConfigRepository.class), targetRepository);

        AzureDiscoveryTargetResponse response = service.update(tenant, existing.getId(),
                new AzureDiscoveryTargetRequest("sub-1", "New Name", false, "[\"westus2\"]"));

        assertEquals("New Name", response.subscriptionName());
        assertEquals(false, response.enabled());
        assertEquals("[\"westus2\"]", response.regionsJson());
    }

    @Test
    void delete_removesTarget() {
        Tenant tenant = tenant();
        AzureDiscoveryConfig config = config(tenant);
        AzureDiscoveryTarget existing = target(tenant, config, "sub-1", "Sub One");
        AzureDiscoveryTargetRepository targetRepository = mock(AzureDiscoveryTargetRepository.class);
        when(targetRepository.findByIdAndTenant_Id(existing.getId(), tenant.getId())).thenReturn(Optional.of(existing));

        AzureDiscoveryTargetService service = service(mock(AzureDiscoveryConfigRepository.class), targetRepository);
        service.delete(tenant, existing.getId());

        org.mockito.Mockito.verify(targetRepository).delete(existing);
    }

    @Test
    void ensureLegacyTarget_migratesOneTargetPerSubscriptionId() {
        Tenant tenant = tenant();
        AzureDiscoveryConfig config = config(tenant);
        config.setSubscriptionIdsJson("[\"sub-1\",\"sub-2\",\"sub-3\"]");
        AzureDiscoveryTargetRepository targetRepository = mock(AzureDiscoveryTargetRepository.class);
        when(targetRepository.countByConfig(config)).thenReturn(0L);
        List<AzureDiscoveryTarget> saved = new ArrayList<>();
        when(targetRepository.save(any(AzureDiscoveryTarget.class))).thenAnswer(invocation -> {
            AzureDiscoveryTarget t = invocation.getArgument(0);
            saved.add(t);
            return t;
        });

        AzureDiscoveryTargetService service = service(mock(AzureDiscoveryConfigRepository.class), targetRepository);
        service.ensureLegacyTarget(config);

        assertEquals(3, saved.size());
        assertEquals(List.of("sub-1", "sub-2", "sub-3"),
                saved.stream().map(AzureDiscoveryTarget::getSubscriptionId).toList());
    }

    @Test
    void ensureLegacyTarget_noOpWhenTargetsAlreadyExist() {
        Tenant tenant = tenant();
        AzureDiscoveryConfig config = config(tenant);
        config.setSubscriptionIdsJson("[\"sub-1\"]");
        AzureDiscoveryTargetRepository targetRepository = mock(AzureDiscoveryTargetRepository.class);
        when(targetRepository.countByConfig(config)).thenReturn(1L);

        AzureDiscoveryTargetService service = service(mock(AzureDiscoveryConfigRepository.class), targetRepository);
        service.ensureLegacyTarget(config);

        org.mockito.Mockito.verify(targetRepository, org.mockito.Mockito.never()).save(any(AzureDiscoveryTarget.class));
    }

    private AzureDiscoveryTargetService service(
            AzureDiscoveryConfigRepository configRepository,
            AzureDiscoveryTargetRepository targetRepository
    ) {
        AssetRepository assetRepository = mock(AssetRepository.class);
        when(assetRepository.countByCloudProviderAndCloudAccountIdAndType(any(), any(), any())).thenReturn(0L);
        return new AzureDiscoveryTargetService(
                configRepository,
                targetRepository,
                assetRepository,
                mock(AzureDiscoveryClient.class),
                new ObjectMapper(),
                mock(TenantQuotaService.class),
                new CredentialEncryptionService(Base64.getEncoder().encodeToString(new byte[32]))
        );
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");
        return tenant;
    }

    private AzureDiscoveryConfig config(Tenant tenant) {
        AzureDiscoveryConfig config = new AzureDiscoveryConfig();
        ReflectionTestUtils.setField(config, "id", UUID.randomUUID());
        config.setTenant(tenant);
        return config;
    }

    private AzureDiscoveryTarget target(Tenant tenant, AzureDiscoveryConfig config, String subscriptionId, String name) {
        AzureDiscoveryTarget target = new AzureDiscoveryTarget();
        ReflectionTestUtils.setField(target, "id", UUID.randomUUID());
        target.setTenant(tenant);
        target.setConfig(config);
        target.setSubscriptionId(subscriptionId);
        target.setSubscriptionName(name);
        target.setEnabled(true);
        target.setRegionsJson("[\"eastus2\"]");
        return target;
    }
}
