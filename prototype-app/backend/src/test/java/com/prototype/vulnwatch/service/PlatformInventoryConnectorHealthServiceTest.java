package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryConnectorHealthResponse;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PlatformInventoryConnectorHealthServiceTest {

    @Mock
    private TenantService tenantService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    @Mock
    private SccmCmdbConfigRepository sccmCmdbConfigRepository;
    @Mock
    private AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;

    private PlatformInventoryConnectorHealthService service;

    @BeforeEach
    void setUp() {
        service = new PlatformInventoryConnectorHealthService(
                tenantService,
                tenantSchemaExecutionService,
                serviceNowCmdbConfigRepository,
                sccmCmdbConfigRepository,
                awsDiscoveryConfigRepository
        );
        when(tenantSchemaExecutionService.run(any(Tenant.class), any(Supplier.class))).thenAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            java.util.function.Supplier<Object> supplier = invocation.getArgument(1);
            return supplier.get();
        });
    }

    @Test
    void listsConnectorHealthAcrossTenantSchemas() {
        Tenant alpha = tenant("Alpha");
        Tenant beta = tenant("Beta");
        when(tenantService.listTenants()).thenReturn(List.of(beta, alpha));

        ServiceNowCmdbConfig alphaSn = new ServiceNowCmdbConfig();
        alphaSn.setEnabled(true);
        alphaSn.setAutoSyncEnabled(true);
        alphaSn.setLastTestStatus("PASSED");
        alphaSn.setLastTestMessage("ok");
        alphaSn.setLastTestedAt(Instant.parse("2026-05-20T10:15:30Z"));
        alphaSn.setLastSyncAt(Instant.parse("2026-05-20T11:15:30Z"));

        AwsDiscoveryConfig betaAws = new AwsDiscoveryConfig();
        betaAws.setEnabled(false);
        betaAws.setAutoSyncEnabled(false);
        betaAws.setLastTestStatus("FAILED");
        betaAws.setLastTestMessage("credential problem");
        betaAws.setLastTestedAt(Instant.parse("2026-05-19T10:15:30Z"));

        when(serviceNowCmdbConfigRepository.findBySourceSystemIgnoreCase("servicenow"))
                .thenReturn(Optional.empty(), Optional.of(alphaSn));
        when(sccmCmdbConfigRepository.findBySourceSystemIgnoreCase("sccm"))
                .thenReturn(Optional.empty(), Optional.empty());
        when(awsDiscoveryConfigRepository.findBySourceSystemIgnoreCase("aws"))
                .thenReturn(Optional.of(betaAws), Optional.empty());

        List<InventoryConnectorHealthResponse> responses = service.listInventoryConnectorHealth();

        assertEquals(2, responses.size());
        assertEquals("Alpha", responses.get(0).tenantName());
        assertEquals("servicenow", responses.get(0).connectorKey());
        assertEquals("HEALTHY", responses.get(0).healthState());
        assertEquals("Beta", responses.get(1).tenantName());
        assertEquals("aws", responses.get(1).connectorKey());
        assertEquals("DISABLED", responses.get(1).healthState());
    }

    @Test
    void returnsEmptyListWhenNoTenantHasConnectorConfig() {
        Tenant tenant = tenant("Solo");
        when(tenantService.listTenants()).thenReturn(List.of(tenant));
        when(serviceNowCmdbConfigRepository.findBySourceSystemIgnoreCase("servicenow"))
                .thenReturn(Optional.empty());
        when(sccmCmdbConfigRepository.findBySourceSystemIgnoreCase("sccm"))
                .thenReturn(Optional.empty());
        when(awsDiscoveryConfigRepository.findBySourceSystemIgnoreCase("aws"))
                .thenReturn(Optional.empty());

        List<InventoryConnectorHealthResponse> responses = service.listInventoryConnectorHealth();

        assertTrue(responses.isEmpty());
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        tenant.setSlug(name.toLowerCase());
        tenant.setSchemaName("tenant_" + name.toLowerCase());
        return tenant;
    }
}
