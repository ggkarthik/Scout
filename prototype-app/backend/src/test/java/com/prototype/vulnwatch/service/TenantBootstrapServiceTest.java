package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TenantBootstrapServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private TenantSchemaService tenantSchemaService;
    @Mock
    private TenantSchemaStatusService tenantSchemaStatusService;

    private TenantBootstrapService service;

    @BeforeEach
    void setUp() {
        service = new TenantBootstrapService(tenantRepository, tenantSchemaService, tenantSchemaStatusService);
    }

    @Test
    void ensureBootstrapTenantNormalizesMalformedStoredSchemaNames() {
        Tenant defaultTenant = new Tenant();
        defaultTenant.setId(UUID.randomUUID());
        defaultTenant.setName(TenantService.DEFAULT_TENANT_NAME);
        defaultTenant.setSlug("default-workspace");
        defaultTenant.setSchemaName("tenant_default,platform");

        Tenant customerTenant = new Tenant();
        customerTenant.setId(UUID.randomUUID());
        customerTenant.setName("GM Test");
        customerTenant.setSlug("gm-test");
        customerTenant.setSchemaName("tenant_gm_test,platform");

        when(tenantSchemaService.defaultSchemaName()).thenReturn("tenant_default");
        when(tenantSchemaService.normalizeSchemaName(anyString())).thenAnswer(invocation -> {
            String schemaName = invocation.getArgument(0, String.class);
            return switch (schemaName) {
                case "tenant_default" -> "tenant_default";
                case "tenant_gm_test,platform" -> "tenant_gm_test_platform";
                default -> schemaName;
            };
        });
        when(tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)).thenReturn(Optional.of(defaultTenant));
        when(tenantRepository.findAll()).thenReturn(List.of(defaultTenant, customerTenant));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(tenantSchemaStatusService.hasProjection(defaultTenant.getId())).thenReturn(true);

        service.ensureBootstrapTenant();

        verify(tenantSchemaService, times(2)).assertSchemaReady("tenant_default");
        verify(tenantRepository, times(2)).save(any(Tenant.class));
        verify(tenantSchemaService).assertSchemaReady("tenant_gm_test_platform");
    }

    @Test
    void ensureBootstrapTenantMarksFreshDefaultSchemaCurrentBeforeReadinessCheck() {
        Tenant defaultTenant = new Tenant();
        defaultTenant.setId(UUID.randomUUID());
        defaultTenant.setName(TenantService.DEFAULT_TENANT_NAME);
        defaultTenant.setSlug("default-workspace");
        defaultTenant.setSchemaName("tenant_default");

        when(tenantSchemaService.defaultSchemaName()).thenReturn("tenant_default");
        when(tenantSchemaService.normalizeSchemaName("tenant_default")).thenReturn("tenant_default");
        when(tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)).thenReturn(Optional.of(defaultTenant));
        when(tenantRepository.findAll()).thenReturn(List.of(defaultTenant));
        when(tenantSchemaStatusService.hasProjection(defaultTenant.getId())).thenReturn(false);

        service.ensureBootstrapTenant();

        verify(tenantSchemaStatusService).markCurrent(
                any(UUID.class),
                anyString(),
                anyInt(),
                any(),
                any(UUID.class));
        verify(tenantSchemaService, times(2)).assertSchemaReady("tenant_default");
    }
}
