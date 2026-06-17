package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TenantSchemaExecutionServiceTest {

    @Mock
    private TenantService tenantService;

    @Mock
    private TenantSchemaService tenantSchemaService;

    private TenantSchemaExecutionService service;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
        service = new TenantSchemaExecutionService(tenantService, tenantSchemaService);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void runWithTenantEnsuresProvisionedSchemaBeforeExecutingSupplier() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setSchemaName("tenant_acme");

        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_acme");

        String result = service.run(tenant, () -> {
            assertThat(TenantContext.getCurrentTenantId()).isEqualTo(tenantId);
            assertThat(TenantContext.getCurrentSchemaName()).isEqualTo("tenant_acme");
            return "ok";
        });

        assertThat(result).isEqualTo("ok");
        verify(tenantSchemaService).schemaNameForTenant(tenant);
        verify(tenantSchemaService).ensureSchemaExists("tenant_acme");
        verify(tenantService, never()).resolveTenantUuid(tenantId);
    }

    @Test
    void runWithTenantIdResolvesAndEnsuresSchemaBeforeExecutingSupplier() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setSchemaName("tenant_acme");

        when(tenantService.resolveTenantUuid(tenantId)).thenReturn(tenant);
        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_acme");

        String result = service.run(tenantId, () -> {
            assertThat(TenantContext.getCurrentTenantId()).isEqualTo(tenantId);
            assertThat(TenantContext.getCurrentSchemaName()).isEqualTo("tenant_acme");
            return "ok";
        });

        assertThat(result).isEqualTo("ok");
        verify(tenantService).resolveTenantUuid(tenantId);
        verify(tenantSchemaService).schemaNameForTenant(tenant);
        verify(tenantSchemaService).ensureSchemaExists("tenant_acme");
    }
}
