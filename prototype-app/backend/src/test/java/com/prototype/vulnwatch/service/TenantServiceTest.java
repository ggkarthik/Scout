package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class TenantServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private TenantSchemaService tenantSchemaService;

    private TenantService tenantService;

    @BeforeEach
    void setUp() {
        tenantService = new TenantService(tenantRepository, tenantSchemaService);
    }

    @Test
    void updateQuotasPersistsTenantSpecificIngestionAdmissionLimits() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantRepository.save(tenant)).thenReturn(tenant);

        Tenant updated = tenantService.updateQuotas(
                tenantId,
                new TenantQuotaUpdateRequest(15, 30, 150, 75000, 40, 120, 8, 2)
        );

        assertEquals(15, updated.getMaxConnectorCount());
        assertEquals(30, updated.getMaxServiceAccountCount());
        assertEquals(150, updated.getMaxDailySbomUploads());
        assertEquals(75000, updated.getMaxExportRows());
        assertEquals(40, updated.getMaxDailyExposureRefreshes());
        assertEquals(120, updated.getSbomRateLimitWindowSeconds());
        assertEquals(8, updated.getMaxSbomJobsPerRateLimitWindow());
        assertEquals(2, updated.getMaxActiveSbomJobs());
        verify(tenantRepository).save(tenant);
    }

    @Test
    void tenantCreationKeepsDemoDataOptionalAndRecordsExplicitOptIn() {
        when(tenantSchemaService.deriveSchemaName(org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(invocation -> "tenant_" + invocation.getArgument(0));
        when(tenantRepository.save(org.mockito.ArgumentMatchers.any(Tenant.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        Tenant withoutDemoData = tenantService.createTenant("Plain Tenant", "plain", null, null);
        Tenant withDemoData = tenantService.createTenant("Kanra", "kanra", null, null, true);

        assertEquals(false, withoutDemoData.isDemoDataRequested());
        assertEquals("NOT_REQUESTED", withoutDemoData.getDemoDataStatus());
        assertEquals(true, withDemoData.isDemoDataRequested());
        assertEquals("REQUESTED", withDemoData.getDemoDataStatus());
    }

    @Test
    void updateQuotasAllowsNullAdmissionOverridesToFallBackToDefaults() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantRepository.save(tenant)).thenReturn(tenant);

        Tenant updated = tenantService.updateQuotas(
                tenantId,
                new TenantQuotaUpdateRequest(15, 30, 150, 75000, 40, null, null, null)
        );

        assertNull(updated.getSbomRateLimitWindowSeconds());
        assertNull(updated.getMaxSbomJobsPerRateLimitWindow());
        assertNull(updated.getMaxActiveSbomJobs());
    }

    @Test
    void updateQuotasRejectsNegativeValues() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> tenantService.updateQuotas(
                        tenantId,
                        new TenantQuotaUpdateRequest(15, 30, 150, 75000, 40, -1, 8, 2)
                )
        );

        assertEquals("sbomRateLimitWindowSeconds must be >= 0", ex.getMessage());
    }

    @Test
    void listActiveTenantsFiltersInactiveAndDeletedTenants() {
        Tenant active = new Tenant();
        active.setName("Active");
        active.setStatus("ACTIVE");
        Tenant suspended = new Tenant();
        suspended.setName("Suspended");
        suspended.setStatus("SUSPENDED");
        Tenant expired = new Tenant();
        expired.setName("Expired");
        expired.setStatus("ACTIVE");
        expired.setExpiredAt(Instant.now());
        Tenant purging = new Tenant();
        purging.setName("Purging");
        purging.setStatus("ACTIVE");
        purging.setPurgeStartedAt(Instant.now());
        Tenant deleted = new Tenant();
        deleted.setName("Deleted");
        deleted.setStatus("ACTIVE");
        deleted.setDeletedAt(Instant.now());
        when(tenantRepository.findAllByOrderByCreatedAtAsc())
                .thenReturn(List.of(active, suspended, expired, purging, deleted));

        List<Tenant> tenants = tenantService.listActiveTenants();

        assertEquals(List.of(active), tenants);
    }

    @Test
    void getDefaultTenantFallsBackToSchemaName() {
        Tenant tenant = new Tenant();
        tenant.setName("Platform Workspace");
        tenant.setSchemaName(TenantService.DEFAULT_TENANT_SCHEMA);
        when(tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)).thenReturn(Optional.empty());
        when(tenantRepository.findBySchemaName(TenantService.DEFAULT_TENANT_SCHEMA)).thenReturn(Optional.of(tenant));

        Tenant resolved = tenantService.getDefaultTenant();

        assertSame(tenant, resolved);
    }

    @Test
    void getDefaultTenantFallsBackToFirstActiveTenant() {
        Tenant suspended = new Tenant();
        suspended.setName("Suspended");
        suspended.setStatus("SUSPENDED");
        suspended.setDeletedAt(null);
        Tenant active = new Tenant();
        active.setName("Customer A");
        active.setStatus("ACTIVE");
        when(tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)).thenReturn(Optional.empty());
        when(tenantRepository.findBySchemaName(TenantService.DEFAULT_TENANT_SCHEMA)).thenReturn(Optional.empty());
        when(tenantRepository.findAllByOrderByCreatedAtAsc()).thenReturn(List.of(suspended, active));

        Tenant resolved = tenantService.getDefaultTenant();

        assertSame(active, resolved);
    }

    @Test
    void getDefaultTenantIgnoresDeletedOrPurgedTenantsWhenFallingBack() {
        Tenant deleted = new Tenant();
        deleted.setName("Deleted");
        deleted.setStatus("ACTIVE");
        deleted.setDeletedAt(Instant.now());
        Tenant purged = new Tenant();
        purged.setName("Purged");
        purged.setStatus("ACTIVE");
        purged.setPurgedAt(Instant.now());
        when(tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)).thenReturn(Optional.empty());
        when(tenantRepository.findBySchemaName(TenantService.DEFAULT_TENANT_SCHEMA)).thenReturn(Optional.empty());
        when(tenantRepository.findAllByOrderByCreatedAtAsc()).thenReturn(List.of(deleted, purged));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, tenantService::getDefaultTenant);

        assertEquals("404 NOT_FOUND \"Default workspace not found\"", ex.getMessage());
    }
}
