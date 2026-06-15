package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
}
