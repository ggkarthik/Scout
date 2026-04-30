package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TenantQuotaServiceTest {

    @Mock
    AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    @Mock
    AwsDiscoveryTargetRepository awsDiscoveryTargetRepository;
    @Mock
    SccmCmdbConfigRepository sccmCmdbConfigRepository;
    @Mock
    ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    @Mock
    ServiceAccountRepository serviceAccountRepository;
    @Mock
    AuditEventRepository auditEventRepository;
    @Mock
    TenantRepository tenantRepository;

    TenantQuotaService service;

    @BeforeEach
    void setUp() {
        service = new TenantQuotaService(
                awsDiscoveryConfigRepository,
                awsDiscoveryTargetRepository,
                sccmCmdbConfigRepository,
                serviceNowCmdbConfigRepository,
                serviceAccountRepository,
                auditEventRepository,
                tenantRepository);
    }

    @Test
    void assertCanCreateConnectorAllowsWhenBelowLimit() {
        Tenant tenant = tenant(3);
        when(awsDiscoveryConfigRepository.countByTenant_Id(tenant.getId())).thenReturn(1L);
        when(awsDiscoveryTargetRepository.countByTenant_Id(tenant.getId())).thenReturn(1L);
        when(sccmCmdbConfigRepository.countByTenant_Id(tenant.getId())).thenReturn(0L);
        when(serviceNowCmdbConfigRepository.countByTenant_Id(tenant.getId())).thenReturn(0L);

        assertDoesNotThrow(() -> service.assertCanCreateConnector(tenant, "aws-target"));
    }

    @Test
    void assertCanCreateConnectorRejectsWhenAtLimit() {
        Tenant tenant = tenant(2);
        when(awsDiscoveryConfigRepository.countByTenant_Id(tenant.getId())).thenReturn(1L);
        when(awsDiscoveryTargetRepository.countByTenant_Id(tenant.getId())).thenReturn(1L);
        when(sccmCmdbConfigRepository.countByTenant_Id(tenant.getId())).thenReturn(0L);
        when(serviceNowCmdbConfigRepository.countByTenant_Id(tenant.getId())).thenReturn(0L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanCreateConnector(tenant, "servicenow"));

        assertEquals("TENANT_CONNECTOR_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    @Test
    void assertCanCreateServiceAccountRejectsWhenAtLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxServiceAccountCount(1);
        when(serviceAccountRepository.countByTenant_Id(tenant.getId())).thenReturn(1L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanCreateServiceAccount(tenant));

        assertEquals("TENANT_SERVICE_ACCOUNT_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    @Test
    void assertCanRefreshTenantExposureAllowsWhenBelowDailyLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxDailyExposureRefreshes(3);
        when(auditEventRepository.countByTenant_IdAndActionAndOccurredAtAfter(
                eq(tenant.getId()),
                eq("tenant.org_cves.refresh"),
                any(Instant.class))).thenReturn(2L);

        assertDoesNotThrow(() -> service.assertCanRefreshTenantExposure(tenant));
    }

    @Test
    void assertCanRefreshTenantExposureRejectsWhenAtDailyLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxDailyExposureRefreshes(2);
        when(auditEventRepository.countByTenant_IdAndActionAndOccurredAtAfter(
                eq(tenant.getId()),
                eq("tenant.org_cves.refresh"),
                any(Instant.class))).thenReturn(2L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanRefreshTenantExposure(tenant));

        assertEquals("TENANT_EXPOSURE_REFRESH_DAILY_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    @Test
    void assertCanExportRowsRejectsWhenAboveLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxExportRows(5);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanExportRows(tenant, 6));

        assertEquals("TENANT_EXPORT_ROW_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    private Tenant tenant(int maxConnectorCount) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Acme");
        tenant.setSlug("acme");
        tenant.setMaxConnectorCount(maxConnectorCount);
        tenant.setMaxServiceAccountCount(25);
        tenant.setMaxDailyExposureRefreshes(25);
        return tenant;
    }
}
