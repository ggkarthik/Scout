package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TenantQuotaService {

    private final AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    private final AwsDiscoveryTargetRepository awsDiscoveryTargetRepository;
    private final SccmCmdbConfigRepository sccmCmdbConfigRepository;
    private final ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    private final ServiceAccountRepository serviceAccountRepository;
    private final AuditEventRepository auditEventRepository;
    private final TenantRepository tenantRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public TenantQuotaService(
            AwsDiscoveryConfigRepository awsDiscoveryConfigRepository,
            AwsDiscoveryTargetRepository awsDiscoveryTargetRepository,
            SccmCmdbConfigRepository sccmCmdbConfigRepository,
            ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository,
            ServiceAccountRepository serviceAccountRepository,
            AuditEventRepository auditEventRepository,
            TenantRepository tenantRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.awsDiscoveryConfigRepository = awsDiscoveryConfigRepository;
        this.awsDiscoveryTargetRepository = awsDiscoveryTargetRepository;
        this.sccmCmdbConfigRepository = sccmCmdbConfigRepository;
        this.serviceNowCmdbConfigRepository = serviceNowCmdbConfigRepository;
        this.serviceAccountRepository = serviceAccountRepository;
        this.auditEventRepository = auditEventRepository;
        this.tenantRepository = tenantRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional(readOnly = true)
    public void assertCanCreateConnector(Tenant tenant, String connectorType) {
        if (isUnlimitedConnectorMode(tenant)) {
            return;
        }
        int max = safeLimit(tenant.getMaxConnectorCount());
        long current = countConnectors(tenant);
        if (current >= max) {
            throw new QuotaExceededException(
                    "TENANT_CONNECTOR_LIMIT_EXCEEDED",
                    "Tenant connector limit exceeded for " + connectorType + " (" + current + "/" + max + ")"
            );
        }
    }

    @Transactional(readOnly = true)
    public void assertCanCreateServiceAccount(Tenant tenant) {
        int max = safeLimit(tenant.getMaxServiceAccountCount());
        long current = tenantSchemaExecutionService.run(tenant, (Supplier<Long>) serviceAccountRepository::count);
        if (current >= max) {
            throw new QuotaExceededException(
                    "TENANT_SERVICE_ACCOUNT_LIMIT_EXCEEDED",
                    "Tenant service account limit exceeded (" + current + "/" + max + ")"
            );
        }
    }

    @Transactional(readOnly = true)
    public void assertCanRefreshTenantExposure(Tenant tenant) {
        int max = safeLimit(tenant.getMaxDailyExposureRefreshes());
        Instant since = Instant.now().minus(24, ChronoUnit.HOURS);
        long current = auditEventRepository.countByTenant_IdAndActionAndOccurredAtAfter(
                tenant.getId(),
                "tenant.org_cves.refresh",
                since);
        if (current >= max) {
            throw new QuotaExceededException(
                    "TENANT_EXPOSURE_REFRESH_DAILY_LIMIT_EXCEEDED",
                    "Tenant exposure refresh daily limit exceeded (" + current + "/" + max + ")"
            );
        }
    }

    public void assertCanExportRows(Tenant tenant, long requestedRows) {
        int max = safeLimit(tenant.getMaxExportRows());
        if (requestedRows > max) {
            throw new QuotaExceededException(
                    "TENANT_EXPORT_ROW_LIMIT_EXCEEDED",
                    "Tenant export row limit exceeded (" + requestedRows + "/" + max + ")"
            );
        }
    }

    @Transactional(readOnly = true)
    public void assertCanExportRows(UUID tenantId, long requestedRows) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        assertCanExportRows(tenant, requestedRows);
    }

    private long countConnectors(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () ->
                (awsDiscoveryConfigRepository.findBySourceSystemIgnoreCase("aws").isPresent() ? 1L : 0L)
                        + awsDiscoveryTargetRepository.count()
                        + (sccmCmdbConfigRepository.findBySourceSystemIgnoreCase("sccm").isPresent() ? 1L : 0L)
                        + (serviceNowCmdbConfigRepository.findBySourceSystemIgnoreCase("servicenow").isPresent() ? 1L : 0L)
        );
    }

    private int safeLimit(Integer value) {
        return value == null ? 0 : Math.max(0, value);
    }

    /**
     * Temporary policy: a connector limit of zero means "unlimited" rather than
     * "none allowed", so older demo tenants and any manually provisioned tenant
     * with a zero quota do not get blocked from configuring integrations.
     */
    private boolean isUnlimitedConnectorMode(Tenant tenant) {
        return tenant != null && safeLimit(tenant.getMaxConnectorCount()) == 0;
    }
}
