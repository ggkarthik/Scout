package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import org.springframework.stereotype.Service;

@Service
public class QualityIssueProjectionService {

    private final QualityIssueRefreshService qualityIssueRefreshService;

    public QualityIssueProjectionService(QualityIssueRefreshService qualityIssueRefreshService) {
        this.qualityIssueRefreshService = qualityIssueRefreshService;
    }

    public int refreshAll() {
        return qualityIssueRefreshService.refreshAll();
    }

    public int refreshTenant(Tenant tenant) {
        return qualityIssueRefreshService.refreshTenant(tenant);
    }

    public void ensureTenantProjection(Tenant tenant) {
        qualityIssueRefreshService.ensureTenantProjection(tenant);
    }
}
