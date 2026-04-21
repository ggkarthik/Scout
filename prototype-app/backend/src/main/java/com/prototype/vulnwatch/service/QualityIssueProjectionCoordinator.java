package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import org.springframework.stereotype.Service;

@Service
public class QualityIssueProjectionCoordinator {

    private final QualityIssueProjectionService qualityIssueProjectionService;

    public QualityIssueProjectionCoordinator(QualityIssueProjectionService qualityIssueProjectionService) {
        this.qualityIssueProjectionService = qualityIssueProjectionService;
    }

    public void refreshTenant(Tenant tenant) {
        qualityIssueProjectionService.refreshTenant(tenant);
    }
}
