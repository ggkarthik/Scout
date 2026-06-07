package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import org.springframework.stereotype.Service;

@Service
public class FindingProjectionOperationsService {

    private final FindingListProjectionService findingListProjectionService;

    public FindingProjectionOperationsService(FindingListProjectionService findingListProjectionService) {
        this.findingListProjectionService = findingListProjectionService;
    }

    public FindingListProjectionService.ProjectionStatus inspectStatus(Tenant tenant) {
        return findingListProjectionService.inspectProjectionStatus(tenant);
    }

    public FindingListProjectionService.ProjectionStatus rebuild(Tenant tenant) {
        findingListProjectionService.refreshTenant(tenant);
        return findingListProjectionService.inspectProjectionStatus(tenant);
    }
}
