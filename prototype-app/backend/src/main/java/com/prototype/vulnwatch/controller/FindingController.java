package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.service.FindingQueryService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/findings")
public class FindingController {

    private final WorkspaceService workspaceService;
    private final FindingQueryService findingQueryService;

    public FindingController(WorkspaceService workspaceService, FindingQueryService findingQueryService) {
        this.workspaceService = workspaceService;
        this.findingQueryService = findingQueryService;
    }

    @GetMapping
    public FindingPageResponse list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) List<String> severity,
            @RequestParam(required = false) List<String> status,
            @RequestParam(required = false) List<String> decisionState,
            @RequestParam(required = false) List<String> matchMethod,
            @RequestParam(required = false) List<String> vexStatus,
            @RequestParam(required = false) List<String> vexFreshness,
            @RequestParam(required = false) List<String> vexProvider,
            @RequestParam(required = false) Double minConfidence,
            @RequestParam(required = false) String vulnerabilityId,
            @RequestParam(required = false) String packageName,
            @RequestParam(required = false) String ecosystem
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueryService.listByTenantPage(
                tenant,
                page,
                size,
                severity,
                status,
                decisionState,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem
        );
    }

    @GetMapping("/filters")
    public FindingFilterValuesResponse filters() {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueryService.listAvailableFilters(tenant);
    }
}
