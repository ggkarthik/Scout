package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingBulkWorkflowRequest;
import com.prototype.vulnwatch.dto.FindingBulkWorkflowResponse;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.FindingQueryService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/findings")
public class FindingController {

    private final WorkspaceService workspaceService;
    private final FindingQueryService findingQueryService;
    private final FindingWorkflowService findingWorkflowService;
    private final FindingRepository findingRepository;

    public FindingController(
            WorkspaceService workspaceService,
            FindingQueryService findingQueryService,
            FindingWorkflowService findingWorkflowService,
            FindingRepository findingRepository
    ) {
        this.workspaceService = workspaceService;
        this.findingQueryService = findingQueryService;
        this.findingWorkflowService = findingWorkflowService;
        this.findingRepository = findingRepository;
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

    @PutMapping("/{findingId}/workflow")
    public Finding updateWorkflow(
            @PathVariable UUID findingId,
            @RequestBody FindingWorkflowUpdateRequest request
    ) {
        return findingWorkflowService.updateWorkflow(findingId, request);
    }

    @PostMapping("/bulk-workflow")
    public FindingBulkWorkflowResponse bulkUpdateWorkflow(
            @RequestBody FindingBulkWorkflowRequest request
    ) {
        if (request.findingIds() == null || request.findingIds().isEmpty()) {
            return new FindingBulkWorkflowResponse(0, 0, 0, "No finding IDs provided");
        }
        List<Finding> findings = findingRepository.findAllById(request.findingIds());
        int targeted = request.findingIds().size();
        FindingWorkflowUpdateRequest workflowUpdate = new FindingWorkflowUpdateRequest(
                request.workflowStatus(),
                request.assignedTo(),
                request.dueAt(),
                request.suppressionReason(),
                request.suppressedUntil(),
                request.actor()
        );
        int updated = findingWorkflowService.updateWorkflowBulk(findings, workflowUpdate);
        int failed = targeted - updated;
        return new FindingBulkWorkflowResponse(targeted, updated, failed, "Bulk workflow update completed");
    }
}
