package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionJobPageResponse;
import com.prototype.vulnwatch.dto.IngestionJobResponse;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ingestion-jobs")
public class IngestionJobController {

    private final IngestionJobService ingestionJobService;
    private final WorkspaceService workspaceService;

    public IngestionJobController(
            IngestionJobService ingestionJobService,
            WorkspaceService workspaceService
    ) {
        this.ingestionJobService = ingestionJobService;
        this.workspaceService = workspaceService;
    }

    @GetMapping("/{jobId}")
    public IngestionJobResponse getJob(@PathVariable UUID jobId) {
        Tenant tenant = workspaceService.getWorkspace();
        return ingestionJobService.getJob(tenant, jobId);
    }

    @GetMapping
    public IngestionJobPageResponse listJobs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return ingestionJobService.listJobs(tenant, page, size);
    }
}
