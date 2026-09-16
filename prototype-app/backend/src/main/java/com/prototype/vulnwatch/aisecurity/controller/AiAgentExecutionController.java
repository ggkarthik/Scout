package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiAgentExecutionApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ai-security/executions")
public class AiAgentExecutionController {
    private final WorkspaceService workspace;
    private final AiSecurityAccessService access;
    private final AiAgentExecutionApiService executions;

    public AiAgentExecutionController(WorkspaceService workspace, AiSecurityAccessService access,
                                      AiAgentExecutionApiService executions) {
        this.workspace = workspace;
        this.access = access;
        this.executions = executions;
    }

    @GetMapping
    public AiAgentExecutionApiService.PageResponse<AiAgentExecutionApiService.ExecutionResponse> list(
            @RequestParam(required = false) UUID agentId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String source,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return executions.list(tenant(), agentId, status, source, from, to, page, size);
    }

    @GetMapping("/{executionId}/timeline")
    public List<AiAgentExecutionApiService.ExecutionEventResponse> timeline(@PathVariable UUID executionId) {
        return executions.timeline(tenant(), executionId);
    }

    private Tenant tenant() {
        Tenant tenant = workspace.getWorkspace();
        access.assertEntitled(tenant);
        return tenant;
    }
}
