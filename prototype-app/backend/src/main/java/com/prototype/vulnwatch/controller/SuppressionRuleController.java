package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SuppressionRuleRequest;
import com.prototype.vulnwatch.dto.SuppressionRuleResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.SuppressionRuleService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/suppression-rules")
public class SuppressionRuleController {

    private final WorkspaceService workspaceService;
    private final SuppressionRuleService suppressionRuleService;

    public SuppressionRuleController(
            WorkspaceService workspaceService,
            SuppressionRuleService suppressionRuleService
    ) {
        this.workspaceService = workspaceService;
        this.suppressionRuleService = suppressionRuleService;
    }

    @GetMapping
    public List<SuppressionRuleResponse> list() {
        Tenant tenant = workspaceService.getWorkspace();
        return suppressionRuleService.list(tenant);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @SensitiveTenantAction("suppression_rule.created")
    public SuppressionRuleResponse create(@RequestBody SuppressionRuleRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return suppressionRuleService.create(tenant, request);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @SensitiveTenantAction("suppression_rule.updated")
    public SuppressionRuleResponse update(
            @PathVariable UUID id,
            @RequestBody SuppressionRuleRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return suppressionRuleService.update(tenant, id, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @SensitiveTenantAction("suppression_rule.deleted")
    public void delete(@PathVariable UUID id) {
        Tenant tenant = workspaceService.getWorkspace();
        suppressionRuleService.delete(tenant, id);
    }

    @PostMapping("/{id}/execute")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @SensitiveTenantAction("suppression_rule.executed")
    public Map<String, Object> execute(@PathVariable UUID id) {
        Tenant tenant = workspaceService.getWorkspace();
        try {
            int suppressed = suppressionRuleService.execute(tenant, id);
            return Map.of("suppressed", suppressed);
        } catch (IllegalStateException e) {
            return Map.of("suppressed", 0, "error", e.getMessage());
        }
    }

    @PostMapping("/{id}/reopen-all")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @SensitiveTenantAction("suppression_rule.reopen_all")
    public Map<String, Object> reopenAll(@PathVariable UUID id) {
        Tenant tenant = workspaceService.getWorkspace();
        int reopened = suppressionRuleService.reopenAllByRule(tenant, id);
        return Map.of("reopened", reopened);
    }

    @PostMapping("/cve-reopen/{recordId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @SensitiveTenantAction("suppression_rule.cve_reopen")
    public void reopenCveRecord(@PathVariable UUID recordId) {
        Tenant tenant = workspaceService.getWorkspace();
        suppressionRuleService.reopenCveRecord(tenant, recordId);
    }
}
