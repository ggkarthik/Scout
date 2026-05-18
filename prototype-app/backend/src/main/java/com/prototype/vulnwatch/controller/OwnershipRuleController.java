package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OwnershipRuleRequest;
import com.prototype.vulnwatch.dto.OwnershipRuleResponse;
import com.prototype.vulnwatch.service.OwnershipRuleService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
@RequestMapping("/api/ownership-rules")
public class OwnershipRuleController {

    private final WorkspaceService workspaceService;
    private final OwnershipRuleService ownershipRuleService;

    public OwnershipRuleController(WorkspaceService workspaceService, OwnershipRuleService ownershipRuleService) {
        this.workspaceService = workspaceService;
        this.ownershipRuleService = ownershipRuleService;
    }

    @GetMapping
    public List<OwnershipRuleResponse> list() {
        Tenant tenant = workspaceService.getWorkspace();
        return ownershipRuleService.list(tenant);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public OwnershipRuleResponse create(@RequestBody OwnershipRuleRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return ownershipRuleService.create(tenant, request);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public OwnershipRuleResponse update(@PathVariable UUID id, @RequestBody OwnershipRuleRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return ownershipRuleService.update(id, tenant, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public void delete(@PathVariable UUID id) {
        Tenant tenant = workspaceService.getWorkspace();
        ownershipRuleService.delete(id, tenant);
    }

    @PostMapping("/apply")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public Map<String, Integer> applyToAll() {
        Tenant tenant = workspaceService.getWorkspace();
        int updated = ownershipRuleService.applyToAll(tenant);
        return Map.of("updated", updated);
    }

    @PostMapping("/{id}/apply")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public Map<String, Integer> applyRule(@PathVariable UUID id) {
        Tenant tenant = workspaceService.getWorkspace();
        int updated = ownershipRuleService.applyRule(id, tenant);
        return Map.of("updated", updated);
    }
}
