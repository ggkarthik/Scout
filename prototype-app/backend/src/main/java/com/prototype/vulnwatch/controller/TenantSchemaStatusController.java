package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.TenantSchemaStatusResponse;
import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/tenant-schema-status")
public class TenantSchemaStatusController {

    private final TenantSchemaStatusService service;

    public TenantSchemaStatusController(TenantSchemaStatusService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantSchemaStatusResponse list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        return service.list(page, size);
    }
}
