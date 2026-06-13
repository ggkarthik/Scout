package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.TenantInviteValidationResponse;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tenant-invites")
public class TenantInviteController {

    private final TenantUserInviteService tenantUserInviteService;

    public TenantInviteController(TenantUserInviteService tenantUserInviteService) {
        this.tenantUserInviteService = tenantUserInviteService;
    }

    @GetMapping("/{token}")
    public TenantInviteValidationResponse validate(@PathVariable String token) {
        return tenantUserInviteService.validateInvite(token);
    }

    @PostMapping("/{token}/accept")
    public TenantInviteValidationResponse accept(@PathVariable String token) {
        return tenantUserInviteService.acceptInvite(token);
    }
}
