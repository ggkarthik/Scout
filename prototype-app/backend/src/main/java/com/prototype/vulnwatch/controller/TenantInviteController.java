package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.TenantInviteValidationResponse;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import com.prototype.vulnwatch.security.PasswordSetupCookieService;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tenant-invites")
public class TenantInviteController {

    private final TenantUserInviteService tenantUserInviteService;
    private final PasswordSetupCookieService passwordSetupCookieService;
    private final PublicEndpointRateLimiter publicEndpointRateLimiter;

    public TenantInviteController(
            TenantUserInviteService tenantUserInviteService,
            PasswordSetupCookieService passwordSetupCookieService,
            PublicEndpointRateLimiter publicEndpointRateLimiter
    ) {
        this.tenantUserInviteService = tenantUserInviteService;
        this.passwordSetupCookieService = passwordSetupCookieService;
        this.publicEndpointRateLimiter = publicEndpointRateLimiter;
    }

    @GetMapping("/{token}")
    public TenantInviteValidationResponse validate(@PathVariable String token, HttpServletRequest request) {
        publicEndpointRateLimiter.checkInvite(request, token);
        return TenantContext.runAsPreAuthentication(() -> tenantUserInviteService.validateInvite(token));
    }

    @PostMapping("/{token}/accept")
    public TenantInviteValidationResponse accept(
            @PathVariable String token,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        publicEndpointRateLimiter.checkInvite(request, token);
        TenantInviteValidationResponse result = TenantContext.runAsPreAuthentication(() -> tenantUserInviteService.acceptInvite(token));
        passwordSetupCookieService.write(response, result.setupToken());
        return result;
    }
}
