package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthLoginRequest;
import com.prototype.vulnwatch.dto.AuthSetupPasswordRequest;
import com.prototype.vulnwatch.dto.AuthTenantContextRequest;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.service.LocalCredentialAuthService;
import com.prototype.vulnwatch.service.TenantContext;
import jakarta.validation.Valid;
import java.security.Principal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class LocalAuthController {

    private final LocalCredentialAuthService localCredentialAuthService;

    public LocalAuthController(
            LocalCredentialAuthService localCredentialAuthService
    ) {
        this.localCredentialAuthService = localCredentialAuthService;
    }

    @PostMapping("/login")
    public AuthTokenResponse login(@Valid @RequestBody AuthLoginRequest request) {
        return localCredentialAuthService.login(request.email(), request.password());
    }

    @PostMapping("/setup-password")
    public AuthTokenResponse setupPassword(@Valid @RequestBody AuthSetupPasswordRequest request) {
        return TenantContext.runAsPreAuthentication(
                () -> localCredentialAuthService.setupPassword(request.setupToken(), request.password()));
    }

    @PostMapping("/tenant-context")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public AuthTokenResponse switchTenantContext(
            Principal principal,
            @Valid @RequestBody AuthTenantContextRequest request
    ) {
        return localCredentialAuthService.switchTenantContext(principal.getName(), request.tenantId());
    }

    @DeleteMapping("/tenant-context")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public AuthTokenResponse clearTenantContext(Principal principal) {
        return localCredentialAuthService.clearTenantContext(principal.getName());
    }
}
