package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthLoginRequest;
import com.prototype.vulnwatch.dto.AuthSetupPasswordRequest;
import com.prototype.vulnwatch.dto.AuthTenantContextRequest;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.service.LocalCredentialAuthService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@RestController
@RequestMapping("/api/auth")
public class LocalAuthController {

    private final LocalCredentialAuthService localCredentialAuthService;
    private final RequestActorService requestActorService;

    public LocalAuthController(
            LocalCredentialAuthService localCredentialAuthService,
            RequestActorService requestActorService
    ) {
        this.localCredentialAuthService = localCredentialAuthService;
        this.requestActorService = requestActorService;
    }

    @PostMapping("/login")
    public AuthTokenResponse login(@Valid @RequestBody AuthLoginRequest request) {
        return localCredentialAuthService.login(request.email(), request.password());
    }

    @PostMapping("/setup-password")
    public AuthTokenResponse setupPassword(@Valid @RequestBody AuthSetupPasswordRequest request) {
        return localCredentialAuthService.setupPassword(request.setupToken(), request.password());
    }

    @PostMapping("/context/tenant")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public AuthTokenResponse selectTenantContext(@Valid @RequestBody AuthTenantContextRequest request) {
        RequestActor actor = requestActorService.currentActor();
        if (!actor.hasRole("PLATFORM_OWNER")) {
            throw new ResponseStatusException(FORBIDDEN, "Only platform owners can switch tenant context");
        }
        return localCredentialAuthService.switchTenantContext(actor.userId(), request.tenantId());
    }

    @PostMapping("/context/clear")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public AuthTokenResponse clearTenantContext() {
        RequestActor actor = requestActorService.currentActor();
        if (!actor.hasRole("PLATFORM_OWNER")) {
            throw new ResponseStatusException(FORBIDDEN, "Only platform owners can clear tenant context");
        }
        return localCredentialAuthService.clearTenantContext(actor.userId());
    }
}
