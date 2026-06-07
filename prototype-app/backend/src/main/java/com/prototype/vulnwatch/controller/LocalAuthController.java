package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthLoginRequest;
import com.prototype.vulnwatch.dto.AuthSetupPasswordRequest;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.service.LocalCredentialAuthService;
import jakarta.validation.Valid;
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
        return localCredentialAuthService.setupPassword(request.setupToken(), request.password());
    }
}
