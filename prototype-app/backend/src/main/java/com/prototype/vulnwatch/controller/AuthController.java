package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthLoginRequest;
import com.prototype.vulnwatch.dto.AuthSessionResponse;
import com.prototype.vulnwatch.service.ValidationAuthService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final ValidationAuthService validationAuthService;

    public AuthController(ValidationAuthService validationAuthService) {
        this.validationAuthService = validationAuthService;
    }

    @PostMapping("/login")
    public AuthSessionResponse login(@Valid @RequestBody AuthLoginRequest request) {
        return validationAuthService.login(request.email(), request.password());
    }
}
