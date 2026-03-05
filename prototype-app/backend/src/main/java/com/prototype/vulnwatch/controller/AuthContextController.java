package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthContextResponse;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthContextController {

    @GetMapping("/context")
    public AuthContextResponse get() {
        Authentication authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext()
                .getAuthentication();
        boolean creator = authentication != null
                && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_CREATOR".equals(authority.getAuthority()));
        String principal = authentication == null ? "unknown" : String.valueOf(authentication.getPrincipal());
        return new AuthContextResponse(creator, principal);
    }
}
