package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class RequestActorService {

    private final WorkspaceService workspaceService;
    private final String defaultUserId;

    public RequestActorService(
            WorkspaceService workspaceService,
            @Value("${app.security.default-user-id:local-analyst}") String defaultUserId
    ) {
        this.workspaceService = workspaceService;
        this.defaultUserId = defaultUserId;
    }

    public RequestActor currentActor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String principal = resolvePrincipal(authentication);
        boolean creator = authentication != null
                && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_CREATOR".equals(authority.getAuthority()));
        Tenant tenant = workspaceService.getWorkspace();
        return new RequestActor(
                principal,
                creator,
                tenant.getId(),
                tenant.getName()
        );
    }

    private String resolvePrincipal(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return defaultUserId;
        }
        String principal = String.valueOf(authentication.getPrincipal()).trim();
        return principal.isEmpty() ? defaultUserId : principal;
    }
}
