package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.config.TenantAuthenticationDetails;
import java.util.Set;
import java.util.stream.Collectors;
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
        if (authentication != null && authentication.getDetails() instanceof TenantAuthenticationDetails details) {
            return new RequestActor(
                    details.userId(),
                    details.roles().contains("PLATFORM_OWNER") || details.roles().contains("CREATOR"),
                    details.tenantId(),
                    details.tenantName(),
                    details.roles());
        }
        String principal = resolvePrincipal(authentication);
        boolean creator = authentication != null
                && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_CREATOR".equals(authority.getAuthority()));
        Tenant tenant = workspaceService.getWorkspace();
        Set<String> roles = authentication == null ? Set.of() : authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority().replaceFirst("^ROLE_", ""))
                .collect(Collectors.toUnmodifiableSet());
        return new RequestActor(
                principal,
                creator,
                tenant.getId(),
                tenant.getName(),
                roles
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
