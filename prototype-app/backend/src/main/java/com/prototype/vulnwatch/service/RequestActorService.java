package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.config.TenantAuthenticationDetails;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
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
            boolean platformOwner = details.roles().contains("PLATFORM_OWNER");
            if (details.tenantId() != null) {
                return new RequestActor(
                        details.userId(),
                        platformOwner || details.roles().contains("CREATOR"),
                        details.tenantId(),
                        details.tenantName(),
                        details.roles(),
                        details.accessMode(),
                        details.accessReferenceId(),
                        details.accessExpiresAt());
            }
            return new RequestActor(
                    details.userId(),
                    platformOwner || details.roles().contains("CREATOR"),
                    null,
                    null,
                    details.roles(),
                    null,
                    null,
                    null);
        }
        String principal = resolvePrincipal(authentication);
        Set<String> roles = authentication == null ? Set.of() : authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority().replaceFirst("^ROLE_", ""))
                .collect(Collectors.toUnmodifiableSet());
        if (authentication instanceof AnonymousAuthenticationToken) {
            return new RequestActor(principal, false, null, null, roles);
        }
        boolean creator = authentication != null
                && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_CREATOR".equals(authority.getAuthority()));
        boolean platformOwner = roles.contains("PLATFORM_OWNER");
        if (platformOwner && TenantContext.getCurrentTenantId() == null) {
            return new RequestActor(principal, creator, null, null, roles);
        }
        Tenant tenant = workspaceService.getWorkspace();
        return new RequestActor(
                principal,
                creator || platformOwner,
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
