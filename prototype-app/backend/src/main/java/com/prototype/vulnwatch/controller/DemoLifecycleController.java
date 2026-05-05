package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.DemoInviteResponse;
import com.prototype.vulnwatch.dto.DemoInviteValidationResponse;
import com.prototype.vulnwatch.dto.DemoRequestCreateRequest;
import com.prototype.vulnwatch.dto.DemoRequestDecisionRequest;
import com.prototype.vulnwatch.dto.DemoRequestResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoLifecycleController {

    private final DemoLifecycleService demoLifecycleService;
    private final RequestActorService requestActorService;
    private final WorkspaceService workspaceService;

    public DemoLifecycleController(
            DemoLifecycleService demoLifecycleService,
            RequestActorService requestActorService,
            WorkspaceService workspaceService
    ) {
        this.demoLifecycleService = demoLifecycleService;
        this.requestActorService = requestActorService;
        this.workspaceService = workspaceService;
    }

    @PostMapping("/demo-requests")
    public DemoRequestResponse createRequest(@Valid @RequestBody DemoRequestCreateRequest request) {
        return demoLifecycleService.createRequest(request);
    }

    @GetMapping("/platform/demo-requests")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<DemoRequestResponse> listRequests() {
        return demoLifecycleService.listRequests();
    }

    @PostMapping("/platform/demo-requests/{requestId}/approve")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public DemoRequestResponse approve(@PathVariable UUID requestId) {
        return demoLifecycleService.approve(requestId, requestActorService.currentActor().userId());
    }

    @PostMapping("/platform/demo-requests/{requestId}/reject")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public DemoRequestResponse reject(
            @PathVariable UUID requestId,
            @Valid @RequestBody(required = false) DemoRequestDecisionRequest request
    ) {
        return demoLifecycleService.reject(
                requestId,
                request == null ? null : request.reason(),
                requestActorService.currentActor().userId());
    }

    @PostMapping("/platform/demo-requests/{requestId}/resend-invite")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public DemoInviteResponse resendInvite(@PathVariable UUID requestId) {
        return demoLifecycleService.resendInvite(requestId);
    }

    @GetMapping("/demo-invites/{token}")
    public DemoInviteValidationResponse validateInvite(@PathVariable String token) {
        return demoLifecycleService.validateInvite(token);
    }

    @PostMapping("/demo-invites/{token}/accept")
    public DemoInviteValidationResponse acceptInvite(@PathVariable String token) {
        return demoLifecycleService.acceptInvite(token);
    }

    @GetMapping("/demo/status")
    public DemoStatusResponse demoStatus() {
        return demoLifecycleService.statusForTenant(workspaceService.getWorkspace());
    }
}
