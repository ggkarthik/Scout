package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiSecurityPlatformPolicyService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityPlatformPolicyService.PlatformPolicyResponse;
import com.prototype.vulnwatch.service.RequestActorService;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/ai-security/policies")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiSecurityPlatformController {

    private final AiSecurityPlatformPolicyService policyService;
    private final RequestActorService actorService;

    public AiSecurityPlatformController(
            AiSecurityPlatformPolicyService policyService,
            RequestActorService actorService
    ) {
        this.policyService = policyService;
        this.actorService = actorService;
    }

    @GetMapping
    public List<PlatformPolicyResponse> list() {
        return policyService.list();
    }

    @PatchMapping("/{policyId}")
    public PlatformPolicyResponse update(
            @PathVariable String policyId,
            @RequestBody PlatformPolicyRequest request
    ) {
        return policyService.update(
                policyId,
                request.available(),
                request.defaultEnabled(),
                actorService.currentActor().userId());
    }

    public record PlatformPolicyRequest(boolean available, boolean defaultEnabled) {
    }
}
