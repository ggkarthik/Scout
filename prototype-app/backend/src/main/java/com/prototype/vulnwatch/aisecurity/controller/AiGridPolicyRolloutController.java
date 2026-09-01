package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyRolloutService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyShippingStatusService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/ai-grid")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiGridPolicyRolloutController {
    private final AiGridPolicyShippingStatusService shipping;
    private final AiGridPolicyRolloutService rollouts;
    public AiGridPolicyRolloutController(AiGridPolicyShippingStatusService shipping, AiGridPolicyRolloutService rollouts) {
        this.shipping = shipping; this.rollouts = rollouts;
    }
    @GetMapping("/policies/shipping-status") public AiGridPolicyShippingStatusService.ShippingStatus shippingStatus() { return shipping.status(); }
    @GetMapping("/policy-rollouts") public List<AiGridPolicyRolloutService.Rollout> list() { return rollouts.rollouts(); }
    @GetMapping("/policy-rollouts/{rolloutId}") public AiGridPolicyRolloutService.RolloutDetail detail(@PathVariable UUID rolloutId) { return rollouts.rollout(rolloutId); }
    @PostMapping("/policy-rollouts/{rolloutId}/retry") public void retry(@PathVariable UUID rolloutId) { rollouts.retry(rolloutId); }
}
