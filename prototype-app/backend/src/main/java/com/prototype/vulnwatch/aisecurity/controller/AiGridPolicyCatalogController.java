package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.Distribution;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.DistributionCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.PolicyDetail;
import com.prototype.vulnwatch.service.RequestActorService;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/platform/ai-grid/policies")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiGridPolicyCatalogController {
    private final AiGridPolicyCatalogService catalog;
    private final RequestActorService actors;
    public AiGridPolicyCatalogController(AiGridPolicyCatalogService catalog, RequestActorService actors) { this.catalog = catalog; this.actors = actors; }
    @GetMapping public List<Distribution> list(
            @RequestParam(required = false) String releaseFamily,
            @RequestParam(required = false) String lifecycle) {
        return catalog.distributions(releaseFamily, lifecycle);
    }
    @GetMapping("/{policyId}/versions/{version}") public PolicyDetail detail(@PathVariable String policyId, @PathVariable String version) { return catalog.detail(policyId, version); }
    @PutMapping("/{policyId}/distribution") public Distribution distribution(@PathVariable String policyId, @RequestBody DistributionCommand command) { return catalog.updateDistribution(policyId, command, actors.currentActor().userId()); }
}
