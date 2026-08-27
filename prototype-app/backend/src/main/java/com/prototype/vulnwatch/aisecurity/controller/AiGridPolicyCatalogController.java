package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.Distribution;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.DistributionCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.PolicyPackageCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.PolicyVersion;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyCatalogService.PolicyDetail;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyImpactPreviewService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyImpactPreviewService.ImpactPreview;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyPortfolioService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyPortfolioService.Candidate;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyPortfolioService.CandidateCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyPortfolioService.FrameworkCoverage;
import com.prototype.vulnwatch.aisecurity.service.AiGridTestDataResetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridTestDataResetService.ResetResult;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.ReleaseDecision;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.ReleaseReadiness;
import com.prototype.vulnwatch.service.RequestActorService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/platform/ai-grid/policies")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiGridPolicyCatalogController {
    private final AiGridPolicyCatalogService catalog;
    private final AiGridPolicyImpactPreviewService previews;
    private final AiGridValidationGovernanceService governance;
    private final AiGridPolicyPortfolioService portfolio;
    private final AiGridTestDataResetService testReset;
    private final RequestActorService actors;
    public AiGridPolicyCatalogController(AiGridPolicyCatalogService catalog, AiGridPolicyImpactPreviewService previews, AiGridValidationGovernanceService governance, AiGridPolicyPortfolioService portfolio, AiGridTestDataResetService testReset, RequestActorService actors) { this.catalog = catalog; this.previews = previews; this.governance = governance; this.portfolio = portfolio; this.testReset = testReset; this.actors = actors; }
    @GetMapping public List<Distribution> list(
            @RequestParam(required = false) String releaseFamily,
            @RequestParam(required = false) String lifecycle) {
        return catalog.distributions(releaseFamily, lifecycle);
    }
    @GetMapping("/{policyId}/versions/{version}") public PolicyDetail detail(@PathVariable String policyId, @PathVariable String version) { return catalog.detail(policyId, version); }
    @PostMapping("/imports") public PolicyVersion importDraft(@RequestBody PolicyPackageCommand command) { return catalog.importDraft(command, actors.currentActor().userId()); }
    @PutMapping("/{policyId}/distribution") public Distribution distribution(@PathVariable String policyId, @RequestBody DistributionCommand command) { return catalog.updateDistribution(policyId, command, actors.currentActor().userId()); }
    @GetMapping("/{policyId}/versions/{version}/impact-preview")
    public ImpactPreview impactPreview(@PathVariable String policyId, @PathVariable String version, @RequestParam UUID tenantId) {
        return previews.preview(policyId, version, tenantId);
    }
    @GetMapping("/{policyId}/versions/{version}/release-readiness")
    public ReleaseReadiness releaseReadiness(@PathVariable String policyId, @PathVariable String version) { return governance.releaseReadiness(policyId, version); }
    @PostMapping("/{policyId}/versions/{version}/publish")
    public ReleaseDecision publish(@PathVariable String policyId, @PathVariable String version) { return governance.publishPolicy(policyId, version, actors.currentActor().userId()); }
    @GetMapping("/portfolio/frameworks")
    public List<AiGridPolicyPortfolioService.ControlCoverage> frameworkCoverage(
            @RequestParam(defaultValue = "OWASP_GENAI_LLM_TOP_10") String framework,
            @RequestParam(defaultValue = "2026") String version) {
        return portfolio.frameworkCoverage(framework, version);
    }

    /** @deprecated Retained for one compatibility release; use {@code /portfolio/frameworks}. */
    @Deprecated
    @GetMapping("/portfolio/owasp") public List<FrameworkCoverage> owaspCoverage() { return portfolio.owaspCoverage(); }
    @GetMapping("/portfolio/candidates") public List<Candidate> candidates() { return portfolio.candidates(); }
    @PostMapping("/portfolio/candidates") public Candidate createCandidate(@RequestBody CandidateCommand command) { return portfolio.create(command, actors.currentActor().userId()); }
    @PostMapping("/test-reset") public ResetResult testReset(@RequestBody TestResetCommand command) { return testReset.reset(command.confirmation(), actors.currentActor().userId()); }
    public record TestResetCommand(String confirmation) {}
}
