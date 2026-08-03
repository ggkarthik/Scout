package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AiGridController {
    private final WorkspaceService workspaces;
    private final RequestActorService actors;
    private final AiSecurityAccessService access;
    private final AiGridApiService api;

    public AiGridController(WorkspaceService workspaces, RequestActorService actors,
                            AiSecurityAccessService access, AiGridApiService api) {
        this.workspaces = workspaces;
        this.actors = actors;
        this.access = access;
        this.api = api;
    }

    @GetMapping("/ai-systems") public List<AiGridApiService.SystemSummary> systems() { return api.systems(tenant()); }
    @GetMapping("/ai-systems/{id}") public AiGridApiService.SystemDetail system(@PathVariable UUID id) { return api.system(tenant(), id); }
    @GetMapping("/ai-systems/{id}/facts")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')")
    public List<AiGridApiService.FactView> facts(@PathVariable UUID id) { return api.systemFacts(tenant(), id); }
    @GetMapping("/ai-systems/{id}/graph")
    public List<AiGridApiService.GraphEdge> graph(@PathVariable UUID id) { return api.systemGraph(tenant(), id); }
    @GetMapping("/ai-systems/{id}/lineage")
    public List<AiGridApiService.SystemLineage> lineage(@PathVariable UUID id) { return api.systemLineage(tenant(), id); }
    @GetMapping("/ai-systems/{id}/findings")
    public List<AiGridApiService.SystemFinding> systemFindings(@PathVariable UUID id) {
        return api.systemFindings(tenant(), id);
    }
    @PostMapping("/ai-systems/{id}/memberships")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public RevisionResponse membership(@PathVariable UUID id, @RequestBody MembershipRequest request) {
        int revision = api.reviseMembership(tenant(), id, request.artifactId(), request.decision(),
                actors.currentActor().userId(), request.reason(), request.lineageType(), request.relatedSystems());
        return new RevisionResponse(revision);
    }
    @PostMapping("/ai-artifacts/{id}/host-context")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService.HostFact hostContext(
            @PathVariable UUID id,
            @RequestBody com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService.HostFactInput request) {
        return api.addHostContext(tenant(), id, request);
    }
    @GetMapping("/ai-exposures")
    public List<AiGridApiService.ExposureSummary> exposures() { return api.exposures(tenant()); }
    @GetMapping("/ai-exposures/{id}")
    public AiGridApiService.ExposureDetail exposure(@PathVariable UUID id) { return api.exposure(tenant(), id); }
    @PostMapping("/ai-exposures/{id}/disposition")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public void disposition(@PathVariable UUID id, @RequestBody DispositionRequest request) {
        api.dispositionExposure(tenant(), id, request.disposition(), actors.currentActor().userId(), request.reason());
    }
    @GetMapping("/ai-coverage")
    public com.prototype.vulnwatch.aisecurity.service.AiGridCoverageService.Coverage coverage() {
        return api.coverage(tenant());
    }
    @GetMapping("/ai-coverage/details")
    public List<com.prototype.vulnwatch.aisecurity.service.AiGridCoverageService.CoverageItem> coverageDetails() {
        return api.coverageDetails(tenant());
    }
    @GetMapping("/ai-coverage/dimensions")
    public List<com.prototype.vulnwatch.aisecurity.service.AiGridCoverageService.CoverageDimension> coverageDimensions() {
        return api.coverageDimensions(tenant());
    }
    @GetMapping("/ai-policy-readiness")
    public List<com.prototype.vulnwatch.aisecurity.service.AiGridReadinessService.PolicyReadinessView> policyReadiness() {
        return api.policyReadiness(tenant());
    }
    @GetMapping("/ai-setup-actions")
    public List<com.prototype.vulnwatch.aisecurity.service.AiGridReadinessService.SetupActionView> setupActions() {
        return api.setupActions(tenant());
    }
    @GetMapping("/ai-assessment-runs") public List<AiGridApiService.AssessmentRun> runs() { return api.runs(tenant()); }
    @GetMapping("/ai-assessment-runs/{id}/metrics")
    public com.prototype.vulnwatch.aisecurity.service.AiGridRunMetricsService.RunMetrics runMetrics(
            @PathVariable UUID id) {
        return api.runMetrics(tenant(), id);
    }
    @PostMapping("/ai-assessment-runs/{id}/replay")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public AiGridApiService.AssessmentRun replay(@PathVariable UUID id) { return api.replay(tenant(), id); }
    @GetMapping("/ai-policies") public List<AiGridApiService.PolicyView> policies() { return api.policies(tenant()); }
    @GetMapping("/ai-policies/{id}/versions")
    public List<AiGridApiService.PolicyView> policyVersions(@PathVariable String id) {
        return api.policyVersions(tenant(), id);
    }
    @PutMapping("/ai-policies/{id}/selection")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public List<AiGridApiService.PolicyView> selection(@PathVariable String id, @RequestBody SelectionRequest request) {
        Tenant tenant = tenant();
        api.updateSelection(tenant, id, request.selection(), actors.currentActor().userId(), request.reason());
        return api.policies(tenant);
    }
    @PutMapping("/ai-artifacts/{id}/owner")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public com.prototype.vulnwatch.aisecurity.service.AiGridOwnershipService.OwnerView confirmOwner(
            @PathVariable UUID id, @RequestBody OwnerRequest request) {
        Tenant tenant = tenant();
        return api.confirmOwner(tenant, id, request.ownerName(), actors.currentActor().userId(), request.reason());
    }

    private Tenant tenant() {
        Tenant tenant = workspaces.getWorkspace();
        access.assertEntitled(tenant);
        return tenant;
    }
    public record SelectionRequest(String selection, String reason) {}
    public record OwnerRequest(String ownerName, String reason) {}
    public record MembershipRequest(UUID artifactId, String decision, String reason,
                                    String lineageType, List<UUID> relatedSystems) {}
    public record RevisionResponse(int revision) {}
    public record DispositionRequest(String disposition, String reason) {}
}
