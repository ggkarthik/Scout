package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiExposureIntelligenceService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyConfigurationResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyScopeConditionResponse;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AiGridController {
    private final WorkspaceService workspaces;
    private final RequestActorService actors;
    private final AiSecurityAccessService access;
    private final AiGridApiService api;
    private final AiExposureIntelligenceService intelligence;
    private final ObjectProvider<AiSecurityApiService> policyCompatibility;

    public AiGridController(WorkspaceService workspaces, RequestActorService actors,
                            AiSecurityAccessService access, AiGridApiService api,
                            AiExposureIntelligenceService intelligence,
                            ObjectProvider<AiSecurityApiService> policyCompatibility) {
        this.workspaces = workspaces;
        this.actors = actors;
        this.access = access;
        this.api = api;
        this.intelligence = intelligence;
        this.policyCompatibility = policyCompatibility;
    }

    @GetMapping("/ai-systems")
    public AiGridApiService.SystemPage systems(@RequestParam(required = false) String cursor,
                                               @RequestParam(defaultValue = "50") int limit) {
        return api.systems(tenant(), cursor, limit);
    }
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
            @RequestBody com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService.AnalystFactInput request) {
        return api.addHostContext(tenant(), id, request);
    }
    @GetMapping("/ai-exposures")
    public AiGridApiService.ExposurePage exposures(
            @RequestParam(required = false) String cursor,
            @RequestParam(defaultValue = "50") int limit) {
        return api.exposures(tenant(), cursor, limit);
    }
    @GetMapping("/ai-exposures/{id}")
    public AiGridApiService.ExposureDetail exposure(@PathVariable UUID id) { return api.exposure(tenant(), id); }
    @GetMapping("/ai-overview")
    public AiExposureIntelligenceService.Overview overview() { return intelligence.overview(tenant()); }
    @GetMapping("/ai-exposure-priorities")
    public List<AiExposureIntelligenceService.ExposurePriority> exposurePriorities() {
        return intelligence.priorities(tenant());
    }
    @GetMapping("/ai-action-queue")
    public List<AiExposureIntelligenceService.ActionQueueItem> actionQueue() { return intelligence.actionQueue(tenant()); }
    @GetMapping("/ai-assets/{id}/posture")
    public AiExposureIntelligenceService.AssetPosture posture(@PathVariable UUID id) {
        return intelligence.posture(tenant(), id);
    }
    @GetMapping("/ai-changes")
    public List<AiExposureIntelligenceService.ActivityItem> changes() { return intelligence.recentActivity(tenant()); }
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
    /** Rich tenant policy view retained while the UI moves to the governed route. */
    @GetMapping("/ai-policies/details")
    public List<AiSecurityApiService.PolicyResponse> policyDetails() {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().policies(tenant);
    }
    @org.springframework.web.bind.annotation.PatchMapping("/ai-policies/{id}/enabled")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public AiSecurityApiService.PolicyResponse updatePolicy(@PathVariable String id, @RequestBody PolicyStateRequest request) {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().updatePolicy(tenant, id, request.enabled(), actors.currentActor().userId());
    }
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
    @GetMapping("/ai-policies/{id}/configuration")
    public PolicyConfigurationResponse configuration(@PathVariable String id) {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().policyConfiguration(tenant, id);
    }
    @PutMapping("/ai-policies/{id}/scope")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse updateScope(@PathVariable String id, @RequestBody ScopeUpdateRequest request) {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().updatePolicyScope(tenant, id, request.mode(), request.conditionLogic(), request.conditions(), actors.currentActor().userId());
    }
    @PostMapping("/ai-policies/{id}/exceptions")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse addException(@PathVariable String id, @RequestBody ExceptionRequest request) {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().addPolicyException(tenant, id, request.artifactId(), request.override(), request.reason(), actors.currentActor().userId());
    }
    @DeleteMapping("/ai-policies/{id}/exceptions/{artifactId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse removeException(@PathVariable String id, @PathVariable UUID artifactId) {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().removePolicyException(tenant, id, artifactId, actors.currentActor().userId());
    }
    @PutMapping("/ai-policies/{id}/parameters")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse updateParameters(@PathVariable String id, @RequestBody ParametersUpdateRequest request) {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().updatePolicyParameters(tenant, id, request.parameters(), actors.currentActor().userId());
    }
    @GetMapping("/ai-policies/{id}/assist/explain")
    public AiSecurityApiService.PolicyAssistExplanationResponse explainPolicy(@PathVariable String id) {
        Tenant tenant = tenant();
        return policyCompatibility.getObject().explainPolicy(tenant, id);
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
    public record PolicyStateRequest(boolean enabled) {}
    public record ScopeUpdateRequest(String mode, String conditionLogic, List<PolicyScopeConditionResponse> conditions) {}
    public record ExceptionRequest(UUID artifactId, String override, String reason) {}
    public record ParametersUpdateRequest(Map<String, String> parameters) {}
    public record OwnerRequest(String ownerName, String reason) {}
    public record MembershipRequest(UUID artifactId, String decision, String reason,
                                    String lineageType, List<UUID> relatedSystems) {}
    public record RevisionResponse(int revision) {}
    public record DispositionRequest(String disposition, String reason) {}
}
