package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ReviewDisposition;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.ArtifactResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.FindingResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.GraphResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PageResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyAssistExplanationResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyConfigurationResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyScopeConditionResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.RelationshipResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.RunResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.ScopeResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.SummaryResponse;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ai-security")
public class AiSecurityController {

    private final WorkspaceService workspaceService;
    private final RequestActorService requestActorService;
    private final AiSecurityAccessService accessService;
    private final AiSecurityApiService apiService;

    public AiSecurityController(
            WorkspaceService workspaceService,
            RequestActorService requestActorService,
            AiSecurityAccessService accessService,
            AiSecurityApiService apiService
    ) {
        this.workspaceService = workspaceService;
        this.requestActorService = requestActorService;
        this.accessService = accessService;
        this.apiService = apiService;
    }

    @GetMapping("/summary")
    public SummaryResponse summary() {
        Tenant tenant = tenant();
        return apiService.summary(tenant);
    }

    @GetMapping("/artifacts")
    public PageResponse<ArtifactResponse> artifacts(
            @RequestParam(required = false) String artifactType,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String subscription,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Tenant tenant = tenant();
        return apiService.artifacts(tenant, artifactType, provider, subscription, page, size);
    }

    @GetMapping("/artifacts/{artifactId}")
    public ArtifactResponse artifact(@PathVariable UUID artifactId) {
        Tenant tenant = tenant();
        return apiService.artifact(tenant, artifactId);
    }

    @GetMapping("/artifacts/{artifactId}/relationships")
    public List<RelationshipResponse> relationships(@PathVariable UUID artifactId) {
        Tenant tenant = tenant();
        return apiService.relationships(tenant, artifactId);
    }

    @GetMapping("/graph")
    public GraphResponse graph(@RequestParam(required = false) UUID rootArtifactId) {
        Tenant tenant = tenant();
        return apiService.graph(tenant, rootArtifactId);
    }

    @GetMapping("/findings")
    public PageResponse<FindingResponse> findings(
            @RequestParam(required = false) String policyId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String subscription,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Tenant tenant = tenant();
        return apiService.findings(tenant, policyId, status, provider, subscription, page, size);
    }

    @GetMapping("/findings/{findingId}")
    public FindingResponse finding(@PathVariable UUID findingId) {
        Tenant tenant = tenant();
        return apiService.finding(tenant, findingId);
    }

    @PutMapping("/findings/{findingId}/review")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public FindingResponse review(@PathVariable UUID findingId, @RequestBody ReviewRequest request) {
        Tenant tenant = tenant();
        return apiService.review(
                tenant, findingId, request.disposition(), request.reason(),
                requestActorService.currentActor().userId());
    }

    @GetMapping("/policies")
    public List<PolicyResponse> policies() {
        Tenant tenant = tenant();
        return apiService.policies(tenant);
    }

    @GetMapping("/policies/{policyId}")
    public PolicyResponse policy(@PathVariable String policyId) {
        Tenant tenant = tenant();
        return apiService.policy(tenant, policyId);
    }

    @PatchMapping("/policies/{policyId}/enabled")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyResponse updatePolicy(@PathVariable String policyId, @RequestBody PolicyStateRequest request) {
        Tenant tenant = tenant();
        return apiService.updatePolicy(
                tenant, policyId, request.enabled(), requestActorService.currentActor().userId());
    }

    @GetMapping("/policies/{policyId}/configuration")
    public PolicyConfigurationResponse configuration(@PathVariable String policyId) {
        Tenant tenant = tenant();
        return apiService.policyConfiguration(tenant, policyId);
    }

    @PutMapping("/policies/{policyId}/scope")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse updateScope(@PathVariable String policyId, @RequestBody ScopeUpdateRequest request) {
        Tenant tenant = tenant();
        return apiService.updatePolicyScope(
                tenant, policyId, request.mode(), request.conditionLogic(), request.conditions(),
                requestActorService.currentActor().userId());
    }

    @PostMapping("/policies/{policyId}/exceptions")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse addException(@PathVariable String policyId, @RequestBody ExceptionRequest request) {
        Tenant tenant = tenant();
        return apiService.addPolicyException(
                tenant, policyId, request.artifactId(), request.override(), request.reason(),
                requestActorService.currentActor().userId());
    }

    @DeleteMapping("/policies/{policyId}/exceptions/{artifactId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse removeException(@PathVariable String policyId, @PathVariable UUID artifactId) {
        Tenant tenant = tenant();
        return apiService.removePolicyException(
                tenant, policyId, artifactId, requestActorService.currentActor().userId());
    }

    @PutMapping("/policies/{policyId}/parameters")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public PolicyConfigurationResponse updateParameters(
            @PathVariable String policyId, @RequestBody ParametersUpdateRequest request) {
        Tenant tenant = tenant();
        return apiService.updatePolicyParameters(
                tenant, policyId, request.parameters(), requestActorService.currentActor().userId());
    }

    @GetMapping("/policies/{policyId}/assist/explain")
    public PolicyAssistExplanationResponse explainPolicy(@PathVariable String policyId) {
        Tenant tenant = tenant();
        return apiService.explainPolicy(tenant, policyId);
    }

    @GetMapping("/runs")
    public List<RunResponse> runs(@RequestParam(required = false) String provider) {
        Tenant tenant = tenant();
        return apiService.runs(tenant, provider);
    }

    @GetMapping("/runs/{runId}/scopes")
    public List<ScopeResponse> scopes(
            @PathVariable UUID runId,
            @RequestParam(required = false) String resourceFamily,
            @RequestParam(required = false) String status
    ) {
        Tenant tenant = tenant();
        return apiService.scopes(tenant, runId, resourceFamily, status);
    }

    private Tenant tenant() {
        Tenant tenant = workspaceService.getWorkspace();
        accessService.assertEntitled(tenant);
        return tenant;
    }

    public record ReviewRequest(ReviewDisposition disposition, String reason) {
    }

    public record PolicyStateRequest(boolean enabled) {
    }

    public record ScopeUpdateRequest(
            String mode, String conditionLogic, List<PolicyScopeConditionResponse> conditions) {
    }

    public record ExceptionRequest(UUID artifactId, String override, String reason) {
    }

    public record ParametersUpdateRequest(Map<String, String> parameters) {
    }
}
