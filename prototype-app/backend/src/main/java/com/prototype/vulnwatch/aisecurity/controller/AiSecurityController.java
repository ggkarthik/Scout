package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ReviewDisposition;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.ArtifactResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.FindingResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.GraphResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PageResponse;
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
import org.springframework.web.bind.annotation.GetMapping;
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
            @RequestParam(required = false) String nativeKind,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String subscription,
            @RequestParam(required = false) String severity,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Tenant tenant = tenant();
        return apiService.artifacts(tenant, artifactType, nativeKind, provider, subscription, severity, page, size);
    }

    @GetMapping("/artifact-summaries")
    public PageResponse<AiSecurityApiService.ArtifactSummaryResponse> artifactSummaries(
            @RequestParam(required = false) String artifactType,
            @RequestParam(required = false) String nativeKind,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String subscription,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String excludeNativeKinds,
            @RequestParam(required = false) String excludeArtifactTypes,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Tenant tenant = tenant();
        return apiService.artifactSummaries(tenant, artifactType, nativeKind, provider, subscription, severity,
                excludeNativeKinds, excludeArtifactTypes, page, size);
    }

    /** Purpose-built inventory views deliberately return the same redacted artifact contract as detail/graph. */
    @GetMapping("/inventory/knowledge-data")
    public PageResponse<ArtifactResponse> knowledgeData(
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String kind,
            @RequestParam(required = false) String sourceType,
            @RequestParam(required = false) String sensitivity,
            @RequestParam(required = false) String publicContentAccess,
            @RequestParam(required = false) Boolean active,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        return apiService.knowledgeData(tenant(), provider, kind, sourceType, sensitivity, publicContentAccess, active, page, size);
    }

    @GetMapping("/inventory/mcp")
    public PageResponse<ArtifactResponse> mcp(
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String authenticationType,
            @RequestParam(required = false) String endpointExposure,
            @RequestParam(required = false) String synchronizationStatus,
            @RequestParam(required = false) Boolean active,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        return apiService.mcp(tenant(), provider, role, authenticationType, endpointExposure, synchronizationStatus, active, page, size);
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
    public GraphResponse graph(
            @RequestParam(required = false) UUID rootArtifactId,
            @RequestParam(defaultValue = "1") int depth
    ) {
        Tenant tenant = tenant();
        return apiService.graph(tenant, rootArtifactId, depth);
    }

    @GetMapping("/severity-grid")
    public AiSecurityApiService.SeverityGridResponse severityGrid() {
        Tenant tenant = tenant();
        return apiService.severityGrid(tenant);
    }

    @GetMapping("/top-risk-artifacts")
    public List<AiSecurityApiService.TopRiskArtifact> topRiskArtifacts(
            @RequestParam(defaultValue = "5") int limit
    ) {
        Tenant tenant = tenant();
        return apiService.topRiskArtifacts(tenant, limit);
    }

    @GetMapping("/findings")
    public PageResponse<FindingResponse> findings(
            @RequestParam(required = false) String policyId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String subscription,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String nativeKind,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Tenant tenant = tenant();
        return apiService.findings(tenant, policyId, status, provider, subscription, severity, nativeKind, page, size);
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

}
