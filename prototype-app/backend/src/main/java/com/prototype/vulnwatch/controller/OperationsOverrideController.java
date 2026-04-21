package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.ManualCorrelationOverrideService;
import com.prototype.vulnwatch.service.ManualNormalizationOverrideService;
import com.prototype.vulnwatch.service.NormalizationClusterOverrideService;
import com.prototype.vulnwatch.service.OperationalQualityReadService;
import com.prototype.vulnwatch.service.OperationalQualityReadService.IssueSourceIds;
import com.prototype.vulnwatch.service.QualityIssueRefreshService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/operations")
public class OperationsOverrideController {

    private final WorkspaceService workspaceService;
    private final OperationalQualityReadService qualityReadService;
    private final ManualNormalizationOverrideService normalizationOverrideService;
    private final ManualCorrelationOverrideService correlationOverrideService;
    private final NormalizationClusterOverrideService clusterOverrideService;
    private final QualityIssueRefreshService refreshService;

    public OperationsOverrideController(
            WorkspaceService workspaceService,
            OperationalQualityReadService qualityReadService,
            ManualNormalizationOverrideService normalizationOverrideService,
            ManualCorrelationOverrideService correlationOverrideService,
            NormalizationClusterOverrideService clusterOverrideService,
            QualityIssueRefreshService refreshService
    ) {
        this.workspaceService = workspaceService;
        this.qualityReadService = qualityReadService;
        this.normalizationOverrideService = normalizationOverrideService;
        this.correlationOverrideService = correlationOverrideService;
        this.clusterOverrideService = clusterOverrideService;
        this.refreshService = refreshService;
    }

    private static boolean isClusterType(String sourceObjectType) {
        return "CLUSTER_DISCOVERY_MODEL".equals(sourceObjectType)
                || "CLUSTER_PACKAGE_PATTERN".equals(sourceObjectType);
    }

    /**
     * GET /api/operations/quality/issues/{issueId}/normalize/impact
     * Returns the blast radius (affected asset + instance count) for a cluster-level
     * normalization issue before the override is applied.
     */
    @GetMapping("/quality/issues/{issueId}/normalize/impact")
    public ResponseEntity<ClusterImpactResponse> getNormalizationImpact(
            @PathVariable String issueId
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        IssueSourceIds sourceIds = qualityReadService.getIssueSourceIds(tenant, issueId);
        if (!isClusterType(sourceIds.sourceObjectType())) {
            return ResponseEntity.ok(new ClusterImpactResponse(0L, 0L));
        }
        NormalizationClusterOverrideService.ClusterImpactResult impact =
                clusterOverrideService.getClusterImpact(
                        tenant.getId(), sourceIds.sourceObjectType(), sourceIds.sourceObjectId());
        return ResponseEntity.ok(new ClusterImpactResponse(impact.affectedAssetCount(), impact.affectedInstanceCount()));
    }

    /**
     * POST /api/operations/quality/issues/{issueId}/normalize
     * Apply a manual normalization override.
     * For cluster-type issues (CLUSTER_DISCOVERY_MODEL / CLUSTER_PACKAGE_PATTERN) writes
     * a software_identity_cluster_link and cascades to all matching records.
     * Falls back to per-instance override for legacy SOFTWARE_INSTANCE issues.
     */
    @PostMapping("/quality/issues/{issueId}/normalize")
    public ResponseEntity<OverrideResponse> applyNormalizationOverride(
            @PathVariable String issueId,
            @RequestBody NormalizationOverrideRequest request,
            @RequestHeader(value = "X-User-ID", defaultValue = "system") String actor
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        IssueSourceIds sourceIds = qualityReadService.getIssueSourceIds(tenant, issueId);
        if (isClusterType(sourceIds.sourceObjectType())) {
            clusterOverrideService.applyClusterOverride(
                    tenant.getId(),
                    sourceIds.sourceObjectType(),
                    sourceIds.sourceObjectId(),
                    request.getSoftwareIdentityId(),
                    request.isApplyToFuture(),
                    request.getReason(),
                    actor);
        } else if ("SOFTWARE_INSTANCE".equals(sourceIds.sourceObjectType())) {
            UUID softwareInstanceId = parseSourceObjectId(sourceIds.sourceObjectId(), issueId);
            normalizationOverrideService.applyOverrideToSoftwareInstance(
                    tenant.getId(), softwareInstanceId,
                    request.getSoftwareIdentityId(), request.getReason(), actor);
        } else if (sourceIds.componentId() != null) {
            normalizationOverrideService.applyOverride(
                    tenant.getId(), sourceIds.componentId(),
                    request.getSoftwareIdentityId(), request.getReason(), actor);
        } else {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "This quality issue is not associated with an inventory component or software instance");
        }
        refreshService.refreshTenant(tenant);
        return ResponseEntity.ok(new OverrideResponse(issueId, true, actor));
    }

    /**
     * DELETE /api/operations/quality/issues/{issueId}/normalize
     * Revoke a manual normalization override.
     */
    @DeleteMapping("/quality/issues/{issueId}/normalize")
    public ResponseEntity<OverrideResponse> revokeNormalizationOverride(
            @PathVariable String issueId,
            @RequestHeader(value = "X-User-ID", defaultValue = "system") String actor
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        IssueSourceIds sourceIds = qualityReadService.getIssueSourceIds(tenant, issueId);
        if (isClusterType(sourceIds.sourceObjectType())) {
            clusterOverrideService.revokeClusterOverride(
                    tenant.getId(),
                    sourceIds.sourceObjectType(),
                    sourceIds.sourceObjectId(),
                    actor);
        } else if ("SOFTWARE_INSTANCE".equals(sourceIds.sourceObjectType())) {
            UUID softwareInstanceId = parseSourceObjectId(sourceIds.sourceObjectId(), issueId);
            normalizationOverrideService.revokeOverrideFromSoftwareInstance(tenant.getId(), softwareInstanceId);
        } else if (sourceIds.componentId() != null) {
            normalizationOverrideService.revokeOverride(tenant.getId(), sourceIds.componentId());
        } else {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "This quality issue is not associated with an inventory component or software instance");
        }
        refreshService.refreshTenant(tenant);
        return ResponseEntity.ok(new OverrideResponse(issueId, false, actor));
    }

    private UUID parseSourceObjectId(String sourceObjectId, String issueId) {
        try {
            return UUID.fromString(sourceObjectId);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "Cannot resolve source object id for issue " + issueId);
        }
    }

    /**
     * POST /api/operations/quality/issues/{issueId}/correlate
     * Apply a manual correlation override: set analyst disposition on all states for the component.
     */
    @PostMapping("/quality/issues/{issueId}/correlate")
    public ResponseEntity<OverrideResponse> applyCorrelationOverride(
            @PathVariable String issueId,
            @RequestBody CorrelationOverrideRequest request,
            @RequestHeader(value = "X-User-ID", defaultValue = "system") String actor
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        IssueSourceIds sourceIds = qualityReadService.getIssueSourceIds(tenant, issueId);
        if (sourceIds.componentId() == null) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "This quality issue is not associated with an inventory component");
        }
        correlationOverrideService.applyOverride(
                tenant.getId(),
                sourceIds.componentId(),
                request.getDisposition(),
                request.getReason(),
                actor
        );
        refreshService.refreshTenant(tenant);
        return ResponseEntity.ok(new OverrideResponse(issueId, true, actor));
    }

    /**
     * DELETE /api/operations/quality/issues/{issueId}/correlate
     * Revoke a manual correlation override.
     */
    @DeleteMapping("/quality/issues/{issueId}/correlate")
    public ResponseEntity<OverrideResponse> revokeCorrelationOverride(
            @PathVariable String issueId,
            @RequestHeader(value = "X-User-ID", defaultValue = "system") String actor
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        IssueSourceIds sourceIds = qualityReadService.getIssueSourceIds(tenant, issueId);
        if (sourceIds.componentId() == null) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "This quality issue is not associated with an inventory component");
        }
        correlationOverrideService.revokeOverride(tenant.getId(), sourceIds.componentId());
        refreshService.refreshTenant(tenant);
        return ResponseEntity.ok(new OverrideResponse(issueId, false, actor));
    }

    /**
     * GET /api/operations/software-identities/search?q=&limit=10
     * Autocomplete search for software identities (used in normalization override form).
     */
    @GetMapping("/software-identities/search")
    public ResponseEntity<List<ManualNormalizationOverrideService.SoftwareIdentityMatch>> searchSoftwareIdentities(
            @RequestParam String q,
            @RequestParam(defaultValue = "10") int limit
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        if (q == null || q.isBlank()) {
            return ResponseEntity.ok(List.of());
        }
        List<ManualNormalizationOverrideService.SoftwareIdentityMatch> results =
                normalizationOverrideService.searchSoftwareIdentities(tenant.getId(), q.trim(), Math.min(limit, 50));
        return ResponseEntity.ok(results);
    }

    // DTOs

    @Data
    public static class NormalizationOverrideRequest {
        private UUID softwareIdentityId;
        private String reason;
        private boolean applyToFuture = true;
    }

    @Data
    public static class ClusterImpactResponse {
        private final long affectedAssetCount;
        private final long affectedInstanceCount;
    }

    @Data
    public static class CorrelationOverrideRequest {
        private String disposition; // IMPACTED | NOT_IMPACTED | UNKNOWN
        private String reason;
    }

    @Data
    public static class OverrideResponse {
        private final String issueId;
        private final boolean overrideActive;
        private final String actor;
    }
}
