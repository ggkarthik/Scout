package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.AnalystDisposition;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingService {

    private final FindingQueryService findingQueryService;
    private final FindingWorkflowFacade findingWorkflowFacade;
    private final FindingAssetRecomputeService findingAssetRecomputeService;
    private final FindingComponentRecomputeService findingComponentRecomputeService;

    public FindingService(
            FindingQueryService findingQueryService,
            FindingWorkflowFacade findingWorkflowFacade,
            FindingAssetRecomputeService findingAssetRecomputeService,
            FindingComponentRecomputeService findingComponentRecomputeService
    ) {
        this.findingQueryService = findingQueryService;
        this.findingWorkflowFacade = findingWorkflowFacade;
        this.findingAssetRecomputeService = findingAssetRecomputeService;
        this.findingComponentRecomputeService = findingComponentRecomputeService;
    }

    @Transactional
    public int recomputeForAsset(Tenant tenant, Asset asset) {
        return findingAssetRecomputeService.recomputeForAsset(tenant, asset);
    }

    @Transactional
    public int recomputeForAssets(List<Asset> assets) {
        return findingAssetRecomputeService.recomputeForAssets(assets);
    }

    @Transactional
    public int recomputeOnSoftwareDelta(UUID tenantId, UUID componentId) {
        return findingComponentRecomputeService.recomputeOnSoftwareDelta(tenantId, componentId);
    }

    @Transactional
    public int recomputeOnSoftwareDeltaBatch(UUID tenantId, Collection<UUID> componentIds) {
        return findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, componentIds);
    }

    public FindingPageResponse listByTenantPage(
            Tenant tenant,
            int page,
            int size,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        return findingQueryService.listByTenantPage(
                tenant,
                page,
                size,
                severity,
                status,
                decisionState,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem
        );
    }

    public List<Finding> listEntitiesByTenantFilter(
            Tenant tenant,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        return findingQueryService.listEntitiesByTenantFilter(
                tenant,
                severity,
                status,
                decisionState,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem
        );
    }

    public List<Finding> listEntitiesByTenantAndIds(Tenant tenant, List<UUID> findingIds) {
        return findingQueryService.listEntitiesByTenantAndIds(tenant, findingIds);
    }

    public List<FindingResponse> listByTenant(Tenant tenant) {
        return findingQueryService.listByTenant(tenant);
    }

    @Transactional(readOnly = true)
    public FindingFilterValuesResponse listAvailableFilters(Tenant tenant) {
        return findingQueryService.listAvailableFilters(tenant);
    }

    public List<FindingResponse> listLatestByTenant(Tenant tenant, int limit) {
        return findingQueryService.listLatestByTenant(tenant, limit);
    }

    public long countOpen(Tenant tenant) {
        return findingQueryService.countOpen(tenant);
    }

    public long countCritical(Tenant tenant) {
        return findingQueryService.countCritical(tenant);
    }

    @Transactional
    public ManualFindingCreationResult createManualFindingsForVulnerability(
            Tenant tenant,
            Vulnerability vulnerability,
            String justification,
            String createdBy,
            Collection<UUID> selectedComponentIds,
            Map<UUID, ApplicabilityState> applicabilityOverrides,
            Map<UUID, AnalystDisposition> analystDispositions
    ) {
        return findingWorkflowFacade.createManualFindingsForVulnerability(
                tenant,
                vulnerability,
                justification,
                createdBy,
                selectedComponentIds,
                applicabilityOverrides,
                analystDispositions
        );
    }

    @Transactional
    public int suppressFindingsForVulnerability(
            Tenant tenant,
            Vulnerability vulnerability,
            String reason,
            String justification,
            String actor,
            Instant suppressedUntil
    ) {
        return findingWorkflowFacade.suppressFindingsForVulnerability(
                tenant,
                vulnerability,
                reason,
                justification,
                actor,
                suppressedUntil
        );
    }

    public FindingResponse toResponse(Finding finding) {
        return findingQueryService.toResponse(finding);
    }
}
