package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.AnalystDisposition;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingsFilter;
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
    private final FindingRecomputeService findingRecomputeService;

    public FindingService(
            FindingQueryService findingQueryService,
            FindingWorkflowFacade findingWorkflowFacade,
            FindingAssetRecomputeService findingAssetRecomputeService,
            FindingRecomputeService findingRecomputeService
    ) {
        this.findingQueryService = findingQueryService;
        this.findingWorkflowFacade = findingWorkflowFacade;
        this.findingAssetRecomputeService = findingAssetRecomputeService;
        this.findingRecomputeService = findingRecomputeService;
    }

    @Transactional
    public int recomputeForAsset(Tenant tenant, Asset asset) {
        return findingAssetRecomputeService.recomputeForAsset(tenant, asset);
    }

    @Transactional
    public int recomputeForAssets(List<Asset> assets) {
        return findingAssetRecomputeService.recomputeForAssets(assets);
    }

    public int recomputeOnSoftwareDelta(UUID tenantId, UUID componentId) {
        return findingRecomputeService.recomputeOnSoftwareDelta(tenantId, componentId);
    }

    public int recomputeOnSoftwareDeltaBatch(UUID tenantId, Collection<UUID> componentIds) {
        return findingRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, componentIds);
    }

    public FindingPageResponse listByTenantPage(
            Tenant tenant,
            int page,
            int size,
            FindingsFilter filter
    ) {
        return findingQueryService.listByTenantPage(tenant, page, size, filter);
    }

    public List<Finding> listEntitiesByTenantFilter(Tenant tenant, FindingsFilter filter) {
        return findingQueryService.listEntitiesByTenantFilter(tenant, filter);
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
