package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.AiBomProjectionReceipt;
import com.prototype.vulnwatch.domain.AiBomProvenanceFact;
import com.prototype.vulnwatch.domain.AiBomResourceVulnerabilityLink;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompletenessAssertion;
import com.prototype.vulnwatch.domain.BomSourceState;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AiBomDeclaredResourceDetailResponse;
import com.prototype.vulnwatch.dto.AiBomDeclaredResourceResponse;
import com.prototype.vulnwatch.dto.BomSetupActionResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import com.prototype.vulnwatch.repo.AiBomProjectionReceiptRepository;
import com.prototype.vulnwatch.repo.AiBomProvenanceFactRepository;
import com.prototype.vulnwatch.repo.AiBomResourceVulnerabilityLinkRepository;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import com.prototype.vulnwatch.repo.BomSourceCompletenessAssertionRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import jakarta.persistence.EntityNotFoundException;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Read side for declared AI-BOM resources (Milestone 3 part 5.3): the detail view a coverage
 * setup action or a findings-affecting-this-resource lookup links out to, none of which existed
 * before this part -- 5.1/5.2 built the correlation and filtering, not a place to look at a
 * declared resource on its own.
 */
@Service
@RequiredArgsConstructor
public class AiBomDeclaredResourceReadService {

    private final AiBomDeclaredResourceRepository declaredResourceRepository;
    private final AiBomResourceVulnerabilityLinkRepository linkRepository;
    private final BomSourceRepository sourceRepository;
    private final BomSourceCompletenessAssertionRepository assertionRepository;
    private final BomComponentRepository componentRepository;
    private final AiBomProvenanceFactRepository provenanceFactRepository;
    private final AiBomProjectionReceiptRepository projectionReceiptRepository;
    private final FindingQueryService findingQueryService;

    @Transactional(readOnly = true)
    public List<AiBomDeclaredResourceResponse> list(Tenant tenant, AiBomDeploymentState deploymentState) {
        List<AiBomDeclaredResource> resources = deploymentState == null
                ? declaredResourceRepository.findAll()
                : declaredResourceRepository.findByDeploymentState(deploymentState);
        return resources.stream()
                .filter(resource -> tenant.getId().equals(resource.getTenantId()))
                .map(AiBomDeclaredResourceReadService::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public AiBomDeclaredResourceDetailResponse getDetail(Tenant tenant, UUID resourceId) {
        AiBomDeclaredResource resource = requireOwnedResource(tenant, resourceId);
        BomSource source = sourceRepository.findById(resource.getSourceId())
                .orElseThrow(() -> new EntityNotFoundException("BOM source not found: " + resource.getSourceId()));

        BomComponent component = resource.getBomComponentId() == null
                ? null
                : componentRepository.findById(resource.getBomComponentId()).orElse(null);

        BomSourceCompletenessAssertion assertion = assertionRepository
                .findByBomId(resource.getBomId())
                .orElse(null);

        AiBomProvenanceFact provenance = source.getAssetId() == null
                ? null
                : provenanceFactRepository
                        .findByTenantIdAndAssetIdAndFactKey(
                                tenant.getId(), source.getAssetId(), "provenance.ai_bom_present")
                        .orElse(null);
        List<AiBomProjectionReceipt> receipts = projectionReceiptRepository
                .findByTenantIdAndSourceIdOrderByCompletedAtDesc(tenant.getId(), source.getId());
        AiBomProjectionReceipt latestReceipt = receipts.isEmpty() ? null : receipts.get(0);

        return new AiBomDeclaredResourceDetailResponse(
                toResponse(resource),
                source.getBomType() == null ? null : source.getBomType().name(),
                source.getState() == null ? null : source.getState().name(),
                source.getRevision(),
                resource.getBomId().equals(source.getCurrentBomId()),
                component == null ? null : new AiBomDeclaredResourceDetailResponse.Component(
                        component.getId(), component.getName(), component.getVersion(),
                        component.getPurl(), component.getLicense(), component.getScope(),
                        component.getComponentType()),
                assertion == null ? null : new AiBomDeclaredResourceDetailResponse.Completeness(
                        assertion.getCompleteness() == null ? null : assertion.getCompleteness().name(),
                        assertion.getAssertedBy(), assertion.getAssertedAt()),
                new AiBomDeclaredResourceDetailResponse.Projection(
                        provenance != null,
                        provenance == null ? null : provenance.getProjectedAt(),
                        provenance == null ? null : provenance.getBomFormat(),
                        provenance == null ? null : provenance.getSpecVersion(),
                        latestReceipt == null ? null : latestReceipt.getOperation(),
                        latestReceipt == null ? null : latestReceipt.getCompletedAt())
        );
    }

    @Transactional(readOnly = true)
    public List<FindingResponse> findingsAffecting(Tenant tenant, UUID resourceId) {
        requireOwnedResource(tenant, resourceId);
        List<UUID> findingIds = linkRepository.findByDeclaredResourceId(resourceId).stream()
                .map(AiBomResourceVulnerabilityLink::getFindingId)
                .distinct()
                .toList();
        return findingQueryService.listEntitiesByTenantAndIds(tenant, findingIds).stream()
                .map(findingQueryService::toResponse)
                .toList();
    }

    /**
     * Coverage work, not policy violations: declarations still awaiting deployment
     * verification, plus sources held behind entitlement or the projection backlog cap.
     * Computed live from the tables that are already the durable truth -- unlike AI Grid's
     * own {@code ai_grid_setup_actions}, there is no separate scan run whose gaps need
     * persisting between reads, so no additional table is warranted here.
     */
    @Transactional(readOnly = true)
    public List<BomSetupActionResponse> listSetupActions(Tenant tenant) {
        List<BomSetupActionResponse> actions = new java.util.ArrayList<>();

        for (AiBomDeclaredResource resource : declaredResourceRepository.findAwaitingDeploymentVerification()) {
            if (!tenant.getId().equals(resource.getTenantId())) {
                continue;
            }
            boolean ambiguous = resource.getDeploymentState() == AiBomDeploymentState.AMBIGUOUS;
            actions.add(new BomSetupActionResponse(
                    ambiguous ? "AMBIGUOUS" : "UNLINKED",
                    ambiguous ? "HIGH" : "MEDIUM",
                    ambiguous
                            ? "Ambiguous deployment mapping: " + resource.getName()
                            : "Unverified declared resource: " + resource.getName(),
                    ambiguous
                            ? "Multiple candidate deployments match this declaration. Propose the "
                                    + "correct one for review."
                            : "This declared resource has not been matched to a real deployment yet.",
                    resource.getId()));
        }

        for (BomSourceState heldState : List.of(BomSourceState.HELD_ENTITLEMENT, BomSourceState.DEFERRED)) {
            for (BomSource source : sourceRepository.findByState(heldState)) {
                if (!tenant.getId().equals(source.getTenantId())) {
                    continue;
                }
                boolean heldEntitlement = heldState == BomSourceState.HELD_ENTITLEMENT;
                actions.add(new BomSetupActionResponse(
                        heldState.name(),
                        "LOW",
                        (heldEntitlement ? "Entitlement-held" : "Backlog-deferred") + " BOM source",
                        heldEntitlement
                                ? "This tenant does not currently have the AI Security entitlement; "
                                        + "projection for this source is paused."
                                : "This source is queued behind the tenant's projection backlog cap.",
                        source.getId()));
            }
        }

        return actions;
    }

    private AiBomDeclaredResource requireOwnedResource(Tenant tenant, UUID resourceId) {
        AiBomDeclaredResource resource = declaredResourceRepository.findById(resourceId)
                .orElseThrow(() -> new EntityNotFoundException("Declared AI-BOM resource not found: " + resourceId));
        if (!tenant.getId().equals(resource.getTenantId())) {
            throw new EntityNotFoundException("Declared AI-BOM resource not found: " + resourceId);
        }
        return resource;
    }

    static AiBomDeclaredResourceResponse toResponse(AiBomDeclaredResource resource) {
        return new AiBomDeclaredResourceResponse(
                resource.getId(),
                resource.getSourceId(),
                resource.getBomId(),
                resource.getBomComponentId(),
                resource.getResourceKind() == null ? null : resource.getResourceKind().name(),
                resource.getName(),
                resource.getVersion(),
                resource.getIdentityKind() == null ? null : resource.getIdentityKind().name(),
                resource.getIdentityValue(),
                resource.getDeploymentState() == null ? null : resource.getDeploymentState().name(),
                resource.getLinkedArtifactId(),
                resource.getLinkMethod() == null ? null : resource.getLinkMethod().name(),
                resource.getLinkReviewedBy(),
                resource.getLinkReviewedAt(),
                resource.getProposedArtifactId(),
                resource.getProposedBy(),
                resource.getProposedAt(),
                resource.getFirstDeclaredAt(),
                resource.getLastDeclaredAt());
    }
}
