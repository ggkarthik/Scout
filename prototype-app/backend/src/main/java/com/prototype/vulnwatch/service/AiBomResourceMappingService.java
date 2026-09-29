package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.AiBomLinkMethod;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AiBomDeclaredResourceResponse;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The human-reviewed mapping path {@link AiBomDeploymentLinkingService} deliberately doesn't
 * perform (Milestone 3 part 5.3): propose a candidate deployment, have a (possibly different)
 * reviewer approve or discard it. A declaration is never presented as LINKED on a proposal
 * alone -- only {@link #approve} sets {@code deploymentState}, exactly the way the V7 schema's
 * own consistency checks require.
 */
@Service
public class AiBomResourceMappingService {

    private final AiBomDeclaredResourceRepository repository;
    private final NamedParameterJdbcTemplate jdbc;

    public AiBomResourceMappingService(
            AiBomDeclaredResourceRepository repository, NamedParameterJdbcTemplate jdbc) {
        this.repository = repository;
        this.jdbc = jdbc;
    }

    @Transactional
    public AiBomDeclaredResourceResponse propose(
            Tenant tenant, UUID resourceId, UUID artifactId, String actorUserId) {
        AiBomDeclaredResource resource = requireOwnedResource(tenant, resourceId);
        if (resource.getDeploymentState() == AiBomDeploymentState.LINKED) {
            throw new IllegalStateException(
                    "Declared resource " + resourceId + " is already linked; remove the link before proposing a new one.");
        }
        if (!artifactExists(tenant, artifactId)) {
            throw new EntityNotFoundException("AI Security artifact not found: " + artifactId);
        }

        resource.setProposedArtifactId(artifactId);
        resource.setProposedBy(actorUserId);
        resource.setProposedAt(Instant.now());
        return AiBomDeclaredResourceReadService.toResponse(repository.save(resource));
    }

    @Transactional
    public AiBomDeclaredResourceResponse approve(Tenant tenant, UUID resourceId, String actorUserId) {
        AiBomDeclaredResource resource = requireOwnedResource(tenant, resourceId);
        if (resource.getProposedArtifactId() == null) {
            throw new IllegalStateException(
                    "Declared resource " + resourceId + " has no pending mapping proposal to approve.");
        }

        resource.setDeploymentState(AiBomDeploymentState.LINKED);
        resource.setLinkedArtifactId(resource.getProposedArtifactId());
        resource.setLinkMethod(AiBomLinkMethod.REVIEWED);
        resource.setLinkReviewedBy(actorUserId);
        resource.setLinkReviewedAt(Instant.now());
        resource.setProposedArtifactId(null);
        resource.setProposedBy(null);
        resource.setProposedAt(null);
        return AiBomDeclaredResourceReadService.toResponse(repository.save(resource));
    }

    /** Discards a pending proposal, or un-links a previously approved/automatic mapping. */
    @Transactional
    public AiBomDeclaredResourceResponse remove(Tenant tenant, UUID resourceId, String actorUserId) {
        AiBomDeclaredResource resource = requireOwnedResource(tenant, resourceId);
        if (resource.getDeploymentState() != AiBomDeploymentState.LINKED
                && resource.getProposedArtifactId() == null) {
            throw new IllegalStateException(
                    "Declared resource " + resourceId + " has no link or pending proposal to remove.");
        }

        resource.setDeploymentState(AiBomDeploymentState.UNVERIFIED);
        resource.setLinkedArtifactId(null);
        resource.setLinkMethod(null);
        resource.setLinkReviewedBy(null);
        resource.setLinkReviewedAt(null);
        resource.setProposedArtifactId(null);
        resource.setProposedBy(null);
        resource.setProposedAt(null);
        return AiBomDeclaredResourceReadService.toResponse(repository.save(resource));
    }

    private AiBomDeclaredResource requireOwnedResource(Tenant tenant, UUID resourceId) {
        AiBomDeclaredResource resource = repository.findById(resourceId)
                .orElseThrow(() -> new EntityNotFoundException("Declared AI-BOM resource not found: " + resourceId));
        if (!tenant.getId().equals(resource.getTenantId())) {
            throw new EntityNotFoundException("Declared AI-BOM resource not found: " + resourceId);
        }
        return resource;
    }

    private boolean artifactExists(Tenant tenant, UUID artifactId) {
        Integer count = jdbc.queryForObject(
                "select count(*) from ai_security_artifacts where id = :id and tenant_id = :tenantId",
                Map.of("id", artifactId, "tenantId", tenant.getId()),
                Integer.class);
        return count != null && count > 0;
    }
}
