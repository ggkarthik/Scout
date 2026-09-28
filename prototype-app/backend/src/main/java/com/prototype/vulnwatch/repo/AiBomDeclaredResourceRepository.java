package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** See {@link BomSourceRepository} on why these are not tenant-qualified. */
@Repository
public interface AiBomDeclaredResourceRepository extends JpaRepository<AiBomDeclaredResource, UUID> {

    Optional<AiBomDeclaredResource> findBySourceIdAndIdentityValue(UUID sourceId, String identityValue);

    List<AiBomDeclaredResource> findBySourceId(UUID sourceId);

    List<AiBomDeclaredResource> findByResourceKind(AiBomDeclaredResourceKind resourceKind);

    List<AiBomDeclaredResource> findByDeploymentState(AiBomDeploymentState deploymentState);

    /**
     * The unlinked queue. Anything not yet shown to correspond to a real deployment, which is
     * coverage work to be surfaced as a setup action rather than a policy violation.
     */
    @Query("""
        SELECT r FROM AiBomDeclaredResource r
        WHERE r.deploymentState <> com.prototype.vulnwatch.domain.AiBomDeploymentState.LINKED
        ORDER BY r.lastDeclaredAt DESC
        """)
    List<AiBomDeclaredResource> findAwaitingDeploymentVerification();

    long countByDeploymentState(AiBomDeploymentState deploymentState);
}
