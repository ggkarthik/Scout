package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.AiBomLinkMethod;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AiBomDeclaredResourceResponse;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import jakarta.persistence.EntityNotFoundException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** Unit-level coverage of the propose/approve/remove state machine, without a database. */
class AiBomResourceMappingServiceTest {

    private AiBomDeclaredResourceRepository repository;
    private NamedParameterJdbcTemplate jdbc;
    private AiBomResourceMappingService service;
    private Tenant tenant;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        repository = mock(AiBomDeclaredResourceRepository.class);
        jdbc = mock(NamedParameterJdbcTemplate.class);
        service = new AiBomResourceMappingService(repository, jdbc);
        tenantId = UUID.randomUUID();
        tenant = new Tenant();
        tenant.setId(tenantId);
    }

    private AiBomDeclaredResource unverifiedResource(UUID id) {
        AiBomDeclaredResource resource = new AiBomDeclaredResource();
        resource.setId(id);
        resource.setTenantId(tenantId);
        resource.setName("llama-3");
        resource.setDeploymentState(AiBomDeploymentState.UNVERIFIED);
        return resource;
    }

    private void stubArtifactExists(boolean exists) {
        when(jdbc.queryForObject(anyString(), any(Map.class), eq(Integer.class)))
                .thenReturn(exists ? 1 : 0);
    }

    @Test
    void proposeStagesACandidateWithoutTouchingDeploymentState() {
        UUID resourceId = UUID.randomUUID();
        UUID artifactId = UUID.randomUUID();
        AiBomDeclaredResource resource = unverifiedResource(resourceId);
        when(repository.findById(resourceId)).thenReturn(Optional.of(resource));
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        stubArtifactExists(true);

        AiBomDeclaredResourceResponse response = service.propose(tenant, resourceId, artifactId, "reviewer-1");

        assertEquals("UNVERIFIED", response.deploymentState());
        assertEquals(artifactId, response.proposedArtifactId());
        assertEquals("reviewer-1", response.proposedBy());
        assertNull(response.linkedArtifactId());
    }

    @Test
    void proposeRejectsAnUnknownArtifact() {
        UUID resourceId = UUID.randomUUID();
        when(repository.findById(resourceId)).thenReturn(Optional.of(unverifiedResource(resourceId)));
        stubArtifactExists(false);

        assertThrows(EntityNotFoundException.class,
                () -> service.propose(tenant, resourceId, UUID.randomUUID(), "reviewer-1"));
    }

    @Test
    void proposeRejectsAResourceThatIsAlreadyLinked() {
        UUID resourceId = UUID.randomUUID();
        AiBomDeclaredResource resource = unverifiedResource(resourceId);
        resource.setDeploymentState(AiBomDeploymentState.LINKED);
        resource.setLinkedArtifactId(UUID.randomUUID());
        resource.setLinkMethod(AiBomLinkMethod.DIGEST_MATCH);
        when(repository.findById(resourceId)).thenReturn(Optional.of(resource));

        assertThrows(IllegalStateException.class,
                () -> service.propose(tenant, resourceId, UUID.randomUUID(), "reviewer-1"));
    }

    @Test
    void approveCommitsTheProposalAndClearsIt() {
        UUID resourceId = UUID.randomUUID();
        UUID artifactId = UUID.randomUUID();
        AiBomDeclaredResource resource = unverifiedResource(resourceId);
        resource.setProposedArtifactId(artifactId);
        resource.setProposedBy("reviewer-1");
        resource.setProposedAt(java.time.Instant.now());
        when(repository.findById(resourceId)).thenReturn(Optional.of(resource));
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        AiBomDeclaredResourceResponse response = service.approve(tenant, resourceId, "reviewer-2");

        assertEquals("LINKED", response.deploymentState());
        assertEquals(artifactId, response.linkedArtifactId());
        assertEquals("REVIEWED", response.linkMethod());
        assertEquals("reviewer-2", response.linkReviewedBy());
        assertNull(response.proposedArtifactId());
        assertNull(response.proposedBy());
    }

    @Test
    void approveWithoutAPendingProposalIsRejected() {
        UUID resourceId = UUID.randomUUID();
        when(repository.findById(resourceId)).thenReturn(Optional.of(unverifiedResource(resourceId)));

        assertThrows(IllegalStateException.class, () -> service.approve(tenant, resourceId, "reviewer-2"));
    }

    @Test
    void removeClearsAConfirmedLinkBackToUnverified() {
        UUID resourceId = UUID.randomUUID();
        AiBomDeclaredResource resource = unverifiedResource(resourceId);
        resource.setDeploymentState(AiBomDeploymentState.LINKED);
        resource.setLinkedArtifactId(UUID.randomUUID());
        resource.setLinkMethod(AiBomLinkMethod.REVIEWED);
        resource.setLinkReviewedBy("reviewer-2");
        when(repository.findById(resourceId)).thenReturn(Optional.of(resource));
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        AiBomDeclaredResourceResponse response = service.remove(tenant, resourceId, "reviewer-3");

        assertEquals("UNVERIFIED", response.deploymentState());
        assertNull(response.linkedArtifactId());
        assertNull(response.linkMethod());
        assertNull(response.linkReviewedBy());
    }

    @Test
    void removeWithNothingToRemoveIsRejected() {
        UUID resourceId = UUID.randomUUID();
        when(repository.findById(resourceId)).thenReturn(Optional.of(unverifiedResource(resourceId)));

        assertThrows(IllegalStateException.class, () -> service.remove(tenant, resourceId, "reviewer-3"));
    }

    @Test
    void aResourceBelongingToAnotherTenantIsNotFound() {
        UUID resourceId = UUID.randomUUID();
        AiBomDeclaredResource resource = unverifiedResource(resourceId);
        resource.setTenantId(UUID.randomUUID());
        when(repository.findById(resourceId)).thenReturn(Optional.of(resource));

        assertThrows(EntityNotFoundException.class,
                () -> service.propose(tenant, resourceId, UUID.randomUUID(), "reviewer-1"));
    }
}
