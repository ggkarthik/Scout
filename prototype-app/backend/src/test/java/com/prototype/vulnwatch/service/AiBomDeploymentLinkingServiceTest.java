package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AiBomDeclaredIdentityKind;
import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.AiBomLinkMethod;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** Unit-level coverage of the conservative model-linking rule, without a database. */
class AiBomDeploymentLinkingServiceTest {

    private NamedParameterJdbcTemplate jdbc;
    private AiBomDeploymentLinkingService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        jdbc = mock(NamedParameterJdbcTemplate.class);
        service = new AiBomDeploymentLinkingService(jdbc);
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
    }

    private static AiBomDeclaredResource model(String name, String version) {
        AiBomDeclaredResource declared = new AiBomDeclaredResource();
        declared.setResourceKind(AiBomDeclaredResourceKind.MODEL);
        declared.setIdentityKind(AiBomDeclaredIdentityKind.VERSIONED_IDENTIFIER);
        declared.setName(name);
        declared.setVersion(version);
        declared.setDeploymentState(AiBomDeploymentState.UNVERIFIED);
        return declared;
    }

    @SuppressWarnings("unchecked")
    private void stubCandidates(AiBomDeploymentLinkingService.Candidate... candidates) {
        when(jdbc.query(anyString(), any(Map.class), any(RowMapper.class)))
                .thenAnswer(invocation -> List.of(candidates));
    }

    @Test
    void aSingleCandidateWithAMatchingVersionIsLinked() {
        UUID artifactId = UUID.randomUUID();
        stubCandidates(new AiBomDeploymentLinkingService.Candidate(artifactId, "3.1"));
        AiBomDeclaredResource declared = model("llama-3", "3.1");

        service.attemptLink(tenant, declared);

        assertEquals(AiBomDeploymentState.LINKED, declared.getDeploymentState());
        assertEquals(artifactId, declared.getLinkedArtifactId());
        assertEquals(AiBomLinkMethod.VERSIONED_IDENTIFIER_MATCH, declared.getLinkMethod());
    }

    @Test
    void twoCandidatesWithDifferentVersionsResolveToTheOneThatMatches() {
        UUID matching = UUID.randomUUID();
        stubCandidates(new AiBomDeploymentLinkingService.Candidate(UUID.randomUUID(), "2.0"), new AiBomDeploymentLinkingService.Candidate(matching, "3.1"));
        AiBomDeclaredResource declared = model("llama-3", "3.1");

        service.attemptLink(tenant, declared);

        assertEquals(AiBomDeploymentState.LINKED, declared.getDeploymentState());
        assertEquals(matching, declared.getLinkedArtifactId());
    }

    @Test
    void twoCandidatesWithNoVersionAtAllBecomeAmbiguousRatherThanAGuess() {
        stubCandidates(new AiBomDeploymentLinkingService.Candidate(UUID.randomUUID(), null), new AiBomDeploymentLinkingService.Candidate(UUID.randomUUID(), null));
        AiBomDeclaredResource declared = model("llama-3", "3.1");

        service.attemptLink(tenant, declared);

        assertEquals(AiBomDeploymentState.AMBIGUOUS, declared.getDeploymentState());
        assertNull(declared.getLinkedArtifactId());
    }

    @Test
    void twoCandidatesSharingTheDeclaredVersionBecomeAmbiguous() {
        stubCandidates(new AiBomDeploymentLinkingService.Candidate(UUID.randomUUID(), "3.1"), new AiBomDeploymentLinkingService.Candidate(UUID.randomUUID(), "3.1"));
        AiBomDeclaredResource declared = model("llama-3", "3.1");

        service.attemptLink(tenant, declared);

        assertEquals(AiBomDeploymentState.AMBIGUOUS, declared.getDeploymentState());
    }

    @Test
    void zeroCandidatesLeaveTheDeclarationUnverified() {
        stubCandidates();
        AiBomDeclaredResource declared = model("llama-3", "3.1");

        service.attemptLink(tenant, declared);

        assertEquals(AiBomDeploymentState.UNVERIFIED, declared.getDeploymentState());
        assertNull(declared.getLinkedArtifactId());
    }

    @Test
    void aVersionRequiredButUnmatchedAgainstAnyCandidateLeavesTheDeclarationUnchanged() {
        stubCandidates(new AiBomDeploymentLinkingService.Candidate(UUID.randomUUID(), "9.9"));
        AiBomDeclaredResource declared = model("llama-3", "3.1");

        service.attemptLink(tenant, declared);

        assertEquals(AiBomDeploymentState.UNVERIFIED, declared.getDeploymentState());
        assertNull(declared.getLinkedArtifactId());
    }

    @Test
    void aNameOnlyMatchIsAcceptedWhenTheArtifactExposesNoVersionAtAllAndItIsUnambiguous() {
        UUID artifactId = UUID.randomUUID();
        stubCandidates(new AiBomDeploymentLinkingService.Candidate(artifactId, null));
        AiBomDeclaredResource declared = model("llama-3", "3.1");

        service.attemptLink(tenant, declared);

        assertEquals(AiBomDeploymentState.LINKED, declared.getDeploymentState());
        assertEquals(artifactId, declared.getLinkedArtifactId());
    }

    @Test
    void aDigestIdentifiedResourceIsNeverQueriedForAutomatically() {
        AiBomDeclaredResource declared = model("llama-3", "3.1");
        declared.setIdentityKind(AiBomDeclaredIdentityKind.DIGEST);

        service.attemptLink(tenant, declared);

        verifyNoInteractions(jdbc);
        assertEquals(AiBomDeploymentState.UNVERIFIED, declared.getDeploymentState());
    }

    @Test
    void aSourceScopedRefResourceIsNeverQueriedForAutomatically() {
        AiBomDeclaredResource declared = model("llama-3", "3.1");
        declared.setIdentityKind(AiBomDeclaredIdentityKind.SOURCE_SCOPED_REF);

        service.attemptLink(tenant, declared);

        verifyNoInteractions(jdbc);
    }

    @Test
    void aDatasetIsNeverQueriedForAutomatically() {
        AiBomDeclaredResource declared = model("training-corpus", "2024.1");
        declared.setResourceKind(AiBomDeclaredResourceKind.DATASET);

        service.attemptLink(tenant, declared);

        verifyNoInteractions(jdbc);
    }
}
