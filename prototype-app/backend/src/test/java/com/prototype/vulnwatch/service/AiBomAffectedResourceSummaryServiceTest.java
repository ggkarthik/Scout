package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.AiBomResourceVulnerabilityLink;
import com.prototype.vulnwatch.dto.AffectedAiResourceSummary;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import com.prototype.vulnwatch.repo.AiBomResourceVulnerabilityLinkRepository;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit-level coverage of the batch resource/finding join, without a database. */
class AiBomAffectedResourceSummaryServiceTest {

    private AiBomResourceVulnerabilityLinkRepository linkRepository;
    private AiBomDeclaredResourceRepository declaredResourceRepository;
    private AiBomAffectedResourceSummaryService service;

    @BeforeEach
    void setUp() {
        linkRepository = mock(AiBomResourceVulnerabilityLinkRepository.class);
        declaredResourceRepository = mock(AiBomDeclaredResourceRepository.class);
        service = new AiBomAffectedResourceSummaryService(linkRepository, declaredResourceRepository);
    }

    private AiBomDeclaredResource declaredResource(UUID id, String name) {
        AiBomDeclaredResource resource = new AiBomDeclaredResource();
        resource.setId(id);
        resource.setName(name);
        resource.setResourceKind(AiBomDeclaredResourceKind.MODEL);
        return resource;
    }

    private AiBomResourceVulnerabilityLink link(UUID declaredResourceId, UUID findingId) {
        AiBomResourceVulnerabilityLink link = new AiBomResourceVulnerabilityLink();
        link.setDeclaredResourceId(declaredResourceId);
        link.setFindingId(findingId);
        return link;
    }

    @Test
    void emptyFindingIdsShortCircuitsWithoutQuerying() {
        Map<UUID, List<AffectedAiResourceSummary>> result = service.summarize(List.of());

        assertTrue(result.isEmpty());
        verifyNoInteractions(linkRepository, declaredResourceRepository);
    }

    @Test
    void noLinksProducesEmptyMapWithoutResolvingResources() {
        UUID findingId = UUID.randomUUID();
        when(linkRepository.findByFindingIdIn(List.of(findingId))).thenReturn(List.of());

        Map<UUID, List<AffectedAiResourceSummary>> result = service.summarize(List.of(findingId));

        assertTrue(result.isEmpty());
        verifyNoInteractions(declaredResourceRepository);
    }

    @Test
    void oneFindingLinkedToTwoResourcesProducesBothSummaries() {
        UUID findingId = UUID.randomUUID();
        UUID resourceIdA = UUID.randomUUID();
        UUID resourceIdB = UUID.randomUUID();
        when(linkRepository.findByFindingIdIn(List.of(findingId)))
                .thenReturn(List.of(link(resourceIdA, findingId), link(resourceIdB, findingId)));
        when(declaredResourceRepository.findAllById(List.of(resourceIdA, resourceIdB)))
                .thenReturn(List.of(declaredResource(resourceIdA, "llama-3"), declaredResource(resourceIdB, "bert")));

        Map<UUID, List<AffectedAiResourceSummary>> result = service.summarize(List.of(findingId));

        assertEquals(1, result.size());
        assertEquals(2, result.get(findingId).size());
        assertTrue(result.get(findingId).stream().anyMatch(s -> "llama-3".equals(s.name())));
        assertTrue(result.get(findingId).stream().anyMatch(s -> "bert".equals(s.name())));
    }

    @Test
    void aLinkWhoseDeclaredResourceNoLongerExistsIsSkipped() {
        UUID findingId = UUID.randomUUID();
        UUID resourceId = UUID.randomUUID();
        when(linkRepository.findByFindingIdIn(List.of(findingId))).thenReturn(List.of(link(resourceId, findingId)));
        when(declaredResourceRepository.findAllById(List.of(resourceId))).thenReturn(List.of());

        Map<UUID, List<AffectedAiResourceSummary>> result = service.summarize(List.of(findingId));

        assertTrue(result.isEmpty());
    }
}
