package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.domain.IdentityMatchRule;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.SoftwareInstanceRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class CorrelationCandidateServiceTest {

    @Mock
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Mock
    private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;

    @Mock
    private SoftwareInstanceRepository softwareInstanceRepository;

    @Mock
    private IdentityLinkRepository identityLinkRepository;

    @Test
    void buildCandidateBundleLoadsTargetsAcrossCpePurlAndCoord() {
        CorrelationCandidateService service = new CorrelationCandidateService(
                vulnerabilityTargetRepository,
                inventoryComponentCpeMapRepository,
                softwareInstanceRepository,
                identityLinkRepository
        );
        InventoryComponent component = component(UUID.randomUUID());
        UUID cpeId = UUID.randomUUID();

        InventoryComponentCpeMap mapRow = new InventoryComponentCpeMap();
        mapRow.setComponent(component);
        CpeDim cpeDim = new CpeDim();
        ReflectionTestUtils.setField(cpeDim, "id", cpeId);
        mapRow.setCpeDim(cpeDim);

        VulnerabilityTarget target = target("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", 1);
        target.setCpeDim(cpeDim);

        when(inventoryComponentCpeMapRepository.findByComponent_IdIn(eq(Set.of(component.getId()))))
                .thenReturn(List.of(mapRow));
        when(vulnerabilityTargetRepository.findByTargetTypeAndCpeDim_IdIn(
                eq(VulnerabilityTargetType.CPE),
                eq(Set.of(cpeId))))
                .thenReturn(List.of(target));
        when(vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(
                eq(VulnerabilityTargetType.PURL),
                eq(Set.of("pkg:maven/org.apache.logging.log4j/log4j@2.14.1"))))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(
                eq(VulnerabilityTargetType.COORD),
                eq(Set.of("maven::log4j", "maven:org.apache.logging.log4j:log4j"))))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(
                eq(VulnerabilityTargetType.ADVISORY_PACKAGE),
                eq(Set.of("maven::log4j", "maven:org.apache.logging.log4j:log4j"))))
                .thenReturn(List.of());
        when(softwareInstanceRepository.findByInventoryComponent_IdIn(eq(Set.of(component.getId()))))
                .thenReturn(List.of());

        CorrelationCandidateService.CandidateBundle bundle = service.buildCandidateBundle(List.of(component));

        assertEquals(Set.of(cpeId), bundle.componentCpeIdsByComponentId().get(component.getId()));
        assertEquals(1, bundle.cpeTargetsByCpeId().get(cpeId).size());
        assertEquals(Set.of("pkg:maven/org.apache.logging.log4j/log4j@2.14.1"), bundle.componentPurlsByComponentId().get(component.getId()));
        assertEquals(
                Set.of("maven::log4j", "maven:org.apache.logging.log4j:log4j"),
                bundle.componentCoordKeysByComponentId().get(component.getId())
        );
    }

    @Test
    void candidatesForComponentReturnsDeterministicCpeOnlyOrder() {
        CorrelationCandidateService service = new CorrelationCandidateService(
                vulnerabilityTargetRepository,
                inventoryComponentCpeMapRepository,
                softwareInstanceRepository,
                identityLinkRepository
        );
        InventoryComponent component = component(UUID.randomUUID());
        UUID cpeId = UUID.randomUUID();

        CpeDim cpeDim = new CpeDim();
        ReflectionTestUtils.setField(cpeDim, "id", cpeId);

        VulnerabilityTarget direct = target("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", 1);
        direct.setCpeDim(cpeDim);
        direct.setVersionStart("2.0.0");
        direct.setVersionEnd("2.17.1");

        VulnerabilityTarget fallback = target("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", 7);
        fallback.setCpeDim(cpeDim);

        CorrelationCandidateService.CandidateBundle bundle = new CorrelationCandidateService.CandidateBundle(
                Map.of(component.getId(), Set.of(cpeId)),
                Map.of(cpeId, List.of(fallback, direct)),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of()
        );

        List<CorrelationCandidateService.CandidateMatch> candidates = service.candidatesForComponent(component, bundle);
        assertEquals(2, candidates.size());
        assertEquals("cpe-indexed-direct+version", candidates.get(0).matchedBy());
        assertEquals("cpe-indexed-fallback+version", candidates.get(1).matchedBy());
        assertTrue(candidates.get(0).confidence() > candidates.get(1).confidence());
        assertEquals(0.05, candidates.get(1).confidenceBreakdown().get("penalties"));
    }

    @Test
    void candidatesForComponentFallsBackToPurlAndCoordWhenCpeMissing() {
        CorrelationCandidateService service = new CorrelationCandidateService(
                vulnerabilityTargetRepository,
                inventoryComponentCpeMapRepository,
                softwareInstanceRepository,
                identityLinkRepository
        );
        InventoryComponent component = component(UUID.randomUUID());

        VulnerabilityTarget purlTarget = targetForType(
                VulnerabilityTargetType.PURL,
                "pkg:maven/org.apache.logging.log4j/log4j@2.14.1"
        );
        VulnerabilityTarget coordTarget = targetForType(
                VulnerabilityTargetType.COORD,
                "maven:org.apache.logging.log4j:log4j"
        );

        CorrelationCandidateService.CandidateBundle bundle = new CorrelationCandidateService.CandidateBundle(
                Map.of(),
                Map.of(),
                Map.of(component.getId(), Set.of("pkg:maven/org.apache.logging.log4j/log4j@2.14.1")),
                Map.of("pkg:maven/org.apache.logging.log4j/log4j@2.14.1", List.of(purlTarget)),
                Map.of(component.getId(), Set.of("maven:org.apache.logging.log4j:log4j")),
                Map.of("maven:org.apache.logging.log4j:log4j", List.of(coordTarget)),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of()
        );

        List<CorrelationCandidateService.CandidateMatch> candidates = service.candidatesForComponent(component, bundle);

        assertEquals(2, candidates.size());
        assertEquals("purl-indexed-exact+version", candidates.get(0).matchedBy());
        assertEquals("coord-indexed-exact+version", candidates.get(1).matchedBy());
    }

    @Test
    void candidatesForComponentPrefersHostIdentityMatchesAheadOfFallbackKeys() {
        CorrelationCandidateService service = new CorrelationCandidateService(
                vulnerabilityTargetRepository,
                inventoryComponentCpeMapRepository,
                softwareInstanceRepository,
                identityLinkRepository
        );
        InventoryComponent component = component(UUID.randomUUID());
        SoftwareIdentity softwareIdentity = new SoftwareIdentity();
        UUID softwareIdentityId = UUID.randomUUID();
        ReflectionTestUtils.setField(softwareIdentity, "id", softwareIdentityId);
        component.setSoftwareIdentity(softwareIdentity);

        VulnerabilityTarget identityTarget = targetForType(
                VulnerabilityTargetType.COORD,
                "generic:microsoft:office"
        );
        identityTarget.setSoftwareIdentity(softwareIdentity);

        CorrelationCandidateService.CandidateBundle bundle = new CorrelationCandidateService.CandidateBundle(
                Map.of(),
                Map.of(),
                Map.of(component.getId(), Set.of("pkg:generic/microsoft/office@16.0")),
                Map.of(),
                Map.of(component.getId(), Set.of("generic:microsoft:office")),
                Map.of(),
                Map.of(),
                Map.of(component.getId(), softwareIdentityId),
                Map.of(softwareIdentityId, List.of(identityTarget)),
                Map.of(component.getId(), IdentityMatchRule.HASH)
        );

        List<CorrelationCandidateService.CandidateMatch> candidates = service.candidatesForComponent(component, bundle);

        assertEquals(1, candidates.size());
        assertEquals("identity-hash-indexed+version", candidates.get(0).matchedBy());
        assertTrue(candidates.get(0).confidence() > 0.9);
    }

    private InventoryComponent component(UUID id) {
        InventoryComponent component = new InventoryComponent();
        ReflectionTestUtils.setField(component, "id", id);
        component.setEcosystem("maven");
        component.setPackageName("log4j");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j@2.14.1");
        return component;
    }

    private VulnerabilityTarget target(String normalizedTargetKey, Integer wildcardScore) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        ReflectionTestUtils.setField(target, "id", UUID.randomUUID());
        target.setTargetType(VulnerabilityTargetType.CPE);
        target.setNormalizedTargetKey(normalizedTargetKey);
        target.setCpeWildcardScore(wildcardScore);
        return target;
    }

    private VulnerabilityTarget targetForType(VulnerabilityTargetType type, String normalizedTargetKey) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        ReflectionTestUtils.setField(target, "id", UUID.randomUUID());
        target.setTargetType(type);
        target.setNormalizedTargetKey(normalizedTargetKey);
        return target;
    }
}
