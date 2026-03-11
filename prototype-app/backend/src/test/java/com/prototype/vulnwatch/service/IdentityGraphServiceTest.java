package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentifierRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class IdentityGraphServiceTest {

    @Mock
    private SoftwareIdentityRepository softwareIdentityRepository;

    @Mock
    private SoftwareIdentifierRepository softwareIdentifierRepository;

    @Mock
    private IdentityLinkRepository identityLinkRepository;

    @Test
    void resolveFromComponents_batchesCanonicalIdentityResolution() {
        IdentityGraphService service = new IdentityGraphService(
                softwareIdentityRepository,
                softwareIdentifierRepository,
                identityLinkRepository
        );
        IdentityGraphService.ComponentIdentityInput log4j = new IdentityGraphService.ComponentIdentityInput(
                "maven",
                "log4j",
                "pkg:maven/org.apache.logging.log4j/log4j@2.14.1",
                "sbom"
        );
        IdentityGraphService.ComponentIdentityInput nginx = new IdentityGraphService.ComponentIdentityInput(
                "oci",
                "nginx",
                "pkg:oci/nginx@1.25.3",
                "sbom"
        );

        SoftwareIdentity existing = new SoftwareIdentity();
        ReflectionTestUtils.setField(existing, "id", UUID.randomUUID());
        existing.setCanonicalKey("pkg:maven:org.apache.logging.log4j:log4j");
        existing.setDisplayName("old name");

        when(softwareIdentityRepository.findByCanonicalKeyIn(any(Collection.class)))
                .thenReturn(List.of(existing));
        when(softwareIdentityRepository.saveAll(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        Map<IdentityGraphService.ComponentIdentityInput, SoftwareIdentity> resolved = service.resolveFromComponents(
                List.of(log4j, nginx)
        );

        ArgumentCaptor<Collection<String>> canonicalKeysCaptor = ArgumentCaptor.forClass(Collection.class);
        verify(softwareIdentityRepository).findByCanonicalKeyIn(canonicalKeysCaptor.capture());
        assertEquals(
                List.of("pkg:maven:org.apache.logging.log4j:log4j", "pkg:oci::nginx"),
                List.copyOf(canonicalKeysCaptor.getValue())
        );
        verify(softwareIdentityRepository, times(2)).saveAll(any());

        assertEquals(2, resolved.size());
        assertSame(existing, resolved.get(log4j));
        assertEquals("pkg:oci::nginx", resolved.get(nginx).getCanonicalKey());
    }
}
