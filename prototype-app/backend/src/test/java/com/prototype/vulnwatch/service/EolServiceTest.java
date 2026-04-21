package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.SoftwareEolMapping;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.dto.EolMappingConfirmRequest;
import com.prototype.vulnwatch.repo.EolProductCatalogRepository;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import com.prototype.vulnwatch.repo.SoftwareEolMappingRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class EolServiceTest {

    @Mock
    private EolProductCatalogRepository catalogRepository;

    @Mock
    private EolReleaseRepository releaseRepository;

    @Mock
    private SoftwareEolMappingRepository mappingRepository;

    @Mock
    private SoftwareIdentityRepository identityRepository;

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private EolRefreshService eolRefreshService;

    @Test
    void confirmMappingLinksUniqueIdentityAndRefreshesProjection() {
        EolService service = new EolService(
                catalogRepository,
                releaseRepository,
                mappingRepository,
                identityRepository,
                jdbcTemplate,
                eolRefreshService
        );

        UUID identityId = UUID.randomUUID();
        SoftwareIdentity identity = new SoftwareIdentity();
        ReflectionTestUtils.setField(identity, "id", identityId);
        identity.setVendor("microsoft");
        identity.setProduct("office");

        when(mappingRepository.findByNormalizedKey("microsoft::office")).thenReturn(Optional.empty());
        when(identityRepository.findAllByVendorIgnoreCaseAndProductIgnoreCase("microsoft", "office"))
                .thenReturn(List.of(identity));
        when(mappingRepository.saveAndFlush(any(SoftwareEolMapping.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service.confirmMapping(new EolMappingConfirmRequest("microsoft::office", "office"));

        ArgumentCaptor<SoftwareEolMapping> mappingCaptor = ArgumentCaptor.forClass(SoftwareEolMapping.class);
        verify(mappingRepository).saveAndFlush(mappingCaptor.capture());
        SoftwareEolMapping saved = mappingCaptor.getValue();
        assertEquals("microsoft::office", saved.getNormalizedKey());
        assertEquals("office", saved.getEolSlug());
        assertEquals(identityId, saved.getSoftwareIdentityId());
        assertEquals("MANUAL", saved.getMatchMethod());
        assertEquals("MANUAL", saved.getMatchConfidence());
        verify(eolRefreshService).refreshConfirmedMapping("microsoft::office");
    }

    @Test
    void confirmMappingKeepsIdentityUnsetWhenMatchIsAmbiguous() {
        EolService service = new EolService(
                catalogRepository,
                releaseRepository,
                mappingRepository,
                identityRepository,
                jdbcTemplate,
                eolRefreshService
        );

        SoftwareIdentity first = new SoftwareIdentity();
        SoftwareIdentity second = new SoftwareIdentity();
        when(mappingRepository.findByNormalizedKey("apache::httpd")).thenReturn(Optional.empty());
        when(identityRepository.findAllByVendorIgnoreCaseAndProductIgnoreCase("apache", "httpd"))
                .thenReturn(List.of(first, second));
        when(mappingRepository.saveAndFlush(any(SoftwareEolMapping.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service.confirmMapping(new EolMappingConfirmRequest("apache::httpd", "apache"));

        ArgumentCaptor<SoftwareEolMapping> mappingCaptor = ArgumentCaptor.forClass(SoftwareEolMapping.class);
        verify(mappingRepository).saveAndFlush(mappingCaptor.capture());
        assertNull(mappingCaptor.getValue().getSoftwareIdentityId());
        verify(eolRefreshService).refreshConfirmedMapping(eq("apache::httpd"));
    }
}
