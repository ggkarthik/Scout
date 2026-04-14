package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.EolProductCatalog;
import com.prototype.vulnwatch.dto.EolSlugSuggestionDto;
import com.prototype.vulnwatch.repo.EolProductCatalogRepository;
import com.prototype.vulnwatch.repo.SoftwareEolMappingRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EolSlugResolverServiceTest {

    @Mock
    private SoftwareIdentityRepository softwareIdentityRepository;

    @Mock
    private EolProductCatalogRepository eolProductCatalogRepository;

    @Mock
    private SoftwareEolMappingRepository softwareEolMappingRepository;

    @Test
    void resolveSuggestionsUsesCatalogDisplayNameAndSlugFallback() {
        EolSlugResolverService service = new EolSlugResolverService(
                softwareIdentityRepository,
                eolProductCatalogRepository,
                softwareEolMappingRepository
        );
        EolSlugResolverService spyService = org.mockito.Mockito.spy(service);

        EolProductCatalog office = new EolProductCatalog();
        office.setSlug("office");
        office.setDisplayName("Microsoft Office");

        EolProductCatalog apache = new EolProductCatalog();
        apache.setSlug("apache");
        apache.setDisplayName(" ");

        doReturn(List.of(
                new EolSlugResolverService.SlugMatch("office", "HIGH", "ALIAS"),
                new EolSlugResolverService.SlugMatch("apache", "MEDIUM", "NAME"),
                new EolSlugResolverService.SlugMatch("missing", "LOW", "TEXT_SEARCH")
        )).when(spyService).resolveCandidates("microsoft::office");

        when(eolProductCatalogRepository.findBySlug("office")).thenReturn(Optional.of(office));
        when(eolProductCatalogRepository.findBySlug("apache")).thenReturn(Optional.of(apache));
        when(eolProductCatalogRepository.findBySlug("missing")).thenReturn(Optional.empty());

        List<EolSlugSuggestionDto> suggestions = spyService.resolveSuggestions("microsoft::office");

        assertEquals(3, suggestions.size());
        assertEquals(new EolSlugSuggestionDto("office", "Microsoft Office", "HIGH", "ALIAS"), suggestions.get(0));
        assertEquals(new EolSlugSuggestionDto("apache", "apache", "MEDIUM", "NAME"), suggestions.get(1));
        assertEquals(new EolSlugSuggestionDto("missing", "missing", "LOW", "TEXT_SEARCH"), suggestions.get(2));
    }
}
