package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.config.PlatformOwnerBootstrapProperties;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.repo.AppUserRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;

@ExtendWith(MockitoExtension.class)
class PlatformOwnerBootstrapServiceTest {

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private AppUserGlobalRoleService appUserGlobalRoleService;

    @Test
    void bootstrapsConfiguredPlatformOwnersUsingEmailAsFallbackSubject() throws Exception {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed = new PlatformOwnerBootstrapProperties.PlatformOwnerSeed();
        seed.setEmail("Owner@Example.com");
        seed.setDisplayName("Owner One");
        properties.setUsers(List.of(seed));

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCase("owner@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PlatformOwnerBootstrapService service = new PlatformOwnerBootstrapService(
                properties,
                userRepository,
                appUserGlobalRoleService
        );

        service.run(new DefaultApplicationArguments(new String[0]));

        verify(userRepository).save(any(AppUser.class));
        verify(appUserGlobalRoleService).ensureRole(any(AppUser.class), eq("PLATFORM_OWNER"));
    }

    @Test
    void rejectsConflictingSubjectAndEmailMatches() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed = new PlatformOwnerBootstrapProperties.PlatformOwnerSeed();
        seed.setExternalSubject("owner-subject");
        seed.setEmail("owner@example.com");
        properties.setUsers(List.of(seed));

        AppUser subjectUser = new AppUser();
        subjectUser.setId(UUID.randomUUID());
        subjectUser.setExternalSubject("owner-subject");
        AppUser emailUser = new AppUser();
        emailUser.setId(UUID.randomUUID());
        emailUser.setEmail("owner@example.com");

        when(userRepository.findByExternalSubject("owner-subject")).thenReturn(Optional.of(subjectUser));
        when(userRepository.findByEmailIgnoreCase("owner@example.com")).thenReturn(Optional.of(emailUser));

        PlatformOwnerBootstrapService service = new PlatformOwnerBootstrapService(
                properties,
                userRepository,
                appUserGlobalRoleService
        );

        IllegalStateException error = assertThrows(
                IllegalStateException.class,
                () -> service.run(new DefaultApplicationArguments(new String[0]))
        );

        assertEquals(
                "Platform owner bootstrap matched different users for subject owner-subject and email owner@example.com",
                error.getMessage()
        );
    }
}
