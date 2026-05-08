package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.repo.AppUserRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@ExtendWith(MockitoExtension.class)
class PlatformOwnerBootstrapServiceTest {

    @Mock
    AppUserRepository appUserRepository;

    @Test
    void bootstrapCreatesPlatformOwnerWhenConfigured() {
        when(appUserRepository.findByEmailIgnoreCase("owner@example.com")).thenReturn(Optional.empty());

        PlatformOwnerBootstrapService service = new PlatformOwnerBootstrapService(
                appUserRepository,
                new BCryptPasswordEncoder(),
                "owner@example.com",
                "Owner",
                "phase-1-password",
                false);

        service.ensurePlatformOwner();

        verify(appUserRepository).save(any(AppUser.class));
    }

    @Test
    void bootstrapDoesNothingWhenNotConfigured() {
        PlatformOwnerBootstrapService service = new PlatformOwnerBootstrapService(
                appUserRepository,
                new BCryptPasswordEncoder(),
                "",
                "",
                "",
                false);

        service.ensurePlatformOwner();

        verify(appUserRepository, never()).save(any(AppUser.class));
    }

    @Test
    void bootstrapPreservesExistingPasswordUnlessResetRequested() {
        AppUser user = new AppUser();
        user.setPasswordHash(new BCryptPasswordEncoder().encode("existing-password"));
        when(appUserRepository.findByEmailIgnoreCase("owner@example.com")).thenReturn(Optional.of(user));

        PlatformOwnerBootstrapService service = new PlatformOwnerBootstrapService(
                appUserRepository,
                new BCryptPasswordEncoder(),
                "owner@example.com",
                "Owner",
                "phase-1-password",
                false);

        service.ensurePlatformOwner();

        verify(appUserRepository).save(user);
        assertTrue(user.isPlatformOwner());
    }
}
