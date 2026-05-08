package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.repo.AppUserRepository;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PlatformOwnerBootstrapService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final String bootstrapEmail;
    private final String bootstrapName;
    private final String bootstrapPassword;
    private final boolean resetPasswordOnBoot;

    public PlatformOwnerBootstrapService(
            AppUserRepository appUserRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.auth.bootstrap.platform-owner-email:}") String bootstrapEmail,
            @Value("${app.auth.bootstrap.platform-owner-name:}") String bootstrapName,
            @Value("${app.auth.bootstrap.platform-owner-password:}") String bootstrapPassword,
            @Value("${app.auth.bootstrap.platform-owner-reset-password:false}") boolean resetPasswordOnBoot
    ) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.bootstrapEmail = bootstrapEmail == null ? "" : bootstrapEmail.trim().toLowerCase();
        this.bootstrapName = bootstrapName == null ? "" : bootstrapName.trim();
        this.bootstrapPassword = bootstrapPassword == null ? "" : bootstrapPassword;
        this.resetPasswordOnBoot = resetPasswordOnBoot;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void ensurePlatformOwner() {
        if (bootstrapEmail.isBlank() || bootstrapName.isBlank() || bootstrapPassword.isBlank()) {
            return;
        }
        AppUser user = appUserRepository.findByEmailIgnoreCase(bootstrapEmail)
                .orElseGet(() -> {
                    AppUser created = new AppUser();
                    created.setExternalSubject(bootstrapEmail);
                    created.setEmail(bootstrapEmail);
                    created.setStatus("ACTIVE");
                    return created;
                });
        user.setEmail(bootstrapEmail);
        user.setDisplayName(bootstrapName);
        user.setPlatformOwner(true);
        user.setStatus("ACTIVE");
        user.setUpdatedAt(Instant.now());
        if (user.getPasswordHash() == null || user.getPasswordHash().isBlank() || resetPasswordOnBoot) {
            user.setPasswordHash(passwordEncoder.encode(bootstrapPassword));
            user.setPasswordSetAt(Instant.now());
        }
        appUserRepository.save(user);
    }
}
