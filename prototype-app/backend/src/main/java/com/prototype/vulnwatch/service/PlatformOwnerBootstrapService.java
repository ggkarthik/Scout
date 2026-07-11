package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.config.PlatformOwnerBootstrapProperties;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.repo.AppUserRepository;
import java.time.Instant;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PlatformOwnerBootstrapService implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(PlatformOwnerBootstrapService.class);

    private final PlatformOwnerBootstrapProperties properties;
    private final AppUserRepository userRepository;
    private final AppUserGlobalRoleService appUserGlobalRoleService;

    public PlatformOwnerBootstrapService(
            PlatformOwnerBootstrapProperties properties,
            AppUserRepository userRepository,
            AppUserGlobalRoleService appUserGlobalRoleService
    ) {
        this.properties = properties;
        this.userRepository = userRepository;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!properties.isEnabled() || properties.getUsers().isEmpty()) {
            return;
        }
        for (PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed : properties.getUsers()) {
            upsertPlatformOwner(seed);
        }
    }

    private void upsertPlatformOwner(PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed) {
        String normalizedEmail = normalizeEmail(seed.getEmail());
        String normalizedSubject = normalizeSubject(seed.getExternalSubject(), normalizedEmail);
        AppUser subjectMatch = userRepository.findByExternalSubject(normalizedSubject).orElse(null);
        AppUser emailMatch = normalizedEmail == null ? null : userRepository.findByEmailIgnoreCase(normalizedEmail).orElse(null);
        if (subjectMatch != null && emailMatch != null && !subjectMatch.getId().equals(emailMatch.getId())) {
            throw new IllegalStateException("Platform owner bootstrap matched different users for subject " + normalizedSubject
                    + " and email " + normalizedEmail);
        }
        AppUser user = subjectMatch != null ? subjectMatch : emailMatch;
        if (user == null) {
            user = new AppUser();
        }
        user.setExternalSubject(normalizedSubject);
        user.setEmail(normalizedEmail);
        if (hasText(seed.getDisplayName())) {
            user.setDisplayName(seed.getDisplayName().trim());
        } else if (!hasText(user.getDisplayName()) && normalizedEmail != null) {
            user.setDisplayName(normalizedEmail);
        }
        user.setPlatformOwner(true);
        user.setStatus("ACTIVE");
        user.setUpdatedAt(Instant.now());
        user = userRepository.save(user);
        appUserGlobalRoleService.ensureRole(user, "PLATFORM_OWNER");
        log.info("Bootstrapped platform owner identity for {}", normalizedSubject);
    }

    private String normalizeEmail(String email) {
        if (!hasText(email)) {
            return null;
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeSubject(String subject, String normalizedEmail) {
        if (hasText(subject)) {
            return subject.trim();
        }
        if (normalizedEmail != null) {
            return normalizedEmail;
        }
        throw new IllegalStateException("Platform owner bootstrap entry must include externalSubject or email");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
