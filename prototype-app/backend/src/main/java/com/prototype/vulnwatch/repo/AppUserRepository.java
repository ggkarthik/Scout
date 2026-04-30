package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AppUser;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
    Optional<AppUser> findByExternalSubject(String externalSubject);
}
