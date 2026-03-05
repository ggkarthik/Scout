package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SoftwareIdentity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SoftwareIdentityRepository extends JpaRepository<SoftwareIdentity, UUID> {
    Optional<SoftwareIdentity> findByCanonicalKey(String canonicalKey);
}
