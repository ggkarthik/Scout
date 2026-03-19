package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SoftwareIdentity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SoftwareIdentityRepository extends JpaRepository<SoftwareIdentity, UUID> {
    Optional<SoftwareIdentity> findByCanonicalKey(String canonicalKey);

    List<SoftwareIdentity> findByCanonicalKeyIn(Collection<String> canonicalKeys);

    Optional<SoftwareIdentity> findByProductHash(String productHash);

    Optional<SoftwareIdentity> findByCpe23(String cpe23);

    List<SoftwareIdentity> findAllByVendorIgnoreCaseAndProductIgnoreCase(String vendor, String product);
}
